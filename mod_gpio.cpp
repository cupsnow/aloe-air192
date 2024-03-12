/**
 * Copyright 2023, Dexatek Technology Ltd.
 * This is proprietary information of Dexatek Technology Ltd.
 * All Rights Reserved. Reproduction of this documentation or the
 * accompanying programs in any manner whatsoever without the written
 * permission of Dexatek Technology Ltd. is strictly forbidden.
 */

/**
 * @author joelai
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "priv.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <mqueue.h>

#include <gpiod.h>
#include <cjson/cJSON.h>

#define DEV_NAME "gpiochip0"

#define LEDBANNED_VAL 1

static int instance_next = 0;
static char mod_name[] = "gpio";

typedef struct conn_rec {
	void *ev, *ctx;
	unsigned flag;
	void (*destroy)(struct conn_rec*);
	TAILQ_ENTRY(conn_rec) qent;
} conn_t;
typedef TAILQ_HEAD(conn_queue_rec, conn_rec) conn_queue_t;

typedef struct ctx_rec {
	int instance;
	conn_queue_t conn;
	struct gpiod_chip *dev;
//	const conn_t *sus;
} ctx_t;

typedef struct restkey_rec {
	conn_t conn;
	long dur, rep_dur;
	int rep;
	struct timeval ts0;
	aloe_buf_t name;
	struct gpiod_line *dev;
} restkey_t;

static void restkey_destroy(conn_t *conn) {
	restkey_t *sess = aloe_container_of(conn, restkey_t, conn);

	if (sess->dev) gpiod_line_release(sess->dev);
	if (sess->name.data) free(sess->name.data);
	free(sess);
}

static void restkey_on_read(int fd, unsigned ev_noti, void *cbarg) {
	restkey_t *sess = (restkey_t*)cbarg;
	ctx_t *ctx = (ctx_t*)sess->conn.ctx;
	int r, val;
	struct timeval ts;
	unsigned long tv = ALOE_EV_INFINITE;
	long dur;
//	aloe_buf_t cmd_buf;
	struct gpiod_line_event gio_ev;
	char cmd_str[120];

	if ((ev_noti & aloe_ev_flag_read) &&
			(r = gpiod_line_event_read(sess->dev, &gio_ev)) == -1) {
		r = errno;
		log_e("Failed read gpio %s event: %s\n", (char*)sess->name.data,
				strerror(r));
		goto finally;
	}
	if ((r = gpiod_line_get_value(sess->dev)) == -1) {
		r = errno;
		log_e("Failed read gpio %s: %s\n", (char*)sess->name.data, strerror(r));
		goto finally;
	}
	val = r;
	log_d("gpio %s, value: %d, ev: %s\n", (char*)sess->name.data, val,
			((ev_noti & aloe_ev_flag_time) ? "Timeout" :
			!(ev_noti & aloe_ev_flag_read) ? "N/A" :
			(gio_ev.event_type == GPIOD_LINE_EVENT_RISING_EDGE) ? "Rising" :
			(gio_ev.event_type == GPIOD_LINE_EVENT_FALLING_EDGE) ? "Falling" :
			"Unknown"));

	do {
		if (!gpio_restkeyhook || !gpio_restkeyhook[0]
				|| aloe_file_size(gpio_restkeyhook, 0) <= 0) {
			break;
		}
		if ((r = snprintf(cmd_str, sizeof(cmd_str), "%s %d %d &",
				gpio_restkeyhook, gpio_restkey, val)) <= 0
				|| r >= sizeof(cmd_str)) {
			log_e("Failed compose command for restkey hook\n");
			break;
		}
		system(cmd_str);
	} while(0);

	if (val == 1) {
		sess->ts0.tv_sec = 0;
		sess->rep = 0;
		r = 0;
		goto finally;
	}

	if ((r = gettimeofday(&ts, NULL)) != 0) {
		r = errno;
		log_e("Failed get current time: %s\n", strerror(r));
		goto finally;
	}

	tv = 1;
	if (sess->ts0.tv_sec == 0) {
		sess->ts0 = ts;
		log_d("Start count for %s\n", (char*)sess->name.data);
		r = 0;
		goto finally;
	}
	ALOE_TIMESEC_SUB(ts.tv_sec, ts.tv_usec, sess->ts0.tv_sec, sess->ts0.tv_usec,
			ts.tv_sec, ts.tv_usec, 1000000ul);
	dur = ts.tv_sec * 1000 + ts.tv_usec / 1000;
	if (dur < sess->dur) {
		log_d("Timer for %s is %ld / %ld\n", (char*)sess->name.data, dur,
				sess->dur);
		r = 0;
		goto finally;
	}
	log_d("Timeout[%d] for %s is %ld / %ld\n", sess->rep,
			(char*)sess->name.data, dur, sess->dur);
	system(gpio_restcmd);
	sess->ts0.tv_sec = 0;
	sess->rep++;
	tv = ((sess->rep_dur >= 1000) ? sess->rep_dur / 1000 : ALOE_EV_INFINITE);
	r = 0;
finally:
	if (r == 0) {
		if ((sess->conn.ev = aloe_ev_put(ev_ctx,
				gpiod_line_event_get_fd(sess->dev),
				&restkey_on_read, sess, aloe_ev_flag_read, tv, 0))) {
			return;
		}
		log_e("Failed schedule read ip port\n");
	}
	TAILQ_REMOVE(&ctx->conn, &sess->conn, qent);
	restkey_destroy(&sess->conn);
}

typedef struct mqled_port_rec {
	int gpio_num, pat, last_val;
	char name[32];
	struct gpiod_line *dev;
} mqled_port_t;

typedef struct mqled_rec {
	conn_t conn;
	mqd_t mq;
	aloe_buf_t recv_fb;
	mqled_port_t pw, st, *led_ports[8];
	struct {
		struct timeval ts0;
		int last_val;
	} tmr500;
	struct {
		struct timeval ts0;
		int last_val;
	} tmr200;

} mqled_t;

static int mqled_port_init(mqled_port_t **led_port, const char *name,
		int gpio_num, struct gpiod_chip *gpio_chip) {
	int r;
	mqled_port_t *led_p = NULL;

	if (*led_port) {
		led_p = *led_port;
	} else if ((led_p = (mqled_port_t*)calloc(1, sizeof(*led_p))) == NULL) {
		r = ENOMEM;
		log_e("Alloc for led port\n");
		goto finally;
	}

	if (gpio_chip) {
#if 1
		if (!(led_p->dev = gpiod_chip_get_line(gpio_chip, gpio_num))) {
			r = EIO;
			log_e("Request info led %s, gpio #%d\n", name, gpio_num);
			goto finally;
		}

		if ((r = gpiod_line_request_input(led_p->dev, mod_name)) != 0) {
			r = errno;
			log_e("Request current value led %s, gpio #%d\n", name, gpio_num);
			goto finally;
		}
		led_p->last_val = gpiod_line_get_value(led_p->dev);
#endif
		gpiod_line_release(led_p->dev);
		if ((r = gpiod_line_request_output(led_p->dev, mod_name,
				led_p->last_val)) != 0) {
			r = errno;
			log_e("Request output led %s, gpio #%d\n", name, gpio_num);
			goto finally;
		}
	}
	if (!*led_port) *led_port = led_p;
	led_p->gpio_num = gpio_num;
	aloe_str_stuff(led_p->name, "%s", name);
	log_d("led %s, gpio #%d\n", name, gpio_num);
	r = 0;
finally:
	if (r != 0) {
		if (led_p->dev) {
			gpiod_line_release(led_p->dev);
			led_p->dev = NULL;
		}
		if (!*led_port && led_p) free(led_p);
	}
	return r;
}

static int mqled_port_setval(mqled_port_t *led_p, int *_led_val) {
	int r, set_val, *req_val;
	int ledbanned;

	ledbanned = (_aloe_file_size(ledban_cfg, 0) >= 0);

	if ((_led_val == NULL) || (_led_val == (int*)1) || (_led_val == (int*)-1)
			 || (_led_val == (int*)-2)) {
		req_val = NULL;
		set_val = (int)(long)_led_val;
	} else {
		req_val = _led_val;
		set_val = *_led_val;
	}

	if (set_val == -2) {
		set_val = led_p->last_val;
	} else if (set_val < 0) {
		if (!led_p->dev) {
			r = led_p->last_val;
		} else if ((r = gpiod_line_get_value(led_p->dev)) < 0) {
			r = errno;
			log_e("Failed get led %s value: %s\n", led_p->name, strerror(r));
			r = led_p->last_val;
		}

		if (set_val == -2) {
			set_val = !!r;
		}
		set_val = !r;
	} else {
		set_val = !!set_val;
	}

	if (req_val) *req_val = set_val;
	if (led_p->dev) {
		if ((r = gpiod_line_set_value(led_p->dev,
				(ledbanned ? LEDBANNED_VAL : set_val))) != 0) {
			r = errno;
			log_e("Failed control led %s, val %d, %s\n", led_p->name, set_val, strerror(r));
			return r;
		}
		if (ledbanned) {
			log_d("LED off instead of %s\n", (set_val ? "on" : "off"));
		}
	}
	led_p->last_val = set_val;
	return 0;
}

static void mqled_destroy(conn_t *conn) {
	mqled_t *sess = aloe_container_of(conn, mqled_t, conn);
	int i;

	if (sess->pw.dev) gpiod_line_release(sess->pw.dev);
	if (sess->st.dev) gpiod_line_release(sess->pw.dev);
	for (i = 0; i < (int)aloe_arraysize(sess->led_ports); i++) {
		if (sess->led_ports[i] && sess->led_ports[i]->dev) {
			gpiod_line_release(sess->led_ports[i]->dev);
		}
	}
	if (sess->mq != (mqd_t)-1) mq_close(sess->mq);
	free(sess);
}

static void mqled_on_read(int fd, unsigned ev_noti, void *cbarg) {
	mqled_t *sess = (mqled_t*)cbarg;
	ctx_t *ctx = (ctx_t*)sess->conn.ctx;
	aloe_buf_t *fb = &sess->recv_fb;
	air192_mqled_tlv_t *msg;
	int r, led_iter;
	struct timeval ts;
	unsigned long tv_ms = ALOE_EV_INFINITE, td500, td200;
	mqled_port_t *led_p;

	if ((r = gettimeofday(&ts, NULL)) != 0) {
		r = errno;
		log_e("Failed get current time: %s\n", strerror(r));
		goto finally;
	}

	if (ev_noti & aloe_ev_flag_read) {
		if (fb->lmt - fb->pos < sizeof(msg)) {
			log_e("unexpected receive buffer size\n");
			aloe_buf_clear(&sess->recv_fb);
		}

		if ((r = mq_receive(sess->mq, (char*)fb->data + fb->pos,
				fb->lmt - fb->pos, NULL)) < 0) {
			r = errno;
			log_e("Failed read led event: %s\n", strerror(r));
			goto finally;
		}
		fb->pos += r;

		aloe_buf_flip(fb);

		for (msg = (air192_mqled_tlv_t*)((char*)fb->data + fb->pos);
				fb->lmt - fb->pos >= sizeof(msg->tlvhdr)
						&& fb->lmt - fb->pos >= sizeof(msg->tlvhdr) + msg->tlvhdr.len;
				fb->pos += (sizeof(msg->tlvhdr) + msg->tlvhdr.len),
						msg = (air192_mqled_tlv_t*)((char*)fb->data + fb->pos)) {
			// sanity check
			if (msg->mqled.name_len < 1
					|| msg->mqled.name_len >= (int)sizeof(msg->mqled.name)
					|| msg->mqled.name[msg->mqled.name_len - 1]
					|| msg->tlvhdr.type != air192_mqled_tlvtype) {
				log_e("unexpected mqled\n");
				continue;
			}

			led_p = NULL;
			if (strcasecmp(msg->mqled.name, "power") == 0) {
				if (sess->pw.name[0]) led_p = &sess->pw;
			} else if (strcasecmp(msg->mqled.name, "standby") == 0) {
				if (sess->st.name[0]) led_p = &sess->st;
			} else {
				for (r = 0; r < (int)aloe_arraysize(sess->led_ports); r++) {
					if (sess->led_ports[r] && strcasecmp(msg->mqled.name,
							sess->led_ports[r]->name) == 0) {
						led_p = sess->led_ports[r];
						break;
					}
				}
			}

			if (!led_p) {
				log_e("unknown led %s, val %d\n", msg->mqled.name, msg->mqled.led_val);
				continue;
			}

			if (msg->mqled.led_val == 2 || msg->mqled.led_val == 5) {
				log_d("led %s, pattern %d\n", msg->mqled.name, msg->mqled.led_val);
				led_p->pat = msg->mqled.led_val;
				continue;
			}

			if ((r = mqled_port_setval(led_p, (int*)(long)msg->mqled.led_val)) != 0) {
				log_e("Failed control led %s, val %d\n", msg->mqled.name,
						msg->mqled.led_val);
				continue;
			}
			if (msg->mqled.led_val != -2) {
				led_p->pat = led_p->last_val;
			}
			log_d("led %s, set %d\n", led_p->name, led_p->pat);
			continue;
		}
		aloe_buf_replay(fb);
		if (fb->pos > 0) log_d("remain %d bytes\n", (int)fb->pos);
	}

	td500 = td200 = ALOE_EV_INFINITE;
	for (led_iter = 0; led_iter < (2 + (int)aloe_arraysize(sess->led_ports));
			led_iter++) {
		led_p = ((led_iter == 0) ? &sess->pw :
				(led_iter == 1) ? &sess->st :
				sess->led_ports[led_iter - 2]);

		if (!led_p || !led_p->name[0]) continue;

		if (led_p->pat == 2) {
			// toggle per 500ms
			if (td500 == ALOE_EV_INFINITE) {
				if (sess->tmr500.ts0.tv_sec == 0) {
					log_d("Start timer 500ms\n");
					td500 = 0;
					continue;
				}
				td500 = ALOE_TIMESEC_TD1(ts.tv_sec, ts.tv_usec,
						sess->tmr500.ts0.tv_sec, sess->tmr500.ts0.tv_usec,
						1000000ul) / 1000ul;
			}
			if (td500 < 500ul) continue;

			if ((r = mqled_port_setval(led_p,
					(int*)(long)(!sess->tmr500.last_val))) != 0) {
				log_e("Failed toggle led %s\n", led_p->name);
				continue;
			}
			continue;
		}

		if (led_p->pat == 5) {
			// toggle per 200ms
			if (td200 == ALOE_EV_INFINITE) {
				if (sess->tmr200.ts0.tv_sec == 0) {
					log_d("Start timer 200ms\n");
					td200 = 0;
					continue;
				}
				td200 = ALOE_TIMESEC_TD1(ts.tv_sec, ts.tv_usec,
						sess->tmr200.ts0.tv_sec, sess->tmr200.ts0.tv_usec,
						1000000ul) / 1000ul;
			}
			if (td200 < 200ul) continue;

			if ((r = mqled_port_setval(led_p,
					(int*)(long)(!sess->tmr200.last_val))) != 0) {
				log_e("Failed toggle led %s\n", led_p->name);
				continue;
			}
			continue;
		}
	}

	if (td500 == ALOE_EV_INFINITE) {
		if (sess->tmr500.ts0.tv_sec != 0) {
			log_d("Stop timer 500ms\n");
			sess->tmr500.ts0.tv_sec = 0;
		}
	} else if (td500 == 0) {
		sess->tmr500.ts0 = ts;
		if (tv_ms == ALOE_EV_INFINITE || tv_ms > 500ul) tv_ms = 500ul;
	} else if (td500 >= 500ul) {
		sess->tmr500.last_val = !sess->tmr500.last_val;
		sess->tmr500.ts0 = ts;
		if (tv_ms == ALOE_EV_INFINITE || tv_ms > 500ul) tv_ms = 500ul;
	} else {
		if (tv_ms == ALOE_EV_INFINITE || tv_ms > 500ul - td500) tv_ms = 500ul - td500;
	}

	if (td200 == ALOE_EV_INFINITE) {
		if (sess->tmr200.ts0.tv_sec != 0) {
			log_d("Stop timer 200ms\n");
			sess->tmr200.ts0.tv_sec = 0;
		}
	} else if (td200 == 0) {
		sess->tmr200.ts0 = ts;
		if (tv_ms == ALOE_EV_INFINITE || tv_ms > 200ul) tv_ms = 200ul;
	} else if (td200 >= 200ul) {
		sess->tmr200.last_val = !sess->tmr200.last_val;
		sess->tmr200.ts0 = ts;
		if (tv_ms == ALOE_EV_INFINITE || tv_ms > 200ul) tv_ms = 200ul;
	} else {
		if (tv_ms == ALOE_EV_INFINITE || tv_ms > 200ul - td200) tv_ms = 200ul - td200;
	}

	r = 0;
finally:
	if (r == 0) {
		if ((sess->conn.ev = aloe_ev_put(ev_ctx, (int)sess->mq,
				&mqled_on_read, sess, aloe_ev_flag_read,
				((tv_ms == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE : tv_ms / 1000ul),
				((tv_ms == ALOE_EV_INFINITE) ? 0 : (tv_ms % 1000ul) * 1000ul)))) {
			return;
		}
		log_e("Failed schedule read led request\n");
	}
	TAILQ_REMOVE(&ctx->conn, &sess->conn, qent);
	mqled_destroy(&sess->conn);
}

typedef struct mqsus_rec {
	conn_t conn;
	mqd_t mq;
	aloe_buf_t recv_fb;
	struct {
		struct timeval ts0;
		char name[50];
	} sus;
} mqsus_t;

static int mqsus_sus(mqsus_t *sus) {
	log_d("Fired suspend from %s\n", sus->sus.name);
	system("pwmgr -p1&");
	return 0;
}

static void mqsus_destroy(conn_t *conn) {
	mqsus_t *sess = aloe_container_of(conn, mqsus_t, conn);

	if (sess->mq != (mqd_t)-1) mq_close(sess->mq);
	free(sess);
}

static void mqsus_on_read(int fd, unsigned ev_noti, void *cbarg) {
	mqsus_t *sess = (mqsus_t*)cbarg;
	ctx_t *ctx = (ctx_t*)sess->conn.ctx;
	aloe_buf_t *fb = &sess->recv_fb;
	air192_mqsus_tlv_t *msg;
	int r;
	struct timeval ts;
	unsigned long tv_ms = ALOE_EV_INFINITE;

	if ((r = gettimeofday(&ts, NULL)) != 0) {
		r = errno;
		log_e("Failed get current time: %s\n", strerror(r));
		goto finally;
	}

	if (ev_noti & aloe_ev_flag_read) {
		if (fb->lmt - fb->pos < sizeof(msg)) {
			log_e("unexpected receive buffer size\n");
			aloe_buf_clear(&sess->recv_fb);
		}

		if ((r = mq_receive(sess->mq, (char*)fb->data + fb->pos,
				fb->lmt - fb->pos, NULL)) < 0) {
			r = errno;
			log_e("Failed read sus event: %s\n", strerror(r));
			goto finally;
		}
		fb->pos += r;

		aloe_buf_flip(fb);

		for (msg = (air192_mqsus_tlv_t*)((char*)fb->data + fb->pos);
				fb->lmt - fb->pos >= sizeof(msg->tlvhdr)
						&& fb->lmt - fb->pos >= sizeof(msg->tlvhdr) + msg->tlvhdr.len;
				fb->pos += (sizeof(msg->tlvhdr) + msg->tlvhdr.len),
						msg = (air192_mqsus_tlv_t*)((char*)fb->data + fb->pos)) {
			// sanity check
			if (msg->mqsus.name_len < 1
					|| msg->mqsus.name_len >= (int)sizeof(msg->mqsus.name)
					|| msg->mqsus.name[msg->mqsus.name_len - 1]
					|| msg->tlvhdr.type != air192_mqsus_tlvtype) {
				log_e("unexpected mqsus\n");
				continue;
			}

			if (msg->mqsus.whence == air192_mqsus_whence_null) {
				log_d("Stop suspend timer from %s\n", msg->mqsus.name);
				sess->sus.ts0.tv_sec = 0;
				aloe_str_stuff(sess->sus.name, "%s", msg->mqsus.name);
				continue;
			}

			if (msg->mqsus.whence == air192_mqsus_whence_set) {
				log_d("Set suspend after %d seconds from %s\n", msg->mqsus.delay,
						msg->mqsus.name);
				ALOE_TIMESEC_ADD(ts.tv_sec, ts.tv_usec,
						msg->mqsus.delay, 0ul,
						sess->sus.ts0.tv_sec, sess->sus.ts0.tv_usec, 1000000l);
				aloe_str_stuff(sess->sus.name, "%s", msg->mqsus.name);
				continue;
			}

			log_e("unknown suspend whence %d from %s\n", msg->mqsus.whence,
					msg->mqsus.name);
		}
		aloe_buf_replay(fb);
		if (fb->pos > 0) log_d("remain %d bytes\n", (int)fb->pos);
	}

	do {
		unsigned long td;

		if (sess->sus.ts0.tv_sec == 0) continue;
		if (ALOE_TIMESEC_CMP(sess->sus.ts0.tv_sec, sess->sus.ts0.tv_usec,
				ts.tv_sec, ts.tv_usec) > 0) {
			td = ALOE_TIMESEC_TD1(sess->sus.ts0.tv_sec, sess->sus.ts0.tv_usec,
					ts.tv_sec, ts.tv_usec,
					1000000ul) / 1000ul;
			if (tv_ms == ALOE_EV_INFINITE || tv_ms > td) tv_ms = td;
			continue;
		}

		sess->sus.ts0.tv_sec = 0;
		mqsus_sus(sess);
		continue;

	} while(0);
	r = 0;
finally:
	if (r == 0) {
		if ((sess->conn.ev = aloe_ev_put(ev_ctx, (int)sess->mq,
				&mqsus_on_read, sess, aloe_ev_flag_read,
				((tv_ms == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE : tv_ms / 1000ul),
				((tv_ms == ALOE_EV_INFINITE) ? 0 : (tv_ms % 1000ul) * 1000ul)))) {
			return;
		}
		log_e("Failed schedule read sus request\n");
	}
	TAILQ_REMOVE(&ctx->conn, &sess->conn, qent);
	mqsus_destroy(&sess->conn);
}

static void destroy(void *_ctx) {
	ctx_t *ctx = (ctx_t*)_ctx;
	conn_t *conn;

	log_d("%s[%d]\n", mod_name, ctx->instance);

	while ((conn = TAILQ_FIRST(&ctx->conn))) {
		TAILQ_REMOVE(&ctx->conn, conn, qent);
		if (!conn->ev) aloe_ev_cancel(ev_ctx, conn->ev);
		if (conn->destroy) (*conn->destroy)(conn);
	}
	if (ctx->dev) gpiod_chip_unref(ctx->dev);
	free(ctx);
}

static void* init(void) {
	ctx_t *ctx = NULL;
	int r;
	aloe_buf_t buf = {0};

	if ((ctx = (ctx_t*)malloc(sizeof(*ctx))) == NULL) {
		r = ENOMEM;
		log_e("Alloc instance\n");
		goto finally;
	}
	TAILQ_INIT(&ctx->conn);
	ctx->instance = instance_next++;
	ctx->dev = NULL;

	if (!(ctx->dev = gpiod_chip_open("/dev/" DEV_NAME))) {
		r = errno;
		log_e("Failed open %s: %s(%d)\n", "/dev/" DEV_NAME, strerror(r), r);
		do {
			if (led_conf) {
				log_d("Dryrun without gpio for %s\n", led_conf);
				break;
			}
			goto finally;
		} while(0);
	}

	if (ctx->dev && gpio_restkey != GPIO_NUM_NONE) {
		restkey_t *sess;
		int fd;

		if ((sess = (restkey_t*)calloc(1, sizeof(*sess))) == NULL
				|| aloe_buf_expand(&sess->name, 100, aloe_buf_flag_none) != 0) {
			r = ENOMEM;
			log_e("Alloc manager for control path\n");
			if (sess) restkey_destroy(&sess->conn);
			goto finally;
		}
		aloe_buf_clear(&sess->name);

		if (aloe_buf_printf(&sess->name, "%s(%d)", "restkey",
				gpio_restkey) <= 0) {
			r = ENOMEM;
			log_e("Failed retrieve gpio name\n");
			restkey_destroy(&sess->conn);
			goto finally;
		}

		if (!(sess->dev = gpiod_chip_get_line(ctx->dev, gpio_restkey))
				|| gpiod_line_request_both_edges_events(sess->dev,
						(char*)sess->name.data) != 0
				|| (fd = gpiod_line_event_get_fd(sess->dev)) == -1) {
			log_e("Failed request gpio %s\n", (char*)sess->name.data);
			restkey_destroy(&sess->conn);
			r = EIO;
			goto finally;
		}
		if (!(sess->conn.ev = aloe_ev_put(ev_ctx, fd,
				&restkey_on_read, sess, aloe_ev_flag_read, ALOE_EV_INFINITE,
				0))) {
			r = EIO;
			log_e("Failed schedule read gpio event\n");
			restkey_destroy(&sess->conn);
			goto finally;
		}
		sess->dur = gpio_restdur * 1000;
		sess->rep_dur = 10000;
		sess->conn.destroy = &restkey_destroy;
		sess->conn.ctx = ctx;
		TAILQ_INSERT_TAIL(&ctx->conn, &sess->conn, qent);

		log_i("%s[%d] gpio: %s\n", mod_name, ctx->instance,
				(char* )sess->name.data);
	}

	if (led_conf != NULL) {
		struct mq_attr mqattr;
		mqled_t *sess;
		char *pl, *pl_tok;
		mqled_port_t *led_p;
		int msg_sz = sizeof(air192_mqled_tlv_t);

		const char *fns[] = {
			led_conf,
			NULL
		};

		if (air192_cfg_load2(fns, &buf, 2000) != 0) {
			r = EIO;
			log_e("Failed read led conf: %s\n", led_conf);
			goto finally;
		}
		aloe_buf_flip(&buf);

		if ((sess = (mqled_t*)malloc(sizeof(*sess) + msg_sz * 2)) == NULL) {
			r = ENOMEM;
			log_e("Alloc manager for mqled\n");
//			if (sess) mqled_destroy(&sess->conn);
			goto finally;
		}
		memset(sess, 0, sizeof(mqled_t));
		sess->mq = (mqd_t)-1;

		for (pl = strtok_r((char*)buf.data + buf.pos, "\r\n", &pl_tok);
				pl; pl = strtok_r(NULL, "\r\n", &pl_tok)) {
			char *name, *val_str, *plk_tok;
			int gpio_num, gpio_val = -1, led_ex;

			pl += strspn(pl, aloe_str_sep);
			if (strncasecmp(pl, "led_", 4) != 0
					|| (!isalpha(pl[4]) && isdigit(pl[4]))) {
				log_d("Ignore line: %s\n", pl);
				continue;
			}

			if (!(name = strtok_r(pl + 4, aloe_str_sep, &plk_tok))
					|| !(val_str = strtok_r(NULL, aloe_str_sep, &plk_tok))) {
				continue;
			}
			if (aloe_strtoi(val_str, NULL, 0, &gpio_num) != 0) {
				log_e("Parse led %s, gpio #%s\n", name, val_str);
				continue;
			}

			if ((val_str = strtok_r(NULL, aloe_str_sep, &plk_tok))) {
				aloe_strtoi(val_str, NULL, 0, &gpio_val);
			}

			if (strcasecmp(name, "power") == 0) {
				led_p = &sess->pw;
				if (led_p->name[0]) {
					log_e("Ignore dup led %s, gpio #%d\n", name, gpio_num);
					continue;
				}
				if ((r = mqled_port_init(&led_p, name, gpio_num,
						ctx->dev)) != 0) {
					log_e("Failed init led %s, gpio #%d\n", name, gpio_num);
					mqled_destroy(&sess->conn);
					goto finally;
				}
				if (gpio_val != -1) {
					mqled_port_setval(led_p, (int*)!!gpio_val);
					log_d("led %s, gpio #%d, val %d\n", name, gpio_num,
							gpio_val);
				} else {
					log_d("led %s, gpio #%d\n", name, gpio_num);
				}
				continue;
			}

			if (strcasecmp(name, "standby") == 0) {
				led_p = &sess->st;
				if (led_p->name[0]) {
					log_e("Ignore dup led %s, gpio #%d\n", name, gpio_num);
					continue;
				}
				led_p->last_val = 0;
				if ((r = mqled_port_init(&led_p, name, gpio_num,
						ctx->dev)) != 0) {
					log_e("Failed init led %s, gpio #%d\n", name, gpio_num);
					mqled_destroy(&sess->conn);
					goto finally;
				}
				if (gpio_val != -1) {
					mqled_port_setval(led_p, (int*)!!gpio_val);
					log_d("led %s, gpio #%d, val %d\n", name, gpio_num,
							gpio_val);
				} else {
					log_d("led %s, gpio #%d\n", name, gpio_num);
				}
				continue;
			}

			for (led_ex = 0; led_ex < (int)aloe_arraysize(sess->led_ports);
					led_ex++) {
				if (!(led_p = sess->led_ports[led_ex])) break;
				if (strcasecmp(name, led_p->name) == 0) {
					log_e("Ignore dup led %s, gpio #%d\n", name, gpio_num);
					led_ex = (int)aloe_arraysize(sess->led_ports);
					break;
				}
			}
			if (led_ex >= (int)aloe_arraysize(sess->led_ports)) continue;
			if ((r = mqled_port_init(&sess->led_ports[led_ex], name, gpio_num,
					ctx->dev)) != 0) {
				log_e("Failed init %s, gpio_num: %d\n", name, gpio_num);
				mqled_destroy(&sess->conn);
				goto finally;
			}
			if (gpio_val != -1) {
				mqled_port_setval(led_p, (int*)!!gpio_val);
				log_d("led[%d] %s, gpio #%d, val %d\n", led_ex, name, gpio_num,
						gpio_val);
			} else {
				log_d("led[%d] %s, gpio #%d\n", led_ex, name, gpio_num);
			}
		}

		memset(&mqattr, 0, sizeof(mqattr));
		mqattr.mq_maxmsg = 10;
		mqattr.mq_msgsize = msg_sz;
		if ((sess->mq = mq_open(air192_mqled_name, O_CREAT | O_RDONLY, 0644,
				&mqattr)) == (mqd_t)-1) {
			r = errno;
			log_e("failed open mq: %s\n", strerror(r));
			mqled_destroy(&sess->conn);
			goto finally;
		}

		if ((r = aloe_file_nonblock((int)sess->mq, 1)) != 0) {
			log_e("failed set nonblock for mq: %s\n", strerror(r));
			mqled_destroy(&sess->conn);
			goto finally;
		}

		if (!(sess->conn.ev = aloe_ev_put(ev_ctx, (int)sess->mq,
				&mqled_on_read, sess, aloe_ev_flag_read, ALOE_EV_INFINITE,
				0))) {
			r = EIO;
			log_e("Failed schedule read led request\n");
			mqled_destroy(&sess->conn);
			goto finally;
		}
		sess->recv_fb.data = (void*)(sess + 1);
		sess->recv_fb.cap = msg_sz * 2;
		aloe_buf_clear(&sess->recv_fb);
		sess->conn.destroy = &mqled_destroy;
		sess->conn.ctx = ctx;
		TAILQ_INSERT_TAIL(&ctx->conn, &sess->conn, qent);

		log_i("%s[%d] mqled: %s\n", mod_name, ctx->instance, air192_mqled_name);
	}

	{
		struct mq_attr mqattr;
		mqsus_t *sess;
		int msg_sz = sizeof(air192_mqsus_tlv_t);

		if ((sess = (mqsus_t*)malloc(sizeof(*sess) + msg_sz * 2)) == NULL) {
			r = ENOMEM;
			log_e("Alloc manager for mqsus\n");
//			if (sess) mqsus_destroy(&sess->conn);
			goto finally;
		}
		memset(sess, 0, sizeof(mqsus_t));
		sess->mq = (mqd_t)-1;

		memset(&mqattr, 0, sizeof(mqattr));
		mqattr.mq_maxmsg = 10;
		mqattr.mq_msgsize = msg_sz;
		if ((sess->mq = mq_open(air192_mqsus_name, O_CREAT | O_RDONLY, 0644,
				&mqattr)) == (mqd_t)-1) {
			r = errno;
			log_e("failed open mq: %s\n", strerror(r));
			mqsus_destroy(&sess->conn);
			goto finally;
		}

		if ((r = aloe_file_nonblock((int)sess->mq, 1)) != 0) {
			log_e("failed set nonblock for mq: %s\n", strerror(r));
			mqsus_destroy(&sess->conn);
			goto finally;
		}

		if (!(sess->conn.ev = aloe_ev_put(ev_ctx, (int)sess->mq,
				&mqsus_on_read, sess, aloe_ev_flag_read, ALOE_EV_INFINITE,
				0))) {
			r = EIO;
			log_e("Failed schedule read sus request\n");
			mqsus_destroy(&sess->conn);
			goto finally;
		}
		sess->recv_fb.data = (void*)(sess + 1);
		sess->recv_fb.cap = msg_sz * 2;
		aloe_buf_clear(&sess->recv_fb);
		sess->conn.destroy = &mqsus_destroy;
		sess->conn.ctx = ctx;
		TAILQ_INSERT_TAIL(&ctx->conn, &sess->conn, qent);

		log_i("%s[%d] mqsus: %s\n", mod_name, ctx->instance, air192_mqsus_name);
	}
	r = 0;
finally:
	if (r != 0) {
		if (ctx) destroy((void*)ctx);
		return NULL;
	}
	if (buf.data) free(buf.data);
	return (void*)ctx;
}

static int ioctl(void *_ctx, void *args) {
	ctx_t *ctx = (ctx_t*)_ctx;

	log_d("%s[%d]\n", mod_name, ctx->instance);
	return 0;
}

extern "C" const aloe_mod_t mod_gpio = {.name = mod_name, .init = &init,
		.destroy = &destroy, .ioctl = &ioctl};
