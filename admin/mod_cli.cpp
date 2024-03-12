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
#include <unistd.h>
#include <fcntl.h>
#include <netinet/ip.h>

#include <cjson/cJSON.h>

static int instance_next = 0;
static char mod_name[] = "cli";

#define conn_flag_sess (1 << 0)
#define conn_flag_ip (1 << 1)

typedef struct conn_rec {
	int fd;
	void *ev, *ctx;
	unsigned flag;
	void (*destroy)(struct conn_rec*);
	TAILQ_ENTRY(conn_rec) qent;
} conn_t;
typedef TAILQ_HEAD(conn_queue_rec, conn_rec) conn_queue_t;

typedef struct listener_rec {
	conn_t conn;
	aloe_buf_t name;
} listener_t;

typedef struct sess_rec {
	conn_t conn;
	aloe_buf_t name, xfer;
} sess_t;

//typedef struct subs_rec {
//	void *topic, *sess;
//	TAILQ_ENTRY(conn_rec) qent_sess, qent_topic;
//} subs_t;
//typedef TAILQ_HEAD(subs_queue_rec, subs_rec) subs_queue_t;
//
//typedef struct topic_rec {
//	aloe_buf_t name;
//	TAILQ_ENTRY(conn_rec) qent;
//} topic_t;
//typedef TAILQ_HEAD(topic_queue_rec, topic_rec) topic_queue_t;

typedef struct ctx_rec {
	int instance, player_state;
	conn_queue_t conn;
//	topic_queue_t topic;
} ctx_t;

static void listener_destroy(conn_t *conn) {
	listener_t *listener = aloe_container_of(conn, listener_t, conn);

	if (listener->conn.fd != -1) close(listener->conn.fd);
	if (listener->name.data) free(listener->name.data);
	free(listener);
}

static void sess_destroy(conn_t *conn) {
	sess_t *sess = aloe_container_of(conn, sess_t, conn);

	if (ctrl_path && ctrl_path[0]) {
		unlink(ctrl_path);
	}

	if (sess->conn.fd != -1) close(sess->conn.fd);
	if (sess->name.data) free(sess->name.data);
	if (sess->xfer.data) free(sess->xfer.data);
	free(sess);
}

typedef enum cli_ret_enum {
	cli_ret_drop_input = 0,
	cli_ret_fatal = 1,
	cli_ret_consumed,
	cli_ret_expect_more,
} cli_ret_t;

#define CLI_DECL(_name) cli_ret_t _name (sess_t *sess, aloe_buf_t *cmd_buf, \
		int cmd_len)

#define CLI_SHUTDOWN_CMD "shutdown"
static CLI_DECL(cli_shutdown) {
	admin_shutdown();
	cmd_buf->pos += cmd_len;
	return cli_ret_consumed;
}

#define CLI_SUBSCRIBE_CMD "subscribe"
static CLI_DECL(cli_subscribe) {
//	ctx_t *ctx = (ctx_t*)sess->conn.ctx;
	cli_ret_t rc;
	const char *jroot_end,*str;
	cJSON *jroot = NULL, *jobj;

	cmd_buf->pos += cmd_len;
	if (!(jroot = cJSON_ParseWithLengthOpts((char*)cmd_buf->data + cmd_buf->pos,
			cmd_buf->lmt - cmd_buf->pos, &jroot_end, 0))) {
		rc = cli_ret_drop_input;
		log_e("Cannot parse subscribe arguments\n");
		goto finally;
	}
	cmd_buf->pos += (jroot_end - ((char*)cmd_buf->data + cmd_buf->pos));

	if (!(jobj = cJSON_GetObjectItem(jroot, "topic"))
			|| !(str = cJSON_GetStringValue(jobj))) {
		log_e("Invalid subscribe: %s", "topic");
		goto finally;
	}
	log_d("Subscribe topic: %s\n", str);
	rc = cli_ret_consumed;
finally:
	if (jroot) cJSON_Delete(jroot);
	return rc;
}

#define CLI_PUBLISH_CMD "publish"
static CLI_DECL(cli_publish) {
	ctx_t *ctx = (ctx_t*)sess->conn.ctx;
	cli_ret_t rc = cli_ret_drop_input;
	const char *jroot_end,*str, *topic, *msg;
	cJSON *jroot = NULL, *jobj, *jout = NULL;
	conn_t *conn;
	int out_cnt, str_len, r;

	cmd_buf->pos += cmd_len;
	if (!(jroot = cJSON_ParseWithLengthOpts((char*)cmd_buf->data + cmd_buf->pos,
			cmd_buf->lmt - cmd_buf->pos, &jroot_end, 0))) {
		log_e("Cannot parse publish arguments\n");
		goto finally;
	}
	cmd_buf->pos += (jroot_end - ((char*)cmd_buf->data + cmd_buf->pos));

	rc = cli_ret_consumed;
	if (!(jobj = cJSON_GetObjectItem(jroot, "topic"))
			|| !(topic = cJSON_GetStringValue(jobj))
			|| !(jobj = cJSON_GetObjectItem(jroot, "message"))
			|| !(msg = cJSON_GetStringValue(jobj))) {
		log_e("Invalid publish");
		goto finally;
	}
	log_d("Published topic: %s, message: %s\n", topic, msg);

	if (!(jout = cJSON_CreateObject())
			|| !cJSON_AddStringToObject(jout, "topic", topic)
			|| !cJSON_AddStringToObject(jout, "message", msg)
			|| !(str = cJSON_PrintUnformatted(jout))) {
		log_e("Alloc jout\n");
		goto finally;
	}
	str_len = strlen(str);
	log_d("Broadcasting %d bytes: %s\n", str_len, str);

	out_cnt = 0;
	TAILQ_FOREACH(conn, &ctx->conn, qent) {
		sess_t *sess2;
		int out_len;

		if (!(conn->flag & conn_flag_sess)
				|| (conn == &sess->conn)
				|| (conn->fd == -1)) {
			continue;
		}
		out_len = 0;
		sess2 = aloe_container_of(conn, sess_t, conn);
		while (out_len < str_len) {
			r = write(conn->fd, str + out_len, str_len - out_len);
			if (r < 0) {
				r = errno;
				if (((r == EINTR) || (r == EAGAIN) || (r == EWOULDBLOCK))) {
					long msec = random() % 100;
					log_d("Defered %ld msec output to %s: %s\n", msec,
							(char*)sess2->name.data, strerror(r));
					usleep(msec * 1000);
					continue;
				}
				log_e("Failed output to %s: %s\n", (char*)sess2->name.data,
						strerror(r));
				break;
			}
			if (out_len + r >= str_len) {
				out_cnt++;
				log_d("Broadcasting[%d] to %s\n", out_cnt, (char*)sess2->name.data);
				break;
			}
			out_len += r;
		}
	}
	log_d("Broadcasted to %d clients\n", out_cnt);

	rc = cli_ret_consumed;
finally:
	if (jroot) cJSON_Delete(jroot);
	if (jout) cJSON_Delete(jout);
	return rc;
}

typedef struct cli_entry_rec {
	const char *name;
	CLI_DECL((*proc));
} cli_entry_t;

static const cli_entry_t cli_lut[] = {
	{CLI_PUBLISH_CMD, &cli_publish},
	{CLI_SHUTDOWN_CMD, &cli_shutdown},
	{CLI_SUBSCRIBE_CMD, &cli_subscribe},
	{0}
};

static void sess_on_read(int fd, unsigned ev_noti, void *cbarg) {
	sess_t *sess = (sess_t*)cbarg;
	ctx_t *ctx = (ctx_t*)sess->conn.ctx;
	int r;
	const cli_entry_t *cli_ent;
	aloe_buf_t cmd_buf;

	log_d("%s, ev_noti: %d\n", (char*)sess->name.data, ev_noti);

	if (sess->xfer.lmt - sess->xfer.pos <= 0) {
		r = EIO;
		log_e("too long data\n");
		goto finally;
	}

	// reserve a trailing zero
	r = read(fd, (char*)sess->xfer.data + sess->xfer.pos,
			sess->xfer.lmt - sess->xfer.pos - 1);
	if (r == 0) {
		r = EIO;
		log_d("closed from remote %s\n", (char*)sess->name.data);
		goto finally;
	}
	if (r < 0) {
		r = errno;
		if ((r == EINTR) || (r == EAGAIN) || (r == EWOULDBLOCK)) {
			r = 0;
			goto finally;
		}
		log_e("Failed read from remote %s, %s\n", (char*)sess->name.data,
				strerror(r));
		goto finally;
	}
	log_d("%s recv %d bytes\n", (char*)sess->name.data, r);

	// the trailing zero not counted
	((char*)sess->xfer.data)[sess->xfer.pos += r] = '\0';

	cmd_buf = sess->xfer;
	aloe_buf_flip(&cmd_buf);

	while (cmd_buf.pos < cmd_buf.lmt) {
		char *cmd, *cmd_end;
		int cmd_len, cmd_remain;
		cli_ret_t cmd_ret;

		cmd_buf.pos += strspn((char*)cmd_buf.data + cmd_buf.pos, aloe_str_sep);
		if (cmd_buf.pos >= cmd_buf.lmt) {
			r = 0;
//			log_d("Drop trailing whitespace\n");
			aloe_buf_clear(&sess->xfer);
			goto finally;
		}

		cmd = (char*)cmd_buf.data + cmd_buf.pos;

		if (!(cmd_end = strpbrk(cmd, aloe_str_sep))) {
			log_d("Expecting command ending: %s\n", cmd);
			break;
		}
		cmd_len = cmd_end - cmd;

		for (cli_ent = cli_lut; cli_ent->name; cli_ent++) {
			if (((int)strlen(cli_ent->name) == cmd_len) &&
					(strncasecmp(cmd, cli_ent->name, cmd_len) == 0)) {
				break;
			}
		}
		if (!cli_ent->name || !cli_ent->proc) {
			r = 0;
			log_e("Unknown cli: %.8s ...\n", cmd);
			aloe_buf_clear(&sess->xfer);
			goto finally;
		}
		cmd_remain = cmd_buf.pos;
		cmd_ret = (*cli_ent->proc)(sess, &cmd_buf, cmd_len);
		if (cmd_ret == cli_ret_drop_input) {
			r = 0;
			aloe_buf_clear(&sess->xfer);
			goto finally;
		}
		if (cmd_ret == cli_ret_fatal) {
			r = -1;
			log_e("Fatal. cli: %.8s ...\n", cmd);
			goto finally;
		}
		if (cmd_ret == cli_ret_consumed) {
			if (cmd_remain == (int)cmd_buf.pos) {
				r = -1;
				log_e("Expected consumed. cli: %.8s ...\n", cmd);
				goto finally;
			}
			continue;
		}
		if (cmd_ret == cli_ret_expect_more) {
			log_d("Expecting more. cli: %.8s ...\n", cmd);
			break;
		}
		r = -1;
		log_e("Invalid. cli: %.8s ...\n", cmd);
		goto finally;
	}

	if (cmd_buf.pos < cmd_buf.lmt) {
		r = 0;
		memmove(sess->xfer.data, (char*)cmd_buf.data + cmd_buf.pos,
				cmd_buf.lmt - cmd_buf.pos);
		sess->xfer.pos = cmd_buf.lmt - cmd_buf.pos;
		goto finally;
	}
	aloe_buf_clear(&sess->xfer);
	r = 0;
finally:
	if (r == 0) {
		if ((sess->conn.ev = aloe_ev_put(ev_ctx, sess->conn.fd,
				&sess_on_read, sess, aloe_ev_flag_read, ALOE_EV_INFINITE,
				0))) {
			return;
		}
		log_e("Failed schedule read ip port\n");
	}
	TAILQ_REMOVE(&ctx->conn, &sess->conn, qent);
	sess_destroy(&sess->conn);
}

static void ctrlport_on_accept(int fd, unsigned ev_noti, void *cbarg) {
	listener_t *listener = (listener_t*)cbarg;
	ctx_t *ctx = (ctx_t*)listener->conn.ctx;
	int r;
	sess_t *sess = NULL;
	union {
		struct sockaddr sa;
		struct sockaddr_in6 sa_in6;
		struct sockaddr_in sa_in;
	} sa_u;
	socklen_t sa_len;

	log_d("%s, ev_noti: %d\n", (char*)listener->name.data, ev_noti);

	if ((sess = (sess_t*)calloc(1, sizeof(*sess))) == NULL ||
			aloe_buf_expand(&sess->name, 100, aloe_buf_flag_none) != 0 ||
			aloe_buf_expand(&sess->xfer, 1200, aloe_buf_flag_none) != 0) {
		r = ENOMEM;
		log_e("Alloc manager for control port session\n");
		// sess->conn.fd == 0
		if (sess) sess_destroy(&sess->conn);
		goto finally;
	}
	aloe_buf_clear(&sess->name);
	aloe_buf_clear(&sess->xfer);

	memset(&sa_u, 0, sizeof(sa_u));
	sa_len = sizeof(sa_u);
	if ((sess->conn.fd = accept(fd, &sa_u.sa, &sa_len)) == -1) {
		r = errno;
		log_e("Failed accept control port session: %s(%d)\n", strerror(r), r);
		sess_destroy(&sess->conn);
		goto finally;
	}
	if ((r = aloe_ip_str(&sa_u.sa, &sess->name, 3)) != 0) {
		log_e("Failed retrieve control port session name\n");
		sess_destroy(&sess->conn);
		goto finally;
	}
	if ((r = aloe_file_nonblock(sess->conn.fd, 1)) != 0) {
		log_e("Failed set control port session nonblock\n");
		sess_destroy(&sess->conn);
		goto finally;
	}
	if (!(sess->conn.ev = aloe_ev_put(ev_ctx, sess->conn.fd,
			&sess_on_read, sess, aloe_ev_flag_read, ALOE_EV_INFINITE,
			0))) {
		r = EIO;
		log_e("Failed schedule read control port session\n");
		sess_destroy(&sess->conn);
		goto finally;
	}

	sess->conn.destroy = &sess_destroy;
	sess->conn.ctx = ctx;
	sess->conn.flag = conn_flag_sess | conn_flag_ip;
	TAILQ_INSERT_TAIL(&ctx->conn, &sess->conn, qent);

	log_i("%s, accepted: %s\n", (char*)listener->name.data,
			(char*)sess->name.data);

	r = 0;
finally:
	if (r != 0) {
		if (sess) {
			if (!sess->conn.ev) aloe_ev_cancel(ev_ctx, sess->conn.ev);
			sess_destroy(&sess->conn);
		}
	}
	if (!(listener->conn.ev = aloe_ev_put(ev_ctx, listener->conn.fd,
			&ctrlport_on_accept, listener, aloe_ev_flag_read, ALOE_EV_INFINITE,
			0))) {
		TAILQ_REMOVE(&ctx->conn, &listener->conn, qent);
		log_e("Failed schedule read ip port\n");
		listener_destroy(&listener->conn);
	}
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
	free(ctx);
}

static void* init(void) {
	ctx_t *ctx = NULL;
	int r;

	if ((ctx = (ctx_t*)malloc(sizeof(*ctx))) == NULL) {
		r = ENOMEM;
		log_e("Alloc instance\n");
		goto finally;
	}
	TAILQ_INIT(&ctx->conn);
	ctx->instance = instance_next++;

	if (ctrl_path && ctrl_path[0]) {
		sess_t *sess;

		if ((sess = (sess_t*)calloc(1, sizeof(*sess))) == NULL ||
				aloe_buf_expand(&sess->name, 100, aloe_buf_flag_none) != 0 ||
				aloe_buf_expand(&sess->xfer, 1200, aloe_buf_flag_none) != 0) {
			r = ENOMEM;
			log_e("Alloc manager for control path\n");
			if (sess) sess_destroy(&sess->conn);
			goto finally;
		}
		aloe_buf_clear(&sess->name);
		aloe_buf_clear(&sess->xfer);

		if ((r = mkfifo(ctrl_path, 0666)) != 0) {
			r = errno;
			log_e("Failed create control path %s, %s\n", ctrl_path, strerror(r));
			sess_destroy(&sess->conn);
			goto finally;
		}
		if ((sess->conn.fd = open(ctrl_path, O_RDWR, 0666)) == -1) {
			r = errno;
			log_e("Failed open control path %s, %s\n", ctrl_path, strerror(r));
			sess_destroy(&sess->conn);
			goto finally;
		}
		if ((r = aloe_file_nonblock(sess->conn.fd, 1)) != 0) {
			log_e("Failed set control path nonblock\n");
			sess_destroy(&sess->conn);
			goto finally;
		}
		if (aloe_buf_printf(&sess->name, "%s", ctrl_path) <= 0) {
			r = EIO;
			log_e("Failed retrieve control path name\n");
			sess_destroy(&sess->conn);
			goto finally;
		}
		if (!(sess->conn.ev = aloe_ev_put(ev_ctx, sess->conn.fd,
				&sess_on_read, sess, aloe_ev_flag_read, ALOE_EV_INFINITE,
				0))) {
			r = EIO;
			log_e("Failed schedule read control path\n");
			sess_destroy(&sess->conn);
			goto finally;
		}
		sess->conn.destroy = &sess_destroy;
		sess->conn.ctx = ctx;
		sess->conn.flag = conn_flag_sess;
		TAILQ_INSERT_TAIL(&ctx->conn, &sess->conn, qent);

		log_i("%s[%d] control path: %s\n", mod_name, ctx->instance,
		        (char*)sess->name.data);
	}

	if (ctrl_port != CTRL_PORT_NONE) {
		listener_t *listener;
		int _ctrl_port = ((ctrl_port == CTRL_PORT_ANY) ? 0 : ctrl_port);
		union {
			struct sockaddr sa;
			struct sockaddr_in sa_in;
		} sa_u;
		socklen_t sa_len;

		if ((listener = (listener_t*)calloc(1, sizeof(*listener))) == NULL ||
				aloe_buf_expand(&listener->name, 100, aloe_buf_flag_none) != 0) {
			r = ENOMEM;
			log_e("Alloc manager for control port\n");
			if (listener) listener_destroy(&listener->conn);
			goto finally;
		}
		aloe_buf_clear(&listener->name);

		memset(&sa_u, 0, sizeof(sa_u));
		sa_u.sa_in.sin_port = htons(_ctrl_port);
		sa_u.sa_in.sin_family = AF_INET;
		sa_u.sa_in.sin_addr = {INADDR_ANY};
		if ((listener->conn.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			r = errno;
			log_e("Failed create socket for control port: %s\n", strerror(r));
			listener_destroy(&listener->conn);
			goto finally;
		}
		r = 1;
		if ((r = setsockopt(listener->conn.fd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(r))) < 0) {
			r = errno;
			log_e("Failed set ip socket reuseaddr for control port, %s(%d)\n",
					strerror(r), r);
			listener_destroy(&listener->conn);
			goto finally;
		}
		if ((r = bind(listener->conn.fd, &sa_u.sa, sizeof(sa_u.sa_in))) < 0) {
			r = errno;
			log_e("Failed bind ip socket, %s(%d)\n", strerror(r), r);
			listener_destroy(&listener->conn);
			goto finally;
		}
		if ((r = aloe_file_nonblock(listener->conn.fd, 1)) != 0) {
			log_e("Failed set ip port nonblock\n");
			listener_destroy(&listener->conn);
			goto finally;
		}
		sa_len = sizeof(sa_u);
		if ((r = getsockname(listener->conn.fd, &sa_u.sa, &sa_len)) != 0) {
			r = errno;
			log_e("Failed retrieve control port address\n");
			listener_destroy(&listener->conn);
			goto finally;
		}
		if ((r = aloe_ip_str(&sa_u.sa, &listener->name, 3)) != 0) {
			log_e("Failed retain ip port\n");
			listener_destroy(&listener->conn);
			goto finally;
		}
		if ((r = listen(listener->conn.fd, 3)) != 0) {
			r = errno;
			log_e("Failed listen on control port\n");
			listener_destroy(&listener->conn);
			goto finally;
		}
		if (!(listener->conn.ev = aloe_ev_put(ev_ctx, listener->conn.fd,
				&ctrlport_on_accept, listener, aloe_ev_flag_read, ALOE_EV_INFINITE,
				0))) {
			r = EIO;
			log_e("Failed schedule read ip port\n");
			listener_destroy(&listener->conn);
			goto finally;
		}

		listener->conn.destroy = &listener_destroy;
		listener->conn.ctx = ctx;
		TAILQ_INSERT_TAIL(&ctx->conn, &listener->conn, qent);

		log_i("%s[%d], Control port: %s\n", mod_name, ctx->instance,
		        (char*)listener->name.data);
	}

	r = 0;
finally:
	if (r != 0) {
		if (ctx) destroy((void*)ctx);
		return NULL;
	}
	return (void*)ctx;
}

static int ioctl(void *_ctx, void *args) {
	ctx_t *ctx = (ctx_t*)_ctx;

	log_d("%s[%d]\n", mod_name, ctx->instance);
	return 0;
}

extern "C" const aloe_mod_t mod_cli = {.name = mod_name, .init = &init,
		.destroy = &destroy, .ioctl = &ioctl};
