/* $Id$
 *
 * Copyright 2023, Dexatek Technology Ltd.
 * This is proprietary information of Dexatek Technology Ltd.
 * All Rights Reserved. Reproduction of this documentation or the
 * accompanying programs in any manner whatsoever without the written
 * permission of Dexatek Technology Ltd. is strictly forbidden.
 *
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

#include <cjson/cJSON.h>

static int instance_next = 0;
static char mod_name[] = "template1";

typedef struct ctx_rec {
	int instance;
	void *dev;
	admin_evconn_queue_t conn;
} ctx_t;

typedef struct sess1_rec {
	admin_evconn_t conn;
	struct timeval ts0;
} sess1_t;

static void sess1_destroy(admin_evconn_t *conn) {
	sess1_t *sess = aloe_container_of(conn, sess1_t, conn);

	free(sess);
}

static void sess1_on_read(int fd, unsigned ev_noti, void *cbarg) {
	sess1_t *sess = (sess1_t*)cbarg;
	ctx_t *ctx = (ctx_t*)sess->conn.ctx;
	int r;
	struct timeval ts;
	unsigned long tv_ms = 1000;

	if ((r = gettimeofday(&ts, NULL)) != 0) {
		r = errno;
		log_e("Failed get current time: %s\n", strerror(r));
		goto finally;
	}

	if (ev_noti & aloe_ev_flag_read) {
		log_e("unexpected read event: %s\n", mod_name);
	}

	do {
		unsigned long td;

		if (sess->ts0.tv_sec == 0) {
			log_d("first triggered\n");
			sess->ts0 = ts;
			break;
		}

		// cal next sch before timeout
		if (ALOE_TIMESEC_CMP(sess->ts0.tv_sec, sess->ts0.tv_usec,
				ts.tv_sec, ts.tv_usec) > 0) {
			td = ALOE_TIMESEC_TD1(sess->ts0.tv_sec, sess->ts0.tv_usec,
					ts.tv_sec, ts.tv_usec,
					1000000ul) / 1000ul;
			if (tv_ms == ALOE_EV_INFINITE || tv_ms > td) tv_ms = td;
			break;
		}

		if (sess->ts0.tv_sec == 0) {
			log_d("first triggered\n");
		} else {
			log_d("timeout triggered\n");
		}

		ALOE_TIMESEC_ADD(ts.tv_sec, ts.tv_usec,
				tv_ms / 1000, tv_ms % 1000,
				sess->ts0.tv_sec, sess->ts0.tv_usec, 1000000l);

	} while(0);
	r = 0;
finally:
	if (r == 0) {
		if ((sess->conn.ev = aloe_ev_put(ev_ctx, sess->conn.fd,
				&sess1_on_read, sess, aloe_ev_flag_read,
				((tv_ms == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE : tv_ms / 1000ul),
				((tv_ms == ALOE_EV_INFINITE) ? 0 : (tv_ms % 1000ul) * 1000ul)))) {
			return;
		}
		log_e("Failed schedule read sus request\n");
	}
	TAILQ_REMOVE(&ctx->conn, &sess->conn, qent);
	sess1_destroy(&sess->conn);
}

static void destroy(void *_ctx) {
	ctx_t *ctx = (ctx_t*)_ctx;
	admin_evconn_t *conn;

	log_d("%s[%d]\n", mod_name, ctx->instance);

	while ((conn = TAILQ_FIRST(&ctx->conn))) {
		TAILQ_REMOVE(&ctx->conn, conn, qent);
		if (!conn->ev) aloe_ev_cancel(ev_ctx, conn->ev);
		if (conn->destroy) (*conn->destroy)(conn);
	}
	if (ctx->dev) { log_d("destroy dummy dev\n"); };
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
	ctx->dev = NULL;

	{
		sess1_t *sess;
		struct timeval ts;

		if ((r = gettimeofday(&ts, NULL)) != 0) {
			r = errno;
			log_e("Failed get current time: %s\n", strerror(r));
			goto finally;
		}

		if ((sess = (sess1_t*)malloc(sizeof(*sess))) == NULL) {
			r = ENOMEM;
			log_e("Alloc manager for template1\n");
//			if (sess) sess1_destroy(&sess->conn);
			goto finally;
		}
		memset(sess, 0, sizeof(sess1_t));
		sess->conn.fd = -1;

		if (!(sess->conn.ev = aloe_ev_put(ev_ctx, sess->conn.fd,
				&sess1_on_read, sess, aloe_ev_flag_read, 1, 0))) {
			r = EIO;
			log_e("Failed schedule read template1 request\n");
			sess1_destroy(&sess->conn);
			goto finally;
		}
		sess->conn.destroy = &sess1_destroy;
		sess->conn.ctx = ctx;
		TAILQ_INSERT_TAIL(&ctx->conn, &sess->conn, qent);

		log_i("%s[%d] template1\n", mod_name, ctx->instance);
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

extern "C" const aloe_mod_t mod_template1 = {.name = mod_name, .init = &init,
		.destroy = &destroy, .ioctl = &ioctl};
