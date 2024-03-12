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

#include <unistd.h>
#include <fcntl.h>
#include <time.h>

 /** Minimal due time for select(), value in micro-seconds. */
#define ALOE_EV_PREVENT_BUSY_WAITING 1001ul

/** Notify event to user. */
typedef struct aloe_ev_ctx_noti_rec {
	int fd;
	aloe_ev_noti_cb_t cb; /**< Callback to user. */
	void *cbarg; /**< Callback argument. */
	unsigned ev_wait; /**< Event to wait. */
	struct timespec due; /**< Monotonic timeout. */
	unsigned ev_noti; /**< Notified event. */
	TAILQ_ENTRY(aloe_ev_ctx_noti_rec) qent;
} aloe_ev_ctx_noti_t;

/** Queue of aloe_ev_noti_t. */
typedef TAILQ_HEAD(aloe_ev_ctx_noti_queue_rec, aloe_ev_ctx_noti_rec) aloe_ev_ctx_noti_queue_t;

/** FD for select(). */
typedef struct aloe_ev_ctx_fd_rec {
	int fd; /**< FD to monitor. */
	aloe_ev_ctx_noti_queue_t noti_q; /**< Queue of aloe_ev_noti_t for this FD. */
	TAILQ_ENTRY(aloe_ev_ctx_fd_rec) qent;
} aloe_ev_ctx_fd_t;

/** Queue of aloe_ev_fd_t. */
typedef TAILQ_HEAD(aloe_ev_ctx_fd_queue_rec, aloe_ev_ctx_fd_rec) aloe_ev_ctx_fd_queue_t;

/** Information about control flow and running context. */
typedef struct aloe_ev_ctx_rec {
	aloe_ev_ctx_fd_queue_t fd_q; /**< Queue to select(). */
	aloe_ev_ctx_fd_queue_t spare_fd_q; /**< Queue for cached memory. */
	aloe_ev_ctx_noti_queue_t noti_q; /**< Queue for ready to notify. */
	aloe_ev_ctx_noti_queue_t spare_noti_q; /**< Queue for cached memory. */
} aloe_ev_ctx_t;

static aloe_ev_ctx_fd_t* fd_q_find(aloe_ev_ctx_fd_queue_t *q, int fd, char pop) {
	aloe_ev_ctx_fd_t *ev_fd;

	if (fd == -1) {
		if ((ev_fd = TAILQ_FIRST(q)) && pop) {
			TAILQ_REMOVE(q, ev_fd, qent);
		}
		return ev_fd;
	}

	TAILQ_FOREACH(ev_fd, q, qent) {
		if (ev_fd->fd == fd) return ev_fd;
	}
	return NULL;
}

static aloe_ev_ctx_noti_t* noti_q_find(aloe_ev_ctx_noti_queue_t *q,
		const aloe_ev_ctx_noti_t *_ev_noti, char pop) {
	aloe_ev_ctx_noti_t *ev_noti;

	if (!_ev_noti) {
		if ((ev_noti = TAILQ_FIRST(q)) && pop) {
			TAILQ_REMOVE(q, ev_noti, qent);
		}
		return ev_noti;
	}

	TAILQ_FOREACH(ev_noti, q, qent) {
		if (ev_noti == _ev_noti) return ev_noti;
	}
	return NULL;
}

void* aloe_ev_get(void *_ctx, int fd, aloe_ev_noti_cb_t cb) {
	aloe_ev_ctx_t *ctx = (aloe_ev_ctx_t*)_ctx;
	aloe_ev_ctx_fd_t *ev_fd;
	aloe_ev_ctx_noti_t *ev_noti;

	if (!(ev_fd = fd_q_find(&ctx->fd_q, fd, 0))) return NULL;

	TAILQ_FOREACH(ev_noti, &ev_fd->noti_q, qent) {
		if (ev_noti->cb == cb) return (void*)ev_noti;
	}
	return NULL;
}

void* aloe_ev_put(void *_ctx, int fd, aloe_ev_noti_cb_t cb, void *cbarg,
		unsigned ev_wait, unsigned long sec, unsigned long usec) {
	aloe_ev_ctx_t *ctx = (aloe_ev_ctx_t*)_ctx;
	aloe_ev_ctx_fd_t *ev_fd;
	aloe_ev_ctx_noti_t *ev_noti;
	struct timespec due;
	struct {
		unsigned ev_fd_inq: 1;
		unsigned ev_noti_inq: 1;
	} flag = {0};

	if (sec == ALOE_EV_INFINITE) {
		due.tv_sec = ALOE_EV_INFINITE;
	} else {
		if ((clock_gettime(CLOCK_MONOTONIC, &due)) != 0) {
			int r = errno;
			log_e("monotonic timestamp: %s(%d)\n", strerror(r), r);
			return NULL;
		}
		ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, sec, usec * 1000ul,
		        due.tv_sec, due.tv_nsec, 1000000000ul);
	}

	if ((ev_fd = fd_q_find(&ctx->fd_q, fd, 0))) {
		flag.ev_fd_inq = 1;
	} else if (!(ev_fd = fd_q_find(&ctx->spare_fd_q, -1, 1)) && !(ev_fd =
	        malloc(sizeof(*ev_fd)))) {
		log_e("malloc ev_fd\n");
		return NULL;
	}

	if ((ev_noti = noti_q_find(&ctx->spare_noti_q, NULL, 1))) {
		flag.ev_noti_inq = 1;
	} else if (!(ev_noti = malloc(sizeof(*ev_noti)))) {
		log_e("malloc ev_noti\n");
		if (!flag.ev_fd_inq) {
			TAILQ_INSERT_TAIL(&ctx->spare_fd_q, ev_fd, qent);
		}
		return NULL;
	}

	if (!flag.ev_fd_inq) {
		TAILQ_INIT(&ev_fd->noti_q);
		TAILQ_INSERT_TAIL(&ctx->fd_q, ev_fd, qent);
		ev_fd->fd = fd;
	}
	TAILQ_INSERT_TAIL(&ev_fd->noti_q, ev_noti, qent);
	ev_noti->fd = fd;
	ev_noti->cb = cb;
	ev_noti->cbarg = cbarg;
	ev_noti->ev_wait = ev_wait;
	ev_noti->due = due;
	return (void*)ev_noti;
}

void aloe_ev_cancel(void *_ctx, void *ev) {
	aloe_ev_ctx_t *ctx = (aloe_ev_ctx_t*)_ctx;
	aloe_ev_ctx_noti_t *ev_noti = (aloe_ev_ctx_noti_t*)ev;
	aloe_ev_ctx_fd_t *ev_fd;

	if ((ev_fd = fd_q_find(&ctx->fd_q, ev_noti->fd, 0))
	        && noti_q_find(&ev_fd->noti_q, ev_noti, 1)) {
		TAILQ_INSERT_TAIL(&ctx->spare_noti_q, ev_noti, qent);
		if (TAILQ_EMPTY(&ev_fd->noti_q)) {
			TAILQ_REMOVE(&ctx->fd_q, ev_fd, qent);
			TAILQ_INSERT_TAIL(&ctx->spare_fd_q, ev_fd, qent);
		}
		return;
	}

	if (noti_q_find(&ctx->noti_q, ev_noti, 1)) {
		TAILQ_INSERT_TAIL(&ctx->spare_noti_q, ev_noti, qent);
		return;
	}
}

int aloe_ev_once(void *_ctx) {
	aloe_ev_ctx_t *ctx = (aloe_ev_ctx_t*)_ctx;
	int r, fdmax = -1;
	fd_set rdset, wrset, exset;
	aloe_ev_ctx_noti_t *ev_noti, *ev_noti_safe;
	aloe_ev_ctx_fd_t *ev_fd, *ev_fd_safe;
	struct timeval sel_tmr = {.tv_sec = ALOE_EV_INFINITE};
	struct timespec ts, *due = NULL;

	FD_ZERO(&rdset); FD_ZERO(&wrset); FD_ZERO(&exset);

	TAILQ_FOREACH(ev_fd, &ctx->fd_q, qent) {
		if (ev_fd->fd != -1 && ev_fd->fd > fdmax) fdmax = ev_fd->fd;
		TAILQ_FOREACH(ev_noti, &ev_fd->noti_q, qent) {
			if (ev_fd->fd != -1) {
				if (ev_noti->ev_wait & aloe_ev_flag_read) {
					FD_SET(ev_fd->fd, &rdset);
				}
				if (ev_noti->ev_wait & aloe_ev_flag_write) {
					FD_SET(ev_fd->fd, &wrset);
				}
				if (ev_noti->ev_wait & aloe_ev_flag_except) {
					FD_SET(ev_fd->fd, &exset);
				}
			}
			if (ev_noti->due.tv_sec != ALOE_EV_INFINITE && (!due
					|| ALOE_TIMESEC_CMP(ev_noti->due.tv_sec, ev_noti->due.tv_nsec,
							due->tv_sec, due->tv_nsec) < 0)) {
				due = &ev_noti->due;
			}
		}
	}

	// convert due for select()
	if (due) {
		if ((clock_gettime(CLOCK_MONOTONIC, &ts)) != 0) {
			r = errno;
			log_e("Failed to get time: %s(%d)\n", strerror(r), r);
			return r;
		}
		if (ALOE_TIMESEC_CMP(ts.tv_sec, ts.tv_nsec,
				due->tv_sec, due->tv_nsec) < 0) {
			ALOE_TIMESEC_SUB(due->tv_sec, due->tv_nsec,
					ts.tv_sec, ts.tv_nsec, ts.tv_sec, ts.tv_nsec, 1000000000ul);
			sel_tmr.tv_sec = ts.tv_sec; sel_tmr.tv_usec = ts.tv_nsec / 1000ul;
		} else {
			sel_tmr.tv_sec = 0; sel_tmr.tv_usec = 0;
		}
	} else if (fdmax == -1) {
		// infinite waiting
		sel_tmr.tv_sec = 0; sel_tmr.tv_usec = 0;
	}

#if ALOE_EV_PREVENT_BUSY_WAITING
	if (sel_tmr.tv_sec == 0 && sel_tmr.tv_usec < ALOE_EV_PREVENT_BUSY_WAITING) {
		sel_tmr.tv_usec = ALOE_EV_PREVENT_BUSY_WAITING;
	}
#endif

	if ((fdmax = select(fdmax + 1, &rdset, &wrset, &exset,
			(sel_tmr.tv_sec == ALOE_EV_INFINITE ? NULL : &sel_tmr))) < 0) {
		r = errno;
//		if (r == EINTR) {
//			log_d("Interrupted when wait IO: %s(%d)\n", strerror(r), r);
//		} else {
			log_e("Failed to wait IO: %s(%d)\n", strerror(r), r);
//		}
		return r;
	}

	if ((r = clock_gettime(CLOCK_MONOTONIC, &ts)) != 0) {
		r = errno;
		log_e("Failed to get time: %s(%d)\n", strerror(r), r);
		return r;
	}

	TAILQ_FOREACH_SAFE(ev_fd, &ctx->fd_q, qent, ev_fd_safe) {
		unsigned triggered = 0;

		if (fdmax > 0 && ev_fd->fd != -1) {
			if (FD_ISSET(ev_fd->fd, &rdset)) {
				triggered |= aloe_ev_flag_read;
				fdmax--;
			}
			if (FD_ISSET(ev_fd->fd, &wrset)) {
				triggered |= aloe_ev_flag_write;
				fdmax--;
			}
			if (FD_ISSET(ev_fd->fd, &exset)) {
				triggered |= aloe_ev_flag_except;
				fdmax--;
			}
		}
		TAILQ_FOREACH_SAFE(ev_noti, &ev_fd->noti_q, qent, ev_noti_safe) {
			if (!(ev_noti->ev_noti = triggered & ev_noti->ev_wait)
					&& ev_noti->due.tv_sec != ALOE_EV_INFINITE
					&& ALOE_TIMESEC_CMP(ev_noti->due.tv_sec, ev_noti->due.tv_nsec,
							ts.tv_sec, ts.tv_nsec) <= 0) {
				ev_noti->ev_noti |= aloe_ev_flag_time;
			}
			if (ev_noti->ev_noti) {
				TAILQ_REMOVE(&ev_fd->noti_q, ev_noti, qent);
				TAILQ_INSERT_TAIL(&ctx->noti_q, ev_noti, qent);
			}
		}
		if (TAILQ_EMPTY(&ev_fd->noti_q)) {
			TAILQ_REMOVE(&ctx->fd_q, ev_fd, qent);
			TAILQ_INSERT_TAIL(&ctx->spare_fd_q, ev_fd, qent);
		}
	}

	fdmax = 0;
	while ((ev_noti = TAILQ_FIRST(&ctx->noti_q))) {
		int fd = ev_noti->fd;
		aloe_ev_noti_cb_t cb = ev_noti->cb;
		void *cbarg = ev_noti->cbarg;
		unsigned triggered = ev_noti->ev_noti;

		fdmax++;
		TAILQ_REMOVE(&ctx->noti_q, ev_noti, qent);
		TAILQ_INSERT_TAIL(&ctx->spare_noti_q, ev_noti, qent);
		(*cb)(fd, triggered, cbarg);
	}
	return fdmax;
}

void* aloe_ev_init(void) {
	aloe_ev_ctx_t *ctx;

	if (!(ctx = malloc(sizeof(*ctx)))) {
		log_e("malloc ev ctx\n");
		return NULL;
	}
	TAILQ_INIT(&ctx->fd_q);
	TAILQ_INIT(&ctx->spare_fd_q);
	TAILQ_INIT(&ctx->noti_q);
	TAILQ_INIT(&ctx->spare_noti_q);
	return (void*)ctx;
}

void aloe_ev_destroy(void *_ctx) {
	aloe_ev_ctx_t *ctx = (aloe_ev_ctx_t*)_ctx;
	aloe_ev_ctx_noti_t *ev_noti;
	aloe_ev_ctx_fd_t *ev_fd;

	while ((ev_fd = TAILQ_FIRST(&ctx->fd_q))) {
		TAILQ_REMOVE(&ctx->fd_q, ev_fd, qent);
		while ((ev_noti = TAILQ_FIRST(&ev_fd->noti_q))) {
			TAILQ_REMOVE(&ev_fd->noti_q, ev_noti, qent);
			free(ev_noti);
		}
		free(ev_fd);
	}
	while ((ev_fd = TAILQ_FIRST(&ctx->spare_fd_q))) {
		TAILQ_REMOVE(&ctx->fd_q, ev_fd, qent);
		free(ev_fd);
	}
	while ((ev_noti = TAILQ_FIRST(&ctx->noti_q))) {
		TAILQ_REMOVE(&ctx->noti_q, ev_noti, qent);
		free(ev_noti);
	}
	while ((ev_noti = TAILQ_FIRST(&ctx->spare_noti_q))) {
		TAILQ_REMOVE(&ctx->spare_noti_q, ev_noti, qent);
		free(ev_noti);
	}
	free(ctx);
}
