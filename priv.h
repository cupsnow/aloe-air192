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

#ifndef _H_ALOE_EV_PRIV
#define _H_ALOE_EV_PRIV

/** @defgroup ALOE_EV_INTERNAL Internal
 * @brief Internal utility.
 *
 * @defgroup ALOE_EV_MISC Miscellaneous
 * @ingroup ALOE_EV_INTERNAL
 * @brief Trivial operation.
 *
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>

#include <admin/ev.h>
#include <admin/air192.h>

#ifdef __cplusplus
extern "C" {
#endif

#define log_m(_lvl, _fmt, _args...) aloe_log_printf((char*)_lvl, __func__, __LINE__, _fmt, ##_args)
#define log_e(_args...) log_m(aloe_log_level_err, ##_args)
#define log_i(_args...) log_m(aloe_log_level_info, ##_args)
#define log_d(_args...) log_m("Debug ", ##_args)
#define log_v(_args...) log_m("verbose ", ##_args)

extern void *ev_ctx;
extern const char *ctrl_path;

#define CTRL_PORT_ANY 0
#define CTRL_PORT_NONE -1
extern int ctrl_port;

#define GPIO_NUM_NONE -1

extern int gpio_restkey, gpio_restdur;
extern const char *gpio_restcmd, *gpio_restkeyhook;

extern const char *wpasup_ctrldir, *wificfg_ifce, *wificfg_ctrlpath;

#define HTTP_ENDL "\r\n"
#define HTTP_RC_OK 200

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#successful_responses
// the request has been accepted for processing, but the processing has not been completed
#define HTTP_RC_ACCEPTED 202

#define HTTP_RC_INTERNAL_SERVER_ERROR 500

void admin_shutdown(void);

typedef struct admin_evconn_rec {
	int fd;
	void *ev, *ctx;
	unsigned flag;
	void (*destroy)(struct admin_evconn_rec*);
	TAILQ_ENTRY(admin_evconn_rec) qent;
} admin_evconn_t;
typedef TAILQ_HEAD(admin_evconn_queue_rec, admin_evconn_rec) admin_evconn_queue_t;

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* _H_ALOE_EV_PRIV */
