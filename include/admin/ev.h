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

#ifndef _H_ALOE_EV
#define _H_ALOE_EV

/** @defgroup ALOE_EV_API Event driven API
 * @brief Event driven API.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup ALOE_EV_API
 * @{
 */

/** Enumeration about event trigger. */
typedef enum aloe_ev_flag_enum {
	aloe_ev_flag_read = (1 << 0), /**< Readable. */
	aloe_ev_flag_write = (1 << 1), /**< Writable. */
	aloe_ev_flag_except = (1 << 2),/**< Exception. */
	aloe_ev_flag_time = (1 << 3), /**< Timeout. */
} aloe_ev_flag_t;

#define _ALOE_EV_FMT "%s%s%s%s(0x%x)"
#define _ALOE_EV_ARG(_ev) \
	((_ev) & aloe_ev_flag_read ? "R" : "") \
	, ((_ev) & aloe_ev_flag_write ? "W" : "") \
	, ((_ev) & aloe_ev_flag_except ? "E" : "") \
	, ((_ev) & aloe_ev_flag_time ? "T" : "") \
	, _ev

/** Indicate no timeout. */
#define ALOE_EV_INFINITE ((unsigned long)-1)

/** Callback for notify event to user. */
typedef void (*aloe_ev_noti_cb_t)(int fd, unsigned ev_noti, void *cbarg);

/** Put the event into internal process. */
void* aloe_ev_put(void *ctx, int fd, aloe_ev_noti_cb_t cb, void *cbarg,
		unsigned ev_wait, unsigned long sec, unsigned long usec);

void* aloe_ev_get(void *ctx, int fd, aloe_ev_noti_cb_t cb);

/** Remove the event from internal process. */
void aloe_ev_cancel(void *ctx, void *ev);

/** Process a loop. */
int aloe_ev_once(void *ctx);

/** Initialize context. */
void* aloe_ev_init(void);

/** Free context. */
void aloe_ev_destroy(void *ctx);

/** @} ALOE_EV_API */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* _H_ALOE_EV */
