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

#ifndef _H_ADMIN_NL
#define _H_ADMIN_NL

/** @defgroup ALOE_NL_API Network with netlink
 * @brief Network with netlink.
 */

#include "admin.h"

#include <sys/types.h>
#include <asm/types.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <net/if.h>

/** @addtogroup ALOE_NL_API
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct aloe_nlpkt_rec {
	int fd, nlpkt_len;
	struct sockaddr_nl sa;
	struct nlmsghdr buf[8192 / sizeof(struct nlmsghdr)];
} aloe_nlpkt_t;

int aloe_nlrt_open(struct sockaddr_nl *sa);
int aloe_nlrt_read(aloe_nlpkt_t *nlpkt);
int aloe_nlrt_check_ifupdown(aloe_nlpkt_t *nlpkt, int ifce_idx);
int aloe_nlrt_check_ifaddr(aloe_nlpkt_t *nlpkt, int ifce_idx);

#ifdef __cplusplus
} /* extern "C" */
#endif

/** @} ALOE_NL_API */

#endif /* _H_ADMIN_NL */
