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

#include <admin/nl.h>

#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

extern "C" int aloe_nlrt_open(struct sockaddr_nl *sa) {
	struct sockaddr_nl _sa;
	int fd = -1, r;

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
		r = errno;
		log_e("Failed open netlink: %s\n", strerror(r));
		return -1;
	}
	if (!sa) sa = &_sa;
	memset(sa, 0, sizeof(*sa));
	sa->nl_family = AF_NETLINK;
	sa->nl_pid = getpid();
	sa->nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(fd, (struct sockaddr*)sa, sizeof(*sa)) != 0) {
		r = errno;
		log_e("Failed bind netlink: %s\n", strerror(r));
		close(fd);
		return -1;
	}
	return fd;
}

extern "C" int aloe_nlrt_read(aloe_nlpkt_t *nlpkt) {
	struct iovec iov;
	struct msghdr rh;
	int r;

	iov = {nlpkt->buf, sizeof(nlpkt->buf)};
	rh = {&nlpkt->sa, sizeof(nlpkt->sa), &iov, 1, NULL, 0, 0};

	if ((nlpkt->nlpkt_len = recvmsg(nlpkt->fd, &rh, 0)) < 0) {
		r = errno;
		nlpkt->nlpkt_len = 0;

		if (r == EWOULDBLOCK || r == EAGAIN) {
			return 0;
		}
		log_e("recvmsg netlink: %s\n", strerror(r));
		return -1;
	}
	return nlpkt->nlpkt_len;
}

extern "C" int aloe_nlrt_check_ifupdown(aloe_nlpkt_t *nlpkt, int ifce_idx) {
	int r, nlpkt_len = nlpkt->nlpkt_len;
	struct nlmsghdr *nh;

	for (nh = (struct nlmsghdr*)nlpkt->buf; NLMSG_OK(nh, nlpkt_len);
			nh = NLMSG_NEXT(nh, nlpkt_len)) {
		if (nh->nlmsg_type == NLMSG_DONE) {
//			log_d("netlink msg done\n");
			return 0;
		}
		if (nh->nlmsg_type == NLMSG_ERROR) {
			r = ((struct nlmsgerr*)NLMSG_DATA(nh))->error;
			log_e("netlink msg: %s\n", strerror(r));
			return -2;
		}
		if (nh->nlmsg_type == RTM_NEWLINK) {
			const struct ifinfomsg *ifinfo = (struct ifinfomsg*)NLMSG_DATA(nh);
//			const struct rtattr *rtinfo/* = IFLA_RTA(nh)*/;
//			int rtlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifinfo));

//			for (rtinfo = IFLA_RTA(nh); RTA_OK(rtinfo, rtlen);
//					rtinfo = RTA_NEXT(rtinfo, rtlen)) {
//
//			}

			if (ifinfo->ifi_index != ifce_idx) continue;

			if (ifinfo->ifi_flags == 69699) {
				// 69699 -> 0x00011043
				// IFF_RUNNING, IFF_LOWER_UP
//				log_d("netlink noti up ifi_flags 0x%x\n", ifinfo->ifi_flags);
				return 1;
			}

			if (ifinfo->ifi_flags == 4099) {
				// 4099 -> 0x00001003
//				log_d("netlink noti down ifi_flags 0x%x\n", ifinfo->ifi_flags);
				return 2;
			}
		}
	}
	return 0;
}

extern "C" int aloe_nlrt_check_ifaddr(aloe_nlpkt_t *nlpkt, int ifce_idx) {
	int r, nlpkt_len = nlpkt->nlpkt_len;
	struct nlmsghdr *nh;

	for (nh = (struct nlmsghdr*)nlpkt->buf; NLMSG_OK(nh, nlpkt_len);
			nh = NLMSG_NEXT(nh, nlpkt_len)) {
		if (nh->nlmsg_type == NLMSG_DONE) {
//			log_d("netlink msg done\n");
			return 0;
		}
		if (nh->nlmsg_type == NLMSG_ERROR) {
			r = ((struct nlmsgerr*)NLMSG_DATA(nh))->error;
			log_e("netlink msg: %s\n", strerror(r));
			return -2;
		}
		if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
			const struct ifaddrmsg *addrinfo = (struct ifaddrmsg*)NLMSG_DATA(nh);
			const struct rtattr *rtinfo;
			int rtlen;

			if (addrinfo->ifa_index != (unsigned int)ifce_idx) continue;

			for (rtinfo = IFA_RTA(addrinfo), rtlen = IFA_PAYLOAD(nh);
					RTA_OK(rtinfo, rtlen); rtinfo = RTA_NEXT(rtinfo, rtlen)) {
				if (rtinfo->rta_type == IFA_ADDRESS
						|| rtinfo->rta_type == IFA_LOCAL) {
//					log_d("netlink noti addr rta_type 0x%x\n", rtinfo->rta_type);
					return nh->nlmsg_type == RTM_NEWADDR ? 1 : 2;
				}
			}
		}
	}
	return 0;
}
