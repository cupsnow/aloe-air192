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

#include "priv.h"

#define TEST_AIR192 1

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/times.h>
#include <syslog.h>
#include <sys/random.h>
#include <admin/unitest.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <getopt.h>
#include <net/if.h>

#if defined(TEST_AIR192) && TEST_AIR192
#include <admin/air192.h>
#include <admin/sa7715.h>
#endif

#include <cjson/cJSON.h>

extern "C" {

#include <libavutil/frame.h>
#include <libavutil/mem.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include <libavutil/opt.h>
#include <libavutil/channel_layout.h>
#include <libavutil/samplefmt.h>
#include <libswresample/swresample.h>

}

#include <admin/nl.h>

#define DECL_TEST(_n, _args...) \
	__attribute__((unused)) \
	static aloe_test_flag_t _n (aloe_test_case_t *test_case, ##_args)

static struct {
	int ondevice;
	char quit;
	void *ev_ctx;
	struct {
		aloe_nlpkt_t nlpkt;
		admin_evconn_t conn;
		int ifce_idx;
	} *nlrt1;
} impl = {};

static void nlrt1_destroy(void) {
	if (impl.nlrt1->nlpkt.fd != -1) close(impl.nlrt1->nlpkt.fd);
	free(impl.nlrt1);
	impl.nlrt1 = NULL;
}

static void nlrt1_on_read1(int fd, unsigned ev_noti, void *cbarg) {
	int r;
	struct nlmsghdr *nh;

	if (impl.nlrt1 != cbarg) {
		r = -1;
		log_e("sanity check invalid argument\n");
		goto finally;
	}
	if (ev_noti & aloe_ev_flag_read) {
		if ((r = aloe_nlrt_read(&impl.nlrt1->nlpkt)) < 0) {
			log_e("Failed read netlink\n");
			goto finally;
		}
		if (r == 0) {
			log_d("recvmsg netlink: EOF\n");
			goto finally;
		}

		if ((r = aloe_nlrt_check_ifupdown(&impl.nlrt1->nlpkt,
				impl.nlrt1->ifce_idx)) < 0) {
			log_d("netlink noti err\n");
			goto finally;
		}
		if (r == 1) {
			log_d("netlink noti up\n");
		} else if (r == 2) {
			log_d("netlink noti down\n");
		}

		if ((r = aloe_nlrt_check_ifaddr(&impl.nlrt1->nlpkt,
				impl.nlrt1->ifce_idx)) < 0) {
			log_d("netlink noti err\n");
			goto finally;
		}
		if (r == 1) {
			log_d("netlink noti addr new\n");
		} else if (r == 2) {
			log_d("netlink noti addr del\n");
		}

	}
	r = 0;
finally:
	if (r == 0) {
		if ((impl.nlrt1->conn.ev = aloe_ev_put(impl.ev_ctx, impl.nlrt1->nlpkt.fd,
				&nlrt1_on_read1, impl.nlrt1, aloe_ev_flag_read, ALOE_EV_INFINITE,
				0))) {
			return;
		}
		log_e("Failed schedule read nlrt1 event\n");
	}
	nlrt1_destroy();
	impl.quit = 1;
}

static int nlrt1_test1(void) {
	int r;

	if (!(impl.nlrt1 = (typeof(impl.nlrt1))malloc(sizeof(*impl.nlrt1)))) {
		r = ENOMEM;
		log_e("alloc nlrt1\n");
		goto finally;
	}
	memset(impl.nlrt1, 0, sizeof(*impl.nlrt1));
	impl.nlrt1->nlpkt.fd = -1;
	impl.nlrt1->conn.fd = -1;
	impl.nlrt1->ifce_idx = (int)if_nametoindex("wlan0");

	if ((impl.nlrt1->nlpkt.fd = aloe_nlrt_open(&impl.nlrt1->nlpkt.sa)) == -1) {
		r = EIO;
		log_e("open nlrt\n");
		goto finally;
	}
	impl.nlrt1->conn.fd = impl.nlrt1->nlpkt.fd;
	if (!(impl.nlrt1->conn.ev = aloe_ev_put(impl.ev_ctx, impl.nlrt1->nlpkt.fd,
			&nlrt1_on_read1, impl.nlrt1, aloe_ev_flag_read, ALOE_EV_INFINITE,
			0))) {
		r = EIO;
		log_e("Failed schedule read nlrt1 event\n");
		goto finally;
	}
	r = 0;
finally:
	if (r != 0) {
		if (impl.nlrt1) nlrt1_destroy();
	}
	return r;
}

DECL_TEST(test1_nlrt1) {
	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;

	test_case->flag_result = aloe_test_flag_result_failed_suite;

	ALOE_TEST_ASSERT_THEN((impl.ev_ctx = aloe_ev_init()),
			test_case, failed, {
		goto finally;
	});

	nlrt1_test1();

    while (!impl.quit) {
		aloe_ev_once(impl.ev_ctx);
//    	log_d("enter\n");
	}

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (impl.ev_ctx) {
		aloe_ev_destroy(impl.ev_ctx);
	}

	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	return test_case->flag_result;
}

static int test_reporter(unsigned lvl, const char *tag, long lno,
		const char *fmt, ...) {
	va_list va;

	printf("%s #%d ", tag, (int)lno);
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
	return 0;
}

static const char opt_short[] = "hv";
enum {
	opt_key_ondevice = 0x201,
};
static struct option opt_long[] = {
	{"help", no_argument, NULL, 'h'},
	{"verbose", no_argument, NULL, 'v'},
	{"ondevice", no_argument, NULL, opt_key_ondevice},
};

static int show_help(const char *fn) {
	fprintf(stdout, ""
"USAGE\n"
"  %s [OPTIONS]\n"
"\n"
"OPTIONS\n"
"  -h, --help     Show this help\n"
"  -v, --verbose  More output\n"
"  --ondevice     Run on sa7715\n"
"\n",
(fn ? fn : "PROG"));
	return 0;
}

int main(int argc, char **argv) {
	int opt_op, opt_idx;
	aloe_test_t test_base;
	aloe_test_report_t test_report;

	for (int i = 0; i < argc; i++) {
		log_d("argv[%d/%d]: %s\n", i + 1, argc, argv[i]);
	}

	optind = 0;
	while ((opt_op = getopt_long(argc, argv, opt_short, opt_long,
			&opt_idx)) != -1) {
		if (opt_op == 'h') {
			show_help(argv[0]);
			continue;
		}
		if (opt_op == 'v') {
			continue;
		}
		if (opt_op == opt_key_ondevice) {
			impl.ondevice = 1;
			continue;
		}
	}

	for (opt_idx = optind; opt_idx < argc; opt_idx++) {
		log_d("argv[%d/%d]: %s\n", opt_idx + 1, argc, argv[opt_idx]);
	}

	if (!impl.ondevice && aloe_file_size("/etc/sa7715.json", 0) >= 0) {
		impl.ondevice = 1;
	}

	ALOE_TEST_INIT(&test_base, "Test1");
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/cjson1", &test1_jcfg1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ledconf1", &test1_ledconf1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/mqcli1", &test1_mqcli1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/wpacli1", &test1_wpacli1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/wpacli1", &test1_wpacfg1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/offsetof1", &test1_offsetof1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ffaac1", &test1_ffaac1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ffaac1", &test1_ffaac2);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/net1", &test1_net1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ini1", &test1_ini1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/str1", &test1_str1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/swres1", &test1_swres1);
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/nlrt1", &test1_nlrt1);

	ALOE_TEST_RUN(&test_base);

	memset(&test_report, 0, sizeof(test_report));
	test_report.log = &test_reporter;
	aloe_test_report(&test_base, &test_report);

	printf("Report result %s, test suite[%s]"
			"\n  Summary total cases PASS: %d, FAILED: %d(PREREQUISITE: %d), TOTAL: %d\n",
			ALOE_TEST_RESULT_STR(test_base.runner.flag_result, "UNKNOWN"),
			test_base.runner.name,
			test_report.pass, test_report.failed,
			test_report.failed_prereq, test_report.total);

	return 0;
}

DECL_TEST(test1_template1) {
	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;

	ALOE_TEST_ASSERT_THEN(0,
			test_case, failed, {
		goto finally;
	});
	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	return test_case->flag_result;
}
