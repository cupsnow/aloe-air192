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
#include <linux/perf_event.h>
#include <pthread.h>
#include <getopt.h>

#if defined(TEST_AIR192) && TEST_AIR192
#include <admin/air192.h>
#include <admin/sa7715.h>
#endif

//#include <cjson/cJSON.h>

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

#define DECL_TEST(_n, _args...) \
	__attribute__((unused)) \
	static aloe_test_flag_t _n (aloe_test_case_t *test_case, ##_args)

static struct {
	int ondevice;
} impl;

DECL_TEST(test1_ssid1) {
	ALOE_TEST_ASSERT_THEN(1,
			test_case, failed, {
		goto finally;
	});
	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	return test_case->flag_result;
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

static int test_reporter(unsigned lvl, const char *tag, long lno,
		const char *fmt, ...) {
	va_list va;

	printf("%s #%d ", tag, (int)lno);
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
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
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ssid1", &test1_ssid1);

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
