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
#include <admin/unitest.h>

aloe_test_flag_t aloe_test_runner(aloe_test_case_t *suite_runner) {
	aloe_test_t *suite = aloe_container_of(suite_runner, aloe_test_t, runner);
	aloe_test_case_t *case_runner;

	// The most use-case for setup on suite
	if ((suite_runner->flag_result == aloe_test_flag_result_pass) && suite->setup) {
		log_d("Setup test suite[%s]\n", suite_runner->name);
		if ((suite->setup)(suite) != aloe_test_flag_result_pass) {
			suite_runner->flag_result = aloe_test_flag_result_failed_suite;
			if (!suite_runner->cause) suite_runner->cause = "SETUP";
			log_e("Setup failed test suite[%s]\n", suite_runner->name);
		}
	} else {
		log_d("Start test suite[%s]\n", suite_runner->name);
	}

	TAILQ_FOREACH(case_runner, &suite->cases, qent) {

		// Populate prerequisite to contained suites and cases.
		if ((suite_runner->flag_result == aloe_test_flag_result_failed_suite) ||
				(suite_runner->flag_result == aloe_test_flag_result_prerequisite)) {
			case_runner->flag_result = aloe_test_flag_result_prerequisite;
			case_runner->cause = "PREREQUISITE";
			log_d("%s for test %s[%s]\n",
					ALOE_TEST_RESULT_STR(case_runner->flag_result, "UNKNOWN result"),
					ALOE_TEST_CLASS_STR(case_runner->flag_class, "UNKNOWN class"),
					case_runner->name);

			if (case_runner->flag_class == aloe_test_flag_class_suite) {
				(case_runner->run)(case_runner);
			}
			continue;
		}

		// Test suite failure do not break containing suite.
		if (case_runner->flag_class == aloe_test_flag_class_suite) {
			case_runner->flag_result = (case_runner->run)(case_runner);
			if (case_runner->flag_result != aloe_test_flag_result_pass) {
				if (!case_runner->cause) case_runner->cause = "RUN";
				if (suite_runner->flag_result == aloe_test_flag_result_pass) {
					suite_runner->flag_result = aloe_test_flag_result_failed;
					suite_runner->cause = case_runner->name;
				}
			}
			continue;
		}

		log_d("Start test case[%s]\n", case_runner->name);
		if ((case_runner->flag_result = (case_runner->run)(case_runner)) !=
				aloe_test_flag_result_pass) {
			if (!case_runner->cause) case_runner->cause = "RUN";
			log_d("%s for test case[%s]\n"
					"  Cause: %s\n",
					ALOE_TEST_RESULT_STR(case_runner->flag_result, "UNKNOWN result"),
					case_runner->name, case_runner->cause);
			if (suite_runner->flag_result < case_runner->flag_result) {
				suite_runner->flag_result = case_runner->flag_result;
				suite_runner->cause = case_runner->name;
				log_d("%s for test suite[%s]\n"
						"  Cause: %s\n",
						ALOE_TEST_RESULT_STR(suite_runner->flag_result, "UNKNOWN result"),
						suite_runner->name, suite_runner->cause);
			}
		}
		log_d("Stopped test case[%s]\n", case_runner->name);
	}

	if (suite->shutdown) {
		(suite->shutdown)(suite);
		log_d("Shutdown test suite[%s]\n", suite_runner->name);
	} else {
		log_d("Stopped test suite[%s]\n", suite_runner->name);
	}

	return suite_runner->flag_result;
}

int aloe_test_report(aloe_test_t *suite, aloe_test_report_t *report_runner) {
#define report_log(_lvl, _args...) if (report_runner->log) { \
		(*report_runner->log)((unsigned)(_lvl), __func__, __LINE__, _args); \
}
#define report_log_d(_args...) report_log(aloe_log_level_debug, _args)
#define report_log_e(_args...) report_log(aloe_log_level_err, _args)
	aloe_test_case_t *case_runner;
	int r = 0, pass = 0, failed = 0, total = 0, failed_prereq = 0;

	TAILQ_FOREACH(case_runner, &suite->cases, qent) {
		if (report_runner && report_runner->runner &&
				((r = (*report_runner->runner)(case_runner, report_runner)) != 0)) {
			report_log_e("Report runner break\n");
			break;
		}

		if (case_runner->flag_class == aloe_test_flag_class_suite) {
			if ((r = aloe_test_report(aloe_container_of(case_runner,
					aloe_test_t, runner), report_runner)) != 0) {
				report_log_e("Report suite break\n");
				break;
			}
			continue;
		}
		total++;
		switch(case_runner->flag_result) {
		case aloe_test_flag_result_pass:
			pass++;
			break;
		case aloe_test_flag_result_failed:
			failed++;
			break;
		case aloe_test_flag_result_failed_suite:
			failed++;
			break;
		case aloe_test_flag_result_prerequisite:
			failed++;
			failed_prereq++;
			break;
		default:
			failed++;
			break;
		}
		if (case_runner->flag_result == aloe_test_flag_result_failed ||
				case_runner->flag_result == aloe_test_flag_result_failed_suite) {
			report_log_d("Report result %s, test case[%s], #%d in suite[%s]\n"
					"  Cause: %s\n",
					ALOE_TEST_RESULT_STR(case_runner->flag_result, "UNKNOWN"),
					case_runner->name, total, suite->runner.name,
					(case_runner->cause ? case_runner->cause : "UNKNOWN"));
		} else {
			report_log_d("Report result %s, test case[%s], #%d in suite[%s]\n",
					ALOE_TEST_RESULT_STR(case_runner->flag_result, "UNKNOWN"),
					case_runner->name, total, suite->runner.name);
		}
	}

	report_log_d("%s result %s, test suite[%s]\n"
			"  Summary test cases PASS: %d, FAILED: %d(PREREQUISITE: %d), TOTAL: %d\n",
			(r != 0 ? "Report(incomplete)" : "Report"),
			ALOE_TEST_RESULT_STR(suite->runner.flag_result, "UNKNOWN"),
			suite->runner.name, pass, failed, failed_prereq, total);

	if (report_runner) {
		report_runner->total += total;
		report_runner->pass += pass;
		report_runner->failed += failed;
		report_runner->failed_prereq += failed_prereq;
	}
	return r;
}
