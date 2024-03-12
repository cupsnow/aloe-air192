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

/** @file aloe/unitest.h
 * @brief unit test
 */

#ifndef _H_ALOE_UNITEST
#define _H_ALOE_UNITEST

#include "admin.h"

/** @defgroup ALOE_TEST Unit test.
 * @ingroup ALOE
 * @brief Public method to write test case.
 *
 * - Test groups to tree.
 * - Test suite could contain test suites and cases.
 * - The tree runs deep first.
 * - Test case failure may break the containing suite.
 *
 * Usage summary:
 *
 *     #include <admin/unitest.h>
 *
 *     static int test_reporter(unsigned lvl, const char *tag, long lno,
 *         const char *fmt, ...) {
 *       va_list va;
 *
 *       printf("%s #%d ", tag, (int)lno);
 *       va_start(va, fmt);
 *       vprintf(fmt, va);
 *       va_end(va);
 *       return 0;
 *     }
 *
 *     static aloe_test_flag_t test_case1(aloe_test_case_t *test_case) {
 *       ALOE_TEST_ASSERT_RETURN(1 == 1, test_case, failed_suite);
 *
 *       return aloe_test_flag_result_pass;
 *     }
 *
 *     static aloe_test_flag_t test_case2(aloe_test_case_t *test_case) {
 *       ALOE_TEST_ASSERT_RETURN(1 != 1, test_case, failed_suite);
 *
 *       return aloe_test_flag_result_pass;
 *     }
 *
 *     main() {
 *       aloe_test_t test_base;
 *       aloe_test_report_t test_report;
 *
 *       ALOE_TEST_INIT(&test_base, "TestBase");
 *
 *       ALOE_TEST_CASE_INIT4(&test_base, "TestBase/Case1", &test_case1);
 *       ALOE_TEST_CASE_INIT4(&test_base, "TestBase/Case2", &test_case2);
 *
 *       ALOE_TEST_RUN(&test_base);
 *
 *       memset(&test_report, 0, sizeof(test_report));
 *       test_report.log = &test_reporter;
 *       aloe_test_report(&test_base, &test_report);
 *
 *       printf("Report result %s, test suite[%s]"
 *         "%s  Summary total cases PASS: %d, FAILED: %d(PREREQUISITE: %d), TOTAL: %d" aloe_endl,
 *         ALOE_TEST_RESULT_STR(test_base.runner.flag_result, "UNKNOWN"),
 *         test_base.runner.name,
 *         aloe_endl, test_report.pass, test_report.failed,
 *         test_report.failed_prereq, test_report.total);
 *     }
 *
 * Result:
 *
 *     aloe_test_report #150 Report result PASS, test case[TestBase/Case1], #1 in suite[TestBase]
 *     aloe_test_report #146 Report result FAILED-SUITE, test case[TestBase/Case2], #2 in suite[TestBase]
 *       Cause: #84 1 != 1
 *     aloe_test_report #158 Report result FAILED-SUITE, test suite[TestBase]
 *       Summary test cases PASS: 1, FAILED: 1(PREREQUISITE: 0), TOTAL: 2
 *     Report result FAILED-SUITE, test suite[TestBase]
 *       Summary total cases PASS: 1, FAILED: 1(PREREQUISITE: 0), TOTAL: 2
 *
 *
 *  @dot "Run test"
 *  digraph G {
 *    subgraph test_suite {
 *      setup;
 *      loop_content[label="loop content"];
 *      shutdown;
 *
 *      setup -> loop_content;
 *      setup -> failed_suite;
 *      loop_content -> shutdown;
 *    };
 *
 *    subgraph test_case {
 *      test_runner;
 *    };
 *
 *    subgraph loop_content {
 *
 *    	runner -> test_suite;
 *    	runner -> test_case;
 *
 *    };
 *
 *  }
 *  @enddot
 */

/** @addtogroup ALOE_TEST
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Flags used in API.
 */
typedef enum aloe_test_flag_enum {
	ALOE_FLAG_MASK(aloe_test_flag_result, 0, 4),
	ALOE_FLAG(aloe_test_flag_result, _pass, 0), /**< Test passed. */

	ALOE_FLAG(aloe_test_flag_result,_failed, 1), /**< Test failure. */

	/** This test failed and populate to containing suite failure. */
	ALOE_FLAG(aloe_test_flag_result,_failed_suite, 2),

	/** This test failed due to prerequisite, ie. former failed suite. */
	ALOE_FLAG(aloe_test_flag_result,_prerequisite, 3),

	ALOE_FLAG_MASK(aloe_test_flag_class, 4, 2),
	ALOE_FLAG(aloe_test_flag_class, _case, 0),
	ALOE_FLAG(aloe_test_flag_class, _suite, 1),
} aloe_test_flag_t;

typedef struct aloe_test_case_rec {
	const char *name, *cause, **argv;
	TAILQ_ENTRY(aloe_test_case_rec) qent;
	aloe_test_flag_t (*run)(struct aloe_test_case_rec*);
	aloe_test_flag_t flag_class, flag_result;
	int argc;
} aloe_test_case_t;

typedef struct aloe_test_rec {
	aloe_test_case_t runner;
	aloe_test_flag_t (*setup)(struct aloe_test_rec*);
	void (*shutdown)(struct aloe_test_rec*);
	TAILQ_HEAD( , aloe_test_case_rec) cases;
} aloe_test_t;

/** Add to suite. */
#define ALOE_TEST_ADD(_baseobj, _obj) \
	TAILQ_INSERT_TAIL(&(_baseobj)->cases, _obj, qent)

/** Initialize test suite data structure. */
#define ALOE_TEST_INIT(_obj, _name) do { \
	memset(_obj, 0, sizeof(*(_obj))); \
	TAILQ_INIT(&(_obj)->cases); \
	(_obj)->runner.name = _name; \
	(_obj)->runner.flag_class = aloe_test_flag_class_suite; \
	(_obj)->runner.run = aloe_test_runner; \
} while(0)

#define ALOE_TEST_INIT2(_baseobj, _obj, _name) do { \
	ALOE_TEST_INIT(_obj, _name); \
	ALOE_TEST_ADD(_baseobj, &(_obj)->runner); \
} while(0)

/** Run test suite. */
#define ALOE_TEST_RUN(_obj) (_obj)->runner.run(&(_obj)->runner)

/** Initialize test case data structure. */
#define ALOE_TEST_CASE_INIT(_obj, _name, _runner) do { \
	memset(_obj, 0, sizeof(*(_obj))); \
	(_obj)->name = _name; \
	(_obj)->flag_class = aloe_test_flag_class_case; \
	(_obj)->run = _runner; \
} while(0)

#define ALOE_TEST_CASE_INIT2(_baseobj, _obj, _name, _case_runner) do { \
	ALOE_TEST_CASE_INIT(_obj, _name, _case_runner); \
	ALOE_TEST_ADD(_baseobj, _obj); \
} while(0)

#define ALOE_TEST_CASE_INIT4(_baseobj, _name, _case_runner) do { \
	static aloe_test_case_t _obj; \
	ALOE_TEST_CASE_INIT2(_baseobj, &_obj, _name, _case_runner); \
} while(0)

#define ALOE_TEST_RESULT_STR(_val, _unknown) ( \
	(_val) == aloe_test_flag_result_pass ? "PASS" : \
	(_val) == aloe_test_flag_result_failed ? "FAILED" : \
	(_val) == aloe_test_flag_result_failed_suite ? "FAILED-SUITE" : \
	(_val) == aloe_test_flag_result_prerequisite ? "FAILED-PREREQUISITE" : \
	_unknown)

#define ALOE_TEST_CLASS_STR(_val, _unknown) ( \
	(_val) == aloe_test_flag_class_suite ? "suite" : \
	(_val) == aloe_test_flag_class_case ? "case" : \
	_unknown)

/** Show test suite report. */
#define ALOE_TEST_REPORT(_obj, _act...) do { \
	aloe_test_report_t report_info; \
	memset(&report_info, 0, sizeof(report_info)); \
	aloe_test_report(_obj, &report_info); \
	aloe_log_d("Report result %s, test suite[%s]" aloe_endl \
			"  Summary total cases PASS: %d, FAILED: %d(PREREQUISITE: %d), TOTAL: %d" aloe_endl, \
			ALOE_TEST_RESULT_STR((_obj)->runner.flag_result, "UNKNOWN"), \
			(_obj)->runner.name, report_info.pass, report_info.failed, \
			report_info.failed_prereq, report_info.total); \
			_act; \
} while(0)

#define ALOE_TEST_ASSERT_THEN(_cond, _runner, _res, _act...) if (!(_cond)) { \
	(_runner)->cause = "#" aloe_stringify(__LINE__) \
			" " aloe_stringify(_cond); \
	(_runner)->flag_result = aloe_test_flag_result_ ## _res; \
	_act; \
}

#define ALOE_TEST_ASSERT_RETURN(_cond, _runner, _res) \
		ALOE_TEST_ASSERT_THEN(_cond, _runner, _res, { \
	return (_runner)->flag_result; \
})

/** Start test suite.
 *
 *   Context to execute test case and reentrant for contained test suite.
 *
 *  **Reentrant with prerequisite failure suite:**
 *  ```
 *  - Skip setup
 *  - Populate prerequisite failure in contained test suite and case.
 *  ```
 *
 * @param
 * @return
 */
aloe_test_flag_t aloe_test_runner(aloe_test_case_t*);

typedef struct aloe_test_report_rec {
	int (*runner)(aloe_test_case_t*, struct aloe_test_report_rec*);
	int pass, failed, total, failed_prereq;
	int (*log)(unsigned lvl, const char *tag, long lno,
			const char *fmt, ...) /*__attribute__((format(printf, 4, 5)))*/;
} aloe_test_report_t;

int aloe_test_report(aloe_test_t*, aloe_test_report_t*);

#ifdef __cplusplus
} /* extern "C" */
#endif

/** @} ALOE_TEST */

#endif // _H_ALOE_UNITEST
