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

#include <sys/types.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "priv.h"

#ifdef USER_PREFIX
#  ifdef spkcal_cfg
#    undef spkcal_cfg
#  endif // redef spkcal_cfg
#  define spkcal_cfg USER_PREFIX "spklatency"
#  define admin_spkcal_progress_path USER_PREFIX "spkcal_prog"
#else
#  define admin_spkcal_progress_path "/var/run/spkcal_prog"
#endif
#define admin_spkcal_spklatency_default 0
#define admin_spkcal_log_path admin_spkcal_progress_path ".log"
#define admin_spkcal_stdout_path admin_spkcal_progress_path ".log2"
#define spkcal_value_invalid -999999

int admin_spkcal(int argc, char * const *argv) {
	const char *str, *reason = NULL;
	aloe_buf_t cmdbuf  = {.data = NULL};
	int r, prog_st, prog_iter, fd = -1, spkcal_value = spkcal_value_invalid,
			spkcal_raw_value = spkcal_value_invalid;
	cJSON *jroot = NULL, *jobj;
	enum {
		prog_null = 0,
		prog_complete = prog_null + 100,
		prog_failed,
		prog_fatal, // including less then prog_null

		req_cmd_null,
		req_cmd_get_spkcal,
		req_cmd_set_spkcal,
		req_cmd_set_spkcal_auto,
	};
	struct {
		int cmd;
		union {
			struct {
				int val, apply, mic_vol;
			} set_spkcal;
		};
	} req_info;

#define reason_f(...) if (cmdbuf.data) { \
	aloe_buf_clear(&cmdbuf); \
	if (aloe_buf_printf(&cmdbuf, __VA_ARGS__) < 0) { \
		aloe_buf_printf(&cmdbuf, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
	reason = (char*)cmdbuf.data; \
	log_d("%s\n", reason); \
}

	if (aloe_buf_expand(&cmdbuf, 500, aloe_buf_flag_none) != 0) {
		r = -1;
		reason = "Out of memory";
		goto finally;
	}

	r = air192_file_scanf1(admin_spkcal_progress_path, "%d %d",
			&prog_st, &prog_iter);
	if (r == 0) {
		prog_st = prog_iter = 0;
	} else if (r == 1) {
		prog_iter = 0;
	} else if (r != 2) {
		r = -1;
		reason_f("Runtime error: %s", "get progress");
		goto finally;
	}
	log_d("load spkcal prog: %d, iter: %d\n", prog_st, prog_iter);

	if (prog_st >= prog_fatal) {
		r = -1;
		reason_f("Fatal error");
		goto finally;
	}

	if (prog_st < prog_complete && prog_st != prog_null) {
		r = prog_st;
		reason_f("Speaker calibration progressing");
		goto finally;
	}

	r = air192_file_scanf1(spkcal_cfg, "%d", &spkcal_value);
	if (r == 0) {
		spkcal_value = 0;
	} else if (r != 1) {
		r = -1;
		reason_f("Runtime error: %s", "get latency");
		goto finally;
	}
	log_d("load spklatency value: %d\n", spkcal_value);

	r = air192_file_scanf1(spkcal_raw, "%d", &spkcal_raw_value);
	if (r != 1) spkcal_raw_value = spkcal_value_invalid;
	log_d("load spklatency raw: %d\n", spkcal_raw_value);

	// CONTENT_TYPE=application/json
	// CONTENT_LENGTH=12
	aloe_buf_clear(&cmdbuf);
	if (!(str = getenv("CONTENT_TYPE"))
			|| strcasecmp(str, "application/json") != 0
			|| !(str = getenv("CONTENT_LENGTH"))
			|| (r = strtol(str, NULL, 0)) <= 0
			|| r >= (int)cmdbuf.cap
			|| r != (int)fread(cmdbuf.data, 1, r, stdin)) {
		r = -1;
		reason_f("Invalid request: %s", "header");
		goto finally;
	}
	cmdbuf.pos += r;
	aloe_buf_flip(&cmdbuf);

	log_d("received request: %d,\n%s\n", (int)cmdbuf.lmt, (char*)cmdbuf.data);

	if (!(jroot = cJSON_Parse((char*)cmdbuf.data))) {
		r = -1;
		reason_f("Invalid request: %s", "JSON");
		goto finally;
	}
	if (!(jobj = cJSON_GetObjectItem(jroot, "command"))
			|| !(str = cJSON_GetStringValue(jobj))) {
		r = -1;
		reason_f("Invalid request: %s", "command");
		goto finally;
	}

	if (strcasecmp(str, "get_spkcal") == 0) {
//		cmd_info.cmd = req_cmd_get_spkcal;
		r = 0;
		goto finally;
	}

	if (strcasecmp(str, "set_spkcal") == 0) {
		if (!(jobj = cJSON_GetObjectItem(jroot, "value"))) {
			r = -1;
			reason_f("Invalid request: %s", "value");
			goto finally;
		}

		if (cJSON_IsNumber(jobj)) {
			req_info.cmd = req_cmd_set_spkcal;
			req_info.set_spkcal.val = (int)cJSON_GetNumberValue(jobj);
		} else if ((str = cJSON_GetStringValue(jobj))) {
			if (strcasecmp(str, "auto") == 0) {
				req_info.cmd = req_cmd_set_spkcal_auto;
			} else {
				r = -1;
				reason_f("Invalid request: %s", "value");
				goto finally;
			}
		} else {
			r = -1;
			reason_f("Invalid request: %s", "value");
			goto finally;
		}
		req_info.set_spkcal.apply = cJSON_IsTrue(cJSON_GetObjectItem(jroot,
				"apply"));
	} else {
		r = -1;
		reason_f("Invalid request: %s", "command");
		goto finally;
	}

	if (req_info.cmd == req_cmd_set_spkcal) {
		if ((aloe_file_fprintf2(spkcal_cfg, "w+", "%d",
				req_info.set_spkcal.val)) <= 0) {
			r = -1;
			reason_f("Runtime error: %s", "set latency");
			goto finally;
		}
		spkcal_value = req_info.set_spkcal.val;
		spkcal_raw_value = spkcal_value_invalid;

		aloe_buf_clear(&cmdbuf);
//		if (req_info.set_spkcal.apply) {
//			r = aloe_buf_aprintf(&cmdbuf, 500,
//					"/sbin/airplayutil control \"spklatency %d\"", spkcal_value);
//		} else {
//			r = aloe_buf_aprintf(&cmdbuf, 500,
//					"/etc/init.d/airplay-initd restart");
//		}
		r = aloe_buf_aprintf(&cmdbuf, 500,
				"/etc/init.d/adk-initd restart");
		if (r <= 0) {
			r = 1;
			reason_f("Value will take effect after next reboot%s",
					", (Failed compose command to reload application)");
			goto finally;
		}
		aloe_buf_flip(&cmdbuf);
		log_d("composed command to reload application: %s\n", (char*)cmdbuf.data);

		if (system((char*)cmdbuf.data) != 0) {
			r = 1;
			reason_f("Value will take effect after next reboot%s",
					", (Failed reload application)");
			goto finally;
		}

		r = air192_file_scanf1(spkcal_cfg, "%d", &spkcal_value);
		if (r == 0) {
			spkcal_value = 0;
		} else if (r != 1) {
			r = -1;
			reason_f("Runtime error: %s", "get latency");
			goto finally;
		}
		log_d("load spklatency value: %d\n", spkcal_value);
		r = 0;
		goto finally;
	}

	// sanity check cmd_info.cmd = req_cmd_set_spkcal_auto
	if (req_info.cmd != req_cmd_set_spkcal_auto) {
		r = -1;
		reason_f("Invalid request: %s", "command");
		log_e("sanity check\n");
		goto finally;
	}
	spkcal_value = spkcal_raw_value = spkcal_value_invalid;

	// fix long waiting for response

	aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
			prog_st = prog_null + 1, prog_iter = prog_iter + 1);

	if ((r = fork()) == (pid_t)-1) {
		reason_f("Runtime error: %s", "fork do spkcal");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}

	if (r) {
		log_d("parent process report progressing\n");

		r = prog_st;
		reason_f("Speaker calibration progressing");
		goto finally;
	}

	log_d("child process progressing in background\n");

#if 1
	if (aloe_file_stdout(admin_spkcal_stdout_path) == -1 ||
			aloe_file_stderr(admin_spkcal_stdout_path) == -1) {
		r = -1;
		reason_f("Runtime error: %s", "redirect stdout");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}
#endif

	// prevent occupied by application
#if 0
	aloe_buf_clear(&cmdbuf);
	if (aloe_buf_aprintf(&cmdbuf, 500,
			"/etc/init.d/airplay-initd stop; sleep 1") <= 0) {
		r = -1;
		reason_f("Runtime error: %s", "compose command to stopping audio application");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}

	aloe_buf_flip(&cmdbuf);
	log_d("composed command to stopping audio application: %s\n", (char*)cmdbuf.data);

	if (system((char*)cmdbuf.data) != 0) {
		r = -1;
		reason_f("Runtime error: %s", "stopping audio application");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}
#endif

	aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
			++prog_st, prog_iter);

	aloe_buf_clear(&cmdbuf);
	if (aloe_buf_aprintf(&cmdbuf, 500,
			"spkcal") <= 0) {
		r = -1;
		reason_f("Runtime error: %s", "compose speaker calibration command");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}

	aloe_buf_flip(&cmdbuf);
	log_d("composed command to calibrate speaker: %s\n", (char*)cmdbuf.data);

	if (system((char*)cmdbuf.data) != 0) {
		r = -1;
		reason_f("Runtime error: %s", "calibrate speaker");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		// passthrough to continuous airplay
//		goto finally;
	}

	aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
			++prog_st, prog_iter);

#if 0
	aloe_buf_clear(&cmdbuf);
	if ((r = aloe_buf_aprintf(&cmdbuf, 500,
			"/etc/init.d/airplay-initd restart")) <= 0) {
		r = 1;
		reason_f("Value will take effect after next reboot%s",
				", (Failed compose command to reload application)");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}
	aloe_buf_flip(&cmdbuf);
	log_d("composed command to reload application: %s\n", (char*)cmdbuf.data);

	if (system((char*)cmdbuf.data) != 0) {
		r = 1;
		reason_f("Value will take effect after next reboot%s",
				", (Failed reload application)");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}
#endif

	r = air192_file_scanf1(spkcal_cfg, "%d", &spkcal_value);
	if (r == 0) {
		spkcal_value = 0;
	} else if (r != 1) {
		r = -1;
		reason_f("Runtime error: %s", "get latency");
		aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
				prog_st = prog_failed, prog_iter);
		goto finally;
	}
	log_d("load spklatency value: %d\n", spkcal_value);

	r = air192_file_scanf1(spkcal_raw, "%d", &spkcal_raw_value);
	if (r != 1) spkcal_raw_value = spkcal_value_invalid;
	log_d("load spklatency raw: %d\n", spkcal_raw_value);

	aloe_file_fprintf2(admin_spkcal_progress_path, "w+", "%d %d\n",
			prog_st = prog_complete, prog_iter);
	r = 0;
finally:
//	printf("HTTP/1.1 %d %s" HTTP_ENDL
//			"Content-Type: application/json" HTTP_ENDL
//			"" HTTP_ENDL
//			"{\"result\": %d, \"value\": %d, \"reason\": \"%s\"}",
//			(r != 0 ? 201 : 200), "Ok", r, spkcal_value, (reason ? reason : ""));
	printf("HTTP/1.1 %d %s" HTTP_ENDL
			"Content-Type: application/json" HTTP_ENDL
			"" HTTP_ENDL
			"{\"result\": %d", (r != 0 ? 201 : 200), "Ok", r);
	if (spkcal_value != spkcal_value_invalid) {
		printf(", \"value\": %d", spkcal_value);
	}
	if (spkcal_raw_value != spkcal_value_invalid) {
		printf(", \"raw\": %d", spkcal_raw_value);
	}
	if (reason) {
		printf(", \"reason\": \"%s\"", reason);
	}
	printf("}");
	if (fd != -1) close(fd);
	if (jroot) cJSON_Delete(jroot);
	if (cmdbuf.data) free(cmdbuf.data);
	return 0;
}

