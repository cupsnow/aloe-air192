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
#include <sys/time.h>

#include <admin/air192.h>

#include "priv.h"

#ifdef USER_PREFIX
#  define progress_path USER_PREFIX "ledban_prog"
#  ifdef ledban_cfg
#    undef ledban_cfg
#  endif // redef ledban_cfg
#  define ledban_cfg USER_PREFIX "ledban"
#else
#  define progress_path "/var/run/ledban_prog"
#endif

#define LED_OVERRIDE_OFF_KEY  "led_override_off"

static int ledban_getcfg(cJSON **jout, aloe_buf_t *reason) {
	int r, ledbanned;

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}

	ledbanned = (_aloe_file_size(ledban_cfg, 0) != -2);
	log_d("%s: %d\n", ledban_cfg, ledbanned);

	if (jout) {
		if ((!*jout && !(*jout = cJSON_CreateObject()))
				|| !cJSON_AddBoolToObject(*jout,
						LED_OVERRIDE_OFF_KEY, ledbanned)) {
			log_e("Failed create json object\n");
			r = -1;
			reason_f("Runtime error: %s", "generate output");
			goto finally;
		}
	}
	r = 0;
finally:
	return r;
#undef reason_f
}

static int ledban_setup(int ledban_en, aloe_buf_t *reason) {
	int r;

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}
	if (ledban_en) {
		if (aloe_file_fprintf2(ledban_cfg, "w", "1") <= 0) {
			log_e("write to %s\n", ledban_cfg);
			r = -1;
			reason_f("Runtime error: %s", "write ledban file");
			goto finally;
		}
	} else {
		unlink(ledban_cfg);
	}
	r = 0;
finally:
	return r;
#undef reason_f
}

int admin_ledban(int argc, char *const*argv) {
	int r, prog_st, prog_iter, prog_refine = 0;
	const char *str, *reason = NULL;
	aloe_buf_t cmdbuf = {.data = NULL};
	cJSON *jroot = NULL, *jout = NULL, *jobj;
	enum {
		prog_null = 0, prog_complete = prog_null + 100, prog_failed, prog_fatal, // including less then prog_null
		prog_refine_rc, // unlock cgi request

		req_cmd_null,
	};

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

	r = air192_file_scanf1(progress_path, "%d %d", &prog_st, &prog_iter);
	if (r == 0) {
		prog_st = prog_iter = 0;
	} else if (r == 1) {
		prog_iter = 0;
	} else if (r != 2) {
		r = -1;
		reason_f("Runtime error: %s", "get progress");
		goto finally;
	}
	log_d("load ledban prog: %d, iter: %d\n", prog_st, prog_iter);

	if (prog_st >= prog_fatal) {
		r = -1;
		reason_f("Fatal error");
		goto finally;
	}

	if (prog_st < prog_complete && prog_st != prog_null) {
		r = prog_st;
		reason_f("acccfg progressing");
		goto finally;
	}

	// CONTENT_TYPE=application/json
	// CONTENT_LENGTH=12
	aloe_buf_clear(&cmdbuf);

#if defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"get_config\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"set_config\""
			", \"" LED_OVERRIDE_OFF_KEY "\": true}");
#else
	if (!(str = getenv("CONTENT_TYPE"))
			|| strcasecmp(str, "application/json") != 0
			|| !(str = getenv("CONTENT_LENGTH"))
			|| (r = strtol(str, NULL, 0)) <= 0 || r >= (int)cmdbuf.cap
			|| r != (int)fread(cmdbuf.data, 1, r, stdin)) {
		r = -1;
		reason_f("Invalid request: %s", "header");
		goto finally;
	}
	cmdbuf.pos += r;
#endif
	aloe_buf_flip(&cmdbuf);

	log_d("received request: %d,\n%s\n", (int )cmdbuf.lmt, (char* )cmdbuf.data);

	if (!(jroot = cJSON_Parse((char*)cmdbuf.data))) {
		r = -1;
		reason_f("Invalid request: %s", "JSON");
		goto finally;
	}
	if (!(jobj = cJSON_GetObjectItem(jroot, "command")) || !(str =
			cJSON_GetStringValue(jobj))) {
		r = -1;
		reason_f("Invalid request: %s", "command");
		goto finally;
	}

	// progressing, prevent overlap progressing

	aloe_file_fprintf2(progress_path, "w+", "%d %d\n", prog_st = prog_null + 1,
			prog_iter = prog_iter + 1);
	prog_refine = prog_refine_rc;

	if (strcasecmp(str, "get_config") == 0) {
		if ((r = ledban_getcfg(&jout, &cmdbuf)) != 0) {
			r = -1;
			reason = (char*)cmdbuf.data;
			goto finally;
		}
		if (!jout) {
//			r = 0;
//			log_d("Empty config\n");
			goto finally;
		}
		if (!cJSON_AddNumberToObject(jout, "result", 0)) {
			r = -1;
			reason_f("Runtime error: %s", "add result");
			goto finally;
		}
		if (!(reason = cJSON_PrintUnformatted(jout))) {
			r = -1;
			reason_f("Runtime error: %s", "generate output string");
			goto finally;
		}
		r = 0;
		goto finally;
	}

	if (strcasecmp(str, "set_config") == 0) {
		int ledbanned = 0;

		if (!(jobj = cJSON_GetObjectItem(jroot, LED_OVERRIDE_OFF_KEY))) {
			r = -1;
			reason_f("Invalid request: %s", LED_OVERRIDE_OFF_KEY);
			goto finally;
		}
		ledbanned = cJSON_IsTrue(jobj);

		if ((r = ledban_setup(ledbanned, &cmdbuf)) != 0) {
			r = -1;
			reason_f("Failed setup");
			goto finally;
		}
		system("sync; sync; led power -2; led standby -2;");
		r = 0;
		reason = NULL;
		goto finally;
	}

	r = -1;
	reason_f("Invalid request: %s", "command");
	goto finally;
finally:
	printf("HTTP/1.1 %d %s" HTTP_ENDL
	"Content-Type: application/json" HTTP_ENDL
	"" HTTP_ENDL, ((r == 0) ? HTTP_RC_OK : HTTP_RC_INTERNAL_SERVER_ERROR),
			((r == 0) ? "Ok" : "Internal Server Error"));
	if (r == 0 && reason) {
		printf("%s", reason);
	} else if (reason) {
		printf("{\"result\": %d, \"reason\": \"%s\"}", r, reason);
	} else {
		printf("{\"result\": %d}", r);
	}
	if (prog_refine == prog_refine_rc) {
		if (aloe_file_fprintf2(progress_path, "w+", "%d %d\n",
				((r == 0) ? prog_complete : prog_failed), prog_iter) <= 0) {
			log_e("Failed to refine progress file\n");
		}
	}
	if (ev_ctx) aloe_ev_destroy(ev_ctx);
	if (jroot) cJSON_Delete(jroot);
	if (jout) cJSON_Delete(jout);
	if (cmdbuf.data) free(cmdbuf.data);
	return 0;
}

