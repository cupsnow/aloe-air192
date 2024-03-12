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
#  define progress_path USER_PREFIX "acccfg_prog"
#  ifdef hostname_cfg
#    undef hostname_cfg
#  endif // redef hostname_cfg
#  define hostname_cfg USER_PREFIX "hostname"
#else
#  define progress_path "/var/run/acccfg_prog"
#endif

static int acc_name_getcfg(cJSON **jout, aloe_buf_t *reason) {
	int r, paired;
	char apName[80];
	const char *cstr;
	cJSON *jcfg = NULL, *jobj;
    aloe_buf_t buf = {0}, apNameFb = {.data = apName, .cap = sizeof(apName)};

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}

	paired = air192_adk_paired(NULL);

	if (!(jcfg = air192_jcfg_load(NULL, NULL))) {
		log_e("Failed load config\n");
	}

	if (air192_name_get(NULL, aloe_buf_clear(&apNameFb),
			&aloe_accessory_name_refine) != 0 || apNameFb.pos <= 0) {
		apNameFb.pos = snprintf(apName, sizeof(apName), "%s", "Air192");
	}

	if (jout) {
		if ((!*jout && !(*jout = cJSON_CreateObject()))
				|| !cJSON_AddStringToObject(*jout, "accessory_name", apName)
				|| ((jobj = cJSON_GetObjectItem(jcfg, "version")) &&
						(cstr = cJSON_GetStringValue(jobj)) &&
						!cJSON_AddStringToObject(*jout, "version", cstr))
				|| ((jobj = cJSON_GetObjectItem(jcfg, "serial_number")) &&
						(cstr = cJSON_GetStringValue(jobj)) &&
						!cJSON_AddStringToObject(*jout, "serial_number", cstr))
				|| ((jobj = cJSON_GetObjectItem(jcfg, "hw_version")) &&
						(cstr = cJSON_GetStringValue(jobj)) &&
						!cJSON_AddStringToObject(*jout, "hw_version", cstr))
				|| (paired && !cJSON_AddTrueToObject(*jout, "homekit_paired"))) {
			log_e("Failed create json object\n");
			r = -1;
			reason_f("Runtime error: %s", "generate output");
			goto finally;
		}
	}
	r = 0;
finally:
	if (buf.data) free(buf.data);
	if (jcfg) cJSON_Delete(jcfg);
	return r;
#undef reason_f
}

static int acc_name_setup(const char *acc_name, aloe_buf_t *reason) {
	int r;
	aloe_buf_t buf = {NULL};

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}
	if (!acc_name) acc_name = "Air192";
	if (aloe_buf_aprintf(&buf, 100, "%s", acc_name) <= 0) {
		log_e("Insufficient memory for accessory name %s\n", acc_name);
		r = -1;
		reason_f("Runtime error: %s", "Insufficient memory");
		goto finally;
	}
	if (aloe_accessory_name_refine(aloe_buf_flip(&buf)) != 0) {
		log_e("Refine accessory name %s\n", acc_name);
		r = -1;
		reason_f("Runtime error: %s", "Invalid accessory name");
		goto finally;
	}

	if (aloe_file_fprintf2(hostname_cfg, "w", "%s", (char*)buf.data + buf.pos) <= 0) {
		log_e("write to %s\n", hostname_cfg);
		r = -1;
		reason_f("Runtime error: %s", "write accessory name file");
		goto finally;
	}
	log_d("accessory name %s written to %s\n", (char*)buf.data + buf.pos, hostname_cfg);

	r = 0;
finally:
	if (buf.data) free(buf.data);
	return r;
#undef reason_f
}

static int do_apply(void) {
	const char *cmd = "sync; sync; "
			"sh -c \"admin --hostname -f " hostname_cfg "\" &>/dev/null; "
			"sh -c \"pgrep adk && /etc/init.d/adk-initd restart\" &>/dev/null; "
			"sh -c \"pgrep airplaydemo && /etc/init.d/airplay-initd restart\" &>/dev/null";
#if defined(USER_PREFIX)
#else
	system(cmd);
#endif
	log_d("system: %s\n", cmd);
	return 0;
}

int admin_acccfg(int argc, char * const *argv) {
	int r, prog_st, prog_iter, prog_refine = 0;
	const char *str, *reason = NULL;
	aloe_buf_t cmdbuf  = {.data = NULL};
	cJSON *jroot = NULL, *jout = NULL, *jobj;
	enum {
		prog_null = 0,
		prog_complete = prog_null + 100,
		prog_failed,
		prog_fatal, // including less then prog_null
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
	log_d("load acccfg prog: %d, iter: %d\n", prog_st, prog_iter);

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
			", \"accessory_name\": \"  假的 收音機 abnormal  \n\"}");
#else
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
#endif
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

	// progressing, prevent overlap progressing

	aloe_file_fprintf2(progress_path, "w+", "%d %d\n",
			prog_st = prog_null + 1, prog_iter = prog_iter + 1);
	prog_refine = prog_refine_rc;

	if (strcasecmp(str, "get_config") == 0) {
		if ((r = acc_name_getcfg(&jout, &cmdbuf)) != 0) {
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
		const char *acc_name = NULL;
		char apply = 0;

		if (!(jobj = cJSON_GetObjectItem(jroot, "accessory_name"))
				|| !(acc_name = cJSON_GetStringValue(jobj))) {
			r = -1;
			reason_f("Invalid request: %s", "accessory_name");
			goto finally;
		}

		if ((jobj = cJSON_GetObjectItem(jroot, "apply")) && cJSON_IsTrue(jobj)) {
			apply |= 1;

			if ((jobj = cJSON_GetObjectItem(jroot, "enforce")) && cJSON_IsTrue(jobj))
				apply |= 2;
		}

		if (!(apply & 0x2) && air192_adk_paired(NULL)) {
#if 0
			r = 2;
			reason_f("homekit paired");
			goto finally;
#else
			if ((!jout && !(jout = cJSON_CreateObject()))
					|| !cJSON_AddNumberToObject(jout, "result", 2)
					|| !cJSON_AddTrueToObject(jout, "homekit_paired")) {
				log_e("Failed create json object\n");
				r = -1;
				reason_f("Runtime error: %s", "generate output");
				goto finally;
			}
			if (!(reason = cJSON_PrintUnformatted(jout))) {
				r = -1;
				reason_f("Runtime error: %s", "generate output string");
				goto finally;
			}
			r = 0;
#endif
			goto finally;
		}

		if ((r = acc_name_setup(acc_name, &cmdbuf)) != 0) {
			r = -1;
			reason_f("Failed setup");
			goto finally;
		}

		if ((apply & 1) && (r = do_apply()) != 0) {
			r = -1;
			reason_f("Failed apply");
			goto finally;
		}

		r = 0;
		reason = NULL;
		goto finally;
	}

	if (strcasecmp(str, "apply_config") == 0) {
		if ((r = do_apply()) != 0) {
			r = -1;
			reason_f("Failed apply");
			goto finally;
		}

		r = 0;
		reason = NULL;
		goto finally;
	}
#if 1
	if (strcasecmp(str, "set_wol") == 0) {
		const char *cmd;

		if ((jobj = cJSON_GetObjectItem(jroot, "enabled"))) {
			char enabled = (char)cJSON_IsTrue(jobj);

			if (enabled) {
				cmd = "sync; sync; "
						"sh -c \"echo wol=1 > " wol_cfg "\"; ";
				system(cmd);
			} else {
				cmd = "sync; sync; "
						"sh -c \"rm -rf " wol_cfg "\"; ";
				system(cmd);
			}
		}

		if ((jobj = cJSON_GetObjectItem(jroot, "fired"))) {
			char fired = (char)cJSON_IsTrue(jobj);

			if (fired) {
				cmd = "sync; sync; "
						"sh -c \"sus\"; ";
				system(cmd);
			}
		}
		r = 0;
		reason = NULL;
		goto finally;
	}
#endif
	r = -1;
	reason_f("Invalid request: %s", "command");
	goto finally;
finally:
	printf("HTTP/1.1 %d %s" HTTP_ENDL
			"Content-Type: application/json" HTTP_ENDL
			"" HTTP_ENDL,
			((r == 0) ? HTTP_RC_OK : HTTP_RC_INTERNAL_SERVER_ERROR),
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

