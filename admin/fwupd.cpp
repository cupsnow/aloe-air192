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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <uriparser/Uri.h>
#include <cjson/cJSON.h>

#include "priv.h"

#define admin_fwupd_ota_file_uri_key "ota_file_uri"
#define admin_fwupd_ota_enforce_key "ota_enforce"
#define admin_fwupd_ota_dryrun_key "ota_dryrun"
#define admin_fwupd_ota_complete_reboot_key "ota_complete_reboot"
#ifdef USER_PREFIX
#  define admin_fwupd_ota_file_path USER_PREFIX "ota.tar.gz"
#  define admin_fwupd_progress_path USER_PREFIX "fwupd_prog"
#else
#  define admin_fwupd_ota_file_path "/media/ota.tar.gz"
#  define admin_fwupd_progress_path "/var/run/fwupd_prog"
#endif
#define admin_fwupd_log_path admin_fwupd_progress_path ".log"
#define admin_fwupd_stdout_path admin_fwupd_progress_path ".log2"

#define admin_fwupd_d(_fmt, _args...) printf("%s #%d " _fmt, __func__, \
		__LINE__, ##_args)
#define admin_fwupd_i(_fmt, _args...) if (impl.log_level >= log_level_info) { \
	printf("%s #%d " _fmt, __func__, __LINE__, ##_args); \
}
#define admin_fwupd_e(_fmt, _args...) printf("%s #%d " _fmt, __func__, \
		__LINE__, ##_args)
#define admin_fwupd_m(_lvl, _fmt, _args) if (_lvl <= impl.log_level) { \
}

#define admin_fwupd_prog_f(...) aloe_file_fprintf2(admin_fwupd_progress_path, "w+", __VA_ARGS__)
#define admin_fwupd_log_f(...) do { \
	log_i("append log: " __VA_ARGS__); \
	aloe_file_fprintf2(admin_fwupd_log_path, "a+", __VA_ARGS__); \
} while(0)

static int admin_fwupd_log_dump(aloe_buf_t *buf) {
	int fd = -1, r, fsz, len;

	if (!buf->data || buf->pos >= buf->lmt ||
			(r = (int)aloe_file_size(admin_fwupd_log_path, 0)) <= 0) {
		return 0;
	}
	fsz = r;
	len = buf->lmt - buf->pos - 1;

	if ((fd = open(admin_fwupd_log_path, O_RDONLY, 0666)) == -1) {
		r = errno;
		log_e("Failed open %s: %s\n", admin_fwupd_log_path, strerror(r));
		return -1;
	}

	r = buf->lmt - buf->pos - 1;
	if (lseek(fd, fsz > r ? fsz - r : 0, SEEK_SET) == (off_t)-1) {
		r = errno;
		log_e("Failed set position %d to %s: %s\n", len, admin_fwupd_log_path,
				strerror(r));
		close(fd);
		return -1;
	}
	if ((r = read(fd, (char*)buf->data + buf->pos, len)) < 0) {
		r = errno;
		log_e("Failed read %s: %s\n", admin_fwupd_log_path,
				strerror(r));
		close(fd);
		return -1;
	}
	((char*)buf->data)[buf->pos += r] = '\0';
	close(fd);
	return r;
}

int admin_fwupd(int argc, char * const *argv) {
	const char *str, *ota_file_uri = NULL, *ota_enforce = NULL;
	aloe_buf_t cmdbuf  = {.data = NULL};
	int r, up_qn, i, prog_st, prog_iter, fd = -1;
	UriQueryListA *up_q = NULL, *up_qi;
	enum {
		prog_null = 0,
		prog_complete = prog_null + 100,
		prog_failed,
		prog_fatal, // including less then prog_null
	};

	// html head title body
	printf("<html>"
			"<head>"
			"<title>%s</title>"
			"</head>"
			"<body>\n", "Firmware update");

	if (aloe_buf_expand(&cmdbuf, 5000, aloe_buf_flag_none) != 0) {
		r = ENOMEM;
		log_e("Out of memory\n");
		goto finally;
	}

	do {
		static const char *sep = " \t\r\n,;:";
		char *tok, *tok_next;

		if ((r = aloe_file_size(admin_fwupd_progress_path, 0)) == 0) {
			prog_st = prog_null;
			prog_iter = 0;
			break;
		}
		if ((fd = open(admin_fwupd_progress_path, O_RDONLY, 0666)) == -1) {
			r = errno;
			log_e("Failed open %s: %s\n", admin_fwupd_progress_path, strerror(r));
			goto finally;
		}
		if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
			r = errno;
			log_e("Failed set position %d to %s: %s\n", 0,
					admin_fwupd_progress_path, strerror(r));
			goto finally;
		}
		aloe_buf_clear(&cmdbuf);
		if ((r = read(fd, (char*)cmdbuf.data + cmdbuf.pos,
				cmdbuf.lmt - cmdbuf.pos - 1)) < 0) {
			r = EIO;
			log_e("Failed get progress\n");
			goto finally;
		}
		log_d("Read %d bytes from %s\n", r, admin_fwupd_progress_path);

		if (r == 0) {
			prog_st = prog_null;
			prog_iter = 0;
			break;
		}

		((char*)cmdbuf.data)[cmdbuf.pos += r] = '\0';

		aloe_buf_flip(&cmdbuf);

		if ((tok = strtok_r((char*)cmdbuf.data, sep, &tok_next)) == NULL) {
			r = EIO;
			log_e("Failed parse progress\n");
			goto finally;
		}
		prog_st = strtol(tok, NULL, 10);

		if ((tok = strtok_r(NULL, sep, &tok_next)) == NULL) {
			log_e("Failed parse progress iter, assume 1\n");
			prog_iter = 0;
		} else {
			prog_iter = strtol(tok, NULL, 10);
		}
	} while(0);
	if (fd != -1) {
		close(fd);
		fd = -1;
	}

	// handle current progressing and previous fatal
	if ((prog_st < prog_complete && prog_st != prog_null)
			|| (prog_st >= prog_fatal)) {
		aloe_buf_clear(&cmdbuf);
		admin_fwupd_log_dump(&cmdbuf);
		aloe_buf_flip(&cmdbuf);
		admin_fwupd_d("%s%d<br/>"
				"<hr/>\n"
				"Log dump (latested %d bytes)<br/>\n"
				"<code>%s</code>"
				"\n",
				((prog_st < prog_complete && prog_st > prog_null) ?
						"Processing: " :
						"Fatal error: "),
				prog_st, (int)cmdbuf.lmt, (char*)cmdbuf.data);
		goto finally;
	}

	// handle startup, previous completed or failed

	if (prog_st == prog_null) {
		// startup
		admin_fwupd_prog_f("%d %d\n", prog_null + 1, prog_iter + 1);
		admin_fwupd_log_f("Startup<br/>\n");
	}

	if (!(str = getenv("QUERY_STRING"))) {
		if (prog_st == prog_null) {
			// fallback
			admin_fwupd_prog_f("%d %d\n", prog_st, prog_iter);
		}
		admin_fwupd_e("Failed get QUERY_STRING<br/>\n");
		goto finally;
	}
	admin_fwupd_log_f("Got query string: %s<br/>\n", str);

	if (uriDissectQueryMallocA(&up_q, &up_qn, str,
			str + strlen(str)) != URI_SUCCESS) {
		if (prog_st == prog_null) {
			// fallback
			admin_fwupd_prog_f("%d %d\n", prog_st, prog_iter);
		}
		admin_fwupd_e("Failed parse query string<br/>\n");
		goto finally;
	}

	for (up_qi = up_q, i = 0; up_qi; up_qi = up_qi->next, i++) {
		admin_fwupd_log_f("Query string item[%d/%d]: %s=%s<br/>\n", i + 1, up_qn,
				up_qi->key, (up_qi->value ? up_qi->value : ""));
		if (strncasecmp(up_qi->key, admin_fwupd_ota_file_uri_key,
				strlen(admin_fwupd_ota_file_uri_key)) == 0) {
			ota_file_uri = up_qi->value;
		}
		if (strncasecmp(up_qi->key, admin_fwupd_ota_enforce_key,
				strlen(admin_fwupd_ota_enforce_key)) == 0) {
			if (!up_qi->value) {
				ota_enforce = "on";
			} else if (aloe_str_find(aloe_str_negative_lut, up_qi->value, 0)) {
				ota_enforce = NULL;
			} else {
				ota_enforce = up_qi->value;
			}
		}
	}

	// handle previous completed
	if (prog_st == prog_complete && !ota_enforce) {
		aloe_buf_clear(&cmdbuf);
		admin_fwupd_log_dump(&cmdbuf);
		aloe_buf_flip(&cmdbuf);
		admin_fwupd_d("Already completed %d<br/>"
				"<hr/>"
				"Log dump (latested %d bytes)<br/>"
				"<code>%s</code>"
				"\n",
				prog_st, (int)cmdbuf.lmt, (char*)cmdbuf.data);
		goto finally;
	}

	// handle startup, restart from failed or completed

	admin_fwupd_prog_f("%d %d\n", prog_null + 2, prog_iter + 1);

	if (!ota_file_uri || !ota_file_uri[0]) {
		if (prog_st == prog_null) {
			admin_fwupd_prog_f("%d %d\n", prog_st, prog_iter);
		}
		admin_fwupd_e("Failed parse OTA file URI<br/>\n");
		goto finally;
	}
	admin_fwupd_log_f("Found OTA file URI: %s<br/>\n", ota_file_uri);

	aloe_buf_clear(&cmdbuf);
	if (aloe_buf_aprintf(&cmdbuf, 500,
			"wget -O " admin_fwupd_ota_file_path " %s",
			ota_file_uri) <= 0) {
		if (prog_st == prog_null) {
			// fallback
			admin_fwupd_prog_f("%d %d\n", prog_st, prog_iter);
		}
		admin_fwupd_e("Failed compose server command<br/>\n");
		goto finally;
	}

	// handle progressing no fallback

	admin_fwupd_prog_f("%d %d\n", prog_st = prog_null + 3,
			prog_iter = prog_iter + 1);

	if ((r = fork()) == (pid_t)-1) {
		admin_fwupd_log_f("Failed fork to get OTA file<br/>\n");
		admin_fwupd_prog_f("%d %d\n", prog_st = prog_failed, prog_iter);
//		goto finally;
		// pass through for parent process report progressing
	}

	if (r) {
		// parent process report progressing

		admin_fwupd_log_f("Processing: %d, iter: %d<br/>\n",
				prog_st, prog_iter);

		aloe_buf_clear(&cmdbuf);
		admin_fwupd_log_dump(&cmdbuf);
		aloe_buf_flip(&cmdbuf);
		admin_fwupd_d("%s%d<br/>"
				"<hr/>"
				"Log dump (latested %d bytes)<br/>"
				"<code>%s</code>"
				"\n",
				((prog_st < prog_complete && prog_st > prog_null) ?
						"Processing: " :
						"Failed: "),
				prog_st, (int)cmdbuf.lmt, (char*)cmdbuf.data);
		goto finally;
	}

	// child process progressing
#if 1
	if (aloe_file_stdout(admin_fwupd_stdout_path) == -1 ||
			aloe_file_stderr(admin_fwupd_stdout_path) == -1) {
		admin_fwupd_log_f("Failed redirect stdout to %s<br/>\n",
				admin_fwupd_stdout_path);
		admin_fwupd_prog_f("%d %d\n", prog_st = prog_failed, prog_iter);
		goto finally;
	}
#endif
	if (ota_enforce && ota_enforce[0] == '.') {
		up_qn = 10;
		for (i = 0; i < up_qn; i++) {
			admin_fwupd_log_f("test: %d/%d<br/>\n", i + 1, up_qn);
			usleep(1000000);
		}
		admin_fwupd_prog_f("%d %d\n", prog_st = prog_failed, prog_iter);
		goto finally;
	}

	aloe_buf_flip(&cmdbuf);
	admin_fwupd_log_f("Composed wget command: %s<br/>\n",
			(char*)cmdbuf.data);

	if (system((char*)cmdbuf.data) != 0) {
		admin_fwupd_log_f("Failed wget OTA file<br/>\n");
		admin_fwupd_prog_f("%d %d\n", prog_st = prog_failed, prog_iter);
		goto finally;
	}
	admin_fwupd_prog_f("%d %d\n", ++prog_st, prog_iter);
	admin_fwupd_log_f("Got OTA file %d bytes, from: %s<br/>\n",
			(int)aloe_file_size(admin_fwupd_ota_file_path, 0), ota_file_uri);

	aloe_buf_clear(&cmdbuf);
	if (aloe_buf_aprintf(&cmdbuf, 500,
			"fwupd -o " admin_fwupd_ota_file_path " -u 1>&2") <= 0) {
		admin_fwupd_log_f("Failed compose fwupd command<br/>\n");
		admin_fwupd_prog_f("%d %d\n", prog_st = prog_failed, prog_iter);
		goto finally;
	}
	admin_fwupd_prog_f("%d %d\n", ++prog_st, prog_iter);
	admin_fwupd_log_f("Composed fwupd command: %s<br/>\n", (char*)cmdbuf.data);

	aloe_buf_flip(&cmdbuf);

	if (system((char*)cmdbuf.data) != 0) {
		admin_fwupd_log_f("Failed firmware upgrade, iter: %d<br/>\n", prog_iter);
		admin_fwupd_prog_f("%d %d\n", prog_st = prog_failed, prog_iter);
		goto finally;
	}
	admin_fwupd_log_f("Successful firmware upgrade<br/>\n");
	admin_fwupd_prog_f("%d %d\n", prog_st = prog_complete, prog_iter);
finally:
#if 0
	// append env
	printf("<hr/>"
			"<code>\n");
	for (env = (const char**)environ; *env; env++) {
		printf("%s<br/>\n", *env);
	}
	printf("</code>\n");
#endif

	// end of body
	printf("</body></html>\n");
	if (fd != -1) close(fd);
	if (up_q) uriFreeQueryListA(up_q);
	if (cmdbuf.data) free(cmdbuf.data);
	return 0;
}

int admin_fwupd2(int argc, char * const *argv) {
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
		req_cmd_set_fwupd,
		req_cmd_get_status,
	};
	struct {
		int cmd;
		union {
			struct {
				const char *ota_file_uri;
				unsigned ota_enforce : 1;
				unsigned ota_dryrun : 1;
				unsigned ota_complete_reboot : 1;
			} set_fwupd;
		};
	} req_info = {0};

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

	r = air192_file_scanf1(admin_fwupd_progress_path, "%d %d", &prog_st, &prog_iter);
	if (r == 0) {
		prog_st = prog_iter = 0;
	} else if (r == 1) {
		prog_iter = 0;
	} else if (r != 2) {
		r = -1;
		reason_f("Runtime error: %s", "get progress");
		goto finally;
	}
	log_d("load fwupd prog: %d, iter: %d\n", prog_st, prog_iter);

	if (prog_st < prog_complete && prog_st != prog_null) {
		r = prog_st;
		reason_f("busy");
		goto finally;
	}

	// CONTENT_TYPE=application/json
	// CONTENT_LENGTH=12
	aloe_buf_clear(&cmdbuf);
#if defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"get_status\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"set_fwupd\""
			", \""admin_fwupd_ota_file_uri_key"\": \"http://192.168.18.6:3000/media/ota-host.tar.gz\""
			", \""admin_fwupd_ota_enforce_key"\": true}");
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

	if (strcasecmp(str, "get_status") == 0) {
		req_info.cmd = req_cmd_get_status;
		r = prog_st;
		if (prog_st == prog_null) {
			reason = NULL; // or report json string
			goto finally;
		}
		if (prog_st == prog_complete) {
			reason_f("%s", "completed");
			goto finally;
		}
		if (prog_st < prog_fatal) {
			reason_f("%s", "failed");
			goto finally;
		}
		reason_f("%s", "fatal error");
		goto finally;
	}

	if (strcasecmp(str, "set_fwupd") == 0) {
		req_info.cmd = req_cmd_set_fwupd;
		if (!(jobj = cJSON_GetObjectItem(jroot, admin_fwupd_ota_file_uri_key))
				|| !(req_info.set_fwupd.ota_file_uri = cJSON_GetStringValue(jobj))
				|| !req_info.set_fwupd.ota_file_uri[0]) {
			r = -1;
			reason_f("Invalid request: %s", admin_fwupd_ota_file_uri_key);
			goto finally;
		}
		req_info.set_fwupd.ota_enforce = cJSON_IsTrue(cJSON_GetObjectItem(jroot,
				admin_fwupd_ota_enforce_key));
		req_info.set_fwupd.ota_dryrun = cJSON_IsTrue(cJSON_GetObjectItem(jroot,
				admin_fwupd_ota_dryrun_key));
		req_info.set_fwupd.ota_complete_reboot = cJSON_IsTrue(cJSON_GetObjectItem(jroot,
				admin_fwupd_ota_complete_reboot_key));
	} else {
		r = -1;
		reason_f("Invalid request: %s", "command");
		goto finally;
	}

	if (req_info.cmd != req_cmd_set_fwupd) {
		r = -1;
		reason_f("Invalid request: %s", "command");
		log_e("sanity check\n");
		goto finally;
	}

	if (prog_st == prog_complete && !req_info.set_fwupd.ota_enforce) {
		r = prog_st;
		reason_f("%s", "already completed");
		goto finally;
	}
	if (prog_st >= prog_fatal && !req_info.set_fwupd.ota_enforce) {
		r = prog_st;
		reason_f("%s", "fatal error");
		goto finally;
	}

	// progressing, prevent overlap progressing

	aloe_file_fprintf2(admin_fwupd_progress_path, "w+", "%d %d\n",
			prog_st = prog_null + 1, prog_iter = prog_iter + 1);
	prog_refine = prog_refine_rc;

	// fix long waiting for response

	if ((r = fork()) == (pid_t)-1) {
		reason_f("Runtime error: %s", "fork do fwupd");
		goto finally;
	}

	if (r) {
		log_d("parent process report, forked child %d do fwupd\n", r);
		// leave the prog_st updated by child
		prog_refine = 0;
		r = prog_st;
		reason_f("busy");
		goto finally;
	}

	log_d("child process do fwupd in background\n");

#if 1
	if (aloe_file_stdout(admin_fwupd_stdout_path) == -1 ||
			aloe_file_stderr(admin_fwupd_stdout_path) == -1) {
		r = -1;
		reason_f("Runtime error: %s", "redirect stdout");
		goto finally;
	}
#endif

	aloe_file_fprintf2(admin_fwupd_progress_path, "w+", "%d %d\n",
			prog_st = prog_null + 2, prog_iter);

	if (aloe_buf_aprintf(aloe_buf_clear(&cmdbuf), 500,
			"wget -O " admin_fwupd_ota_file_path " %s",
			req_info.set_fwupd.ota_file_uri) <= 0) {
		r = -1;
		reason_f("Failed: %s", "compose server command");
		goto finally;
	}
	aloe_buf_flip(&cmdbuf);
	log_d("Composed wget command: %s\n", (char*)cmdbuf.data);
	if (system((char*)cmdbuf.data) != 0) {
		r = -1;
		reason_f("Failed: %s", "wget OTA file");
		goto finally;
	}
	log_d("wget OTA file %d bytes\n", (int)aloe_file_size(
			admin_fwupd_ota_file_path, 0));

	aloe_file_fprintf2(admin_fwupd_progress_path, "w+", "%d %d\n",
			prog_st = prog_null + 3, prog_iter);
#if defined(USER_PREFIX) && 0
	if (aloe_buf_aprintf(aloe_buf_clear(&cmdbuf), 500, "sleep 5") <= 0) {
		r = -1;
		reason_f("Failed: %s", "compose fwupd command");
		goto finally;
	}
#else
	if (aloe_buf_aprintf(aloe_buf_clear(&cmdbuf), 500, "fwupd"
			" -o " admin_fwupd_ota_file_path " -u %s 1>&2"
			, ((req_info.set_fwupd.ota_dryrun) ? "-n" : "")) <= 0) {
		r = -1;
		reason_f("Failed: %s", "compose fwupd command");
		goto finally;
	}
#endif
	aloe_buf_flip(&cmdbuf);
	log_d("Composed fwupd command: %s\n", (char*)cmdbuf.data);
	if (system((char*)cmdbuf.data) != 0) {
		r = -1;
		reason_f("Failed: %s", "fwupd OTA file");
		goto finally;
	}
	log_d("successful fwupd OTA file\n");
	r = prog_complete;
	if (req_info.set_fwupd.ota_complete_reboot) {
#if defined(USER_PREFIX) && 0
		system("{ sleep 3; sync ; sync; } &");
#else
		system("{ sleep 3; sync ; sync ; reboot; } &");
#endif
		reason_f("%s", "completed, rebooting");
		goto finally;
	}
	reason_f("%s", "completed");
finally:
	printf("HTTP/1.1 %d %s" HTTP_ENDL
			"Content-Type: application/json" HTTP_ENDL
			"" HTTP_ENDL,
			((r == 0) || (r == prog_complete) ? HTTP_RC_OK :
			(r > 0) ? HTTP_RC_ACCEPTED :
			HTTP_RC_INTERNAL_SERVER_ERROR),
			((r == 0) || (r == prog_complete) ? "Ok" :
			(r > 0) && (r < prog_complete) ? "Accepted" :
			"Internal Server Error"));
	if (r == 0 && reason) {
		printf("%s", reason);
	} else if (reason) {
		printf("{\"result\": %d, \"reason\": \"%s\"}", r, reason);
	} else {
		printf("{\"result\": %d}", r);
	}
	if (prog_refine == prog_refine_rc) {
		if (aloe_file_fprintf2(admin_fwupd_progress_path, "w+", "%d %d\n",
				((r == 0) || (r == prog_complete) ? r : prog_failed), prog_iter) <= 0) {
			log_e("Failed to refine progress file\n");
		}
	}
	if (jroot) cJSON_Delete(jroot);
	if (jout) cJSON_Delete(jout);
	if (cmdbuf.data) free(cmdbuf.data);
	return 0;
}
