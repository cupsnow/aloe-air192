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

#include <cjson/cJSON.h>

#include "priv.h"

#ifdef USER_PREFIX
#  ifdef eth_cfg
#    undef eth_cfg
#  endif // redef eth_cfg
#  define eth_cfg USER_PREFIX "eth.conf"
#  define progress_path USER_PREFIX "ethcfg_prog"
#else
#  define progress_path "/var/run/ethcfg_prog"
#endif

#define kw_ip "ip"
#define kw_dhcp "dhcp"
#define kw_auto "auto"
#define kw_zcip "zcip"
#define kw_netmask "netmask"
#define kw_router "router"
#define kw_dns "dns"

enum {
	ip_mode_dhcp = (1 << 0),
	ip_mode_zcip = (1 << 1),
	ip_mode_auto = (1 << 2),
	ip_mode_not_static = ip_mode_dhcp | ip_mode_zcip | ip_mode_auto,
};

extern "C"
int air192_cgireq_ipcfg_read(const char *cfg, cJSON **jout, aloe_buf_t *reason) {
	int r, dhcp = 0;
	aloe_buf_t buf = {NULL};
	regmatch_t mah[2];
	char ip[20], msk[20], gw[20], dns[20];

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}
#define mah_reset() for (r = 0; r < (int)aloe_arraysize(mah); r++) { \
	mah[r].rm_so = mah[r].rm_eo = -1; \
}
#define mah_len(_mah) ((_mah)->rm_eo - (_mah)->rm_so)

	ip[0] = msk[0] = gw[0] = dns[0] = '\0';

	if ((r = aloe_file_size(cfg, 0)) < 0) {
		log_e("Failed get config file size\n");
		r = -1;
		reason_f("Runtime error: %s", "config file size");
		goto finally;
	}
	if (r == 0) {
		r = 0;
		log_d("Empty config file\n");
		goto finally;
	}

	if (aloe_buf_expand(&buf, r + 8, aloe_buf_flag_none) != 0) {
		log_e("Failed alloc for config file\n");
		r = -1;
		reason_f("Runtime error: %s", "no memory");
		goto finally;
	}
	aloe_buf_clear(&buf);
	if (aloe_file_fread(cfg, &buf) <= 0) {
		log_e("Load %s\n", eth_cfg);
		r = -1;
		reason_f("Runtime error: %s", "read config file");
		goto finally;
	}
	aloe_buf_flip(&buf);

#define mah_ids1(_ids, _arr, _pat1) \
	mah_reset(); \
	r = air192_regex_test1((char*)buf.data + buf.pos, \
			"^\\s*" _ids "\\s*=\\s*" _pat1 "\\s*", \
			REG_ICASE | REG_EXTENDED | REG_NEWLINE, \
			aloe_arraysize(mah), mah); \
	if (r == 0) { \
		/* log_d(_ids " %d(+%d)\n", buf.pos + mah[1].rm_so, mah_len(&mah[1])); */ \
		if (mah_len(&mah[1]) >= (int)sizeof(_arr)) { \
			log_e("insufficient memory for " _ids "\n"); \
			r = -1; \
			reason_f("Runtime error: %s", "read config file"); \
			goto finally; \
		} \
		strncpy(_arr, (char*)buf.data + buf.pos + mah[1].rm_so, mah_len(&mah[1])); \
		_arr[mah_len(&mah[1])] = '\0'; \
		log_d(_ids " %d(+%d): %s\n", (int)buf.pos + mah[1].rm_so, mah_len(&mah[1]), _arr); \
	} else if (r == REG_NOMATCH) { \
		_arr[0] = '\0'; \
		log_d(_ids": Unspecified\n"); \
	} else { \
		log_e("parse " _ids "\n"); \
		r = -1; \
		reason_f("Runtime error: %s", "read config file"); \
		goto finally; \
	}

	mah_ids1(kw_ip, ip, "(.*)");
	if (!ip[0]) {
		r = 0;
		log_d("Might empty/ineffective config file\n");
		goto finally;
	}

	if (strcasecmp(ip, kw_dhcp) == 0) dhcp |= ip_mode_dhcp;
	if (strcasecmp(ip, kw_zcip) == 0) dhcp |= ip_mode_zcip;
	if (strcasecmp(ip, kw_auto) == 0) dhcp |= ip_mode_auto;

	if (!dhcp) {
		mah_ids1(kw_netmask, msk, "(.*)");
		if (!msk[0]) {
			log_e("parse %s\n", kw_netmask);
			r = -1;
			reason_f("Runtime error: %s", "read config file");
			goto finally;
		}

		mah_ids1(kw_router, gw, "(.*)");
		if (!gw[0]) {
			log_e("parse %s\n", kw_router);
			r = -1;
			reason_f("Runtime error: %s", "read config file");
			goto finally;
		}

		mah_ids1(kw_dns, dns, "(.*)");
		if (!dns[0]) {
			log_e("parse %s\n", kw_dns);
			r = -1;
			reason_f("Runtime error: %s", "read config file");
			goto finally;
		}
	}

	if (jout) {
		if ((!*jout && !(*jout = cJSON_CreateObject()))
				|| !(cJSON_AddStringToObject(*jout, kw_ip, ip))
				|| (!dhcp && !cJSON_AddStringToObject(*jout, kw_netmask, msk))
				|| (!dhcp && !cJSON_AddStringToObject(*jout, kw_router, gw))
				|| (!dhcp && !cJSON_AddStringToObject(*jout, kw_dns, dns))) {
			log_e("Failed create json object\n");
			r = -1;
			reason_f("Runtime error: %s", "generate output");
			goto finally;
		}
	}
	r = 0;
finally:
	if (buf.data) free(buf.data);
	return r;
#undef reason_f
#undef mah_reset
#undef mah_len
#undef mah_ids1
}

extern "C"
int air192_cgireq_ipcfg_save(const char *ip, const char *msk, const char *gw,
		const char *dns, aloe_buf_t *reason, const char *cfg) {
	int r, dhcp = 0;
	aloe_buf_t buf = {NULL};

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}

	if ((r = aloe_buf_expand(&buf, 500, aloe_buf_flag_none)) != 0) {
		log_e("alloc buffer to write ipcfg\n");
		r = -1;
		reason_f("Runtime error: %s", "No memory");
		goto finally;
	}
	aloe_buf_clear(&buf);

	if (strcasecmp(ip, kw_dhcp) == 0) dhcp |= ip_mode_dhcp;
	if (strcasecmp(ip, kw_zcip) == 0) dhcp |= ip_mode_zcip;
	if (strcasecmp(ip, kw_auto) == 0) dhcp |= ip_mode_auto;

	if (dhcp) {
		if (aloe_buf_printf(&buf,
				"ip=%s\n"
				"\n", ip) <= 0) {
			log_e("Compose ip config\n");
			r = -1;
			reason_f("Runtime error: %s", "Compose ip config\n");
			goto finally;
		}
	} else {
		if (aloe_buf_printf(&buf,
				"ip=%s\n"
				"netmask=%s\n"
				"router=%s\n"
				"dns=%s\n"
				"\n", ip, msk, gw, dns) <= 0) {
			log_e("Compose static ip config\n");
			r = -1;
			reason_f("Runtime error: %s", "Compose static ip config\n");
			goto finally;
		}
	}
	aloe_buf_flip(&buf);
	if ((r = aloe_file_fwrite(cfg, &buf)) != (int)(buf.lmt - buf.pos)) {
		log_e("Write %s\n", eth_cfg);
		r = -1;
		reason_f("Runtime error: %s", "Write ip config\n");
		goto finally;
	}
	log_d("output to %s:\n  %s\n", cfg, (char*)buf.data);
	r = 0;
finally:
	if (buf.data) free(buf.data);
	return r;
#undef reason_f
}

extern "C"
int air192_cgireq_ipcfg_unmarshal(cJSON *jroot, const char **ip,
		const char **msk, const char **gw, const char **dns,
		aloe_buf_t *reason) {
	int r;
	unsigned flag = 0;
	cJSON *jobj;

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}
	if (!(jobj = cJSON_GetObjectItem(jroot, kw_ip))
			|| !(*ip = cJSON_GetStringValue(jobj))) {
		r = -1;
		reason_f("Invalid request: %s", kw_ip);
		goto finally;
	}

	if (strcasecmp(*ip, kw_dhcp) == 0) flag |= ip_mode_dhcp;
	if (strcasecmp(*ip, kw_zcip) == 0) flag |= ip_mode_zcip;
	if (strcasecmp(*ip, kw_auto) == 0) flag |= ip_mode_auto;
	if (!(flag & ip_mode_not_static)) {
		if (!(jobj = cJSON_GetObjectItem(jroot, kw_netmask))
				|| !(*msk = cJSON_GetStringValue(jobj))) {
			r = -1;
			reason_f("Invalid request: %s", kw_netmask);
			goto finally;
		}

		if (!(jobj = cJSON_GetObjectItem(jroot, kw_router))
				|| !(*gw = cJSON_GetStringValue(jobj))) {
			r = -1;
			reason_f("Invalid request: %s", kw_router);
			goto finally;
		}

		if (!(jobj = cJSON_GetObjectItem(jroot, kw_dns))
				|| !(*dns = cJSON_GetStringValue(jobj))) {
			r = -1;
			reason_f("Invalid request: %s", kw_dns);
			goto finally;
		}
	}
	r = 0;
finally:
	return r;
#undef reason_f
}


static int eth_getcfg(cJSON **jout, aloe_buf_t *reason) {
	return air192_cgireq_ipcfg_read(eth_cfg, jout, reason);
}

static int eth_setup(const char *ip, const char *msk, const char *gw,
		const char *dns, aloe_buf_t *reason) {
	return air192_cgireq_ipcfg_save(ip, msk, gw, dns, reason, eth_cfg);
}

int admin_ethcfg(int argc, char * const *argv) {
	int r, prog_st, prog_iter, prog_refine = 0;
	const char *str, *reason = NULL;
	aloe_buf_t cmdbuf  = {.data = NULL};
	cJSON *jroot = NULL, *jout = NULL, *jobj;
	enum {
		prog_null = 0,
		prog_complete = prog_null + 100,
		prog_failed,
		prog_fatal, // including less then prog_null
		prog_refine_rc,

		req_cmd_null,
	};

#define reason_f(...) if (cmdbuf.data) { \
	aloe_buf_clear(&cmdbuf); \
	if (aloe_buf_printf(&cmdbuf, __VA_ARGS__) < 0) { \
		aloe_buf_printf(&cmdbuf, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
	reason = (char*)cmdbuf.data; \
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
	log_d("load ethcfg prog: %d, iter: %d\n", prog_st, prog_iter);

	if (prog_st >= prog_fatal) {
		r = -1;
		reason_f("Fatal error");
		goto finally;
	}

	if (prog_st < prog_complete && prog_st != prog_null) {
		r = prog_st;
		reason_f("ethcfg progressing");
		goto finally;
	}

	// CONTENT_TYPE=application/json
	// CONTENT_LENGTH=12
	aloe_buf_clear(&cmdbuf);
#if defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"get_config\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"set_config\""
			", \"ip\": \"dhcp\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"set_config\""
			", \"ip\": \"10.0.1.50\""
			", \"netmask\": \"10.0.1.50\", \"router\": \"10.0.1.1\""
			", \"dns\": \"1.1.1.1\"}");
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
		if ((r = eth_getcfg(&jout, &cmdbuf)) != 0) {
			if (jobj) cJSON_Delete(jobj);
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
		const char *ip, *msk = NULL, *gw = NULL, *dns = NULL;

		if ((r = air192_cgireq_ipcfg_unmarshal(jroot, &ip, &msk, &gw,
				&dns, &cmdbuf)) != 0) {
			goto finally;
		}

		if ((r = eth_setup(ip, msk, gw, dns, &cmdbuf)) != 0) {
			r = -1;
			reason_f("Failed setup");
			goto finally;
		}

		r = 0;
		reason = NULL;
		goto finally;
	}

	if (strcasecmp(str, "reboot") == 0) {
		const char cmd[] = "sync; sync; { sleep 0.5; reboot now; } &";
		system(cmd);
		log_d("send %s\n", cmd);
		r = 0;
		goto finally;
	}

	r = -1;
	reason_f("Invalid request: %s", "command");
	goto finally;
finally:
	if (ev_ctx) aloe_ev_destroy(ev_ctx);
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
	if (jroot) cJSON_Delete(jroot);
	if (jout) cJSON_Delete(jout);
	if (cmdbuf.data) free(cmdbuf.data);
	return 0;
#undef reason_f
}

