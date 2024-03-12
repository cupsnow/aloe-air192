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

#ifdef WITH_WPACTRL
#include <wpa_ctrl.h>
#endif

#include "priv.h"


#ifdef WITH_WPACTRL
//#  define USE_WPACTRL 1
#endif

#ifdef USER_PREFIX

#  ifdef wpasup_cfg
#    undef wpasup_cfg
#  endif // redef wpasup_cfg
#  define wpasup_cfg USER_PREFIX "wpa_supplicant.conf"

#  ifdef wlan_cfg
#    undef wlan_cfg
#  endif // redef wlan_cfg
#  define wlan_cfg USER_PREFIX "wlan.conf"

#  define progress_path USER_PREFIX "wificfg_prog"
#  define APLIST_PATH USER_PREFIX "aplist.txt"
#else
#  define progress_path "/var/run/wificfg_prog"
#  define APLIST_PATH "/media/aplist.txt"
#endif

typedef struct conn_rec {
	int fd;
	void *ev;
	unsigned flag, ev_noti;
	void (*destroy)(struct conn_rec*);
} conn_t;

typedef struct wpa_rec {
	conn_t conn;
	aloe_buf_t ctrl, xfer;
} wpa_t;

static void conn_on_noti(int fd, unsigned ev_noti, void *cbarg) {
	((conn_t*)cbarg)->ev_noti = ev_noti;
}

static void wpa_destroy(struct conn_rec *conn) {
	wpa_t *wpa = aloe_container_of(conn, wpa_t, conn);

	if (wpa->conn.fd != -1) close(wpa->conn.fd);
	if (wpa->ctrl.data) free(wpa->ctrl.data);
	if (wpa->xfer.data) free(wpa->xfer.data);
	free(wpa);
}

static int wpa_request(wpa_t *wpa, const char *req, unsigned wait_noti,
		unsigned long timeout, const char *wait_resp) {
	int r, rc = 0, pos0 = (int)wpa->xfer.pos;
	struct timeval ts0, ts;

	if ((r = gettimeofday(&ts0, NULL)) != 0) {
		r = errno;
		log_e("Get current time: %s\n", strerror(r));
		return -1;
	}

	if (req) {
		int len = strlen(req);

		r = write(wpa->conn.fd, req, len);
		if (r < 0) {
			r = errno;
			log_e("write command %s, %s\n", req, strerror(r));
			return -1;
		}
		if (r != len) {
			log_e("write command %s, incomplete\n", req);
			return -1;
		}
		log_d("written command %s\n", req);
	}

#define wpa_request_m(_lf, _fmt, _args...) if (req) { \
	_lf ("command %s, " _fmt, req, ##_args); \
} else { \
	_lf (_fmt, ##_args); \
}
#define wpa_request_v(...) wpa_request_m(log_v, __VA_ARGS__)
#define wpa_request_d(...) wpa_request_m(log_d, __VA_ARGS__)
#define wpa_request_e(...) wpa_request_m(log_e, __VA_ARGS__)

	ts = ts0;
	while (wait_noti) {
		unsigned long tv = ((timeout == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE :
				ts0.tv_sec + timeout - ts.tv_sec);
		wpa->conn.ev_noti = 0;
		if (!(wpa->conn.ev = aloe_ev_put(ev_ctx, wpa->conn.fd,
				&conn_on_noti, wpa, wait_noti, tv, 0))) {
			log_e("schedule event\n");
			return -1;
		}

		wpa_request_v("waiting event %x in %lu seconds\n", wait_noti,tv);

		while (!wpa->conn.ev_noti) aloe_ev_once(ev_ctx);

		wpa_request_v("waited event %x\n", wpa->conn.ev_noti);

		if (!(wpa->conn.ev_noti & aloe_ev_flag_read)) {
			// timeout before wait_resp
			if (wait_resp) {
				wpa_request_d("miss %s, response:\n  %s\n", wait_resp,
						((pos0 < (int)wpa->xfer.pos) ? (char*)wpa->xfer.data : ""));
			}
			break;
		}

		r = read(wpa->conn.fd, (char*)wpa->xfer.data + wpa->xfer.pos,
				wpa->xfer.lmt - wpa->xfer.pos - 1);
		if (r < 0) {
			r = errno;
			if (r == EINTR) {
				log_d("%s\n", strerror(r));
				usleep(100);
				continue;
			}
			wpa_request_e("read response, %s\n", strerror(r));
			return -1;
		}
		((char*)wpa->xfer.data)[wpa->xfer.pos + r] = '\0';

		if (!wait_resp) {
			wpa->xfer.pos += r;
//			wpa_request_d("read response:\n  %s\n", (char*)wpa->xfer.data);
			break;
		}

		if (strstr((char*)wpa->xfer.data + wpa->xfer.pos, wait_resp)) {
			wpa->xfer.pos += r;
			wpa_request_d("matched %s, response:\n  %s\n", wait_resp,
					(char*)wpa->xfer.data);
			rc = 1;
			break;
		}
		wpa_request_v("matching %s, response appended:\n  %s\n", wait_resp,
				(char*)wpa->xfer.data + wpa->xfer.pos);
		wpa->xfer.pos += r;
	}
	return rc;
#undef wpa_request_m
#undef wpa_request_v
#undef wpa_request_d
#undef wpa_request_e
}

#if 0
static void wpa_close(wpa_t *wpa) {
	if (wpa && (wpa->conn.fd != -1)) {
		close(wpa->conn.fd);
		wpa->conn.fd = -1;
	}
	if (wpa->ctrl.data && wpa->ctrl.pos > 0 &&
			_aloe_file_size((char*)wpa->ctrl.data, 0) >= 0) {
		unlink((char*)wpa->ctrl.data);
	}
}
#endif

static int wpa_open(wpa_t *wpa, aloe_buf_t *reason) {
	int r;
	union {
		struct sockaddr sa;
		struct sockaddr_in sa_in;
		struct sockaddr_un sa_un;
	} sa_u;

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}
	if (!wpa->ctrl.data || wpa->ctrl.pos <= 0) {
		if ((r = aloe_buf_aprintf(&wpa->ctrl, sizeof(sa_u.sa_un), "%s",
				wificfg_ctrlpath)) <= 0) {
			log_e("local socket name\n");
			r = -1;
			reason_f("Runtime error: %s", "local socket name");
			goto finally;
		}
		log_v("local socket name refined: %s\n", (char*)wpa->ctrl.data);
	}
	if (wpa->ctrl.pos >= sizeof(sa_u.sa_un)) {
		log_e("local socket name must less then %d but %s\n",
				(int)sizeof(sa_u.sa_un), (char*)wpa->ctrl.data);
		r = -1;
		reason_f("Runtime error: %s", "local socket name");
		goto finally;
	}
	if (_aloe_file_size((char*)wpa->ctrl.data, -1) >= 0) {
		unlink((char*)wpa->ctrl.data);
	}

	if ((wpa->conn.fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		r = errno;
		log_e("Create socket: %s\n", strerror(r));
		r = -1;
		reason_f("Runtime error: %s", "create socket");
		goto finally;
	}
	if (aloe_file_nonblock(wpa->conn.fd, 1) != 0) {
		r = -1;
		wpa_destroy(&wpa->conn);
		reason_f("Runtime error: %s", "set nonblock");
		goto finally;
	}

	sa_u.sa_un.sun_family = AF_UNIX;
	memcpy(sa_u.sa_un.sun_path, wpa->ctrl.data, wpa->ctrl.pos);
	((char*)sa_u.sa_un.sun_path)[wpa->ctrl.pos] = '\0';

	if (bind(wpa->conn.fd, &sa_u.sa, sizeof(sa_u.sa_un)) != 0) {
		r = errno;
		log_e("Bind wificfg: %s\n", strerror(r));
		r = -1;
		reason_f("Runtime error: %s", "connect to wpa_supplicant");
		goto finally;
	}

	r = snprintf(sa_u.sa_un.sun_path, sizeof(sa_u.sa_un.sun_path),
			"%s/%s", wpasup_ctrldir, wificfg_ifce);
	if (r <= 0 || r >= (int)sizeof(sa_u.sa_un.sun_path)) {
		r = -1;
		reason_f("Runtime error: %s", "local socket name");
		goto finally;
	}
	sa_u.sa_un.sun_family = AF_UNIX;
	if (connect(wpa->conn.fd, &sa_u.sa, sizeof(sa_u.sa_un)) != 0) {
		r = errno;
		if (r != EAGAIN && r != EINPROGRESS) {
			log_e("Connect to wpa_supplication: %s\n", strerror(r));
			r = -1;
			reason_f("Runtime error: %s", "connect to wpa_supplicant");
			goto finally;
		}
	}
	wpa->conn.destroy = &wpa_destroy;

	aloe_buf_clear(&wpa->xfer);
	if (wpa_request(wpa, NULL, aloe_ev_flag_write, 1, NULL) < 0) {
		r = -1;
		reason_f("Runtime error: %s", "connect to wpa_supplicant");
		goto finally;
	}
	if ((wpa->conn.ev_noti & aloe_ev_flag_write) == 0) {
		r = -1;
		log_e("Failed connect to wpa_supplicant\n");
		reason_f("Runtime error: %s", "connect to wpa_supplicant");
		goto finally;
	}
	log_d("Connected to wpa_supplicant (%s)\n", sa_u.sa_un.sun_path);

	aloe_buf_clear(&wpa->xfer);
	if (wpa_request(wpa, "ATTACH", aloe_ev_flag_read, 1, "OK\n") != 1) {
		r = -1;
		reason_f("Runtime error: %s", "communication to wpa_supplicant");
		goto finally;
	}
	log_d("Attached to wpa_supplicant\n");

	r = 0;
finally:
	if (r != 0) {
		if (wpa->conn.fd != -1) {
			close(wpa->conn.fd);
			wpa->conn.fd = -1;
		}
	}
	return r;
#undef reason_f
}

#if defined(USER_PREFIX) // mock-up
__attribute__((unused))
#endif
static int wpa_scan(wpa_t *wpa, aloe_buf_t *reason) {
	int r;

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}
	if (wpa->conn.fd == -1 && (r = wpa_open(wpa, reason)) != 0) return r;

	aloe_buf_clear(&wpa->xfer);
	if (wpa_request(wpa, "SCAN", aloe_ev_flag_read, 1, "OK\n") != 1) {
		r = -1;
		reason_f("Runtime error: %s", "communication to wpa_supplicant");
		goto finally;
	}

	aloe_buf_clear(&wpa->xfer);
	if (wpa_request(wpa, NULL, aloe_ev_flag_read, 10,
			"CTRL-EVENT-SCAN-RESULTS") != 1) {
		r = -1;
		reason_f("Runtime error: %s", "wait scan result");
		goto finally;
	}

	while (1) {
		aloe_buf_clear(&wpa->xfer);
		if (wpa_request(wpa, "SCAN_RESULTS", aloe_ev_flag_read, 2, NULL) < 0
				|| wpa->xfer.pos <= 0) {
			r = -1;
			reason_f("Runtime error: %s", "communication to wpa_supplicant");
			goto finally;
		}
		if (*(char*)wpa->xfer.data != '<') break;
		log_d("Recv tag: %s\n", (char*)wpa->xfer.data);
	}
//	log_d("get result %d bytes:\n  %s", wpa->xfer.pos, (char*)wpa->xfer.data);
	r = 0;
finally:
	return r;
#undef reason_f
}

static int wpa_scanresult_parse(aloe_buf_t *buf, cJSON **jarr,
		aloe_buf_t *reason) {
	int r;
	char *ln1, *ln1_tok;

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}

	// skip 'bssid / frequency / signal level / flags / ssid'
	if (!(ln1 = strtok_r((char*)buf->data, "\n", &ln1_tok))) {
		log_e("Failed parse aplist line1\n");
		r = -1;
		reason_f("Runtime error: %s", "parse aplist");
		goto finally;
	}

	if (jarr && !*jarr && !(*jarr = cJSON_CreateArray())) {
		log_e("Failed create json array\n");
		r = -1;
		reason_f("Runtime error: %s", "parse aplist");
		goto finally;
	}

	while ((ln1 = strtok_r(NULL, "\n", &ln1_tok))) {
#define SSID_LEN 33
#define FLAGS_LEN 128
		char bssid[SSID_LEN + 1], flags[FLAGS_LEN + 1], ssid[SSID_LEN + 1];
		int freq = 0, rssi = -999, bssid_len, flags_len, ssid_len;
		cJSON *jln1, *jobj;

		bssid[0] = flags[0] = ssid[0] = '\0';
		r = sscanf(ln1, "%" aloe_stringify(SSID_LEN) "s %d %d"
				" %" aloe_stringify(FLAGS_LEN) "s"
				" %" aloe_stringify(SSID_LEN) "[^\n]", bssid, &freq, &rssi, flags,
				ssid);

		if ((bssid_len = strlen(bssid)) >= SSID_LEN
				|| (flags_len = strlen(flags)) >= FLAGS_LEN
				|| (ssid_len = strlen(ssid)) >= SSID_LEN) {
			log_e("Failed parse %s\n", ln1);
			continue;
		}
//		log_v("ssid: \"%s\" (bssid: %s), freq: %d, rssi: %d, flags: %s\n",
//				ssid, bssid, freq, rssi, flags);

		if (!jarr) continue;

		if (!(jln1 = cJSON_CreateObject())
				|| !(jobj = cJSON_AddStringToObject(jln1, "ssid", ssid))
				|| !(jobj = cJSON_AddStringToObject(jln1, "bssid", bssid))
				|| !(jobj = cJSON_AddStringToObject(jln1, "flags", flags))
				|| !(jobj = cJSON_AddNumberToObject(jln1, "freq", freq))
				|| !(jobj = cJSON_AddNumberToObject(jln1, "rssi", rssi))
				|| !cJSON_AddItemToArray(*jarr, jln1)) {
			if (jln1) cJSON_free(jln1);
			log_e("Failed create json array\n");
			r = -1;
			reason_f("Runtime error: %s", "parse aplist");
			goto finally;
		}
	}
	r = 0;
finally:
	return r;
#undef reason_f
}

typedef enum wpa_sec_enum {
	wpa_sec_open,
	wpa_sec_wpa_tkip,
	wpa_sec_wpa_ccmp,
	wpa_sec_wpa2_ccmp,
	wpa_sec_wpa3_sae,
	wpa_sec_enum_max,
} wpa_sec_t;

static struct {
	const char *ids;
	wpa_sec_t sec;
} wpa_sec_lut[] = {
	{"Open", wpa_sec_open}, {"WPA-TKIP", wpa_sec_wpa_tkip},
	{"WPA-CCMP", wpa_sec_wpa_ccmp}, {"WPA2-CCMP", wpa_sec_wpa2_ccmp},
	{"WPA3-SAE", wpa_sec_wpa3_sae}, {"NONE", wpa_sec_open}, {NULL},
};

#define wpa_flag_hidden_ssid (1 << 0)
#define ip_mode_dhcp (1 << 0)
#define ip_mode_zcip (1 << 1)
#define ip_mode_auto (1 << 2)
#define ip_mode_not_static (ip_mode_dhcp | ip_mode_zcip | ip_mode_auto)

static int wpa_getcfg(cJSON **jout, aloe_buf_t *reason) {
	int r, scan_ssid = 0;
	aloe_buf_t buf = {NULL};
	regmatch_t mah[2];
	char ssid[40], proto[20], key_mgmt[20], pairwise[20], ieee80211w[20];
#if defined(USER_PREFIX)
	char psk[200];
#endif
	const char *sec_str;
	wpa_sec_t sec = wpa_sec_enum_max;

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

	ssid[0] = proto[0] = key_mgmt[0] = pairwise[0] = '\0';

	if ((r = aloe_file_size(wpasup_cfg, 0)) < 0) {
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
	if (aloe_file_fread(wpasup_cfg, &buf) <= 0) {
		log_e("Load %s\n", wpasup_cfg);
		r = -1;
		reason_f("Runtime error: %s", "read config file");
		goto finally;
	}
	aloe_buf_flip(&buf);

	// find network block
	mah_reset();
	r = air192_regex_test1((char*)buf.data,
				"[^#]\\s*network\\s*=\\s*\\{\\s*([^{]*)\\s*}",
				REG_ICASE | REG_EXTENDED,
				aloe_arraysize(mah), mah);
	if (r == REG_NOMATCH) {
		r = 0;
		log_d("Empty network file\n");
		goto finally;
	}
	if (r != 0 || mah[1].rm_so < 0) {
		log_e("parse network block\n");
		r = -1;
		reason_f("Runtime error: %s", "read config file");
		goto finally;
	}
//	log_d("network block %d(+%d)\n", mah[1].rm_so, mah[1].rm_eo - mah[1].rm_so);

	buf.pos = mah[1].rm_so;
	((char*)buf.data)[mah[1].rm_eo] = '\0';
	log_d("network block %d(+%d)\n%s\n", mah[1].rm_so, mah_len(&mah[1]),
			(char*)buf.data + buf.pos);

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

	mah_ids1("ssid", ssid, "\"(.*)\"");
	if (!ssid[0]) {
		log_e("parse ssid\n");
		r = -1;
		reason_f("Runtime error: %s", "read config file");
		goto finally;
	}

	// find scan_ssid ie. hidden ssid
	mah_reset();
	r = air192_regex_test1((char*)buf.data + buf.pos,
			"^\\s*scan_ssid\\s*=\\s*(1)\\s*",
			REG_ICASE | REG_EXTENDED | REG_NEWLINE,
			aloe_arraysize(mah), mah);
	if (r == 0) {
		log_d("scan_ssid=1 %d(+%d)\n", (int)buf.pos + mah[1].rm_so, mah_len(&mah[1]));
		scan_ssid = 1;
	} else if (r == REG_NOMATCH) {
		scan_ssid = 0;
	} else {
		log_e("parse scan_ssid\n");
		r = -1;
		reason_f("Runtime error: %s", "read config file");
		goto finally;
	}
	log_d("hidden ssid: %s\n", (scan_ssid ? "yes" : "no"));

	mah_ids1("key_mgmt", key_mgmt, "(.*)");
	mah_ids1("proto", proto, "(.*)");
	mah_ids1("pairwise", pairwise, "(.*)");
	mah_ids1("ieee80211w", ieee80211w, "(.*)");

	// quoted plain
#if defined(USER_PREFIX)
	mah_ids1("psk", psk, "(.*)");
#endif

	sec = wpa_sec_enum_max;
	if (strcasecmp(key_mgmt, "NONE") == 0) {
		sec = wpa_sec_open;
	} else if (strcasecmp(key_mgmt, "SAE") == 0) {
		sec = wpa_sec_wpa3_sae;
	} else if (strcasecmp(proto, "WPA") == 0) {
		if (strcasecmp(pairwise, "TKIP") == 0) {
			sec = wpa_sec_wpa_tkip;
		} else if (strcasecmp(pairwise, "CCMP") == 0) {
			sec = wpa_sec_wpa_ccmp;
		}
	} else if (strstr(proto, "RSN") || strstr(proto, "rsn")
			 || strstr(proto, "WPA2") || strstr(proto, "wpa2")) {
		if (strcasecmp(pairwise, "CCMP") == 0) {
			sec = wpa_sec_wpa2_ccmp;
		}
	}
	for (r = 0; r < (int)aloe_arraysize(wpa_sec_lut); r++) {
		if (!wpa_sec_lut[r].ids || sec == wpa_sec_lut[r].sec ) {
			break;
		}
	}
	sec_str = ((r < (int)aloe_arraysize(wpa_sec_lut) && wpa_sec_lut[r].ids) ?
			wpa_sec_lut[r].ids : NULL);
	log_d("sec: %s\n", sec_str);

	if ((r = air192_cgireq_ipcfg_read(wlan_cfg, jout, reason)) != 0) {
		log_e("Failed get ipcfg for wlan\n");
		goto finally;
	}

	if (jout) {
		if ((!*jout && !(*jout = cJSON_CreateObject()))
				|| !(cJSON_AddStringToObject(*jout, "ssid", ssid))
#if defined(USER_PREFIX)
				|| (psk[0] && !(cJSON_AddStringToObject(*jout, "psk", psk)))
#endif
				|| (scan_ssid && !(cJSON_AddTrueToObject(*jout, "hidden_ssid")))
				|| (sec_str && !(cJSON_AddStringToObject(*jout, "security_proto", sec_str))) ) {
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
#undef mah_ids1
#undef mah_reset
#undef mah_len
}

static int wpa_setup(wpa_t *wpa, unsigned flag, wpa_sec_t sec, const char *ssid,
		const char *psk, const char *ip, const char *msk, const char *gw,
		const char *dns, aloe_buf_t *reason) {
	int r;
	aloe_buf_t buf = {NULL};

#define reason_f(...) if (reason && reason->data) { \
	aloe_buf_clear(reason); \
	if (aloe_buf_printf(reason, __VA_ARGS__) < 0) { \
		aloe_buf_printf(reason, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
}

	if ((r = aloe_buf_expand(&buf, 1000, aloe_buf_flag_none)) != 0) {
		log_e("alloc buffer to write wificfg\n");
		r = -1;
		reason_f("Runtime error: %s", "No memory");
		goto finally;
	}
	aloe_buf_clear(&buf);

	if (aloe_buf_printf(&buf,
			"ctrl_interface=/var/run/wpa_supplicant\n"
			"update_config=1\n"
			"country=TW\n"
			"p2p_disabled=1\n"
			"\n") <= 0) {
		log_e("Compose wifi config global scope\n");
		r = -1;
		reason_f("Runtime error: %s", "Compose wifi config\n");
		goto finally;
	}

	if (sec == wpa_sec_open) {
		if (aloe_buf_printf(&buf,
				"network={\n"
				"  %s"
				"  ssid=\"%s\"\n"
				"  key_mgmt=NONE\n"
				"}\n", ((flag & wpa_flag_hidden_ssid) ? "scan_ssid=1\n" : ""),
				ssid) <= 0) {
			log_e("Compose wifi config network scope\n");
			r = -1;
			reason_f("Runtime error: %s", "Compose wifi config\n");
			goto finally;
		}
	} else if (sec == wpa_sec_wpa_tkip) {
		if (aloe_buf_printf(&buf,
				"network={\n"
				"  %s"
				"  ssid=\"%s\"\n"
				"  proto=WPA\n"
				"  key_mgmt=WPA-PSK\n"
				"  pairwise=TKIP\n"
				"  psk=\"%s\"\n"
				"}\n", ((flag & wpa_flag_hidden_ssid) ? "scan_ssid=1\n" : ""),
				ssid, psk) <= 0) {
			log_e("Compose wifi config network scope\n");
			r = -1;
			reason_f("Runtime error: %s", "Compose wifi config\n");
			goto finally;
		}
	} else if (sec == wpa_sec_wpa_ccmp) {
		if (aloe_buf_printf(&buf,
				"network={\n"
				"  %s"
				"  ssid=\"%s\"\n"
				"  proto=WPA\n"
				"  key_mgmt=WPA-PSK\n"
				"  pairwise=CCMP\n"
				"  psk=\"%s\"\n"
				"}\n", ((flag & wpa_flag_hidden_ssid) ? "scan_ssid=1\n" : ""),
				ssid, psk) <= 0) {
			log_e("Compose wifi config network scope\n");
			r = -1;
			reason_f("Runtime error: %s", "Compose wifi config\n");
			goto finally;
		}
	} else if (sec == wpa_sec_wpa2_ccmp) {
		if (aloe_buf_printf(&buf,
				"network={\n"
				"  %s"
				"  ssid=\"%s\"\n"
				"  proto=RSN\n"
				"  key_mgmt=WPA-PSK\n"
				"  pairwise=CCMP\n"
				"  psk=\"%s\"\n"
				"}\n", ((flag & wpa_flag_hidden_ssid) ? "scan_ssid=1\n" : ""),
				ssid, psk) <= 0) {
			log_e("Compose wifi config network scope\n");
			r = -1;
			reason_f("Runtime error: %s", "Compose wifi config\n");
			goto finally;
		}
	} else if (sec == wpa_sec_wpa3_sae) {
		if (aloe_buf_printf(&buf,
				"network={\n"
				"  %s"
				"  ssid=\"%s\"\n"
				"  key_mgmt=SAE\n"
				"  psk=\"%s\"\n"
				"  ieee80211w=2\n"
				"}\n", ((flag & wpa_flag_hidden_ssid) ? "scan_ssid=1\n" : ""),
				ssid, psk) <= 0) {
			log_e("Compose wifi config network scope\n");
			r = -1;
			reason_f("Runtime error: %s", "Compose wifi config\n");
			goto finally;
		}
	}
	aloe_buf_flip(&buf);
	if ((r = aloe_file_fwrite(wpasup_cfg, &buf)) != (int)(buf.lmt - buf.pos)) {
		log_e("Write %s\n", wpasup_cfg);
		r = -1;
		reason_f("Runtime error: %s", "Write wifi config\n");
		goto finally;
	}
	log_d("output to %s:\n  %s\n", wpasup_cfg, (char*)buf.data);

	if ((r = air192_cgireq_ipcfg_save(ip, msk, gw, dns, reason, wlan_cfg)) != 0) {
		log_e("Save ip config\n");
		goto finally;
	}
	r = 0;
finally:
	if (buf.data) free(buf.data);
	return r;
#undef reason_f
}

int admin_wificfg(int argc, char * const *argv) {
	int r, prog_st, prog_iter, prog_refine = 0;
	const char *str, *reason = NULL;
	aloe_buf_t cmdbuf  = {.data = NULL};
	cJSON *jroot = NULL, *jout = NULL, *jobj;
	wpa_t *wpa = NULL;
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
	log_d("load wificfg prog: %d, iter: %d\n", prog_st, prog_iter);

	if (prog_st >= prog_fatal) {
		r = -1;
		reason_f("Fatal error");
		goto finally;
	}

	if (prog_st < prog_complete && prog_st != prog_null) {
		r = prog_st;
		reason_f("wificfg progressing");
		goto finally;
	}

	// CONTENT_TYPE=application/json
	// CONTENT_LENGTH=12
	aloe_buf_clear(&cmdbuf);
#if defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"get_config\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"set_config\""
			", \"ssid\": \"airport\", \"password\": \"12345678\""
			", \"hidden_ssid\": true"
			", \"security_proto\": \"open\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"set_config\""
			", \"ssid\": \"airport\", \"password\": \"12345678\""
			", \"hidden_ssid\": true"
			", \"security_proto\": \"WPA-TKIP\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"set_config\""
			", \"ssid\": \"airport\", \"password\": \"12345678\""
			", \"hidden_ssid\": true"
			", \"security_proto\": \"WPA2-CCMP\"}");
#elif defined(USER_PREFIX) && 0
	aloe_buf_printf(&cmdbuf, "{\"command\": \"get_aplist\"}");
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
		if ((r = wpa_getcfg(&jout, &cmdbuf)) != 0) {
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
		const char *ssid, *psk, *sec_str;
		unsigned flag = 0;
		wpa_sec_t sec;

		if (!(jobj = cJSON_GetObjectItem(jroot, "security_proto"))
				|| !(sec_str = cJSON_GetStringValue(jobj))) {
			r = -1;
			reason_f("Invalid request: %s", "security_proto");
			goto finally;
		}

		for (r = 0; r < (int)aloe_arraysize(wpa_sec_lut); r++) {
			if (!wpa_sec_lut[r].ids
					|| strcasecmp(sec_str, wpa_sec_lut[r].ids) == 0) {
				break;
			}
		}
		if (r >= (int)aloe_arraysize(wpa_sec_lut) || !wpa_sec_lut[r].ids) {
			r = -1;
			reason_f("Invalid request: %s", "security_proto");
			goto finally;
		}
		sec = wpa_sec_lut[r].sec;

		if (!(jobj = cJSON_GetObjectItem(jroot, "ssid"))
				|| !(ssid = cJSON_GetStringValue(jobj))) {
			r = -1;
			reason_f("Invalid request: %s", "ssid");
			goto finally;
		}

		if (sec == wpa_sec_open) {
			psk = NULL;
		} else if (!(jobj = cJSON_GetObjectItem(jroot, "password"))
				|| !(psk = cJSON_GetStringValue(jobj))) {
			r = -1;
			reason_f("Invalid request: %s", "password");
			goto finally;
		}

		if ((jobj = cJSON_GetObjectItem(jroot, "hidden_ssid")) &&
				cJSON_IsTrue(jobj)) {
			flag |= wpa_flag_hidden_ssid;
		}

		if ((r = air192_cgireq_ipcfg_unmarshal(jroot, &ip, &msk, &gw,
				&dns, &cmdbuf)) != 0) {
			goto finally;
		}

		if ((r = wpa_setup(wpa, flag, sec, ssid, psk, ip, msk, gw, dns,
				&cmdbuf)) != 0) {
			r = -1;
			reason_f("Failed setup");
			goto finally;
		}

		r = 0;
		reason = NULL;
		goto finally;
	}

	if (strcasecmp(str, "get_aplist") == 0) {
		if (!jout && !(jout = cJSON_CreateObject())) {
			log_e("alloc json output\n");
			r = -1;
			reason_f("Runtime error: %s", "No memory");
			goto finally;
		}

		if (!ev_ctx && !(ev_ctx = aloe_ev_init())) {
			r = -1;
			reason_f("Runtime error: %s", "event system");
			goto finally;
		}

		if (!(wpa = (wpa_t*)calloc(1, sizeof(*wpa)))
				|| aloe_buf_expand(&wpa->ctrl, 100, aloe_buf_flag_none) != 0
				|| aloe_buf_expand(&wpa->xfer, 5000, aloe_buf_flag_none) != 0) {
			r = -1;
			reason_f("Out of memory");
			goto finally;
		}
		wpa->conn.fd = -1;
		aloe_buf_clear(&wpa->ctrl);
		aloe_buf_clear(&wpa->xfer);

#if defined(USER_PREFIX) // mock-up
		if (aloe_file_fread(APLIST_PATH, &wpa->xfer) <= 0) {
			log_e("load %s\n", APLIST_PATH);
			r = -1;
			reason_f("load %s", APLIST_PATH);
			goto finally;
		}
#else
		if ((r = wpa_scan(wpa, &cmdbuf)) != 0) {
			r = -1;
			reason = (char*)cmdbuf.data;
			goto finally;
		}
#  if 1 // dump to mock-up
		{
			aloe_buf_t xfer = wpa->xfer;
			aloe_buf_flip(&xfer);
			aloe_file_fwrite(APLIST_PATH, &xfer);
			log_d("output to %s:\n  %s\n", APLIST_PATH, (char*)xfer.data);
		}
#  endif
#endif
		jobj = NULL;
		if ((r = wpa_scanresult_parse(&wpa->xfer, &jobj, &cmdbuf)) != 0) {
			if (jobj) cJSON_Delete(jobj);
			r = -1;
			reason = (char*)cmdbuf.data;
			goto finally;
		}
		if (!cJSON_AddItemToObject(jout, "aplist", jobj)) {
			cJSON_Delete(jobj);
			r = -1;
			reason_f("Runtime error: %s", "parse aplist");
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
	if (wpa) wpa_destroy(&wpa->conn);
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
}

