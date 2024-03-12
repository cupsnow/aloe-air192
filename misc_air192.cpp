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
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/random.h>
#include <mqueue.h>
#include <pthread.h>

#include "priv.h"
#include <admin/air192.h>
#include <admin/sa7715.h>
#include <admin/WPACtrl.h>

#define APPCFG "/etc/sa7715.json"

typedef struct conn_rec {
	int fd;
	void *ev;
	unsigned flag, ev_noti;
	void (*destroy)(struct conn_rec*);
} conn_t;

typedef struct wpa_rec {
	conn_t conn;
	const char *ctrlPath;
	aloe_buf_t xfer;
	void *ev_ctx;
} wpa_t;

static void wpa_conn_on_noti(int fd, unsigned ev_noti, void *cbarg) {
	((conn_t*)cbarg)->ev_noti = ev_noti;
}

static void wpa_destroy(struct conn_rec *conn) {
	wpa_t *wpa = aloe_container_of(conn, wpa_t, conn);

	if (wpa->conn.fd != -1) close(wpa->conn.fd);
	free(wpa);
}

static int wpa_request(wpa_t *wpa, const char *req, unsigned wait_noti,
		unsigned long timeout, const char *wait_resp, aloe_buf_t *xfer) {
	int r, rc = 0, retry, len;
	struct timeval ts0, ts;

	if (!xfer) xfer = &wpa->xfer;

	if ((r = gettimeofday(&ts0, NULL)) != 0) {
		r = errno;
		log_e("Get current time: %s\n", strerror(r));
		return -1;
	}

	if (req && (len = strlen(req)) > 0) {
#if 1
		for (retry = 3; retry > 0; retry--) {
			r = write(wpa->conn.fd, req, len);
			if (r < 0) {
				r = errno;
				if ((r == EAGAIN
#ifdef EWOULDBLOCK
						|| r == EWOULDBLOCK
#endif
				) && retry > 1) {
					log_e("retry command %s (%d more)\n", req, (retry - 1));
					sleep(1);
					continue;
				}
				log_e("write command %s, %s\n", req, strerror(r));
				return -1;
			}
			if (r != len) {
				log_e("write command %s, incomplete\n", req);
				return -1;
			}
			log_d("written command %s\n", req);
			break;
		}
		if (retry <= 0) {
			log_e("Failed write command %s\n", req);
			return -1;
		}
#else
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
#endif
	}

	ts = ts0;
	while (wait_noti) {
		unsigned long tv = ((timeout == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE :
				ts0.tv_sec + timeout - ts.tv_sec);
		wpa->conn.ev_noti = 0;
		if (!(wpa->conn.ev = aloe_ev_put(wpa->ev_ctx, wpa->conn.fd,
				&wpa_conn_on_noti, &wpa->conn, wait_noti, tv, 0))) {
			log_e("schedule event\n");
			return -1;
		}

		log_d("%s%swait %d seconds for event " _ALOE_EV_FMT "%s%s\n", \
				(req ? req : ""),  (req ? " " : ""),
				(int)tv, _ALOE_EV_ARG(wait_noti),
				(wait_resp ? " until " : ""), (wait_resp ? wait_resp : ""));

		while (!wpa->conn.ev_noti) aloe_ev_once(wpa->ev_ctx);

		log_v("Recv event " _ALOE_EV_FMT "\n", _ALOE_EV_ARG(wpa->conn.ev_noti));

		if (!(wpa->conn.ev_noti & aloe_ev_flag_read)) {
			// timeout before wait_resp
			if (wait_resp) {
				log_e("Timeout for response\n");
			}
			break;
		}

		r = read(wpa->conn.fd, (char*)xfer->data + xfer->pos,
				xfer->lmt - xfer->pos - 1);
		if (r < 0) {
			r = errno;
			if (r == EINTR) {
				log_v("Again from %s\n", strerror(r));
				usleep(100);
				continue;
			}
			log_e("Read for response %s\n", strerror(r));
			return -1;
		}
		((char*)xfer->data)[xfer->pos + r] = '\0';

		log_v("Recv %d bytes %s\n", r, (char*)xfer->data + xfer->pos);

		if (!wait_resp) {
			// Read through
			xfer->pos += r;
			break;
		}

		if (strstr((char*)xfer->data + xfer->pos, wait_resp)) {
			xfer->pos += r;
			rc = 1;
			break;
		}
		xfer->pos += r;
		if ((r = gettimeofday(&ts, NULL)) != 0) {
			r = errno;
			log_e("Get current time: %s\n", strerror(r));
			return -1;
		}
	}
	return rc;
}

extern "C"
void air192_wpa_close(void *ctx) {
	wpa_t *wpa = (wpa_t*)ctx;

	if (wpa) {
		if (wpa->conn.fd != -1) close(wpa->conn.fd);
		if (wpa->ctrlPath && wpa->ctrlPath[0]
				&& _aloe_file_size(wpa->ctrlPath, 0) >= 0) {
			unlink(wpa->ctrlPath);
		}
		if (wpa->ev_ctx) aloe_ev_destroy(wpa->ev_ctx);
		free(wpa);
	}
}

extern "C"
void* air192_wpa_open(const char *ctrlPath, const char *wpaPath
		, const char *ifce) {
	int r;
	union {
		struct sockaddr sa;
		struct sockaddr_in sa_in;
		struct sockaddr_un sa_un;
	} sa_u;
	wpa_t *wpa = NULL;
	int ctrlPathLen = ctrlPath ? strlen(ctrlPath) : 0;
	int wpaPathLen = wpaPath ? strlen(wpaPath) : 0;
	int ifceLen = ifce ? strlen(ifce) : 0;
	int xferLen = 5000;
	char *ctrlPathBak;

	if (ctrlPathLen <= 0 || ctrlPathLen >= (int)sizeof(sa_u.sa_un)) {
		r = EINVAL;
		log_e("ctrlPath length not within 0 < %d < %d, %s\n",
				ctrlPathLen, (int)sizeof(sa_u.sa_un),
				ctrlPath ? ctrlPath : "Null");
		goto finally;
	}

	// "wpaPath/ifce\0"
	if (wpaPathLen <= 0 || ifceLen <= 0
			|| (wpaPathLen + ifceLen + 2) >= (int)sizeof(sa_u.sa_un)) {
		r = EINVAL;
		log_e("wpaIfcePath length not within 0 < %d < %d, %s/%s\n",
				wpaPathLen + ifceLen + 1, (int)sizeof(sa_u.sa_un),
				(wpaPath ? wpaPath : "Null"),
				(ifce ? ifce : "Null"));
		goto finally;
	}

	if ((wpa = (wpa_t*)malloc(sizeof(*wpa)
			+ ctrlPathLen + 1
			+ xferLen)) == NULL) {
		r = ENOMEM;
		log_e("alloc wpa\n");
		goto finally;
	}
	memset(wpa, 0, sizeof(*wpa));
	wpa->conn.fd = -1;
	wpa->ctrlPath = ctrlPathBak = (char*)(wpa + 1);
	wpa->xfer.data = (void*)(wpa->ctrlPath + ctrlPathLen + 1);
	wpa->xfer.cap = xferLen;
	memcpy(ctrlPathBak, ctrlPath, ctrlPathLen);
	ctrlPathBak[ctrlPathLen] = '\0';

	if (!(wpa->ev_ctx = aloe_ev_init())) {
		r = ENOMEM;
		log_e("Create event loop, %s\n", strerror(r));
		goto finally;
	}

	if (_aloe_file_size(ctrlPath, -1) >= 0) unlink(ctrlPath);

	if ((wpa->conn.fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		r = errno;
		log_e("Create socket, %s\n", strerror(r));
		goto finally;
	}
	if ((r = aloe_file_nonblock(wpa->conn.fd, 1)) != 0) {
		r = EIO;
		goto finally;
	}

	sa_u.sa_un.sun_family = AF_UNIX;
	memcpy(sa_u.sa_un.sun_path, ctrlPath, ctrlPathLen);
	((char*)sa_u.sa_un.sun_path)[ctrlPathLen] = '\0';
	if (bind(wpa->conn.fd, &sa_u.sa, sizeof(sa_u.sa_un)) != 0) {
		r = errno;
		log_e("Bind ctrlPath, %s\n", strerror(r));
		goto finally;
	}

	sa_u.sa_un.sun_family = AF_UNIX;
	memcpy(sa_u.sa_un.sun_path, wpaPath, wpaPathLen);
	((char*)sa_u.sa_un.sun_path)[wpaPathLen] = '/';
	memcpy((char*)sa_u.sa_un.sun_path + wpaPathLen + 1, ifce, ifceLen);
	((char*)sa_u.sa_un.sun_path)[wpaPathLen + 1 + ifceLen] = '\0';
	if (connect(wpa->conn.fd, &sa_u.sa, sizeof(sa_u.sa_un)) != 0) {
		r = errno;
		if (r != EAGAIN && r != EINPROGRESS) {
			log_e("Connect to wpasup: %s\n", strerror(r));
			goto finally;
		}
	}
	wpa->conn.destroy = &wpa_destroy;

	log_d("Waiting connect to wpasup\n");
	if (wpa_request(wpa, NULL, aloe_ev_flag_write, 1,
			NULL, aloe_buf_clear(&wpa->xfer)) < 0
			|| !(wpa->conn.ev_noti & aloe_ev_flag_write)) {
		r = EIO;
		log_e("Connect to wpasup\n");
		goto finally;
	}
	log_d("Connected to wpasup (%s)\n", sa_u.sa_un.sun_path);

	log_d("Waiting attach to wpasup\n");
	if (wpa_request(wpa, "ATTACH", aloe_ev_flag_read, 1,
			"OK\n", aloe_buf_clear(&wpa->xfer)) != 1) {
		r = EIO;
		log_e("Attach to wpasup\n");
		goto finally;
	}
	log_d("Attached to wpasup\n");
	r = 0;
finally:
	if (r != 0) {
		air192_wpa_close(wpa);
		return NULL;
	}
	return wpa;
}

extern "C"
const aloe_buf_t* air192_wpa_scan(void *ctx, long dur, aloe_buf_t *buf) {
	wpa_t *wpa = (wpa_t*)ctx;

	if (wpa_request(wpa, "SCAN", aloe_ev_flag_read, 1,
			"OK\n", aloe_buf_clear(&wpa->xfer)) != 1) {
		log_e("Command scan to wpasup\n");
		return NULL;
	}

	if (wpa_request(wpa, NULL, aloe_ev_flag_read, dur,
			"CTRL-EVENT-SCAN-RESULTS", aloe_buf_clear(&wpa->xfer)) != 1) {
		log_e("Cannot wait scan result\n");
		return NULL;
	}

	if (!buf) buf = aloe_buf_clear(&wpa->xfer);
	while (1) {
		size_t pos0 = buf->pos;
		if (wpa_request(wpa, "SCAN_RESULTS", aloe_ev_flag_read, 20,
				NULL, buf) < 0
				|| buf->pos <= 0) {
			log_e("Cannot get scan result\n");
			return NULL;
		}
		if (*(char*)buf->data != '<') break;
		if (buf->pos > pos0) {
			log_d("wpasup reply add: %s\n", (char*)buf->data + pos0);
		}
	}
	log_d("wpasup scan result %d bytes\n%s",
			(int)buf->pos, (char*)buf->data);
	return buf;
}

extern "C"
int air192_wpa_disconnect(void *ctx) {
	wpa_t *wpa = (wpa_t*)ctx;

	if (wpa_request(wpa, "DISCONNECT", aloe_ev_flag_read, 1,
			"OK\n", aloe_buf_clear(&wpa->xfer)) != 1) {
		log_e("Command disconnect to wpasup\n");
		return -1;
	}
	return 0;
}

extern "C"
int air192_wpa_scanresult_parse(aloe_buf_t *buf, cJSON **jarr) {
	char *ln1, *ln1_tok;

	if (!buf || !buf->data) return -1;

	// skip 'bssid / frequency / signal level / flags / ssid'
	if (!(ln1 = strtok_r((char*)buf->data, "\n", &ln1_tok))) {
		log_e("Failed parse aplist line1\n");
		return -1;
	}

	if (jarr && !*jarr && !(*jarr = cJSON_CreateArray())) {
		log_e("Failed create json array\n");
		return -1;
	}

	while ((ln1 = strtok_r(NULL, "\n", &ln1_tok))) {
#define SSID_LEN 33
#define FLAGS_LEN 128
		char bssid[SSID_LEN + 1], flags[FLAGS_LEN + 1], ssid[SSID_LEN + 1];
		int freq = 0, rssi = -999, bssid_len, flags_len, ssid_len;
		cJSON *jln1, *jobj;

		bssid[0] = flags[0] = ssid[0] = '\0';
		sscanf(ln1, "%" aloe_stringify(SSID_LEN) "s %d %d"
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
			log_e("Failed add to json array\n");
			return -1;
		}
	}
	return 0;
}

extern "C"
int air192_wpa_scanresult_parse_sec(const char *sec_str,
		air192_wpa_sec_t *sec, int sec_max) {
	int sec_cnt = 0;

	if (sec_max <= 0) return 0;

	if (strcasecmp(sec_str, "WPA2-PSK-TKIP") == 0 ||
			strcasecmp(sec_str, "WPA2-PSK-TKIP-preauth") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa2_tkip;
		return sec_cnt;
	}
	if (strcasecmp(sec_str, "WPA2-PSK-CCMP") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa2_ccmp;
		return sec_cnt;
	}
	if (strcasecmp(sec_str, "WPA2-PSK-CCMP+TKIP") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa2_ccmp_tkip;
		return sec_cnt;
	}
	if (strcasecmp(sec_str, "WPA-PSK-TKIP") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa_tkip;
		return sec_cnt;
	}
	if (strcasecmp(sec_str, "WPA-PSK-CCMP") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa_ccmp;
		return sec_cnt;
	}
	if (strcasecmp(sec_str, "WPA-PSK-CCMP+TKIP") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa_ccmp_tkip;
		return sec_cnt;
	}
	if (strcasecmp(sec_str, "WPA2-SAE-CCMP") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa3_sae;
		return sec_cnt;
	}
	if (strcasecmp(sec_str, "WPA2-PSK+SAE-CCMP") == 0) {
		sec[sec_cnt++] = air192_wpa_sec_wpa3_sae;
		if (sec_cnt >= sec_max) return sec_cnt;
		sec[sec_cnt++] = air192_wpa_sec_wpa2_ccmp;
		return sec_cnt;
	}

	return sec_cnt;
}

extern "C"
int air192_wpa_scanresult_parse_flags(const char *flags,
		air192_wpa_sec_t *sec, int sec_max) {
	int sec_cnt = 0;

	while (flags && *flags && sec_cnt < sec_max) {
		const char *str;
		char sec_str[64];
		int len;

		if (!(str = strchr(flags, '[')) || !(flags = strchr(++str, ']'))) break;
		// str point after '[', flags point to ']'

		str += strspn(str, " [\t");
		// str point to flag string

//		len = aloe_strip_end(str, flags++ - str, " \t");
		len = flags++ - str;
		len -= aloe_strrspn(str, flags++ - str, " \t");
		// flags point after ']', len is flag string length

		if (len <= 0) continue;

		if (len >= (int)sizeof(sec_str)) {
			log_e("Wifi flag string too long %d >= %d\n", len, (int)sizeof(sec_str));
			continue;
		}
		memcpy(sec_str, str, len);
		sec_str[len] = '\0';

		sec_cnt += air192_wpa_scanresult_parse_sec(sec_str, &sec[sec_cnt],
				sec_max - sec_cnt);
	}
	return sec_cnt;
}

extern "C"
int air192_name_get(const char **fns, aloe_buf_t *buf,
		int (*refine)(aloe_buf_t*)) {
	int fnidx = 0;
	const char *fn;

	if (!fns) {
		static const char *_fns[] = {
				accname_cfg,
				hostname_cfg,
				"/etc/hostname-template",
				NULL
		};
		fns = _fns;
	}

	for (fnidx = 0; (fn = fns[fnidx]); fnidx++) {
		if (!*fn) continue;
		aloe_buf_t buf2 = {.data = (char*)buf->data + buf->pos,
				.cap = buf->lmt - buf->pos};
		if (aloe_file_fread(fn, aloe_buf_clear(&buf2)) < 1) continue;
		aloe_buf_flip(&buf2);
		// refine will modify buf2
		if (refine && (*refine)(&buf2) != 0) continue;
		if (buf2.pos >= buf2.lmt) continue;
		if (buf2.pos > 0) {
			memmove(buf2.data, (char*)buf2.data + buf2.pos, buf2.lmt - buf2.pos);
		}
		((char*)buf->data)[buf->pos += (buf2.lmt - buf2.pos)] = '\0';
		return 0;
	}
	return -1;
}

extern "C"
cJSON* air192_jcfg_load(const char **fns, aloe_buf_t *buf) {
	aloe_buf_t _buf = {0};
	int r, fidx;
	const char *fn;
	cJSON *jroot;

	if (!buf) buf = &_buf;
	if (!fns) {
		static const char *_fns[] = {
				APPCFG,
				NULL
		};
		fns = _fns;
	}
	for (fidx = 0; (fn = fns[fidx]); fidx++) {
		int fsz;

		if (!*fn || (fsz = aloe_file_size(fn, 0)) <= 0) continue;
		if (aloe_buf_expand(buf, aloe_padding2(fsz, 31), aloe_buf_flag_none) != 0) {
			r = ENOMEM;
			log_e("Failed malloc %d bytes\n", fsz + 8);
			goto finally;
		}
		if (aloe_file_fread(fn, aloe_buf_clear(buf)) != fsz) {
			r = EIO;
			log_e("Failed read config file %s\n", fn);
			goto finally;
		}
		aloe_buf_flip(buf);
		if (!(jroot = cJSON_ParseWithLengthOpts((char*)buf->data + buf->pos,
				buf->lmt - buf->pos, NULL, 0))) {
			r = EIO;
			log_e("Failed parse config file %s\n", fn);
			goto finally;
		}
		r = 0;
		goto finally;
	}
	r = EIO;
finally:
	if (_buf.data) free(_buf.data);
	return r == 0 ? jroot : NULL;
}

extern "C"
int air192_cfg_load2(const char **fns, aloe_buf_t *buf, int oob) {
	int fidx;
	const char *fn;

	for (fidx = 0; (fn = fns[fidx]); fidx++) {
		int fsz;

		if (!fn[0] || (fsz = aloe_file_size(fn, 0)) <= 0) continue;
		if (oob > 0 && fsz > oob) {
			log_e("Unexpected size %d > %d bytes for: %s\n", fsz, oob, fn);
			return -1;
		}
		if (aloe_buf_expand(buf, aloe_padding2(fsz, 31),
				aloe_buf_flag_none) != 0) {
			log_e("Out of memory to read %s\n", fn);
			return -1;
		}
		if (aloe_file_fread(fn, aloe_buf_clear(buf)) != fsz) {
			log_e("Failed read %s\n", fn);
			return -1;
		}
		log_d("Load %d bytes form %s\n", fsz, fn);
		return 0;
	}
	return -1;
}

extern "C"
int air192_ini_find(const char *fname, const char *key, aloe_buf_t *buf) {
	int r;
	char sn_buf[200];
	aloe_buf_t sn_fb = {.data = sn_buf, .cap = sizeof(sn_buf)};
	const char *sn_str;
	size_t sn_len;

	if ((r = aloe_file_size(fname, 0)) <= 0) {
		r = EINVAL;
		log_e("Invalid file %s\n", fname);
		return -1;
	}
	if (r >= (int)sn_fb.cap) {
		r = EIO;
		log_e("Insufficient buffer for read file %s\n", fname);
		return -1;
	}
	if (aloe_file_fread(fname, aloe_buf_clear(&sn_fb)) != r) {
		r = EIO;
		log_e("Failed read file %s\n", fname);
		return -1;
	}
	if (!(sn_str = aloe_ini_find(sn_fb.data, sn_fb.pos, key, &sn_len))) {
		r = EIO;
		log_e("Failed find %s in %s\n", key, fname);
		return -1;
	}
	if (buf->lmt - buf->pos <= sn_len) {
		r = EIO;
		log_e("Insufficient buffer for %s\n", key);
		return -1;
	}
	memcpy((char*)buf->data + buf->pos, sn_str, sn_len);
	((char*)buf->data)[buf->pos += sn_len] = '\0';
	return sn_len;
}

extern "C"
uint16_t air192_eve_hash4(const void *data, size_t sz) {
	uint32_t hash32 = 2166136261;

	while (sz-- > 0) {
		hash32 = (hash32 ^ *(char*)data) * 16777619;
		data = (char*)data + 1;
	}
	return (uint16_t)((hash32 >> 16) ^ (hash32 & 0xFFFF));
}

extern "C"
int air192_GetSerialNumberHashString(const char *inSerialNumber,
		char *outHashStrBuf, int outHashStrBufSize) {
	if (inSerialNumber == NULL || outHashStrBuf == NULL
			|| outHashStrBufSize <= 4) // Reserved 1 byte of NULL character
	{
		return -1;
	}

	int len = (int)strlen(inSerialNumber);
	uint32_t hash32 = 2166136261;

	for (int i = 0; i < len; ++i) {
		hash32 = (hash32 ^ inSerialNumber[i]) * 16777619;
	}

	uint16_t hash = (hash32 >> 16) ^ (hash32 & 0xFFFF);
	if (snprintf(outHashStrBuf, outHashStrBufSize, "%04X", hash) != 4) {
		return -1;
	}
	return 0;
}

extern "C"
__attribute__((format(scanf, 2, 3)))
int air192_file_scanf1(const char *fname, const char *fmt, ...) {
	int r;
	FILE *fp = NULL;
	va_list va;

	if ((r = aloe_file_size(fname, 0)) == 0) return 0;
	if (!(fp = fopen(fname, "r"))) {
//		r = errno;
//		log_e("Failed open %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
	va_start(va, fmt);
	r = vfscanf(fp, fmt, va);
	va_end(va);
	if (r == EOF) {
//		r = errno;
//		log_f("Failed scanf %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
finally:
	if (fp) fclose(fp);
	return r;
}

extern "C"
int air192_regex_test1(const char *fmt, const char *pat, int cflags,
		size_t nmatch, regmatch_t *pmatch) {
	regex_t regex;
	int r;
	char err_msg[100];

	if ((r = regcomp(&regex, pat, cflags)) != 0) {
		regerror(r, &regex, err_msg, sizeof(err_msg));
		err_msg[sizeof(err_msg) - 1] = '\0';
		log_e("Compile regex pattern '%s', flag: %d, %s\n", pat, cflags, err_msg);
		return r;
	}

	if ((r = regexec(&regex, fmt, nmatch, pmatch, 0)) == 0) {
//		log_d("Matched string '%s' against '%s'\n", fmt, pat);
		regfree(&regex);
		return 0;
	}

	if (r != REG_NOMATCH) {
		regerror(r, &regex, err_msg, sizeof(err_msg));
		err_msg[sizeof(err_msg) - 1] = '\0';
		regfree(&regex);
		log_e("Failed match string '%s' against '%s': %s\n", fmt, pat, err_msg);
		return r;
	}
	regfree(&regex);
//	log_e("No matched string '%s' against '%s'\n", fmt, pat);
	return r;
}

extern "C"
__attribute__((format(printf, 3, 4)))
int air192_led_set(int led_val, unsigned long send_dur,
		const char *name_fmt, ...) {
	int r;
	mqd_t mq = (mqd_t)-1;
	air192_mqled_tlv_t msg;
	va_list va;

	va_start(va, name_fmt);
	r = vsnprintf(msg.mqled.name, sizeof(msg.mqled.name), name_fmt, va);
	va_end(va);
	if (r >= (int)sizeof(msg.mqled.name)) {
		r = EIO;
		log_e("too long for led name\n");
		goto finally;
	}
	msg.mqled.name_len = r + 1;
	msg.mqled.led_val = led_val;
	msg.tlvhdr.type = air192_mqled_tlvtype;
	msg.tlvhdr.len = offsetof(air192_mqled_t, name) + msg.mqled.name_len;

	if ((mq = mq_open(air192_mqled_name, O_WRONLY, 0644, NULL)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}
	if (send_dur != (unsigned long)-1) {
		struct timespec due;

		if ((r = clock_gettime(CLOCK_REALTIME, &due)) != 0) {
			r = errno;
			log_e("failed get time: %s\n", strerror(r));
			goto finally;
		}
		if (send_dur != 0) {
			ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, send_dur / 1000l,
					(send_dur % 1000l) * 1000000l,
					due.tv_sec, due.tv_nsec, 1000000000l);
		}
		r = mq_timedsend(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len,
				0, &due);
	} else {
		r = mq_send(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len, 0);
	}
	if (r != 0) {
		r = errno;
		log_e("send to mq: %s\n", strerror(r));
		goto finally;
	}
	log_d("sent to %s, led %s, val %d\n", air192_mqled_name, msg.mqled.name,
			msg.mqled.led_val);
	r = 0;
finally:
	if (mq != (mqd_t)-1) mq_close(mq);
	return r;
}

extern "C"
int air192_adk_paired(const char **fns) {
	int fidx;
	const char *fn;

	if (!fns) {
		static const char *_fns[] = {
				persist_cfg "/hap-setupinfo/A0.00",
				"/root/.HomeKitStore/hap-setupinfo/A0.00",
				NULL
		};
		fns = _fns;
	}
	for (fidx = 0; (fn = fns[fidx]); fidx++) {
		int fsz;

		if (!fn[0] || (fsz = aloe_file_size(fn, 0)) > 0) return 1;
	}
	return 0;
}

/* [0-9a-zA-Z-"',.#&] */
extern "C"
const char* air192_accname_char(size_t *sz) {
	static char tlb0[72] = {0};
	static size_t tlb0_sz;

	if (!tlb0[0]) {
		const char ext[] = "-\"',.#&";
		int c;

		tlb0_sz = 0;
		for (c = '0'; c <= '9'; c++) tlb0[tlb0_sz++] = c;
		for (c = 'a'; c <= 'z'; c++) tlb0[tlb0_sz++] = c;
		for (c = 'A'; c <= 'Z'; c++) tlb0[tlb0_sz++] = c;
		memcpy(&tlb0[tlb0_sz], ext, sizeof(ext) - 1);
		tlb0_sz += sizeof(ext) - 1;
	}
	if (sz) *sz = tlb0_sz;
	return tlb0;
}

extern "C"
__attribute__((format(printf, 3, 4)))
int air192_cgireq_open(air192_cgireq_t *req, const char *prog_lock,
		const char *fmt, ...) {
	int r;
	va_list va;
	const char *str;

	if (aloe_buf_expand(&req->cmdbuf, 500, aloe_buf_flag_none) != 0) {
		r = ENOMEM;
		req->err = -1;
		req->reason = "Out of memory";
		goto finally;
	}
	if (prog_lock) {
		r = air192_file_scanf1(prog_lock, "%d %d", &req->prog_st, &req->prog_iter);
		if (r == 0) {
			req->prog_st = req->prog_iter = air192_cgireq_prog_null;
		} else if (r == 1) {
			req->prog_iter = air192_cgireq_prog_null;
		} else if (r != 2) {
			req->err = -1;
			air192_cgireq_reason(req, "Runtime error: %s", "get progress");
			goto finally;
		}
		log_d("%s prog: %d, iter: %d\n", prog_lock, req->prog_st, req->prog_iter);

		if (req->prog_st >= air192_cgireq_prog_fatal) {
			r = EIO;
			req->err = -1;
			air192_cgireq_reason(req, "Fatal error");
			goto finally;
		}

		if (req->prog_st < air192_cgireq_prog_complete &&
				req->prog_st != air192_cgireq_prog_null) {
			r = EBUSY;
			req->err = req->prog_st;
			air192_cgireq_reason(req, "Busy");
			goto finally;
		}
	}

	// CONTENT_TYPE=application/json
	// CONTENT_LENGTH=12
	aloe_buf_clear(&req->cmdbuf);
	if (fmt) {
		va_start(va, fmt);
		r = aloe_buf_vprintf(&req->cmdbuf, fmt, va);
		va_end(va);
		if (r < 0) {
			r = ENOMEM;
			req->err = -1;
			air192_cgireq_reason(req, "Invalid request: %s", "header");
			goto finally;
		}
	} else {
		if (!(str = getenv("CONTENT_TYPE"))
				|| strcasecmp(str, "application/json") != 0
				|| !(str = getenv("CONTENT_LENGTH"))
				|| (r = strtol(str, NULL, 0)) <= 0
				|| r >= (int)req->cmdbuf.cap
				|| r != (int)fread(req->cmdbuf.data, 1, r, stdin)) {
			r = EINVAL;
			req->err = -1;
			air192_cgireq_reason(req, "Invalid request: %s", "header");
			goto finally;
		}
		req->cmdbuf.pos += r;
	}
	aloe_buf_flip(&req->cmdbuf);

	log_d("received request: %d,\n%s\n", (int)req->cmdbuf.lmt, (char*)req->cmdbuf.data);

	if (!(req->jroot = cJSON_Parse((char*)req->cmdbuf.data))) {
		r = EINVAL;
		req->err = -1;
		air192_cgireq_reason(req, "Invalid request: %s", "JSON");
		goto finally;
	}
//	if (!(jobj = cJSON_GetObjectItem(req->jroot, "command"))
//			|| !(str = cJSON_GetStringValue(jobj))) {
//		r = -1;
//		air192_cgireq_reason(req, "Invalid request: %s", "command");
//		goto finally;
//	}
finally:
	return r;
}

extern "C"
__attribute__((format(printf, 4, 5)))
int air192_sus_set(int whence, int delay, unsigned long send_dur,
		const char *name_fmt, ...) {
	int r;
	mqd_t mq = (mqd_t)-1;
	air192_mqsus_tlv_t msg;
	va_list va;

	va_start(va, name_fmt);
	r = vsnprintf(msg.mqsus.name, sizeof(msg.mqsus.name), name_fmt, va);
	va_end(va);
	if (r >= (int)sizeof(msg.mqsus.name)) {
		r = EIO;
		log_e("too long for sus name\n");
		goto finally;
	}
	msg.mqsus.name_len = r + 1;
	msg.mqsus.whence = whence;
	msg.mqsus.delay = delay;
	msg.tlvhdr.type = air192_mqsus_tlvtype;
	msg.tlvhdr.len = offsetof(air192_mqsus_t, name) + msg.mqsus.name_len;

	if ((mq = mq_open(air192_mqsus_name, O_WRONLY, 0644, NULL)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}
	if (send_dur != (unsigned long)-1) {
		struct timespec due;

		if ((r = clock_gettime(CLOCK_REALTIME, &due)) != 0) {
			r = errno;
			log_e("failed get time: %s\n", strerror(r));
			goto finally;
		}
		if (send_dur != 0) {
			ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, send_dur / 1000l,
					(send_dur % 1000l) * 1000000l,
					due.tv_sec, due.tv_nsec, 1000000000l);
		}
		r = mq_timedsend(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len,
				0, &due);
	} else {
		r = mq_send(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len, 0);
	}
	if (r != 0) {
		r = errno;
		log_e("send to mq: %s\n", strerror(r));
		goto finally;
	}
	log_d("sent to %s, sender %s, whence %d, delay %d\n", air192_mqsus_name,
			msg.mqsus.name, msg.mqsus.whence, msg.mqsus.delay);
	r = 0;
finally:
	if (mq != (mqd_t)-1) mq_close(mq);
	return r;
}

static const char mqcli_prename[] = air192_mqcli_name_prefix;
#define mqcli_prename_sz (sizeof(mqcli_prename) - 1)

typedef struct {
	int quit;
	pthread_t thread;
	void *ev_ctx;

	void *ev_mq;
	mqd_t mq;
	aloe_buf_t recv_fb_mq;
	const char *name_mq;
	air192_cli_cb_t clicb;
	void *clicbarg;

	void *ev_mgr;
	int pipe_mgr[2];
	aloe_buf_t recv_fb_mgr;

} air192_cli_conn_t;

static void* air192_cli_thread(void *_conn) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)_conn;

	log_d("%s started\n", conn->name_mq);
	while (!conn->quit) {
    	aloe_ev_once(conn->ev_ctx);
	}
	log_d("%s stopped\n", conn->name_mq);
	return NULL;
}

static void air192_climgr_on_read(int fd, unsigned ev_noti, void *cbarg) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)cbarg;
	aloe_buf_t *fb = &conn->recv_fb_mgr;
	air192_tlvhdr_t *tlvhdr;
	int r;
	unsigned long tv_ms = ALOE_EV_INFINITE;

	if (ev_noti & aloe_ev_flag_read) {
		if (fb->lmt - fb->pos < sizeof(tlvhdr)) {
			log_e("unexpected receive buffer size\n");
			aloe_buf_clear(fb);
		}

		if ((r = read(conn->pipe_mgr[0], (char*)fb->data + fb->pos,
				fb->lmt - fb->pos)) < 0) {
			r = errno;
			log_e("Failed read air192 cli mgr: %s\n", strerror(r));
			goto finally;
		}
		fb->pos += r;

		aloe_buf_flip(fb);

		for (tlvhdr = (air192_tlvhdr_t*)((char*)fb->data + fb->pos);
				fb->lmt - fb->pos >= sizeof(*tlvhdr)
						&& fb->lmt - fb->pos >= sizeof(*tlvhdr) + tlvhdr->len;
				fb->pos += (sizeof(*tlvhdr) + tlvhdr->len),
						tlvhdr = (air192_tlvhdr_t*)((char*)fb->data + fb->pos)) {
			// sanity check
			if (tlvhdr->type != air192_climgr_tlvtype) {
				log_e("unexpected climgr\n");
				continue;
			}

			if (tlvhdr->len > 0 && ((char*)(tlvhdr + 1))[tlvhdr->len - 1] == '\0') {
				// assume string message
				log_d("%s %s recv %s\n", conn->name_mq, "climgr", (char*)(tlvhdr + 1));
			} else {
				log_d("%s %s recv %d bytes\n", conn->name_mq, "climgr", tlvhdr->len);
			}
		}
		aloe_buf_replay(fb);
		if (fb->pos > 0) log_d("remain %d bytes\n", (int)fb->pos);
	}
	r = 0;
finally:
	if (r == 0) {
		if ((conn->ev_mgr = aloe_ev_put(conn->ev_ctx, conn->pipe_mgr[0],
				&air192_climgr_on_read, conn, aloe_ev_flag_read,
				((tv_ms == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE : tv_ms / 1000ul),
				((tv_ms == ALOE_EV_INFINITE) ? 0 : (tv_ms % 1000ul) * 1000ul)))) {
			return;
		}
		log_e("Failed schedule air192 cli\n");
	}
}

static int air192_climgr_send_tlv(air192_cli_conn_t *conn,
		const air192_tlvhdr_t *tlvhdr) {
	aloe_buf_t fb = {.data = (void*)tlvhdr, .cap = sizeof(*tlvhdr) + tlvhdr->len};
	int r;

	aloe_buf_clear(&fb);
	while (fb.pos < fb.lmt) {
		if ((r = write(conn->pipe_mgr[1], (char*)fb.data + fb.pos,
				fb.lmt - fb.pos)) <= 0) {
			log_e("Failed notify air192 cli mgr\n");
			return r;
		}
		fb.pos += r;
	}
	return 0;
}

__attribute__((format(printf, 2, 3)))
static int air192_climgr_send_msg(air192_cli_conn_t *conn,
		const char *fmt, ...) {
	struct __attribute__((packed)) {
		air192_tlvhdr_t tlvhdr;
		char msg[80];
	} pkg;
	int r;
	va_list va;

	va_start(va, fmt);
	r = vsnprintf(pkg.msg, sizeof(pkg.msg), fmt, va);
	va_end(va);
	if (r >= (int)sizeof(pkg.msg)) {
		log_e("Too large for cli mgr\n");
		return EIO;
	}
	pkg.tlvhdr.type = air192_climgr_tlvtype;
	pkg.tlvhdr.len = r + 1;
	return air192_climgr_send_tlv(conn, &pkg.tlvhdr);
}

static void air192_cli_on_read(int fd, unsigned ev_noti, void *cbarg) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)cbarg;
	aloe_buf_t *fb = &conn->recv_fb_mq;
	air192_mqcli_tlv_t *msg;
	int r;
	unsigned long tv_ms = ALOE_EV_INFINITE;

	if (ev_noti & aloe_ev_flag_read) {
		if (fb->lmt - fb->pos < sizeof(msg)) {
			log_e("unexpected receive buffer size\n");
			aloe_buf_clear(fb);
		}

		if ((r = mq_receive(conn->mq, (char*)fb->data + fb->pos,
				fb->lmt - fb->pos, NULL)) < 0) {
			r = errno;
			log_e("Failed read air192 cli event: %s\n", strerror(r));
			goto finally;
		}
		fb->pos += r;

		aloe_buf_flip(fb);

		for (msg = (air192_mqcli_tlv_t*)((char*)fb->data + fb->pos);
				fb->lmt - fb->pos >= sizeof(msg->tlvhdr)
						&& fb->lmt - fb->pos >= sizeof(msg->tlvhdr) + msg->tlvhdr.len;
				fb->pos += (sizeof(msg->tlvhdr) + msg->tlvhdr.len),
						msg = (air192_mqcli_tlv_t*)((char*)fb->data + fb->pos)) {
			// sanity check
			if (msg->mqcli.name_len < 1
					|| msg->mqcli.name_len >= (int)sizeof(msg->mqcli.msg)
					|| msg->mqcli.msg[msg->mqcli.name_len - 1]
					|| msg->tlvhdr.type != air192_mqcli_tlvtype) {
				log_e("unexpected mqcli\n");
				continue;
			}

			log_d("%s recv: %s\n", conn->name_mq, msg->mqcli.msg);
			if (conn->clicb) {
				conn->clicb(conn->clicbarg, msg->mqcli.name_len - 1, msg->mqcli.msg);
			}
		}
		aloe_buf_replay(fb);
		if (fb->pos > 0) log_d("remain %d bytes\n", (int)fb->pos);
	}
	r = 0;
finally:
	if (r == 0) {
		if ((conn->ev_mq = aloe_ev_put(conn->ev_ctx, (int)conn->mq,
				&air192_cli_on_read, conn, aloe_ev_flag_read,
				((tv_ms == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE : tv_ms / 1000ul),
				((tv_ms == ALOE_EV_INFINITE) ? 0 : (tv_ms % 1000ul) * 1000ul)))) {
			return;
		}
		log_e("Failed schedule air192 cli\n");
	}
}

extern "C"
void* air192_cli_start(const char *name, air192_cli_cb_t cb, void *cbarg) {
	int name_sz = strlen(name), msg_sz = sizeof(air192_mqcli_tlv_t),
			mgrmsg_sz = 150, r;
	air192_cli_conn_t *conn = NULL;
	struct mq_attr mqattr;
	char *ctr;

	if (!(conn = (air192_cli_conn_t*)malloc(sizeof(*conn)
			+ mqcli_prename_sz + name_sz + 1
			+ msg_sz * 2
			+ mgrmsg_sz))) {
		r = ENOMEM;
		log_e("no memory for air192_cli\n");
		goto finally;
	}
	memset(conn, 0, sizeof(*conn));
	conn->mq = (mqd_t)-1;
	conn->pipe_mgr[0] = conn->pipe_mgr[1] = -1;
	if (!(conn->ev_ctx = aloe_ev_init())) {
		r = ENOMEM;
		log_e("no memory for event proc\n");
		goto finally;
	}

	conn->name_mq = ctr = (char*)(conn + 1);
	memcpy(ctr, mqcli_prename, mqcli_prename_sz);
	memcpy(ctr + mqcli_prename_sz, name, name_sz);
	ctr[mqcli_prename_sz + name_sz] = '\0';
	ctr += mqcli_prename_sz + name_sz + 1;

	memset(&mqattr, 0, sizeof(mqattr));
	mqattr.mq_maxmsg = 10;
	mqattr.mq_msgsize = msg_sz;
	if ((conn->mq = mq_open(conn->name_mq, O_CREAT | O_RDONLY, 0644,
			&mqattr)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}

	if ((r = aloe_file_nonblock((int)conn->mq, 1)) != 0) {
		log_e("failed set nonblock for mq: %s\n", strerror(r));
		goto finally;
	}

	if (!(conn->ev_mq = aloe_ev_put(conn->ev_ctx, (int)conn->mq,
			&air192_cli_on_read, conn, aloe_ev_flag_read, ALOE_EV_INFINITE, 0))) {
		r = EIO;
		log_e("Failed schedule air192 cli\n");
		goto finally;
	}

	if (pipe(conn->pipe_mgr) != 0) {
		r = errno;
		log_e("Failed create air192 cli mgr pipe\n");
		goto finally;
	}

	if ((r = aloe_file_nonblock(conn->pipe_mgr[0], 1)) != 0) {
		log_e("failed set nonblock for mgr pipe: %s\n", strerror(r));
		goto finally;
	}

	if (!(conn->ev_mgr = aloe_ev_put(conn->ev_ctx, conn->pipe_mgr[0],
			&air192_climgr_on_read, conn, aloe_ev_flag_read, ALOE_EV_INFINITE, 0))) {
		r = EIO;
		log_e("Failed schedule air192 cli\n");
		goto finally;
	}

	conn->recv_fb_mq.data = ctr;
	conn->recv_fb_mq.cap = msg_sz * 2;
	aloe_buf_clear(&conn->recv_fb_mq);
	ctr += msg_sz * 2;

	conn->recv_fb_mgr.data = ctr;
	conn->recv_fb_mgr.cap = mgrmsg_sz;
	aloe_buf_clear(&conn->recv_fb_mgr);
	ctr += mgrmsg_sz;

	conn->clicb = cb;
	conn->clicbarg = cbarg;

	if ((r = pthread_create(&conn->thread, NULL, &air192_cli_thread,
			conn)) != 0) {
		r = errno;
		log_e("air192 cli thread: %s\n", strerror(r));
		goto finally;
	}
	r = 0;
finally:
	if (r != 0) {
		if (conn) {
			if (conn->pipe_mgr[0] == -1) close(conn->pipe_mgr[0]);
			if (conn->pipe_mgr[1] == -1) close(conn->pipe_mgr[1]);
			if (conn->mq != (mqd_t)-1) mq_close(conn->mq);
			if (conn->ev_ctx) aloe_ev_destroy(conn->ev_ctx);
			free(conn);
		}
		return NULL;
	}
	return conn;
}

void air192_cli_stop(void *ctx) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)ctx;
	int r;

	conn->quit = 1;

//	conn->clicb = NULL;
//	air192_cli_send(conn->name_mq + mqcli_prename_sz, ALOE_EV_INFINITE, "terminate");

	air192_climgr_send_msg(conn, "terminate");

	if ((r = pthread_join(conn->thread, NULL)) != 0) {
		r = errno;
		log_e("Failed join air192 cli: %s\n", strerror(r));
		return;
	}
	if (conn->ev_ctx) aloe_ev_destroy(conn->ev_ctx);
	if (conn->pipe_mgr[0] == -1) close(conn->pipe_mgr[0]);
	if (conn->pipe_mgr[1] == -1) close(conn->pipe_mgr[1]);
	if (conn->mq != (mqd_t)-1) mq_close(conn->mq);
	free(conn);
}

extern "C"
__attribute__((format(printf, 3, 0)))
int air192_cli_vsend(const char *name, unsigned long send_dur,
		const char *fmt, va_list va) {
	int name_sz = strlen(name), r;
	char mqname[50];
	mqd_t mq = (mqd_t)-1;
	air192_mqcli_tlv_t msg;

	if (mqcli_prename_sz + name_sz >= (int)sizeof(mqname)) {
		r = EIO;
		log_e("name too long for air192 cli\n");
		goto finally;
	}

	r = vsnprintf(msg.mqcli.msg, sizeof(msg.mqcli.msg), fmt, va);
	if (r >= (int)sizeof(msg.mqcli.msg)) {
		r = EIO;
		log_e("too long for air192 cli\n");
		goto finally;
	}
	msg.mqcli.name_len = r + 1;
	msg.tlvhdr.type = air192_mqcli_tlvtype;
	msg.tlvhdr.len = offsetof(air192_mqcli_t, msg) + msg.mqcli.name_len;
	memcpy(mqname, mqcli_prename, mqcli_prename_sz);
	memcpy(mqname + mqcli_prename_sz, name, name_sz);
	mqname[mqcli_prename_sz + name_sz] = '\0';

	if ((mq = mq_open(mqname, O_WRONLY, 0644, NULL)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}
	if (send_dur != (unsigned long)-1) {
		struct timespec due;

		if ((r = clock_gettime(CLOCK_REALTIME, &due)) != 0) {
			r = errno;
			log_e("failed get time: %s\n", strerror(r));
			goto finally;
		}
		if (send_dur != 0) {
			ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, send_dur / 1000l,
					(send_dur % 1000l) * 1000000l,
					due.tv_sec, due.tv_nsec, 1000000000l);
		}
		r = mq_timedsend(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len,
				0, &due);
	} else {
		r = mq_send(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len, 0);
	}
	if (r != 0) {
		r = errno;
		log_e("send to mq: %s\n", strerror(r));
		goto finally;
	}
	log_d("sent to %s, %s\n", mqname, msg.mqcli.msg);
	r = 0;
finally:
	if (mq != (mqd_t)-1) mq_close(mq);
	return r;
}

extern "C"
__attribute__((format(printf, 3, 4)))
int air192_cli_send(const char *name, unsigned long send_dur,
		const char *fmt, ...) {
	int r;
	va_list va;

	va_start(va, fmt);
	r = air192_cli_vsend(name, send_dur, fmt, va);
	va_end(va);
	return r;
}

extern "C" {

#define _bs_lut_start(_n) static volatile const uint8_t _ ## _n []
#define _bs_lut_end(_n) \
	volatile const uint8_t * _n = _ ## _n; \
	volatile const size_t _n ## _size = sizeof( _ ## _n );

//static const uint8_t _air192_eve_wifi_verifying_key[] = { // SignatureID 3
_bs_lut_start(air192_eve_wifi_verifying_key) {
	0x4f, 0xd8, 0x87, 0xb0, 0xec, 0x50, 0x97, 0x60, 0xbb, 0x78, 0x41, 0xa9,
	0x3a, 0x16, 0x2b, 0x62, 0xe4, 0x7a, 0x65, 0xb3, 0x8e, 0x0b, 0x5f, 0x05,
	0xae, 0x56, 0x97, 0xac, 0xd2, 0xc5, 0xdc, 0x3a
};
//volatile const uint8_t *air192_eve_wifi_verifying_key = _air192_eve_wifi_verifying_key;
_bs_lut_end(air192_eve_wifi_verifying_key);

//volatile const uint8_t _air192_elgato_wifi_verifying_key[] = { // SignatureID 1
_bs_lut_start(air192_elgato_wifi_verifying_key) {
	0x8e, 0x52, 0x56, 0x12, 0x86, 0xf8, 0xbd, 0x7a, 0xf0, 0x97, 0x09, 0x08,
	0x5b, 0xad, 0x50, 0x44, 0x72, 0x62, 0xdd, 0xd7, 0x8f, 0x9c, 0xff, 0xd8,
	0x5c, 0x97, 0x3b, 0xcf, 0x66, 0x99, 0xbf, 0x8f
};
_bs_lut_end(air192_elgato_wifi_verifying_key);

//volatile const uint8_t air192_dexatek_verification_public_key[32] = { // SignatureID 2
_bs_lut_start(air192_dexatek_verification_public_key) {
    0xcc, 0xe1, 0x30, 0xfd, 0xef, 0xb4, 0xf2, 0xb3, 0x35, 0xba, 0xed, 0x0c,
    0x8a, 0x54, 0x32, 0x32, 0x88, 0xc3, 0x7a, 0xb5, 0x1f, 0x16, 0x22, 0xc8,
    0xb3, 0x3c, 0xb7, 0x8e, 0x7c, 0x6b, 0x21, 0xe8
};
_bs_lut_end(air192_dexatek_verification_public_key);

#undef _bs_lut_start
#undef _bs_lut_end

#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wall"
#pragma GCC push_options
#pragma GCC optimize("O0")
volatile air192_eve_tagged_fwhdr_t air192_eve_tagged_fwhdr __attribute__((section("eve_fwhdr"))) = {
	/*uint8_t tag[8];*/ {air192_eve_fwhdr_tag},
	/*air192_eve_fwhdr_t hdr;*/ {
		/*uint16_t ElgatoVendorConstant;*/ ELGATO_VENDOR_CONSTANT,
		/*uint16_t Version;*/ ELGATO_HEADER_VERSION,

/* error: initializer-string for ‘uint8_t [41]’ {aka ‘unsigned char [41]’} is too long [-fpermissive] */
		/*uint8_t ElgatoHeader[41];*/ {EVE_HEADER},

		/*uint8_t BoardType;*/ SA7715_BOARD_TYPE,
		/*uint16_t VersionMajor;*/ SA7715_VERSION_MAJOR,
		/*uint16_t VersionMinor;*/ SA7715_VERSION_MINOR,
		/*uint16_t VersionMinor2;*/ SA7715_VERSION_RELEASE,
		/*uint16_t VersionBuildNumber;*/ SA7715_BUILD_NUMBER,
		/*uint32_t FirmwareSize;*/ 0,
		/*uint16_t FirmwareDataOffset;*/ 128,
		/*uint8_t Reserved[2];*/
		/*uint16_t SignatureID;*/
		/*uint8_t Signature[64];*/
	}
};
#pragma GCC pop_options
#pragma GCC diagnostic pop
} // extern "C"

extern "C"
int air192_serial_number(aloe_buf_t *buf) {
	int r;
	aloe_buf_t _buf = *buf;

	if ((r = air192_ini_find(serialnum_cfg, "serialnum", buf)) > 0) {
		if (buf->pos == _buf.pos + r) {
			_aloe_str_toupper((char*)buf->data + _buf.pos, r);
		} else {
			log_d("sanity check unexpected serialnum\n");
		}
	}
	return r;
}

extern "C"
int air192_bdname(aloe_buf_t *buf) {
	int r;
	aloe_buf_t _buf = *buf;

	if ((r = air192_ini_find(bdname_cfg, "bdname", buf)) > 0) {
		if (buf->pos == _buf.pos + r) {
			_aloe_str_toupper((char*)buf->data + _buf.pos, r);
		} else {
			log_d("sanity check unexpected bdname\n");
		}
	}
	return r;
}

extern "C"
int air192_refact_num(int *refact) {
	int r;
	char buf[100];
	aloe_buf_t fb = {.data = buf, .cap = sizeof(buf)};

	if ((r = air192_ini_find(oob_cfg, "refactory", aloe_buf_clear(&fb))) <= 0 ||
			(r = (aloe_strtoi((char*)fb.data, NULL, 0, refact) != 0))) {
		return -1;
	}
	return 0;
}

extern "C"
size_t air192_hostname_refine(const char *data, size_t sz, int chr, char *out) {
	char cont;
	size_t out_sz;

	if (!data) return 0;
	for (cont = 0, out_sz = 0;
			sz > 0; data++, sz--) {
		int c = *data;
		if (aloe_alphanum(c)) {
			if (out) *out++ = (char)c;
			out_sz++;
			cont = 0;
		} else if (!cont) {
			if (chr >= 0) {
				if (out) *out++ = (char)chr;
				out_sz++;
			}
			cont = 1;
		}
	}
	if (out) *out = '\0';
	return out_sz;
}

extern "C"
int air192_wac_name(aloe_buf_t *out) {
	char bdname[5];
	aloe_buf_t buf = {0};
	int r;

	bdname[0] = '\0';
	do {
		aloe_buf_t fb;

		fb.data = bdname;
		fb.cap = sizeof(bdname);
		if ((r = aloe_file_size(bdname_cfg, 0)) > 0
				&& air192_bdname(aloe_buf_clear(&fb)) > 0
				&& fb.pos < sizeof(bdname)) {
			break;
		}
		bdname[0] = '\0';
		if (aloe_buf_expand(aloe_buf_clear(&buf), 200,
				aloe_buf_flag_none) != 0) {
			r = -1;
			log_e("Not enough memory to hash\n");
			goto finally;
		}
		if (air192_serial_number(aloe_buf_clear(&buf)) <= 0) {
			r = -1;
			log_e("Failed read serialnum file\n");
			break;
		}
		snprintf(bdname, sizeof(bdname), "%04X",
				air192_eve_hash4(buf.data, buf.pos));
		bdname[sizeof(bdname) - 1] = '\0';
	} while(0);

	if (aloe_buf_expand(aloe_buf_clear(&buf), 200,
			aloe_buf_flag_none) != 0) {
		r = -1;
		log_e("Not enough memory to hash\n");
		goto finally;
	}

	if (air192_name_get(NULL, aloe_buf_clear(&buf),
			&aloe_accessory_name_refine) != 0
			|| buf.pos <= 0
			|| buf.lmt - buf.pos < 6) {
		buf.pos = snprintf((char*)buf.data, buf.cap, "%s", "Air192");
	}

	aloe_buf_flip(&buf);

	if (bdname[0]) {
		r = aloe_buf_printf(out, "%s %s", (char*)buf.data, bdname);
	} else {
		r = aloe_buf_printf(out, "%s", (char*)buf.data);
	}
	if (r <= 0) {
		log_e("Failed to compose name\n");
		goto finally;
	}
finally:
	if (buf.data) free(buf.data);
	return r;
}

static int air192_stacktrace1_cb(char **sym,
		void **trace __attribute__((unused)),
		size_t cnt,
		void *cbarg __attribute__((unused))) {
	int r;

	for (r = 0; r < (int)cnt; r++) {
		air192_d2("[%d/%d]%s\n", r, cnt, (sym && sym[r] ? sym[r] : ""));
	}
	return r;
}

extern "C"
int air192_stacktrace1(int skip) {
	return aloe_backtrace_dump(&air192_stacktrace1_cb, NULL, skip > 0 ? skip + 1 : 0);
}

static int find_wpasup_keymgmt_getc(void *arg) {
	aloe_buf_t *fb = (aloe_buf_t*)arg;

	if (!fb->data || fb->lmt >= fb->cap) return -1;
	return (int)((unsigned char*)fb->data)[fb->lmt++];
}

extern "C"
int air192_find_wpasup_keymgmt(const char *fn, aloe_buf_t *keyMgmtBuf) {
#define line_sz  200
#define key_keymgmt "key_mgmt="
#define key_network "network="
	aloe_buf_t fb = {}, linefb = {};
	int fsz, r, fd = -1, line_len;
	enum {
		parse_state_null,
		parse_state_network,
		parse_state_key_mgmt,
	} parse_state = parse_state_null;

	if ((fsz = aloe_file_size(fn, 0)) <= 0) {
		log_e("Empty file file\n");
		r = -1;
		goto finally;
	}
	if (!(fb.data = malloc(fsz + 1 + line_sz))) {
		log_e("Alloc memory\n");
		r = -1;
		goto finally;
	}
	((char*)fb.data)[fb.cap = fsz] = '\0';

	linefb.data = (char*)fb.data + fb.cap + 1;
	linefb.cap = line_sz;

	_aloe_buf_clear(&fb);
	if ((fd = open(fn, O_RDONLY, 0666)) == -1) {
		log_e("Failed open file\n");
		r = -1;
		goto finally;
	}
	if ((r = read(fd, fb.data, fb.lmt)) != (int)fb.lmt) {
		log_e("Failed read file\n");
		r = -1;
		goto finally;
	}
	close(fd);
	fd = -1;

	fb.pos = fb.lmt = 0;
	for (; (line_len = aloe_readline(&find_wpasup_keymgmt_getc, &fb, NULL)) >= 0;
			fb.pos = fb.lmt) {
		const char *line_start = (char*)fb.data + fb.pos;
		int sp_len, key_len, ext_len;

		sp_len = strspn(line_start, " \t");

		// all ws
		if (sp_len >= line_len) continue;

		line_len -= sp_len;
		line_start += sp_len;

		// comment
		if (*line_start == '#') continue;

		if (line_len >= (int)linefb.cap) {
			log_e("line length too large\n");
			return -1;
		}

		memcpy(linefb.data, line_start, line_len);
		linefb.pos = 0;
		((char*)linefb.data)[linefb.lmt = line_len] = '\0';

		line_start = (char*)linefb.data;
		switch (parse_state) {
		case parse_state_null:
		case parse_state_network:
			key_len = strlen(key_network);
			if (strncasecmp(line_start, key_network, key_len) != 0) continue;

			// found network
			parse_state = parse_state_key_mgmt;
			break;
		case parse_state_key_mgmt:
			key_len = strlen(key_keymgmt);
			if (strncasecmp(line_start, key_keymgmt, key_len) != 0) continue;

			// found key_mgmt
			// check leading ws
			sp_len = strspn(line_start + key_len, " \t");
			if (key_len + sp_len >= (int)linefb.lmt) {
				log_d("%s got empty value\n", key_keymgmt);
				r = 0;
				goto finally;
			}

			ext_len = (int)linefb.lmt - (key_len + sp_len);

			// length without trailing ws
			ext_len -= aloe_strrspn(line_start + key_len + sp_len,
					ext_len, " \t");

			log_d("%s value len %d: '%s'\n", key_keymgmt, ext_len,
					line_start + key_len + sp_len);

			if (!keyMgmtBuf) {
				// assume caller interesting existance
				r = 0;
				goto finally;
			}

			if ((size_t)ext_len >= keyMgmtBuf->lmt - keyMgmtBuf->pos) {
				// copy without trailing zero
				memcpy((char*)keyMgmtBuf->data + keyMgmtBuf->pos,
						line_start + key_len + sp_len,
						keyMgmtBuf->lmt - keyMgmtBuf->pos);
				keyMgmtBuf->pos = keyMgmtBuf->lmt;
				r = 0;
				goto finally;
			}

			// copy with trailing zero
			memcpy((char*)keyMgmtBuf->data + keyMgmtBuf->pos,
					line_start + key_len + sp_len, ext_len);
			((char*)keyMgmtBuf->data)[keyMgmtBuf->pos += ext_len] = '\0';
			r = 0;
			goto finally;
		default:
			log_e("Invalid parse state\n");
			r = -1;
			goto finally;
		}
	}
	r = -1;
finally:
	if (fb.data) free(fb.data);
	return r;
}

extern "C"
__attribute__((format(printf, 2, 0)))
int air192_mqadk2_vsend(unsigned long send_dur, const char *fmt, va_list va) {
	int r;
	mqd_t mq = (mqd_t)-1;
	air192_mqadk2_tlv_t msg;

	r = vsnprintf(msg.mqadk.msg, sizeof(msg.mqadk.msg), fmt, va);
	if (r >= (int)sizeof(msg.mqadk.msg)) {
		r = EIO;
		log_e("too long for air192 mqadk\n");
		goto finally;
	}
	msg.mqadk.name_len = r + 1;
	msg.tlvhdr.type = air192_mqadk2_tlvtype;
	msg.tlvhdr.len = offsetof(air192_mqadk2_t, msg) + msg.mqadk.name_len;

	if ((mq = mq_open(air192_mqadk2_name_prefix, O_WRONLY, 0644, NULL)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}
	if (send_dur != (unsigned long)-1) {
		struct timespec due;

		if ((r = clock_gettime(CLOCK_REALTIME, &due)) != 0) {
			r = errno;
			log_e("failed get time: %s\n", strerror(r));
			goto finally;
		}
		if (send_dur != 0) {
			ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, send_dur / 1000l,
					(send_dur % 1000l) * 1000000l,
					due.tv_sec, due.tv_nsec, 1000000000l);
		}
		r = mq_timedsend(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len,
				0, &due);
	} else {
		r = mq_send(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len, 0);
	}
	if (r != 0) {
		r = errno;
		log_e("send to mq: %s\n", strerror(r));
		goto finally;
	}
	log_d("sent to %s, %s\n", air192_mqadk2_name_prefix, msg.mqadk.msg);
	r = 0;
finally:
	if (mq != (mqd_t)-1) mq_close(mq);
	return r;
}

extern "C"
__attribute__((format(printf, 2, 3)))
int air192_mqadk2_send(unsigned long send_dur, const char *fmt, ...) {
	int r;
	va_list va;

	va_start(va, fmt);
	r = air192_mqadk2_vsend(send_dur, fmt, va);
	va_end(va);
	return r;
}

extern "C"
int time_delay_ms(uint32_t ms_to_delay) {
	struct timespec ms_delay;
	ms_delay.tv_sec = ( ( ms_to_delay ) >= 1000)? ( ms_to_delay ) / 1000: 0;
	ms_delay.tv_nsec = ( ( ms_to_delay ) % 1000) * 1000000;
	nanosleep( &ms_delay, NULL );

	return SUCCESS;
}

extern "C"
uint64_t time64_get_current_ms(void) {
	struct timeval curr_time;

	gettimeofday(&curr_time, NULL);

	return ((uint64_t)((uint64_t)curr_time.tv_sec * 1000)
			+ ((uint64_t)curr_time.tv_usec / 1000));
}

#define PTHREAD_STACK_SIZE_MIN (20 * 1024) 			// 20 KB
#define PTHREAD_STACK_SIZE_MAX (20 * 1024 * 1024)	// 20 MB

extern "C"
int platform_task_create(PlatformTaskCuntion task_function,
                        char* name,
		                uint32_t stack_size,
		                void* const parameter,
		                unsigned long priority,
                        PlatformTaskHandle* handle) {
	int ret = SUCCESS;

	pthread_t* task = (pthread_t*)calloc(1, sizeof(pthread_t));
	*handle = task;

	pthread_attr_t attr;

	ret = pthread_attr_init(&attr);

	if(ret != 0) {
		log_e("[%s] pthread_attr_init fail %d", __FUNCTION__, ret);
		goto error;
	}

	if(stack_size < PTHREAD_STACK_SIZE_MIN) {
		stack_size = PTHREAD_STACK_SIZE_MIN;
	}

	if(stack_size > PTHREAD_STACK_SIZE_MAX) {
		stack_size = PTHREAD_STACK_SIZE_MAX;
	}

	ret = pthread_attr_setstacksize(&attr, stack_size);

	if(ret != 0) {
		log_e("[%s] pthread_attr_setstacksize %d fail ret %d", __FUNCTION__, stack_size, ret);
		goto error;
	}

	ret = pthread_create(task, &attr, task_function, parameter);

	if(ret != 0) {
		log_e("[%s] pthread_createfail %d", __FUNCTION__, ret);
		goto error;
	}

	ret = pthread_setname_np(*task, name);

	if(ret != 0) {
		log_e("[%s] pthread_setname_np %d", __FUNCTION__, ret);
		goto error;
	}

	pthread_attr_destroy(&attr);

	goto exit;
error:
	free(task);
	return FAIL;
exit:
	pthread_attr_destroy(&attr);

	return ret;
}

extern "C"
int platform_task_cancel(PlatformTaskHandle handle) {
	int ret = SUCCESS;
	pthread_t* task = (pthread_t*)handle;

	pthread_cancel(*task);

	if(task != NULL) {
		free(task);
	}

	return ret;
}

extern "C"
int net_carrier_detect_get(const char* ifa_name, unsigned char* carrier)
{
	size_t ret = 0;
	FILE *fp;

	char path[128] = {0};
	char string_buffer[128] = {0};
	int read_back = 0;

	sprintf(path, "/sys/class/net/%s/carrier", ifa_name);

	fp = fopen(path, "r");

	if (fp == NULL) {
		log_e("open fail\n");
		return -ENOENT;
	}

	ret = fread(string_buffer, 128 , 1, fp);

	if ((int)ret < 0) {
		log_e("can't read net carrier %d\n", ret);
		ret = -EINVAL;
		goto exit;
	}

	read_back = strtol(string_buffer, (char **)NULL, 10);

	if (read_back == 1) {
		*carrier = 1;
	} else {
		*carrier = 0;
	}

exit:
	if (fp != NULL) {
		fclose(fp);
	}

	return ret;
}

extern "C"
int air192_parse_ipsetup(const char *cfg, air192_ipsetup_t *res) {
	int r;
	char ip[20], msk[20], gw[20], dns[20];
	aloe_buf_t cfgFb = {};
	regmatch_t mah[2];

	memset(res, 0, sizeof(*res));
	if (aloe_buf_expand(&cfgFb, 1024, aloe_buf_flag_none) != 0) {
		log_e("Failed alloc for config file\n");
		r = -1;
		goto finally;
	}

	if (aloe_file_fread(cfg, aloe_buf_clear(&cfgFb)) <= 0) {
		log_e("Failed read file\n");
		r = -1;
		goto finally;
	}
	aloe_buf_flip(&cfgFb);

#define kw_ip "ip"
#define kw_dhcp "dhcp"
#define kw_auto "auto"
#define kw_zcip "zcip"
#define kw_netmask "netmask"
#define kw_router "router"
#define kw_dns "dns"

#define mah_reset() for (r = 0; r < (int)aloe_arraysize(mah); r++) { \
	mah[r].rm_so = mah[r].rm_eo = -1; \
}
#define mah_len(_mah) ((_mah)->rm_eo - (_mah)->rm_so)
#define mah_ids1(_ids, _arr, _pat1) \
	mah_reset(); \
	r = air192_regex_test1((char*)cfgFb.data + cfgFb.pos, \
			"^\\s*" _ids "\\s*=\\s*" _pat1 "\\s*", \
			REG_ICASE | REG_EXTENDED | REG_NEWLINE, \
			aloe_arraysize(mah), mah); \
	if (r == 0) { \
		/* log_d(_ids " %d(+%d)\n", cfgFb.pos + mah[1].rm_so, mah_len(&mah[1])); */ \
		if (mah_len(&mah[1]) >= (int)sizeof(_arr)) { \
			log_e("insufficient memory for " _ids "\n"); \
			r = -1; \
			goto finally; \
		} \
		strncpy(_arr, (char*)cfgFb.data + cfgFb.pos + mah[1].rm_so, mah_len(&mah[1])); \
		_arr[mah_len(&mah[1])] = '\0'; \
		log_d(_ids " %d(+%d): %s\n", (int)cfgFb.pos + mah[1].rm_so, mah_len(&mah[1]), _arr); \
	} else if (r == REG_NOMATCH) { \
		_arr[0] = '\0'; \
		log_d(_ids": Unspecified\n"); \
	} else { \
		log_e("parse " _ids "\n"); \
		r = -1; \
		goto finally; \
	}

	ip[0] = msk[0] = gw[0] = dns[0] = '\0';

	mah_ids1(kw_ip, ip, "(.*)");
	if (!ip[0]) {
		log_d("Might empty/ineffective config file\n");
		r = -1;
		goto finally;
	}

	strncpy(res->ip, ip, sizeof(res->ip) - 1);

	if (strcasecmp(ip, kw_dhcp) == 0) res->ipmode |= air192_ipmode_dhcp;
	if (strcasecmp(ip, kw_zcip) == 0) res->ipmode |= air192_ipmode_zcip;
	if (strcasecmp(ip, kw_auto) == 0) res->ipmode |= air192_ipmode_auto;

	if (!res->ipmode) {
		mah_ids1(kw_netmask, msk, "(.*)");
		if (!msk[0]) {
			log_e("parse %s\n", kw_netmask);
			r = -1;
			goto finally;
		}

		mah_ids1(kw_router, gw, "(.*)");
		if (!gw[0]) {
			log_e("parse %s\n", kw_router);
			r = -1;
			goto finally;
		}

		mah_ids1(kw_dns, dns, "(.*)");
		if (!dns[0]) {
			log_e("parse %s\n", kw_dns);
			r = -1;
			goto finally;
		}

		strncpy(res->msk, msk, sizeof(res->msk) - 1);
		strncpy(res->gw, gw, sizeof(res->gw) - 1);
		strncpy(res->dns, dns, sizeof(res->dns) - 1);
	}
	r = 0;
finally:
	res->parse_eno = r;
	if (cfgFb.data) {
		free(cfgFb.data);
	}
	return r;
}
