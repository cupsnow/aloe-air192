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

#ifndef _H_ALOE_AIR192
#define _H_ALOE_AIR192

#include "admin.h"
#include <regex.h>
#include <time.h>
#include <cjson/cJSON.h>

/** @defgroup ALOE_AIR192_API Air192 API
 * @brief Air192 API.
 */

/** @defgroup ALOE_CAM2 Copy from cam2
 * @brief Copy from cam2.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup ALOE_AIR192_API
 * @{
 */

#define persist_cfg "/media/cfg"
#define accname_cfg persist_cfg "/acc_name"
#define hostname_cfg persist_cfg "/hostname"
#define wpasup_cfg persist_cfg "/wpa_supplicant.conf"
#define eth_cfg persist_cfg "/eth.conf"
#define wlan_cfg persist_cfg "/wlan.conf"
#define macaddr_cfg persist_cfg "/macaddr.conf"
#define wifi_macaddr_cfg persist_cfg "/wifi_macaddr.conf"
#define spkcal_cfg persist_cfg "/spklatency"
#define wol_cfg persist_cfg "/wol.conf"
#define ledban_cfg persist_cfg "/ledban.conf"
#define serialnum_cfg persist_cfg "/serialnum.conf"
#define bdname_cfg persist_cfg "/bdname.conf"
#define spkcal_raw "/var/run/spklatency"
#define led_cfg "/etc/led.conf"
#define oob_cfg "/etc/outofbox"
#define promisc_cfg "/etc/promisc"
#define resolv_cfg "/var/run/udhcpc/resolv.conf"
#define wfa_cfg "/etc/wfa.conf"
#define app_cfg "/etc/sa7715.json"
#define wacbusy_cfg "/var/run/wac_busy"
#define unpaired_cfg "/var/run/adk_unpaired"
#define mainguard_cfg "/var/run/main_guard"
#ifdef USER_PREFIX
// ie. build/sysroot-ub20/var/cgi-bin/admin-debug.log
#  define air192_ts1_LOG_PATH USER_PREFIX "admin-debug-timing.log"
#else
#  define air192_ts1_LOG_PATH "/media/admin-debug_timing.log"
#endif

#define HTTP_TOKEN_SIZE "size"
#define HTTP_TOKEN_OFFSET "offset"

#define ELGATO_ERROR_MESSAGE_OTHER "Other error message, see message field"
#define ELGATO_ERROR_MESSAGE_FW_SIZE_TOO_BIG "Firmware file size is too big"
#define ELGATO_ERROR_MESSAGE_FW_SIZE_TOO_SMALL "Firmware file size is too small"
#define ELGATO_ERROR_MESSAGE_INAVLID_OFFSET "Invalid offset"
#define ELGATO_ERROR_MESSAGE_TOO_MUCH_DATA "Too much data"
#define ELGATO_ERROR_MESSAGE_FW_SIG_INVALID "Firmware signature invalid"
#define ELGATO_ERROR_MESSAGE_FW_NOT_FOR_THIS_ACC "Firmware cannot be used by this accessory"

#define ELGATO_ERROR_CODE_OTHER -1
#define ELGATO_ERROR_CODE_SUCCES 0
#define ELGATO_ERROR_CODE_FW_SIZE_TOO_BIG 100
#define ELGATO_ERROR_CODE_FW_SIZE_TOO_SMALL 101
#define ELGATO_ERROR_CODE_INAVLID_OFFSET 102
#define ELGATO_ERROR_CODE_TOO_MUCH_DATA 103
#define ELGATO_ERROR_CODE_FW_SIG_INVALID 104
#define ELGATO_ERROR_CODE_FW_NOT_FOR_THIS_ACC 105

#define _ELGATO_HTTP_FIRMWAREUPDATE_EXECUTE "/firmware-update/execute"
#define _ELGATO_HTTP_FIRMWAREUPDATE_PREPARE "/firmware-update/prepare"
#define _ELGATO_HTTP_FIRMWAREUPDATE_DATA "/firmware-update/data"
#define _ELGATO_HTTP_ACCESSORY_INFO "/accessory-info"
#define _ELGATO_HTTP_IDENTIFY "/identify"
#define _ELGATO_HTTP_WIFI_INFO "/wifi-info"

#define ELGATO_HTTP_PATH "/elgato"
#define ELGATO_HTTP_FIRMWAREUPDATE_EXECUTE ELGATO_HTTP_PATH _ELGATO_HTTP_FIRMWAREUPDATE_EXECUTE
#define ELGATO_HTTP_FIRMWAREUPDATE_PREPARE ELGATO_HTTP_PATH _ELGATO_HTTP_FIRMWAREUPDATE_PREPARE
#define ELGATO_HTTP_FIRMWAREUPDATE_DATA ELGATO_HTTP_PATH _ELGATO_HTTP_FIRMWAREUPDATE_DATA

#define EVE_HTTP_PATH "/eve"
#define EVE_HTTP_FIRMWAREUPDATE_EXECUTE EVE_HTTP_PATH _ELGATO_HTTP_FIRMWAREUPDATE_EXECUTE
#define EVE_HTTP_FIRMWAREUPDATE_PREPARE EVE_HTTP_PATH _ELGATO_HTTP_FIRMWAREUPDATE_PREPARE
#define EVE_HTTP_FIRMWAREUPDATE_DATA EVE_HTTP_PATH _ELGATO_HTTP_FIRMWAREUPDATE_DATA
#define EVE_HTTP_ACCESSORY_INFO EVE_HTTP_PATH _ELGATO_HTTP_ACCESSORY_INFO
#define EVE_HTTP_IDENTIFY EVE_HTTP_PATH _ELGATO_HTTP_IDENTIFY
#define EVE_HTTP_WIFI_INFO EVE_HTTP_PATH _ELGATO_HTTP_WIFI_INFO

int air192_name_get(const char **fns, aloe_buf_t *buf,
		int (*refine)(aloe_buf_t*));

cJSON* air192_jcfg_load(const char **fns, aloe_buf_t *buf);

int air192_cfg_load2(const char **fns, aloe_buf_t *buf, int max);
int air192_ini_find(const char *fname, const char *key, aloe_buf_t *buf);

uint16_t air192_eve_hash4(const void *data, size_t sz);

int air192_GetSerialNumberHashString(const char *inSerialNumber,
		char *outHashStrBuf, int outHashStrBufSize);

/**
 *
 * @param fname
 * @param fmt
 * @return
 *   - 0 for file not exist or size zero
 *   - negative for error
 *   - otherwise number of scanf
 */
__attribute__((format(scanf, 2, 3)))
int air192_file_scanf1(const char *fname, const char *fmt, ...);

int air192_regex_test1(const char *fmt, const char *pat, int cflags,
		size_t nmatch, regmatch_t *pmatch);

__attribute__((format(printf, 3, 4)))
int air192_led_set(int led_val, unsigned long send_dur,
		const char *name_fmt, ...);

int air192_adk_paired(const char **fns);

const char* air192_accname_char(size_t *sz);

#define air192_d2(...) _air192_d3(__VA_ARGS__)

#define _air192_d3(_fmt, _args...) do { \
    struct timespec ts; struct tm tm; \
    clock_gettime(CLOCK_REALTIME, &ts); localtime_r(&ts.tv_sec, &tm); \
    fprintf(stdout, "[%02d:%02d:%02d.%06d][air192][%s][#%d]" _fmt, \
            (int)tm.tm_hour, (int)tm.tm_min, (int)tm.tm_sec, (int)(ts.tv_nsec / 1000), \
            __func__, __LINE__, ##_args); \
    fflush(stdout); \
} while(0)

#define _air192_ts1(_fmt, _args...) do { \
	struct timespec ts; struct tm tm; \
	FILE *fp; \
	clock_gettime(CLOCK_REALTIME, &ts); localtime_r(&ts.tv_sec, &tm); \
	fprintf(stdout, "[%02d:%02d:%02d.%06d][air192][%s][#%d]" "[DebugTiming " __DATE__ "]" _fmt, \
			(int)tm.tm_hour, (int)tm.tm_min, (int)tm.tm_sec, (int)(ts.tv_nsec / 1000), \
			__func__, __LINE__, ##_args); \
	fflush(stdout); \
	if ((fp = fopen(air192_ts1_LOG_PATH, "a+"))) { \
		fprintf(fp, "[%02d:%02d:%02d.%06d][air192][%s][#%d]" "[DebugTiming " __DATE__ "]" _fmt, \
				(int)tm.tm_hour, (int)tm.tm_min, (int)tm.tm_sec, (int)(ts.tv_nsec / 1000), \
				__func__, __LINE__, ##_args); \
		fflush(fp); \
		fclose(fp); \
	} \
} while(0);

typedef struct air192_cgireq_rec {
	const char *reason;
	int prog_st, prog_iter, err;
	aloe_buf_t cmdbuf;
	cJSON *jroot, *jout;
} air192_cgireq_t;

enum {
	air192_cgireq_prog_null = 0,
	air192_cgireq_prog_complete = air192_cgireq_prog_null + 100,
	air192_cgireq_prog_failed,
	air192_cgireq_prog_fatal, // including less then prog_null
	air192_cgireq_prog_refine_rc, // unlock cgi request
	air192_cgireq_prog_max,
};

#define air192_cgireq_reason(_req, ...) if ((_req)->cmdbuf.data) { \
	aloe_buf_clear(&(_req)->cmdbuf); \
	if (aloe_buf_printf(&(_req)->cmdbuf, __VA_ARGS__) < 0) { \
		aloe_buf_printf(&(_req)->cmdbuf, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
	(_req)->reason = (char*)(_req)->cmdbuf.data; \
	log_d("%s\n", (_req)->reason); \
}

__attribute__((format(printf, 3, 4)))
int air192_cgireq_open(air192_cgireq_t *req, const char *prog_lock,
		const char *fmt, ...);

int air192_cgireq_ipcfg_read(const char *cfg, cJSON **jout, aloe_buf_t *reason);
int air192_cgireq_ipcfg_save(const char *ip, const char *msk, const char *gw,
		const char *dns, aloe_buf_t *reason, const char *cfg);
int air192_cgireq_ipcfg_unmarshal(cJSON *jroot, const char **ip,
		const char **msk, const char **gw, const char **dns,
		aloe_buf_t *reason);

__attribute__((format(printf, 4, 5)))
int air192_sus_set(int whence, int delay, unsigned long send_dur,
		const char *name_fmt, ...);

typedef int (*air192_cli_cb_t)(void *cbarg, int len, const char *msg);
void* air192_cli_start(const char *name, air192_cli_cb_t cb, void *cbarg);
void air192_cli_stop(void*);

__attribute__((format(printf, 3, 0)))
int air192_cli_vsend(const char *name, unsigned long send_dur,
		const char *fmt, va_list va);
__attribute__((format(printf, 3, 4)))
int air192_cli_send(const char *name, unsigned long send_dur,
		const char *fmt, ...);

typedef enum air192_wpa_sec_enum {
	air192_wpa_sec_open,
	air192_wpa_sec_wpa_tkip,
	air192_wpa_sec_wpa_ccmp,
	air192_wpa_sec_wpa_ccmp_tkip,
	air192_wpa_sec_wpa2_tkip,
	air192_wpa_sec_wpa2_ccmp,
	air192_wpa_sec_wpa2_ccmp_tkip,
	air192_wpa_sec_wpa3_sae,
	air192_wpa_sec_enum_max,
} air192_wpa_sec_t;

void air192_wpa_close(void *ctx);
void* air192_wpa_open(const char *ctrlPath, const char *wpaPath,
		const char *ifce);
int air192_wpa_disconnect(void *ctx);
const aloe_buf_t* air192_wpa_scan(void *ctx, long dur, aloe_buf_t *buf);
int air192_wpa_scanresult_parse(aloe_buf_t *buf, cJSON **jarr);
int air192_wpa_scanresult_parse_flags(const char *flags,
		air192_wpa_sec_t *sec, int sec_max);
int air192_wpa_scanresult_parse_sec(const char *sec_str,
		air192_wpa_sec_t *sec, int sec_max);

void air192_ffaac_close(void *_dec);
void* air192_ffaac_open_lc(int rate, int channel, long buf_ms);
int air192_ffaac_reset(void *_dec);
int air192_ffaac_decode(void *_dec, const void *data, size_t sz, void *aout,
		size_t asz, unsigned flag);

void air192_fdkaac_close(void *_dec);
void* air192_fdkaac_open_lc(int rate, int channel, long buf_ms);
int air192_fdkaac_reset(void *_dec);
int air192_fdkaac_decode(void *_dec, const void *data, size_t sz, void *aout,
		size_t asz, unsigned flag);

// No accessory when use this
#define EVE_IE_HDR_OUI_0 0x00
#define EVE_IE_HDR_OUI_1 0x0C
#define EVE_IE_HDR_OUI_2 0x6C

#define ELGATO_HTTP_PORT 9123
#define ELGATO_VENDOR_CONSTANT 0x00CE
#define ELGATO_HEADER_VERSION 1
#define ELGATO_HEADER_STR "Elgato Firmware - (c) Elgato Systems GmbH"
#define ELGATO_HEADER \
		0x45, 0x6c, 0x67, 0x61, 0x74, 0x6f, 0x20, 0x46, \
		0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x20, \
		0x2d, 0x20, 0x28, 0x63, 0x29, 0x20, 0x45, 0x6c, \
		0x67, 0x61, 0x74, 0x6f, 0x20, 0x53, 0x79, 0x73, \
		0x74, 0x65, 0x6d, 0x73, 0x20, 0x47, 0x6d, 0x62, \
		0x48

#define EVE_HEADER_STR "Eve Firmware - (c) Eve Systems GmbH      "
#define EVE_HEADER \
		0x45, 0x76, 0x65, 0x20, 0x46, 0x69, 0x72, 0x6d, \
		0x77, 0x61, 0x72, 0x65, 0x20, 0x2d, 0x20, 0x28, \
		0x63, 0x29, 0x20, 0x45, 0x76, 0x65, 0x20, 0x53, \
		0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x20, 0x47, \
		0x6d, 0x62, 0x48, 0x20, 0x20, 0x20, 0x20, 0x20, \
		0x20

typedef struct __attribute__((packed)) air192_eve_fwhdr_rec {
	uint16_t ElgatoVendorConstant;
	uint16_t Version;
	uint8_t ElgatoHeader[41];
	uint8_t BoardType;
	uint16_t VersionMajor;
	uint16_t VersionMinor;
	uint16_t VersionMinor2;
	uint16_t VersionBuildNumber;
	uint32_t FirmwareSize;
	uint16_t FirmwareDataOffset;
	uint8_t Reserved[2];
	uint16_t SignatureID;
	uint8_t Signature[64];
} air192_eve_fwhdr_t;

typedef struct __attribute__((packed)) air192_eve_tagged_fwhdr_rec {
	uint8_t tag[8];
	air192_eve_fwhdr_t hdr;
} air192_eve_tagged_fwhdr_t;

#define air192_eve_fwhdr_tag 0x11, 0xFE, 0x22, 0xDC, 0x33, 0xBA, 0x44, 0x98

extern volatile air192_eve_tagged_fwhdr_t air192_eve_tagged_fwhdr;

extern volatile const uint8_t *air192_eve_wifi_verifying_key;
extern volatile const size_t air192_eve_wifi_verifying_key_size;

extern volatile const uint8_t *air192_elgato_wifi_verifying_key;
extern volatile const size_t air192_elgato_wifi_verifying_key_size;

extern volatile const uint8_t *air192_dexatek_verification_public_key;
extern volatile const size_t air192_dexatek_verification_public_key_size;

int air192_serial_number(aloe_buf_t *buf);

int air192_bdname(aloe_buf_t *buf);

int air192_refact_num(int *refact);

size_t air192_hostname_refine(const char *data, size_t sz, int chr, char *out);

int air192_wac_name(aloe_buf_t *buf);

int air192_stacktrace1(int skip);

int air192_find_wpasup_keymgmt(const char *fn, aloe_buf_t *keyMgmtBuf);

#define air192_spkcal_val_unknown 0x7fff
#define air192_spkcal_val_inprogress 0

/** Keep the same formula to spkcal. */
#define air192_spkcal_to_airplay(_v) (-33 + 13 * (((_v) <= 0 ? 0 : (_v)) - 117) / 19)

typedef struct __attribute__((packed)) {
	int16_t type, len;
} air192_tlvhdr_t;

extern const char *led_conf;

#define air192_mqled_name "/air192_mqled"
typedef struct __attribute__((packed)) {
	int16_t led_val, name_len;
	char name[50]; // max size
} air192_mqled_t;

#define air192_mqled_tlvtype 0x1
typedef struct __attribute__((packed)) {
	air192_tlvhdr_t tlvhdr;
	air192_mqled_t mqled;
} air192_mqled_tlv_t;

#define air192_mqsus_name "/air192_sus"
typedef struct __attribute__((packed)) {
	uint8_t whence, name_len;
	uint16_t delay; // seconds
	char name[50]; // max size
} air192_mqsus_t;
typedef enum air192_mqsus_whence_enum {
	air192_mqsus_whence_null = 0,
	air192_mqsus_whence_set,
	air192_mqsus_whence_max,
} air192_mqsus_whence_t;

#define air192_mqsus_tlvtype 0x2
typedef struct __attribute__((packed)) {
	air192_tlvhdr_t tlvhdr;
	air192_mqsus_t mqsus;
} air192_mqsus_tlv_t;

#define air192_mqcli_name_prefix "/air192_cli_"
typedef struct __attribute__((packed)) {
	int16_t dummy, name_len;
	char msg[100]; // max size
} air192_mqcli_t;

#define air192_mqcli_tlvtype 0x3
typedef struct __attribute__((packed)) {
	air192_tlvhdr_t tlvhdr;
	air192_mqcli_t mqcli;
} air192_mqcli_tlv_t;

#define air192_climgr_tlvtype 0x4

#define air192_mqadk2_name_prefix "/air192_adk2_"
typedef struct __attribute__((packed)) {
	int16_t dummy, name_len;
	char msg[100]; // max size
} air192_mqadk2_t;

#define air192_mqadk2_tlvtype 0x5
typedef struct __attribute__((packed)) {
	air192_tlvhdr_t tlvhdr;
	air192_mqadk2_t mqadk;
} air192_mqadk2_tlv_t;

__attribute__((format(printf, 2, 0)))
int air192_mqadk2_vsend(unsigned long send_dur, const char *fmt, va_list va);

__attribute__((format(printf, 2, 3)))
int air192_mqadk2_send(unsigned long send_dur, const char *fmt, ...);

/** @} ALOE_AIR192_API */

/** @addtogroup ALOE_CAM2
 * @{
 */

//#define _ecam2_log_error( tag, format, ... )		printf( "\033[1;31m[%lld][ERROR][%s:%d]"format"\033[1;39m\n", time64_get_current_ms(), tag, __LINE__, ##__VA_ARGS__ )
//#define _ecam2_log_warn( tag, format, ... )		printf( "\033[1;33m[%lld][WARN][%s:%d]"format"\033[1;39m\n", time64_get_current_ms(), tag, __LINE__, ##__VA_ARGS__ )
//#define _ecam2_log_info( tag, format, ... )		printf( "\033[1;32m[%lld][INFO][%s]"format"\033[1;39m\n", time64_get_current_ms(), tag, ##__VA_ARGS__ )
//#define _ecam2_log_debug( tag, format, ... )		printf( "\033[1;39m[%lld][DEBUG][%s]"format"\033[1;39m\n", time64_get_current_ms(), tag, ##__VA_ARGS__ )
//#define _ecam2_log_trace( tag, format, ... )		printf( "\033[1;34m[%lld][TRACE][%s]"format"\033[1;39m\n", time64_get_current_ms(), tag, ##__VA_ARGS__ )

#define ecam2_log_msg(_lvl, _tag, _acr, _fmt, ...) do { \
	fprintf(stdout, _acr "[%lld]["_lvl"][%s:%d]" _fmt "\033[1;39m\n", time64_get_current_ms(), tag, __LINE__, ##__VA_ARGS__ ); \
	fflush(stdout); \
} while(0)

#define ecam2_log_error( ... ) 		ecam2_log_msg("ERROR", tag, "\033[1;31m", __VA_ARGS__)
#define ecam2_log_warn( ... )		ecam2_log_msg("WARN", tag, "\033[1;33m", __VA_ARGS__)
#define ecam2_log_info( ... )		ecam2_log_msg("INFO", tag, "\033[1;32m", __VA_ARGS__)
#define ecam2_log_debug( ... )		ecam2_log_msg("DEBUG", tag, "\033[1;39m", __VA_ARGS__)
#define ecam2_log_trace( ... )		ecam2_log_msg("TRACE", tag, "\033[1;34m", __VA_ARGS__)

#ifndef SUCCESS
#	define		SUCCESS				0
#endif

#ifndef FAIL
#	define		FAIL			   -1
#endif

#ifndef BOOL
#	define		BOOL				uint8_t
#endif

#ifndef TRUE
#	define		TRUE				1
#endif

#ifndef FALSE
#	define		FALSE				0
#endif

#ifndef INT32_INVALID
#   define INT32_INVALID           INT_MIN
#endif

#define SECOND (1000)

#ifndef time_after
#  define time_after(a,b)	((int64_t)((int64_t)(b) - (int64_t)(a)) < 0)
#endif

int time_delay_ms(uint32_t ms_to_delay);
uint64_t time64_get_current_ms(void);

typedef void* (*PlatformTaskCuntion)(void*);
typedef void *PlatformTaskHandle;
typedef void *TaskReturn;

int platform_task_create(PlatformTaskCuntion task_function,
                        char* name,
		                uint32_t stack_size,
		                void* const parameter,
		                unsigned long priority,
                        PlatformTaskHandle* handle);

int platform_task_cancel(PlatformTaskHandle handle);
int net_carrier_detect_get(const char* ifa_name, unsigned char* carrier);

typedef enum {
	air192_ipmode_dhcp = (1 << 0),
	air192_ipmode_zcip = (1 << 1),
	air192_ipmode_auto = (1 << 2),
	air192_ipmode_not_static = air192_ipmode_dhcp | air192_ipmode_zcip
		| air192_ipmode_auto,
} air192_ipmode_t;

typedef struct ipsetup_rec {
	int ipmode, parse_eno;
	char ip[20], msk[20], gw[20], dns[20];
} air192_ipsetup_t;

int air192_parse_ipsetup(const char *cfg, air192_ipsetup_t *res);

/** @} ALOE_CAM2 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* _H_ALOE_AIR192 */
