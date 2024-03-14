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

#define TEST_AIR192 1

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <syslog.h>
#include <sys/random.h>
#include <admin/unitest.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <getopt.h>

#if defined(TEST_AIR192) && TEST_AIR192
#include <admin/air192.h>
#include <admin/sa7715.h>
#endif

#include <cjson/cJSON.h>

extern "C" {

#include <libavutil/frame.h>
#include <libavutil/mem.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include <libavutil/opt.h>
#include <libavutil/channel_layout.h>
#include <libavutil/samplefmt.h>
#include <libswresample/swresample.h>

}

#include <admin/nl.h>

#define DECL_TEST(_n, _args...) \
	__attribute__((unused)) \
	static aloe_test_flag_t _n (aloe_test_case_t *test_case, ##_args)

static struct {
	int ondevice;
} impl;

DECL_TEST(test1_jcfg1) {
	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;
	const char *str, *fns[] = {
#define TEST1_JCFG1_CFG1 "test1_jcfg1.json"
			TEST1_JCFG1_CFG1,
			NULL
	};

	ALOE_TEST_ASSERT_THEN(aloe_buf_aprintf(aloe_buf_clear(&buf), -1,
			"{"
				"\"name\": \"%s\","
				"\"num\": %d"
			"}", "bob", 8) > 0
			&& aloe_file_fwrite(TEST1_JCFG1_CFG1, aloe_buf_flip(&buf)) > 0,
			test_case, failed, {
		goto finally;
	});

	ALOE_TEST_ASSERT_THEN((jroot = air192_jcfg_load(fns, &buf))
			&& (str = cJSON_GetStringValue(cJSON_GetObjectItem(jroot, "name")))
			&& strcmp(str, "bob") == 0,
			test_case, failed, {
		goto finally;
	});
	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	return test_case->flag_result;
#undef TEST1_JCFG1_CFG1
}

DECL_TEST(test1_ledconf1) {
	char pat[] = {
		"led_power 38\n"
		"led_standby 39\n"
		"  # led_gear 122\n"
		"led_gear 123\n"
		"\n"
		"sw_gear 144\n"
	};
	aloe_buf_t buf = {.data = pat, .cap = sizeof(pat)};
	char *pl, *pl_tok;
	int led_ex = 0;

	buf.pos = strlen((char*)buf.data);
	aloe_buf_flip(&buf);

	for (pl = strtok_r((char*)buf.data + buf.pos, "\r\n", &pl_tok);
			pl; pl = strtok_r(NULL, "\r\n", &pl_tok)) {
		char *name, *val_str, *plk_tok;
		long gpio_num;

		pl += strspn(pl, aloe_str_sep);
		if (strncasecmp(pl, "led_", 4) != 0
				|| (!isalpha(pl[4]) && isdigit(pl[4]))) {
			log_d("Ignore line: %s\n", pl);
			continue;
		}

		if (!(name = strtok_r(pl + 4, aloe_str_sep, &plk_tok))
				|| !(val_str = strtok_r(NULL, aloe_str_sep, &plk_tok))) {
			continue;
		}
		if (aloe_strtol(val_str, NULL, 0, &gpio_num) != 0) {
			log_e("Parse led %s, gpio #%s\n", name, val_str);
			continue;
		}

		if (strcasecmp(name, "power") == 0) {
			log_d("led %s, gpio #%ld\n", name, gpio_num);
			continue;
		}

		if (strcasecmp(name, "standby") == 0) {
			log_d("led %s, gpio #%ld\n", name, gpio_num);
			continue;
		}
		log_d("led[%d] %s, gpio #%ld\n", led_ex++, name, gpio_num);
	}

	test_case->flag_result = aloe_test_flag_result_pass;
finally: __attribute__((unused));
	return test_case->flag_result;
}

typedef struct {
	void *ctx;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int argc;
	char args[200], *argv[20];
} test1_mqcli1_t;

static const char mqcli_prename[] = air192_mqcli_name_prefix;
#define mqcli_prename_sz (sizeof(mqcli_prename) - 1)

#define HAPLogError(_ignore1, ...) log_e(__VA_ARGS__)
static int test1_mqcli1_cli(void *cbarg, int len, const char *msg) {
	test1_mqcli1_t *mqcli = (test1_mqcli1_t*)cbarg;
	int r, i;

	air192_d2("recv %d bytes, %s\n", len, msg);
	if (len >= (int)sizeof(mqcli->args)) {
		r = EIO;
        HAPLogError(&kHAPLog_Default, "Too long args\n");
        goto finally;
	}
	memcpy(mqcli->args, msg, len);
	mqcli->args[len] = '\0';
	mqcli->argc = aloe_arraysize(mqcli->argv);
	if ((r = aloe_cli_tok(mqcli->args, &mqcli->argc, mqcli->argv, NULL)) != 0
			|| mqcli->argc >= (int)aloe_arraysize(mqcli->argv)) {
		r = EIO;
		HAPLogError(&kHAPLog_Default, "Too long args\n");
		goto finally;
	}

#if 1
	for (i = 0; i < mqcli->argc; i++) {
		air192_d2("argv[%d/%d]: %s\n", i + 1, mqcli->argc, mqcli->argv[i]);
	}
#endif
	if ((r = pthread_mutex_lock(&mqcli->mutex)) != 0) {
		r = errno;
		log_e("lock mutex: %s\n", strerror(r));
		goto finally;
	}

	if ((r = pthread_cond_broadcast(&mqcli->cond))) {
		r = errno;
		log_e("cond broadcast: %s\n", strerror(r));
		goto finally;
	}

	if ((r = pthread_mutex_unlock(&mqcli->mutex)) != 0) {
		r = errno;
		log_e("unlock mutex: %s\n", strerror(r));
		goto finally;
	}
	r = 0;
finally:
	return r;
}

DECL_TEST(test1_mqcli1) {
	test1_mqcli1_t mqcli = {.ctx = NULL};
	struct {
		unsigned mux : 1;
		unsigned cond : 1;
	} init_iter = {0};
	int r;

	ALOE_TEST_ASSERT_THEN((mqcli_prename_sz == strlen(air192_mqcli_name_prefix)),
			test_case, failed, {
		goto finally;
	});

	ALOE_TEST_ASSERT_THEN((r = pthread_mutex_init(&mqcli.mutex, NULL)) == 0,
			test_case, failed, {
		r = errno;
		log_e("alloc mutex: %s\n", strerror(r));
		goto finally;
	});
	init_iter.mux = 1;

	ALOE_TEST_ASSERT_THEN((r = pthread_cond_init(&mqcli.cond, NULL)) == 0,
			test_case, failed, {
		r = errno;
		log_e("alloc cond: %s\n", strerror(r));
		goto finally;
	});
	init_iter.cond = 1;

	ALOE_TEST_ASSERT_THEN((mqcli.ctx = air192_cli_start("test1_mqcli1",
			&test1_mqcli1_cli, &mqcli)), test_case, failed, {
		goto finally;
	});

#define mqcli1_wait() \
	ALOE_TEST_ASSERT_THEN((r = pthread_mutex_lock(&mqcli.mutex)) == 0, \
			test_case, failed, { \
		r = errno; \
		log_e("lock mutex: %s\n", strerror(r)); \
		goto finally; \
	}); \
	ALOE_TEST_ASSERT_THEN((r = pthread_cond_wait(&mqcli.cond, &mqcli.mutex)) == 0, \
			test_case, failed, { \
		r = errno; \
		log_e("cond wait: %s\n", strerror(r)); \
		goto finally; \
	}); \
	ALOE_TEST_ASSERT_THEN((r = pthread_mutex_unlock(&mqcli.mutex)) == 0, \
			test_case, failed, { \
		r = errno; \
		log_e("unlock mutex: %s\n", strerror(r)); \
		goto finally; \
	});

	ALOE_TEST_ASSERT_THEN((air192_cli_send("test1_mqcli1",
			ALOE_EV_INFINITE, "volume 20")) == 0, test_case, failed, {
		goto finally;
	});
	mqcli1_wait();

#if 0
	ALOE_TEST_ASSERT_THEN((air192_cli_send("test1_mqcli1",
			ALOE_EV_INFINITE, "%s", "bye")) == 0, test_case, failed, {
		goto finally;
	});
	mqcli1_wait();
#endif

	test_case->flag_result = aloe_test_flag_result_pass;
finally: __attribute__((unused));
	if (mqcli.ctx) air192_cli_stop(mqcli.ctx);
	if (init_iter.mux) pthread_mutex_destroy(&mqcli.mutex);
	if (init_iter.cond) pthread_cond_destroy(&mqcli.cond);
	return test_case->flag_result;
}

DECL_TEST(test1_wpacli1) {
	void *wpa = NULL;
	std::unique_ptr<char[]> _buf(new char[5000]);
	aloe_buf_t buf = {.data = _buf.get(), .cap = 5000};
	cJSON *jarr = NULL;
	int r;
#if !defined(USER_PREFIX)
	const char *wpaPath = "/var/run/wpa_supplicant";
	const char *ifce = "wlan0";
	const char *ctrlPath = "/var/run/wificfg-ctrl";
	aloe_buf_t buf2;
	struct {
		unsigned wpasup: 1;
		unsigned wpasup_retain: 1;
	} start_flag = { };
#endif

#if defined(USER_PREFIX)
	ALOE_TEST_ASSERT_THEN((r = aloe_file_fread("wpacli1.log", aloe_buf_clear(&buf))) > 0 &&
			aloe_buf_remain(&buf) > 0
			, test_case, failed, {
		goto finally;
	});
#else
	ALOE_TEST_ASSERT_THEN((r = snprintf((char*)buf.data, buf.cap,
			"wpa_cli status &>/dev/null")) > 0 && r < (int)buf.cap
			, test_case, failed, {
		log_e("Failed compose wpa_cli status\n");
		goto finally;
	});
	if (system((char*)buf.data) == 0) start_flag.wpasup_retain = 1;
	log_d("wpasup_retain: %d\n", start_flag.wpasup_retain);

	ALOE_TEST_ASSERT_THEN ((r = snprintf((char*)buf.data, buf.cap,
			"wpasup -i %s start; sleep 10", ifce)) > 0 && r < (int)buf.cap
			, test_case, failed, {
		log_e("Failed compose command to run wpasup\n");
		goto finally;
	});
	system((char*)buf.data);
	start_flag.wpasup = 1;

	ALOE_TEST_ASSERT_THEN((wpa = air192_wpa_open(ctrlPath, wpaPath, ifce))
			, test_case, failed, {
		goto finally;
	});

	ALOE_TEST_ASSERT_THEN(
			(!start_flag.wpasup_retain || air192_wpa_disconnect(wpa) == 0) &&
			air192_wpa_scan(wpa, 30, aloe_buf_clear(&buf))
			, test_case, failed, {
		goto finally;
	});
	buf2 = buf;
	aloe_buf_flip(&buf2);
	ALOE_TEST_ASSERT_THEN(aloe_buf_remain(&buf2) > 0 &&
			((size_t)aloe_file_write("wpacli1.log", "w", &buf2) == aloe_buf_remain(&buf2))
			, test_case, failed, {
		goto finally;
	});
#endif

	ALOE_TEST_ASSERT_THEN((air192_wpa_scanresult_parse(&buf, &jarr) == 0)
			, test_case, failed, {
		goto finally;
	});

	for (int i = 0; i < cJSON_GetArraySize(jarr); i++) {
		cJSON *jarr1 = cJSON_GetArrayItem(jarr, i);
		air192_wpa_sec_t sec[5];
		int sec_cnt, sec_idx;

		const char *ssid = cJSON_GetStringValue(cJSON_GetObjectItem(jarr1,
				"ssid"));
		const char *bssid = cJSON_GetStringValue(cJSON_GetObjectItem(jarr1,
				"bssid"));
		const char *flags = cJSON_GetStringValue(cJSON_GetObjectItem(jarr1,
				"flags"));
		const int freq = cJSON_GetNumberValue(cJSON_GetObjectItem(jarr1,
				"freq"));
		const int rssi = cJSON_GetNumberValue(cJSON_GetObjectItem(jarr1,
				"rssi"));

		log_d("ssid %s (bssid %s) flags %s freq %d rssi %d\n",
				ssid, bssid, flags, freq, rssi);

		sec_cnt = air192_wpa_scanresult_parse_flags(flags, sec,
				aloe_arraysize(sec));
		for (sec_idx = 0; sec_idx < sec_cnt; sec_idx++) {
			if (sec[sec_idx] == air192_wpa_sec_wpa3_sae) {
				log_d("found wpa3\n");
				break;
			}
		}
	}

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (jarr) cJSON_Delete(jarr);
	air192_wpa_close(wpa);
	return test_case->flag_result;
}

DECL_TEST(test1_wpacfg1) {
	std::unique_ptr<char[]> _buf(new char[5000]);
	aloe_buf_t buf = {.data = _buf.get(), .cap = 5000};
	int r;

	r = air192_find_wpasup_keymgmt("tmp/wpa_supplicant.conf",
			aloe_buf_clear(&buf));
	log_d("findKeyMgmt ret %s(%d), len %d, %s\n",
			(r >= 0 ? "Found" : "Miss"), r, (int)buf.pos,
			((buf.pos <= 0) ? "" :
			(buf.pos < buf.lmt) ? (char*)buf.data :
			"<ORZ>"));

	test_case->flag_result = aloe_test_flag_result_pass;
//finally:
	return test_case->flag_result;
}

DECL_TEST(test1_offsetof1) {
	typedef struct {
		int16_t i16;
		uint8_t u8;
		int16_t i16_2;
		int8_t i8;
		int8_t i8_2;
		int8_t i8_3;
	} rec_t;

	typedef struct __attribute__((packed)) {
		int16_t i16;
		uint8_t u8;
		int16_t i16_2;
		int8_t i8;
		int8_t i8_2;
		int8_t i8_3;
	} rec_packed_t;

	ALOE_TEST_ASSERT_THEN(aloe_offsetwith(rec_t, i16_2) == 6,
			test_case, failed, {
		goto finally;
	});
	ALOE_TEST_ASSERT_THEN(aloe_offsetwith(rec_packed_t, i16_2) == 5,
			test_case, failed, {
		goto finally;
	});

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	return test_case->flag_result;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define AU_MS2SZ(_rate, _ch, _samp, _ms) ( \
		(_rate) * (_ch) * (_samp) * (_ms) / 1000)

#define aloe_aac_test_info() "aac.info"
#define aloe_aac_test_tlv() "aac.tlv"
#define aloe_aac_test_pcm() "aac.pcm"
#define aloe_aac_test_raw() "aac.raw"
#define aloe_aac_test_out() "aac-out.pcm"

typedef struct {
//	AVFormatContext *fmt_ctx;

    const AVCodec *codec;
    AVCodecContext *codec_ctx;
    AVCodecParserContext *parser;
    AVPacket *pkt;
	AVFrame *frm;

	SwrContext *swr_ctx;

	FILE *aufd, *ofd;
	void *aubuf;
	size_t aubuf_pos, aubuf_len;

	struct {
		size_t aubuf_prog; /**< current input buffer progress */
		size_t au_prog; /**< current input process progress */
		size_t samp_prog; /**< current sample progress */
	} stat;

} ffaac2_dec_t;

static int ffaac2_decode(ffaac2_dec_t *dec, void *ctx) {
	int res;
	char err_str[100];

	if ((res = avcodec_send_packet(dec->codec_ctx, dec->pkt)) < 0) {
		av_strerror(res, err_str, sizeof(err_str));
		log_e("err[%d]: %s\n", res, err_str);
		return res;
	}
	while (res >= 0) {
		int samp_sz;

		res = avcodec_receive_frame(dec->codec_ctx, dec->frm);
		if (res == AVERROR(EAGAIN) || res == AVERROR_EOF) {
			samp_sz = av_get_bytes_per_sample(dec->codec_ctx->sample_fmt);
			log_d("sample size: %d, channels: %d, input %ld/%ld"
					", samples: %ld(%d added)\n", samp_sz, dec->codec_ctx->channels,
					(long)dec->stat.au_prog, (long)dec->stat.aubuf_prog,
					(long)dec->stat.samp_prog, dec->frm->nb_samples);
			return 0;
		} else if (res < 0) {
			av_strerror(res, err_str, sizeof(err_str));
			log_e("err[%d]: %s\n", res, err_str);
			return res;
		}
		if ((samp_sz = av_get_bytes_per_sample(
				dec->codec_ctx->sample_fmt)) < 0) {
			log_e("get sample size\n");
			return -1;
		}
		dec->stat.samp_prog += dec->frm->nb_samples;
		log_d("sample size: %d, channels: %d, input %ld/%ld"
				", samples: %ld(%d added)\n", samp_sz, dec->codec_ctx->channels,
				(long)dec->stat.au_prog, (long)dec->stat.aubuf_prog,
				(long)dec->stat.samp_prog, dec->frm->nb_samples);
		if (dec->ofd) {
			int i, ch;

			for (i = 0; i < dec->frm->nb_samples; i++) {
				for (ch = 0; ch < dec->codec_ctx->channels; ch++) {
					fwrite(dec->frm->data[ch] + samp_sz * i, 1, samp_sz,
							dec->ofd);
				}
			}
		}
	}
	return res;
}

DECL_TEST(test1_ffaac2) {
#define AUBUF_SZ AU_MS2SZ(44100, 2, sizeof(float), 50)
#define AUBUF_THR (AUBUF_SZ / 2)

	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;
	ffaac2_dec_t *dec = NULL;

	if ((dec = (ffaac2_dec_t*)calloc(1, sizeof(*dec) + AUBUF_SZ +
			AV_INPUT_BUFFER_PADDING_SIZE)) == NULL) {
		log_e("ENOMEM\n");
		goto finally;
	}
	dec->aubuf = (void*)(dec + 1);

	if ((dec->pkt = av_packet_alloc()) == NULL) {
		log_e("alloc dec pkt\n");
		goto finally;
	}
    if ((dec->codec = avcodec_find_decoder(AV_CODEC_ID_AAC)) == NULL) {
    	log_e("Codec not find!\n");
		goto finally;
    }
    if ((dec->parser = av_parser_init(dec->codec->id)) == NULL) {
    	log_e("Parser not find!\n");
		goto finally;
    }
    if ((dec->codec_ctx = avcodec_alloc_context3(dec->codec)) == NULL) {
    	log_e("alloc codex\n");
		goto finally;
	}
    dec->codec_ctx->sample_rate = 44100;
    dec->codec_ctx->channels = 2;
    if (avcodec_open2(dec->codec_ctx, dec->codec, NULL) < 0) {
    	log_e("open codex\n");
		goto finally;
    }

	if ((dec->ofd = fopen(aloe_aac_test_out(), "wb")) == NULL) {
		log_e("open %s\n", aloe_aac_test_out());
		goto finally;
	}

	if ((dec->aufd = fopen(aloe_aac_test_raw(), "rb")) == NULL) {
		log_e("open %s\n", aloe_aac_test_raw());
		goto finally;
	}

	if ((dec->frm = av_frame_alloc()) == NULL) {
		log_e("alloc dec frm\n");
		goto finally;
	}

	dec->aubuf_pos = 0;
	dec->aubuf_len = fread(dec->aubuf, 1, AUBUF_SZ, dec->aufd);
	if (dec->aubuf_len < 0) {
		fclose((FILE*)dec->aufd);
		dec->aufd = NULL;
		log_d("eof\n");
	} else if (dec->aubuf_len > 0) {
		dec->stat.aubuf_prog += dec->aubuf_len;
		log_d("input %ld/%ld(%d added) bytes\n", (long)dec->stat.au_prog,
				(long)dec->stat.aubuf_prog, (int)dec->aubuf_len);
	}
	while (dec->aubuf_len > 0) {
		int psz;
        if ((psz = av_parser_parse2(dec->parser, dec->codec_ctx,
				&dec->pkt->data, &dec->pkt->size,
				(uint8_t*)dec->aubuf + dec->aubuf_pos, dec->aubuf_len,
				AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0)) < 0) {
        	log_e("parse aac\n");
			goto finally;
		}
		dec->aubuf_pos += psz;
		dec->aubuf_len -= psz;
		dec->stat.au_prog += psz;
		if (dec->pkt->size && (ffaac2_decode(dec, NULL)) < 0) {
			log_e("decode aac\n");
			goto finally;
		}
		if ((dec->aubuf_len < AUBUF_THR) && dec->aufd) {
			if (dec->aubuf_len < 0) {
				dec->aubuf_len = 0;
			} else if (dec->aubuf_len > 0) {
				memmove(dec->aubuf, (char*)dec->aubuf + dec->aubuf_pos,
						dec->aubuf_len);
			}
			dec->aubuf_pos = 0;
			psz = fread((char*)dec->aubuf + dec->aubuf_len, 1,
					AUBUF_SZ - dec->aubuf_len, dec->aufd);
			if (psz < 0) {
				fclose((FILE*)dec->aufd);
				dec->aufd = NULL;
				log_d("eof\n");
			} else if (psz > 0) {
				dec->aubuf_len += psz;
				dec->stat.aubuf_prog += psz;
				log_d("input %ld/%ld(%d added) bytes\n", (long)dec->stat.au_prog,
						(long)dec->stat.aubuf_prog, psz);
			}
		}
	}
	dec->pkt->data = NULL; dec->pkt->size = 0;
	ffaac2_decode(dec, NULL);

	log_d("channels: %d, sample rate: %d, sample format: %s\n",
			dec->codec_ctx->channels, dec->codec_ctx->sample_rate,
			av_get_sample_fmt_name(dec->codec_ctx->sample_fmt));


	ALOE_TEST_ASSERT_THEN(0,
			test_case, failed, {
		goto finally;
	});

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (dec->aufd) fclose((FILE*)dec->aufd);
	if (dec->ofd) fclose((FILE*)dec->ofd);
	if (dec->codec_ctx) avcodec_free_context(&dec->codec_ctx);
	if (dec->parser) av_parser_close(dec->parser);
	if (dec->swr_ctx) swr_free(&dec->swr_ctx);
	if (dec->frm) av_frame_free(&dec->frm);
	if (dec->pkt) av_packet_free(&dec->pkt);

	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	return test_case->flag_result;
}

typedef struct __attribute__((packed)) {
	int16_t type, len;
	uint8_t cksum;
	uint8_t padding[3];
} aloe_aac_test_tlv_t;

DECL_TEST(test1_ffaac1) {
//#define ffaac1_cksum 1
//#define ffaac1_genraw 1

#if 1
#define testaac_open air192_ffaac_open_lc
#define testaac_close air192_ffaac_close
#define testaac_decode air192_ffaac_decode
#else
#define testaac_open air192_fdkaac_open_lc
#define testaac_close air192_fdkaac_close
#define testaac_decode air192_fdkaac_decode
#endif

	aloe_buf_t buf = {0}, pcm = {0};
	cJSON *jroot = NULL;
	void *dec = NULL;
	int r, fsz = aloe_file_size(aloe_aac_test_tlv(), 0);
	const aloe_aac_test_tlv_t *tlv;

	unlink(aloe_aac_test_out());

	ALOE_TEST_ASSERT_THEN(
			(aloe_buf_expand(&buf, fsz + 1, aloe_buf_flag_none) == 0)
			&& (aloe_buf_expand(&pcm, AU_MS2SZ(44100, 2, sizeof(float), 200) + 1, aloe_buf_flag_none) == 0)
			&& (aloe_file_fread(aloe_aac_test_tlv(), aloe_buf_clear(&buf)) == fsz),
			test_case, failed, {
		goto finally;
	});
	aloe_buf_flip(&buf);

	ALOE_TEST_ASSERT_THEN((dec = testaac_open(44100, 2, 50)),
			test_case, failed, {
		goto finally;
	});

	for (tlv = (aloe_aac_test_tlv_t*)((char*)buf.data + buf.pos); ;
			buf.pos += sizeof(*tlv) + tlv->len,
					tlv = (aloe_aac_test_tlv_t*)((char*)buf.data + buf.pos)) {
#ifdef ffaac1_cksum
		typeof(aloe_memberof(aloe_aac_test_tlv_t, cksum)) cksum = 0;
#endif
		if (buf.pos >= buf.lmt) {
			log_d("input process done\n");
			break;
		}
		ALOE_TEST_ASSERT_THEN(((buf.lmt - buf.pos >= sizeof(*tlv))
				&& (buf.lmt - buf.pos >= sizeof(*tlv) + tlv->len)),
				test_case, failed, {
			goto finally;
		});
#ifdef ffaac1_cksum
		cksum = aloe_cksum(tlv, aloe_offsetof(aloe_aac_test_tlv_t, cksum))
				+ aloe_cksum(tlv + 1, tlv->len);
		if (tlv->len == 6) {
			unsigned char *s = (unsigned char*)(tlv + 1);
			log_d("[0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x]\n",
					s[0], s[1], s[2], s[3], s[4], s[5]);
		}
		ALOE_TEST_ASSERT_THEN((cksum == tlv->cksum),
				test_case, failed, {
			goto finally;
		});
#endif

#ifdef ffaac1_genraw
        {
        	aloe_buf_t buf = {.data = (void*)(tlv + 1),
        			.cap = (size_t)tlv->len, .lmt = (size_t)tlv->len};

//			cannot use compound literal in c++
//        	r = aloe_file_write(aloe_aac_test_raw(), "a", &(const aloe_buf_t){
//        		(void*)(tlv + 1), (size_t)tlv->len, (size_t)tlv->len, 0});

        	r = aloe_file_write(aloe_aac_test_raw(), "a", &buf);
        }
#endif

#if 1
		aloe_buf_clear(&pcm);
		if ((r = testaac_decode(dec, tlv + 1, tlv->len,
				(char*)pcm.data + pcm.pos, pcm.lmt - pcm.pos, 1)) < 0) {
			log_e("decode\n");
			break;
		}
		if (r == 0) {
			log_d("decode none\n");
			continue;
		}
		pcm.pos += r;
        aloe_file_write(aloe_aac_test_out(), "a", aloe_buf_flip(&pcm));
#endif
	}


	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (dec) testaac_close(dec);
	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	if (pcm.data) free(pcm.data);
	return test_case->flag_result;
}

#pragma GCC diagnostic pop // ignored "-Wdeprecated-declarations"

DECL_TEST(test1_net1) {
	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;
	struct sockaddr_in sin;
	uint32_t u32;
	int i;

	i = aloe_eth_linkup("eth");
	log_d("check eth link up: %s\n",
			((i > 0) ? "Yes" :
			(i == 0) ? "No" :
			"Unknown"));

	ALOE_TEST_ASSERT_THEN(aloe_get_ifaddr("wlan", &sin, 1) == 1,
			test_case, failed, {
		goto finally;
	});

	u32 = ntohl(sin.sin_addr.s_addr);
	// ipaddr: 192, 168, 50, 59
	log_d("ipaddr: %d, %d, %d, %d\n", (u32 >> 24) & 0xff, (u32 >> 16) & 0xff,
			(u32 >> 8) & 0xff, u32 & 0xff);

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	return test_case->flag_result;
}

DECL_TEST(test1_ini1) {
	int r, ini_idx, refact;
	const char *test_ini1[] = {
		"ini_idx=0 expect no",
		"ini_idx=1 expect ok"
			"\ntgt=  value leader space",
		"ini_idx=2 expect ok"
			"\n  tgt  =key around space",
		"ini_idx=3 expect no"
			"\n # tgt  =comment",
		"ini_idx=4 expect ok"
			"\ntgt",
		"ini_idx=5 expect no"
			"\ntgt tgt =spaced key",
		NULL
	}, **ini;

	for (ini = test_ini1, ini_idx = 0; *ini; ini++, ini_idx++) {
		size_t tgt_len;
		const char *tgt = aloe_ini_find(*ini, strlen(*ini), "tgt", &tgt_len);
		char tgt_val[500];

		if (!tgt) {
			log_d("ini[%d] miss tgt\n", ini_idx);
			continue;
		}
		if (tgt_len >= sizeof(tgt_val)) {
			log_e("too large tgt %d > %d\n", (int)tgt_len, (int)sizeof(tgt_val));
			continue;
		}
		memcpy(tgt_val, tgt, tgt_len);
		tgt_val[tgt_len] = '\0';
		log_d("ini[%d] tgt: %s len: %d\n", ini_idx, tgt_val, (int)tgt_len);
	}

	if ((r = air192_refact_num(&refact)) != 0) {
		log_d("no refact\n");
	} else {
		log_d("refact: %d\n", refact);
	}

	test_case->flag_result = aloe_test_flag_result_pass;
//finally:
	return test_case->flag_result;
}

DECL_TEST(test1_str1) {
	const char *sep = " \t", *c;
	char buf[] = "abc\0def \tghz";
	char hname[] = "Eve Play #3CC7";
	char buf_out[200];
	int r;

	air192_stacktrace1(-1);

	{
		const char *msg=" abcdef \n line2";
		char result_ssid[512] = {0};

		log_d("0x%x, 0x%x\n",
				(unsigned)(unsigned long)&result_ssid,
				(unsigned)(unsigned long)result_ssid);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
/*
warning: format ‘%[^
   ’ expects argument of type ‘char*’, but argument 3 has type ‘char (*)[512]’ [-Wformat=]
  860 |             sscanf(msg, "%32[^\n]", &result_ssid);
      |                          ~~~~~^~    ~~~~~~~~~~~~
      |                               |     |
      |                               char* char (*)[512]
 */
	    sscanf(msg, "%32[^\n]", &result_ssid);
#pragma GCC diagnostic pop

	    log_d("result_ssid: %s\n", result_ssid);

	    sscanf(msg, "%32[^\n]", result_ssid);
	    log_d("result_ssid: %s\n", result_ssid);
	}


	// The terminating null byte is considered part of the string,
	// strchr return a pointer to the terminator
	ALOE_TEST_ASSERT_THEN((c = strchr(sep, '\0')) && *c == '\0',
			test_case, failed, {
		goto finally;
	});

	ALOE_TEST_ASSERT_THEN(sizeof(buf) == 13,
			test_case, failed, {
		goto finally;
	});

	// match '\0' only
	ALOE_TEST_ASSERT_THEN(((r = _aloe_tr(buf, sizeof(buf) - 1,
			"", -1, NULL)) == 11)
			&& ((r = _aloe_tr(buf, sizeof(buf) - 1,
			"", -1, buf_out)) == 11)
			&& strncmp(buf_out, "abcdef \tghz", r) == 0,
			test_case, failed, {
		log_e("r: %d\n", r);
		goto finally;
	});
	log_d("buf_out: %s\n", buf_out);

	// convert ws to '_'
	ALOE_TEST_ASSERT_THEN(((r = _aloe_tr(buf, sizeof(buf) - 1,
			" \t", '_', NULL)) == 11)
			&& ((r = _aloe_tr(buf, sizeof(buf) - 1,
			" \t", '_', buf_out)) == 11)
			&& strncmp(buf_out, "abc_def_ghz", r) == 0,
			test_case, failed, {
		log_e("r: %d\n", r);
		goto finally;
	});
	log_d("buf_out: %s\n", buf_out);

	ALOE_TEST_ASSERT_THEN(((r = air192_hostname_refine(hname, sizeof(hname) - 1,
			-1, NULL)) == 11)
			&& ((r = air192_hostname_refine(hname, sizeof(hname) - 1,
			-1, buf_out)) == 11)
			&& strncmp(buf_out, "EvePlay3CC7", r) == 0,
			test_case, failed, {
		log_e("r: %d\n", r);
		goto finally;
	});
	log_d("buf_out: %s\n", buf_out);

	ALOE_TEST_ASSERT_THEN(((r = air192_hostname_refine(hname, sizeof(hname) - 1,
			'_', NULL)) == 13)
			&& ((r = air192_hostname_refine(hname, sizeof(hname) - 1,
			'_', buf_out)) == 13)
			&& strncmp(buf_out, "Eve_Play_3CC7", r) == 0,
			test_case, failed, {
		log_e("r: %d\n", r);
		goto finally;
	});
	log_d("buf_out: %s\n", buf_out);

	{
		char msg[] = "a b c d e  \r\n\t  "; // 7 ws
		char msg2[] = "ca_get_version\r\n"; // 2 ws
		char msg3[] = "ca_get_version"; // 0 ws
		const char *ws = " \r\n\t";


		log_d("len ws = %d\n", (int)aloe_strip_end2(msg, (size_t)-1, ws));
		log_d("len ws = %d\n", (int)aloe_strip_end2(msg, strlen(msg), ws));
		log_d("len ws = %d\n", (int)aloe_strip_end2(msg2, strlen(msg2), ws));
		log_d("len ws = %d\n", (int)aloe_strip_end2(msg3, strlen(msg3), ws));
	}

	if (impl.ondevice) {
		aloe_buf_t fb;

		fb.data = buf_out;
		fb.cap = sizeof(buf_out);

		ALOE_TEST_ASSERT_THEN((r = air192_bdname(aloe_buf_clear(&fb))) <= 0
				|| fb.pos <= 4,
				test_case, failed, {
			log_e("Failed to get bdname\n");
		});
		log_d("bdname: %s, len: %d\n", (char*)fb.data, (int)fb.pos);

		ALOE_TEST_ASSERT_THEN((r = air192_wac_name(aloe_buf_clear(&fb))) > 0,
				test_case, failed, {
			goto finally;
		});
		aloe_buf_flip(&fb);
		log_d("wac name: %s, len: %d\n", (char*)fb.data + fb.pos, r);

		fb.data = buf_out;
		fb.cap = sizeof(buf_out);
		ALOE_TEST_ASSERT_THEN((r = air192_serial_number(aloe_buf_clear(&fb))) > 0
				&& fb.pos == (size_t)r,
				test_case, failed, {
			goto finally;
		});
		aloe_buf_flip(&fb);
		log_d("serialnum: %s, len: %d\n", (char*)fb.data + fb.pos, r);
	}

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	return test_case->flag_result;
}

static struct {
	struct {
		SwrContext *ctx;
		enum AVSampleFormat aout_fmt;
		AVChannelLayout channel;
		uint32_t sample_rate;
	} swr;
	struct {
		uint32_t mSampleRate;
	} format;
} swres1 = {};

DECL_TEST(test1_swres1) {
#define kUnsupportedErr -1
	int r, err;
	char errstr[100];
	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;
	typeof(swres1) *me = &swres1;
	const char *in_fn = "/home/joelai/Downloads/aac.pcm";
	const char *out_fn = "/home/joelai/Downloads/aac48k.pcm";
	int in_fd = -1, out_fd = -1, rdlen;
	char in_buf[1024 * (2 * 16 / 8)], out_buf[sizeof(in_buf) * 2];

	(void)err;

	me->format.mSampleRate = 44100;
	if (me->swr.ctx == NULL
			|| me->swr.sample_rate != me->format.mSampleRate) {
		me->swr.channel = (AVChannelLayout)AV_CHANNEL_LAYOUT_STEREO;
		me->swr.aout_fmt = AV_SAMPLE_FMT_S16; // also be dec out format
		me->swr.sample_rate = me->format.mSampleRate;

		if ((r = swr_alloc_set_opts2(&me->swr.ctx,
				&me->swr.channel, me->swr.aout_fmt, 48000,
				&me->swr.channel, me->swr.aout_fmt, me->swr.sample_rate,
				0, NULL)) < 0) {
			av_strerror(r, errstr, sizeof(errstr));
			air192_d2("alloc swr failed, %s\n", errstr);
			err = kUnsupportedErr;
//			if (me->swr.ctx) swr_free(&me->swr.ctx);
//			memset(&me->swr, 0, sizeof(me->swr));
			goto exit;
		}
		if ((r = swr_init(me->swr.ctx)) < 0) {
			av_strerror(r, errstr, sizeof(errstr));
			air192_d2("init swr failed, %s\n", errstr);
			err = kUnsupportedErr;
//			if (me->swr.ctx) swr_free(&me->swr.ctx);
//			memset(&me->swr, 0, sizeof(me->swr));
			goto exit;
		}
	}

	if ((in_fd = open(in_fn, O_RDONLY)) == -1) {
		air192_d2("openfile: %s\n", strerror(errno));
		goto exit;
	}
	if ((out_fd = open(out_fn, O_WRONLY | O_CREAT | O_TRUNC, 0664)) == -1) {
		air192_d2("openfile: %s\n", strerror(errno));
		goto exit;
	}

	while ((rdlen = read(in_fd, in_buf, sizeof(in_buf))) == sizeof(in_buf)) {
		int in_samp = rdlen / (2 * 16 / 8);
		int dly = swr_get_delay(me->swr.ctx, me->swr.sample_rate);
		int out_samp = av_rescale_rnd(dly + in_samp, 48000,
				me->swr.sample_rate, AV_ROUND_UP);
		uint8_t *out_frm[AV_NUM_DATA_POINTERS], *in_frm[AV_NUM_DATA_POINTERS];

		log_d("samp %d -> %d, (dly: %d)\n", in_samp, out_samp, dly);

		r = av_samples_fill_arrays(out_frm, NULL, NULL,
				2, out_samp, me->swr.aout_fmt, 0);
		if ((size_t)r >= sizeof(out_buf)) {
			air192_d2("output buffer too small\n");
			goto exit;
		}
		av_samples_fill_arrays(out_frm, NULL, (uint8_t*)out_buf,
				2, out_samp, me->swr.aout_fmt, 0);
		av_samples_fill_arrays(in_frm, NULL, (uint8_t*)in_buf,
				2, in_samp, me->swr.aout_fmt, 0);
	    if ((r = swr_convert(me->swr.ctx, out_frm, out_samp,
	    		(const uint8_t**)in_frm, in_samp)) < 0) {
			log_e("failed convert to output\n");
			goto exit;
	    }
	    out_samp = r;
	    write(out_fd, out_buf, out_samp * 2 * 16 / 8);
	}

	ALOE_TEST_ASSERT_THEN(0,
			test_case, failed, {
		goto finally;
	});
	test_case->flag_result = aloe_test_flag_result_pass;
finally:
exit:
	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	if (me->swr.ctx) swr_free(&me->swr.ctx);
	if (in_fd != -1) close(in_fd);
	if (out_fd != -1) close(out_fd);
	return test_case->flag_result;
}

static int rdbytes(int fd, void *buf, size_t sz) {
	int r;

	if (fd == -1 || !buf || sz <= 0) {
		r = EINVAL;
		log_e("%s\n", strerror(r));
		goto finally;
	}
	while (1) {
		if ((r = read(fd, buf, sz)) < 0) {
			r = errno;
			log_e("read fd, %s\n", strerror(r));
			goto finally;
		}
		if (r == 0) {
			r = EIO;
			log_e("read fd, EOF\n");
			goto finally;
		}
		if ((size_t)r >= sz) break;
		buf = (char*)buf + r;
		sz -= r;
	}
	r = 0;
finally:
	return r;
}

static int wrbytes(int fd, const void *buf, size_t sz) {
	int r;

	if (fd == -1 || !buf || sz <= 0) {
		r = EINVAL;
		log_e("%s\n", strerror(r));
		goto finally;
	}
	while (1) {
		if ((r = write(fd, buf, sz)) < 0) {
			r = errno;
			log_e("write fd, %s\n", strerror(r));
			goto finally;
		}
		if (r == 0) {
			r = EIO;
			log_e("write fd, EOF\n");
			goto finally;
		}
		if ((size_t)r >= sz) break;
		buf = (char*)buf + r;
		sz -= r;
	}
	r = 0;
finally:
	return r;
}


DECL_TEST(test1_ftrim1) {
#define gc_fd(_fd) if (_fd != -1) { close(_fd); (_fd) = -1; }

	int r, fd = -1;
	const char *cfg = NULL;
	aloe_buf_t fb = {}, mm = {};
	size_t cap = 400 * 1048576;
	struct stat fst;
	void *mm_addr = NULL;

	if (!(fb.data = malloc(fb.cap = cap * 2))) {
		r = ENOMEM;
		log_e("alloc %zdMB\n", cap * 2 / 1048576);
		goto finally;
	}

	cfg = "/dev/urandom";
	if ((fd = open(cfg, O_RDONLY, 0660)) == -1) {
		r = errno;
		log_e("open %s, %s\n", cfg, strerror(r));
		goto finally;
	}
	if ((r = rdbytes(fd, fb.data, cap)) != 0) {
		log_e("read random\n");
		goto finally;
	}
	gc_fd(fd);

	cfg = "abc";
	if ((fd = open(cfg, O_RDWR | O_CREAT | O_TRUNC, 0660)) == -1) {
		r = errno;
		log_e("open fn %s, %s\n", cfg, strerror(r));
		goto finally;
	}
	if ((r = wrbytes(fd, fb.data, cap)) != 0) {
		log_e("write random\n");
		goto finally;
	}
	gc_fd(fd);

	if ((fd = open(cfg, O_RDWR, "0660")) == -1) {
		r = errno;
		log_e("open fn %s, %s\n", cfg, strerror(r));
		goto finally;
	}
	memset(&mm, 0, sizeof(mm));
	if (!(mm.data = aloe_mmapfile(fd, &mm_addr, &mm.pos, &mm.cap))) {
		r = EIO;
		log_e("Failed mmap\n");
		goto finally;
	}

	if (mm.pos != 0 || mm.cap != cap) {
		log_e("Sanity check expect offset 0 and size %zd but got offset %zd size %zd\n",
				cap, mm.pos, mm.cap);
	}

	log_d("mmap offset %zd, len %zd\n", mm.pos, mm.cap);

	// trim head - data
	memmove(mm.data, (char*)mm.data + 288, cap - 288);
	if ((r = munmap(mm_addr, mm.cap)) != 0) {
		r = errno;
		log_e("Failed munmap %s\n", strerror(r));
		goto finally;
	}
	mm_addr = NULL;

	// trim tail - file
	if ((r = ftruncate(fd, cap - 288)) != 0) {
		r = errno;
		log_e("Failed ftruncate %s\n", strerror(r));
		goto finally;
	}
	gc_fd(fd);

    if ((r = stat(cfg, &fst)) != 0) {
		r = errno;
		log_e("file stat, %s\n", strerror(r));
		goto finally;
    }
    if ((size_t)fst.st_size != cap - 288) {
    	r = EIO;
    	log_e("expected size %zd but got %zd\n", cap, (size_t)fst.st_size);
    	goto finally;
    }

	if ((fd = open(cfg, O_RDWR, "0660")) == -1) {
		r = errno;
		log_e("open fn %s, %s\n", cfg, strerror(r));
		goto finally;
	}
	if ((r = rdbytes(fd, (char*)fb.data + cap, cap - 288)) != 0) {
		log_e("read random\n");
		goto finally;
	}
	if (memcmp((char*)fb.data + 288, (char*)fb.data + cap, cap - 288) != 0) {
		r = EIO;
		log_e("compare error\n");
		goto finally;
	}
	log_d("compare done\n");
	gc_fd(fd);
finally:
	if (fb.data) free(fb.data);
	if (mm_addr && (munmap(mm_addr, mm.cap)) != 0) {
		int eno = errno;
		log_e("Failed munmap %s\n", strerror(eno));
	}
	gc_fd(fd);
	if (r != 0) {
		test_case->flag_result = aloe_test_flag_result_failed_suite;
	} else {
		test_case->flag_result = aloe_test_flag_result_pass;
	}
	return test_case->flag_result;
#undef gc_fd
}

DECL_TEST(test1_cfgstr1) {
	int r;
	const char* if_name = "eth0";
	const char *cfg = NULL;
	air192_ipsetup_t ipsetup;
	char cmd[100];

	if (cfg == NULL) {
		if (strncasecmp(if_name, "eth", strlen("eth")) == 0) {
			cfg = eth_cfg;
		} else if (strncasecmp(if_name, "wlan", strlen("wlan")) == 0) {
			cfg = wlan_cfg;
		} else {
			cfg = wlan_cfg;
		}
	}

	r = air192_parse_ipsetup(cfg, &ipsetup);

	if ((ipsetup.parse_eno != 0)
			|| (ipsetup.ipmode & air192_ipmode_dhcp)
			|| (ipsetup.ipmode & air192_ipmode_auto)) {
		log_d("ipsetup result is DHCP\n");
	} else if ((ipsetup.ipmode & air192_ipmode_zcip)) {
		log_d("ipsetup result is ZCIP\n");
	} else if (ipsetup.ip[0]) {
		log_d("ipsetup result ip: %s, msk: %s, gw: %s, dns: %s\n",
				ipsetup.ip, ipsetup.msk, ipsetup.gw, ipsetup.dns);

		system("killall -9 udhcpc");
		system("killall -9 zcip");

		snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s%s", if_name, ipsetup.ip,
				(ipsetup.msk[0] ? "netmask " : ""),
				(ipsetup.msk[0] ? ipsetup.msk : ""));
		log_d("cmd: %s\n", cmd);
		if ((r = system(cmd)) != 0) {
			log_e("[%s] %s ret =  %d", __FUNCTION__, cmd, r);
			goto finally;
		}

		if (ipsetup.gw[0]) {
			snprintf(cmd, sizeof(cmd), "route add default gw %s dev %s",
					ipsetup.gw, if_name);
			log_d("cmd: %s\n", cmd);
			if ((r = system(cmd)) != 0) {
				log_e("[%s] %s ret =  %d", __FUNCTION__, cmd, r);
				goto finally;
			}
		}

		if (ipsetup.dns[0]) {
			snprintf(cmd, sizeof(cmd), "rm -rf %s", resolv_cfg);
			log_d("cmd: %s\n", cmd);
			if ((r = system(cmd)) != 0) {
				log_e("[%s] %s ret =  %d", __FUNCTION__, cmd, r);
				goto finally;
			}

			snprintf(cmd, sizeof(cmd), "/etc/init.d/func_test add_resolv_dns %s %s",
					resolv_cfg, ipsetup.dns);
			log_d("cmd: %s\n", cmd);
			if ((r = system(cmd)) != 0) {
				log_e("[%s] %s ret =  %d", __FUNCTION__, cmd, r);
				goto finally;
			}
		}
	}

finally:
	if (r != 0) {
		test_case->flag_result = aloe_test_flag_result_failed_suite;
	} else {
		test_case->flag_result = aloe_test_flag_result_pass;
	}
	return test_case->flag_result;
}

static int test_reporter(unsigned lvl, const char *tag, long lno,
		const char *fmt, ...) {
	va_list va;

	printf("%s #%d ", tag, (int)lno);
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
	return 0;
}

static const char opt_short[] = "hv";
enum {
	opt_key_ondevice = 0x201,
};
static struct option opt_long[] = {
	{"help", no_argument, NULL, 'h'},
	{"verbose", no_argument, NULL, 'v'},
	{"ondevice", no_argument, NULL, opt_key_ondevice},
};

static int show_help(const char *fn) {
	fprintf(stdout, ""
"USAGE\n"
"  %s [OPTIONS]\n"
"\n"
"OPTIONS\n"
"  -h, --help     Show this help\n"
"  -v, --verbose  More output\n"
"  --ondevice     Run on sa7715\n"
"\n",
(fn ? fn : "PROG"));
	return 0;
}

int main(int argc, char **argv) {
	int opt_op, opt_idx;
	aloe_test_t test_base;
	aloe_test_report_t test_report;

	for (int i = 0; i < argc; i++) {
		log_d("argv[%d/%d]: %s\n", i + 1, argc, argv[i]);
	}

	optind = 0;
	while ((opt_op = getopt_long(argc, argv, opt_short, opt_long,
			&opt_idx)) != -1) {
		if (opt_op == 'h') {
			show_help(argv[0]);
			continue;
		}
		if (opt_op == 'v') {
			continue;
		}
		if (opt_op == opt_key_ondevice) {
			impl.ondevice = 1;
			continue;
		}
	}

	for (opt_idx = optind; opt_idx < argc; opt_idx++) {
		log_d("argv[%d/%d]: %s\n", opt_idx + 1, argc, argv[opt_idx]);
	}

	if (!impl.ondevice && aloe_file_size("/etc/sa7715.json", 0) >= 0) {
		impl.ondevice = 1;
	}

	ALOE_TEST_INIT(&test_base, "Test1");
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/cjson1", &test1_jcfg1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ledconf1", &test1_ledconf1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/mqcli1", &test1_mqcli1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/wpacli1", &test1_wpacli1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/wpacli1", &test1_wpacfg1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/offsetof1", &test1_offsetof1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ffaac1", &test1_ffaac1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ffaac1", &test1_ffaac2);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/net1", &test1_net1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ini1", &test1_ini1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/str1", &test1_str1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/swres1", &test1_swres1);
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/str1", &test1_cfgstr1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ftrim1", &test1_ftrim1);

	ALOE_TEST_RUN(&test_base);

	memset(&test_report, 0, sizeof(test_report));
	test_report.log = &test_reporter;
	aloe_test_report(&test_base, &test_report);

	printf("Report result %s, test suite[%s]"
			"\n  Summary total cases PASS: %d, FAILED: %d(PREREQUISITE: %d), TOTAL: %d\n",
			ALOE_TEST_RESULT_STR(test_base.runner.flag_result, "UNKNOWN"),
			test_base.runner.name,
			test_report.pass, test_report.failed,
			test_report.failed_prereq, test_report.total);

	return 0;
}

DECL_TEST(test1_template1) {
	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;

	ALOE_TEST_ASSERT_THEN(0,
			test_case, failed, {
		goto finally;
	});
	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	return test_case->flag_result;
}
