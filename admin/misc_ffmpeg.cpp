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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "priv.h"

#define AU_MS2SZ(_rate, _ch, _samp, _ms) ( \
		(_rate) * (_ch) * (_samp) * (_ms) / 1000)

#define AU_FOUT(_aout, _asz) ((_asz) == (size_t)-2 ? _aout : NULL)

#if LIBAVUTIL_VERSION_MAJOR >= 57
#define FF_CH_LAYOUT
#else
#endif

typedef struct {
//	AVFormatContext *fmt_ctx;

	const AVCodec *codec;
	AVCodecContext *codec_ctx;
	AVCodecParserContext *parser;
	AVPacket *pkt;
	AVFrame *frm;
	SwrContext *swr;
	enum AVSampleFormat aout_fmt;
	uint8_t *aout_frm[8];
	aloe_buf_t buf;

} dec_t;

// https://wiki.multimedia.cx/index.php?title=MPEG-4_Audio#Audio_Specific_Config
static unsigned asc_aot_aac_lc = 2;
static const unsigned asc_freq_lut[] = {96000, 88200, 64000, 48000, 44100,
		32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350};

static unsigned asc_ch_lut[] = {0, 1, 2};

static int decode(dec_t *dec, void *aout, size_t asz, unsigned flag) {
	int res, sz;
	char err_str[100];

	if ((res = avcodec_send_packet(dec->codec_ctx, dec->pkt)) < 0) {
		av_strerror(res, err_str, sizeof(err_str));
		log_e("failed send to decode, %s\n", err_str);
//		return res;
		return 0;
	}
	sz = 0;
	while (res >= 0) {
		res = avcodec_receive_frame(dec->codec_ctx, dec->frm);
		if (res == AVERROR(EAGAIN)) {
			log_d("more data requisite\n");
			return sz;
		}
		if (res == AVERROR_EOF) {
//			log_d("more data requisite\n");
			return sz;
		}
		if (res < 0) {
			av_strerror(res, err_str, sizeof(err_str));
			log_e("failed fetch decode data, %s\n", err_str);
			if (sz > 0) return sz;
			return -1;
		}

		if (dec->codec_ctx->channels > (int)aloe_arraysize(dec->aout_frm)
				|| av_samples_fill_arrays(dec->aout_frm, NULL, NULL,
						dec->codec_ctx->channels, dec->frm->nb_samples,
						dec->aout_fmt, 0) > (int)asz) {
			log_e("output buffer too small\n");
			return sz;
		}
		av_samples_fill_arrays(dec->aout_frm, NULL, (uint8_t*)aout,
				dec->codec_ctx->channels, dec->frm->nb_samples, dec->aout_fmt,
				0);
	    if ((res = swr_convert(dec->swr, dec->aout_frm, dec->frm->nb_samples,
	    		(const uint8_t**)dec->frm->extended_data,
				dec->frm->nb_samples)) < 0) {
			log_e("failed convert to output\n");
			return sz;
	    }
	    sz += res * dec->codec_ctx->channels
	    		* av_get_bytes_per_sample(dec->aout_fmt);

		if (flag) break;
	}
	return sz;
}

extern "C"
void air192_ffaac_close(void *_dec) {
	dec_t *dec = (dec_t*)_dec;

	if (dec) {
		if (dec->frm && dec->pkt && dec->codec_ctx) {
			dec->pkt->data = NULL; dec->pkt->size = 0;
			decode(dec, NULL, 0, 0);
		}
		if (dec->codec_ctx) avcodec_free_context(&dec->codec_ctx);
		if (dec->parser) av_parser_close(dec->parser);
		if (dec->swr) swr_free(&dec->swr);
		if (dec->frm) av_frame_free(&dec->frm);
		if (dec->pkt) av_packet_free(&dec->pkt);
		free(dec);
	}
}

extern "C"
void* air192_ffaac_open_lc(int rate, int channel, long buf_ms) {
	dec_t *dec = NULL;
	int r, aubuf_sz = AU_MS2SZ(44100, 2, sizeof(float), 50);
	unsigned char asc[2];
	unsigned asc_aot = asc_aot_aac_lc, asc_freq, asc_ch;
	char errstr[100];

	for (r = 0; r < (int)aloe_arraysize(asc_freq_lut); r++) {
		if ((int)asc_freq_lut[r] == rate) break;
	}
	if (r >= (int)aloe_arraysize(asc_freq_lut)) {
		r = EINVAL;
		log_e("Invalid rate\n");
		goto finally;
	}
	asc_freq = (unsigned)r;

	for (r = 0; r < (int)aloe_arraysize(asc_ch_lut); r++) {
		if ((int)asc_ch_lut[r] == channel) break;
	}
	if (r >= (int)aloe_arraysize(asc_ch_lut)) {
		r = EINVAL;
		log_e("Invalid channel\n");
		goto finally;
	}
	asc_ch = (unsigned)r;

	if ((dec = (dec_t*)malloc(sizeof(*dec)
			+ aubuf_sz + AV_INPUT_BUFFER_PADDING_SIZE)) == NULL) {
		r = ENOMEM;
		log_e("alloc dec\n");
		goto finally;
	}
	memset(dec, 0, sizeof(*dec));
	dec->buf.data = (void*)(dec + 1);
	dec->buf.cap = aubuf_sz; // imply trailing AV_INPUT_BUFFER_PADDING_SIZE

	do {
		const char *dec_lut[] = {"aac_fixed", NULL}, **dec_name;
		for (dec_name = dec_lut; *dec_name; dec_name++) {
			if ((dec->codec = avcodec_find_decoder_by_name(*dec_name))) break;
		}
		if (!dec->codec) dec->codec = avcodec_find_decoder(AV_CODEC_ID_AAC);
	} while(0);

	if (!dec->codec) {
		r = EIO;
		log_e("unknown aac\n");
		goto finally;
	}
#if 0
	if ((dec->parser = av_parser_init(dec->codec->id)) == NULL) {
		r = EIO;
		log_e("alloc parser\n");
		goto finally;
	}
#endif
	if ((dec->codec_ctx = avcodec_alloc_context3(dec->codec)) == NULL) {
		r = EIO;
		log_e("alloc aac decoder ctx\n");
		goto finally;
	}

	dec->codec_ctx->sample_rate = rate;
	dec->codec_ctx->channels = channel;
	dec->codec_ctx->channel_layout = AV_CH_LAYOUT_STEREO;

#if 1
	/*
	 * Audio Specific Config:
	 * 5 bits for object type
	 * 4 bits for sampling rate
	 * 4 bits for channel
	 * 1 bit for frame length flag: 0=1024 sample or 1=960 sample
	 * 1 bit for depends on core coder
	 * 1 bit for extension flag
	 */
	asc[0] = (asc_aot << 3) | ((asc_freq & 0x0E) >> 1);
	asc[1] = ((asc_freq & 0x01) << 7) | ((asc_ch & 0x0F) << 3);

	if (!(dec->codec_ctx->extradata = (uint8_t*)av_malloc(sizeof(asc)
			+ AV_INPUT_BUFFER_PADDING_SIZE))) {
		r = ENOMEM;
		log_e("alloc for aac asc\n");
		goto finally;
	}
	memcpy(dec->codec_ctx->extradata, asc,
			dec->codec_ctx->extradata_size = sizeof(asc));
#endif
	if (avcodec_open2(dec->codec_ctx, dec->codec, NULL) < 0) {
		r = EIO;
		log_e("open aac decoder");
		goto finally;
	}

	if ((r = swr_alloc_set_opts2(&dec->swr,
			&dec->codec_ctx->ch_layout, dec->aout_fmt = AV_SAMPLE_FMT_S16,
			dec->codec_ctx->sample_rate,
			&dec->codec_ctx->ch_layout, dec->codec_ctx->sample_fmt,
			dec->codec_ctx->sample_rate,
			0, NULL)) < 0) {
		av_strerror(r, errstr, sizeof(errstr));
		log_e("alloc swr failed, %s\n", errstr);
		goto finally;
	}

	if ((r = swr_init(dec->swr)) < 0) {
		av_strerror(r, errstr, sizeof(errstr));
		log_e("init swr failed, %s\n", errstr);
		goto finally;
	}

	if ((dec->pkt = av_packet_alloc()) == NULL) {
		r = ENOMEM;
		log_e("alloc dec\n");
		goto finally;
	}
	if ((dec->frm = av_frame_alloc()) == NULL) {
		log_e("alloc dec frm\n");
		goto finally;
	}
	aloe_buf_clear(&dec->buf);
	r = 0;
finally:
	if (r != 0) {
		if (dec) air192_ffaac_close(dec);
		return NULL;
	}
	return dec;
}

extern "C"
int air192_ffaac_reset(void *_dec) {
	dec_t *dec = (dec_t*)_dec;

	avcodec_flush_buffers(dec->codec_ctx);
	aloe_buf_clear(&dec->buf);
	return 0;
}

extern "C"
int air192_ffaac_decode(void *_dec, const void *data, size_t sz,
		void *aout, size_t asz, unsigned flag) {
	dec_t *dec = (dec_t*)_dec;
	int r;

	if (!data || sz <= 0) return 0;
	if (sz > (dec->buf.lmt - dec->buf.pos)) {
		air192_ffaac_reset(dec);
		if (sz > dec->buf.cap) {
			log_e("insufficient buffer for input\n");
			return -1;
		}
		log_d("insufficient buffer for input, drain old data\n");
	}
	memcpy((char*)dec->buf.data + dec->buf.pos, data, sz);
	dec->buf.pos += sz;

	aloe_buf_flip(&dec->buf);
	sz = 0;
	while (dec->buf.pos < dec->buf.lmt) {
		if (dec->parser) {
			if ((r = av_parser_parse2(dec->parser, dec->codec_ctx,
					&dec->pkt->data, &dec->pkt->size,
					(uint8_t*)dec->buf.data + dec->buf.pos,
					dec->buf.lmt - dec->buf.pos,
					AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0)) < 0) {
				log_e("parse aac\n");
				air192_ffaac_reset(dec);
				return -1;
			}
		} else {
			dec->pkt->data = (uint8_t*)dec->buf.data + dec->buf.pos;
			dec->pkt->size = dec->buf.lmt - dec->buf.pos;
			r = dec->buf.lmt - dec->buf.pos;
		}
		dec->buf.pos += r;
		if (r == 0 || dec->pkt->size <= 0) {
			log_d("more data requisite\n");
			break;
		}
		if (AU_FOUT(aout, asz)) {
			r = decode(dec, aout, asz, flag);
		} else {
			r = decode(dec, (char*)aout + sz, asz - sz, flag);
		}
		if (r < 0) {
			log_e("decode aac\n");
			air192_ffaac_reset(dec);
			return -1;
		}
		if (r == 0) {
//			log_d("decoded none\n");
			continue;
		}
		sz += r;
		if (!AU_FOUT(aout, asz) && sz >= asz) {
			log_d("output buffer full\n");
			break;
		}
	}
	aloe_buf_replay(&dec->buf);
	return sz;
}

#pragma GCC diagnostic pop
