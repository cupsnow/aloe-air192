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

#include <fdk-aac/aacdecoder_lib.h>
//#include <fdk-aac/aacenc_lib.h>

}

#include "priv.h"

#define AU_MS2SZ(_rate, _ch, _samp, _ms) ( \
		(_rate) * (_ch) * (_samp) * (_ms) / 1000)

#define AU_FOUT(_aout, _asz) ((_asz) == (size_t)-2 ? _aout : NULL)

typedef struct {
    uint32_t sourceFormatID;
    uint32_t destFormatID;
    uint32_t sampleRate;
    uint32_t channels;
    void* nativeCodecRef;

	aloe_buf_t buf;

	struct {
		size_t aubuf_prog; /**< current input buffer progress */
		size_t au_prog; /**< current input process progress */
		size_t samp_prog; /**< current sample progress */
	} stat;

} dec_t;

// https://wiki.multimedia.cx/index.php?title=MPEG-4_Audio#Audio_Specific_Config
static unsigned asc_aot_aac_lc = 2;
static const unsigned asc_freq_lut[] = {96000, 88200, 64000, 48000, 44100,
		32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350};

static unsigned asc_ch_lut[] = {0, 1, 2};

extern "C"
void air192_fdkaac_close(void *_dec) {
	dec_t *dec = (dec_t*)_dec;

	if (dec) {
		if (dec->nativeCodecRef) {
			aacDecoder_Close((HANDLE_AACDECODER)dec->nativeCodecRef);
		}
		free(dec);
	}
}

extern "C"
void* air192_fdkaac_open_lc(int rate, int channel, long buf_ms) {
	dec_t *dec = NULL;
	int r, aubuf_sz = AU_MS2SZ(44100, 2, sizeof(float), 50);
	unsigned char asc[2];
	unsigned asc_aot = asc_aot_aac_lc, asc_freq, asc_ch;
    UCHAR* configBuffers[1] = {0};
    UINT configBufferSizes[1] = {0};

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
			+ aubuf_sz)) == NULL) {
		r = ENOMEM;
		log_e("alloc dec\n");
		goto finally;
	}
	memset(dec, 0, sizeof(*dec));
	dec->buf.data = (void*)(dec + 1);
	dec->buf.cap = aubuf_sz;
	dec->channels = channel;
	dec->sampleRate = rate;

	if ((dec->nativeCodecRef = aacDecoder_Open(TT_MP4_RAW, 1)) == NULL) {
		r = EIO;
		log_e("alloc decoder\n");
		goto finally;
	}

	asc[0] = (asc_aot << 3) | ((asc_freq & 0x0E) >> 1);
	asc[1] = ((asc_freq & 0x01) << 7) | ((asc_ch & 0x0F) << 3);

    configBuffers[0] = asc;
    configBufferSizes[0] = sizeof(asc);

    if (aacDecoder_ConfigRaw((HANDLE_AACDECODER)dec->nativeCodecRef,
    		configBuffers, configBufferSizes) != 0) {
    	r = EIO;
    	log_e("config decoder\n");
    	goto finally;
    }

    /*
	 * In order to reduce the amount of audio delay in FDK using the default settings, and causing
	 * sync problems with other AirPlay speakers, changing the concealment to ::CONCEAL_NOISE and
	 * turning off the limiter reduces the audio output delay to 0 samples.
	 *
	 * Documentation/Comment from FDK in conceal.cpp file regarding noise concealment.
	 *
	 * Noise substitution: In case of an detected error, concealment copies the
	 * last frame and adds attenuates the spectral data. For this mode you have to
	 * set the #CONCEAL_NOISE define. Noise substitution adds no additional delay.
	 *
	 */
    (void)aacDecoder_SetParam((HANDLE_AACDECODER)dec->nativeCodecRef, AAC_CONCEAL_METHOD, 1);
    (void)aacDecoder_SetParam((HANDLE_AACDECODER)dec->nativeCodecRef, AAC_PCM_LIMITER_ENABLE, 0);

	aloe_buf_clear(&dec->buf);
	r = 0;
finally:
	if (r != 0) {
		if (dec) air192_fdkaac_close(dec);
		return NULL;
	}
	return dec;
}

extern "C"
int air192_fdkaac_reset(void *_dec) {
	dec_t *dec = (dec_t*)_dec;

//	avcodec_flush_buffers(dec->codec_ctx);
	aloe_buf_clear(&dec->buf);
	return 0;
}

extern "C"
int air192_fdkaac_decode(void *_dec, const void *data, size_t sz,
		void *aout, size_t asz, unsigned flag) {
	dec_t *dec = (dec_t*)_dec;
	int r;

	if (!data || sz <= 0) return 0;
	if (sz > (dec->buf.lmt - dec->buf.pos)) {
		air192_fdkaac_reset(dec);
		if (sz > dec->buf.cap) {
			log_e("insufficient buffer for input\n");
			return -1;
		}
		log_d("insufficient buffer for input, drain old data\n");
	}
	memcpy((char*)dec->buf.data + dec->buf.pos, data, sz);
	dec->buf.pos += sz;
	log_d("append input %d/%d\n", (int)sz, (int)dec->buf.pos);

	aloe_buf_flip(&dec->buf);

    UCHAR* aacInputBuffers[2] = {(UCHAR*)dec->buf.data + dec->buf.pos};
    UINT aacInputBufferSizes[2] = {(UINT)(dec->buf.lmt - dec->buf.pos)};
    UINT numValidBytes[2] = {(UINT)(dec->buf.lmt - dec->buf.pos)};

    if ((r = aacDecoder_Fill((HANDLE_AACDECODER)dec->nativeCodecRef, aacInputBuffers,
    		aacInputBufferSizes, numValidBytes)) != AAC_DEC_OK) {
		air192_fdkaac_reset(dec);
		log_e("unknown error\n");
		return -1;
    }

    r = aacDecoder_DecodeFrame((HANDLE_AACDECODER)dec->nativeCodecRef,
    		(INT_PCM*)aout, asz / sizeof(INT_PCM), 0);
    if (IS_DECODE_ERROR(r)) {
        if (r == AAC_DEC_NOT_ENOUGH_BITS) {
            log_d("codec cannot decode without enough data\n");
        } else {
    		air192_fdkaac_reset(dec);
    		log_e("unknown error\n");
    		return -1;
        }
    }
	aloe_buf_clear(&dec->buf);
	return 1024 * dec->channels * sizeof(uint16_t);
}

