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

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/times.h>
#include <syslog.h>
#include <sys/random.h>
#include <admin/unitest.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <getopt.h>

#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <admin/sa7715.h>

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

#define DEF_I2CDEV "/dev/i2c-0"

// _v = strtol(str, &_toe, )
#define strtol_failed(_v, _toe) (((_toe) && *(_toe)) \
		|| errno == ERANGE || (_v) == LONG_MIN || (_v) == LONG_MAX)

static struct {
	int ondevice, i2caddr, i2cfd;
	const char *i2cdev;
	unsigned long i2cfuncs;
} impl;

static int i2c_funcs_desc(unsigned long funcs, char *desc, size_t cap) {
	struct {
		unsigned int flag;
		const char *desc;
		int kind;
	} spec_lut[] = {
		{I2C_FUNC_I2C, "Plain I2C"},
		{I2C_FUNC_10BIT_ADDR, "10Bits"},
		{I2C_FUNC_PROTOCOL_MANGLING, "Protocol mangling"},
		{I2C_FUNC_SLAVE, "Slave"},
		{I2C_FUNC_NOSTART, "No start"},
		{I2C_FUNC_SMBUS_EMUL, "SMBus"},
		{0, NULL}
	}, *spec;
	aloe_buf_t rbuf;
	int r;

	rbuf.data = desc;
	rbuf.cap = cap;
	aloe_buf_clear(&rbuf);
	for (spec = spec_lut; spec->desc; spec++) {
		if ((unsigned)funcs & spec->flag) {
			if ((aloe_buf_printf(&rbuf, "%s%s", (rbuf.pos > 0 ? ", " : ""),
					spec->desc)) <= 0) {
				log_e("Insufficient memory to show I2C adapter functionality\n");
				r = -1;
				goto finally;
			}
		}
	}
	r = rbuf.pos;
finally:
	return r;
}

static int i2c_write(const void *data, size_t sz) {
	int r;

	if ((r = write(impl.i2cfd, data, sz)) < 0) {
		r = errno;
		log_e("Failed write i2c: %s\n", strerror(r));
		return -1;
	}
	return r;
}

static int i2c_read(void *data, size_t sz) {
	int r;

	if ((r = read(impl.i2cfd, data, sz)) < 0) {
		r = errno;
		log_e("Failed read i2c: %s\n", strerror(r));
		return -1;
	}
	return r;
}

static int aloe_parse_i2c_cli(int argc, char *const *argv, void *wbuf,
		int *wlen, int *rlen) {
	enum {
		flag_null,
		flag_parse_addr7,
		flag_parse_rw,
		flag_parse_w,
		flag_parse_ww,
		flag_parse_r,
		flag_done,
	};
	int parse = flag_null, opt_idx = 0, wcap = (wlen && wbuf ? *wlen : 0);
	long val;
	char *toe;

	if (wcap > 0) *wlen = 0;
	while (opt_idx < argc) {
		log_d("parse argv[%d]: %s\n", opt_idx, argv[opt_idx]);
		if ((parse == flag_parse_w) || (parse == flag_parse_ww)) {
			val = strtol(argv[opt_idx], &toe, 0);

			if (strtol_failed(val, toe)) {
				log_d("parse w val but found not a number (argv[%d]: %s)\n",
						opt_idx, argv[opt_idx]);
				parse = flag_parse_rw;
				continue;
			}

			opt_idx++;

			if (wcap > 0) {
				if (*wlen >= wcap) {
					log_e("Insufficient write buffer\n");
					return -1;
				}
				((char*)wbuf)[*wlen] = (char)val;
				*wlen += 1;
			}
			parse = flag_parse_ww;
			continue;
		}
		if (parse == flag_parse_r) {
			val = strtol(argv[opt_idx], &toe, 0);

			if (strtol_failed(val, toe)) {
				log_e("Failed get read byte count (argv[%d]: %s)\n",
						opt_idx, argv[opt_idx]);
				return -1;
			}

			opt_idx++;

			if (rlen) {
				*rlen = (int)val;
			}
			parse = flag_parse_rw;
			continue;
		}
		switch(*argv[opt_idx]) {
		case 'w':
		case 'W':
			if (opt_idx >= argc) {
				log_e("out of w args\n");
				return -1;
			}
			log_d("start parse w (argv[%d]: %s)\n", opt_idx, argv[opt_idx]);
			parse = flag_parse_w;
			break;
		case 'r':
		case 'R':
			if (opt_idx >= argc) {
				log_e("out of r args\n");
				return -1;
			}
			log_d("start parse r (argv[%d]: %s)\n", opt_idx, argv[opt_idx]);
			parse = flag_parse_r;
			break;
		default:
			log_e("unknown (argv[%d]: %s)\n", opt_idx, argv[opt_idx]);
			return -1;
		}
		opt_idx++;
	}
	return 0;
}

static const char opt_short[] = "hv";
enum {
	opt_key_ondevice = 0x201,
	opt_key_i2cdev,
	opt_key_i2caddr,
};
static struct option opt_long[] = {
	{"help", no_argument, NULL, 'h'},
	{"verbose", no_argument, NULL, 'v'},
	{"ondevice", required_argument, NULL, opt_key_ondevice},
	{"dev", required_argument, NULL, opt_key_i2cdev},
	{"addr", required_argument, NULL, opt_key_i2caddr},
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
"  --dev          I2C device[%s]\n"
"  --addr         I2C slave address\n"
"\n",
	(fn ? fn : "PROG"), DEF_I2CDEV);
	return 0;
}

int main(int argc, char *const *argv) {
	int r, opt_op, opt_idx, i, rlen;
	aloe_buf_t rbuf = {0}, wbuf = {0};

//	for (i = 0; i < argc; i++) {
//		log_d("argv[%d/%d]: %s\n", i + 1, argc, argv[i]);
//	}

	memset(&impl, 0, sizeof(impl));
	impl.i2cdev = DEF_I2CDEV;
	impl.i2cfd = -1;

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
		if (opt_op == opt_key_i2cdev) {
			impl.i2cdev = optarg;
			continue;
		}
		if (opt_op == opt_key_i2caddr) {
			char *toe;
			long val = strtol(optarg, &toe, 0);

			if (strtol_failed(val, toe)) {
				log_e("Invalid I2C slave address (%s)\n", optarg);
				r = -1;
				goto finally;
			}
			impl.i2caddr = (int)val;
			continue;
		}
	}

//	for (opt_idx = optind; opt_idx < argc; opt_idx++) {
//		log_d("non-optional argv[%d/%d]: %s\n", opt_idx + 1, argc, argv[opt_idx]);
//	}

	if ((aloe_buf_expand(&rbuf, 1024, aloe_buf_flag_none)) != 0
			|| (aloe_buf_expand(&wbuf, 128, aloe_buf_flag_none)) != 0) {
		log_e("Allocate buffer\n");
		r = -1;
		goto finally;
	}

	aloe_buf_clear(&wbuf);
	rlen = 0;
	i = wbuf.lmt - wbuf.pos;
	if ((r = aloe_parse_i2c_cli(argc - optind, &argv[optind],
			(char*)wbuf.data + wbuf.pos, &i, &rlen)) != 0) {
		log_e("Failed parse I2C data\n");
		r = -1;
		goto finally;
	}
	wbuf.pos += i;
	aloe_buf_flip(&wbuf);
	log_d("I2C data write %d bytes, read %d bytes\n", (int)wbuf.lmt, rlen);

	if (!impl.ondevice && aloe_file_size(app_cfg, 0) >= 0) {
		impl.ondevice = 1;
		log_d("Imply running on sa7715 (found %s)\n", app_cfg);
	}

	if ((impl.i2cfd = open(impl.i2cdev, O_RDWR)) == -1) {
		r = errno;
		log_e("Failed open I2C device %s, %s\n", impl.i2cdev, strerror(r));
		goto finally;
	}
	if ((r = ioctl(impl.i2cfd, I2C_FUNCS, &impl.i2cfuncs)) < 0) {
		r = errno;
		log_e("Failed get I2C adapter functionality, %s\n", strerror(r));
		goto finally;
	}
	aloe_buf_clear(&rbuf);
	if ((r = i2c_funcs_desc(impl.i2cfuncs, (char*)rbuf.data,
			rbuf.lmt - rbuf.pos)) > 0) {
		rbuf.pos += r;
		log_d("I2C adapter functionality (0x%x): %s\n",
				(unsigned int)impl.i2cfuncs, (char*)rbuf.data);
	} else {
		log_e("Failed compose I2C adapter functionality (0x%x) description\n",
				(unsigned int)impl.i2cfuncs);
		r = -1;
//		goto finally;
	}

	if (impl.i2caddr == 0) {
		log_e("Miss I2C slave address\n");
		r = -1;
		goto finally;
	}

	if ((r = ioctl(impl.i2cfd, I2C_SLAVE, impl.i2caddr)) < 0) {
		log_e("Failed apply I2C slave address %d\n", impl.i2caddr);
		r = -1;
		goto finally;
	}

	if (rlen >= (int)rbuf.cap) {
		r = -1;
		log_e("Insurfficient memory for read buffer\n");
		goto finally;
	}

	if (wbuf.lmt > wbuf.pos) {
		if ((r = i2c_write((char*)wbuf.data + wbuf.pos,
				wbuf.lmt - wbuf.pos)) <= 0) {
			log_e("Failed write I2C\n");
			goto finally;
		}
	}

	if (rlen > 0) {
		aloe_buf_clear(&rbuf);
		if ((r = i2c_read((char*)rbuf.data, rlen)) <= 0) {
			log_e("Failed read I2C\n");
			goto finally;
		}

		log_d("Read output: ");
		for (i = 0; i < rlen; i++) {
			printf("%s0x%x", (i > 0 ? ", " : ""), ((char*)rbuf.data)[i]);
		}
		printf("\n");
	}

	r = 0;
finally:
	if (impl.i2cfd != -1) close(impl.i2cfd);
	if (wbuf.data) free(wbuf.data);
	if (rbuf.data) free(rbuf.data);
	return r;
}
