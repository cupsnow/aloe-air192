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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <getopt.h>
#include <sys/mman.h>

#define log_m(_lvl, _fmt, _args...) printf(_lvl "%s #%d " _fmt, __func__, __LINE__, ##_args)
#define log_e(_args...) log_m("ERROR ", ##_args)
#define log_i(_args...) log_m("INFO ", ##_args)
#define log_d(_args...) log_m("Debug ", ##_args)
#define log_v(_args...) log_m("verbose ", ##_args)

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

extern "C"
void* aloe_mmapfile(int fd, void **vm, size_t *offset, size_t *len) {
	size_t _offset = 0, _len = 0;
	long pgz = 0, pga = 0;
	void *_vm = (void*)MAP_FAILED;
	int r;
	struct stat fst;

	// given all or none
	if ((vm || offset || len) && !(vm && offset && len)) {
		r = EINVAL;
		log_e("%s\n", strerror(r));
		goto finally;
	}

	if ((pgz = sysconf(_SC_PAGE_SIZE)) == -1l) {
		r = errno;
		log_e("Failed get page size, %s\n", strerror(r));
		goto finally;
	}

	if (pgz == 0) {
		r = EIO;
		log_e("Sanity check page size 0\n");
		goto finally;
	}

	if ((r = fstat(fd, &fst)) != 0) {
		r = errno;
		log_e("Failed file stat, %s\n", strerror(r));
		goto finally;
	}

	if (vm) {
		_offset = *offset;
		_len = *len;
	}

	if (_offset >= (size_t)fst.st_size) {
		r = EIO;
		log_e("Failed offset after file size\n");
		goto finally;
	}

	if (_len == 0) _len = fst.st_size;
	if (_offset + _len > (size_t)fst.st_size) _len = fst.st_size - _offset;
	if (_offset && (pga = _offset % pgz) > 0) {
		log_d("page size %zd, offset %zd -> %zd\n", (size_t)pgz, (size_t)_offset,
				_offset - (size_t)pga);
		_offset -= pga;
		_len += pga;
	} else {
		pga = 0;
	}

	if ((_vm = mmap(NULL, _len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			_offset)) == (void*)MAP_FAILED) {
		r = errno;
		log_e("Failed mmap %s\n", strerror(r));
		_vm = NULL;
		goto finally;
	}

	if (vm) {
		*offset = _offset;
		*len = _len;
		*vm = _vm;
	}

	if (pga > 0) {
		_vm = (char*)_vm + pga;
	}
finally:
	return _vm;
}

int main(int argc, char **argv) {
#define gc_fd(_fd) if (_fd != -1) { close(_fd); (_fd) = -1; }

	typedef struct aloe_buf_rec {
		void *data; /**< Memory pointer. */
		size_t cap; /**< Memory capacity. */
		size_t lmt; /**< Data size. */
		size_t pos; /**< Data start. */
	} aloe_buf_t;

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
	return r;
#undef gc_fd
}

