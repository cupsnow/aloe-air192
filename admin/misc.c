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
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/syscall.h>

#include <net/if.h>
#include <ifaddrs.h>
#include <linux/wireless.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#ifdef WITH_PREF_EVENTS
#  include <linux/perf_event.h>
#endif

#include <execinfo.h>

#include "priv.h"

static const char* _aloe_str_negative_lut[] = {
	"no", "negative", "n", "none", "null", "empty", "false", "failure",
	"lose", "lost", "loser", NULL
};

static const char* _aloe_str_positive_lut[] = {
	"yes", "affirmative", "positive", "y", "any", "true", "success",
	"get", "got", "found", "win", "winner", "good", NULL
};

const char **aloe_str_negative_lut = _aloe_str_negative_lut;
const char **aloe_str_positive_lut = _aloe_str_positive_lut;

const char* aloe_str_find(const char **lut, const char *val, size_t len) {
	const char **r;

	if (!val) return NULL;

	for (r = lut; *r; r++) {
		if (len) {
			if (strncasecmp(*r, val, len) == 0) return *r;
		} else {
			if (strcasecmp(*r, val) == 0) return *r;
		}
	}
	return NULL;
}

const void* aloe_memmem(const void *data, size_t data_len,
		const void *tgt, size_t tgt_len) {
	if (!data || !tgt || tgt_len < 1 || data_len < tgt_len) return NULL;

	while (1) {
		if (memcmp(data, tgt, tgt_len) == 0) return data;
		if (--data_len < tgt_len) break;
		data = (void*)((char*)data + 1);
	}
	return NULL;
}

int aloe_str_endwith(const char *str, const char *suf) {
	int str_len, sur_len;

	return str && suf && (str_len = strlen(str)) >= (sur_len = strlen(suf)) &&
			strcmp(str + str_len - sur_len, suf) == 0;
}

int aloe_strtol(const char *s, char **e, int base, long *val) {
	long v = strtol(s, e, base);
	if (v == LONG_MIN || v == LONG_MAX) return -1;
	if (val) *val = v;
	return 0;
}

int aloe_strtoi(const char *s, char **e, int base, int *val) {
	long v = strtol(s, e, base);
	if (v == LONG_MIN || v == LONG_MAX) return -1;
	if (val) *val = (int)v;
	return 0;
}

int aloe_str_ctrl1(char *buf, int len) {
	int i;

	if (!buf) return 32;

	for (i = 0; i <= aloe_min(len - 2, 30); i++) buf[i] = i + 1;
	if (len - 1 > i) buf[i++] = 127;
	buf[i] = '\0';
	return i;
}

static const char _aloe_str_sep[] = " \r\n\t";
const char *aloe_str_sep = _aloe_str_sep;

int aloe_cli_tok(char *cli, int *argc, char **argv, const char *sep) {
	int argmax = *argc;

	if (!sep) sep = aloe_str_sep;
	_aloe_cli_tok(cli, *argc, argv, sep, argmax);
	return 0;
}

size_t aloe_strrspn(const void *buf, size_t sz, const char *ext) {
	size_t _sz = sz;

	while (_sz > 0 && (((char*)buf)[_sz - 1] == '\0'
			|| (ext && strchr(ext, ((char*)buf)[_sz - 1])))) {
		_sz--;
	}
	return sz - _sz;
}

size_t aloe_strip_end(const void *buf, size_t sz, const char *ext) {
	while (sz > 0) {
		if (((char*)buf)[sz - 1] == '\0' ||
				(ext && strchr(ext, ((char*)buf)[sz - 1]))) {
			sz--;
			continue;
		}
		break;
	}
	return sz;
}

size_t aloe_strip_end2(const void *_buf, size_t sz, const char *ext) {
	const char *c;
	size_t sz_i;

	if (sz == (size_t)-1) sz = strlen((char*)_buf);
	for (sz_i = sz, c = (char*)_buf + sz - 1;
			sz_i > 0
			&& (*c == '\0' || (ext && strchr(ext, *c)));
			sz_i--, c--) {
		;
	}
	return sz - sz_i;
}

size_t _aloe_str_toupper(char *str, size_t sz) {
	int i, cnt;

	if (!str) return 0;
	for (i = cnt = 0; *str; i++, str++) {
		if (sz != (size_t)-1 && i >= sz) break;
		if (*str >= 'a' && *str <= 'z') {
			*str = *str - 'a' + 'A';
			cnt++;
		}
	}
	return cnt;
}

size_t _aloe_str_tolower(char *str, size_t sz) {
	int i, cnt;

	if (!str) return 0;
	for (i = cnt = 0; *str; i++, str++) {
		if (sz != (size_t)-1 && i >= sz) break;
		if (*str >= 'A' && *str <= 'Z') {
			*str = *str - 'A' + 'a';
			cnt++;
		}
	}
	return cnt;
}

size_t _aloe_tr(const void *_data, size_t sz, const char *pat, int chr,
		void *_out) {
	char *data, *out, cont;
	size_t out_sz;

	if (!_data) return 0;
	if (!pat) pat = aloe_str_sep;
	for (data = (char*)_data, out = (char*)_out, cont = 0, out_sz = 0;
			sz > 0; data++, sz--) {
		int c = *data;
		if (!strchr(pat, c)) {
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

size_t aloe_rinbuf_read(aloe_buf_t *buf, void *data, size_t sz) {
	size_t rw_sz, ret_sz;

	if (sz > buf->lmt) sz = buf->lmt;
	ret_sz = sz;

	// rinbuf max continuous readable size: min(lmt, (cap - pos))
	while ((rw_sz = aloe_min(sz, buf->cap - buf->pos)) > 0) {
		memcpy(data, (char*)buf->data + buf->pos, rw_sz);
		buf->pos = (buf->pos + rw_sz) % buf->cap;
		buf->lmt -= rw_sz;
		if (rw_sz >= sz) break;
		sz -= rw_sz;
		data = (char*)data + rw_sz;
	}
	return ret_sz;
}

size_t aloe_rinbuf_write(aloe_buf_t *buf, const void *data, size_t sz) {
	size_t rw_sz, ret_sz;

	ret_sz = aloe_min(sz, buf->cap - buf->lmt);

	// rinbuf max continuous writable position: wpos = ((pos + lmt) % cap)
	while ((rw_sz = aloe_min(sz, buf->cap - buf->lmt)) > 0) {
		int rw_pos = (buf->pos + buf->lmt) % buf->cap;
		if (rw_sz > buf->cap - rw_pos) rw_sz = buf->cap - rw_pos;
		memcpy((char*)buf->data + rw_pos, data, rw_sz);
		buf->lmt += rw_sz;
		if (rw_sz >= sz) break;
		sz -= rw_sz;
		data = (char*)data + rw_sz;
	}
	return ret_sz;
}

aloe_buf_t* aloe_buf_clear(aloe_buf_t *buf) {
	_aloe_buf_clear(buf);
	return buf;
}

aloe_buf_t* aloe_buf_flip(aloe_buf_t *buf) {
	_aloe_buf_flip(buf);
	return buf;
}

aloe_buf_t* aloe_buf_replay(aloe_buf_t *buf) {
	// sanity check
	if (buf->pos > buf->lmt) {
		log_e("Invalid pos > lmt\n");
		return buf;
	}
	_aloe_buf_replay(buf);
	return buf;
}

size_t aloe_buf_remain(aloe_buf_t *buf) {
	return _aloe_buf_remain(buf);
}

//aloe_buf_t* aloe_buf_shift_left(aloe_buf_t *buf, size_t offset) {
//	if (!buf->data || offset > buf->pos || buf->pos > buf->lmt) return buf;
//	memmove(buf->data, (char*)buf->data + offset, buf->pos - offset);
//	buf->pos -= offset;
//	buf->lmt -= offset;
//	return buf;
//}

int aloe_buf_expand(aloe_buf_t *buf, size_t cap, aloe_buf_flag_t retain) {
	void *data;

	if (cap <= 0 || buf->cap >= cap) return 0;
	if (!(data = malloc(cap))) return ENOMEM;
	if (buf->data) {
		if (retain == aloe_buf_flag_retain_rinbuf) {
			aloe_rinbuf_read(buf, data, buf->lmt);
			buf->pos = 0;
		} else if (retain == aloe_buf_flag_retain_index) {
			memcpy(data, (char*)buf->data, buf->pos);
			if (buf->lmt == buf->cap) buf->lmt = cap;
		}
		free(buf->data);
	} else if (retain == aloe_buf_flag_retain_index) {
		buf->lmt = cap;
	}
	buf->data = data;
	buf->cap = cap;
	return 0;
}

int aloe_buf_vprintf(aloe_buf_t *buf, const char *fmt, va_list va) {
	int r;

	r = vsnprintf((char*)buf->data + buf->pos, buf->lmt - buf->pos, fmt, va);
	if (r < 0 || r >= buf->lmt - buf->pos) return -1;
	buf->pos += r;
	return r;
}

int aloe_buf_printf(aloe_buf_t *buf, const char *fmt, ...) {
	int r;
	va_list va;

	va_start(va, fmt);
	r = aloe_buf_vprintf(buf, fmt, va);
	va_end(va);
	return r;
}

int aloe_buf_vaprintf(aloe_buf_t *buf, ssize_t max, const char *fmt,
		va_list va) {
	int r;

	if (!fmt || !fmt[0]) return 0;

	if (max == 0 || buf->lmt != buf->cap) {
		// might enough buf
		return aloe_buf_vprintf(buf, fmt, va);
	}

	if (aloe_buf_expand(buf, ((max > 0 && max < 32) ? max : 32),
			aloe_buf_flag_retain_index) != 0) {
		return -1;
	}

	while (1) {
		va_list vb;

#if __STDC_VERSION__ < 199901L
#  warning "va_copy() may require C99"
#endif
		va_copy(vb, va);
		r = aloe_buf_vprintf(buf, fmt, vb);
		if (r < 0 || r >= buf->cap) {
			if (max > 0 && buf->cap >= max) return -1;
			r = buf->cap * 2;
			if (max > 0 && r > max) r = max;
			if (aloe_buf_expand(buf, r, aloe_buf_flag_retain_index) != 0) {
				va_end(vb);
				return -1;
			}
			va_end(vb);
			continue;
		}
		va_end(vb);
		return r;
	};
}

int aloe_buf_aprintf(aloe_buf_t *buf, ssize_t max, const char *fmt, ...) {
	int r;
	va_list va;

	if (!fmt) return 0;
	va_start(va, fmt);
	r = aloe_buf_vaprintf(buf, max, fmt, va);
	va_end(va);
	return r;
}

aloe_buf_t* aloe_buf_strip_text(aloe_buf_t *buf) {
	char spn[aloe_str_ctrl1(NULL, 0) + 8]; // space and ctrl
	int r;

	// assume buf contain string buf->lmt point to trailing zero
	if (buf->lmt >= buf->cap || ((char*)buf->data)[buf->lmt]) return NULL;

	if (buf->pos >= buf->lmt) return buf;

	// strip trailing whitespace
	r = aloe_strrspn((char*)buf->data + buf->pos,
			buf->lmt - buf->pos, aloe_str_sep);
	if (r > 0) {
		((char*)buf->data)[buf->lmt -= r] = '\0';
		if (buf->pos >= buf->lmt) return buf;
	}

	// strip leading whitespace and ctrl chars
	spn[0] = ' ';
	aloe_str_ctrl1(&spn[1], sizeof(spn) - 1);
	buf->pos += strspn((char*)buf->data + buf->pos, spn);
	if (buf->pos >= buf->lmt) return buf;
	return buf;
}

int aloe_log_lvl(const char *lvl) {
	int lvl_n = (int)(unsigned long)lvl;

	if (lvl_n == aloe_log_level_err
			|| lvl_n == aloe_log_level_info
			|| lvl_n == aloe_log_level_debug
			|| lvl_n == aloe_log_level_verb) {
		return lvl_n;
	}
	if (strncasecmp(lvl, "err", strlen("err")) == 0) return aloe_log_level_err;
	if (strncasecmp(lvl, "inf", strlen("inf")) == 0) return aloe_log_level_info;
	if (strncasecmp(lvl, "deb", strlen("deb")) == 0) return aloe_log_level_debug;
	if (strncasecmp(lvl, "ver", strlen("ver")) == 0) return aloe_log_level_verb;
	return 0;
}

const char *aloe_log_lvl_str(const char *lvl) {
	int lvl_n = (int)(unsigned long)lvl;

	if (lvl_n == aloe_log_level_err) return "ERROR";
	else if (lvl_n == aloe_log_level_info) return "INFO";
	else if (lvl_n == aloe_log_level_debug) return "Debug";
	else if (lvl_n == aloe_log_level_verb) return "verbose";
	else if (lvl && lvl[0]) return lvl;
	return "";
}

__attribute__((format(printf, 5, 0)))
int aloe_log_vsnprintf(aloe_buf_t *fb, const char *lvl, const char *func_name,
		int lno, const char *fmt, va_list va) {
	int r, pos0 = (int)fb->pos;

	{
		struct timespec ts;
		struct tm tm;

		clock_gettime(CLOCK_REALTIME, &ts);
		localtime_r(&ts.tv_sec, &tm);

		if ((r = aloe_buf_printf(fb, "[%02d:%02d:%02d:%06d]", tm.tm_hour,
				tm.tm_min, tm.tm_sec, (int)(ts.tv_nsec / 1000))) <= 0) {
			r = -1;
			goto finally;
		}
	}

	{
		if ((r = aloe_buf_printf(fb, "[%s]", aloe_log_lvl_str(lvl))) <= 0) {
			r = -1;
			goto finally;
		}
	}

	{
		if ((r = aloe_buf_printf(fb, "[%s][#%d]", func_name, lno)) <= 0) {
			r = -1;
			goto finally;
		}
	}

	if ((r = vsnprintf((char*)fb->data + fb->pos, fb->lmt - fb->pos, fmt,
			va)) <= 0) {
		r = -1;
		goto finally;
	}
	if (fb->pos + r >= fb->lmt) {
#if 1
		// apply ellipsis
		const char ellipsis[] = "...\r\n";
		int len = (int)strlen(ellipsis);

		if (len < fb->lmt) {
			memcpy((char*)fb->data + fb->lmt - 1 - len, ellipsis, len + 1);
			fb->pos = fb->lmt - 1;
			r = 0;
			goto finally;
		}
#endif
		r = -1;
		goto finally;
	}
	fb->pos += r;
	r = 0;
finally:
	return r == 0 ? fb->pos - pos0 : 0;
}

__attribute__((format(printf, 5, 6)))
int aloe_log_snprintf(aloe_buf_t *fb, const char *lvl, const char *func_name,
		int lno, const char *fmt, ...) {
	int r;
	va_list va;

	va_start(va, fmt);
	r = aloe_log_vsnprintf(fb, lvl, func_name, lno, fmt, va);
	va_end(va);
	return r;
}

int aloe_log_printf_def(const char *lvl, const char *func_name, int lno,
		const char *fmt, ...) {
#if 0
	return 0;
#else
	char buf[500];
	aloe_buf_t fb = {.data = buf, .cap = sizeof(buf)};
	int r, lvl_n = aloe_log_lvl(lvl);
	FILE *fp;
	va_list va;

	fp = ((lvl_n >= aloe_log_level_info) ? stderr : stdout);

	aloe_buf_clear(&fb);
	va_start(va, fmt);
	r = aloe_log_vsnprintf(&fb, lvl, func_name, lno, fmt, va);
	va_end(va);
	if ((r <= 0)) return 0;
	aloe_buf_flip(&fb);
	if (fb.lmt > 0) {
		fwrite(fb.data, 1, fb.lmt, fp);
		fflush(fp);
	}
	return fb.lmt;
#endif
}

__attribute__((weak, alias("aloe_log_printf_def")))
int aloe_log_printf(const char *lvl, const char *func_name, int lno,
		const char *fmt, ...) ;

ssize_t _aloe_file_size(const void *f, int is_fd) {
	struct stat st;
	int r;

	if (is_fd == 1) {
		r = fstat((int)(long)f, &st);
	} else {
		r = stat((char*)f, &st);
	}
	if (r == 0) return st.st_size;
	r = errno;
	if (r == ENOENT) return -2;
	return -1;
}

ssize_t aloe_file_size(const void *f, int is_fd) {
	int r = _aloe_file_size(f, is_fd);
	if (r >= 0) return r;
	if (r == -2) return 0;
	return -1;
}

ssize_t aloe_file_vfprintf2(const char *fname, const char *fp_mode,
		const char *fmt, va_list va) {
	int r;
	FILE *fp = NULL;

	if (!fname || !fp_mode) return -1;
	if (!fmt) return 0;
	if (!(fp = fopen(fname, fp_mode))) {
		r = errno;
		log_e("Failed open %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
	if ((r = vfprintf(fp, fmt, va)) < 0) {
		r = errno;
		log_e("Failed write %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
finally:
	if (fp) {
		fflush(fp);
		fclose(fp);
	}
	return r;
}

ssize_t aloe_file_fprintf2(const char *fname, const char *mode,
		const char *fmt, ...) {
	va_list va;
	int r;

	va_start(va, fmt);
	r = aloe_file_vfprintf2(fname, mode, fmt, va);
	va_end(va);
	return r;
}

int aloe_file_fread(const char *fname, aloe_buf_t *buf) {
	int fd = -1, r, fsz, len;

	if (!buf->data || (len = buf->lmt - buf->pos) < 2
			|| (fsz = (int)aloe_file_size(fname, 0)) < 1) {
		return 0;
	}

	// reserve trailing zero
	len--;

	if (len > fsz) len = fsz;
	if ((fd = open(fname, O_RDONLY, 0666)) == -1) {
		r = errno;
		log_e("Failed open %s: %s\n", fname, strerror(r));
		return -1;
	}
	r = read(fd, (char*)buf->data + buf->pos, len);
	close(fd);
	if (r < 0) {
		r = errno;
		log_e("Failed read %s: %s\n", fname, strerror(r));
		return -1;
	}
	((char*)buf->data)[buf->pos += r] = '\0';
	if (r != len) {
		r = EIO;
		log_e("Incomplete read %s, %d / %d\n", fname, r, len);
		return -2;
	}
	return r;
}

int aloe_file_write(const char *fname, const char *fp_mode,
		const aloe_buf_t *buf) {
	FILE *fp = NULL;
	int r, len;

	if (!fname || !fp_mode) return -1;
	if (!buf->data || (len = buf->lmt - buf->pos) <= 0) return 0;
	if ((fp = fopen(fname, fp_mode)) == NULL) {
		r = errno;
		log_e("Failed open %s, %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
	if ((r = (int)fwrite((char*)buf->data + buf->pos, 1, len, fp)) != len) {
		log_e("Failed write %s, %s\n", fname, strerror(ferror(fp)));
		r = -1;
		goto finally;
	}
finally:
	if (fp) {
		fflush(fp);
		fclose(fp);
	}
	return r;
}

#if 0
int aloe_file_fwrite(const char *fname, aloe_buf_t *buf) {
	int fd = -1, r, len;

	if (!buf->data || (len = buf->lmt - buf->pos) <= 0) {
		return 0;
	}
	if ((fd = open(fname, O_CREAT|O_WRONLY|O_TRUNC, 0666)) == -1) {
		r = errno;
		log_e("Failed open %s: %s\n", fname, strerror(r));
		return -1;
	}
	r = write(fd, (char*)buf->data + buf->pos, len);
	close(fd);
	if (r < 0) {
		r = errno;
		log_e("Failed write %s: %s\n", fname, strerror(r));
		return -1;
	}
	if (r != len) {
		r = EIO;
		log_e("Incomplete write %s, %d / %d\n", fname, r, len);
		return -1;
	}
	return r;
}
#endif

int aloe_file_nonblock(int fd, int en) {
	int r;

	if ((r = fcntl(fd, F_GETFL, NULL)) == -1) {
		r = errno;
		log_e("Failed to get file flag: %s(%d)\n", strerror(r), r);
		return r;
	}
	if (en) r |= O_NONBLOCK;
	else r &= (~O_NONBLOCK);
	if ((r = fcntl(fd, F_SETFL, r)) != 0) {
		r = errno;
		log_e("Failed to set nonblocking file flag: %s(%d)\n", strerror(r), r);
		return r;
	}
	return 0;
}

int _aloe_file_stdout(const char *fname, FILE **sfp, int sfd) {
	int r, fd;

	if (sfp && *sfp) {
		FILE *f;

		if (!(f = freopen(fname, "a+", *sfp))) {
			r = errno;
//			log_e("Failed reopen %s, %s\n", fname, strerror(r));
			return -1;
		}
		if (*sfp != f) *sfp = f;
		fd = fileno(f);
	} else {
		if ((fd = open(fname, O_WRONLY | O_APPEND | O_CREAT, 0666)) == -1) {
			r = errno;
//			log_e("Failed open %s, %s\n", fname, strerror(r));
			return -1;
		}
		if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
			r = errno;
//			log_e("Failed set position bottom to %s: %s\n", fname, strerror(r));
			close(fd);
			return -1;
		}
	}

	if (sfd != -1) {
		while (dup2(fd, sfd) == -1) {
			r = errno;
			if (r == EBUSY || r == EINTR) {
				usleep(rand() % 300);
				continue;
			}
			if (!sfp || !*sfp) close(fd);
//			log_e("Failed dup2 %s for #%d, %s\n", fname, sfd, strerror(r));
			return -1;
		}
	}
	return fd;
}

int aloe_ip_bind(struct sockaddr *sa, int cs) {
	int fd = -1, r, af = aloe_sockaddr_family(sa);
	socklen_t sa_len;

	switch (af) {
	case AF_INET:
		sa_len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		sa_len = sizeof(struct sockaddr_in6);
		break;
	case AF_UNIX:
		sa_len = sizeof(struct sockaddr_un);
		break;
	default:
		log_e("Unknown socket type\n");
		return -1;
	}

	if ((fd = socket(af, cs, 0)) == -1) {
		r = errno;
		log_e("Failed create ip socket, %s(%d)\n", strerror(r), r);
		return -1;
	}
	if (af == AF_INET || af == AF_INET6) {
		r = 1;
		if ((r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(r))) < 0) {
			r = errno;
			close(fd);
			log_e("Failed set ip socket reuseaddr, %s(%d)\n", strerror(r), r);
			return -1;
		}
	}
	if ((r = bind(fd, sa, sa_len)) < 0) {
		r = errno;
		close(fd);
		log_e("Failed bind ip socket, %s(%d)\n", strerror(r), r);
		return -1;
	}
	return fd;
}

int aloe_ip_listener(struct sockaddr *sa, int cs, int backlog) {
	int fd = -1, r;

	if ((fd = aloe_ip_bind(sa, cs)) == -1) return -1;
	if ((r = listen(fd, backlog)) < 0) {
		r = errno;
		close(fd);
		log_e("Failed listen ip socket, %s(%d)\n", strerror(r), r);
		return -1;
	}
	return fd;
}

int aloe_ip_str(struct sockaddr *sa, aloe_buf_t *buf, unsigned flag) {
	if (sa->sa_family == AF_INET) {
		if (flag & aloe_ip_str_addr) {
			if (!inet_ntop(AF_INET, &((struct sockaddr_in*)sa)->sin_addr,
					(char*)buf->data + buf->pos,
					(socklen_t)buf->lmt - buf->pos - 1)) {
				return -1;
			}
			buf->pos += strlen((char*)buf->data + buf->pos);
		}
		if (flag & aloe_ip_str_port) {
			if (aloe_buf_printf(buf, ":%d",
					ntohs(((struct sockaddr_in*)sa)->sin_port)) <= 0) {
				return -1;
			}
		}
		return 0;
	}
	if (sa->sa_family == AF_INET6) {
		if (flag & aloe_ip_str_addr) {
			if (!inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa)->sin6_addr,
					(char*)buf->data + buf->pos,
					(socklen_t)buf->lmt - buf->pos - 1)) {
				return -1;
			}
			buf->pos += strlen((char*)buf->data + buf->pos);
		}
		if (flag & aloe_ip_str_port) {
			if (aloe_buf_printf(buf, ":%d",
					ntohs(((struct sockaddr_in6*)sa)->sin6_port)) <= 0) {
				return -1;
			}
		}
		return 0;
	}
	return -1;
}

int aloe_accessory_name_refine(aloe_buf_t *buf) {
	char spn[aloe_str_ctrl1(NULL, 0) + 8]; // space and ctrl

	// strip trailing whitespace
	((char*)buf->data)[buf->lmt -= aloe_strrspn((char*)buf->data + buf->pos,
			buf->lmt - buf->pos, aloe_str_sep)] = '\0';
	if (buf->pos >= buf->lmt) return -1;

	// strip leading whitespace and ctrl chars
	spn[0] = ' ';
	aloe_str_ctrl1(&spn[1], sizeof(spn) - 1);
	buf->pos += strspn((char*)buf->data + buf->pos, spn);
	if (buf->pos >= buf->lmt) return -1;

	// filter valid character
	((char*)buf->data)[(buf->lmt = buf->pos + strcspn(
			(char*)buf->data + buf->pos, spn + 1))] = '\0';
	if (buf->pos >= buf->lmt) return -1;
	return 0;
}

int aloe_hostname_refine(aloe_buf_t *buf) {

	char *c, *t;

	for (c = (char*)buf->data + buf->pos, t = (char*)buf->data + buf->lmt;
			c < t; c++) {
		if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z')
				|| (*c >= '0' && *c <= '9'))) {
			*c = '_';
		}
	}
	return 0;
}

int aloe_hostname_get(aloe_buf_t *buf) {
	int r;

	if (buf && !buf->data && aloe_buf_expand(buf, HOST_NAME_MAX,
			aloe_buf_flag_retain_index) != 0) {
		log_e("Failed alloc memory for host name\n");
		return -1;
	}

	if (buf->data && buf->lmt - buf->pos < 2) {
		log_e("Invalid buffer for host name\n");
		return -1;
	}

	((char*)buf->data)[buf->pos] = '\0';
	if (gethostname((char*)buf->data + buf->pos, buf->lmt - buf->pos - 1) != 0) {
		r = errno;
		log_e("Failed gethostname %s\n", strerror(r));
		return -1;
	}
	((char*)buf->data)[buf->lmt - 1] = '\0';
	r = strlen((char*)buf->data + buf->pos);
	buf->pos += r;
	return 0;
}

int aloe_hostname_set(const char *fn_cfg, aloe_buf_t *buf) {
	int r;

	if (fn_cfg && (r = aloe_file_fwrite(fn_cfg, buf)) != (buf->lmt - buf->pos)) {
		r = EIO;
		log_e("Save hostname to %s\n", fn_cfg);
		goto finally;
	}
	if ((r = sethostname((char*)buf->data + buf->pos, buf->lmt - buf->pos)) != 0) {
		r = errno;
		log_e("Set hostname %s, %s\n", (char*)buf->data + buf->pos, strerror(r));
		goto finally;
	}
	log_d("Set hostname: %s\n", (char*)buf->data + buf->pos);
	r = 0;
finally:
	return r;
}

int aloe_hostname_printf(const char *fn_cfg, const char *fmt, ...) {
	int r;
	aloe_buf_t buf = {0};
	va_list va;

	va_start(va, fmt);
	r = aloe_buf_vaprintf(&buf, -1, fmt, va);
	va_end(va);
	if (r <= 0) {
		r = ENOMEM;
		log_e("No memory for host name\n");
		goto finally;
	}
	aloe_buf_flip(&buf);
	aloe_hostname_refine(&buf);
	r = aloe_hostname_set(fn_cfg, &buf);
finally:
	if (buf.data) free(buf.data);
	return r;
}

#if defined(WITH_PREF_EVENTS)

typedef struct {
	int fd, st;
} perfev_t;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags) {
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

void* aloe_perfev_init(void) {
	struct perf_event_attr pe;
	perfev_t *pfe = NULL;
	int r;

	if ((pfe = malloc(sizeof(*pfe))) == NULL) {
		r = ENOMEM;
		log_e("Allocate memory for context\n");
		goto finally;
	}
	pfe->fd = -1;
	pfe->st = 0;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_HARDWARE;
	pe.size = sizeof(pe);
	pe.config = PERF_COUNT_HW_CPU_CYCLES;
	pe.disabled = 1;
//	pe.exclude_kernel = 1;
//	pe.exclude_hv = 1;

	if ((pfe->fd = perf_event_open(&pe, 0, -1, -1,
			PERF_FLAG_FD_NO_GROUP)) == -1) {
		r = errno;
		log_e("Open perf events: %s\n", strerror(r));
		goto finally;
	}
	r = 0;
finally:
	if (r != 0) {
		aloe_perfev_destroy(pfe);
		return NULL;
	}
	return pfe;
}

void aloe_perfev_destroy(void *ctx) {
	perfev_t *pfe = (perfev_t*)ctx;

	if (pfe) {
		if (pfe->fd != -1) close(pfe->fd);
		free(pfe);
	}
}

long long aloe_perfev_enable(void *ctx, int sw) {
	perfev_t *pfe = (perfev_t*)ctx;

	if (!sw) {
		long long count;

		ioctl(pfe->fd, PERF_EVENT_IOC_DISABLE, 0);
		read(pfe->fd, &count, sizeof(count));
		return count;
	}
	ioctl(pfe->fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(pfe->fd, PERF_EVENT_IOC_ENABLE, 0);
	return 0;
}

#endif /* WITH_PREF_EVENTS */

unsigned aloe_cksum(const void *data, size_t sz) {
	const unsigned char *s = data;
	unsigned k = 0;

	while (sz-- > 0) k += *s++;
	return k;
}

long aloe_quoted_number_parse(const char *str, const char *se, aloe_buf_t *fb) {
	void *_fb = NULL;
	long r = aloe_quoted_number_invalid, n = strlen(str);

	if (!str || !str[0]) goto finally;
	if (!se) {
		se = "[]";
	} else if (!se[0] || !se[1]) {
		log_e("Invalid argument\n");
		goto finally;
	}
	if (fb) {
		if (fb->cap <= n) goto finally;
	} else {
		 if (!(_fb = malloc(sizeof(*fb) + n + 1))) goto finally;
		 fb = (aloe_buf_t*)_fb;
		 fb->data = (void*)(fb + 1);
		 fb->cap = n + 1;
	}
	aloe_buf_clear(fb);
	memcpy(fb->data, str, fb->pos = n);
	aloe_buf_flip(fb);

	if (!aloe_buf_strip_text(fb) || fb->pos >= fb->lmt
			|| fb->lmt - fb->pos < 2) {
		goto finally;
	}

	if (((char*)fb->data)[fb->pos] != se[0]
			|| ((char*)fb->data)[fb->lmt - 1] != se[1]) {
		goto finally;
	}

	fb->pos++;
	((char*)fb->data)[--fb->lmt] = '\0';

	if (!aloe_buf_strip_text(fb) || fb->pos >= fb->lmt) {
		goto finally;
	}

	char *eon = NULL;
	n = strtol(&((char*)fb->data)[fb->pos], &eon, 0);
	if (n == LONG_MIN || n == LONG_MAX) goto finally;
	// not full valid
	if (!eon || *eon) goto finally;
	r = n;
finally:
	if (_fb) free(_fb);
	return r;
}

int aloe_readline(int (*getc)(void *arg), void *arg, char *_nl) {
	int c, n, cr;

	for (n = 0, cr = -1; (c = (*getc)(arg)) >= 0; n++) {
		// the got character not in count
		if (c == aloe_lf) {
			// check CRLF(\r\n)
			if ((cr >= 0) && (cr == n - 1)) {
				// newline is CRLF(\r\n)
				if (_nl) *_nl = 2;

				// return count excluding CR(\r)
				return n - 1;
			}
			// newline is LF(\n)
			if (_nl) *_nl = 1;
			return n;
		}
		// save index if found CR(\r)
		cr = (c == aloe_cr ? n : -1);
	}
	// no newline
	if (_nl) *_nl = 0;

	// negative when no input at all
	return (n <= 0) ? -1 : n;
}

int aloe_get_ifaddr(const char *ifce, struct sockaddr_in *sin, int cnt) {
	struct ifaddrs *ifaddr;
    int idx = 0, ifce_len = ifce ? strlen(ifce) : 0;

    if (!sin || cnt < 1) return -1;
    if (getifaddrs(&ifaddr) != 0) return -1;
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
        if (ifce_len > 0 && strncmp(ifa->ifa_name, ifce, ifce_len) != 0) continue;
        if ((ifa->ifa_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING)) {
        	if (ifa->ifa_addr->sa_family == AF_INET) {
        		*sin = *(struct sockaddr_in*)ifa->ifa_addr;
        		if ((++idx >= cnt)) break;
        	}
        }
    }
    freeifaddrs(ifaddr);
    return idx;
}

int aloe_iface_wifi(const char *ifce, char *proto, size_t proto_len) {
	struct iwreq iwreq1;
	int fd = -1, r;

	memset(&iwreq1, 0, sizeof(iwreq1));

	strncpy(iwreq1.ifr_name, ifce, IFNAMSIZ);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		r = errno;
		log_e("create socket %s\n", strerror(r));
		goto finally;
	}

	if (ioctl(fd, SIOCGIWNAME, &iwreq1) == -1) {
		r = errno;
//		log_e("SIOCGIWNAME %s\n", strerror(r));
		goto finally;
	}

	if (proto && proto_len > 0) {
		r = aloe_min(IFNAMSIZ, proto_len);
		strncpy(proto, iwreq1.u.name, r);
		if (r > 0) proto[r - 1] = '\0';
	}
	r = 0;
finally:
	if (fd != -1) close(fd);
	return r;
}

int aloe_eth_link_state(int fd, const char *ifce) {
	int _fd = -1, r, ifceLen, linked = -1;
	struct ifreq if_req = {0};
	struct ethtool_value edata = {0};

	if (!ifce || !ifce[0]
			|| (ifceLen = strlen(ifce)) >= sizeof(if_req.ifr_name)) {
		r = EINVAL;
		log_e("Invalid ifce name %s\n", ifce ? ifce : "None");
		goto finally;
	}
	memcpy(if_req.ifr_name, ifce, ifceLen);

	if (fd == -1) {
		do {
			if ((_fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1) break;
			r = errno;
			log_e("Open AF_INET: %s\n", strerror(r));

			if ((_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)) != -1) break;
			r = errno;
			log_e("Open AF_NETLINK: %s\n", strerror(r));

			goto finally;
		} while(0);
		fd = _fd;
	}
	edata.cmd = ETHTOOL_GLINK;
	if_req.ifr_data = (char*)&edata;
	if ((r = ioctl(fd, SIOCETHTOOL, &if_req)) < 0) {
		r = errno;
		log_e("%s SIOCETHTOOL: %s\n", ifce, strerror(r));
		goto finally;
	}
	linked = !!edata.data;
	r = 0;
finally:
	if (_fd != -1) close(_fd);
	return linked;
}

int aloe_eth_linkup(const char *ifcePrefix) {
	struct ifaddrs *ifaddr = NULL;
	int r, ifcePrefixLen, linked = -1;

	if (getifaddrs(&ifaddr) != 0) {
		r = errno;
		log_e("getifaddrs %s\n", strerror(r));
		goto finally;
	}
	ifcePrefixLen = ifcePrefix ? strlen(ifcePrefix) : 0;
	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if ((ifa->ifa_flags & IFF_LOOPBACK)
				|| (ifa->ifa_flags & IFF_POINTOPOINT)
//				|| !(ifa->ifa_flags & IFF_RUNNING)
//				|| !(ifa->ifa_flags & IFF_UP)
//				|| !ifa->ifa_addr
//				|| (ifa->ifa_addr->sa_family != AF_INET)
				) {
			continue;
		}
		if (ifcePrefix
				&& strncasecmp(ifa->ifa_name, ifcePrefix, ifcePrefixLen) != 0) {
			continue;
		}
		if (aloe_iface_wifi(ifa->ifa_name, NULL, 0) == 0) continue;
		linked = aloe_eth_link_state(-1, ifa->ifa_name);
//		log_d("found %s link state %s, flag: 0x%x\n", ifa->ifa_name,
//				((linked > 0) ? "yes" :
//				(linked == 0) ? "no":
//				"unknown"), (unsigned)ifa->ifa_flags);
		break;
	}
	r = 0;
finally:
    if (ifaddr) freeifaddrs(ifaddr);
	return linked;
}

static int aloe_ini_find_get(void *arg) {
	aloe_buf_t *fb = (aloe_buf_t*)arg;

	if (!fb->data || fb->lmt >= fb->cap)

	if (fb->lmt >= fb->cap) return -1;
	return (int)((unsigned char*)fb->data)[fb->lmt++];
}

const char* aloe_ini_find(const void *raw, size_t raw_len, const char *key,
		size_t *found_len) {
	aloe_buf_t fb = {.data = (void*)raw, .cap = raw_len};
	int key_len, line_len;

	if (!raw || raw_len < 1) return NULL;
	key_len = strlen(key);
	for ( ; (line_len = aloe_readline(&aloe_ini_find_get, &fb, NULL)) >= 0;
			fb.pos = fb.lmt) {
		const char *line_start = (char*)fb.data + fb.pos;
		int sp_len;

		if (line_len < key_len) continue;
		sp_len = strspn(line_start, " \t");
		if (sp_len >= line_len) continue;
		if ((line_len -= sp_len) < key_len) continue;
		line_start += sp_len;
		if (*line_start == '#' || *line_start == ';') continue;
		if (strncasecmp(line_start, key, key_len) != 0) continue;
		sp_len = strspn(line_start + key_len, " \t");

		if (key_len + sp_len == line_len) {
			if (found_len) *found_len = 0;
			return line_start + key_len + sp_len;
		}
		if (line_start[key_len + sp_len] == '=') {
			if (found_len) *found_len = line_len - key_len - sp_len - 1;
			return line_start + key_len + sp_len + 1;
		}
	}

	return NULL;
}

struct timeval* aloe_timeval_norm(struct timeval *a) {
	if (a) ALOE_TIMESEC_NORM(a->tv_sec, a->tv_usec, 1000000ul);
	return a;
}

int aloe_timeval_cmp(const struct timeval *a, const struct timeval *b) {
	return ALOE_TIMESEC_CMP(a->tv_sec, a->tv_usec, b->tv_sec, b->tv_usec);
}

struct timeval* aloe_timeval_sub(const struct timeval *a, const struct timeval *b,
		struct timeval *c) {
	ALOE_TIMESEC_SUB(a->tv_sec, a->tv_usec, b->tv_sec, b->tv_usec,
			c->tv_sec, c->tv_usec, 1000000ul);
	return c;
}

struct timeval* aloe_timeval_add(const struct timeval *a, const struct timeval *b,
		struct timeval *c) {
	ALOE_TIMESEC_ADD(a->tv_sec, a->tv_usec, b->tv_sec, b->tv_usec,
			c->tv_sec, c->tv_usec, 1000000ul);
	return c;
}

int aloe_backtrace_dump(int (*cb)(char**, void**, size_t, void*), void *cbarg,
		int skip) {
	void *trace[64];
	char **sym = NULL;
	int r, cnt;

	if ((cnt = backtrace(trace, 64)) <= 0) {
		r = 0;
		goto finally;
	}
	sym = backtrace_symbols(trace, cnt);
	if (cb) {
		r = cb(sym, trace, cnt, cbarg);
		goto finally;
	}
	for (r = skip > 0 ? skip : 0; r < cnt; r++) {
		log_d("[%d/%d]%s\n", r, cnt, (sym && sym[r] ? sym[r] : ""));
	}
finally:
	if (sym) free(sym);
	return r;
}

static void timespec_dur_ms(struct timespec *tv, unsigned long dur_ms) {
	tv->tv_sec += (dur_ms / aloe_10e3);
	tv->tv_nsec += ((dur_ms % aloe_10e3) * aloe_10e6);
	while (tv->tv_nsec >= aloe_10e9) {
		tv->tv_sec++;
		tv->tv_nsec -= aloe_10e9;
	}
}

static int mutex_lock(pthread_mutex_t *mutex, unsigned long dur_ms) {
	struct timespec tv;

	if (dur_ms == aloe_dur_zero) return pthread_mutex_trylock(mutex);
	if (dur_ms == aloe_dur_infinite) return pthread_mutex_lock(mutex);

	if (clock_gettime(CLOCK_REALTIME, &tv) != 0) return errno;
	timespec_dur_ms(&tv, dur_ms);
	return pthread_mutex_timedlock(mutex, &tv);
}

static int cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex,
		unsigned long dur_ms) {
	struct timespec tv;

	if (dur_ms == aloe_dur_infinite) return pthread_cond_wait(cond, mutex);

	if (clock_gettime(CLOCK_REALTIME, &tv) != 0) return errno;
	if (dur_ms != aloe_dur_zero) timespec_dur_ms(&tv, dur_ms);
	return pthread_cond_timedwait(cond, mutex, &tv);
}

unsigned long aloe_ticks(void) {
	struct timespec tv;

	clock_gettime(CLOCK_REALTIME, &tv);
	return tv.tv_sec * aloe_ms2tick(aloe_10e3) +
			aloe_ms2tick(tv.tv_nsec / aloe_10e3) / aloe_10e3;
}

int aloe_sem_init(aloe_sem_t *ctx, int max, int cnt) {
	int r;

	if ((r = pthread_mutex_init(&ctx->mutex, NULL)) != 0) {
		return r;
	}
	if ((r = pthread_cond_init(&ctx->not_empty, NULL)) != 0) {
		pthread_mutex_destroy(&ctx->mutex);
		return r;
	}
	ctx->max = max;
	ctx->cnt = cnt;
	return 0;
}

void aloe_sem_post(aloe_sem_t *ctx, char broadcast) {
	mutex_lock(&ctx->mutex, aloe_dur_infinite);
	if ((ctx->cnt < ctx->max) && ((++(ctx->cnt)) == 1)) {
		if (broadcast) pthread_cond_broadcast(&ctx->not_empty);
		else pthread_cond_signal(&ctx->not_empty);
	}
	pthread_mutex_unlock(&ctx->mutex);
}

int aloe_sem_wait(aloe_sem_t *ctx, unsigned long dur_ms) {
	int r;

	mutex_lock(&ctx->mutex, aloe_dur_infinite);
	while (ctx->cnt == 0) {
		if ((r = cond_wait(&ctx->not_empty, &ctx->mutex, dur_ms)) != 0) {
			goto finally;
		}
	}
	ctx->cnt--;
	r = 0;
finally:
	pthread_mutex_unlock(&ctx->mutex);
	return r;
}

void aloe_sem_destroy(aloe_sem_t *ctx) {
	pthread_cond_destroy(&ctx->not_empty);
	pthread_mutex_destroy(&ctx->mutex);
}
