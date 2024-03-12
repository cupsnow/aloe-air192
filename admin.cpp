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

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
//#include <syslog.h>

#include <time.h>
#include <getopt.h>
#include <libgen.h>

#include <uriparser/Uri.h>
#include <cjson/cJSON.h>

#include "priv.h"

#ifdef USER_PREFIX
// ie. build/sysroot-ub20/var/cgi-bin/admin-debug.log
#  define ADMIN_LOG_PATH USER_PREFIX "admin-debug.log"
#else
#  define ADMIN_LOG_PATH "/media/admin-debug.log"
#endif

//extern const char **environ;

static struct {
	unsigned quit: 1;
	int log_level;
	FILE *log_ferr, *log_fout;

} impl = {0};

void *ev_ctx = NULL, *cfg_ctx = NULL;

int ctrl_port = CTRL_PORT_NONE;
const char *ctrl_path = NULL;

int gpio_restkey = GPIO_NUM_NONE;
int gpio_restdur = 10;
const char *gpio_restcmd = "/etc/init.d/refactory enforce&";
const char *gpio_restkeyhook = NULL;

const char *wpasup_ctrldir = "/var/run/wpa_supplicant";
const char *wificfg_ifce = "wlan0";

// must be abs path, wpa_supplicant might be daemon and may alter root/ then
// failed reply to the wificfg_ctrlpath
const char *wificfg_ctrlpath = "/var/run/wificfg-ctrl";

const char *led_conf = NULL;

#if 1
extern "C"
int aloe_log_printf(const char *lvl, const char *func_name, int lno,
		const char *fmt, ...) {
	char buf[200];
	aloe_buf_t fb = {.data = buf, .cap = sizeof(buf)};
	int r, lvl_n;
	FILE *fp;
	va_list va;

	if ((lvl_n = aloe_log_lvl(lvl)) > impl.log_level) return 0;
	fp = ((lvl_n <= aloe_log_level_info) ? impl.log_ferr : impl.log_fout);

	aloe_buf_clear(&fb);

	aloe_buf_printf(&fb, "%s", "[admin]");

#if 0
	aloe_log_snprintf(&fb, lvl, func_name, lno, "");
	aloe_buf_flip(&fb);
	if (fb.lmt > 0) fwrite(fb.data, 1, fb.lmt, fp);
	va_start(va, fmt);
	r = vfprintf(fp,fmt, va);
	va_end(va);
	fflush(fp);
	return (r > 0 ? r : 0) + (fb.lmt > 0 ? fb.lmt : 0);
#else
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
#endif /* if 1 */

//int aloe_syslog_lvl(const char *lvl) {
//	int lvl2 = aloe_log_lvl(lvl);
//
//	return ((lvl2 == aloe_log_level_err) ? LOG_ERR :
//			(lvl2 == aloe_log_level_info) ? LOG_INFO :
//			LOG_DEBUG);
//}

static int regcomp_flag_parse(char *str, int *cf) {
	static const char *sep = " \t\r\n,;:";
	char *tok, *tok_next;

	if (!cf) return EINVAL;
	if (!str) return 0;
	for (tok = strtok_r(str, sep, &tok_next);
			tok; tok = strtok_r(NULL, sep, &tok_next)) {
		if (strcasecmp(tok, "EXTENDED") == 0) *cf |= REG_EXTENDED;
		if (strcasecmp(tok, "ICASE") == 0) *cf |= REG_ICASE;
		if (strcasecmp(tok, "NOSUB") == 0) *cf |= REG_NOSUB;
		if (strcasecmp(tok, "NEWLINE") == 0) *cf |= REG_NEWLINE;
	}
	return 0;
}

typedef struct req_rec {
	const char *re_pat;
	int re_cflags;
	int (*func)(int argc, char * const *argv);
	regex_t *regex;
} req_t;

static int cgienv(int argc, char * const *argv) {
	char **env;

	printf("<html>");
	for (env = environ; *env; env++) {
		printf("%s<br/>\n", *env);
	}
	printf("</html>");
	return 0;
}

extern "C"
void admin_shutdown(void) {
	impl.quit = 1;
}

static int admin(int argc, char * const *argv) {
	int r;
	typedef struct mod_rec {
		const aloe_mod_t *op;
		TAILQ_ENTRY(mod_rec) qent;
		void *ctx;
	} mod_t;
	TAILQ_HEAD(mod_queue_rec, mod_rec) mod_q = TAILQ_HEAD_INITIALIZER(mod_q);
	mod_t *mod;

#if 0
	if (ctrl_port == CTRL_PORT_NONE && (!ctrl_path || !ctrl_path[0])) {
		log_e("admin service without control interface\n");
		r = EINVAL;
		goto finally;
	}
#endif

	if (!(ev_ctx = aloe_ev_init())) {
		r = ENOMEM;
		log_e("aloe_ev_init\n");
		goto finally;
	}
#define MOD_INIT(_op) { \
		extern const aloe_mod_t _op; \
		static mod_t mod = {&_op}; \
		if (!(mod.ctx = (*mod.op->init)())) { \
			r = EIO; \
			log_e("init mod: %s\n", mod.op->name); \
			goto finally; \
		} \
		TAILQ_INSERT_TAIL(&mod_q, &mod, qent); \
	}
	if (ctrl_port != CTRL_PORT_NONE || (ctrl_path && ctrl_path[0])) {
		MOD_INIT(mod_cli);
	}
#ifdef WITH_GPIOD
	MOD_INIT(mod_gpio);
#endif
//	MOD_INIT(mod_template1);

    while (!impl.quit) {
    	aloe_ev_once(ev_ctx);
//    	log_d("enter\n");
    }

	while ((mod = TAILQ_LAST(&mod_q, mod_queue_rec))) {
		TAILQ_REMOVE(&mod_q, mod, qent);
		mod->op->destroy(mod->ctx);
	}
	if (ev_ctx) {
		aloe_ev_destroy(ev_ctx);
	}

	r = 0;
finally:
	return r;
}

#define admin_air192_cli_send_pat "air192_cli_send"
static int admin_air192_cli_send(int argc, char * const *argv) {
	int r, arg0, i;
	aloe_buf_t args = {0};

	for (arg0 = 0; arg0 < argc; arg0++) {
		if (strcasecmp(argv[arg0], admin_air192_cli_send_pat) == 0) {
			break;
		}
	}
	if (arg0 + 1 >= argc) {
		r = EIO;
		log_e("miss air192_cli target name\n");
		goto finally;
	}
	log_d("air192_cli target name: %s\n", argv[arg0 + 1]);

	if (aloe_buf_expand(&args, 2000, aloe_buf_flag_none) != 0) {
		r = ENOMEM;
		log_e("out of memory for args\n");
		goto finally;
	}

	aloe_buf_clear(&args);

	if ((i = arg0 + 2) < argc) {
		if (aloe_buf_printf(&args, "%s", argv[i]) <= 0) {
			r = EIO;
			log_e("args too long\n");
			goto finally;
		}
	}
	for (++i; i < argc; i++) {
		if (aloe_buf_printf(&args, " %s", argv[i]) <= 0) {
			r = EIO;
			log_e("args too long\n");
			goto finally;
		}
	}
	aloe_buf_flip(&args);

	if ((r = air192_cli_send(argv[arg0 + 1], 300,
			"%s", (char*)args.data + args.pos)) != 0) {
		goto finally;
	}
	log_d("sent %s\n", (char*)args.data + args.pos);

	r = 0;
finally:
	if (args.data) free(args.data);
	return r;
}

#define admin_air192_mqadk_send_pat "air192_mqadk_send"
static int admin_air192_mqadk_send(int argc, char * const *argv) {
	int r, arg0, i;
	aloe_buf_t args = {0};

	for (arg0 = 0; arg0 < argc; arg0++) {
		if (strcasecmp(argv[arg0], admin_air192_mqadk_send_pat) == 0) {
			break;
		}
	}
	if (arg0 + 1 >= argc) {
		r = EIO;
		log_e("miss air192_mqadk msg\n");
		goto finally;
	}
	log_d("air192_mqadk msg: %s\n", argv[arg0 + 1]);

	if (aloe_buf_expand(&args, 2000, aloe_buf_flag_none) != 0) {
		r = ENOMEM;
		log_e("out of memory for args\n");
		goto finally;
	}

	aloe_buf_clear(&args);

	i = arg0 + 1;
	if (aloe_buf_printf(&args, "%s", argv[i]) <= 0) {
		r = EIO;
		log_e("args empty or too long\n");
		goto finally;
	}
	for (++i; i < argc; i++) {
		if (aloe_buf_printf(&args, " %s", argv[i]) <= 0) {
			r = EIO;
			log_e("args too long\n");
			goto finally;
		}
	}
	aloe_buf_flip(&args);

	if ((r = air192_mqadk2_send(300,
			"%s", (char*)args.data + args.pos)) != 0) {
		goto finally;
	}
	log_d("sent %s\n", (char*)args.data + args.pos);

	r = 0;
finally:
	if (args.data) free(args.data);
	return r;
}

extern int admin_spkcal(int argc, char * const *argv);
extern int admin_fwupd(int argc, char * const *argv);
extern int admin_fwupd2(int argc, char * const *argv);
extern int admin_wificfg(int argc, char * const *argv);
extern int admin_ethcfg(int argc, char * const *argv);
extern int admin_acccfg(int argc, char * const *argv);
extern int admin_ledban(int argc, char * const *argv);

static req_t cgi_lut[] = {
	{ .re_pat = ".*admin_ledban\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_ledban},
	{ .re_pat = ".*admin_fwupd2\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_fwupd2},
	{ .re_pat = ".*admin_fwupd\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_fwupd},
	{ .re_pat = ".*cgienv\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &cgienv},
	{ .re_pat = ".*admin_spkcal\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_spkcal},
	{ .re_pat = ".*admin_wificfg\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_wificfg},
	{ .re_pat = ".*admin_ethcfg\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_ethcfg},
	{ .re_pat = ".*admin_acccfg\\.cgi", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_acccfg},
	{ .re_pat = "admin", .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin},
	{ .re_pat = admin_air192_cli_send_pat, .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_air192_cli_send},
	{ .re_pat = admin_air192_mqadk_send_pat, .re_cflags = REG_ICASE | REG_EXTENDED,
			.func = &admin_air192_mqadk_send},
	{0}
};

static req_t* req_match(const char *fmt, req_t *req_lut) {
	int r;
	char err_msg[100];
	req_t *req;

	for (req = req_lut; req->re_pat; req++) {
		if (!req->regex) {
			regex_t regex;

			if ((r = regcomp(&regex, req->re_pat, req->re_cflags)) != 0) {
				regerror(r, &regex, err_msg, sizeof(err_msg));
				err_msg[sizeof(err_msg) - 1] = '\0';
				log_e("Compile regex pattern %s, flag: %d, %s\n", req->re_pat,
						req->re_cflags, err_msg);
				return NULL;
			}
			if (!(req->regex = (regex_t*)malloc(sizeof(regex)))) {
				log_e("Out of memory for regex\n");
				regfree(&regex);
				return NULL;
			}
			memcpy(req->regex, &regex, sizeof(regex));
		}
		if ((r = regexec(req->regex, fmt, 0, NULL, 0)) == 0) {
			return req;
		} else if (r != REG_NOMATCH) {
			regerror(r, req->regex, err_msg, sizeof(err_msg));
			err_msg[sizeof(err_msg) - 1] = '\0';
			log_e("Match string %s against %s: %s\n", fmt, req->re_pat, err_msg);
		}
	}
	return NULL;
}

static const char opt_short[] = "hve:f:";
enum {
	opt_key_reflags = 0x201,
	opt_key_ctrlpath,
	opt_key_ctrlport,
	opt_key_restkey,
	opt_key_restdur,
	opt_key_restkeyhook,
	opt_key_ledconf,
	opt_key_ledset,
	opt_key_wpactrldir,
	opt_key_wificfg_ifce,
	opt_key_wificfg_ctrlpath,
	opt_key_hostname,
	opt_key_sus,
	opt_key_evehash,
	opt_key_json,
	opt_key_errno,
	opt_key_max
};
static struct option opt_long[] = {
	{"help", no_argument, NULL, 'h'},
	{"verbose", no_argument, NULL, 'v'},
	{"regex", required_argument, NULL, 'e'},
	{"file", required_argument, NULL, 'f'},
	{"reflags", required_argument, NULL, opt_key_reflags},
	{"ctrlpath", required_argument, NULL, opt_key_ctrlpath},
	{"ctrlport", required_argument, NULL, opt_key_ctrlport},
	{"restkey", required_argument, NULL, opt_key_restkey},
	{"restdur", required_argument, NULL, opt_key_restdur},
	{"restkeyhook", required_argument, NULL, opt_key_restkeyhook},
	{"ledconf", required_argument, NULL, opt_key_ledconf},
	{"ledset", required_argument, NULL, opt_key_ledset},
	{"wpactrldir", required_argument, NULL, opt_key_wpactrldir},
	{"wificfg-ifce", required_argument, NULL, opt_key_wificfg_ifce},
	{"wificfg-ctrlpath", required_argument, NULL, opt_key_wificfg_ctrlpath},
	{"hostname", optional_argument, NULL, opt_key_hostname},
	{"sus", required_argument, NULL, opt_key_sus},
	{"evehash", optional_argument, NULL, opt_key_evehash},
	{"json", required_argument, NULL, opt_key_json},
	{"errno", required_argument, NULL, opt_key_errno},
	{0},
};

static void help(int argc, char * const *argv) {
	int i;
	req_t *req;

#if 1
	for (i = 0; i < argc; i++) {
		log_d("argv[%d/%d]: %s\n", i + 1, argc, argv[i]);
	}
#endif

	fprintf(stdout,
"COMMAND\n"
"    %s [OPTIONS] [APPLET]\n"
"\n"
"OPTIONS\n"
"    -h, --help          Show help\n"
"    -v, --verbose       Verbose output (default mimic debug and more)\n"
"    -e, --regex=<RE>    Test regex pattern RE against APPLET or file if -f\n"
"        is given\n"
"    -f, --file=<FILE>   Use FILE content (regex target ...)\n"
"    --reflags=<CF>      Compilation flags for regex\n"
"    --ctrlpath=<FILE>   Start admin service, unix socket FILE for control\n"
"        interface\n"
"\n"
"    --ctrlport=<PORT>   Start admin service, bound PORT for control\n"
"        interface\n"
"\n"
#if !WITH_GPIOD
"WITH_GPIOD (disabled)\n"
#endif
"    --restkey=<GPIO>    Rest key GPIO num\n"
"    --restdur=<SEC>     Rest key duration [default %d]\n"
"    --restkeyhook=<FILE>\n"
"        Command when rest key react\n"
"    --ledconf=<FILE>    LED config for load or name to set value\n"
"        [default %s]\n"
"    --ledset=<NAME>     LED value\n"
"\n"
"    --wpactrldir=<DIR>  wpa_supplication control path\n"
"        [default %s]\n"
"    --wificfg-ifce=<IFCE>\n"
"        Wifi interface [default %s]\n"
"    --wificfg-ctrlpath=<ABSPATH>\n"
"        admin_wificfg.cgi control path [default %s]\n"
"    --hostname=[NAME]   Set hostname with NAME or content in file\n"
"        specified with -f and trailing evehash serialnum in " serialnum_cfg "\n"
"    --sus=<DELAY>       Suspend after DELAY seconds, or clear if DELAY is\n"
"        negative, issuer name specified with -f\n"
"    --evehash=[STR]     Hash from STR or content in file specified with -f\n"
"    --json=[STR]        Parse json file specified with -f then show value of\n"
"        the key specified by comma separated STR\n"
"    --errno=[NUM]       Show corresponded explanation\n"
"\n"
"Compilation flags for regex\n"
"    Comma separated token, detail refer to regcomp(3)\n"
"\n"
"        EXTENDED, ICASE, NOSUB, NEWLINE\n"
"\n", ((argc > 0) && argv && argv[0] ? argv[0] : "Program"), gpio_restdur,
			(led_conf ? led_conf : "N/A"),
			wpasup_ctrldir, wificfg_ifce, wificfg_ctrlpath);

	if (impl.log_level >= aloe_log_level_debug) {
		fprintf(stdout,
"Registered APPLET\n");
		for (req = cgi_lut, i = 1; req->re_pat; req++, i++) {
			fprintf(stdout,
"    [%d] %s\n", i, req->re_pat);
		}
		fprintf(stdout,
"\n");

		fprintf(stdout,
"Build config\n"
#ifdef USER_PREFIX
"    USER_PREFIX: " USER_PREFIX "\n"
#endif
#ifdef ADMIN_LOG_PATH
"    ADMIN_LOG_PATH: " ADMIN_LOG_PATH "\n"
#endif
"    gpio_restcmd: %s\n"
"\n", gpio_restcmd);

	// end of log_level >= debug
	}
}

int main(int argc, char **argv) {
#define OPT_LEDSET_NA -10
#define OPT_SUS_NA -24504

	int opt_op, opt_idx, opt_exit = 0, opt_re_cf = 0,
			opt_ledset = OPT_LEDSET_NA, opt_sus = OPT_SUS_NA, r, i;
	const char *opt_re = NULL, *opt_fname = NULL, *str, \
			*opt_hostname = NULL, *opt_evehash = NULL, *opt_json = NULL;
	aloe_buf_t buf = {.data = NULL}, applet_name = {.data = NULL};
	req_t *req;
	cJSON *jroot = NULL;
#ifdef ADMIN_LOG_PATH
	FILE *fp_log = NULL;
#endif
	enum {
		opt_flag_show_help = (1 << 0),
		opt_flag_show_help_if_verbose = (1 << 1),
	};

	impl.log_level = aloe_log_level_info;
	impl.log_fout = stdout;
	impl.log_ferr = stderr;

	optind = 0;
	while ((opt_op = getopt_long(argc, argv, opt_short, opt_long,
			&opt_idx)) != -1) {
		if (opt_op == 'h') {
			opt_exit |= opt_flag_show_help;
			continue;
		}
		if (opt_op == opt_key_ctrlpath) {
			ctrl_path = optarg;
			continue;
		}
		if (opt_op == opt_key_ctrlport) {
			ctrl_port = strtol(optarg, NULL, 10);
			continue;
		}
		if (opt_op == 'v') {
			if (impl.log_level < aloe_log_level_verb) impl.log_level++;
			continue;
		}
		if (opt_op == 'e') {
			opt_re = optarg;
			continue;
		}
		if (opt_op == 'f') {
			opt_fname = optarg;
			continue;
		}
		if (opt_op == opt_key_reflags) {
			aloe_buf_clear(&buf);
			if (aloe_buf_aprintf(&buf, 300, "%s", optarg) <= 0) {
				r = ENOMEM;
				log_e("Not enough memory for parse regex compilation flags\n");
				goto finally;
			}
			if (regcomp_flag_parse((char*)buf.data, &opt_re_cf) != 0) {
				log_e("Failed parse regex compilation flags for %s\n", optarg);
				opt_exit |= opt_flag_show_help_if_verbose;
			}
			continue;
		}
		if (opt_op == opt_key_restkey) {
			gpio_restkey = strtol(optarg, NULL, 10);
			continue;
		}
		if (opt_op == opt_key_restdur) {
			gpio_restdur = strtol(optarg, NULL, 10);
			continue;
		}
		if (opt_op == opt_key_restkeyhook) {
			gpio_restkeyhook = optarg;
			continue;
		}
		if (opt_op == opt_key_ledconf) {
			led_conf = optarg;
			continue;
		}
		if (opt_op == opt_key_ledset) {
			opt_ledset = strtol(optarg, NULL, 10);
			continue;
		}
		if (opt_op == opt_key_wpactrldir) {
			wpasup_ctrldir = optarg;
			continue;
		}
		if (opt_op == opt_key_wificfg_ifce) {
			wificfg_ifce = optarg;
			continue;
		}
		if (opt_op == opt_key_wificfg_ctrlpath) {
			wificfg_ctrlpath = optarg;
			continue;
		}
		if (opt_op == opt_key_hostname) {
			opt_hostname = optarg ? optarg : (char*)1;
			continue;
		}
		if (opt_op == opt_key_sus) {
			opt_sus = strtol(optarg, NULL, 10);
			continue;
		}
		if (opt_op == opt_key_evehash) {
			opt_evehash = optarg ? optarg : (char*)1;
			continue;
		}
		if (opt_op == opt_key_json) {
			opt_json = optarg;
			continue;
		}
		if (opt_op == opt_key_errno) {
			int eno = (int)strtol(optarg, NULL, 10);
			if (aloe_buf_expand(&buf, 1000, aloe_buf_flag_none) != 0) {
				r = ENOMEM;
				log_e("Not enough memory for get message\n");
				goto finally;
			}
			r = 0;
			log_i("errno %d (0x%x): %s\n", eno, eno, strerror_r(eno,
					(char*)buf.data, buf.cap));
			goto finally;
		}
#if 0
		if (opt_op == ':' || opt_op == '?') {
			log_e("Invalid argument for -%c\n", optopt);
			opt_exit |= opt_flag_show_help_if_verbose;
			continue;
		}
		if (isprint(opt_op)) {
			log_d("opt_op: %c\n", opt_op);
		} else {
			log_d("opt_op: 0x%x(%d)\n", opt_op, opt_op);
		}
#endif
	}

#if 0
	for (i = optind; i < argc; i++) {
		log_d("non-option argv[%d]: %s\n", i, argv[i]);
	}
#endif

	if (opt_exit) {
		if (opt_exit & opt_flag_show_help_if_verbose
				&& impl.log_level >= aloe_log_level_verb) {
			opt_exit |= opt_flag_show_help;
		}
		if (opt_exit & opt_flag_show_help) help(argc, argv);
		r = 1;
		goto finally;
	}

	// applet check either non-optional argument or program basename
	if (aloe_buf_aprintf(aloe_buf_clear(&buf), 300, "%s",
			argv[optind < argc ? optind : 0]) <= 0) {
		r = ENOMEM;
		log_e("Not enough memory for check basename\n");
		goto finally;
	}
	if (!(str = basename((char*)buf.data))) {
		r = EIO;
		log_e("Failed to get applet name\n");
		goto finally;
	}
	if (aloe_buf_aprintf(aloe_buf_clear(&applet_name), 300, "%s",
			str) <= 0) {
		r = ENOMEM;
		log_e("Not enough memory for applet name\n");
		goto finally;
	}

	if (opt_sus != OPT_SUS_NA) {
		if (!opt_fname) {
			r = EINVAL;
			log_e("Invalid issuer name\n");
			goto finally;
		}
		if ((r = air192_sus_set((opt_sus < 0 ? air192_mqsus_whence_null :
				air192_mqsus_whence_set), opt_sus, 100, "%s", opt_fname)) != 0) {
			log_e("Failed set sus %s\n", opt_fname);
			goto finally;
		}
		goto finally;
	}

	if (opt_ledset != OPT_LEDSET_NA) {
		if (!led_conf) {
			r = EINVAL;
			log_e("Invalid led name\n");
			goto finally;
		}
		if ((r = air192_led_set(opt_ledset, 100, "%s", led_conf)) != 0) {
			log_e("Failed set led %s\n", led_conf);
			goto finally;
		}
		goto finally;
	}

	if (opt_json) {
		static const char *sep = " \t\r\n,;:";
		char *tok, *tok_next;
		cJSON *jobj;

		if (aloe_buf_aprintf(aloe_buf_clear(&buf), 500, "%s",
				opt_json) <= 0) {
			r = ENOMEM;
			log_e("Not enough memory to json key\n");
			goto finally;
		}

		if (opt_fname) {
			const char *fns[] = {
					opt_fname,
					NULL
			};
			if ((jroot = air192_jcfg_load(fns, NULL)) == NULL) {
				r = EIO;
				log_e("Failed parse json\n");
				goto finally;
			}
		} else {
			r = EINVAL;
			log_e("Nothing to parse\n");
			goto finally;
		}

		aloe_buf_flip(&buf);
		jobj = jroot;
		for (tok = strtok_r((char*)buf.data + buf.pos, sep, &tok_next);
				tok; tok = strtok_r(NULL, sep, &tok_next)) {
			int idx;

			if (cJSON_IsArray(jobj) && (idx = (int)aloe_quoted_number_parse(
					tok, "[]", NULL)) != (int)aloe_quoted_number_invalid) {
				if (!(jobj = cJSON_GetArrayItem(jobj, idx))) {
					r = EIO;
					log_v("Out of array index: %s\n", tok);
					goto finally;
				}
				continue;
			}

			if (!(jobj = cJSON_GetObjectItem(jobj, tok))) {
				r = EIO;
				log_v("Miss key: %s\n", tok);
				goto finally;
			}
		}
		printf("%s\n", cJSON_Print(jobj));
		r = 0;
		goto finally;
	}

	if (opt_evehash) {
		uint16_t hash;
		if (opt_evehash != (char*)1) {
			if (aloe_buf_aprintf(aloe_buf_clear(&buf), 300, "%s",
					opt_evehash) <= 0) {
				r = ENOMEM;
				log_e("Not enough memory to hash\n");
				goto finally;
			}
		} else if (opt_fname) {
			if ((i = aloe_file_size(opt_fname, 0)) <= 0) {
				r = EINVAL;
				log_e("Invalid file to hash\n");
				goto finally;
			}
			if (aloe_buf_expand(aloe_buf_clear(&buf), i + 1,
					aloe_buf_flag_none) != 0) {
				r = ENOMEM;
				log_e("Not enough memory to hash\n");
				goto finally;
			}
			if (aloe_file_fread(opt_fname, aloe_buf_clear(&buf)) != i) {
				r = EIO;
				log_e("Failed read file to hash\n");
				goto finally;
			}
		} else {
			r = EINVAL;
			log_e("Nothing to hash\n");
			goto finally;
		}
		aloe_buf_flip(&buf);
		hash = air192_eve_hash4((char*)buf.data + buf.pos, buf.lmt - buf.pos);
		printf("%04X", hash);
		return 0;
	}

	if (opt_hostname) {
		char bdname[5];

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
				r = ENOMEM;
				log_e("Not enough memory to hash\n");
				goto finally;
			}
			if (air192_serial_number(aloe_buf_clear(&buf)) <= 0) {
				r = EIO;
				log_e("Failed read serialnum file\n");
				break;
			}
			snprintf(bdname, sizeof(bdname), "%04X",
					air192_eve_hash4(buf.data, buf.pos));
			bdname[sizeof(bdname) - 1] = '\0';
		} while(0);

		if (opt_hostname != (char*)1) {
			if (aloe_buf_aprintf(aloe_buf_clear(&buf), 300 + 8, "%s",
					opt_hostname) <= 0) {
				r = ENOMEM;
				log_e("Not enough memory for check hostname\n");
				goto finally;
			}
		} else if (opt_fname) {
			if ((i = aloe_file_size(opt_fname, 0)) <= 0) {
				r = EINVAL;
				log_e("Invalid file for check hostname\n");
				goto finally;
			}
			if (aloe_buf_expand(aloe_buf_clear(&buf), i + 8,
					aloe_buf_flag_none) != 0) {
				r = ENOMEM;
				log_e("Not enough memory for check hostname\n");
				goto finally;
			}
			if (aloe_file_fread(opt_fname, aloe_buf_clear(&buf)) != i) {
				r = EIO;
				log_e("Failed read file for check hostname\n");
				goto finally;
			}
		} else {
			r = EINVAL;
			log_e("Nothing to set hostname\n");
			goto finally;
		}

		// strip leading and trailing whitespace
		if (!aloe_buf_strip_text(aloe_buf_flip(&buf)) || buf.pos >= buf.lmt) {
			r = EINVAL;
			log_e("Nothing to set hostname\n");
			goto finally;
		}

		if (bdname[0]) {
			if (aloe_buf_printf(aloe_buf_replay(&buf), " %s", bdname) <= 0) {
				r = EIO;
				log_e("Failed to append eve hash\n");
				goto finally;
			}
			aloe_buf_flip(&buf);
		}

		buf.lmt = air192_hostname_refine((char*)buf.data, buf.lmt,
				'_', (char*)buf.data);

		if ((r = sethostname((char*)buf.data + buf.pos, buf.lmt - buf.pos)) != 0) {
			r = errno;
			log_e("Failed set hostname: %s\n", strerror(r));
			goto finally;
		}
		r = 0;
		goto finally;
	}

	if (opt_re && opt_fname) {
		regmatch_t mah[5];

		if ((r = aloe_file_size(opt_fname, 0)) == 0) {
			r = 2;
			goto finally;
		}
		if (r < 0) {
			log_e("Failed get regex matching file size\n");
			r = -1;
			goto finally;
		}
		if (aloe_buf_expand(&buf, r + 8, aloe_buf_flag_none) != 0) {
			log_e("Failed alloc for regex matching file\n");
			r = -1;
			goto finally;
		}
		aloe_buf_clear(&buf);
		if (aloe_file_fread(opt_fname, &buf) <= 0) {
			log_e("Failed read regex matching file\n");
			r = -1;
			goto finally;
		}
		aloe_buf_flip(&buf);
		for (r = 0; r < (int)aloe_arraysize(mah); r++) {
			mah[r].rm_so = mah[r].rm_eo = -1;
		}
		if ((r = air192_regex_test1((char*)buf.data + buf.pos, opt_re, opt_re_cf,
				aloe_arraysize(mah), mah)) < 0) {
			goto finally;
		}
		if (r == REG_NOMATCH) {
			r = 2;
			goto finally;
		}
		for (r = 0; r < (int)aloe_arraysize(mah); r++) {
			if (mah[r].rm_so == -1) continue;
			log_d("match[%d] %d..%d\n", r, mah[r].rm_so, mah[r].rm_eo);
		}
		r = 0;
		goto finally;
	}

	log_d("APPLET: %s\n", (char*)applet_name.data);

	if (opt_re) {
		r = air192_regex_test1((char*)applet_name.data, opt_re, opt_re_cf, 0, NULL);
		goto finally;
	}

#ifdef ADMIN_LOG_PATH
#  if 0 // reply cwd
	{
		if (aloe_buf_expand(&buf, 300, aloe_buf_flag_none) != 0) {
			r = ENOMEM;
			log_e("Not enough memory for current dir name\n");
			goto finally;
		}
		aloe_buf_clear(&buf);
		if (!getcwd((char*)buf.data, buf.lmt)) {
			r = errno;
			log_e("Failed get current directory: %s\n", strerror(r));
			goto finally;
		}
		printf("\n%s #%d, cwd: %s, ADMIN_LOG_PATH: %s\n", __func__, __LINE__
				, (char*)buf.data, ADMIN_LOG_PATH);
	}
#  endif // reply cwd

	if ((r = _aloe_file_size(ADMIN_LOG_PATH, 0)) == -1) {
		r = EIO;
		log_e("Failed to check cgi debug file existence\n");
		goto finally;
	}
	if (r >= 0 && (fp_log = fopen(ADMIN_LOG_PATH, "a+"))) {
		impl.log_fout = impl.log_ferr = fp_log;
		if (impl.log_level < aloe_log_level_verb) impl.log_level++;
	}
#endif // ADMIN_LOG_PATH

	if ((req = req_match((char*)applet_name.data, cgi_lut))) {
		r = (*req->func)(argc, argv);
		goto finally;
	}

	r = 0;
finally:
#define _reqlut_free(_lut) for (req = (_lut); req->re_pat; req++) { \
		if (req->regex) regfree(req->regex); \
	}
	_reqlut_free(cgi_lut);
	if (buf.data) free(buf.data);
	if (applet_name.data) free(applet_name.data);
#ifdef ADMIN_LOG_PATH
	if (fp_log) fclose(fp_log);
#endif
	if (jroot) cJSON_Delete(jroot);
	return r;
}
