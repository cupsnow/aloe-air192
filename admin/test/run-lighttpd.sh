#!/bin/bash
SELF=${BASH_SOURCE[0]}
SELFDIR=`dirname $SELF`
# SELFDIR=`realpath -L -s $SELFDIR`
SELFDIR=`cd $SELFDIR && pwd -L`

log_e () {
  echo "ERROR $*"
}

log_d () {
  echo "Debug $*"
}

# join ":" "$PWD" "$PATH"
join () {
  [ $# -ge 2 ] || return
  local sep="$1"
  shift
  local str="$1"
  shift
  while test -n "$1"; do
    str="${str}${sep}${1}"
    shift
  done
  echo "$str"
}

run_cmd () {
  log_d "Execute: $*"
  $@
}

help () {
cat <<-EOFHELP

USAGE
  $(basename $0) [OPTIONS] <lighttpd program> -- [lighttpd options ...]

OPTIONS
  -h                   Show this help
  -c, --config=CFG     Set config file (Default: cfg.cfg)
  -l, --lighttpd=PATH  Path for lighttpd

EOFHELP
}

options=$(getopt -o hc:l: -l help,config: -- "$@")
log_d "options: ${options}"
[ $? -eq 0 ] || {
  log_e "Incorrect options provided"
  help
  exit 1
}
eval set -- "$options"
while true; do
    case "$1" in
    -h)
        help
        exit 1
        ;;
    -c|--config)
        shift
        _priv_cfg=$1
        ;;
    -l|--lighttpd)
        shift
        _priv_httpd=$1
        ;;
    --)
        shift
        break
        ;;
    esac
    shift
done

# test join
# join "$@"
# exit 1

# Check httpd executable
[ -z "$_pri_httpd" ] && [ -n "${DESTDIR}" ] && _pri_httpd=$(type -P ${DESTDIR}/sbin/lighttpd)
[ -z "$_pri_httpd" ] && _pri_httpd=$(type -P lighttpd)
[ -n "$_pri_httpd" ] || { log_e "Miss lighttpd program"; help; exit 1; }
_pri_httpd="$(realpath -L -m -s ${_pri_httpd})"
log_d "lighttpd program: $_pri_httpd"

# Check httpd runtime library path
_pri_httpd_lib="$(realpath -L -m -s ${_pri_httpd%/sbin/$(basename $_pri_httpd)}/lib)"
[ -d "${_pri_httpd_lib}" ] || _pri_httpd_lib=
log_d "lighttpd module path: ${_pri_httpd_lib}"

export LD_LIBRARY_PATH=`join : "${_pri_httpd_lib}" \
  "$LD_LIBRARY_PATH"`

log_d "DESTDIR: $DESTDIR"
log_d "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"

run_cmd $_pri_httpd -f ${SELFDIR}/lighttpd.conf ${_pri_httpd_lib:+-m ${_pri_httpd_lib}} \
    "$@"
