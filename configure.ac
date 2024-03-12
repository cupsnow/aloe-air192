# 
# Copyright 2023, Dexatek Technology Ltd.
# This is proprietary information of Dexatek Technology Ltd.
# All Rights Reserved. Reproduction of this documentation or the
# accompanying programs in any manner whatsoever without the written
# permission of Dexatek Technology Ltd. is strictly forbidden.
# 
# @author joelai
# 
AC_PREREQ([2.69])
AC_INIT([admin], [0.1.1], [joe@levender.local])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([misc.c])
AC_CONFIG_HEADERS([config.h])

# override preset output variable CFLAGS between AC_INIT and AC_PROG_CC
: ${CFLAGS="-Wall -pthread"}
: ${CXXFLAGS="-Wall -pthread"}
: ${LDFLAGS="-pthread"}

# Checks for programs.
AC_PROG_CC([gcc])
AC_PROG_CC_C99
AC_PROG_CXX([g++ gcc])

AC_PROG_RANLIB

# archiver requires 'AM_PROG_AR' in 'configure.ac'
AM_PROG_AR

AC_PROG_LIBTOOL

# use $(LN_S) in Makefile.am
AC_PROG_LN_S

# $(MKDIR_P)
AC_PROG_MKDIR_P

# --enable-air192
AC_ARG_ENABLE([air192],
  [AS_HELP_STRING([--enable-air192], [enable air192, @<:@no@:>@])],
  [],
  [enable_air192=no])
AC_MSG_CHECKING([enable air192])
AC_MSG_RESULT([$enable_air192])
AS_IF([test "x$enable_air192" != "xno"],
  [AC_DEFINE([ENABLE_AIR192], [1], [enable air192])],
  [])
AM_CONDITIONAL([ENABLE_AIR192], [test "x$enable_air192" != "xno"])

# --enable-debug
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [enable debugging, @<:@no@:>@])],
  [],
  [enable_debug=no])
AC_MSG_CHECKING([enable debugging])
AC_MSG_RESULT([$enable_debug])
AS_IF([test "x$enable_debug" != "xno"],
  [AC_DEFINE([ENABLE_DEBUG], [1], [enable debugging])],
  [])
AM_CONDITIONAL([ENABLE_DEBUG], [test "x$enable_debug" != "xno"])

# USER_PREFIX=
AC_ARG_VAR([USER_PREFIX], [user writable path])
AC_MSG_CHECKING([user writable path])
AC_MSG_RESULT([$USER_PREFIX])
AS_IF([test "x$USER_PREFIX" != "x"],
  [AC_DEFINE_UNQUOTED([USER_PREFIX], ["$USER_PREFIX"], [user writable path])],
  [])
# AM_CONDITIONAL([USER_PREFIX], [test "x$USER_PREFIX" != "x"])

# Checks for libraries.
# AC_CHECK_LIB([z], [deflate], [dummy=yes])
# AC_SEARCH_LIBS([deflate], [z])
# AC_CHECK_LIB([rt], [mq_open], [dummy=yes])
AC_SEARCH_LIBS([mq_open], [rt])

AC_SEARCH_LIBS([sqrt], [m])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# package uriparser
AC_CHECK_HEADERS([uriparser/Uri.h], [], [enable_uriparser=no])
AC_CHECK_LIB([uriparser], [uriParseSingleUriA], [dummy=yes], [enable_uriparser=no])
AS_IF([test "x$enable_uriparser" != "xno"], [
  AC_DEFINE([WITH_URIPARSER], [1], [build with uriparser])
], [])
AM_CONDITIONAL([WITH_URIPARSER], [test "x$enable_uriparser" != "xno"])

# package cjson
AC_CHECK_HEADERS([cjson/cJSON.h], [], [enable_cjson=no])
AC_CHECK_LIB([cjson], [cJSON_Delete], [dummy=yes], [enable_cjson=no])
AS_IF([test "x$enable_cjson" != "xno"], [
  AC_DEFINE([WITH_CJSON], [1], [build with cJSON])
], [])
AM_CONDITIONAL([WITH_CJSON], [test "x$enable_cjson" != "xno"])

# package gpiod
AC_CHECK_HEADERS([gpiod.h], [], [enable_gpiod=no])
AC_CHECK_LIB([gpiod], [gpiod_chip_open], [dummy=yes], [enable_gpiod=no])
AS_IF([test "x$enable_gpiod" != "xno"], [
  AC_DEFINE([WITH_GPIOD], [1], [build with gpiod])
], [])
AM_CONDITIONAL([WITH_GPIOD], [test "x$enable_gpiod" != "xno"])

# package wpa_client (from wpa_supplicant)
AC_CHECK_HEADERS([wpa_ctrl.h], [], [enable_wpactrl=no])
AC_CHECK_LIB([wpa_client], [wpa_ctrl_open], [dummy=yes], [enable_wpactrl=no])
AS_IF([test "x$enable_wpactrl" != "xno"], [
  AC_DEFINE([WITH_WPACTRL], [1], [build with wpa_client])
], [])
AM_CONDITIONAL([WITH_WPACTRL], [test "x$enable_wpactrl" != "xno"])

# perf_events
AC_CHECK_HEADERS([linux/perf_event.h], [], [enable_pref_events=no])
AS_IF([test "x$enable_pref_events" != "xno"], [
  AC_DEFINE([WITH_PREF_EVENTS], [1], [build with pref_events])
], [])
AM_CONDITIONAL([WITH_PREF_EVENTS], [test "x$enable_pref_events" != "xno"])

# package ffmpeg
AC_CHECK_HEADERS([libavutil/avutil.h \
  libavcodec/avcodec.h \
  libavformat/avformat.h \
  libswresample/swresample.h], [], [enable_ffmpeg=no])
# libswresample dep: libavutil
# libavcodec dep: libswresample libavutil libz
# libavformat dep: libavcodec libavutil
AC_SEARCH_LIBS(av_frame_alloc, [avutil], [], [enable_ffmpeg=no], [-pthread])
AC_SEARCH_LIBS(swr_init, [swresample], [], [enable_ffmpeg=no])
AC_SEARCH_LIBS(avcodec_free_context, [avcodec], [], [enable_ffmpeg=no])
AC_SEARCH_LIBS(avformat_open_input, [avformat], [], [])

AC_MSG_CHECKING([build with ffmpeg])
AS_IF([test "x$enable_ffmpeg" != "xno"], [
  AC_MSG_RESULT([candidate])
  AC_DEFINE([WITH_FFMPEG], [1], [build with ffmpeg])
], [
  AC_MSG_RESULT([$enable_ffmpeg])
])
AM_CONDITIONAL([WITH_FFMPEG], [test "x$enable_ffmpeg" != "xno"])

# todo: https://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/External-Software.html#External-Software
# # libfdk-aac
# AC_CHECK_HEADERS([fdk-aac/aacdecoder_lib.h], [], [enable_fdkaac=no])
# AC_SEARCH_LIBS(aacDecoder_Open, [fdk-aac], [], [enable_fdkaac=no])
# 
# AC_MSG_CHECKING([build with fdkaac])
# AS_IF([test "x$enable_fdkaac" != "xno"], [
#   AC_MSG_RESULT([candidate])
#   AC_DEFINE([WITH_FDKAAC], [1], [build with fdkaac])
# ], [
#   AC_MSG_RESULT([$enable_fdkaac])
# ])
# AM_CONDITIONAL([WITH_FDKAAC], [test "x$enable_fdkaac" != "xno"])

AC_C_FLEXIBLE_ARRAY_MEMBER

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([memmove])

# AC_MSG_NOTICE([LIBS: $LIBS])

AC_CONFIG_FILES([
	Makefile
])

AC_OUTPUT
