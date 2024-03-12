# 
# Copyright 2023, Dexatek Technology Ltd.
# This is proprietary information of Dexatek Technology Ltd.
# All Rights Reserved. Reproduction of this documentation or the
# accompanying programs in any manner whatsoever without the written
# permission of Dexatek Technology Ltd. is strictly forbidden.
# 
# @author joelai
# 
bin_PROGRAMS =
noinst_PROGRAMS =
lib_LTLIBRARIES =

AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/include
AM_LDFLAGS =
LDADD = 
# LDADD += $(top_srcdir)/mod.ld

if ENABLE_DEBUG
AM_CPPFLAGS += -g -funwind-tables
AM_LDFLAGS += -rdynamic
else
AM_CPPFLAGS += -O -ffunction-sections -fdata-sections
AM_LDFLAGS += -Wl,--gc-sections
endif

lib_LTLIBRARIES += libadmin.la
libadmin_la_SOURCES = misc.c ev.c unitest.c nl.cpp

if ENABLE_AIR192
libadmin_la_SOURCES += misc_air192.cpp
endif

if WITH_FFMPEG
libadmin_la_SOURCES += misc_ffmpeg.cpp
endif

libadmin_la_SOURCES += app_msg_queue.c \
  wifi_manager.c WPACtrl.c

# if WITH_FDKAAC
# libadmin_la_SOURCES += misc_fdkaac.cpp
# endif

compatopenbsdsysincludedir= $(includedir)/admin/compat/openbsd/sys
compatopenbsdsysinclude_HEADERS=include/admin/compat/openbsd/sys/queue.h 
compatopenbsdsysinclude_HEADERS+=include/admin/compat/openbsd/sys/tree.h 

adminincludedir= $(includedir)/admin
admininclude_HEADERS=include/admin/ev.h include/admin/admin.h \
  include/admin/nl.h \
  include/admin/air192.h include/admin/sa7715.h \
  include/admin/wifi_manager.h include/admin/WPACtrl.h \
  include/admin/app_msg_queue.h \
  include/admin/app_msg_define.h

bin_PROGRAMS += admin
admin_SOURCES = admin.cpp mod_cli.cpp \
  fwupd.cpp \
  spkcal.cpp \
  wificfg.cpp \
  ethcfg.cpp \
  acccfg.cpp \
  ledban.cpp

admin_SOURCES += mod_template1.cpp

admin_LDADD = libadmin.la -lcjson
admin_LDFLAGS =
# admin_LDFLAGS += -static

admin_LDADD += -luriparser

if WITH_GPIOD
admin_SOURCES += mod_gpio.cpp
admin_LDADD += -lgpiod
endif

noinst_PROGRAMS += test1
test1_SOURCES = test1.cpp
test1_LDADD = libadmin.la -lcjson
test1_LDFLAGS =
# test1_LDFLAGS += -static

test1_LDADD += -luriparser

if WITH_GPIOD
test1_LDADD += -lgpiod
endif

noinst_PROGRAMS += testi2c1
testi2c1_SOURCES = testi2c1.cpp
testi2c1_LDADD = libadmin.la -lcjson
testi2c1_LDFLAGS =
# testi2c1_LDFLAGS += -static

testi2c1_LDADD += -luriparser

if WITH_GPIOD
testi2c1_LDADD += -lgpiod
endif

noinst_PROGRAMS += testssid1
testssid1_SOURCES = testssid1.cpp
testssid1_LDADD = libadmin.la -lcjson
testssid1_LDFLAGS =
# testssid1_LDFLAGS += -static

# testssid1_LDADD += -luriparser

if WITH_GPIOD
testssid1_LDADD += -lgpiod
endif

noinst_PROGRAMS += testnl1
testnl1_SOURCES = testnl1.cpp
testnl1_LDADD = libadmin.la -lcjson
testnl1_LDFLAGS =
# testnl1_LDFLAGS += -static

# testnl1_LDADD += -luriparser

if WITH_GPIOD
testnl1_LDADD += -lgpiod
endif
