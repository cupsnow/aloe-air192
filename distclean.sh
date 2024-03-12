#!/bin/bash
SELF=${BASH_SOURCE[0]}
SELFDIR=`dirname $SELF`
# SELFDIR=`realpath -L -s $SELFDIR`
SELFDIR=`cd $SELFDIR && pwd -L`

cd $SELFDIR && rm -rf autom4te.cache build docs/html aclocal.m4 \
    aloe_ev.doxyfile.bak compile config.h.in~ configure depcomp install-sh \
    Makefile Makefile.in missing \
    ar-lib config.guess config.sub ltmain.sh


