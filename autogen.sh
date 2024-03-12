#!/bin/bash
SELF=${BASH_SOURCE[0]}
SELFDIR=`dirname $SELF`
# SELFDIR=`realpath -L -s $SELFDIR`
SELFDIR=`cd $SELFDIR && pwd -L`

if [ ! -x "$SELFDIR/configure" ]; then
  if [ ! -e "$SELFDIR/config.h.in" ]; then
    cd $SELFDIR && autoheader -f -Iinclude
  fi
  cd $SELFDIR && autoreconf -fiv -Iinclude
fi

