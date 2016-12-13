#!/bin/sh

#   This code is public domain and comes with no warranty.
#   You are free to do whatever you want with it. You can
#   contact me at lolisamurai@tfwno.gf but don't expect any
#   support.
#   I hope you will find the code useful or at least
#   interesting to read. Have fun!
#   -----------------------------------------------------------
#   This file is part of "weeb", a http mirror for gopherspace
#   written in C without the standard C library.

exename="weeb"
archname=${1:-amd64}

if [ -e $archname/flags.sh ]; then
    source $archname/flags.sh
fi

gcc -std=c89 -pedantic -s -O2 -Wall -Werror \
    -nostdlib \
    -fno-unwind-tables \
    -fno-asynchronous-unwind-tables \
    -fdata-sections \
    -Wl,--gc-sections \
    -Wa,--noexecstack \
    -fno-builtin \
    -fno-stack-protector \
    $COMPILER_FLAGS \
    $archname/start.S $archname/main.c \
    -o $exename \
\
&& strip -R .comment $exename
