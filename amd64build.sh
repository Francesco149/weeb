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

exename=weeb

gcc \
    amd64/start.S amd64/main.c \
    -std=c89 -pedantic -O2 \
    -Wall -Werror \
    -fdata-sections \
    -fno-stack-protector \
    -Wl,--gc-sections \
    -fno-unwind-tables \
    -fno-asynchronous-unwind-tables \
    -Wa,--noexecstack \
    -fno-builtin \
    -nostdlib \
    -o $exename \
\
&& strip \
    -R .eh_frame \
    -R .eh_frame_hdr \
    -R .comment \
    $exename
