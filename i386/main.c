/*
    This code is public domain and comes with no warranty.
    You are free to do whatever you want with it. You can
    contact me at lolisamurai@tfwno.gf but don't expect any
    support.
    I hope you will find the code useful or at least
    interesting to read. Have fun!
    -----------------------------------------------------------
    This file is part of "weeb", a http mirror for gopherspace
    written in C without the standard C library.
*/

#define I386
#include "syscalls.h"

typedef unsigned long long int u64;
typedef unsigned int           u32;
typedef unsigned short int     u16;
typedef unsigned char          u8;

typedef long long int i64;
typedef int           i32;
typedef short int     i16;
typedef signed char   i8;

typedef i32 intptr;
typedef u32 uintptr;

#include "../weeb.c"

int main(int argc, char const* argv[]) {
    return weeb(argc, argv);
}
