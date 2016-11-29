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

#define SYS_read            0
#define SYS_write           1
#define SYS_open            2
#define SYS_close           3
#define SYS_stat            4
#define SYS_rt_sigaction    13
#define STUB_rt_sigreturn   15
#define SYS_socket          41
#define SYS_connect         42
#define SYS_accept          43
#define SYS_shutdown        48
#define SYS_bind            49
#define SYS_listen          50
#define SYS_setsockopt      54
#define SYS_fork            57
#define SYS_exit            60
#define SYS_wait4           61
#define SYS_rename          82
#define SYS_mkdir           83
#define SYS_clock_gettime   228
#define SYS_utimensat       280
