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

#define WEEB_VER "weeb 0.1.5"

#define WEEB_TIMEOUT       30 /* seconds */
#define WEEB_BACKLOG       10 /* max pending connections */
#define WEEB_CACHE_LIFE    (60 * 60) /* seconds */

#define WEEB_TITLE         "Franc[e]sco's Gopherspace"
#define WEEB_GOPHER_DOMAIN "sdf.org"
#define WEEB_GOPHER_IP     {192, 94, 73, 15} /* sdf.org's ip */
#define WEEB_GOPHER_ROOT   "/users/loli"
#define WEEB_GOPHER_PROXY  "gopher.floodgap.com/gopher/gw?a="

/* ------------------------------------------------------------- */

#ifdef WEEB_NOCACHE
#undef WEEB_CACHE_LIFE
#define WEEB_CACHE_LIFE 0
#endif

typedef intptr syscall_t;

void* syscall(syscall_t number);
void* syscall1(syscall_t number, void* arg);
void* syscall2(syscall_t number, void* arg1, void* arg2);

void* syscall3(
    syscall_t number,
    void* arg1,
    void* arg2,
    void* arg3);

void* syscall4(
    syscall_t number,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4);

void* syscall5(
    syscall_t number,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4,
    void* arg5);

/* ------------------------------------------------------------- */

typedef i32 b32;

#define internal static
#define globvar static

#define EIO 5

internal
void memeset(void* dst, u8 value, intptr nbytes)
{
    intptr i;

    if (nbytes % sizeof(intptr) == 0)
    {
        intptr* dst_chunks = (intptr*)dst;
        intptr chunk;
        u8* chunk_raw = (u8*)&chunk;

        for (i = 0; i < sizeof(intptr); ++i) {
            chunk_raw[i] = value;
        }

        for (i = 0; i < nbytes / sizeof(intptr); ++i) {
            dst_chunks[i] = chunk;
        }
    }
    else
    {
        u8* dst_bytes = (u8*)dst;

        for (i = 0; i < nbytes; ++i) {
            dst_bytes[i] = value;
        }
    }
}

internal
void memecpy(void* dst, void const* src, intptr nbytes)
{
    intptr i = 0;

    if (nbytes % sizeof(intptr) == 0)
    {
        intptr* dst_chunks = (intptr*)dst;
        intptr* src_chunks = (intptr*)src;

        for (; i < nbytes / sizeof(intptr); ++i) {
            dst_chunks[i] = src_chunks[i];
        }
    }
    else
    {
        u8* dst_bytes = (u8*)dst;
        u8* src_bytes = (u8*)src;

        for (; i < nbytes; ++i) {
            dst_bytes[i] = src_bytes[i];
        }
    }
}

internal
b32 streq(char const* a, char const* b)
{
    for (; *a && *b; ++a, ++b)
    {
        if (*a != *b) {
            return 0;
        }
    }

    return *a == *b;
}

internal
b32 strneq(char const* a, char const* b, intptr len)
{
    intptr i;

    for (i = 0; i < len; ++i)
    {
        if (a[i] != b[i]) {
            return 0;
        } else if (!a[i]) {
            return 1;
        }
    }

    return 1;
}

internal
b32 cisws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

internal
b32 isws(char const* s)
{
    for (; *s && cisws(*s); ++s);
    return !*s;
}

internal
intptr strlen(char const* str)
{
    char const* p;
    for(p = str; *p; ++p);
    return p - str;
}

internal
intptr strcpy(char* dst, char const* src)
{
    intptr srclen = strlen(src);
    memecpy(dst, src, srclen);
    dst[srclen] = 0;
    return srclen;
}

internal
intptr uitoa(
    u8 base,
    uintptr val,
    char* buf,
    intptr width,
    char filler)
{
    char c;
    char* p = buf;
    intptr res;

    if (!base) {
        return 0;
    }

    if (base > 16) {
        return 0;
    }

    do
    {
        u8 digit = val % base;
        val /= base;
        *p++ = "0123456789abcdef"[digit];
    }
    while(val);

    while (p - buf < width) {
        *p++ = filler;
    }

    res = p - buf;
    *p-- = 0;

    while (p > buf)
    {
        /* flip the string */
        c = *p;
        *p-- = *buf;
        *buf++ = c;
    }

    return res;
}

internal
intptr itoa(
    u8 base,
    intptr val,
    char* buf,
    intptr width,
    char filler)
{
    if (val < 0) {
        *buf++ = '-';
        val = -val;
    }

    return uitoa(base, (uintptr)val, buf, width, filler);
}

/* ------------------------------------------------------------- */

#define PATH_MAX 4096
#define PATH_MAX_LEVEL (PATH_MAX / 2 + 1)

/* a non-null terminated const string. used to trim or tokenize
   strings that must not be modified without creating a copy */
typedef struct
{
    char const* p;
    intptr len;
}
cstr;

internal
b32 cstrneq(cstr const* a, cstr const* b, intptr n) {
    return strneq(a->p, b->p, n);
}

internal
b32 cstreq(cstr const* a, cstr const* b)
{
    if (a->len != b->len) {
        return 0;
    }

    return cstrneq(a, b, a->len);
}

/* copies the path's elements to dst, ignoring any double slashes.
   does not handle ".." or ".".
   if path exceeds dst_nelements number of elements, it will be
   truncated.
   the dst array will be null terminated (p and len will be zero
   on the last element) */
internal
void pathn(
    char const* path,
    cstr* dst,
    intptr dst_nelements)
{
    char const* p = path;
    cstr* d = dst;

    while (*p)
    {
        if (d - dst >= dst_nelements - 1) {
            break;
        }

        /* skip until first forward slash */
        d->p = p;
        for (; *p && *p != '/'; ++p);

        d->len = p - path;
        ++d;

        /* skip remaining slashes */
        for (; *p && *p == '/'; ++p);

        path = p;
    }

    memeset(d, 0, sizeof(cstr));
}

/* returns the number of elements in a path generated by pathn */
internal
intptr pathlen(cstr const* path)
{
    cstr const* p = path;
    for (; p->p; ++p);
    return p - path;
}

/* compares two arrays of path elements created with pathn and
   returns true of p is a child of base */
internal
b32 pathchld(cstr const* p, cstr const* base)
{
    for (; p->p && base->p; ++p, ++base)
    {
        if (!cstreq(p, base)) {
            return 0;
        }
    }

    return p->p == base->p || p->p;
}

/* ------------------------------------------------------------- */

internal
void exit(int code) {
    syscall1(SYS_exit, (void*)(intptr)code);
}

typedef i32 pid_t;

#define WNOHANG 1

internal
pid_t waitpid(pid_t upid, u32* status, int options)
{
    return (pid_t)(intptr)
        syscall4(
            SYS_wait4,
            (void*)(intptr)upid,
            status,
            (void*)(intptr)options,
            0
        );
}

internal
pid_t fork() {
    return (pid_t)(intptr)syscall(SYS_fork);
}

#define SIGINT  2
#define SIGCHLD 17

#define SA_RESTART   0x10000000
#define SA_NOCLDSTOP 0x00000001
#define SA_RESTORER  0x04000000

/* this is a huge bitmask. the size is straight from signal.h */
#define SIGSET_NWORDS 8
typedef intptr sigset_t[1024 / (SIGSET_NWORDS * sizeof(intptr))];

typedef void (sighandler)(i32 signum);

typedef struct
{
    sighandler* handler; /* actually an union but who cares */
    u32 flags;
    void (*restorer)();
    sigset_t mask; /* bitmask of signals set */
}
sigaction;

#ifdef STUB_rt_sigreturn
internal
void rt_sigreturn() {
    syscall(STUB_rt_sigreturn);
}
#endif

internal
int rt_sigaction(
    i32 signum,
    sigaction* act,
    sigaction* oldact)
{
#ifdef STUB_rt_sigreturn
    act->flags |= SA_RESTORER;
    act->restorer = rt_sigreturn;
#endif

    return (int)(intptr)
        syscall4(
            SYS_rt_sigaction,
            (void*)(intptr)signum,
            act,
            oldact,
            (void*)SIGSET_NWORDS
        );
}

internal
int signal(i32 signum, sighandler* handler, sighandler** prev)
{
    int res;
    sigaction sa, prevsa;

    memeset(&sa, 0, sizeof(sigaction));
    sa.handler = handler;
    res = rt_sigaction(signum, &sa, &prevsa);

    if (prev) {
        *prev = prevsa.handler;
    }

    return res;
}

#define stdout 1
#define stderr 2

#define O_RDONLY      00
#define O_WRONLY      01
#define O_RDWR        02
#define O_CREAT     0100
#define O_NOCTTY    0400
#define O_NONBLOCK 04000
#define O_TRUNC    01000

typedef u32 mode_t;

internal
int open(char const* filename, u32 flags, mode_t mode)
{
    return (int)(intptr)
        syscall3(
            SYS_open,
            (void*)filename,
            (void*)(intptr)flags,
            (void*)(intptr)mode
        );
}

internal
void close(int fd) {
    syscall1(SYS_close, (void*)(intptr)fd);
}

typedef intptr time_t;
typedef intptr syscall_slong_t;
typedef intptr suseconds_t;

typedef struct
{
    time_t sec;
    suseconds_t usec;
}
timeval;

typedef struct
{
    time_t sec;
    syscall_slong_t nsec;
}
timespec;

#define AT_FDCWD -100

internal
int utimensat(int dirfd, char const* pathname,
    timespec const* times, u32 flags)
{
    return (int)(intptr)
        syscall4(
            SYS_utimensat,
            (void*)(intptr)dirfd,
            (void*)pathname,
            (void*)times,
            (void*)(intptr)flags
        );
}

internal
int touch(char const* filename)
{
    int res;

    int fd = open(
        filename,
        O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK,
        0666
    );

    if (fd < 0) {
        return fd;
    }

    res = utimensat(AT_FDCWD, filename, 0, 0);
    close(fd);

    return res;
}

internal
intptr write(int fd, void const* data, intptr nbytes)
{
    return (intptr)
        syscall3(
            SYS_write,
            (void*)(intptr)fd,
            (void*)data,
            (void*)nbytes
        );
}

internal
intptr read(int fd, void* data, intptr nbytes)
{
    return (intptr)
        syscall3(
            SYS_read,
            (void*)(intptr)fd,
            data,
            (void*)nbytes
        );
}

typedef struct
{
#ifdef AMD64
    u64 dev;
    u64 ino;
    u64 nlink;
    mode_t mode;
    u32 uid;
    u32 gid;
    i32 __pad0;
    u64 rdev;
    intptr size;
    i64 blksize;
    i64 blocks;
    timespec atim;
    timespec mtim;
    timespec ctim;
    intptr __unused[3];
#else
    u32 dev;
    u32 ino;
    u16 mode;
    u16 nlink;
    u16 uid;
    u16 gid;
    u32 rdev;
    u32 size;
    u32 blksize;
    u32 blocks;
    timespec atim;
    timespec mtim;
    timespec ctim;
    intptr __unused[2];
#endif
}
stat_info;

internal
int stat(char const* path, stat_info* s)
{
    return (int)(intptr)
        syscall2(
            SYS_stat,
            (void*)path,
            s
        );
}

internal
int rename(char const* frm, char const* to)
{
    return (int)(intptr)
        syscall2(SYS_rename, (void*)frm, (void*)to);
}

internal
int mkdir(char const* path, mode_t mode)
{
    return (int)(intptr)
        syscall2(
            SYS_mkdir,
            (void*)path,
            (void*)(intptr)mode
        );
}

/* recursively creates path, ignoring all failures. strips nstrip
   elements at the end of path. */
internal
void mkdir_p(char const* path, mode_t mode, intptr nstrip)
{
    cstr npath[PATH_MAX_LEVEL];
    cstr* p;
    char tmp[PATH_MAX];
    char* t = tmp;

    pathn(path, npath, PATH_MAX_LEVEL);

    for (p = npath; p->p; ++p);
    --p;

    for (; nstrip; --nstrip)
    {
        p->p = 0;
        p->len = 0;
        --p;
    }

    for (p = npath; p->p; ++p)
    {
        memecpy(t, p->p, p->len);
        t += p->len;
        *t = 0;

        mkdir(tmp, mode);
        *t++ = '/';
    }
}

internal
intptr fcpy(int dstfd, int srcfd, u8* buf, u32 bufsize)
{
    intptr res = 0;

    while (1)
    {
        intptr n, towrite;

        n = read(srcfd, buf, bufsize);
        if (!n) {
            break;
        }
        else if (n < 0) {
            return n;
        }

        towrite = n;

        n = write(dstfd, buf, towrite);
        if (n != towrite) {
            return -EIO;
        }
        else if (n < 0) {
            return n;
        }

        res += n;
    }

    return res;
}

internal
intptr fprln(int fd, char const* str) {
    return write(fd, str, strlen(str)) + write(fd, "\n", 1);
}

internal
intptr fputs(int fd, char const* str) {
    return write(fd, str, strlen(str));
}

internal
intptr puts(char const* str) {
    return fputs(stdout, str);
}

internal
intptr prln(char const* str) {
    return fprln(stdout, str);
}

internal
intptr errln_impl(char const* func, char const* msg)
{
    return fputs(stderr, "ORERU ") +
           fputs(stderr, func) +
           fputs(stderr, ": ") +
           fprln(stderr, msg);
}

#define errln(msg) errln_impl(__FUNCTION__, msg)
#define kms(msg) { errln(msg); exit(0); }

/* ------------------------------------------------------------- */

#define AF_INET 2
#define SOCK_STREAM 1

#define IPPROTO_TCP 6

typedef struct
{
    u16 family;
    u16 port; /* NOTE: this is big endian!!!!!!! use letobe16u */
    u32 addr;
    u8  zero[8];
}
sockaddr_in;

internal
u16 letobe16u(u16 v) {
    return (v << 8) | (v >> 8);
}

#ifdef SYS_socketcall
/* i386 multiplexes socket calls through socketcall */
#define SYS_SOCKET      1
#define SYS_BIND        2
#define SYS_CONNECT     3
#define SYS_LISTEN      4
#define SYS_ACCEPT      5
#define SYS_SHUTDOWN   13
#define SYS_SETSOCKOPT 14

internal
int socketcall(u32 call, void* args)
{
    return (int)(intptr)
        syscall2(
            SYS_socketcall,
            (void*)(intptr)call,
            args
        );
}
#endif

internal
int socket(u16 family, i32 type, i32 protocol)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall3(
            SYS_socket,
            (void*)(intptr)family,
            (void*)(intptr)type,
            (void*)(intptr)protocol
        );
#else
    void* args[3];
    args[0] = (void*)(intptr)family;
    args[1] = (void*)(intptr)type;
    args[2] = (void*)(intptr)protocol;

    return socketcall(SYS_SOCKET, args);
#endif
}

internal
int bind(int sockfd, sockaddr_in const* addr)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall3(
            SYS_bind,
            (void*)(intptr)sockfd,
            (void*)addr,
            (void*)sizeof(sockaddr_in)
        );
#else
    void* args[3];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)addr;
    args[2] = (void*)sizeof(sockaddr_in);

    return socketcall(SYS_BIND, args);
#endif
}

internal
int listen(int sockfd, int backlog)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall2(
            SYS_listen,
            (void*)(intptr)sockfd,
            (void*)(intptr)backlog
        );
#else
    void* args[2];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)(intptr)backlog;

    return socketcall(SYS_LISTEN, args);
#endif
}

internal
int accept(int sockfd, sockaddr_in const* addr)
{
    int addrlen = sizeof(sockaddr_in);
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall3(
            SYS_accept,
            (void*)(intptr)sockfd,
            (void*)addr,
            &addrlen
        );
#else
    void* args[3];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)addr;
    args[2] = &addrlen;

    return socketcall(SYS_ACCEPT, args);
#endif
}

internal
int connect(int sockfd, sockaddr_in const* addr)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall3(
            SYS_connect,
            (void*)(intptr)sockfd,
            (void*)addr,
            (void*)sizeof(sockaddr_in)
        );
#else
    void* args[3];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)addr;
    args[2] = (void*)sizeof(sockaddr_in);

    return socketcall(SYS_CONNECT, args);
#endif
}

#define SHUT_RDWR 2

internal
int shutdown(int sockfd, i32 how)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall2(
            SYS_shutdown,
            (void*)(intptr)sockfd,
            (void*)(intptr)how
        );
#else
    void* args[2];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)(intptr)how;

    return socketcall(SYS_SHUTDOWN, args);
#endif
}

#define SOL_SOCKET 1

#define SO_REUSEADDR 2
#define SO_RCVTIMEO  20
#define SO_SNDTIMEO  21

internal
int setsockopt(
    int sockfd,
    i32 level,
    i32 optname,
    void const* optval,
    u32 optlen)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall5(
            SYS_setsockopt,
            (void*)(intptr)sockfd,
            (void*)(intptr)level,
            (void*)(intptr)optname,
            (void*)optval,
            (void*)(intptr)optlen
        );
#else
    void* args[5];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)(intptr)level;
    args[2] = (void*)(intptr)optname;
    args[3] = (void*)optval;
    args[4] = (void*)(intptr)optlen;

    return socketcall(SYS_SETSOCKOPT, args);
#endif
}

/* ------------------------------------------------------------- */

internal
int tcp_init(sockaddr_in* serv_addr, u16 port)
{
    memeset(serv_addr, 0, sizeof(sockaddr_in));
    serv_addr->family = AF_INET;
    serv_addr->port = letobe16u(port);

    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

internal
int tcp_listen(u16 port)
{
    b32 const y = 1;
    sockaddr_in serv_addr;
    int sockfd = tcp_init(&serv_addr, port);

    if (sockfd < 0) {
        errln("Failed to create socket");
        return sockfd;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(b32));

    if (bind(sockfd, &serv_addr) < 0)
    {
        errln("Bind failed. Try waiting for the port to be "
              "available or change it");
        return -1;
    }

    if (listen(sockfd, WEEB_BACKLOG) < 0)
    {
        errln("Listen failed");
        return -1;
    }

    return sockfd;
}

internal
int tcp_dial(u32 addr, u16 port)
{
    sockaddr_in serv_addr;
    int sockfd = tcp_init(&serv_addr, port);

    if (sockfd < 0) {
        errln("Failed to create socket");
        return sockfd;
    }

    serv_addr.addr = addr;

    if (connect(sockfd, &serv_addr) < 0) {
        errln("Connect failed");
        return -1;
    }

    return sockfd;
}

/* ------------------------------------------------------------- */

#define HTTP_VER "HTTP/1.0"

internal
b32 http_line(int fd, char const* text)
{
    int res = fputs(fd, text);
    if (res != strlen(text)) {
        errln("Failed to write text");
        return 0;
    }

    if (fputs(fd, "\r\n") != 2) {
        errln("Failed to write CRLF");
        return 0;
    }

    return 1;
}

#define mkcode(code, desc) \
    case code: return HTTP_VER " " #code " " desc;

internal
char const* http_get_code(u16 code)
{
    switch (code)
    {
        mkcode(200, "OK")
        mkcode(400, "Bad Request")
        mkcode(404, "Not Found")
        mkcode(501, "Not Implemented")
    }

    kms("unimplemented or invalid code");
    return 0; /* never executes */
}

#undef mkcode

internal
b32 http_code(int fd, u16 code) {
    return http_line(fd, http_get_code(code));
}

internal
b32 http_body(int fd) {
    return fputs(fd, "\r\n") == 2;
}

typedef struct
{
    char* method;
    char* path;
}
http_request;

#define REQ_EMPTY   (-1)
#define REQ_TOOBIG  (-2)
#define REQ_INVALID (-3)

/* parses a http request, using buf to store the raw header.

   returns 0 and sets the contents of res on success.
   returns REQ_EMPTY if the request is empty.
   returns REQ_TOOBIG if the request header exceeds bufsize.
   returns REQ_INVALID if the request cannot be parsed.

   the contents of res are valid as long as buf is valid */
internal
int http_parse_request(
    int fd,
    http_request* res,
    char* buf,
    u32 bufsize)
{
    intptr n;
    char* p = buf;

    /* consume entire request */
    n = read(fd, buf, bufsize);
    if (n >= bufsize) {
        return REQ_TOOBIG;
    }
    if (n <= 0) {
        return REQ_EMPTY;
    }
    buf[n - 1] = 0;

    p = buf;

    /* parse method */
    res->method = p;

    for (; *p && *p != ' '; ++p);
    if (!*p) {
        return REQ_INVALID;
    }

    *p++ = 0;

    /* parse path */
    res->path = p;

    for (; *p != ' ' && *p; ++p);
    if (!*p) {
        return REQ_INVALID;
    }

    *p++ = 0;

    return 0;
}

/* ------------------------------------------------------------- */

internal
char const* gopher_to_mime(char type)
{
    switch (type)
    {
        case '0':
        case '3': return "text/plain";
        case '1':
        case '2':
        case '7': return "text/html";
        case '4': return "application/binhex";
        case '5': return "application/x-compressed";
        case '6': return "text/x-uuencode";
        case ';':
        case 'c':
        case '9': return "application/octet-stream";
        case 'g': return "image/gif";
        case 'I': return "image/jpeg";  /* TODO: sniff mime */
        case 'd': return "pdf";         /* ^ */
        case 's': return "audio/mpeg3"; /* ^ */
        case 'M': return "www/mime";
    }

    if (type >= '0' && type <= 'Z') {
        return "application/octet-stream";
    }

    return 0;
}

/* escapes html chars (but not quotes!) */
internal
void fputhtmltext(int fd, char const* p)
{
    for (; *p; ++p)
    {
        switch (*p)
        {
            case '&': fputs(fd, "&amp;"); break;
            case '<': fputs(fd, "&lt;"); break;
            default: write(fd, p, 1);
        }
    }
}

internal
void fputhtmlpropc(int fd, char c)
{
    switch (c)
    {
        case '"': fputs(fd, "&quot;"); break;
        case '\'': fputs(fd, "&#39;"); break;
    }

    write(fd, &c, 1);
}

/* html escapes quotes and double quotes */
internal
void fputhtmlprop(int fd, char const* p)
{
    for (; *p; ++p) {
        fputhtmlpropc(fd, *p);
    }
}

/* prints a path generated by pathn with
   html escaped quotes and double quotes */
internal
void fputhtmlpath(int fd, cstr const* p)
{
    for (; p->p; ++p)
    {
        intptr i;
        for (i = 0; i < p->len; ++i) {
            fputhtmlpropc(fd, p->p[i]);
        }

        if (p[1].p) {
            write(fd, "/", 1);
        }
    }
}

typedef struct
{
    char type;
    char* text, *path;
    char const* host, *port;
}
gophermap_line;

/* parses a gophermap line. the gophermap_line struct should be
   initialized with the desired default values that will be used
   if the fields are omitted in the gophermap.
   text is guaranteed to be set.

   NOTE: this modifies p. p must remain valid for the elements of
         the gophermap_line to be valid */
internal
void gophermap_parse_line(char* p, gophermap_line* res)
{
                    /* ([] is the character that p points to)
                        [0]something<TAB>/<TAB>sdf.org<TAB>70 */
    /* type */
    res->type = *p++;/* 0[s]omething<TAB>/<TAB>sdf.org<TAB>70 */

    /* text */
    res->text = p;

    for (; *p != '\t' && *p; ++p);
    if (!*p) {
        return;
    }                /* 0something[<TAB>]/<TAB>sdf.org<TAB>70 */

    *p++ = 0;        /* 0something<NULL>[/]<TAB>sdf.org<TAB>70 */

    /* path */
    res->path = p;

    for (; *p != '\t' && *p; ++p);
    if (!*p) {       /* 0something<NULL>/[<TAB>]sdf.org<TAB>70 */
        return;
    }

    *p++ = 0;        /* 0something<NULL>/<NULL>[s]df.org<TAB>70 */

    /* host */
    res->host = p;

    for (; *p != '\t' && *p; ++p);
    if (!*p) {       /* 0something<NULL>/<NULL>sdf.org[<TAB>]70 */
        return;
    }

    *p++ = 0;        /* 0something<NULL>/<NULL>sdf.org<NULL>[7]0 */

    /* port */
    res->port = p;
}

typedef struct
{
    /* urls are relative by default.
       if local_host is not empty, all urls external to that
       ip/domain will have proxy_prefix prepended to them and
       target="_blank" */
    char const* local_host;
    char const* proxy_prefix;

    /* the root path (selector) of the gopher mirror. if set,
       urls that go outside of this directory will be redirected
       to the proxy */
    char const* root_selector;

    /* hides parent directory url (..) when in the root dir */
    b32 hide_parent_in_root;

    /* a file descriptor to a stylesheet for the page. if set to -1
       it will use a hardcoded default css. body should always have
       a monospace font and white-space:pre to correctly display
       gopher content */
    int cssfd;

    /* a file descriptor to a html file that will be appended right
       after <body>. set to -1 for the default gopher notice */
    int headerfd;

    /* this will be the title of the page. set to zero to omit the
       title tag entirely */
    char const* title;

    /* this will be appended to title */
    char const* title_suffix;

    /* this will be prepended to every line read from the file
       descriptor. this is used to convert txt files to gophermaps
       by prepending 'i' to every line. */
    char const* line_prefix;
}
gophermap_info;

const gophermap_info gophermap_default_info =
{
    "", "", "", 0, -1, -1, 0, "", ""
};

/* converts the gophermap line p to html and writes it to fd.
   i defines various options for the conversion. if zero,
   gophermap_default_info will be used.
   the result is written to the fd file descriptor.
   NOTE: this modifies and invalidates p */
internal
void gophermap_line_to_html(
    char* p,
    int fd,
    gophermap_info const* i)
{
    gophermap_line ln;
    char *tag = 0, *suffix = 0, *protocol = 0;
    b32 is_parent = 0;

    ln.path = 0;
    ln.host = i->local_host;
    ln.port = "70";

    gophermap_parse_line(p, &ln);
    if (!ln.path) {
        ln.path = ln.text;
    }

    switch (ln.type)
    {
        case '.':
            return;

        case 'i':
        case '3':
            /* just print the text */
            break;

        case '8':
            protocol = "telnet";
            /* fallthrough */

        case 'T':
            if (!protocol) protocol = "tn3270";

        /* TODO: handle search queries */

        default:
        {
            b32 same_host, external;
            cstr npath[PATH_MAX_LEVEL], nroot[PATH_MAX_LEVEL];

            pathn(ln.path, npath, PATH_MAX_LEVEL);
            pathn(i->root_selector, nroot, PATH_MAX_LEVEL);

            is_parent = ln.type == '1' &&
                        strneq(ln.text, "..", 2) &&
                        isws(ln.text + 2);

            same_host = streq(ln.host, i->local_host);

            external =
                !same_host ||
                !pathchld(npath, nroot);

            if (i->hide_parent_in_root &&
                same_host && is_parent && external)
            {
                /* ignore parent url in root dir */
                return;
            }

            tag = "a";
            fputs(fd, "<a ");

            if (external) {
                fputs(fd, "target=\"_blank\" ");
            }

            fputs(fd, "href=\"");

            if (protocol)
            {
                fputs(fd, protocol);
                fputs(fd, "://");

                if (*ln.path)
                {
                    /* username */
                    fputs(fd, ln.path);
                    fputs(fd, "@");
                }
            }
            else if (external) {
                fputs(fd, i->proxy_prefix);
            }

            if (external || protocol)
            {
                fputs(fd, ln.host);
                fputs(fd, ":");
                fputhtmlprop(fd, ln.port);
            }

            if (strneq(ln.path, "URL:", 4)) {
                fputhtmlprop(fd, ln.path + 4);
            }
            else if (!protocol)
            {
                fputs(fd, "/");
                write(fd, &ln.type, 1);
                fputs(fd, "/");
                fputhtmlpath(fd, npath + pathlen(nroot));
            }

            fputs(fd, "\">");
        }
    }
    /* end switch (ln.type) */

    if (is_parent)
    {
        /* truncate whitespace after .. in parent dir url */
        ln.text[2] = 0;
        suffix = " (parent directory)";
    }

    fputhtmltext(fd, ln.text);

    if (suffix) {
        fputhtmltext(fd, suffix);
    }

    if (tag)
    {
        fputs(fd, "</");
        fputs(fd, tag);
        fputs(fd, ">");
    }

    fputs(fd, "<br />");
}

/* reads and parses a gophermap into a html file.
   each line is buffered into buf.
   lines that exceed bufsize will be truncated and displayed as
   text elements.
   i defines various options for the conversion. if zero,
   gophermap_default_info will be used.
   the result is written to the fd file descriptor. */
internal
b32 gophermap_to_html(
    int gopherfd,
    int fd,
    gophermap_info const* i,
    char* buf,
    u32 bufsize)
{
    b32 res = 1; /* TODO: return bytes written instead */
    char c;
    char* p;
    intptr lineprefix_len = strlen(i->line_prefix);
    intptr n;

    if (!i) {
        i = &gophermap_default_info;
    }

    /* TODO: work in large chunks instead of having many writes */
    /* TODO: error check writes */

    fputs(fd,
        "<!DOCTYPE html>"
        "<head>"
        "<meta charset=\"UTF-8\" />");

    if (i->title) {
        fputs(fd,
            "<title>");
        fputhtmltext(fd, i->title);
        fputhtmltext(fd, i->title_suffix);
        fputs(fd,
            "</title>");
    }

    fputs(fd,
        "<style>");

    /* css */
    n = -1;

    if (i->cssfd != -1)
    {
        n = fcpy(fd, i->cssfd, (u8*)buf, bufsize);
        if (n < 0) {
            fputs(stderr, "fcpy failed for css");
        }
    }

    if (n < 0)
    {
        fputs(fd,
            "body{"
                "font-family:monospace;"
                "white-space:pre;"
                "color:#afbccc;"
                "background-color:#191c1f"
            "}"
            "a:link,a:visited,a:active,a:hover{"
                "color:#bcaeda;"
                "text-decoration:none"
            "}"
            "a:visited{color:#8d849f}");
    }

    fputs(fd,
        "</style>"
        "</head>"
        "<body>");

    n = -1;

    if (i->headerfd != -1)
    {
        n = fcpy(fd, i->headerfd, (u8*)buf, bufsize);
        if (n < 0) {
            fputs(stderr, "fcpy failed for header");
        }
    }

    if (n < 0)
    {
        fputs(fd,
            "Hello there! You are currently visiting gopherspace "
            "through a<br />proxy. To learn more about gopher and "
            "how to browse it, read "
            "<a href=\"http://weeb.ddns.net/1/gopher\">this</a>."
            "<br />______________________________________________"
            "________________________<br /><br />");
    }

    strcpy(buf, i->line_prefix);
    p = buf + lineprefix_len;

    /* parse gophermap */
    while (1)
    {
        intptr n = read(gopherfd, &c, 1);
        if (n < 0) {
            errln("gopher read failed");
            fputs(fd, "*** GOPHER I/O ERROR, try again ***");
            res = 0;
        }
        if (n <= 0) {
            break;
        }

        if (p - buf >= bufsize - 1) {
            errln("Line is too long, truncating");
            buf[0] = 'i';
            goto newline;
        }

        if (c != '\n' && c != '\r') {
            *p++ = c;
            continue;
        }

        if (c == '\r') {
            /* for servers that send CRLF */
            continue;
        }

newline:
        *p = '\0';
        gophermap_line_to_html(buf, fd, i);

        /* start reading a new line */
        strcpy(buf, i->line_prefix);
        p = buf + lineprefix_len;
    }

    fputs(fd,
        "</body>"
        "</html>");

    return res;
}

/* ------------------------------------------------------------- */

internal
void weeb_timeouts(int fd)
{
    timeval tv = {WEEB_TIMEOUT, 0};
    intptr tvcb = sizeof(tv);

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, tvcb) < 0) {
        errln("Failed to set SO_RCVTIMEO");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, tvcb) < 0) {
        errln("Failed to set SO_SNDTIMEO");
    }
}

/* download gopher page, convert it to html (unless it's a binary
   file and write it to fd */
internal
b32 weeb_scrape_gopher(
    int fd,
    u32 ip,
    char const* selector,
    char type,
    char* buf,
    intptr bufsize)
{
    int gopherfd = tcp_dial(ip, 70);
    if (gopherfd < 0) {
        return 0;
    }

    weeb_timeouts(gopherfd);

    puts("Gophering ");
    puts(WEEB_GOPHER_ROOT "/");
    prln(selector);

    fputs(gopherfd, WEEB_GOPHER_ROOT "/");
    fputs(gopherfd, selector);
    fputs(gopherfd, "\r\n");

    if (type == '1' || type == '0')
    {
        static gophermap_info i;
        if (!i.title)
        {
            i = gophermap_default_info;
            i.root_selector = WEEB_GOPHER_ROOT;
            i.local_host = WEEB_GOPHER_DOMAIN;
            i.proxy_prefix = "http://" WEEB_GOPHER_PROXY;
            i.title = WEEB_TITLE ": /";
            i.hide_parent_in_root = 1;
        }

        i.title_suffix = selector;

        if (type == '0') {
            /* convert txt to gophermap so it gets the same theme
               as the gophermaps */
            i.line_prefix = "i";
        }

        if (!gophermap_to_html(gopherfd, fd, &i, buf, bufsize))
        {
            return 0;
        }
    }
    else
    {
        if (fcpy(fd, gopherfd, (u8*)buf, bufsize) < 0)
        {
            fputs(fd, "*** I/O ERROR, try again later ***");
            return 0;
        }
    }

    close(gopherfd);

    return 1;
}

internal
void weeb_get_cache(
    char const* selector,
    char type,
    char* cache_filename)
{
    char* c = cache_filename;
    c += strcpy(c, "cache");
    *c++ = '/';
    *c++ = type;
    *c++ = '/';
    c += strcpy(c, selector);
    c += strcpy(c, ".cache");
}

/* if force is true, it will open the file even if it's outdated */
internal
int weeb_open_cache(
    char const* cache_filename,
    uintptr* size,
    b32 force)
{
    char itoabuf[24];
    int cachefd = -1;
    stat_info si_gopher, si_now;
    time_t file_age;

    /* execution bit actually allows people to enter the dir */
    mkdir_p(cache_filename, 0755, 1);

    if (stat(cache_filename, &si_gopher) < 0) {
        prln("Failed to stat cache file, recaching");
        return -1;
    }

    touch(".now");

    if (stat(".now", &si_now) < 0) {
        errln("Failed to stat .now, WTF? recaching");
        return -1;
    }

    file_age = si_now.mtim.sec - si_gopher.mtim.sec;
    itoa(10, (intptr)file_age, itoabuf, 0, '0');
    puts("This page is ");
    puts(itoabuf);
    prln(" seconds old");

    if (!force && file_age > WEEB_CACHE_LIFE)
    {
        prln("It's time to recache it!");
        return -1;
    }

    cachefd = open(cache_filename, O_RDONLY, 0);
    if (cachefd < 0) {
       prln("Failed to open cache file, recaching");
       return -1;
    }

    if (size) {
        *size = si_gopher.size;
    }

    return cachefd;
}

/* zero's a file's modification/access/creation times so that it's
   forced to be recached */
internal
void weeb_invalidate_cache(char const* filename)
{
    timespec times[2];
    memeset(&times, 0, sizeof(times));
    utimensat(AT_FDCWD, filename, times, 0);
}

internal
void print_sockaddr(sockaddr_in const* addr)
{
    static char buf[16];
    char* p = buf;
    u8* bytes = (u8*)&addr->addr;

    p += uitoa(10, (uintptr)bytes[0], p, 0, '0');
    *p++ = '.';

    p += uitoa(10, (uintptr)bytes[1], p, 0, '0');
    *p++ = '.';

    p += uitoa(10, (uintptr)bytes[2], p, 0, '0');
    *p++ = '.';

    uitoa(10, (uintptr)bytes[3], p, 0, '0');

    puts(buf);
}

internal
int weeb_handle(int fd, sockaddr_in const* addr)
{
    char buf[8000];

    http_request req;
    char const* mime_type = "text/plain";
    u16 code = 200;

    char cache_filename[PATH_MAX];
    int cachefd;
    uintptr cache_file_size = 0;
    char type = '1';
    char* selector = "/";

    u8 gopherip[4] = WEEB_GOPHER_IP;
    u32 gopherip_u32;
    b32 invalidate_cache = 0;

    /* --------------------------------------------------------- */

    print_sockaddr(addr);
    puts(" ");

    memeset(&req, 0, sizeof(http_request));

    switch (http_parse_request(fd, &req, buf, sizeof(buf)))
    {
        case REQ_EMPTY:
            errln("Empty request, wtf?");
            code = 400;
            break;

        case REQ_INVALID:
            errln("Malformed request");
            code = 400;
            break;

        case REQ_TOOBIG:
            errln("Request too big, refusing");
            code = 414;
            break;
    }

    puts(req.method);
    puts(" ");
    prln(req.path);

    if (!streq(req.method, "GET")) {
        errln("Unimplemented method");
        code = 501;
    }

    if (code == 200)
    {
        /* TODO: find a nice way to pull this out without using
                 goto's */

        /* gopher selector without the leading slash */
        selector = req.path;
        if (*selector == '/') {
            ++selector;
        }

        /* TODO: used pathp in here */
        if (streq(selector, "favicon.ico"))
        {
            code = 404;
            prln("FUCK the favicon");
            /* TODO: send favicon */
            goto sendcode;
        }

        /* parse gopher filetype */
        if (selector[1] == '/') {
            type = *selector;
            selector += 2;
        }

        puts("Gopher type: ");
        write(stdout, &type, 1);
        prln("");

        /* map gopher type to MIME type */
        mime_type = gopher_to_mime(type);
        if (!mime_type) {
            errln("Invalid gopher type");
            code = 404;
        }

        /* exception for txt files which we convert to gophermap */
        if (type == '0') {
            mime_type = "text/html";
        }
    }

sendcode:
    http_code(fd, code);

    if (code == 200)
    {
        puts("MIME type: ");
        prln(mime_type);

        fputs(fd, "Content-Type: ");
        http_line(fd, mime_type);
    }

    if (code != 200)
    {
        http_body(fd);
        /* this is a http error. there is no body */
        return 0;
    }

    /* --------------------------------------------------------- */

    /* get cached file or re-cache page */
    weeb_get_cache(selector, type, cache_filename);
    cache_file_size = 0;
    cachefd = weeb_open_cache(cache_filename, &cache_file_size, 0);
    if (cachefd < 0)
    {
        char cache_filename_tmp[PATH_MAX];
        char* t = cache_filename_tmp;

        /* no cache file, let's create it */

        /* write to a temporary file so we don't risk sending a
           partial file + we keep the old copy if it fails */
        t += strcpy(t, cache_filename);
        strcpy(t, ".tmp");

        cachefd = open(
            cache_filename_tmp,
            O_CREAT | O_WRONLY | O_TRUNC,
            0664
        );

        if (cachefd < 0)
        {
            http_body(fd);
            errln("Failed to create new cache file, falling back"
                  " to direct output. THIS IS BAD, PLS FIX");
            cachefd = fd;
        }

        /* can't use a normal cast for this in c89
           so I'll memcpy the ip bytes into a u32 */
        memecpy(&gopherip_u32, gopherip, sizeof(u32));

        /* ! NOTE: p, buf and all pointers to it are
                   invalidated from here ! */

        invalidate_cache =
            !weeb_scrape_gopher(
                cachefd,
                gopherip_u32,
                selector,
                type,
                buf,
                sizeof(buf)
            );

        if (cachefd != fd)
        {
            close(cachefd);

            if (rename(cache_filename_tmp, cache_filename) < 0) {
                errln("rename failed");
            }

            cache_file_size = 0;
            cachefd = weeb_open_cache(
                cache_filename,
                &cache_file_size,
                1
            );
            if (cachefd < 0)
            {
                errln("failed to open cache file after rename???");
                cachefd = fd;

                http_body(fd);
                fputs(fd, "*** I/O ERROR, try again later ***");
            }
        }
    }

    /* we are in direct output fallback mode, so we already sent
       the page to the client, or an error occurred */
    if (cachefd == fd) {
        return 0;
    }

    /* --------------------------------------------------------- */

    /* now that we either opened an existing cache file or created
       it and still have the file descriptor open, let's send it
       to the client */

    prln("Sending cached page...");

    if (cache_file_size)
    {
        char itoabuf[24];
        uitoa(10, cache_file_size, itoabuf, 0, '0');
        fputs(fd, "Content-Length: ");
        http_line(fd, itoabuf);
    }
    http_body(fd);

    if (fcpy(fd, cachefd, (u8*)buf, sizeof(buf)) < 0) {
        fputs(fd, "*** I/O ERROR, try again later ***");
    }

    close(cachefd);

    if (invalidate_cache)
    {
        /* if the scraping failed, we make sure it will be
           re-cached on the next refresh */
        weeb_invalidate_cache(cache_filename);
    }

    /* client connection is closed by the caller */

    return 0;
}

globvar volatile
b32 running = 1;

internal
void sig_handle(int signum)
{
    switch (signum)
    {
        case SIGINT:
            prln("Caught CTRL-C");
            running = 0;
            break;

        case SIGCHLD:
            prln("Caught SIGCHLD");
            while(waitpid(-1, 0, WNOHANG) > 0);
    }
}

internal
int weeb(int argc, char const* argv[])
{
    sigaction sa;
    int sockfd;

    /* this prevents the dead child processes from filling the
       process list */
    memeset(&sa, 0, sizeof(sigaction));
    sa.handler = sig_handle;
    sa.flags = SA_RESTART | SA_NOCLDSTOP;

    if (rt_sigaction(SIGCHLD, &sa, 0) < 0) {
        kms("Failed to install SIGCHLD handler");
    }

    if (signal(SIGINT, sig_handle, 0) < 0) {
        kms("Failed to install SIGINT handler");
    }

    prln(WEEB_VER);

    sockfd = tcp_listen(8080);
    if (sockfd < 0) {
        return 1;
    }

    while (running)
    {
        int clientfd, pid;
        sockaddr_in addr;

        clientfd = accept(sockfd, &addr);
        if (clientfd < 0) {
            errln("Failed to accept connection");
            break;
        }

        weeb_timeouts(clientfd);

        pid = fork();
        if (pid < 0) {
            errln("Failed to fork");
            break;
        }

        if (!pid) {
            int res;

            close(sockfd);

            /* child process handles the client and exits */
            res = weeb_handle(clientfd, &addr);

            /* prevents connection reset err since we don't read
               the entire request */
            if (shutdown(clientfd, SHUT_RDWR) < 0) {
                errln("shutdown failed");
            }

            /* tell the client the http response is over */
            close(clientfd);

            return res;
        }

        /* the parent process still has a handle to the client's
           connection. we must close this otherwise it will stay
           open forever and the client will keep waiting for more
           data when we don't have Content-Length */
        close(clientfd);

        /* parent process keeps on accepting new connections */
    }

    close(sockfd);
    return 0;
}
