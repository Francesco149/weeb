A server that relays gopher content over HTTP, written in C without
using the standard C library.

This is mainly for personal usage at
[my gopherspace](http://weeb.ddns.net/).

At the moment, only remote gopher servers are supported, but I'm
planning support for local gopher directories.

Features:
* Lightweight, ~10kb executable that uses a couple kb of memory per
  client.
* Basic caching system to minimize bandwidth usage and system load.
* Small C89 codebase that compiles instantly. Just 1 main C file
  and 3 small files for each architecture.
* No dependencies nor build systems required. No C library, not
  even kernel headers. All you need is gcc.
* Configuration is embedded at the top of the main source file
  (weeb.c). Just tweak and recompile.

![How it looks out of the box](http://www.hnng.moe/f/KFb)

# How to use (Linux 32-bit)
```
$ git clone https://github.com/Francesco149/weeb.git
$ cd weeb
$ chmod +x ./i386build.sh
$ ./i386build.sh
$ ./weeb &
$ xdg-open http://localhost:8080/
$ killall weeb
```

# How to use (Linux 32-bit)
```
$ git clone https://github.com/Francesco149/weeb.git
$ cd weeb
$ chmod +x ./amd64build.sh
$ ./amd64build.sh
$ ./weeb &
$ xdg-open http://localhost:8080/
$ killall weeb
```

# License
This code is public domain and comes with no warranty. You are free
to do whatever you want with it.

You can contact me at
[lolisamurai@tfwno.gf](mailto:lolisamurai@tfwno.gf) but don't
expect any support.

I hope you will find the code useful or at least interesting to
read. Have fun!
