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

#include "syscalls.h"

/* on i386, parameters are pushed on the stack in reverse
   order, which means that we can access them in order by
   reading the stack pointer every 4 bytes.

   calling functions also pushes the return address onto the
   stack, so arguments actually start at esp+4.

   int 0x80 is the intruction to enter syscalls.

   the rest is the same stuff as amd64 except with 32-bit
   registers. see amd64_weeb.S for explanations */

.intel_syntax noprefix
.text
    .globl _start
    .type main, @function

    _start:
        xor ebp,ebp

        pop esi
        mov ecx,esp

        /* 16-byte stack alignment is not mandatory here but
           according to glibc it improves SSE performance */
        and esp,-16

        /* push garbage to align to 16 bytes */
        push 0xb16b00b5
        push 0xb16b00b5
        push ecx
        push esi
        call main
        add esp,16
        /* on i386 it's up to the caller to clean up the stack */

        mov ebx,eax
        mov eax,SYS_exit
        int 0x80
        ret

    .globl syscall, syscall1, syscall2, syscall3, syscall4
    .globl syscall5

    /* on i386 calling convention it's up to the callee to save and
       restore all registers except for the scratch registers
       eax, ecx, edx. so we're going to save registers we overwrite
       on the stack.

       vim search command for registers used by int 0x80
       that must be preserved:

       /\vebx|esi|edi|ebp|esp */

    syscall:
        mov eax,[esp+4]
        int 0x80
        ret

    syscall1:
        push ebx
        mov eax,[esp+4+4]
        mov ebx,[esp+8+4]
        int 0x80
        pop ebx
        ret

    syscall2:
        push ebx
        mov eax,[esp+4+4]
        mov ebx,[esp+8+4]
        mov ecx,[esp+12+4]
        int 0x80
        pop ebx
        ret

    syscall3:
        push ebx
        mov eax,[esp+4+4]
        mov ebx,[esp+8+4]
        mov ecx,[esp+12+4]
        mov edx,[esp+16+4]
        int 0x80
        pop ebx
        ret

    syscall4:
        push ebx
        push esi
        mov eax,[esp+4+8]
        mov ebx,[esp+8+8]
        mov ecx,[esp+12+8]
        mov edx,[esp+16+8]
        mov esi,[esp+20+8]
        int 0x80
        pop esi
        pop ebx
        ret

    syscall5:
        push ebx
        push esi
        push edi
        mov eax,[esp+4+12]
        mov ebx,[esp+8+12]
        mov ecx,[esp+12+12]
        mov edx,[esp+16+12]
        mov esi,[esp+20+12]
        mov edi,[esp+24+12]
        int 0x80
        pop edi
        pop esi
        pop ebx
        ret
