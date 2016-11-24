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

.intel_syntax noprefix
.text
    .globl _start
    .type main, @function

    _start:
        /* according to the amd64 abi,
           "rbp: The content of this register is unspecified at
           process initialization time, but the user code should
           mark the deepest stack frame by setting the frame
           pointer to zero." */
        xor rbp,rbp

        pop rdi /* argc */
        mov rsi,rsp
        /* argv (basically the rest of the stack as an array of
                 char pointers) */

        /* zero the last 4 bits of rsp, aligning it to 16 bytes */
        and rsp,-16
        call main

        /* exit with main's return code */
        mov rdi,rax
        mov rax,SYS_exit
        syscall
        ret

    .globl syscall, syscall1, syscall2, syscall3, syscall4
    .globl syscall5

    /* all registers except RBP, RBX, and R12–R15 are automatically
       restored after a call on amd64, so we don't need to preserve
       anything in these syscall trampolines */

    syscall:
        mov rax,rdi
        syscall
        ret

    syscall1:
        mov rax,rdi
        mov rdi,rsi
        syscall
        ret

    syscall2:
        mov rax,rdi
        mov rdi,rsi
        mov rsi,rdx
        syscall
        ret

    syscall3:
        mov rax,rdi /* syscall number */
        mov rdi,rsi /* arg1 */
        mov rsi,rdx /* arg2 */
        mov rdx,rcx /* arg3 */
        syscall
        ret

    syscall4:
        mov rax,rdi
        mov rdi,rsi
        mov rsi,rdx
        mov rdx,rcx
        mov r10,r8
        syscall
        ret

    syscall5:
        mov rax,rdi
        mov rdi,rsi
        mov rsi,rdx
        mov rdx,rcx
        mov r10,r8
        mov r8,r9
        syscall
        ret
