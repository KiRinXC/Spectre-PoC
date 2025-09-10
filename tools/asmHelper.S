.section .text
.global time_access

# ---------------------------------------------------------------------------
# uint64_t time_access(void* addr);
#
# Purpose: Measure the time (in CPU cycles) required to access a single memory address.
# Author: hujinwei@iie.ac.cn
# ---------------------------------------------------------------------------
time_access:
    lfence
    rdtsc
    shl         $32, %rdx
    or          %rax, %rdx
    movq        %rdx, %r8

    lfence
    movb        (%rdi), %r9b

    rdtscp
    shl         $32, %rdx
    or          %rdx, %rax
    subq        %r8, %rax

    mfence

    ret


.global flush_addr
flush_addr:
    mfence
    clflush 0(%rdi)
    mfence
    ret
    
