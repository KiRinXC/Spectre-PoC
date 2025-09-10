/*************************
 *
 * Description: Some utility functions for assisting in measuring the cache measurement channel.
 *
 * Author: hujinwei@iie.ac.cn
 * ************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <limits.h>
#include <unistd.h>

extern void flush_addr(void* addr);
extern uint64_t time_access(void* addr);

// 状态保存结构体
typedef struct {
    cpu_set_t original_mask;
    int old_policy;
    struct sched_param old_param;
} cpuOriginalState_t;

static cpuOriginalState_t originalState;
static int pinned_to_cpu_ok = 0;
static int setup_scheduling_ok = 0;

int pin_to_cpu(int core_id) {
    if (sched_getaffinity(0, sizeof(cpu_set_t), &originalState.original_mask) != 0) {
        perror(" [!] sched_getaffinity failed");
        return -1;
    }

    cpu_set_t target_mask;
    CPU_ZERO(&target_mask);
    CPU_SET(core_id, &target_mask);
    
    if(sched_setaffinity(0, sizeof(cpu_set_t), &target_mask) != 0) {
        perror(" [!] sched_setaffinity failed");
        return -1;
    }

    printf("[*] Process pinned to CPU Core %d.\n", core_id);
    pinned_to_cpu_ok = 1;
    return 0;
}

int set_realtime_scheduling() {
    originalState.old_policy = sched_getscheduler(0);
    if (sched_getparam(0, &originalState.old_param) != 0) {
        perror(" [!] sched_getparam failed");
        return -1;
    }

    struct sched_param new_param;

    new_param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    if (sched_setscheduler(0, SCHED_FIFO, &new_param) != 0) {
        perror(" [!] sched_setscheduler failed (run with sudo?)");
        return -1;
    }

    printf("[*] Scheduler set to SCHED_FIFO with max priority.\n");
    setup_scheduling_ok = 1;
    return 0;
}

void restore_pin_to_cpu() {
    if (!pinned_to_cpu_ok) return;

    if (sched_setaffinity(0, sizeof(cpu_set_t), &originalState.original_mask) == 0) {
        printf("[*] CPU affinity restored.\n");
    } else {
        perror(" [!] Failed to restore CPU affinity");
    }

    pinned_to_cpu_ok = 0;
}

void restore_scheduling() {
    if (!setup_scheduling_ok) return;

    if (sched_setscheduler(0, originalState.old_policy, &originalState.old_param) == 0) {
        printf("[*] Scheduler policy restored.\n");
    } else {
        perror(" [!] Failed to restore scheduler policy");
    }

    setup_scheduling_ok = 0;
}

void restore_cpu() {
    restore_pin_to_cpu();
    restore_scheduling();
}

static inline void access_addr(void *addr) {
    volatile int temp = *(int *)addr;
}

/**
 * @brief 自动校准缓存命中时间的阈值。
 * @return 计算出的缓存命中阈值。失败则返回0。
 */
uint64_t measure_access_time() {

    // --- 测量逻辑 ---
    const int TRIES = 2000;
    const int WARMUP_TRIES = 100;
    long page_size = sysconf(_SC_PAGESIZE);
    uint8_t *probe_area = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (probe_area == MAP_FAILED) {
        perror(" [!] mmap failed");
        restore_cpu();
        return 0;
    }

    memset(probe_area, 1, page_size);
    void* probe_addr = &probe_area[0];
    asm volatile("mfence" ::: "memory");
    
    uint64_t hit_times[TRIES], miss_times[TRIES];
    for (int i = 0; i < TRIES; i++) { access_addr(probe_addr); hit_times[i] = time_access(probe_addr); }
    for (int i = 0; i < TRIES; i++) { flush_addr(probe_addr); miss_times[i] = time_access(probe_addr); }
    
    uint64_t hit_sum = 0, miss_sum = 0;
    uint64_t hit_min = UINT64_MAX, hit_max = 0;
    uint64_t miss_min = UINT64_MAX, miss_max = 0;
    for (int i = WARMUP_TRIES; i < TRIES; i++) {
        hit_sum += hit_times[i];
        if (hit_times[i] < hit_min) hit_min = hit_times[i];
        if (hit_times[i] > hit_max) hit_max = hit_times[i];
        miss_sum += miss_times[i];
        if (miss_times[i] < miss_min) miss_min = miss_times[i];
        if (miss_times[i] > miss_max) miss_max = miss_times[i];
    }

    int count = TRIES - WARMUP_TRIES;
    uint64_t hit_avg = hit_sum / count;
    uint64_t miss_avg = miss_sum / count;
    uint64_t threshold = (hit_avg + miss_avg) / 2;

    // --- 打印结果 ---
    printf("\n");
    printf("================ Cache Timing Results ================\n");
    printf("Cache Hit Times:\n");
    printf("  -> Min:    %5lu cycles\n", hit_min);
    printf("  -> Max:    %5lu cycles\n", hit_max);
    printf("  -> Average:%5lu cycles\n", hit_avg);
    printf("\n");
    printf("Cache Miss Times:\n");
    printf("  -> Min:    %5lu cycles\n", miss_min);
    printf("  -> Max:    %5lu cycles\n", miss_max);
    printf("  -> Average:%5lu cycles\n", miss_avg);
    printf("===============================================================\n\n");
    printf("Recommended Threshold: %lu cycles\n", threshold);

    // --- 释放资源 ---
    munmap(probe_area, page_size);

    printf("\n[*] Measurement environment restored to original state.\n");
    
    return threshold;
}

// For test
// int main() {
//     uint64_t threshold = measure_and_print_cache_timing(1);
//     return 0;
// }
