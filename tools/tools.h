/*************************
 *
 * Description: Some utility functions for assisting in measuring the cache measurement channel.
 *
 * Author: hujinwei@iie.ac.cn
 * ************************/
#ifndef TOOLS_H
#define TOOLS_H
#include <stdint.h>

#define MFENCE              asm volatile("mfence" ::: "memory");
#define LFENCE              asm volatile("lfence" ::: "memory");
#define SFENCE              asm volatile("sfence" ::: "memory");
#define CFENCE              asm volatile("" ::: "memory");

#define CLFLUSH(addr)       do {    \
                                MFENCE  \
                                asm volatile("clflush (%0)" : : "r" (addr) : "memory"); \
                                MFENCE  \
                            } while(0);




void flush_addr(void* addr);
uint64_t time_access(void* addr);
int pin_to_cpu(int core_id);
int set_realtime_scheduling(void);
void restore_cpu(void);

uint64_t measure_access_time(void);



#endif
