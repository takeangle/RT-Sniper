#ifndef __UTIL_H_
#define __UTIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/time.h>
#include <errno.h>
#include <dirent.h>
#include <malloc.h>
#include <iostream>
#include <future>
#include <vector>
#include <queue>
#include <thread>

#define DEBUG_MODE false
#define DETAIL_CORE 12

#define MAX_PID_COUNT 32768 // cat /proc/sys/kernel/pid_max
#define MAX_CORE_COUNT 16	//

#define MAX_PROCESSES_ON_CORE 10000
// process information structure
typedef struct Process_Info {
        int pid;
        int psr;
        char cmd[20];
} process_info;

typedef struct Process_List {
	int cnt;
	int pid[MAX_PROCESSES_ON_CORE];
} process_list;

typedef struct Process_List_All {
	long long last_updated;
	process_list pl[16];
} process_list_all;

/*
 * perf event structures
 */
#define CNT_HW_EVENTS 2
const uint64_t HW_EVENTS[CNT_HW_EVENTS] =
{
	PERF_COUNT_HW_CPU_CYCLES,
	PERF_COUNT_HW_INSTRUCTIONS
};

#define CNT_HW_CACHE_EVENTS 0
// const uint64_t HW_CACHE_EVENTS[CNT_HW_CACHE_EVENTS] = {
//     PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8)  | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
// };

#define CNT_HW_RAW_EVENTS 3
const uint64_t HW_RAW_EVENTS[CNT_HW_RAW_EVENTS] = {
	9223372036859175121U,	// l3 miss
	9223372036859167953U,	// l3 hit
	9223372036859167441U	// l2hit
};



#define CNT_PERF_EVENTS CNT_HW_EVENTS+CNT_HW_CACHE_EVENTS+CNT_HW_RAW_EVENTS
const __u64 PERF_EVENTS[CNT_PERF_EVENTS][2] =
{
	{PERF_TYPE_HARDWARE, HW_EVENTS[0]},
	{PERF_TYPE_HARDWARE, HW_EVENTS[1]},
	{PERF_TYPE_RAW, HW_RAW_EVENTS[0]},
	{PERF_TYPE_RAW, HW_RAW_EVENTS[1]},
	{PERF_TYPE_RAW, HW_RAW_EVENTS[2]}
};

#define IDX_CYCLE 		0
#define IDX_INSTRUCTION	1
#define IDX_L3M			3
#define IDX_L3H			4
#define IDX_L2H			5

typedef struct Perf_FDs {
	long long last_update_ts;
	int fd[CNT_PERF_EVENTS];
} perf_fds;

typedef struct Perf_Event_Res {
	long long timestamp;
	uint64_t perf_val[CNT_PERF_EVENTS + 1];
} perf_event_res;


/*
 * analyzer
 *
 */
#define RES_MALICIOUS   1
#define RES_NORMAL      2
#define RES_UNKNOWN     3

int string_to_integer(char *str);

#endif // __UTIL_H_
