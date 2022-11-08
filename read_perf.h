#ifndef __READ_PERF_H_
#define __READ_PERF_H_

#include "util.h"

void init_pea();
void init_core_fds(int cid);
int set_perf_events_for_pid(int pid);
int set_perf_events_for_cid(int cid);
void get_perf_event_proc(int pid, perf_event_res *per, long long us_ts);
void get_perf_event_core(int cid, perf_event_res *per, long long us_ts, bool reset);

void disable_core_fds(int cid);
void enable_core_fds(int cid);
void close_proc_fds(int pid);

void print_proc_fds(int pid);
void print_core_fds(int cid);

#endif
