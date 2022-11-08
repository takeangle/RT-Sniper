/*
 * New Interface to Process Table -- PROCTAB Stream (a la Directory streams)
 * Copyright (C) 1996 Charles L. Blake.
 * Copyright (C) 1998 Michael K. Johnson
 * Copyright 1998-2003 Albert Cahalan
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __READPROC_H_
#define __READPROC_H_

#include "util.h"

#define likely(x)       __builtin_expect(!!(x),1)
#define unlikely(x)     __builtin_expect(!!(x),0)
#define expected(x,y)   __builtin_expect((x),(y))
#define ENTER(x)
#define LEAVE(x)

// Basic data structure which holds all information we can get about a process.
// (unless otherwise specified, fields are read from /proc/#/stat)
//
// Most of it comes from task_struct in linux/sched.h
//
typedef struct proc_t {
	char cmd[64];    // stat,status     basename of executable file in call to exec(2)
	// declare only use in stat2proc
	// origin : https://gitlab.com/procps-ng/procps.git, proc/readproc.h
	char state;
	int ppid, pgrp, session, tty, tpgid;
	unsigned long flags, min_flt, cmin_flt, maj_flt, cmaj_flt;
	unsigned long long utime, stime, cutime, cstime;
	long priority, nice;
	int nlwp;
	long alarm;
	unsigned long long start_time;
	long unsigned int vsize;
	long rss;
	unsigned long rss_rlim;
	unsigned long start_code, end_code, start_stack, kstk_esp, kstk_eip;
	unsigned long wchan;
	int exit_signal, processor;
	unsigned long rtprio, sched;
	unsigned long long delayacct_blkio_ticks;
	unsigned long guest_time, cguest_time;
	unsigned long start_data, end_data, start_brk, arg_start, arg_end, env_start, env_end;
	int exit_code;
} proc_t;

// dynamic 'utility' buffer support for file2str() calls
typedef struct utlbuf_s {
    char *buf;     // dynamically grown buffer
    int   siz;     // current len of the above
} utlbuf_s;

// Reads /proc/*/stat files, being careful not to trip over processes with
// names like ":-) 1 2 3 4 5 6".
void stat2proc(const char* S, proc_t *P);
process_info get_process_info(int);
#endif
