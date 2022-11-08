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

#include "readproc.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void stat2proc(const char* S, proc_t *P) {
    size_t num;
    char* tmp;

    ENTER(0x160);

    /* fill in default values for older kernels */
    P->processor = 0;
    P->rtprio = -1;
    P->sched = -1;
    P->nlwp = 0;

    S = strchr(const_cast<char*>(S), '(');
    if(unlikely(!S)) return;
    S++;
    tmp = strrchr(const_cast<char*>(S), ')');
    if(unlikely(!tmp)) return;
    if(unlikely(!tmp[1])) return;
    num = tmp - S;
    if(unlikely(num >= sizeof P->cmd)) num = sizeof P->cmd - 1;
    memcpy(P->cmd, S, num);
    P->cmd[num] = '\0';
    S = tmp + 2;                 // skip ") "

    sscanf(S,
        "%c "
        "%d %d %d %d %d "
        "%lu %lu %lu %lu %lu "
        "%llu %llu %llu %llu "  /* utime stime cutime cstime */
        "%ld %ld "
        "%d "
        "%ld "
        "%llu "  /* start_time */
        "%lu "
        "%ld "
        "%lu %lu %lu %lu %lu %lu "
        "%*s %*s %*s %*s " /* discard, no RT signals & Linux 2.1 used hex */
        "%lu %*u %*u "
        "%d %d "
        "%lu %lu "
        "%llu "
        "%lu %lu "
        "%lu %lu %lu %lu %lu %lu %lu "
        "%d"
        ,
        &P->state,
        &P->ppid, &P->pgrp, &P->session, &P->tty, &P->tpgid,
        &P->flags, &P->min_flt, &P->cmin_flt, &P->maj_flt, &P->cmaj_flt,
        &P->utime, &P->stime, &P->cutime, &P->cstime,
        &P->priority, &P->nice,
        &P->nlwp,
        &P->alarm,
        &P->start_time,
        &P->vsize,
        &P->rss,
        &P->rss_rlim, &P->start_code, &P->end_code, &P->start_stack, &P->kstk_esp, &P->kstk_eip,
        /*     P->signal, P->blocked, P->sigignore, P->sigcatch,   */ /* can't use */
        &P->wchan, /* &P->nswap, &P->cnswap, */  /* nswap and cnswap dead for 2.4.xx and up */
        /* -- Linux 2.0.35 ends here -- */
        &P->exit_signal, &P->processor,  /* 2.2.1 ends with "exit_signal" */
        /* -- Linux 2.2.8 to 2.5.17 end here -- */
        &P->rtprio, &P->sched,  /* both added to 2.5.18 */
        &P->delayacct_blkio_ticks, /* since 2.6.18 */
        &P->guest_time, &P->cguest_time, /* since 2.6.24 */
        &P->start_data, &P->end_data, &P->start_brk, &P->arg_start, &P->arg_end, &P->env_start, &P->env_end, /* since 3.5 */
        &P->exit_code /* since 3.5 */
    );

    if(!P->nlwp){
        P->nlwp = 1;
    }

    LEAVE(0x160);
}

process_info get_process_info(int pid) {
	process_info pi;

	pi.pid = -1;
	char path[20];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return pi;
	}
	char buf[1024];
	read(fd, buf, 1024);
	close(fd);
	struct proc_t curproc;
	stat2proc(buf, &curproc);
	pi.pid = pid;
	pi.psr = curproc.processor;
	return pi;
}
