#include "read_perf.h"

/* 
 *  set perf_event_open
 *  return : fd created
 */
static int set_perf_event_open(struct perf_event_attr pea, uint64_t type, uint64_t config, int cid, int pid, int leader) {
    pea.type = type;
    pea.config = config;
    int fd = syscall(__NR_perf_event_open, &pea, pid, cid, leader, 0);
    if (fd < 0 && DEBUG_MODE) printf("ERROR! set_perf %d %lu %lu %d : %d : %s\n ", pid, type, config, leader, errno, strerror(errno));
    ioctl(fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    return fd;
}


struct perf_event_attr pea_default;
perf_fds proc_fds[MAX_PID_COUNT];
perf_fds core_fds[MAX_CORE_COUNT];

/* initialize common parametrs perf_event_attr */
void init_pea() {
	memset(&pea_default, 0, sizeof(struct perf_event_attr));
	pea_default.size = sizeof(struct perf_event_attr);
	pea_default.disabled = 0;
	pea_default.exclude_kernel = 0;
	pea_default.exclude_hv = 0;
	pea_default.read_format = PERF_FORMAT_GROUP;

	pea_default.inherit = 0;
	pea_default.pinned = 1;
	pea_default.exclusive = 0;
	pea_default.exclude_user = 0;
	pea_default.exclude_idle = 0;
	pea_default.mmap = 0;
	pea_default.comm = 0;
	pea_default.freq = 0;
	pea_default.inherit_stat = 0;
	pea_default.enable_on_exec = 0;
	pea_default.task = 0;
	pea_default.watermark = 0;
	pea_default.wakeup_events = 0;

	memset(&proc_fds, 0, sizeof(perf_fds) * MAX_PID_COUNT);
	for (int i = 0; i < MAX_PID_COUNT; i++) {
		proc_fds[i].last_update_ts = -1;
	}
}

void init_core_fds(int cid) {
	struct perf_event_attr pea = pea_default;
	int leader = 0;

	for (int i = 0; i < CNT_PERF_EVENTS; i++) {
		if (i % 6 == 0) {
			leader = i;
			pea.pinned = 1;
			core_fds[cid].fd[i] = set_perf_event_open(pea, PERF_EVENTS[i][0], PERF_EVENTS[i][1], cid, -1, -1);
		} else {
			pea.pinned = 0;
			core_fds[cid].fd[i] = set_perf_event_open(pea, PERF_EVENTS[i][0], PERF_EVENTS[i][1], cid, -1, core_fds[cid].fd[leader]);
		}
	}
}

void disable_core_fds(int cid) {
	for (int i = 0; i < CNT_PERF_EVENTS; i++) {
		close(core_fds[cid].fd[i]);
	}
}

void close_proc_fds(int pid) {
	for (int i = 0; i < CNT_PERF_EVENTS; i++) {
		close(proc_fds[pid].fd[i]);
		proc_fds[pid].fd[i] = -1;
		proc_fds[pid].last_update_ts = -1;
	}
}

void enable_core_fds(int cid) {
	for (int i = 0; i < CNT_PERF_EVENTS; i++) {
		ioctl(core_fds[cid].fd[i], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
	}
}

/* 	set all target perf_events for given pid 
 *	and save the fd, last update time 
 */
int set_perf_events_for_pid(int pid) {
	struct perf_event_attr pea = pea_default;
	int leader = 0;
	for (int i = 0; i < CNT_PERF_EVENTS; i++) {
		if (i % 6 == 0) {
			leader = i;
			pea.pinned = 1;
			proc_fds[pid].fd[i] = set_perf_event_open(pea, PERF_EVENTS[i][0], PERF_EVENTS[i][1], -1, pid, -1);
		} else {
			pea.pinned = 0;
			proc_fds[pid].fd[i] = set_perf_event_open(pea, PERF_EVENTS[i][0], PERF_EVENTS[i][1], -1, pid, proc_fds[pid].fd[leader]);
		}
	}
    return 1;
}

bool new_declared_pid(int pid, long long us_ts) {
	long long last_updated = proc_fds[pid].last_update_ts;
	/*
		last_updated <= 0 : the pid is initialized
		us_ts - last_updated > 2000000 : the pid is old one. 
	*/
	if (last_updated <= 0|| us_ts - last_updated > 2000000) {
		return true;
	} else {
		return false;
	}
}


void get_perf_event_proc(int pid, perf_event_res *per, long long us_ts) {
	memset(per, 0, sizeof(perf_event_res));
	per->timestamp = us_ts;

	if (new_declared_pid(pid, us_ts)) {			// first declared pid
		int res = set_perf_events_for_pid(pid);
		proc_fds[pid].last_update_ts = us_ts;
	} else {
		proc_fds[pid].last_update_ts = us_ts;
		if (proc_fds[pid].fd[0] > 0) {
			int res = read(proc_fds[pid].fd[0], &(per->perf_val[0]), sizeof(uint64_t) * (CNT_PERF_EVENTS + 1));
			if (res < 0 && DEBUG_MODE) printf("ERROR! get_proc %d / %d / %s\n", res, errno, strerror(errno));
		}
		ioctl(proc_fds[pid].fd[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
	}
}

void get_perf_event_core(int core_id, perf_event_res *per, long long us_ts, bool reset) {
	memset(per, 0, sizeof(perf_event_res));
	per->timestamp = us_ts;
	if (!reset) {
		int res = read(core_fds[core_id].fd[0], &(per->perf_val[0]), sizeof(uint64_t) * (CNT_PERF_EVENTS + 1));
		if (res < 0 && DEBUG_MODE) printf("ERROR! get_core(%d) %d / %d / %s\n", core_id, res, errno, strerror(errno));
	}
	 ioctl(core_fds[core_id].fd[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
}

void print_proc_fds(int pid) {
	printf("fds of pid %d : ", pid);
	for (int i = 0; i < CNT_PERF_EVENTS; i++) printf("%d ", proc_fds[pid].fd[i]);
	printf("\n");
}

void print_core_fds(int cid) {
    printf("fds of %d : ", cid);
    for (int i = 0; i < CNT_PERF_EVENTS; i++) printf("%d ", core_fds[cid].fd[i]);
    printf("\n");
}
