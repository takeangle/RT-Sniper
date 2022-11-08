#include "read_process.h"
#include "readproc.h"

bool lock_grp;
process_list_all pla;
void init_process_list_all() {
	memset(&pla, 0, sizeof(process_list_all));
	lock_grp = false;
}

process_list get_running_processes(int core_id, long long ts) {
	if (lock_grp || pla.last_updated + 1000 > ts) {
		return pla.pl[core_id];
	}

	lock_grp = true;
	memset(&pla, 0, sizeof(process_list_all));
	DIR *dp;
	struct dirent *dir;
	if ((dp = opendir("/proc")) == NULL) {
		if (DEBUG_MODE) printf("ERROR: opendir error %d %s\n", errno, strerror(errno));
		return pla.pl[core_id];
	}
	while((dir = readdir(dp)) != NULL) {
		if (dir->d_ino == 0) continue;
		int pid = string_to_integer(dir->d_name);
		if (pid != -1) {
			process_info pi = get_process_info(pid);
			if (pi.pid != -1 && pla.pl[pi.psr].cnt < MAX_PROCESSES_ON_CORE) {
				pla.pl[pi.psr].pid[pla.pl[pi.psr].cnt++] = pi.pid;
			}
		}
	}
	closedir(dp);
	pla.last_updated = ts;

	lock_grp = false;

	return pla.pl[core_id];
}


