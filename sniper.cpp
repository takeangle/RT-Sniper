#include "./util.h"
#include "./read_process.h"
#include "./read_perf.h"
#include "./analyze.h"
#include "./readproc.h"

void process_level_work(int core_id, struct timeval tp);
void core_level_work(int core_id);

#define MODE_ONLYPROCESS		1
#define MODE_ONLYCORE			2
#define MODE_MIXSEQUENTIAL		3
#define MODE_MIXPARALLEL		4

int probe_period;

int main(int argc, char * argv[]) {
	if (argc < 3) {
		printf("Invalid: sudo ./run_time_sniper <mode> <period time>\n");
		printf("  -- period time : usec\n");
		printf("  -- mode : \n");
		printf("     1 : only process scan\n");
		printf("     2 : only core scan\n");
		printf("     3 : single-sentinel\n");
		printf("     4 : multi-sentinels\n");
		exit(0);
	}
	int mode = atoi(argv[1]);
	probe_period = atoi(argv[2]);

	init_pea();
	init_analyzer();

	printf("mode : %d\n", mode);
	printf("period : %d us\n", probe_period);
	if (mode == MODE_ONLYPROCESS) {
		struct timeval tp;
		process_list pil;
		perf_event_res per_proc;
		while (true) {
			usleep(probe_period);
			gettimeofday(&tp, NULL);
			long long timestamp = tp.tv_usec + tp.tv_sec * 1000000;
			pil = get_running_processes(-1, timestamp);
			for (int j = 0; j < pil.cnt; j++) {
				int pid = pil.pid[j];

				get_perf_event_proc(pid, &per_proc, timestamp);
				int res_anpe = analyze_perf_event_proc(pid, per_proc, timestamp, IDX_FINE_GRAIN);
				if (res_anpe < 0) {
					printf("ERROR: analyze_perf_event invalid : %d\n", pid);
					continue;
				}

				switch (res_anpe) {
					case RES_MALICIOUS:
						printf("MALICIOUS!\tts : \t%lld\t| pid : \t%d\n", timestamp, pid);
						break;
					default:
						break;
				}
			}
		}

		return 0;
	}

	if (mode == MODE_ONLYCORE) {
		perf_event_res per_core[16];
		struct timeval tp;
		for (int i = 0; i < 16; i++) {
			init_core_fds(i);
			memset(&per_core[i], 0, sizeof(perf_event_res));
		}
		while (1) {
			usleep(probe_period);
			gettimeofday(&tp, NULL);
			long long timestamp = tp.tv_usec + tp.tv_sec * 1000000;
			for (int i = 0; i < 16; i++) {
				get_perf_event_core(i, &per_core[i], timestamp, false);
				int res_anpe = analyze_perf_event_core(i, per_core[i], timestamp, IDX_COURSE_GRAIN);
			}
		}
		return 0;
	}

	if (mode == MODE_MIXSEQUENTIAL) {
		perf_event_res per_core;
		bool reset[16];
		for (int i = 0; i < 16; i++) {
			reset[i] = true;
		}
		struct timeval tp;
		long long timestamp = 0;
		while (1) {
			usleep(probe_period);
			for (int i = 0; i < 16; i++) {
				gettimeofday(&tp, NULL);
				timestamp = tp.tv_usec + tp.tv_sec * 1000000;
				if (reset[i]) {
					init_core_fds(i);
					reset[i] = false;
					continue;
				}
				get_perf_event_core(i, &per_core, timestamp, reset[i]);
				int res_anpe = analyze_perf_event_core(i, per_core, timestamp, IDX_COURSE_GRAIN);
				if (res_anpe == RES_MALICIOUS) {
					disable_core_fds(i);
					process_level_work(i, tp);
					reset[i] = true;
				}
			}
		}		
		return 0;
	}	

	std::vector<std::future<void>> asyncCoreResults;
	for (int core_id = 0; core_id < 16; core_id++) {
		asyncCoreResults.push_back(std::async(std::launch::async, core_level_work, core_id));
	}
	for (auto & ar : asyncCoreResults) {
		ar.wait();
	}
	return 0;
}

void core_level_work(int core_id) {
    if (DEBUG_MODE && core_id != DETAIL_CORE) return;

    perf_event_res per_core;
    struct timeval tp;
    bool reset = true;
    long long timestamp = 0;

    while (1) {
        usleep(probe_period);
        gettimeofday(&tp, NULL);
        timestamp = tp.tv_usec + tp.tv_sec * 1000000;
        if (reset) {
            init_core_fds(core_id);
            reset = false;
            continue;
        }
        get_perf_event_core(core_id, &per_core, timestamp, reset);

        int res_anpe = analyze_perf_event_core(core_id, per_core, timestamp, (probe_period < 5000) ? IDX_FINE_GRAIN : IDX_COURSE_GRAIN);
        if (res_anpe == RES_MALICIOUS) {
            disable_core_fds(core_id);
            process_level_work(core_id, tp);
            reset = true;
        }
    }
}


struct process_list_on_core{
    int pid;
    struct process_list_on_core *next;

    void push(process_list_on_core *pl1) {
        this->next = pl1;
    }
};

void process_level_work(int core_id, struct timeval tp) {
    perf_event_res per_proc;
    bool process_list_on_core[MAX_PID_COUNT];

    process_list pl;

    int probe = (probe_period < 1000) ? 1000 : probe_period;
    bool pinpointed = false;

    for (int iter = 0; iter < 5 && !pinpointed; iter++) {
        usleep(probe);
        gettimeofday(&tp, NULL);
        long long timestamp = tp.tv_usec + tp.tv_sec * 1000000;
        pl = get_running_processes(core_id, timestamp);
        for (int j = 0; j < pl.cnt; j++) {
            int pid = pl.pid[j];

            process_list_on_core[pid] = true;
            get_perf_event_proc(pid, &per_proc, timestamp);
            int res_anpe = analyze_perf_event_proc(pid, per_proc, timestamp, IDX_FINE_GRAIN);
            if (res_anpe < 0) {
                printf("ERROR: analyze_perf_event invalid : %d\n", pid);
                continue;
            }

            switch (res_anpe) {
                case RES_MALICIOUS:
                    printf("MALICOUS %d : \t%lld\t%d\n", iter, timestamp, pid);
                    pinpointed = true;
                    break;
                default:
                    break;
            }
        }
    }
    for (int i = 0; i < MAX_PID_COUNT; i++) {
        if (process_list_on_core[i] == true) {
            close_proc_fds(i);
        }
    }
}

