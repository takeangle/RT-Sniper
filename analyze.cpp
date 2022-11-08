#include "analyze.h"

analyzer *anal_proc;
analyzer *anal_core;
void init_analyzer() {
	anal_proc = (analyzer *)malloc(sizeof(analyzer) * MAX_PID_COUNT);

	for(int i = 0; i < MAX_PID_COUNT; i++) {
		anal_proc[i].history = (cache_property *)malloc(sizeof(cache_property) * MAX_HISTORY);
		anal_proc[i].last_detected = 0;
		anal_proc[i].type = TYPE_PROCESS;
	}

	anal_core = (analyzer *)malloc(sizeof(analyzer) * MAX_CORE_COUNT);

	for (int i = 0; i < MAX_CORE_COUNT; i++) {
		anal_core[i].history = (cache_property *)malloc(sizeof(cache_property) * MAX_HISTORY);
		anal_core[i].last_detected = 0;
		anal_core[i].type = TYPE_CORE;
	}
}

int analyze_perf_event_core(int cid, perf_event_res per, long long timestamp, int granularity) {
	return analyze_perf_event(&anal_core[cid], per, THRES_MALICIOUS[IDX_CORE], timestamp, granularity);
}

int analyze_perf_event_proc(int pid, perf_event_res per, long long timestamp, int granularity) {
	return analyze_perf_event(&anal_proc[pid], per, THRES_MALICIOUS[IDX_PROC], timestamp, granularity);
}


const unsigned long long thres_instr = 500000;
const unsigned long long thres_cache = 500;
int analyze_perf_event(analyzer *anal, perf_event_res per, int threshold, long long timestamp, int granularity) {
	// reduce score by aging
    if (granularity == IDX_COURSE_GRAIN) {
        anal->score -= 10;
    } else if (granularity == IDX_FINE_GRAIN) {
        anal->score -= 4;
    }
	anal->score = (anal->score < 0) ? 0 : anal->score;


	// calcualte current score
	uint64_t cycle = per.perf_val[1];
	uint64_t instr = per.perf_val[2];
	uint64_t l3miss = per.perf_val[3];
	uint64_t l3hits = per.perf_val[4];
	uint64_t l2hits = per.perf_val[5];
	uint64_t l2miss = l3miss + l3hits;
	double l2mr = (l2miss + l2hits > 0) ? (double)l2miss / (double)(l2miss + l2hits) : -1.0;
	double l3mr = (l3miss + l3hits > 0) ? (double)l3miss / (double)(l3miss + l3hits) : -1.0;
	double ipc = (cycle > 0) ? (double)instr / (double)cycle : -1.0;



	if (granularity == IDX_COURSE_GRAIN && (instr < thres_instr || l3miss + l3hits + l2hits < thres_cache)) return RES_UNKNOWN;
	if (granularity == IDX_FINE_GRAIN && (instr < thres_instr / 5 || l3miss + l3hits + l2hits < thres_cache / 5)) {
		if (DEBUG_MODE && anal->type == TYPE_CORE) printf("%lu, %lu, %lu, %lu\n", instr, l3miss, l3hits, l2hits);
		return RES_UNKNOWN;
	}
	if (DEBUG_MODE && anal->type == TYPE_CORE) {
		printf("\tl2mr : %.6f\tl3mr : %.6f\tipc : %.6f\tinstr : %lu\n",  l2mr, l3mr, ipc, instr);
	 }

	if (ipc < 0) return RES_UNKNOWN;

	cache_property new_cp(l2mr, l3mr, ipc);
	int cursor = (anal->cnt_history++) % MAX_HISTORY;
	anal->history[cursor] = new_cp;

	anal->score += get_malicious_score_fr(anal->history[cursor], granularity);
	if (DEBUG_MODE)	printf("%f\n", anal->score);
	if (anal->score > threshold) {
		anal->score = 0;
		anal->last_detected = timestamp;
		return RES_MALICIOUS;
	} else {
		return RES_NORMAL;
	}

	return -1;
}

double get_malicious_score_fr(cache_property cur, int granularity) {
	double ret = 0.0;

	if (granularity == IDX_FINE_GRAIN) {
		if (cur.l2mr > 0.95) ret += 10 * cur.l2mr;
		else if (cur.l2mr > 0.90) ret += 7 * cur.l2mr;
		else if (cur.l2mr > 0.85) ret += 5 * cur.l2mr;

		if (cur.l3mr > 0.95) ret += 4 * cur.l3mr;
		else if (cur.l3mr > 0.90) ret += 2 * cur.l3mr;
		else if (cur.l3mr > 0.8) ret += 1 * cur.l3mr;

		if (cur.l3mr < 0.03) ret += 4 * (1 - cur.l3mr);
		else if (cur.l3mr < 0.5) ret += 2 * (1 - cur.l3mr);

		if (cur.ipc < 0.3) ret += 3;
		else if (cur.ipc < 0.5) ret += 2;
		else if (cur.ipc < 0.8) ret += 1;

		return ret;
	} else {
		if (cur.l2mr > 0.95) ret += 30 * cur.l2mr;
		else if (cur.l2mr > 0.90) ret += 20 * cur.l2mr;
		else if (cur.l2mr > 0.85) ret += 10 * cur.l2mr;

		if (cur.l3mr > 0.95 || cur.l3mr < 0.03) ret += 15 * cur.l3mr;
		else if (cur.l3mr > 0.90 || cur.l3mr < 0.5) ret += 10 * cur.l3mr;
		else if (cur.l3mr > 0.8) ret += 5 * cur.l3mr;

		if (cur.ipc < 0.3) ret += 5;
		else if (cur.ipc < 0.5) ret += 3;
		else if (cur.ipc < 0.8) ret += 2;

        return ret;
	}
	
	return ret;
}
