#ifndef __ANALYZE_H_
#define __ANALYZE_H_

#include "util.h"

typedef class Cache_Property {
public:
    double l2mr;
    double l3mr;
    double ipc;

    Cache_Property(double l2mr, double l3mr, double ipc) {
        this->l2mr = l2mr;
        this->l3mr = l3mr;
		this->ipc = ipc;
    }

} cache_property;

#define MAX_HISTORY 10

#define IDX_PROC 0
#define IDX_CORE 1

#define IDX_FINE_GRAIN 1
#define IDX_COURSE_GRAIN 2

#define TYPE_PROCESS 0
#define TYPE_CORE 1

const int THRES_MALICIOUS[2] = {30, 50};

typedef struct Analyzer {

    cache_property *history; // MAX_history
    int cnt_history;
    double score;
    long long last_detected;
	int type;
} analyzer;


void init_analyzer();

int analyze_perf_event_core(int cid, perf_event_res perc, long long timestamp, int granularity);

int analyze_perf_event_proc(int pid, perf_event_res perp, long long timestamp, int granularity);

int analyze_perf_event(analyzer *anal, perf_event_res per, int threshold, long long timestamp, int granularity);

double get_malicious_score_fr(cache_property cur, int granularity);

#endif
