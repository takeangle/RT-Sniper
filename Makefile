FILES= sniper.cpp read_perf.cpp read_process.cpp analyze.cpp util.cpp readproc.cpp 

all:
#	g++ $(FILES) -o run_time_sniper -lpthread
	g++ -Wall -g -O3 -Wno-unknown-pragmas -fPIC -std=c++11 -Wextra -pthread  -o run_time_sniper $(FILES) -lpthread -lrt

clean:
	rm -f run_time_sniper
