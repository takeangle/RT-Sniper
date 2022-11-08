# RT-Sniper PoC program
The PoC application of RT-Sniper: A Low-Overhead Defense Mechanism Pinpointing Cache Side-Channel Attacks

1. Usage
1) build
	make

2) run
	./run_time_sniper <mode> <sampling period>

	<mode>
		1 : only process-level monitoring (without print result)
		2 : only core-level monitoring (without print result)
		3 : RT-Sniper(single-sentinel)
		4 : RT-Sniper(multi-sentinel)

2. Source Tree
1) sniper.cpp
	main source. read mode and sampling period, execute proper mode

2) read_process.cpp
	read /proc directory and read current running processes 

3) read_perf.cpp
	open erf_event_open and read periodic perf events

4) readproc.cpp
	from 'ps linux command' git


3. Contact
Minkyu Song <minkyu0_song@korea.ac.kr>

