#ifndef CTIMER_H
#define CTIMER_H

#include <chrono>

class CTimer {

public:

	// constructor
	CTimer();

	// start
	void start();

	// end
	size_t end();

	// reset
	void reset();

	// get elapsed time
	size_t getElapsedTime();

	// print time
	void printTime();

private:

	std::chrono::high_resolution_clock::time_point startPoint, endPoint;
	size_t elapsedTime;
};

#endif