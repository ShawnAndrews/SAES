#include "CTimer.h"

// constructor
CTimer::CTimer() : startPoint({}), endPoint({}), elapsedTime(0) {}

// start timer
void CTimer::start() {

	// start
	startPoint = std::chrono::high_resolution_clock::now();

}

// end timer
size_t CTimer::end() {

	// end
	endPoint = std::chrono::high_resolution_clock::now();

	// store elapsed time
	elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(endPoint - startPoint).count();

	// return
	return elapsedTime;

}

// reset timer
void CTimer::reset() {

	// reset
	startPoint = {};
	endPoint = {};
	elapsedTime = 0;

}

// get elapsed time
size_t CTimer::getElapsedTime() {

	return elapsedTime;

}

// print time
void CTimer::printTime() {

	// print
	printf("Timer completed in %d ms \n", getElapsedTime());

}