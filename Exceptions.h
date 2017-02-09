#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>

// file exception class
class FileException : public std::exception {

public:

	FileException(const char* _errorString) : errorString(_errorString) {}

	~FileException() {}

	const char* getError() {
		return errorString;
	}

private:

	FileException() {}

	const char* errorString;

};

// GPU exception class
class GPUException {

public:

	GPUException(const char* _errorString) : errorString(_errorString) {}

	~GPUException() {}

	const char* getError() {
		return errorString;
	}

private:

	GPUException() {}

	const char* errorString;

};


#endif