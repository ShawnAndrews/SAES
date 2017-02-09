#ifndef COMMANDLINEPARSER_H
#define COMMANDLINEPARSER_H

#include "SAESconstants.h"
#include <memory>
#include <iostream>

class CommandLineParser {

public:

	// parser
	static bool parseArguments(const int, const char**, OPCODE&, byte*, int&, int&, std::unique_ptr<byte[][SAES_MAX_FILENAME_BUFFER_SIZE]>&);

private:

	// constructor
	CommandLineParser();
	

};

#endif