#include "CommandLineParser.h"

// parser
bool CommandLineParser::parseArguments(
	const int argc,
	const char** argv,
	OPCODE& status,
	byte* password,
	int& iKeylength,
	int& numFiles,
	std::unique_ptr<byte[][SAES_MAX_FILENAME_BUFFER_SIZE]>& files) {

	bool forceCPU = false;

	/* No arguments */
	if (argc < 2)
		exit(EXIT_FAILURE);

	/* Help command */
	if ((argv[1][0] == '-') && (argv[1][1] == 'h') && (argv[1][2] == 'e') && (argv[1][3] == 'l') && (argv[1][4] == 'p')) {
		printf("Format structure:\nOperation type: -{e,d}\nPassword: -p password\nKey size(Required only if encryption): -k {128, 192, 256}\nFiles: -f files\nExample: -e -b 64 -p loop -k 128 -f *.*\n");
		exit(EXIT_FAILURE);
	}

	/* Error-check command line argument formatting */
	if ((argv[1][0] != '-') || ((argv[1][1] != 'e') && (argv[1][1] != 'd'))) {
		printf("Error in command line: Near -{e,d} OPERATION command.\n");
		exit(EXIT_FAILURE);
	}
	if ((argv[2][0] != '-') || (argv[2][1] != 'p')) {
		printf("Error in command line: Near -p PASSWORD command.\n");
		exit(EXIT_FAILURE);
	}

	/* Get operation type */
	if ((argv[1][0] == '-') && ((argv[1][1] == 'e') || ((argv[1][1] == 'e') && (argv[1][2] == 'f')) || (argv[1][1] == 'd'))) {
		if (argv[1][1] == 'e')
			status = OPCODE::ENCRYPTION;
		else
			status = OPCODE::DECRYPTION;
		if (argv[1][2] == 'f')
			forceCPU = true;
	}

	/* Get password */
	if ((argv[2][0] == '-') && (argv[2][1] == 'p'))
		memcpy(password, argv[3], strlen(argv[3]) + 1);

	printf("Password: '%s'\n", password);

	/* Get key size */
	if (status == OPCODE::ENCRYPTION)
		if ((argv[4][0] == '-') && (argv[4][1] == 'k'))
			iKeylength = atoi(argv[5]);

	printf("Key size: '%i'\n", iKeylength);

	/* Get all files */
	int indexBeginFiles = -1;
	if (status == OPCODE::ENCRYPTION)
		indexBeginFiles = 6;
	else
		indexBeginFiles = 4;
	if ((argv[indexBeginFiles][0] == '-') && (argv[indexBeginFiles][1] == 'f')) {
		numFiles = argc - (indexBeginFiles + 1);
		printf("Num of files: '%i'\n", numFiles);
		// allocate space for files
		files = std::unique_ptr<byte[][SAES_MAX_FILENAME_BUFFER_SIZE]>(new byte[numFiles][SAES_MAX_FILENAME_BUFFER_SIZE]);

		// for all files
		for (int i = (indexBeginFiles + 1); i < argc; i++)
			memcpy(files.get()[i - (indexBeginFiles + 1)], argv[i], strlen(argv[i]) + 1);
	}

	for (int i = 0; i < numFiles; i++)
		printf("Filename added: '%s' \n", files.get()[i]);

	// return
	return forceCPU;

}