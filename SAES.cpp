#include "SAES.h"

// constructor
SAES::SAES(int _keyLen, byte* _key) {

	// copy ken length
	keyLen = _keyLen;

	// copy key
	for (int i = 0; i < SAES_MAX_KEY_BYTES; i++)
		key[i] = _key[i];

	numRounds = keyLen;
	numKeyWords = numRounds / SAES_WORD_SIZE;
	numRounds = numKeyWords + SAES_MIN_ROUNDS;

	// expand key
	keyExpansion();
}

/* GENERAL FUNCTIONS */

/**
Get cipher block stored internally from call to Cipher().

@param cipherBlocks (OUT) Copy ciphertext from AES encryption to cipherBlocks.
*/
void SAES::storeCipherBlockAtOffset(byte* cipherBlocks) {

	// copy ciphertext
	memcpy(cipherBlocks, encryptCiphertext, SAES_BLOCK_BYTES);

}

/**
Derive an expanded form of the key buffer and produce {10, 12, 14} round keys, depending on key size.
*/
void SAES::keyExpansion()
{
	int i, j;
	byte temp[SAES_STATE_ROW_COL_SIZE], k;

	// 1st round key = original key
	for (i = 0; i < numKeyWords; i++)
	{
		roundKey[i * SAES_STATE_ROW_COL_SIZE] = key[i * SAES_STATE_ROW_COL_SIZE];
		roundKey[i * SAES_STATE_ROW_COL_SIZE + 1] = key[i * SAES_STATE_ROW_COL_SIZE + 1];
		roundKey[i * SAES_STATE_ROW_COL_SIZE + 2] = key[i * SAES_STATE_ROW_COL_SIZE + 2];
		roundKey[i * SAES_STATE_ROW_COL_SIZE + 3] = key[i * SAES_STATE_ROW_COL_SIZE + 3];
	}

	// subsequent round keys derived from previous round keys
	while (i < (SAES_STATE_ROW_COL_SIZE * (numRounds + 1)))
	{
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
		{
			temp[j] = roundKey[(i - 1) * SAES_STATE_ROW_COL_SIZE + j];
		}
		if (i % numKeyWords == 0)
		{
			{
				k = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = k;
			}
			{
				temp[0] = sbox[temp[0]];
				temp[1] = sbox[temp[1]];
				temp[2] = sbox[temp[2]];
				temp[3] = sbox[temp[3]];
			}

			temp[0] = temp[0] ^ rcon[i / numKeyWords];
		}
		else if ((numKeyWords > 6) && ((i % numKeyWords) == SAES_STATE_ROW_COL_SIZE))
		{
			{
				temp[0] = sbox[temp[0]];
				temp[1] = sbox[temp[1]];
				temp[2] = sbox[temp[2]];
				temp[3] = sbox[temp[3]];
			}
		}
		roundKey[i * SAES_STATE_ROW_COL_SIZE + 0] = roundKey[(i - numKeyWords) * SAES_STATE_ROW_COL_SIZE + 0] ^ temp[0];
		roundKey[i * SAES_STATE_ROW_COL_SIZE + 1] = roundKey[(i - numKeyWords) * SAES_STATE_ROW_COL_SIZE + 1] ^ temp[1];
		roundKey[i * SAES_STATE_ROW_COL_SIZE + 2] = roundKey[(i - numKeyWords) * SAES_STATE_ROW_COL_SIZE + 2] ^ temp[2];
		roundKey[i * SAES_STATE_ROW_COL_SIZE + 3] = roundKey[(i - numKeyWords) * SAES_STATE_ROW_COL_SIZE + 3] ^ temp[3];
		i++;
	}
}

/**
Derive nonce from password.

@param nonce (OUT) Buffer to hold result.
@param password (IN) Buffer holding given password.
*/
void SAES::calculateNonce(byte* nonce, const byte* password) {

	// calculate nonce
	for (int i = 0; i < SAES_NONCE_SIZE_BYTES; i++)
		nonce[i] = (password[i] & ~password[i + 1]) >> 2;

}

/**
Set nonce counters for all SAES file blocks.

@param nonceCounterBlocks (OUT) Buffer of concatenated nonce counters.
@param nonce (IN) Nonce derived from password.
@param numFileBlocks (IN) Number of blocks in file.
*/
void SAES::setNonceCounters(std::unique_ptr<byte[]>& nonceCounterBlocks, const byte* nonce, const _saes64 numFileBlocks) {

	// for all file blocks
	for (int i = 0; i < numFileBlocks; i++)
		concatNonceCounter(nonceCounterBlocks.get() + (i * SAES_BLOCK_BYTES), (const byte*)nonce, i);

}

/**
Get file size of given stream.

@param inFile (IN/OUT) Stream holding file data.

@return Return size of file.

@throw Throws FileException() if file is empty.
*/
_saes64 SAES::getFileSize(std::fstream& inFile) {

	_saes64 fileSize = -1;

	// set file size
	inFile.seekg(0, std::ios::end);
	fileSize = inFile.tellg();
	//printf("Size of file: %i\n", fileSize);
	inFile.seekg(0, std::ios::beg);
	if (fileSize == 0)
		throw FileException("Cannot encrypt an empty file. Exiting program.\n");

	// return
	return fileSize;

}

/**
Extract SAES file header data.

@param inFile (IN/OUT) Stream holding file data.
@param fileSize (IN) Size of file held by inFile.
@param padding (OUT) File padding needed up to SAES block size.
@param filenameFormat (OUT) File format of original file (ie., .txt, .jpg).
@param keylength (OUT) Key length used in encryption of original file.

@throw Throws FileException() if there was a problem reading header data.
*/
void SAES::extractFileSAESHeader(std::fstream& inFile, const _saes64 fileSize, byte* padding, byte* filenameFormat, byte* keylength) {


	// extract padding
	inFile.seekg(fileSize - (SAES_BLOCK_BYTES * (SAES_HEADERS - 0)), inFile.beg);
	inFile.read((char*)padding, SAES_BLOCK_BYTES);
	if (inFile.gcount() != SAES_BLOCK_BYTES)
		throw FileException("Error reading SAES header padding. Exiting program.\n");

	// extract file format
	inFile.seekg(fileSize - (SAES_BLOCK_BYTES * (SAES_HEADERS - 1)), inFile.beg);
	inFile.read((char*)filenameFormat, SAES_BLOCK_BYTES);
	if (inFile.gcount() != SAES_BLOCK_BYTES)
		throw FileException("Error reading SAES header file format. Exiting program.\n");

	// extract key length
	inFile.seekg(fileSize - (SAES_BLOCK_BYTES * (SAES_HEADERS - 2)), inFile.beg);
	inFile.read((char*)keylength, SAES_BLOCK_BYTES);
	if (inFile.gcount() != SAES_BLOCK_BYTES)
		throw FileException("Error reading SAES header key length. Exiting program.\n");

}

/**
Writes SAES file header data to end of file.

@param outFile (IN/OUT) Stream of file to which header data will be written.
@param padding (IN) Array which will be written to file
@param paddingLen (OUT) Length of padding up to SAES_BLOCK_SIZE.
@param filenameFormat (OUT) File format of original file (ie., .txt, .jpg).
@param keylength (OUT) Key length used in encryption of original file.
@param iKeylength (IN) Key size in integer form.
*/
void SAES::writeHeaders(
	std::fstream& outFile,
	byte* padding,
	const int paddingLen,
	const byte* filenameFormat,
	byte* keylength,
	const int iKeylength) {

	// store padding
	padding[0] = (paddingLen & 0x00FF);
	outFile.write((const char*)padding, SAES_MAX_PADDING_BYTES);

	// store file format
	outFile.write((const char*)filenameFormat, SAES_MAX_FILENAME_BYTES);

	// store key length
	keylength[0] = (iKeylength & 0x00FF) >> 0;
	keylength[1] = (iKeylength & 0xFF00) >> 8;
	outFile.write((const char*)keylength, SAES_MAX_KEYLENGTH_BYTES);

}

/**
Concatenate nonce and counter into noncecounter for encryption/decryption.

@param nonceCounter (OUT) Noncecounter for encryption/decryption.
@param nonce (IN) Random nonce.
@param counter (IN) Incrementing counter.
*/
void SAES::concatNonceCounter(byte* nonceCounter, const byte* nonce, const _saes64 counter) {

	// concatenate nonce and counter into noncecounter
	memcpy(nonceCounter, nonce, SAES_NONCE_SIZE_BYTES);
	nonceCounter[SAES_NONCE_SIZE_BYTES + 7] = (counter & 0x00000000000000FF) >> 0;
	nonceCounter[SAES_NONCE_SIZE_BYTES + 6] = (counter & 0x000000000000FF00) >> 8;
	nonceCounter[SAES_NONCE_SIZE_BYTES + 5] = (counter & 0x0000000000FF0000) >> 16;
	nonceCounter[SAES_NONCE_SIZE_BYTES + 4] = (counter & 0x00000000FF000000) >> 24;
	nonceCounter[SAES_NONCE_SIZE_BYTES + 3] = (counter & 0x000000FF00000000) >> 32;
	nonceCounter[SAES_NONCE_SIZE_BYTES + 2] = (counter & 0x0000FF0000000000) >> 40;
	nonceCounter[SAES_NONCE_SIZE_BYTES + 1] = (counter & 0x00FF000000000000) >> 48;
	nonceCounter[SAES_NONCE_SIZE_BYTES + 0] = (counter & 0xFF00000000000000) >> 56;

}

/**
Get file format of given file.

@param filename (IN) Entire filename buffer.
@param newFilename (OUT) Blank filename to which the file format and old filename will be appended.
@param filenameFormat (OUT) File format of filename.

@throw Throws FileException() if there was a problem finding file format.
*/
void SAES::setNewFilename(byte* filename, byte* newFilename, byte* filenameFormat) {

	// get file format
	char *tempPeriodPos = strchr((char*)filename, '.');
	if(!tempPeriodPos)
		throw FileException("Error cannot find '.' in filename to extract file format. Exiting program.\n");

	// copy file format
	memmove(filenameFormat, tempPeriodPos, strlen((const char*)tempPeriodPos) + 1);

	// set new filename with SAES file format
	memmove(newFilename, filename, (int)(tempPeriodPos - (char*)filename));
	memmove(newFilename + (int)(tempPeriodPos - (char*)filename), SAES_FILE_FORMAT, SAES_FILE_FORMAT_LEN + 1);

}

/**
Set new file size by calculating and adding padding.

@param inputFilesize (IN) Old filesize needed to calculate padding needed.
@param newFilename (OUT) Padding necessary for new filesize.
@param outputFilesize (OUT) New filesize with added padding. A multiple of AES block size.
*/
void SAES::setNewFilesize(const _saes64 inputFilesize, int& paddingLen, _saes64& outputFilesize) {

	// calculate required padding
	paddingLen = (SAES_BLOCK_BYTES - (inputFilesize % SAES_BLOCK_BYTES));
	if (paddingLen == 0x10)
		paddingLen = 0x00;

	// add padding to make new filesize a multiple of AES block size
	outputFilesize = inputFilesize + paddingLen;

}

/**
Open file for encryption/decryption.

@param fileStream (IN/OUT) Stream holding file data.
@param filename (IN) Name of file to open.
@param fileCode (IN) Mode of operation, input/output.

@throw Throws FileException() if there was a problem opening file.
*/
void SAES::openFile(std::fstream& fileStream, const char* filename, const FILECODE fileCode) {

	std::ios::openmode fileFlags;

	// set input/output flags
	if (fileCode == FILECODE::FILE_INPUT) {
		fileFlags = std::fstream::in | std::fstream::binary;
	}
	else if (fileCode == FILECODE::FILE_OUTPUT) {
		fileFlags = std::fstream::out | std::fstream::binary;
	}

	// open file
	fileStream.open((const char*)filename, fileFlags);
	if (!fileStream.is_open())
		throw FileException("Failed to open file. Exiting program.\n");

}

/**
Close file for encryption/decryption.

@param fileStream (IN/OUT) Stream holding file data.
*/
void SAES::closeFile(std::fstream& fileStream) {

	// close file
	fileStream.close();

}

/**
Delete file from encryption/decryption.

@param filename (IN) Name of file to open.
*/
void SAES::deleteFile(const char* filename) {

	// delete file
	remove(filename);

}

/**
Get round keys.

@return Pointer to round keys.
*/
byte* SAES::getRoundKeys() {
	return roundKey;
}

/**
Get number of rounds.

@return Pointer to number of rounds.
*/
int* SAES::getNumRounds() {
	return &numRounds;
}

/**
Add round key to current state.

@param round (IN) Index of round key to be added.
*/
void SAES::addRoundKey(const int round)
{
	int i, j;
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
			state[i][j] ^= roundKey[round * SAES_STATE_ROW_COL_SIZE * SAES_STATE_ROW_COL_SIZE + i * SAES_STATE_ROW_COL_SIZE + j];
}

/* DECRYPT FUNCTIONS */

/**
Shift rows in state to the left with different offsets where offset is the row number.
*/
void SAES::invShiftRows()
{
	byte temp;

	// rotate first row 1 columns to right
	temp = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp;

	// rotate second row 2 columns to right
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	// rotate third row 3 columns to right
	temp = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp;
}

/**
Substitute bytes in current state with those at the same index in inverse s-box.
*/
void SAES::invSubBytes()
{
	int i, j;
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
			state[i][j] = rsbox[state[i][j]];
}

/**
Mix columns of the current state.
*/
void SAES::invMixColumns()
{
	int i;
	byte a, b, c, d;
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
	{
		a = state[0][i];
		b = state[1][i];
		c = state[2][i];
		d = state[3][i];

		state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

/**
Decrypt cipher block.
*/
void SAES::invCipher()
{
	int i, j, round = 0;

	// copy the input ciphertext to state array.
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
			state[j][i] = encryptCiphertext[i * SAES_STATE_ROW_COL_SIZE + j];

	// add the 1st round key to the state before starting rounds
	addRoundKey(numRounds);

	// perform inverse cipher for all rounds except the last
	for (round = numRounds - 1; round > 0; round--)
	{
		invShiftRows();
		invSubBytes();
		addRoundKey(round);
		invMixColumns();
	}

	// perform last round of decryption
	invShiftRows();
	invSubBytes();
	addRoundKey(0);

	// copy result to internal buffer
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
			decryptPlain[i * SAES_STATE_ROW_COL_SIZE + j] = state[j][i];
}

/* ENCRYPT FUNCTIONS */

/**
Substitute bytes in current state with those at the same index in s-box.
*/
void SAES::subBytes()
{
	int i, j;
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
			state[i][j] = sbox[state[i][j]];
}

/**
Shift rows in state to the left with different offsets where offset is row number.
*/
void SAES::shiftRows()
{
	byte temp;

	// rotate first row 1 columns to left
	temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;

	// rotate second row 2 columns to left
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	// rotate third row 3 columns to left
	temp = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;
}

/**
Mix columns of the current state.
*/
void SAES::mixColumns()
{
	int i;
	byte Tmp, Tm, t;
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
	{
		t = state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		Tm = state[0][i] ^ state[1][i]; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp;
		Tm = state[1][i] ^ state[2][i]; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp;
		Tm = state[2][i] ^ state[3][i]; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp;
		Tm = state[3][i] ^ t; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp;
	}
}

/**
Encrypt plaintext block.

@param plaintextBlocks (IN) Buffer holding plaintext file data.
*/
void SAES::cipher(const byte* plaintextBlocks)
{
	int i, j, round = 0;
	byte* cipherBlocks = 0;

	// copy plaintext to internal cipherblock buffer
	memcpy(encryptPlain, plaintextBlocks, SAES_BLOCK_BYTES);

	/* CIPHER */

	// copy plaintext to state array
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
			state[i][j] = encryptPlain[i * SAES_STATE_ROW_COL_SIZE + j];

	// add the 1st round key to the state before starting the rounds
	addRoundKey(0);

	// perform cipher for all rounds except the last
	for (round = 1; round < numRounds; round++)
	{
		subBytes();
		shiftRows();
		mixColumns();
		addRoundKey(round);
	}

	// perform last round of encryption
	subBytes();
	shiftRows();
	addRoundKey(round);

	// copy result to internal buffer
	for (i = 0; i < SAES_STATE_ROW_COL_SIZE; i++)
		for (j = 0; j < SAES_STATE_ROW_COL_SIZE; j++)
			encryptCiphertext[i * SAES_STATE_ROW_COL_SIZE + j] = state[i][j];
}
