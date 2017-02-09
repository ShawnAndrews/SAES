#ifndef SAES_H
#define SAES_H


#ifdef __linux__
#include <inttypes.h>
#endif
#include "SAESconstants.h"
#include "Exceptions.h"
#include <stdio.h>
#include <string.h>
#include <memory>
#include <fstream>

#define xtime(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))

// SAES crypto class
class SAES {

public:

	// constructor
	SAES(int, byte*);

	// general purpose
	void storeCipherBlockAtOffset(byte*);
	void calculateNonce(byte*, const byte*);
	void setNonceCounters(std::unique_ptr<byte[]>&, const byte*, const _saes64);
	static _saes64 getFileSize(std::fstream&);
	static void extractFileSAESHeader(std::fstream&, const _saes64, byte*, byte*, byte*);
	void writeHeaders(std::fstream&, byte*, const int, const byte*, byte*, const int);
	void concatNonceCounter(byte*, const byte*, const _saes64);
	void setNewFilename(byte*, byte*, byte*);
	void setNewFilesize(const _saes64, int&, _saes64&);
	static void openFile(std::fstream&, const char*, const FILECODE);
	void closeFile(std::fstream&);
	void deleteFile(const char*);
	byte* getRoundKeys();
	int* getNumRounds();

	// decryption
	void invCipher();

	// encryption
	void cipher(const byte*);

private:

	// general purpose
	void addRoundKey(const int);
	void keyExpansion();

	// decryption
	void invShiftRows();
	void invSubBytes();
	void invMixColumns();

	// encryption
	void subBytes();
	void shiftRows();
	void mixColumns();

	int numRounds;
	int numKeyWords;
	int keyLen;
	byte encryptPlain[SAES_BLOCK_BYTES], encryptCiphertext[SAES_BLOCK_BYTES], decryptPlain[SAES_BLOCK_BYTES];
	byte key[SAES_MAX_KEY_BYTES], roundKey[SAES_MAX_ROUND_KEY_BYTES], state[SAES_STATE_ROW_COL_SIZE][SAES_STATE_ROW_COL_SIZE];

};

#endif
