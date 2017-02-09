/**
main.cpp
Purpose: Proprietary file encryption, SAES, based on AES standard cryptography.

@author Shawn Andrews (BSc (hons.))
@version 1.0 4/01/16
*/

#include <stdlib.h>
#include <math.h>
#include <memory>
#include <chrono>
#include <iostream>
#include "SAES.h"
#include "GPU.h"
#include "CTimer.h"
#include "CommandLineParser.h"

using namespace std;

int main(int argc, char** argv)
{
	int numFiles = -1;
	int iKeylength = -1;
	byte password[SAES_BLOCK_BYTES] = { 0x00 };
	byte filename[SAES_MAX_FILENAME_BUFFER_SIZE] = { 0x00 };
	unique_ptr<byte[][SAES_MAX_FILENAME_BUFFER_SIZE]> files = nullptr;
	unique_ptr<byte[]> gpuName = nullptr;
	OPCODE status;
	GPU gpu(GPU_KERNEL_FILENAME);
	bool gpuEnabled;
	bool forceCPU;

	/* Parse arguments */
	forceCPU = CommandLineParser::parseArguments(argc, (const char**)argv, status, password, iKeylength, numFiles, files);

	// preemptively force CPU mode
	if (forceCPU)
		gpuEnabled = false;
	else
		gpuEnabled = true;

	// skip if forced CPU execution
	if (!forceCPU) {

		/* Build program and set GPU/CPU execution mode */
		try {
			gpu.buildProgram(gpuName);
			gpu.createKernelFromProgram(GPU_KERNEL_FUNC_NAME);
			printf("Using GPU device: '%s' \n", gpuName.get());
			gpuEnabled = true;
		}
		catch (GPUException& e) {
			printf(e.getError());
			printf("Defaulting to single-core CPU execution.\n");
			gpuEnabled = false;
		}

	}

	/* Perform operation for all files */
	for (int fileIndex = 0; fileIndex < numFiles; fileIndex++) {

		std::fstream inFile = {};
		std::fstream outFile = {};
		int paddingLen = -1;
		_saes64 inputFilesize = -1;
		_saes64 outputFilesize = -1;
		_saes64 numBufferIterations = -1;
		_saes64 numCipherIterations = -1;
		_saes64 numCipherLastIterations = -1;
		byte filenameFormat[SAES_MAX_FILENAME_BYTES] = { 0x00 };
		byte padding[SAES_MAX_PADDING_BYTES] = { 0x00 };
		byte newFilename[SAES_MAX_FILENAME_BYTES] = { 0x00 };
		byte nonce[SAES_NONCE_SIZE_BYTES] = { 0x00 };
		byte keylength[SAES_MAX_KEYLENGTH_BYTES] = { 0x00 };
		unique_ptr<byte[]> cipherBlocks = nullptr;
		unique_ptr<byte[]> plaintextBlocks = nullptr;
		cl_mem memBufferNonceCounterBlocks, memBufferSBox, memBufferRoundKeys, memBufferNumRounds;
		CTimer timer = {};

		// set current file
		memcpy(filename, files.get()[fileIndex], strlen((const char*)files.get()[fileIndex]) + 1);

		// select operation
		if (status == OPCODE::ENCRYPTION) {

			byte encryptPlain[SAES_BLOCK_BYTES] = { 0x00 };
			SAES saes(iKeylength, password);
			
			// start timer
			timer.start();

			try {
				// extract input file format and set output filename
				saes.setNewFilename(filename, newFilename, filenameFormat);

				// open files
				saes.openFile(inFile, (const char*)filename, FILECODE::FILE_INPUT);
				saes.openFile(outFile, (const char*)newFilename, FILECODE::FILE_OUTPUT);

				// get file size
				inputFilesize = saes.getFileSize(inFile);
			}
			catch (FileException& e) {
				printf(e.getError());
				exit(EXIT_FAILURE);
			}

			// calculate file information
			saes.setNewFilesize(inputFilesize, paddingLen, outputFilesize);
			numBufferIterations = ceil((outputFilesize / _saes64d(SAES_CPU_BUFFER_SIZE)));
			numCipherIterations = SAES_CPU_BUFFER_SIZE / SAES_BLOCK_BYTES;
			numCipherLastIterations = (outputFilesize % SAES_CPU_BUFFER_SIZE) / SAES_BLOCK_BYTES;

			//printf("Total buffer iterations #%i \n", numBufferIterations);
			//printf("Total blocks in buffer iterations #%i \n", BUFFER_SIZE / SAES_BLOCK_BYTES);

			// calculate nonce
			saes.calculateNonce(nonce, password);

			// GPU/CPU execution
			if (gpuEnabled) {

				unique_ptr<byte[]> fileBlocks = unique_ptr<byte[]>(new byte[outputFilesize]);
				unique_ptr<byte[]> nonceCounterBlocks = unique_ptr<byte[]>(new byte[outputFilesize]);
				int numFileBlocks = outputFilesize / SAES_BLOCK_BYTES;
				
				memset(nonceCounterBlocks.get(), 0, outputFilesize);

				// Read next buffer
				inFile.read((char*)fileBlocks.get(), inputFilesize);

				// Calculate all nonces
				saes.setNonceCounters(nonceCounterBlocks, nonce, numFileBlocks);

				try {

					// Create and write to buffer
					gpu.writeMemBuffer(memBufferNonceCounterBlocks, nonceCounterBlocks.get(), sizeof(byte) * outputFilesize, CL_MEM_READ_WRITE);

					// Create and write to buffer
					gpu.writeMemBuffer(memBufferSBox, sbox, sizeof(byte) * SAES_LOOKUP_TABLE_SIZE, CL_MEM_READ_ONLY);

					// Create and write to buffer
					gpu.writeMemBuffer(memBufferRoundKeys, saes.getRoundKeys(), sizeof(byte) * SAES_MAX_ROUND_KEY_BYTES, CL_MEM_READ_ONLY);

					// Create and write to buffer
					gpu.writeMemBuffer(memBufferNumRounds, saes.getNumRounds(), sizeof(int), CL_MEM_READ_ONLY);

					// Add kernel param
					gpu.addKernelParam(0, memBufferNonceCounterBlocks);

					// Add kernel param
					gpu.addKernelParam(1, memBufferSBox);

					// Add kernel param
					gpu.addKernelParam(2, memBufferRoundKeys);

					// Add kernel param
					gpu.addKernelParam(3, memBufferNumRounds);

					// Execute kernel
					gpu.execute1DKernel(outputFilesize);

					// Read buffer
					gpu.readMemBuffer(memBufferNonceCounterBlocks, nonceCounterBlocks.get(), sizeof(byte) * outputFilesize);

					for (int i = 0; i < (outputFilesize/SAES_BLOCK_BYTES); i++) {
						for (int j = 0; j < SAES_BLOCK_BYTES; j++)
							printf("'%02X' ", nonceCounterBlocks[j + (i * SAES_BLOCK_BYTES)]);
						printf("\n");
					}
					/*printf("\n"); printf("\n");
					for (int i = 0; i < (240 / SAES_BLOCK_BYTES); i++) {
						for (int j = 0; j < SAES_BLOCK_BYTES; j++)
							printf("0x%02X, ", nonceCounterBlocks.get()[j + (i * SAES_BLOCK_BYTES)]);
						printf("\n");
					}*/
						
					// Free
					gpu.freeMemObject(memBufferNonceCounterBlocks);
					gpu.freeMemObject(memBufferSBox);
					gpu.freeMemObject(memBufferRoundKeys);
					gpu.freeMemObject(memBufferNumRounds);
				}
				catch (GPUException& e) {
					printf(e.getError());
					exit(EXIT_FAILURE);
				}

				// XOR
				for (_saes64 index = 0; index < outputFilesize; index++)
					fileBlocks[index] = fileBlocks[index] ^ nonceCounterBlocks[index];

				// Write to file
				outFile.write((const char*)fileBlocks.get(), outputFilesize);

				// Write SAES headers to end of file
				saes.writeHeaders(outFile, padding, paddingLen, filenameFormat, keylength, iKeylength);

			}
			else {

				// loop all buffers in file
				for (_saes64 i = 0; i < numBufferIterations; i++) {

					plaintextBlocks = unique_ptr<byte[]>(new byte[SAES_CPU_BUFFER_SIZE]);
					cipherBlocks = unique_ptr<byte[]>(new byte[SAES_CPU_BUFFER_SIZE]);
					bool lastBuffer = false;

					// Read next buffer
					inFile.seekg((i * SAES_CPU_BUFFER_SIZE), inFile.beg);
					inFile.read((char*)plaintextBlocks.get(), SAES_CPU_BUFFER_SIZE);

					// Detect if last buffer
					if (i == (numBufferIterations - 1))
						lastBuffer = true;

					// Cipher until buffer size
					if (lastBuffer)
						numCipherIterations = numCipherLastIterations;
					for (_saes64 j = 0; j < numCipherIterations; j++) {

						int cipherOffset = j * SAES_BLOCK_BYTES;
						byte nonceCounter[SAES_BLOCK_BYTES] = { 0x00 };
						_saes64 counter = (i * (SAES_CPU_BUFFER_SIZE / SAES_BLOCK_BYTES)) + j;

						// concatenate nonce and counter
						saes.concatNonceCounter(nonceCounter, nonce, counter);

						// cipher and copy result
						saes.cipher(nonceCounter);
						saes.storeCipherBlockAtOffset(cipherBlocks.get() + cipherOffset);

						for (int i = 0; i < SAES_BLOCK_BYTES; i++)
							printf("'%02X' ", cipherBlocks[i + (j * SAES_BLOCK_BYTES)]);
						printf("\n");

					}

					// XOR
					for (_saes64 index = 0; index < SAES_CPU_BUFFER_SIZE; index++)
						cipherBlocks[index] = cipherBlocks[index] ^ plaintextBlocks[index];

					// Write to file
					for (_saes64 index = 0; index < numCipherIterations; index++)
						outFile.write((const char*)(cipherBlocks.get() + (index * SAES_BLOCK_BYTES)), SAES_BLOCK_BYTES);

					// Write SAES headers to end of file
					if (lastBuffer)
						saes.writeHeaders(outFile, padding, paddingLen, filenameFormat, keylength, iKeylength);

				}

			}

			// close files
			saes.closeFile(inFile);
			saes.closeFile(outFile);

			// remove input file
			saes.deleteFile((const char*)filename);

			// end timer
			timer.end();

			// print timer
			timer.printTime();

		}
		else if (status == OPCODE::DECRYPTION) {

			try {
				// open input file
				SAES::openFile(inFile, (const char*)filename, FILECODE::FILE_INPUT);

				// get file size
				inputFilesize = SAES::getFileSize(inFile);

				// extract SAES file header data
				SAES::extractFileSAESHeader(inFile, inputFilesize, padding, filenameFormat, keylength);
			}
			catch (FileException& e) {
				printf(e.getError());
				exit(EXIT_FAILURE);
			}

			// set key length
			iKeylength = (keylength[1] << 8) | (keylength[0] << 0);

			byte encryptPlain[SAES_BLOCK_BYTES] = { 0x00 };
			SAES saes(iKeylength, password);

			// start timer
			timer.start();

			// set output filename
			char *tempPeriodPos = strchr((char*)filename, '.');
			memcpy(newFilename, filename, (int)(tempPeriodPos - (char*)filename));
			memcpy(newFilename + (int)(tempPeriodPos - (char*)filename), filenameFormat, strlen((const char*)filenameFormat) + 1);

			try {
				// open output file
				saes.openFile(outFile, (const char*)newFilename, FILECODE::FILE_OUTPUT);
			}
			catch (FileException& e) {
				printf(e.getError());
				exit(EXIT_FAILURE);
			}

			// get file size
			paddingLen = padding[0];
			outputFilesize = inputFilesize - (SAES_BLOCK_BYTES * SAES_HEADERS) - paddingLen;
			numBufferIterations = ceil((outputFilesize / _saes64d(SAES_CPU_BUFFER_SIZE)));
			numCipherIterations = SAES_CPU_BUFFER_SIZE / SAES_BLOCK_BYTES;
			numCipherLastIterations = ceil((outputFilesize % SAES_CPU_BUFFER_SIZE) / _saes64d(SAES_BLOCK_BYTES));

			//printf("Total buffer iterations #%i \n", numBufferIterations);
			//printf("Total blocks in buffer iterations #%i \n", BUFFER_SIZE / SAES_BLOCK_BYTES);

			// calculate nonce
			saes.calculateNonce(nonce, password);

			// loop all buffers in file
			for (_saes64 i = 0; i < numBufferIterations; i++) {

				cipherBlocks = unique_ptr<byte[]>(new byte[SAES_CPU_BUFFER_SIZE]);
				plaintextBlocks = unique_ptr<byte[]>(new byte[SAES_CPU_BUFFER_SIZE]);
				bool lastBuffer = false;

				// Read file to fill plaintext buffer
				inFile.seekg((i * SAES_CPU_BUFFER_SIZE), inFile.beg);
				inFile.read((char*)cipherBlocks.get(), SAES_CPU_BUFFER_SIZE);

				// Detect if last buffer
				if (i == (numBufferIterations - 1))
					lastBuffer = true;

				// cipher all blocks in current buffer size
				if (lastBuffer)
					numCipherIterations = numCipherLastIterations;
				for (_saes64 j = 0; j < numCipherIterations; j++) {

					int plaintextOffset = j * SAES_BLOCK_BYTES;
					byte nonceCounter[SAES_BLOCK_BYTES] = { 0x00 };
					_saes64 counter = (i * (SAES_CPU_BUFFER_SIZE / SAES_BLOCK_BYTES)) + j;

					// concatenate nonce and counter
					saes.concatNonceCounter(nonceCounter, nonce, counter);

					// cipher and copy result
					saes.cipher(nonceCounter);
					saes.storeCipherBlockAtOffset(plaintextBlocks.get() + plaintextOffset);

				}

				// XOR
				for (_saes64 index = 0; index < SAES_CPU_BUFFER_SIZE; index++)
					plaintextBlocks[index] = plaintextBlocks[index] ^ cipherBlocks[index];

				// Write to file
				for (_saes64 index = 0; index < numCipherIterations; index++) {
					if (lastBuffer && (index == (numCipherIterations - 1)))
						outFile.write((const char*)(plaintextBlocks.get() + (index * SAES_BLOCK_BYTES)), SAES_BLOCK_BYTES - paddingLen);
					else
						outFile.write((const char*)(plaintextBlocks.get() + (index * SAES_BLOCK_BYTES)), SAES_BLOCK_BYTES);

				}

			}

			// close files
			saes.closeFile(inFile);
			saes.closeFile(outFile);

			// remove input file
			saes.deleteFile((const char*)filename);

			// end timer
			timer.end();

			// print timer
			timer.printTime();

		}

	}

	#ifdef _WIN32
		system("pause");
	#endif
	return 0;
}
