#ifndef GPU_H
#define GPU_H

#include <fstream>
#include <memory>
#include <CL/cl.h>
#include "Exceptions.h"

#define CL_CHECK(_expr)                                                         \
   do {                                                                         \
     cl_int _err = _expr;                                                       \
     if (_err == CL_SUCCESS)                                                    \
       break;                                                                   \
     fprintf(stderr, "OpenCL Error: '%s' returned %d!\n", #_expr, (int)_err);   \
     abort();                                                                   \
      } while (0)

#define GPU_NUM_GPUS 1
#define GPU_ONE_DIMENSION 1
#define GPU_TWO_DIMENSION 2
#define GPU_MAX_NAME_SIZE 256
#define GPU_KERNEL_FILENAME "kernel.cl"
#define GPU_KERNEL_FUNC_NAME "encrypt"

typedef unsigned char byte;

class GPU {

public:

	// constructor
	GPU(const char*);

	//destructor
	~GPU();

	// build program from file
	void buildProgram(std::unique_ptr<byte[]>&);

	// create kernel from program
	void createKernelFromProgram(const char*);

	// write data to mem buffer
	void writeMemBuffer(cl_mem&, const void*, size_t, int);

	// read mem buffer data to buffer
	void readMemBuffer(cl_mem&, void*, size_t);

	// add kernel parameter
	void addKernelParam(const int, const cl_mem&);

	// execute 1d kernel
	void execute1DKernel(const int);

	// execute 2d kernel
	void execute2DKernel(const int*, const int*);

	// free mem object
	void freeMemObject(cl_mem&);

private:

	// check if file exists
	bool fileExists();

	// get file size
	size_t getFilesize();

	// read file data to buffer
	void readFileToBuffer();

	std::unique_ptr<cl_platform_id[]> platformIds;
	std::unique_ptr<char[]> fileBuffer;
	cl_device_id deviceGPUId;
	cl_command_queue commandQueue;
	cl_program program;
	cl_context context;
	cl_kernel kernel;
	const char* filename;
	cl_uint retNumPlatforms;
	cl_uint retNumDevices;
	cl_int retVal;
	size_t filesize;

};


#endif