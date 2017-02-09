#include "GPU.h"

////////////
/* PUBLIC */
////////////

// constructor
GPU::GPU(const char* _filename) : 
	filename(_filename), 
	platformIds(nullptr), 
	fileBuffer(nullptr), 
	deviceGPUId(NULL), 
	commandQueue(NULL), 
	program(NULL),
	context(NULL),
	kernel(NULL),
	retNumPlatforms(-1),
	retNumDevices(-1),
	retVal(-1),
	filesize(-1)
{
	
	// check if file exists
	if (!fileExists()) {
		printf("Program file does not exist. Exiting now.\n");
		exit(EXIT_FAILURE);
	}


	// set filesize
	filesize = getFilesize();

	// allocate file buffer
	fileBuffer = std::unique_ptr<char[]>(new char[filesize]);

	// read file to buffer
	readFileToBuffer();

}

// destructor
GPU::~GPU(){

	// free
	clReleaseKernel(kernel);
	clReleaseContext(context);
	clReleaseProgram(program);
	clReleaseCommandQueue(commandQueue);

}

// build program from file
void GPU::buildProgram(std::unique_ptr<byte[]>& gpuName) {

	cl_uint platformIndexWithGPU = -1;

	// Get num of platforms and allocate platform space
	retVal = clGetPlatformIDs(0, NULL, &retNumPlatforms);
	platformIds = std::unique_ptr<cl_platform_id[]>(new cl_platform_id[retNumPlatforms]);
	if (retVal != 0)
		throw GPUException("Error: Finding size of platforms in clGetPlatformIDs() failed.\n");

	// Get platforms
	retVal = clGetPlatformIDs(retNumPlatforms, platformIds.get(), NULL);
	if (retVal != 0)
		throw GPUException("Error: Finding platforms in clGetPlatformIDs() failed.\n");

	// Get 1st platform with GPU device and allocate device space
	for (int i = 0; i < retNumPlatforms; i++) { // auto range platforms
		retVal = clGetDeviceIDs(platformIds.get()[i], CL_DEVICE_TYPE_GPU, NULL, NULL, &retNumDevices);
		if (retVal != 0)
			throw GPUException("Error: Finding size of devices in clGetDeviceIDs() failed.\n");

		if (retNumDevices > 0) {
			platformIndexWithGPU = i;
			break;
		}
	}
	if (platformIndexWithGPU == -1)
		throw GPUException("Error: Finding any GPU in any platform in clGetDeviceIDs() failed.\n");

	// Get first detected GPU device
	retVal = clGetDeviceIDs(platformIds.get()[platformIndexWithGPU], CL_DEVICE_TYPE_GPU, GPU_NUM_GPUS, &deviceGPUId, NULL);
	if (retVal != 0)
		throw GPUException("Error: Getting GPU id in clGetPlatformIDs() failed.\n");

	// Set GPU name
	gpuName = std::unique_ptr<byte[]>(new byte[GPU_MAX_NAME_SIZE]);
	CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_NAME, GPU_MAX_NAME_SIZE, gpuName.get(), NULL));

	// Create context
	context = clCreateContext(NULL, GPU_NUM_GPUS, &deviceGPUId, NULL, NULL, &retVal);
	if (retVal != 0)
		throw GPUException("Error: Creating context in clCreateContext() failed.\n");

	// Create command queue
	commandQueue = clCreateCommandQueue(context, deviceGPUId, NULL, &retVal);
	if (retVal != 0)
		throw GPUException("Error: Creating command queue in clCreateCommandQueue() failed.\n");

	// Create program from file
	program = clCreateProgramWithSource(context, 1, (const char**)&fileBuffer, &filesize, &retVal);
	if (retVal != 0)
		throw GPUException("Error: Creating program from source in clCreateProgramWithSource() failed.\n");

	// Build program
	retVal = clBuildProgram(program, 1, &deviceGPUId, NULL, NULL, NULL);
	if (retVal != 0)
		throw GPUException("Error: Creating program in clBuildProgram() failed.\n");

	// debug
	#ifdef _DEBUG

		printf("Found %d platforms.\n", retNumPlatforms);
		printf("=== %d OpenCL platform(s) found: ===\n", retNumPlatforms);
		for (int i = 0; i<retNumPlatforms; i++)
		{
			char buffer[10240];
			printf("  -- %d --\n", i);
			CL_CHECK(clGetPlatformInfo(platformIds.get()[i], CL_PLATFORM_PROFILE, 10240, buffer, NULL));
			printf("  PROFILE = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platformIds.get()[i], CL_PLATFORM_VERSION, 10240, buffer, NULL));
			printf("  VERSION = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platformIds.get()[i], CL_PLATFORM_NAME, 10240, buffer, NULL));
			printf("  NAME = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platformIds.get()[i], CL_PLATFORM_VENDOR, 10240, buffer, NULL));
			printf("  VENDOR = %s\n", buffer);
			CL_CHECK(clGetPlatformInfo(platformIds.get()[i], CL_PLATFORM_EXTENSIONS, 10240, buffer, NULL));
			printf("  EXTENSIONS = %s\n", buffer);
		}

		printf("Found %d devices.\n", retNumDevices);

		printf("=== %d OpenCL device(s) found on platform:\n", retNumDevices);
		for (int i = 0; i<retNumDevices; i++)
		{

			char buffer[10240];
			cl_uint buf_uint[3];
			cl_ulong buf_ulong;
			printf("  -- %d --\n", i);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_NAME, sizeof(buffer), buffer, NULL));
			printf("  DEVICE_NAME = %s\n", buffer);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_VENDOR, sizeof(buffer), buffer, NULL));
			printf("  DEVICE_VENDOR = %s\n", buffer);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_VERSION, sizeof(buffer), buffer, NULL));
			printf("  DEVICE_VERSION = %s\n", buffer);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DRIVER_VERSION, sizeof(buffer), buffer, NULL));
			printf("  DRIVER_VERSION = %s\n", buffer);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &buf_uint[0], NULL));
			printf("  DEVICE_MAX_COMPUTE_UNITS = %u\n", (unsigned int)buf_uint[0]);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(cl_uint), &buf_uint[0], NULL));
			printf("  DEVICE_MAX_CLOCK_FREQUENCY = %u\n", (unsigned int)buf_uint[0]);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_LOCAL_MEM_SIZE, sizeof(buf_ulong), &buf_ulong, NULL));
			printf("  CL_DEVICE_LOCAL_MEM_SIZE = %llu\n", (unsigned long long)buf_ulong);
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(cl_uint), &buf_uint[0], NULL));
			printf("  CL_DEVICE_MAX_WORK_GROUP_SIZE = %llu\n", (unsigned long long)buf_uint[0]);
			//CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_MAX_WORK_ITEM_SIZES, sizeof(buf_uint), &buf_uint, NULL));
			//std::cout << "  CL_DEVICE_MAX_WORK_ITEM_SIZES = (" << (unsigned long long)buf_uint[0] << ", " << (unsigned long long)buf_uint[1] << ", " << (unsigned long long)buf_uint[2] << ")\n";
			CL_CHECK(clGetDeviceInfo(deviceGPUId, CL_DEVICE_MAX_PARAMETER_SIZE, sizeof(size_t), &buf_uint[0], NULL));
			printf("  CL_DEVICE_MAX_PARAMETER_SIZE = %llu\n", (unsigned long long)buf_uint[0]);
		}

	#endif

}

// create kernel from program
void GPU::createKernelFromProgram(const char* kernelFunc) {

	// Create kernel
	kernel = clCreateKernel(program, kernelFunc, &retVal);
	if (retVal != 0)
		throw GPUException("Error: Creating kernel from function in clCreateKernel() failed.\n");

}

// write data to mem buffer
void GPU::writeMemBuffer(cl_mem& memBuffer, const void* data, size_t bytesToAllocate, int flags) {

	// Create memory buffer
	memBuffer = clCreateBuffer(context, flags, bytesToAllocate, NULL, &retVal);
	if (retVal != 0)
		throw GPUException("Error: Creating memory buffer in clCreateBuffer() failed.\n");

	// if NULL, skip write to buffer
	if (!data)
		return;

	// Set memory buffer
	retVal = clEnqueueWriteBuffer(commandQueue, memBuffer, CL_TRUE, 0, bytesToAllocate, data, 0, NULL, NULL);
	if (retVal != 0)
		throw GPUException("Error: Queueing write to buffer in clEnqueueWriteBuffer() failed.\n");

}

// read mem buffer data to buffer
void GPU::readMemBuffer(cl_mem& memBuffer, void* data, size_t bytesToAllocate) {

	// Copy result from memory buffer
	retVal = clEnqueueReadBuffer(commandQueue, memBuffer, CL_TRUE, 0, bytesToAllocate, data, 0, NULL, NULL);
	if (retVal != 0)
		throw GPUException("Error: Queueing read of buffer in clEnqueueReadBuffer() failed.\n");

}

// add kernel parameter
void GPU::addKernelParam(const int argNum, const cl_mem& memBuffer) {

	// Set kernel params
	retVal = clSetKernelArg(kernel, argNum, sizeof(cl_mem), (void *)&memBuffer);
	if (retVal != 0)
		throw GPUException("Error: Setting of argument to kernel in clSetKernelArg() failed.\n");

}

// execute 1d kernel
void GPU::execute1DKernel(const int outputFilesize) {

	size_t* localWorkSize = new size_t[GPU_ONE_DIMENSION];
	size_t* globalWorkSize = new size_t[GPU_ONE_DIMENSION];

	localWorkSize[0] = 1;
	globalWorkSize[0] = outputFilesize;

	retVal = clEnqueueNDRangeKernel(commandQueue, kernel, GPU_ONE_DIMENSION, NULL, globalWorkSize, localWorkSize, 0, NULL, NULL);
	if (retVal != 0)
		throw GPUException("Error: Execution of 1-dim kernel in clEnqueueNDRangeKernel() failed.\n");

}

// execute 2d kernel
void GPU::execute2DKernel(const int* globalWorkSize, const int* localWorkSize) {

	retVal = clEnqueueNDRangeKernel(commandQueue, kernel, GPU_TWO_DIMENSION, NULL, (const size_t*)globalWorkSize, (const size_t*)localWorkSize, 0, NULL, NULL);
	if (retVal != 0)
		throw GPUException("Error: Execution of 2-dim kernel in clEnqueueNDRangeKernel() failed.\n");

}

// free mem object
void GPU::freeMemObject(cl_mem& memObject) {

	retVal = clReleaseMemObject(memObject);
	if (retVal != 0)
		throw GPUException("Error: Freeing of memory object in clReleaseMemObject() failed.\n");

}

/////////////
/* PRIVATE */
/////////////

// check if file exists
bool GPU::fileExists() {
	struct stat buffer;
	return (stat(filename, &buffer) == 0);
}

// get file size
size_t GPU::getFilesize() {

	size_t size;
	std::fstream fileStream;

	// open file
	fileStream.open(filename, std::fstream::in | std::fstream::binary);

	// get length of file
	fileStream.seekg(0, fileStream.end);
	size = fileStream.tellg();
	fileStream.seekg(0, fileStream.beg);

	// close file
	fileStream.close();

	// return
	return size;
}

// read file data to buffer
void GPU::readFileToBuffer() {

	std::fstream fileStream = {};

	// open file
	fileStream.open(filename, std::fstream::in | std::fstream::binary);
	fileStream.seekg(0, fileStream.beg);

	// read
	fileStream.read(fileBuffer.get(), filesize);

	// close file
	fileStream.close();
}