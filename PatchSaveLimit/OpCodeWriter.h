#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdint.h>

//todo: change constructors with specified addr to store in "preferred addr" field, which can be changed.
//Then have vAllocAddr as the actual result. Same with desired size.

//Thread function pointer typedef
typedef DWORD(WINAPI *THREADPROC)(LPVOID param);

//Export the thread routine without name mangling so we can easily get its address in our process
//to copy later
extern "C"
{
	__declspec(dllexport) DWORD WINAPI ourRemoteThread(LPVOID args);
}

enum WriterState : uint32_t
{
	STATE_CLOSED = 0,
	STATE_OPEN = 1,
	STATE_INVALID_HANDLE = 2,
	STATE_NULL_PROC = 3,
	STATE_PROC_OPEN_FAILED = 4,
};

#pragma pack(push, 4)
typedef struct ORT_ARGS
{
	//Addr
	DWORD addr;
	//Length
	DWORD len;
	//Buffer
	uint8_t buf[1];
} ORT_ARGS, *pORT_ARGS;
#pragma pack(pop,4)

//Size of ourRemoteThread
const DWORD remoteThreadSize = 0x45;

//if client wants to use a different remote thread function, they should subclass and call protected constructor in initialization list.
//They must then override all of the virtual functions.

class OpCodeWriter
{

public:

	//It needs to know the process ID, and by default will use ourRemoteThread
	OpCodeWriter(DWORD nprocID);

	//If you want to try and specify an address to allocate memory at in the remote process, otherwise we choose arbitary
	OpCodeWriter(DWORD nprocID, DWORD allocAddr);

	//If you want to try and specify an address and size to allocate memory at in the remote process, otherwise we choose arbitary
	OpCodeWriter(DWORD nprocID, DWORD allocAddr, DWORD allocSize);

	virtual ~OpCodeWriter();

	//Set the alignment (must be power of 2)
	bool SetAlignment(DWORD nAlign);

	//If you want to write opcodes in a continuous chunk of memory in the remote process, set the address
	//here and use writeopcodeatnextaddress
	int SetStartingOpAddr(HANDLE sAddr);

	//address = address in remote process, length = length of bytecode, opcodes = pointer to buffer containing opcodes
	virtual int WriteOpCodeAtAddress(DWORD address, DWORD length, const uint8_t* opcodes);

	//continues writing at the next alignment boundary, unless told to not use padding
	virtual int WriteOpCodeAtNextAddress(DWORD length, const uint8_t* opcode);

	//must be called before anything can be written
	virtual int OpenProcessHandle();

	//should be called before destructor
	virtual int CloseProcessHandle();

	//Get the function we are using as thread entry point
	const virtual THREADPROC GetRemoteThreadEntryPointFunction() const
	{
		return procToUse;
	};

	//Get alignment (padding between remote thread code and arguments)
	DWORD GetAlignment() const
	{
		return alignment;
	};

	//Get count of opcodes written
	DWORD GetBytesWritten() const
	{
		return bytesOfCodeWritten;
	};


	DWORD GetAllocatedMemorySize() const
	{
		return sizeOfBlock;
	};

	//Get the address that the next byte will be written to
	DWORD GetCurrentAddr() const
	{
		return (DWORD)currentAddr;
	};

	//Get the address of where we allocated memory for our remote thread and arguments
	const HANDLE GetBaseVAllocAddres() const
	{
		return vAllocAddr;
	};

	//Get the address of where we will be writing thread arguments
	const HANDLE GetThreadArgAddress() const
	{
		return vThreadArgAddr;
	};

	//Get process handle after opened
	const HANDLE GetProcessHandle() const
	{
		return procHandle;
	};



	bool GetIsPrivilegeElevated() const
	{
		return isPrivilegeElevated;
	};

	//Get state of writer
	WriterState GetState() const
	{
		return state;
	};

protected:
	//Get as elevated priveleges as possible
	virtual bool ElevatePriveleges();

	//for subclasses which may want to use different threadproc to use
	OpCodeWriter(DWORD nprocID, THREADPROC nProc, DWORD nProcSize);

	//If you want to try and specify an address to allocate memory at in the remote process, otherwise we choose arbitary
	OpCodeWriter(DWORD nprocID, DWORD allocAddr, THREADPROC nProc, DWORD nProcSize);

	//If you want to try and specify an address and size to allocate memory at in the remote process, otherwise we choose arbitary
	OpCodeWriter(DWORD nprocID, DWORD allocAddr, DWORD allocSize, THREADPROC nProc, DWORD nProcSize);


private:

	//process ID
	const DWORD procID;

	//alignment
	DWORD alignment;

	//Where we allocated (or will) memory in remote process
	HANDLE vAllocAddr;

	//Where we will write arguments for thread
	HANDLE vThreadArgAddr;

	//Addr of where the next byte written will go if WriteOpcodeAtNextAddress is called
	HANDLE currentAddr;

	HANDLE remoteThreadEntryPointAddr;

	//address of the start of the last write
	DWORD lastWriteStartAddres;

	//How much memory we will allocate in remote process
	DWORD sizeOfBlock;

	//default size if not specified
	const DWORD defaultBlockSize = 0x1000;

	DWORD threadFunctSize;

	//Total count of opcodes written
	DWORD bytesOfCodeWritten;

	//function used as remote thread entry point
	const THREADPROC procToUse;

	//Handle to process
	HANDLE procHandle;

	//for internal use, make sure we are ready to rock
	bool isRemoteThreadWritten;

	bool isPrivilegeElevated;

	bool isProcessOpen;
	bool isMemoryAllocated;

	DWORD lastRemoteThreadReturnValue;

	//todo
	DWORD actualSize;

	//state
	WriterState state;

	//Taken from https://support.microsoft.com/en-us/kb/131065
	BOOL SetPrivilege(
		HANDLE hToken,  // token handle 
		LPCTSTR Privilege,  // Privilege to enable/disable 
		BOOL bEnablePrivilege  // TRUE to enable. FALSE to disable 
	);

	//todo
	void AddLogLine(const TCHAR* str)
	{
		return;
	}

	void ResetStats();

	void FreeAllocatedMemory(DWORD size);

	bool WriteRemoteThreadArgs(DWORD length, DWORD addr, const uint8_t* opcodes);

	//todo: make block for result an option they can set
	//in that case also include arbitrary sleep time param
	//also include alternate wait time for WaitForsingleObject
	int RunRemoteThread(DWORD& threadReturn, bool blockForResult = true);

};

