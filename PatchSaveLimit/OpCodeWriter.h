#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdint.h>

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
	STATE_INVALID_HANDLE =2,
	STATE_NULL_PROC = 3
};

class OpCodeWriter
{

public:

	OpCodeWriter(DWORD nprocID, THREADPROC proc);
	OpCodeWriter(DWORD nprocID, HANDLE nstartingAddr, THREADPROC proc);

	virtual ~OpCodeWriter();
	virtual int WriteOpCodeAtAddress(HANDLE address, DWORD length, const uint8_t* opcodes);
	virtual int WriteOpCodeAtNextAddress(DWORD length, const uint8_t* opcode);

	DWORD GetAlignment() const;
	DWORD GetBytesWritten() const;
	DWORD GetBytesWrittenWithoutAlignment() const;
	bool SetAlignment(DWORD nAlign);

	int SetStartingAddr(HANDLE sAddr);
	HANDLE GetCurrentAddr() const;

	virtual int OpenProcessHandle(DWORD memSize);
	virtual int CloseProcessHandle();

	HANDLE GetProcessHandle() const;
	WriterState GetState() const;


private:

	DWORD procID;
	DWORD alignment;
	HANDLE startAddr;
	HANDLE currentAddr;
	DWORD sizeOfBlock;
	DWORD bytesWrittenIncludingPadding;
	DWORD bytesWrittenExludingPadding;

	const THREADPROC procToUse;
	HANDLE procHandle;

	bool isRemoteThreadWritten;

	WriterState state;

};