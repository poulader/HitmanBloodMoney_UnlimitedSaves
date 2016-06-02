#include "OpCodeWriter.h"

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdint.h>



OpCodeWriter::OpCodeWriter(DWORD nprocID, const THREADPROC proc)
	: procID(nprocID), alignment(4), startAddr(INVALID_HANDLE_VALUE), currentAddr(INVALID_HANDLE_VALUE), bytesWrittenIncludingPadding(0), bytesWrittenExludingPadding(0), procHandle(INVALID_HANDLE_VALUE), state(STATE_CLOSED), procToUse(proc), isRemoteThreadWritten(false)
{
	if (procID == NULL || procID == (DWORD)-1)
	{
		state = STATE_INVALID_HANDLE;
	}
	else if (proc == NULL)
	{
		state = STATE_NULL_PROC;
	}

	//call the threadproc once to make sure compiled
	if (state == STATE_CLOSED)
		procToUse(NULL);
}

OpCodeWriter::OpCodeWriter(DWORD nprocID, HANDLE nstartingAddr, const THREADPROC proc)
	: procID(nprocID), alignment(4), startAddr(nstartingAddr), currentAddr(INVALID_HANDLE_VALUE), bytesWrittenIncludingPadding(0), bytesWrittenExludingPadding(0), procHandle(INVALID_HANDLE_VALUE), state(STATE_CLOSED), procToUse(proc), isRemoteThreadWritten(false)
{
	if (startAddr == INVALID_HANDLE_VALUE || startAddr == NULL || procID == NULL || procID == (DWORD)-1)
	{
		state = STATE_INVALID_HANDLE;
	}
	else if (proc == NULL)
	{
		state = STATE_NULL_PROC;
	}

	//call the threadproc once to make sure compiled
	if (state == STATE_CLOSED)
		procToUse(NULL);
}

OpCodeWriter::~OpCodeWriter()
{
	if (procHandle != NULL && procHandle != INVALID_HANDLE_VALUE)
	{
		if (state == STATE_OPEN)
		{
			//clean memory
			VirtualFreeEx(procHandle, startAddr, )
		}

		state = STATE_CLOSED;
	}

}

//returns bytes written including any padding
int OpCodeWriter::WriteOpCodeAtAddress(HANDLE address, DWORD length, const uint8_t* opcodes)
{
	int result = 0;

	if (state != STATE_OPEN)
	{
		return -1;
	}
	else if (address == NULL || address == INVALID_HANDLE_VALUE || ((DWORD)address + length) > 0x7FFFFFFF)
	{
		return -2;
	}
	else if (opcodes == NULL)	
	{ 
		return -3;
	}

	//Copy the opcodes over as arguments, call the remote thread routine

}

int OpCodeWriter::WriteOpCodeAtNextAddress(DWORD length, const uint8_t* opcode)
{

}

DWORD OpCodeWriter::GetAlignment() const
{


}

DWORD OpCodeWriter::GetBytesWritten() const
{


}

DWORD OpCodeWriter::GetBytesWrittenWithoutAlignment() const
{


}

bool OpCodeWriter::SetAlignment(DWORD nAlign)
{


}

int OpCodeWriter::SetStartingAddr(DWORD sAddr)
{


}

DWORD OpCodeWriter::GetCurrentAddr() const
{


}

int OpCodeWriter::OpenProcessHandle(DWORD memSize)
{
	if (state != STATE_CLOSED)
	{
		return -1;
	}
	else if (memSize == 0 || memSize > 0x10000)
	{
		return -2;
	}

	sizeOfBlock = memSize;

}

int OpCodeWriter::CloseProcessHandle()
{


}

HANDLE OpCodeWriter::GetProcessHandle() const
{


}