#include "OpCodeWriter.h"

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdint.h>


//Instead of doing validation in the constructor, validate args once OpenProcess is called


//It needs to know the process ID, and by default will use ourRemoteThread
OpCodeWriter::OpCodeWriter(DWORD nprocID)
	: procID(nprocID), procToUse(&ourRemoteThread), threadFunctSize(remoteThreadSize), procHandle(INVALID_HANDLE_VALUE), isRemoteThreadWritten(false), state(STATE_CLOSED), bytesOfCodeWritten(0), sizeOfBlock(0), lastWriteStartAddres((DWORD)-1), currentAddr(INVALID_HANDLE_VALUE),
	vAllocAddr(NULL), alignment(4), isPrivilegeElevated(false), remoteThreadEntryPointAddr(INVALID_HANDLE_VALUE), vThreadArgAddr(NULL), isProcessOpen(false), isMemoryAllocated(false), lastRemoteThreadReturnValue(0)
{


};

//If you want to try and specify an address to allocate memory at in the remote process, otherwise we choose arbitary
OpCodeWriter::OpCodeWriter(DWORD nprocID, DWORD allocAddr)
	: procID(nprocID), procToUse(&ourRemoteThread), threadFunctSize(remoteThreadSize), procHandle(INVALID_HANDLE_VALUE), isRemoteThreadWritten(false), state(STATE_CLOSED), bytesOfCodeWritten(0), sizeOfBlock(0), lastWriteStartAddres((DWORD)-1), currentAddr(INVALID_HANDLE_VALUE),
	vAllocAddr((HANDLE)allocAddr), alignment(4), isPrivilegeElevated(false), remoteThreadEntryPointAddr(INVALID_HANDLE_VALUE), vThreadArgAddr(NULL), isProcessOpen(false), isMemoryAllocated(false), lastRemoteThreadReturnValue(0)
{



};

//If you want to try and specify an address and size to allocate memory at in the remote process, otherwise we choose arbitary
OpCodeWriter::OpCodeWriter(DWORD nprocID, DWORD allocAddr, DWORD allocSize)
	: procID(nprocID), procToUse(&ourRemoteThread), threadFunctSize(remoteThreadSize), procHandle(INVALID_HANDLE_VALUE), isRemoteThreadWritten(false), state(STATE_CLOSED), bytesOfCodeWritten(0), sizeOfBlock(allocSize), lastWriteStartAddres((DWORD)-1), currentAddr(INVALID_HANDLE_VALUE),
	vAllocAddr((HANDLE)allocAddr), alignment(4), isPrivilegeElevated(false), remoteThreadEntryPointAddr(INVALID_HANDLE_VALUE), vThreadArgAddr(NULL), isProcessOpen(false), isMemoryAllocated(false), lastRemoteThreadReturnValue(0)
{


};


//protected constructors for subclasses which use a different threadproc

//for subclasses which may want to use different threadproc to use
//PROTECTED
OpCodeWriter::OpCodeWriter(DWORD nprocID, THREADPROC nProc, DWORD nProcSize)
	: procID(nprocID), procToUse(nProc), threadFunctSize(nProcSize), procHandle(INVALID_HANDLE_VALUE), isRemoteThreadWritten(false), state(STATE_CLOSED), bytesOfCodeWritten(0), sizeOfBlock(0), lastWriteStartAddres((DWORD)-1), currentAddr(INVALID_HANDLE_VALUE),
	vAllocAddr(NULL), alignment(4), isPrivilegeElevated(false), remoteThreadEntryPointAddr(INVALID_HANDLE_VALUE), vThreadArgAddr(NULL), isProcessOpen(false), isMemoryAllocated(false), lastRemoteThreadReturnValue(0)
{

};

//for subclasses which may want to use different threadproc to use
//PROTECTED
//If you want to try and specify an address to allocate memory at in the remote process, otherwise we choose arbitary
OpCodeWriter::OpCodeWriter(DWORD nprocID, DWORD allocAddr, THREADPROC nProc, DWORD nProcSize)
	: procID(nprocID), procToUse(nProc), threadFunctSize(nProcSize), procHandle(INVALID_HANDLE_VALUE), isRemoteThreadWritten(false), state(STATE_CLOSED), bytesOfCodeWritten(0), sizeOfBlock(0), lastWriteStartAddres((DWORD)-1), currentAddr(INVALID_HANDLE_VALUE),
	vAllocAddr((HANDLE)allocAddr), alignment(4), isPrivilegeElevated(false), remoteThreadEntryPointAddr(INVALID_HANDLE_VALUE), vThreadArgAddr(NULL), isProcessOpen(false), isMemoryAllocated(false), lastRemoteThreadReturnValue(0)
{

};

//for subclasses which may want to use different threadproc to use
//PROTECTED
//If you want to try and specify an address and size to allocate memory at in the remote process, otherwise we choose arbitary
OpCodeWriter::OpCodeWriter(DWORD nprocID, DWORD allocAddr, DWORD allocSize, THREADPROC nProc, DWORD nProcSize)
	: procID(nprocID), procToUse(nProc), threadFunctSize(nProcSize), procHandle(INVALID_HANDLE_VALUE), isRemoteThreadWritten(false), state(STATE_CLOSED), bytesOfCodeWritten(0), sizeOfBlock(allocSize), lastWriteStartAddres((DWORD)-1), currentAddr(INVALID_HANDLE_VALUE),
	vAllocAddr((HANDLE)allocAddr), alignment(4), isPrivilegeElevated(false), remoteThreadEntryPointAddr(INVALID_HANDLE_VALUE), vThreadArgAddr(NULL), isProcessOpen(false), isMemoryAllocated(false), lastRemoteThreadReturnValue(0)
{

};


OpCodeWriter::~OpCodeWriter()
{
	//These functions check if they need to do anything
	FreeAllocatedMemory(actualSize);
	CloseProcessHandle();
	ResetStats();
	state = STATE_CLOSED;
};

//address = address in remote process, length = length of bytecode, opcodes = pointer to buffer containing opcodes
int OpCodeWriter::WriteOpCodeAtAddress(DWORD address, DWORD length, const uint8_t* opcodes)
{
	//meh lazy right now
	HANDLE oldCurrentAddr = currentAddr;
	currentAddr = (HANDLE)address;
	int returnCode = WriteOpCodeAtNextAddress(length, opcodes);
	currentAddr = oldCurrentAddr;
	return returnCode;
};

//continues writing at the next alignment boundary, unless told to not use padding
int OpCodeWriter::WriteOpCodeAtNextAddress(DWORD length, const uint8_t* opcode)
{
	if (GetState() != STATE_OPEN)
	{
		return -1;
	}
	else if (opcode == NULL || (DWORD)opcode > 0x7FFFFFFF)
	{
		return -2;
	}

	//We can't really validate length, as we don't know where in the remote process they are going to write
	//but we can make sure its not 0 or some huge size
	if (length == 0 || length > 0x80000)
	{
		return -3;
	}

	//Make sure we have an address to write to
	if (currentAddr == INVALID_HANDLE_VALUE || (DWORD)currentAddr > 0x7FFFFFFF)
	{
		return -4;
	}


	//ok, try to write args to remote thread (currentAddr = address in process space we want remote thread to modify)
	if (!WriteRemoteThreadArgs(length, (DWORD)currentAddr, opcode))
	{
		//We need to make errors at this point more granular, check getlasterror, return errors which would mean we need to clean up (proc dead, etc)
		//For now, assume proc is dead
		FreeAllocatedMemory(actualSize);
		CloseProcessHandle();
		ResetStats();
		state = STATE_CLOSED;
		return -5;
	}

	//Try to run remote thread and check return value

	DWORD threadReturnValue = 0;

	if (RunRemoteThread(threadReturnValue))
	{
		//We need to make errors at this point more granular, check getlasterror, return errors which would mean we need to clean up (proc dead, etc)
		//For now, assume proc is dead
		FreeAllocatedMemory(actualSize);
		CloseProcessHandle();
		ResetStats();
		state = STATE_CLOSED;
		return -6;
	}
	else
	{

		//Check thread return code
		bytesOfCodeWritten += threadReturnValue;
		currentAddr = (HANDLE)((DWORD)currentAddr + bytesOfCodeWritten);
		return 0;
	}

};

//This is a private function performing an implementation task, we will have already validated that we can be called
bool OpCodeWriter::WriteRemoteThreadArgs(DWORD length, DWORD addr, const uint8_t* opcodes)
{
	HANDLE targetAddr = vThreadArgAddr;
	DWORD bytesWritten = 0;

	//We are going to write an ORT_ARGS struct to remote process memory, piecewise so I don't have to copy opcodes to a struct and then copy again.
	//The thread routine will interpret it correctly.

	if (!WriteProcessMemory(procHandle, targetAddr, &addr, sizeof(DWORD), &bytesWritten))
	{
		AddLogLine(_T("Failed to write addr to remote args address"));
		return false;
	}

	targetAddr = (HANDLE)((DWORD)vThreadArgAddr + sizeof(DWORD));

	if (!WriteProcessMemory(procHandle, targetAddr, &length, sizeof(DWORD), &bytesWritten))
	{
		AddLogLine(_T("Failed to write length to remote args address"));
		return false;
	}

	targetAddr = (HANDLE)((DWORD)vThreadArgAddr + sizeof(DWORD));

	//Write opcode argument to thread args
	if (!WriteProcessMemory(procHandle, targetAddr, opcodes, length, &bytesWritten))
	{
		AddLogLine(_T("Failed to write opcodes to remote args address"));
		return false;
	}
};

//todo: make block for result an option they can set
//in that case also include arbitrary sleep time
//also include alternate wait time for WaitForsingleObject
//private implementation routine, 
int OpCodeWriter::RunRemoteThread(DWORD& threadReturn, bool blockForResult = true)
{

	//run remote thread, and then zero the arguments area in remote proc

	HANDLE threadHandle = NULL;
	DWORD threadId = 0;

	threadHandle = CreateRemoteThreadEx(procHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)remoteThreadEntryPointAddr, (ORT_ARGS*)vThreadArgAddr, NULL, NULL, &threadId);
	if (threadHandle == INVALID_HANDLE_VALUE || threadHandle == NULL)
	{
		//really need to log GetLastError here
		AddLogLine(_T("CreateRemoteThreadEx failed."));
		return -1;
	}

	if (blockForResult)
	{
		if (!WaitForSingleObject((HANDLE)threadId, INFINITE))
		{
			//really need to log GetLastError here
			AddLogLine(_T("WaitForSingleObject failed"));
			CloseHandle(threadHandle);
			return -2;
		}

		if (!GetExitCodeThread(threadHandle, &threadReturn))
		{
			//really need to log GetLastError here
			AddLogLine(_T("GetExitCodeThread failed"));
			CloseHandle(threadHandle);
			return -3;
		}

	}

	CloseHandle(threadHandle);
	return 0;
};

//must be called before anything can be written
int OpCodeWriter::OpenProcessHandle()
{
	if (GetState() == STATE_OPEN)
	{
		return 1;
	}
	else if (GetState() != STATE_CLOSED)
	{
		return -1;
	}

	//only change state if its something they cannot fix in the current instance

	//Validate all args from constructor
	if (procID == (DWORD)INVALID_HANDLE_VALUE || procID == NULL)
	{
		state = STATE_INVALID_HANDLE;
		return -3;
	}
	else if (alignment % 2 != 0)
	{
		return -4;
	}
	else if (vAllocAddr == INVALID_HANDLE_VALUE ||  (DWORD)vAllocAddr + sizeOfBlock > 0 ? sizeOfBlock : defaultBlockSize > 0x7FFFFFFF) /* if they specified a specified addr at which to allocate memory, check it*/
	{
		return -5;
	}
	else if (GetRemoteThreadEntryPointFunction() == NULL || GetRemoteThreadEntryPointFunction() != &ourRemoteThread) /* make sure a subclass which specified a different threadproc isnt calling this, they need to override*/
	{
		state = STATE_NULL_PROC;
		return -6;
	}

	//That's everything I think

	//Try to elevate privilege, mark the result as we may be able to proceed anyways.
	//If we fail later, it can help the client diagnose.
	if (!isPrivilegeElevated)
		isPrivilegeElevated = ElevatePriveleges();

	//Try to open a handle to the process
	procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

	if (procHandle == INVALID_HANDLE_VALUE || procHandle == NULL)
	{
		state = STATE_PROC_OPEN_FAILED;
		return -7;
	}
	else
	{
		isProcessOpen = true;
	}

	DWORD targetSize = sizeOfBlock > 0 ? sizeOfBlock : defaultBlockSize;

	//todo, replace targetsize with actualsize, see notes in OpCodeWriter.h
	actualSize = targetSize;

	//Try to allocate some memory in the remote process
	HANDLE tempAllocAddr = VirtualAllocEx(procHandle, &vAllocAddr, targetSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//we wont mark state as unrecoverable in this instance, just report that allocation failed.
	//If they want, they can try changing address and size and trying again.
	if (tempAllocAddr == INVALID_HANDLE_VALUE || tempAllocAddr == NULL)
	{
		CloseProcessHandle();
		ResetStats();
		state = STATE_CLOSED;
		return -8;
	}
	else
	{
		vAllocAddr = tempAllocAddr;
		isMemoryAllocated = true;
	}

	//Set argument address
	DWORD functAllocEnd = (DWORD)vAllocAddr + threadFunctSize;
	DWORD toPad = functAllocEnd % alignment;

	DWORD bytesWritten = 0;

	vThreadArgAddr = (HANDLE)(functAllocEnd + (alignment - toPad));

	//Try to zero out the allocated region
	uint8_t *zeroBuf = new uint8_t[targetSize];

	if (!WriteProcessMemory(procHandle, vAllocAddr, zeroBuf, targetSize, &bytesWritten))
	{
		AddLogLine(_T("Failed to write zeroing array"));
		delete[] zeroBuf;
		FreeAllocatedMemory(targetSize);
		CloseProcessHandle();
		ResetStats();
		state = STATE_CLOSED;
		return -9;
	}

	delete[] zeroBuf;

	//Ok, we allocated memory and zeroed it, try to copy over remote thread entry point
	if (!WriteProcessMemory(procHandle, vAllocAddr, procToUse, threadFunctSize, &bytesWritten))
	{

		//We failed to copy over thread routine... we have to clean up and bail
		AddLogLine(_T("WPM of remote thread funct failed"));
		FreeAllocatedMemory(targetSize);
		CloseProcessHandle();
		ResetStats();
		state = STATE_CLOSED;
		return -10;
	}
	else
	{
		remoteThreadEntryPointAddr = vAllocAddr;
	}

	//We can consider ourselves "open" at this point.
	state = STATE_OPEN;
	return 0;
};

void OpCodeWriter::ResetStats()
{
	bytesOfCodeWritten = 0;
	lastWriteStartAddres = (DWORD)-1;
	remoteThreadEntryPointAddr = INVALID_HANDLE_VALUE;
	currentAddr = INVALID_HANDLE_VALUE;
	vThreadArgAddr = INVALID_HANDLE_VALUE;
	procHandle = INVALID_HANDLE_VALUE;
	isPrivilegeElevated = false;
};


int OpCodeWriter::CloseProcessHandle()
{
	if (isProcessOpen)
	{
		if (!CloseHandle(procHandle))
		{
			AddLogLine(_T("CloseHandle returned false"));
		}

		procHandle = INVALID_HANDLE_VALUE;
		isProcessOpen = false;
		return 0;
	}
	else
	{
		procHandle = INVALID_HANDLE_VALUE;
		return 0;
	}
};


void OpCodeWriter::FreeAllocatedMemory(DWORD size)
{
	if (isMemoryAllocated)
	{
		if (!VirtualFreeEx(procHandle, vAllocAddr, size, MEM_DECOMMIT))
		{
			AddLogLine(_T("VirtualFreeEx returned false"));
		}
		isMemoryAllocated = false;
	}
}

//Set the alignment (must be power of 2), will only take affect on next write
bool OpCodeWriter::SetAlignment(DWORD nAlign)
{
	if (nAlign % 2 != 0)
		return false;
	else
		alignment = nAlign;
	return true;
};

//If you want to write opcodes in a continuous chunk of memory in the remote process, set the address
//here and use writeopcodeatnextaddress
int OpCodeWriter::SetStartingOpAddr(HANDLE sAddr)
{

};

//Get as elevated priveleges as possible
//caged from msdn
bool OpCodeWriter::ElevatePriveleges()
{
	HANDLE hToken;

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
				return false;

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				return false;
			}
		}
		else
			return false;
	}


	// enable SeDebugPrivilege
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{

		// close token handle
		CloseHandle(hToken);

		// indicate failure
		return false;
	}

	return true;
};

//caged from MSDN
BOOL OpCodeWriter::SetPrivilege(
	HANDLE hToken,  // token handle 
	LPCTSTR Privilege,  // Privilege to enable/disable 
	BOOL bEnablePrivilege  // TRUE to enable. FALSE to disable 
)
{
		TOKEN_PRIVILEGES tp = { 0 };
		// Initialize everything to zero 
		LUID luid;
		DWORD cb = sizeof(TOKEN_PRIVILEGES);
		if (!LookupPrivilegeValue(NULL, Privilege, &luid))
			return FALSE;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (bEnablePrivilege) {
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		}
		else {
			tp.Privileges[0].Attributes = 0;
		}
		AdjustTokenPrivileges(hToken, FALSE, &tp, cb, NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS)
			return FALSE;

		return TRUE;
};


//This is the function which we copy the opcodes over to the hitman proc and start a thread pointing to it.
//It does not have any operations which depend on addresses which won't exist in another process. The args are copied over as well.
DWORD WINAPI ourRemoteThread(LPVOID args)
{
	if (args == NULL || args == INVALID_HANDLE_VALUE)
		return 1;
	else
	{

	}
}