#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdint.h>

using namespace std;


/*

I wrote this because I want to play harder difficulty in hitman blood money without being limited by saves.
I do not patch the hitman image on disk because they are using a packer which I'm working on atm; although they do not appear
to have any checksum checking for the part this modifies in the running process, there may be an initial checksum check before or while
unpacking as well. So this modifies an opcode in the hitman process in memory to always jmp to the "ok do a save" condition, instead of
a conditional jl based on number of saves so far.

This has been tested on the steam version, 1.2. It might not work on a non-steam version, as the offset from module base to opcode we want may 
be different. RPM does not appear to work on the steam 1.2 version, so as of right now I cannot dynamically find the instruction. I will
keep tinkering and see what is what for a future version.

You must use the compiler and linker settings included in the project file, "Minimal x86". If you do not, the size of the exported thread routine
may change, you will need to check disassembly and change the WPM size. Also, an earlier version had the exported function pointing to an entry in a jmp
table, so if you change compile/link options, watch out for that as well. I had to parse the instructions at the exported function address to get the
actual offset to the exported function, which is a pain. So change options at your own risk!

I am not responsible for the effectiveness, safety, or anything else of this software, blah blah blah, use at your own risk.

This does not modify any copyrighted files, it makes a change in your PCs memory, and this is for educational and research purposes.

Also I wrote this late at night so the code is sloppy, so sue me. I'll refactor later.

INstructions: Start hitman blood money 1.2 steam version, wait for it to reach main menu ("profile manager") or later. Run the program. It will tell you if it fails
or succeeds.

*/

//Give ourselves debug privileges, was written earlier when trying to use ReadProcessMemory, which was not returning expected values
//even though addresses were correct. There is a goofy packer which I'm poking at right now, may have some answers.
bool SetDebug();

//Taken from https://support.microsoft.com/en-us/kb/131065
BOOL SetPrivilege(
	HANDLE hToken,  // token handle 
	LPCTSTR Privilege,  // Privilege to enable/disable 
	BOOL bEnablePrivilege  // TRUE to enable. FALSE to disable 
);

//Thread function pointer typedef
typedef DWORD (WINAPI *THREADPROC)(LPVOID param);

//Function was written with a global bool to try this method instead, hence the name
DWORD doRemoteThreadInstead(DWORD processID, DWORD base, DWORD offset);

//Export the thread routine without name mangling so we can easily get its address in our process
//to copy later
extern "C"
{
	__declspec(dllexport) DWORD WINAPI ourRemoteThread(LPVOID args);
}

int main()
{

	//Make sure the remote thread function is compiled, I have all optimizations disabled but just make sure
	DWORD result = ourRemoteThread((LPVOID)NULL);
	
	//Handles for process + snapshot enumerating
	HANDLE hProcessSnap;
	HANDLE hProcess;

	//Some info about the process, image name and ID are what we want
	PROCESSENTRY32 pe32;

	//The opcode we will write (unconditional short jmp)
	const uint8_t bytesToWrite[]{ 0xEB };

	//The opcodes we want to find (not using this, left over from RPM attempt, jl and last byte in little endian of offset)
	const uint8_t bytesToRead[]{ 0x7C, 0x18 };

	//Ze process name
	const CHAR processName[] = { "HitmanBloodMoney.exe" };

	//Once everything has been unpacked, this is the offset from the module base to the jl we want to make jmp
	const DWORD opcodeOffset = 0x2776CD;

	SIZE_T nBytesWritten = 0;

	if (!SetDebug())
	{
		printf("\nCould not obtain debug privilege.\n");
		Sleep(2000);
		return -1;
	}

	while (1)
	{
		//Caged from an MSDN example to enumerate processes
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			printf("\nUnable to get process snapshot handle.\n");
			Sleep(2000);
			return -1;
		}

		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hProcessSnap, &pe32))
		{
			printf("\nProcess32first returned an error.\n");
			CloseHandle(hProcessSnap);
			Sleep(2000);
			return -1;
		}

		bool foundit = false;

		while (!foundit)
		{

			if (memcmp(pe32.szExeFile, processName, sizeof(processName)) == 0)
			{
				foundit = true;
				break;
			}
			else
			{
				if (!Process32Next(hProcessSnap, &pe32))
				{
					break;
				}
			}

		}

		//If we didn't find it, lets loop and look again
		if (!foundit)
		{
			CloseHandle(hProcessSnap);
			ZeroMemory(&pe32, pe32.dwSize);
			printf("\nDidn't find it, launch game and make sure it makes it to the main menu (profile manager or later) before running.\n");
			Sleep(10000);
			continue;
		}
		else
		{

			//Try to get the base address
			MODULEENTRY32 moduleEntry = { 0 };
			moduleEntry.dwSize = sizeof(MODULEENTRY32);
			bool foundModule = false;

			hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);

			if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE)
			{
				CloseHandle(hProcessSnap);
				printf("\nError getting process snapshot.\n");
				Sleep(2000);
				break;
			}

			if (!Module32First(hProcess, &moduleEntry))
			{
				CloseHandle(hProcessSnap);
				CloseHandle(hProcess);
				printf("\nError getting first module handle.\n");
				Sleep(2000);
				break;
			}

			while (!foundModule)
			{
				if (_tcscmp(moduleEntry.szModule, _T("HitmanBloodMoney.exe")) == 0)
				{
					foundModule = true;
					break;
				}
				else
				{
					if (!Module32Next(hProcess, &moduleEntry))
					{
						break;
					}
				}
			}

			//Close handle anyways
			CloseHandle(hProcess);

			//Well we found the process but the main module is not present according to the snapshot...
			if (!foundModule)
			{
				CloseHandle(hProcessSnap);
				printf("\nCould not find hitman module.\n");
				Sleep(2000);
				break;
			}

			//Ok we found it, send procID, base address, opcode offset. Leaving them as separate params
			//in case I get RPM working and can look for the opcodes I want instead of depending on fixed offset
			DWORD retcode = 0;
			if ( (retcode =doRemoteThreadInstead(pe32.th32ProcessID, (DWORD)moduleEntry.modBaseAddr, opcodeOffset)))
			{
				if (retcode != 2)
					printf("\nRemote thread method failed...\n");
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}
			else
			{
				printf("\ndoremotethread ok.\n");
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

		}

	}



};

//caged from msdn
bool SetDebug()
{
	HANDLE hToken;

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
				return false;

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				printf("\nOpenThreadToken failed.\n");
				return false;
			}
		}
		else
			return false;
	}


	// enable SeDebugPrivilege
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		printf("\nSetPrivilege failed.\n");

		// close token handle
		CloseHandle(hToken);

		// indicate failure
		return false;
	}

	return true;

}

//Earlier I was passing in the address as the thread arg, but I will break them up in case things change
#pragma pack(push, 4)
typedef struct threadArgs
{
	DWORD base;
	DWORD offset;
} threadArgs, *pthreadArgs;
#pragma pack(pop, 4)

//caged from msdn
BOOL SetPrivilege(
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
}


DWORD doRemoteThreadInstead(DWORD processID, DWORD base, DWORD offset)
{

	HANDLE hitmanProc = NULL;

	//make sure args are ok
	if (processID == 0 || processID == (DWORD)INVALID_HANDLE_VALUE)
		return 1;
	else if (base == NULL || offset == NULL || (int)base == -1 || (base + offset) > (DWORD)0x7FFFFFFF)
	{
		printf("\nInvalid args.\n");
		return 1;
	}

	hitmanProc = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

	if (hitmanProc == NULL || hitmanProc == INVALID_HANDLE_VALUE)
	{
		printf("\nCouldn't get handle to process.\n");
		return 1;
	}

	HANDLE remoteAddr = 0;

	//function we need to run is 0x45 bytes WITH THE CURRENT COMPILER AND LINKER SETTINGS! If they are changed, the size will change.
	//Also some optimization earlier was making the exported function address point to an entry in a jmp table, so I had to originally
	//grab offset from jmp and add it to exported function address + 5 bytes.
	//The exported function now directly points to the function, so we can use the address directly.

	//Allocate some memory in the hitman process
	remoteAddr = (HANDLE)VirtualAllocEx(hitmanProc, NULL, 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (remoteAddr == NULL || remoteAddr == INVALID_HANDLE_VALUE)
	{
		printf("\nError allocating memory in hitman proccess.\n");
		CloseHandle(hitmanProc);
		return 1;
	}

	//Get the address of the thread routine we want to run, we are exporting it
	HMODULE currentModule = GetModuleHandle(NULL);

	if (currentModule == NULL || currentModule == INVALID_HANDLE_VALUE)
	{
		printf("\nCould not get handle to self.\n");
		CloseHandle(hitmanProc);
		return 1;
	}

	//Addr of function
	HANDLE ptrToFunct = GetProcAddress(currentModule, "_ourRemoteThread@4");

	if (ptrToFunct == NULL || ptrToFunct == INVALID_HANDLE_VALUE)
	{
		printf("\nError getting function pointer...\n");
		CloseHandle(hitmanProc);
		return 1;
	}

	DWORD nBytesWritten = 0;

	uint8_t nullarray[0x100];
	ZeroMemory(nullarray, sizeof(nullarray));

	//zero the memory first, if the write fails at this point, I'm not going to try and free it, who cares
	if (!WriteProcessMemory(hitmanProc, remoteAddr, nullarray, (SIZE_T)sizeof(nullarray), &nBytesWritten))
	{
		printf("\nError writing to memory we allocated in hitman process.\n");
		CloseHandle(hitmanProc);
		return 1;
	}

	nBytesWritten = 0;

	//Due to compiler options being changed, we no longer have a jmp redirect to the function. We can directly
	//use the address from getprocaddress

	//Copy the function bytecode over. The function does not call anything so we don't have to worry about
	//fixing up any import addresses.

	//Also all automatically generated security things should be disabled or it will try to jmp
	//to an address that is incorrect in the remote process.
	if (!WriteProcessMemory(hitmanProc, remoteAddr, (uint8_t*)ptrToFunct, 0x45, &nBytesWritten))
	{
		if (nBytesWritten < 0x45)
		{
			printf("\nError copying function to hitman proc.\n");
			CloseHandle(hitmanProc);
			return 1;
		}
	}

	DWORD remoteThreadID = 0;

	//Copy over the arguments as well. Originally this was not needed as I passed in the address
	//as the thread argument directly, but this is more flexible.
	threadArgs args = { 0 };
	args.base = base;
	args.offset = offset;

	//write args to hitman process memory as well
	HANDLE remoteArgsAddr = (HANDLE)((DWORD)remoteAddr + 0x50);

	nBytesWritten = 0;

	//Again if we fail to write to memory we allocated, I'm not going to try and free it.

	if (!WriteProcessMemory(hitmanProc, remoteArgsAddr, (threadArgs*)&args, sizeof(args), &nBytesWritten))
	{
		printf("\nError writing args.\n");
		CloseHandle(hitmanProc);
		return 1;
	}

	//The free/closehandles is repeated a lot, it was in one place originally and I'm too lazy atm to refactor

	HANDLE remoteThreadHandle = NULL;
	DWORD threadExitCode = 0;

	//Try to start a thread with the entry point being the function we copied over, and the args opinting to the args we copied over
	if (!(remoteThreadHandle = CreateRemoteThread(hitmanProc, NULL, 0, (THREADPROC)remoteAddr, (LPVOID)remoteArgsAddr, 0, &remoteThreadID)) || remoteThreadHandle == INVALID_HANDLE_VALUE)
	{
		printf("\nError starting remote thread.\n");
		VirtualFreeEx(hitmanProc, remoteAddr, 0x100, MEM_DECOMMIT);
		CloseHandle(hitmanProc);
		return 1;
	}

	Sleep(250);

	//Wait for thread to finish
	if (!WaitForSingleObject((HANDLE)remoteThreadID, INFINITE))
	{
		printf("\nWe were not signalled that remote thread terminated... however the patch might have worked.\n");
		VirtualFreeEx(hitmanProc, remoteAddr, 0x100, MEM_DECOMMIT);
		CloseHandle(remoteThreadHandle);
		CloseHandle(hitmanProc);
		return 2;

	}

	//See if we succeeded or not. I will change thread routine to return another value if it is already patched,
	//its too late tonight to re-measure function length.
	if (!GetExitCodeThread(remoteThreadHandle, (DWORD*)&threadExitCode))
	{
		printf("\nWe were unable to retreieve thread return value, game may be paused or minimized. Give it a shot.\n");
		VirtualFreeEx(hitmanProc, remoteAddr, 0x100, MEM_DECOMMIT);
		CloseHandle(remoteThreadHandle);
		CloseHandle(hitmanProc);
		return 2;
	}
	else if (threadExitCode == 0)
	{
		printf("\nSuccesfully patched code in memory, infinite saves activated.");
	}
	else
	{
		printf("\nAlready patched (OK) or opcode not found (BAD). Running steam 1.2 version?\n");

	}

	//Free the memory we allocated earlier
	if (!VirtualFreeEx(hitmanProc, remoteAddr, 0x100, MEM_DECOMMIT))
	{
		printf("\nUnable to free the memory we allocated earlier in hitman process, oh well..");
	}
	else
	{
		printf("\nFreed memory we allocated earlier.");
	}

	CloseHandle(remoteThreadHandle);
	CloseHandle(hitmanProc);

	if (threadExitCode == 0)
		return 0;
	else
		return 2;
}

//This is the function which we copy the opcodes over to the hitman proc and start a thread pointing to it.
//It does not have any operations which depend on addresses which won't exist in another process. The args are copied over as well.
DWORD WINAPI ourRemoteThread(LPVOID args)
{
	if (args == NULL || args == INVALID_HANDLE_VALUE)
		return 1;
	else
	{
		//Ok... we are in the address space of the process... verify we are patching the right place
		DWORD targetAddress = ((threadArgs*)args)->base + ((threadArgs*)args)->offset;

		//Change jl to a short jmp
		if (*(uint8_t*)targetAddress == 0x7C)
		{
			*(uint8_t*)targetAddress = 0xEB;
			return 0;
		}
		else
			return 1;
	}
}