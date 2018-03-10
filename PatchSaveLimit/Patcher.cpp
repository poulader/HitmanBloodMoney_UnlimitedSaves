#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdint.h>
#include "OpCodeWriter.h"

using namespace std;


/*

I wrote this because I want to play harder difficulty in hitman blood money without being limited by saves.
I do not patch the hitman image on disk because they are using a packer which I'm working on atm; although they do not appear
to have any checksum checking for the part this modifies in the running process, there may be an initial checksum check before or while
unpacking as well. So this modifies an opcode in the hitman process in memory to always jmp to the "ok do a save" condition, instead of
a conditional jl based on number of saves so far.

This has been tested on steam v 1.2, but I added pattern matching so it should work for non steam versions too. If it doesn't work, please make an issue on github page, and include a link to your game exe uploaded somewhere.

If you want to build this yourself, you must use the compiler and linker settings included in the project file, "Minimal x86". If you do not, the size of the exported thread routine
may change, you will need to check disassembly and change the WPM size. Also, an earlier version had the exported function pointing to an entry in a jmp
table, so if you change compile/link options, watch out for that as well. I had to parse the instructions at the exported function address to get the
actual offset to the exported function, which is a pain. So change options at your own risk!

I am not responsible for the effectiveness, safety, or anything else of this software, blah blah blah, use at your own risk.

This does not modify any copyrighted files, it makes a change in your PCs memory, and this is for educational and research purposes.

Also I wrote this late at night so the code is sloppy, so sue me. I'll refactor later.

INstructions: Start hitman blood money latest version, wait for it to reach main menu ("profile manager") or later. Run the program. It will tell you if it fails
or succeeds.

*/

//The opcode we will write for save patch (unconditional short jmp)
const uint8_t saveBytesToWrite[]{ 0xEB };

//The pattern we expect before and at at our save offset, jl
const uint8_t saveBytesToRead[]
{
	0x8b,
	0x01,
	0xff,
	0x50,
	0x1c,
	0x3b,
	0xc7,
	0x7c,
	0x18
};

const DWORD saveBytesToReadTargetPos = sizeof(saveBytesToRead) - 2;

//xor edx, edx
//will replace opcodes at load offset, we want the zf active
const uint8_t loadBytesToWrite[]{ 0x31, 0xFF };

//test dl,dl
//original instructions before and at load offset.
const uint8_t loadBytesToRead[]
{
	0x8a,
	0x96,
	0xc4,
	0x00,
	0x00,
	0x00,
	0x84,
	0xd2

};

const DWORD loadBytesToReadTargetPos = sizeof(loadBytesToRead) - 2;

//Ze process name
const CHAR processName[] = { "HitmanBloodMoney.exe" };

//base of page region where the save, load logic is implemented.
const DWORD saveLoadSectionBase = 0x00277000;

//Once everything has been unpacked, this is the offset from the module base to the jl we want to make jmp for save
const DWORD saveOpcodeOffset = 0x2776CD;

//Once everything has been unpacked, this is the offset from the module base to the test for load
const DWORD loadOpcodeOffset = 0x277689;

bool LazyPatternMatch(BYTE* nTargetBuf, SIZE_T nTargetBufLen, BYTE* nPatternMatch, SIZE_T nPatternMatchLen, DWORD& out_nPatternStartAddress);

//changed to use OpCodeWriter class
int main()
{

	//Handles for process + snapshot enumerating
	HANDLE hProcessSnap;
	HANDLE hProcess;

	//Some info about the process, image name and ID are what we want
	PROCESSENTRY32 pe32;

	SIZE_T nBytesWritten = 0;

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

		bool didStartBeforeGame = false;

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
			didStartBeforeGame = true;
			CloseHandle(hProcessSnap);
			ZeroMemory(&pe32, pe32.dwSize);
			printf("\nWaiting for game to start....\n");
			Sleep(10000);
			continue;
		}
		else
		{
			if (didStartBeforeGame)
			{
				printf("\nGame started, waiting a bit before trying to patch. Please make sure game makes it to load profile menu before running this if it fails.\n");

				Sleep(2000);
			}
			else
			{
				printf("\nGetting ready to try to patch.\n");
				Sleep(500);
			}

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

			OpCodeWriter codeWriter(pe32.th32ProcessID);

			if (codeWriter.OpenProcessHandle())
			{
				printf(_T("Failed to open process.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			MEMORY_BASIC_INFORMATION queryMem;

			ZeroMemory(&queryMem, sizeof(MEMORY_BASIC_INFORMATION));

			SIZE_T returnedByteCount = VirtualQueryEx(codeWriter.GetProcessHandle(), (void*)((DWORD)moduleEntry.modBaseAddr + saveOpcodeOffset), &queryMem, sizeof(MEMORY_BASIC_INFORMATION));

			if (returnedByteCount == 0)
			{
				printf(_T("Failed reading target memory.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			byte readSaveMemoryBuf[0x2000];

			SIZE_T numberOfBytesRead = 0;

			ZeroMemory(readSaveMemoryBuf, sizeof(readSaveMemoryBuf));

			//Read the memory
			if (!ReadProcessMemory(codeWriter.GetProcessHandle(), queryMem.BaseAddress, readSaveMemoryBuf, sizeof(readSaveMemoryBuf), &numberOfBytesRead))
			{
				printf(_T("Failed reading target memory.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			DWORD savePatternStartAddress = 0;

			DWORD loadPatternStartAddress = 0;

			//search for the save pattern, if found will store the address of the first byte in pattern relative to read buffer start in savePatternStartAddress
			bool savePatternFound = LazyPatternMatch(readSaveMemoryBuf, sizeof(readSaveMemoryBuf), (PBYTE)saveBytesToRead, sizeof(saveBytesToRead), savePatternStartAddress);

			if (!savePatternFound)
			{
				printf(_T("Could not find save pattern.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			//find the pattern for load patch
			if (!LazyPatternMatch(readSaveMemoryBuf, sizeof(readSaveMemoryBuf), (PBYTE)loadBytesToRead, sizeof(loadBytesToRead), loadPatternStartAddress))
			{
				printf(_T("Could not find load pattern.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			//OK, we found save and load locations in the target area in process memory.
			//adjust our offsets.

			DWORD savePatternInRemoteProcStart = (DWORD)moduleEntry.modBaseAddr + saveLoadSectionBase + savePatternStartAddress + saveBytesToReadTargetPos;

			DWORD loadPatternInRemoteProcStart = (DWORD)moduleEntry.modBaseAddr + saveLoadSectionBase + loadPatternStartAddress + loadBytesToReadTargetPos;

			Sleep(500);

			if (codeWriter.WriteOpCodeAtAddress(savePatternInRemoteProcStart, sizeof(saveBytesToWrite), saveBytesToWrite))
			{
				printf(_T("Failed to patch.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			Sleep(500);

			if (codeWriter.WriteOpCodeAtAddress(loadPatternInRemoteProcStart, sizeof(loadBytesToWrite), loadBytesToWrite))
			{
				printf(_T("Failed to patch.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			Sleep(500);

			printf(_T("Patched! Enjoy.\n"));

			CloseHandle(hProcessSnap);
			Sleep(5000);
			break;

		}

	}



};


//Lazy pattern search, area to search is small enough that this works just fine.
bool LazyPatternMatch(BYTE* nTargetBuf, SIZE_T nTargetBufLen, BYTE* nPatternMatch, SIZE_T nPatternMatchLen, DWORD& out_nPatternStartAddress)
{
	//find the pattern in target region

	DWORD stopSearchPoint = nTargetBufLen - nPatternMatchLen;

	bool foundPattern = true;

	DWORD patternStart = 0;

	for (; patternStart <= stopSearchPoint; patternStart++)
	{
		foundPattern = true;

		for (DWORD j = 0; j < sizeof(nPatternMatchLen); j++)
		{
			if (nTargetBuf[patternStart + j] != nPatternMatch[j])
			{
				foundPattern = false;
				break;
			}
		}

		if (foundPattern)
		{
			out_nPatternStartAddress = patternStart;
			break;
		}
	}

	return foundPattern;
}