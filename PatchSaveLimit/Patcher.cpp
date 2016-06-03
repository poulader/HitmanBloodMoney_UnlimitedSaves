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

//The opcode we will write for save patch (unconditional short jmp)
const uint8_t saveBytesToWrite[]{ 0xEB };

//The opcode we expect at our save offset, jl
const uint8_t saveBytesToRead[]{ 0x7C };

//xor edx, edx
//will replace opcodes at load offset, we want the zf active
const uint8_t loadBytesToWrite[]{ 0x31, 0xFF };

//test dl,dl
//original instructions at load offset
const uint8_t loadBytesToRead[]{ 0x84, 0xD2 };

//Ze process name
const CHAR processName[] = { "HitmanBloodMoney.exe" };

//Once everything has been unpacked, this is the offset from the module base to the jl we want to make jmp for save
const DWORD saveOpcodeOffset = 0x2776CD;

//Once everything has been unpacked, this is the offset from the module base to the test for load
const DWORD loadOpcodeOffset = 0x277689;

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

			OpCodeWriter codeWriter(pe32.th32ProcessID);

			if (codeWriter.OpenProcessHandle())
			{
				printf(_T("Failed to open process.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			if (codeWriter.WriteOpCodeAtAddress((DWORD)moduleEntry.modBaseAddr + saveOpcodeOffset, sizeof(saveBytesToWrite), saveBytesToWrite))
			{
				printf(_T("Failed to patch.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			if (codeWriter.WriteOpCodeAtAddress((DWORD)moduleEntry.modBaseAddr + loadOpcodeOffset, sizeof(loadBytesToWrite), loadBytesToWrite))
			{
				printf(_T("Failed to patch.\n"));
				CloseHandle(hProcessSnap);
				Sleep(5000);
				break;
			}

			printf(_T("Patched! Enjoy.\n"));

			CloseHandle(hProcessSnap);
			Sleep(5000);
			break;

		}

	}



};