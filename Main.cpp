#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>

// Win API
HANDLE _hProcess;
uintptr_t _moduleBase;
DWORD _mSize = 0;

// Pointers
uintptr_t _fowtoggleaddr;
uintptr_t _fowmodeaddr;
uintptr_t _jumppatchaddr;
BYTE* buffer;

// Vector with offsets loaded from .txt
std::vector<unsigned int> bases;
std::vector<unsigned int> offsets;

// FOV toggles
int _fowMode = 0;
int _fowVal = 0;

// Configuration vars
bool active = false;
bool run = true;
bool cfg = true;

// Get the Process ID
DWORD GetPID(const PWCHAR pName)
{
	DWORD pid = 0;
	PROCESSENTRY32 pCurrent;
	pCurrent.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!(hSnap == INVALID_HANDLE_VALUE)) {
		if (Process32First(hSnap, &pCurrent))
		{
			do
			{
				if (!wcscmp(pCurrent.szExeFile, pName))
				{
					pid = pCurrent.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &pCurrent));
		}
	}
	if (hSnap != 0)
		CloseHandle(hSnap);
	return pid;
}

// Get the Module Base Address
PVOID GetMBA(DWORD pid, const PWCHAR mName, DWORD* mSize)
{
	PVOID addr = 0;
	MODULEENTRY32 mCurrent;
	mCurrent.dwSize = sizeof(mCurrent);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap != INVALID_HANDLE_VALUE) {
		if (Module32First(hSnap, &mCurrent))
		{
			do
			{
				if (!wcscmp(mCurrent.szModule, mName))
				{
					addr = (PVOID)mCurrent.modBaseAddr;
					*mSize = mCurrent.modBaseSize;
					break;
				}
			} while (Module32Next(hSnap, &mCurrent));
		}
	}
	if (hSnap != 0)
		CloseHandle(hSnap);
	return addr;
}

// Get the addresses from the pointers chain
uintptr_t ResolveAddrEx(HANDLE hProcess, uintptr_t ptr, std::vector<unsigned int> offsets)
{
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		ReadProcessMemory(hProcess, (BYTE*)addr, &addr, sizeof(addr), 0);
		addr += offsets[i];
	}
	return addr;
}

void HPX(HANDLE hProcess, PBYTE destination, PBYTE source, SIZE_T size, BYTE* oldBytes)
{
	DWORD oldProtection;
	VirtualProtectEx(hProcess, destination, size, PAGE_READWRITE, &oldProtection);
	ReadProcessMemory(hProcess, destination, oldBytes, size, nullptr);
	WriteProcessMemory(hProcess, destination, source, size, nullptr);
	VirtualProtectEx(hProcess, destination, size, oldProtection, &oldProtection);
}

PBYTE Aobs(PCHAR pattern, PCHAR mask, PBYTE begin, SIZE_T size)
{
	SIZE_T patternSize = strlen((char*)mask);

	for (int i = 0; i < size; i++)
	{
		bool match = true;
		for (int j = 0; j < patternSize; j++)
		{
			if (*(char*)((uintptr_t)begin + i + j) != pattern[j] && mask[j] != '?')
			{
				match = false;
				break;
			}
		}
		if (match) return (begin + i);
	}
	return nullptr;
}

char* AobsEx(HANDLE hProc, char* pattern, char* mask, char* begin, intptr_t size)
{
	char* match{ nullptr };
	SIZE_T bytesRead;
	DWORD oldprotect;
	char* buffer{ nullptr };
	MEMORY_BASIC_INFORMATION mbi;
	mbi.RegionSize = 0x1000;

	VirtualQueryEx(hProc, (LPCVOID)begin, &mbi, sizeof(mbi));

	for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize)
	{
		if (!VirtualQueryEx(hProc, curr, &mbi, sizeof(mbi))) continue;

		if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

		delete[] buffer;
		buffer = new char[mbi.RegionSize];

		if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect))
		{
			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
			VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);

			char* internalAddr = (char*)Aobs(pattern, mask, (PBYTE)buffer, (intptr_t)bytesRead);

			if (internalAddr != nullptr)
			{
				match = curr + (internalAddr - buffer);
				break;
			}
		}
	}
	delete[] buffer;
	return match;
}

// Load offsets from a .txt
bool loadAddresses(const char* file)
{
	std::ifstream inFile;
	inFile.open(file);
	if (!inFile) {
		return false;
	}
	else
	{
		std::string c;
		while (inFile >> c);
		std::string n;
		int cInserted = 0;
		int cIndex = 0;

		std::cout << "Offsets file found!" << std::endl;

		// Index =          0       1         2      3   4    5
		// Example .txt = "51148,127568792,137422160,0,10008,684,"
		// Split the .txt contents ...
		for (int i = 0; i < c.size(); i++)
		{
			if (c.at(i) == 44) // ... separated with a ","
			{
				if (cIndex >= 3) // If >= 3 we are reading offsets
				{
					n = c.substr(cInserted, i);
					offsets.push_back(stoi(n));
					n.clear();
					cInserted = i + 1;
				}
				else // Else we are reading Game version number / base pointers
				{
					n = c.substr(cInserted, i);
					bases.push_back(stoi(n));
					n.clear();
					cInserted = i + 1;
				}
				cIndex++;
			}
		}
		std::cout << "Update: " << bases[0] << "." << std::endl;

		return true;
	}
	return false;
}

bool initPatchAddress()
{
	// Patch vma by static offset
	//_jumppatchaddr = ResolveAddrEx(_hProcess, _moduleBase + 0x50CEB0, { });

	// Patch by AoB Scan
	if (!active)
	{
		char aob[] = "\x74\x30\x48\x8b\x02\x44\x38\x48";
		char mask[] = "xxxxxxxx";
		_jumppatchaddr = (uintptr_t)AobsEx(_hProcess, (PCHAR)aob, (PCHAR)mask, (char*)_moduleBase, (intptr_t)_mSize);
	}
	else
	{
		char aob[] = "\xeb\x35\x48\x8b\x02\x44\x38\x48";
		char mask[] = "xxxxxxxx";
		_jumppatchaddr = (uintptr_t)AobsEx(_hProcess, (PCHAR)aob, (PCHAR)mask, (char*)_moduleBase, (intptr_t)_mSize);
	}
	if (!_jumppatchaddr) return false;
	return true;
}

// Load offsets at Runtime if cfg = true (Use offsets.txt file)
bool initAddressesCFG()
{
	_fowtoggleaddr = ResolveAddrEx(_hProcess, _moduleBase + bases[2], offsets);
	_fowmodeaddr = ResolveAddrEx(_hProcess, _moduleBase + bases[1], { });
	if (!initPatchAddress()) return false;
	return true;
}

// Load offsets at Runtime if cfg = false (Use hard coded offsets)
bool initAddresses()
{
	_fowtoggleaddr = ResolveAddrEx(_hProcess, _moduleBase + 0x84EE578, { 0x0, 0x2718, 0x2C8 });
	_fowmodeaddr = ResolveAddrEx(_hProcess, _moduleBase + 0x7B82C28, { });
	if (!initPatchAddress()) return false;
	return true;
}

// Main Loop
void input()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	while (run)
	{
		if (GetAsyncKeyState(0x50) & 1) // P Key
		{
			bool addrReady = true;
			if (cfg)
			{
				addrReady = initAddressesCFG();
			}
			else
			{
				addrReady = initAddresses();
			}

			if (!addrReady)
			{
				SetConsoleTextAttribute(hConsole, 12);
				std::cout << "ERROR: COULDN'T FIND SIGNATURE! PLEASE UPDATE." << std::endl;
				continue;
			}

			ReadProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(float), NULL);
			if (!active) {
				active = true;
				ReadProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(_fowVal), NULL);
				ReadProcessMemory(_hProcess, (int*)_fowmodeaddr, &_fowMode, sizeof(_fowMode), NULL);
				_fowVal += 1;
				_fowMode += 1;
				WriteProcessMemory(_hProcess, (int*)_fowmodeaddr, &_fowMode, sizeof(_fowMode), NULL);
				WriteProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(_fowVal), NULL);

				// Unconditional Jump to skip the FoW check
				char org[] = "\xeb\x35";
				HPX(_hProcess, (PBYTE)_jumppatchaddr, (PBYTE)org, 2, buffer);

				SetConsoleTextAttribute(hConsole, 15);
				std::cout << "Anti FoW ";
				SetConsoleTextAttribute(hConsole, 10);
				std::cout << "ON." << std::endl;
			}
			else {
				active = false;
				ReadProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(_fowVal), NULL);
				ReadProcessMemory(_hProcess, (int*)_fowmodeaddr, &_fowMode, sizeof(_fowMode), NULL);
				_fowVal -= 1;
				_fowMode -= 1; 
				WriteProcessMemory(_hProcess, (int*)_fowmodeaddr, &_fowMode, sizeof(_fowMode), NULL);
				WriteProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(_fowVal), NULL);

				// Restore Jump if Zero FoW check
				char org[] = "\x74\x30";
				HPX(_hProcess, (PBYTE)_jumppatchaddr, (PBYTE)org, 2, buffer);

				SetConsoleTextAttribute(hConsole, 15);
				std::cout << "Anti FoW ";
				SetConsoleTextAttribute(hConsole, 12);
				std::cout << "OFF." << std::endl;
			}
		}

		Sleep(20);
	}
	CloseHandle(hConsole);
}

int main()
{
	// We look for the file "offsets.txt"

	cfg = loadAddresses("offsets.txt");

	// In not .txt file found at all, use the hard coded offsets
	if (!cfg) {
		std::cout << "Update: 10.1.48." << std::endl;
	}
	DWORD pid = 0;

	// Find the Process ID RelicCardinal.exe for Steam version
	pid = GetPID((PWCHAR)L"RelicCardinal.exe");

	if (pid != 0)
	{
		// Find the Module Base Address
		_hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
		_moduleBase = (uintptr_t)GetMBA(pid, (PWCHAR)L"RelicCardinal.exe", &_mSize);

		buffer = new BYTE[5]; // Buffer for FoW values (old bytes from patching binary)

		// Extra prints
		std::cout << "God Hates Cheats!" << std::endl;
		std::cout << "Toggle Key: \"P\"" << std::endl;
		input();
	}
	else {
		std::cout << "Game not found. Press Enter to exit." << std::endl;
		char ctest = getchar();
	}
	return 0;
}