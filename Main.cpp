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

// Vector with offsets loaded from .txt
std::vector<unsigned int> bases;
std::vector<unsigned int> offsets;

// FOW toggles
int _fowMode = 0;
int _fowVal = 1;

// Configuration vars
bool run = true;
bool cfg = true;
bool ms = false;

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
PVOID GetMBA(DWORD pid, const PWCHAR mName, DWORD_PTR mSize)
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
					mSize = mCurrent.modBaseSize;
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

// Load offsets at Runtime if cfg = true (Use offsets.txt file)
void initAddressesCFG()
{
	_fowtoggleaddr = ResolveAddrEx(_hProcess, _moduleBase + bases[2], offsets);
	_fowmodeaddr = ResolveAddrEx(_hProcess, _moduleBase + bases[1], { });
}

// Load offsets at Runtime if cfg = false (Use hard coded offsets)
void initAddresses()
{
	_fowtoggleaddr = ResolveAddrEx(_hProcess, _moduleBase + 0x830E550, { 0x0, 0x2718, 0x2AC });
	_fowmodeaddr = ResolveAddrEx(_hProcess, _moduleBase + 0x79A8B98, { });
}

// Main Loop
void input()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	while (run)
	{
		if (GetAsyncKeyState(0x50) & 1) // P Key
		{
			if (cfg)
				initAddressesCFG();
			else
				initAddresses();

			ReadProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(float), NULL);
			if (_fowVal == 1) {
				_fowVal = 0;
				_fowMode = 1;
				WriteProcessMemory(_hProcess, (int*)_fowmodeaddr, &_fowMode, sizeof(_fowMode), NULL);
				WriteProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(_fowVal), NULL);
				SetConsoleTextAttribute(hConsole, 15);
				std::cout << "Anti FoW ";
				SetConsoleTextAttribute(hConsole, 10);
				std::cout << "ON." << std::endl;
			}
			else {
				_fowVal = 1;
				_fowMode = 0;
				WriteProcessMemory(_hProcess, (int*)_fowmodeaddr, &_fowMode, sizeof(_fowMode), NULL);
				WriteProcessMemory(_hProcess, (int*)_fowtoggleaddr, &_fowVal, sizeof(_fowVal), NULL);
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
	/* We look for the file "offsets.txt" or "steam.txt", if it doesn't find them, 
	* look for "ms.txt" and set the variable ms to true
	*/
	ms = false;
	cfg = loadAddresses("offsets.txt");
	if (!cfg) {
		cfg = loadAddresses("steam.txt");
	}
	if (!cfg) {
		cfg = loadAddresses("ms.txt");
		if (cfg) {
			ms = true;
		}
	}
	// In not .txt file found at all, use the hard coded offsets
	if (!cfg) {
		std::cout << "Update: 5.1.148." << std::endl;
	}
	DWORD pid = 0;

	// Find the Process ID
	// RelicCardinal_ws.exe for Xbox pass version, RelicCardinal_ws.exe for Steam version
	if (ms)
	{
		pid = GetPID((PWCHAR)L"RelicCardinal_ws.exe");
	}
	else
	{
		pid = GetPID((PWCHAR)L"RelicCardinal_ws.exe");
	}
	if (pid != 0)
	{
		// Find the Module Base Address
		_hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
		if (ms)
		{
			_moduleBase = (uintptr_t)GetMBA(pid, (PWCHAR)L"RelicCardinal_ws.exe", _mSize);
		}
		else
		{
			_moduleBase = (uintptr_t)GetMBA(pid, (PWCHAR)L"RelicCardinal.exe", _mSize);
		}


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