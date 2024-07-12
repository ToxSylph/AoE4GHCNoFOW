#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include "json.hpp"

using json = nlohmann::json;

// Win API
HANDLE hProcess;
HANDLE hConsole;
uintptr_t moduleBase;
DWORD mSize = 0;

bool run = false;
bool active = false;
bool patched = false;

int toggleKey = 0x50; // P Key
int exitKey = VK_END; // End Key
bool customKeys = false;

std::vector<unsigned int> offsets;

uintptr_t fowAddr = NULL;
uintptr_t mpBoolAddr = NULL;
uintptr_t patchAddr = NULL;
int fowMode = 0;
int fowVal = 0;

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

void HPX(HANDLE hProcess, PBYTE destination, PBYTE source, SIZE_T size)
{
	DWORD oldProtection;
	VirtualProtectEx(hProcess, destination, size, PAGE_READWRITE, &oldProtection);
	WriteProcessMemory(hProcess, destination, source, size, nullptr);
	VirtualProtectEx(hProcess, destination, size, oldProtection, &oldProtection);
}

unsigned int hexToUint(const std::string& hexStr) {
	unsigned int result;
	std::stringstream ss;
	ss << std::hex << hexStr;
	ss >> result;
	return result;
}

bool loadAddresses()
{
	std::ifstream input_file("data.json");
	if (!input_file.is_open()) {
		std::cerr << "data.json doesn't exists!" << std::endl;
		return false;
	}

	json j;
	input_file >> j;

	std::string gameversion = j["gameversion"];
	unsigned int patchaddress = hexToUint(j["patchaddress"]);
	unsigned int fowbase = hexToUint(j["fowaddr"]);
	unsigned int mpboolbase = hexToUint(j["mpboolbase"]);
	unsigned int mpboolo1 = hexToUint(j["mpboolo1"]);
	unsigned int mpboolo2 = hexToUint(j["mpboolo2"]);
	unsigned int mpboolo3 = hexToUint(j["mpboolo3"]);
	int cToggleKey = hexToUint(j["togglekey"]);
	int cExitKey = hexToUint(j["exitkey"]);

	if (cToggleKey != 0)
		toggleKey = cToggleKey;
	if (cExitKey != 0)
		exitKey = cExitKey;
	if (cToggleKey != 0 || cExitKey != 0)
		customKeys = true;

	mpBoolAddr = ResolveAddrEx(hProcess, moduleBase + mpboolbase, { mpboolo1, mpboolo2, mpboolo3 });
	fowAddr = ResolveAddrEx(hProcess, moduleBase + fowbase, { });
	patchAddr = ResolveAddrEx(hProcess, moduleBase + patchaddress, { });

	SetConsoleTextAttribute(hConsole, 15);
	std::cout << "MpBool Address: " << std::hex << mpBoolAddr << std::endl;
	std::cout << "FoW Toggle Address: " << std::hex << fowAddr << std::endl;

	char org[] = "\x90\x90";
	HPX(hProcess, (PBYTE)patchAddr, (PBYTE)org, 2);
	patched = true;
	std::cout << "Patch address: " << std::hex << patchAddr << std::endl;

	if (mpBoolAddr == NULL || fowAddr == NULL)
	{
		SetConsoleTextAttribute(hConsole, 12);
		std::cerr << "Wrong offsets!" << std::endl;
		return false;
	}

	SetConsoleTextAttribute(hConsole, 14);
	std::cout << "Addresses loaded. Game Version: " << gameversion << std::endl;

	return true;
}
void toggleOn()
{
	active = true;
	ReadProcessMemory(hProcess, (int*)fowAddr, &fowVal, sizeof(fowVal), NULL);
	ReadProcessMemory(hProcess, (int*)mpBoolAddr, &fowMode, sizeof(fowMode), NULL);
	fowVal += 1;
	fowMode += 1;
	WriteProcessMemory(hProcess, (int*)fowAddr, &fowVal, sizeof(fowVal), NULL);
	WriteProcessMemory(hProcess, (int*)mpBoolAddr, &fowMode, sizeof(fowMode), NULL);
}

void toggleOff()
{
	active = false;
	ReadProcessMemory(hProcess, (int*)fowAddr, &fowVal, sizeof(fowVal), NULL);
	ReadProcessMemory(hProcess, (int*)mpBoolAddr, &fowMode, sizeof(fowMode), NULL);
	fowVal -= 1;
	fowMode -= 1;
	WriteProcessMemory(hProcess, (int*)fowAddr, &fowVal, sizeof(fowVal), NULL);
	WriteProcessMemory(hProcess, (int*)mpBoolAddr, &fowMode, sizeof(fowMode), NULL);
}
void input()
{
	run = true;

	while (run)
	{
		if (GetAsyncKeyState(exitKey) & 1) // End Key
		{
			run = false;
			SetConsoleTextAttribute(hConsole, 10);
			std::cout << "Exiting..." << std::endl;
			if (active)
				toggleOff();
			SetConsoleTextAttribute(hConsole, 15);
			continue;
		}
		if (GetAsyncKeyState(toggleKey) & 1) // P Key
		{

			if (!active) {
				toggleOn();

				SetConsoleTextAttribute(hConsole, 15);
				std::cout << "Anti FoW ";
				SetConsoleTextAttribute(hConsole, 10);
				std::cout << "ON." << std::endl;
			}
			else {
				toggleOff();

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
	DWORD pid = 0;
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 15);

	pid = GetPID((PWCHAR)L"RelicCardinal.exe");

	if (pid != 0)
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
		moduleBase = (uintptr_t)GetMBA(pid, (PWCHAR)L"RelicCardinal.exe", &mSize);
	}
	else {
		SetConsoleTextAttribute(hConsole, 12);
		std::cout << "Game not found. Press Enter to exit." << std::endl;
		char ctest = getchar();
		return 1;
	}

	if (!loadAddresses())
	{
		SetConsoleTextAttribute(hConsole, 12);
		std::cout << "Failed to load addresses. Press Enter to exit." << std::endl;
		char ctest = getchar();
		return 1;
	}

	SetConsoleTextAttribute(hConsole, 10);
	std::cout << "God Hates Cheats!" << std::endl;
	SetConsoleTextAttribute(hConsole, 14);
	if (customKeys)
	{
		std::cout << "Custom keys loaded." << std::endl;
		std::cout << "Toggle Key: 0x" << std::hex << toggleKey << std::endl;
		std::cout << "Exit Key: 0x" << std::hex << exitKey << std::endl;
	}
	else
	{
		std::cout << "Default keys loaded." << std::endl;
		std::cout << "Toggle Key: \"P\"" << std::endl;
		std::cout << "Exit Key: \"End\"" << std::endl;
	}
	input();
	if (patched)
	{
		char org[] = "\x7D\x16";
		HPX(hProcess, (PBYTE)patchAddr, (PBYTE)org, 2);
	}

	return 0;
}