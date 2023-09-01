#include <stdio.h>
#include <Windows.h>

int main(int argc, char* argv[])
{
    unsigned int char_in_hex;

    char* shellcode = argv[1];
    unsigned int iterations = strlen(shellcode);

    unsigned int memory_allocation = strlen(shellcode) / 2;

    //十六进制的shellcode转换为可执行的代码
    for (unsigned int i = 0; i < iterations - 1; i++)
    {
        sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
        shellcode[i] = (char)char_in_hex;
    }

    void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
    memcpy(exec, shellcode, memory_allocation);
    DWORD ignore;
    VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
    (*(void(*)()) exec)();

    return 0;
}
