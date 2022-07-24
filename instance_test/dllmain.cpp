// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "memcheck.h"
#include "mscan.h"

#include "MinHook.h"

void open_console(LPCSTR title = "epxloit") {
    unsigned long ignore = 0;
    VirtualProtect(&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &ignore);
    *(BYTE*)&FreeConsole = 0xC3;
    VirtualProtect(&FreeConsole, 1, ignore, &ignore);

    AllocConsole();
    freopen("conin$", "r", stdin); // Enable input
    freopen("conout$", "w", stdout); // Display output
    freopen("conout$", "w", stderr); // std error handling
    SetConsoleTitleA(title);
}

typedef int(__fastcall* tdTempt)(int* a1, int a2, int a3, int a4);
tdTempt origTempt = nullptr;

typedef int(__cdecl* tdNewInstance)(int a1);
tdNewInstance origNewInstance = nullptr;

typedef int(__thiscall* tdTest)(int a1, int a2, int a3, int a4);
tdTest origTest = nullptr;

typedef int(__thiscall* tdLookup)(const char* a1);
tdLookup origLookup = nullptr;

int __fastcall hkLookup(const char* name) {
    printf("hkLookup %s", name);
    int ret = origLookup(name);
    printf(" - %p\n", ret);
    return ret;
}

int __fastcall temp(int* a1, int edx, int a2, int a3, int a4) {
    printf("%p %p %p %p\n", a1, a2, a3, a4);
    system("pause");
    int ret = origTempt(a1, a2, a3, a4);
    printf("%p\n", ret);
    system("pause");
    return ret;
}

int __fastcall test(int a1, int edx, int a2, int a3, int a4) {
    printf("test: %p %p %p %p\n", a1, a2, a3, a4);
    return origTest(a1, a2, a3, a4);
}

int hkNewInstance(int a1) {
    int top = (*(int*)(a1 + 0x14) - *(int*)(a1 + 0x8)) / 16;
    printf("top: %d\n", top);
    return origNewInstance(a1);
}

void main() {
    open_console();

    memcheck::bypass();

    int newInstanceAddr = memscan::scan("558BEC6AFF68????????64A1????????50648925????????83EC1053568B75088D45F05750BA")[0];
    int nameLookupOffset = newInstanceAddr + 0x46;
    int nameLookupAddr = nameLookupOffset + 0x4 + *(int*)nameLookupOffset;
    int createByNameOffset = newInstanceAddr + 0x52;
    int createByNameAddr = createByNameOffset + 0x4 + *(int*)createByNameOffset;
    

    MH_Initialize();
    MH_CreateHook((LPVOID)createByNameAddr, temp, reinterpret_cast<void**>(&origTempt));
    MH_EnableHook((LPVOID)createByNameAddr);

    //MH_CreateHook((LPVOID)0x79C440, hkNewInstance, reinterpret_cast<void**>(&origNewInstance));
    //MH_EnableHook((LPVOID)0x79C440);

    MH_CreateHook((LPVOID)nameLookupAddr, hkLookup, reinterpret_cast<void**>(&origLookup));
    MH_EnableHook((LPVOID)nameLookupAddr);

    /*int r = origTempt(origLookup("Part"), 2, 0, 0);
    printf("%p\n", r);
    printf("%p\n", *(int*)r);
    system("pause");*/


    printf("%p\n", createByNameAddr);

    //int BasePart = origLookup("Part");
   // printf("base Part : %p\n", BasePart);

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0,(LPTHREAD_START_ROUTINE)main, 0, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

