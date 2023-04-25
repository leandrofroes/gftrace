#include "utils.h"
#include "hooks.h"

VOID
Init()
{
    //
    // Get kernel32.dll module base address.
    //
    HMODULE ModuleBase = GetModuleHandleW(L"kernel32.dll");

    if (ModuleBase == NULL)
    {
        PrintWinError("Failed to get kernel32.dll base address", GetLastError());
    }

    //
    // Get the address of GetCommandLineW() and save it for further usage.
    //
    pGetCommandLineW = GetProcAddress(ModuleBase, (LPCSTR)"GetCommandLineW");

    if (pGetCommandLineW == NULL)
    {
        PrintWinError("Failed to resolve GetCommandLineW() address", GetLastError());
    }

    //
    // Get the address of GetProcAddress() and save it for further usage.
    //
    pGetProcAddress = GetProcAddress(ModuleBase, (LPCSTR)"GetProcAddress");

    if (pGetProcAddress == NULL)
    {
        PrintWinError("Failed to resolve GetProcAddress() address", GetLastError());
    }

    //
    // Initialize a critical section object.
    //
    InitializeCriticalSection(&CriticalSection);

    //
    // Parse the user-defined API function list and initialize our global target list.
    //
    InitTargetFuncList();

    //
    // Initialize our IAT deny list.
    //
    InitIATDenyList();

    //
    // Perform the asmstdcall hook.
    //
    HookAsmstdcall();
}

BOOL WINAPI DllMain(
    HINSTANCE hModule,
    DWORD Reason,
    LPVOID Reserved
    )
{
    switch (Reason)
    {
        case DLL_PROCESS_ATTACH:
            //
            // Disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notifications in our DLL.
            //
            DisableThreadLibraryCalls(hModule);

            Init();

            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            while (!GetAsyncKeyState(VK_RETURN))
            {
                Sleep(1000);
            }

            printf("\n\n[+] Trace finished! Press \"Enter\" to close...\n");

            break;
    }

    return TRUE;
}