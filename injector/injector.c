#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[]) {
    if (argc != 2)
    {
        puts("Usage: gftrace.exe <target_file>");
        return 1;
    }

    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFOA StartupInfo;

    memset(&StartupInfo, 0, sizeof(STARTUPINFO));
    StartupInfo.cb = sizeof(STARTUPINFO);
    memset(&ProcessInformation, 0, sizeof(PROCESS_INFORMATION));

    //
    // Create the target process in suspended state.
    //
    if (!CreateProcessA(NULL, (LPSTR)argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInformation)) 
    {
        printf("[!] Failed to create the target process.\n[!] Error code: %u\n", GetLastError());
        return 1;
    }

    HANDLE hProcess = ProcessInformation.hProcess;
    HANDLE hThread = ProcessInformation.hThread;

    BOOL IsWow64Proc = FALSE;

    //
    // Check if the target process is a Wow64 process and if so, terminate it cause we don't support it.
    //
    if (!IsWow64Process(hProcess, &IsWow64Proc))
    {
        printf("[!] Failed to check if the target process is WoW64.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    if (IsWow64Proc)
    {
        printf("[!] The target file needs to be a x64 file.\n");
        TerminateProcess(hProcess, 0);
        return 1;
    }

    char LibFullPath[MAX_PATH] = { 0 };
    char CurrentModuleFilepath[MAX_PATH] = { 0 };

    DWORD Len = GetModuleFileNameA(GetModuleHandleA(NULL), CurrentModuleFilepath, MAX_PATH);

    if (!Len)
    {
        printf("[!] Failed to get the current module filepath.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    for (SIZE_T i = Len - 1; i > 0; i--)
    {
        if (CurrentModuleFilepath[i] == 0x5c || CurrentModuleFilepath[i] == 0x2f)
        {
            CurrentModuleFilepath[i + 1] = '\0';
            break;
        }
    }

    SIZE_T i = 0;

    do {
        LibFullPath[i] = CurrentModuleFilepath[i];
        i++;
    } while (CurrentModuleFilepath[i] != '\0');

    const char* LibName = "\\gftrace.dll";

    SIZE_T Size = strlen(LibFullPath) + strlen(LibName) + 1;

    //
    // Build the gftrace.dll full path to be used in the injection step.
    //
    strncat_s(LibFullPath, Size, LibName, _TRUNCATE);

    //
    // Check if the gftrace.dll file exists in the gftrace.exe directory.
    //
    if (GetFileAttributesA((LPCSTR)LibFullPath) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        printf("[!] Failed to find the gftrace.dll file in the gftrace.exe directory.\n");
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Get kernel32.dll module base address.
    //
    HMODULE ModuleBase = GetModuleHandleW(L"kernel32.dll");

    if (ModuleBase == NULL)
    {
        printf("[!] Failed to get kernel32 base address.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Get the address of LoadLibraryA() to be used to inject gftrace DLL into the target process.
    //
    FARPROC pLoadLibraryA = GetProcAddress(ModuleBase, "LoadLibraryA");

    if (pLoadLibraryA == NULL)
    {
        printf("[!] Failed to resolve LoadLibraryA address.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Allocate memory for gftrace DLL full path in the target process.
    //
    LPVOID LibFullPathRemoteAddr = VirtualAllocEx(hProcess, NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (LibFullPathRemoteAddr == NULL)
    {
        printf("[!] Failed to allocate virtual memory in the target process.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Write gftrace DLL full path into the target process.
    //
    if (!WriteProcessMemory(hProcess, LibFullPathRemoteAddr, (LPCVOID)LibFullPath, Size, NULL))
    {
        printf("[!] Failed to write to the target process memory.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    DWORD ThreadId;

    //
    // Create a thread in the target process pointing to LoadLibraryA() to load the gftrace DLL into the target process address space.
    //
    HANDLE hInjectionThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, (LPVOID)LibFullPathRemoteAddr, 0, &ThreadId);

    if (hInjectionThread == NULL)
    {
        printf("[!] Failed to create a remote thread in the target process.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Wait for the injection thread to finish.
    //
    WaitForSingleObject(hInjectionThread, INFINITE);

    //
    // Resume the target process main thread.
    //
    ResumeThread(hThread);

    VirtualFreeEx(hProcess, LibFullPathRemoteAddr, 0, MEM_RELEASE);
    CloseHandle(hInjectionThread);
    CloseHandle(hThread);

    return 0;
}