#pragma once

#include <windows.h>

//
// Since we only need some fields of these structs there's no need to define all of them.
//
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        } s1;
    } u1;

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

PIMAGE_NT_HEADERS64 GetNtHeader(_In_ DWORD_PTR ModuleBase);
PIMAGE_NT_HEADERS32 GetNtHeader32(_In_ DWORD_PTR ModuleBase);
PIMAGE_SECTION_HEADER GetSectionHeader(_In_ DWORD_PTR ModuleBase, _In_ BYTE* SectionName);
PIMAGE_EXPORT_DIRECTORY GetExportDirectory(_In_ DWORD_PTR ModuleBase);
FARPROC GetExportAddr(_In_ LPCSTR ExportName);
FARPROC ResolveExportAddr(_In_ DWORD_PTR ModuleBase, _In_ LPCSTR ExportName);
PIMAGE_IMPORT_DESCRIPTOR GetImportDesc(_In_ DWORD_PTR ModuleBase);
BOOL HasImport(_In_ FARPROC ImportAddr);
LPCSTR GetImportName(_In_ FARPROC ImportAddr);