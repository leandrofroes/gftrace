#pragma once

#include <windows.h>

typedef struct LIBCALL {
	ULONG_PTR FuncAddr;
	DWORD Argc;
	ULONG_PTR Argv;
	ULONG_PTR ReturnValue;
} LIBCALL, *PLIBCALL;

extern VOID AsmstdcallStub(VOID);

LPVOID JmpBackAddr;

LPVOID PerformHook(_In_ ULONG_PTR Src, _In_ ULONG_PTR Dest, _In_ SIZE_T Size);
LPVOID PerformHook32(_In_ ULONG_PTR Src, _In_ ULONG_PTR Dest, _In_ SIZE_T Size);
VOID HookAsmstdcall();
VOID hk_Asmstdcall(_In_ PLIBCALL Frame);