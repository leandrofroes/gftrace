#pragma once

#include <windows.h>

typedef struct LIBCALL {
	DWORD_PTR FuncAddr;
	DWORD Argc;
	DWORD_PTR Argv;
	DWORD_PTR ReturnValue;
} LIBCALL, *PLIBCALL;

extern VOID AsmstdcallStub(VOID);

LPVOID JmpBackAddr;

LPVOID PerformHook(_In_ DWORD_PTR Src, _In_ DWORD_PTR Dest, _In_ SIZE_T Size);
LPVOID PerformHook32(_In_ DWORD_PTR Src, _In_ DWORD_PTR Dest, _In_ SIZE_T Size);
VOID HookAsmstdcall();
VOID hk_Asmstdcall(_In_ PLIBCALL Frame);