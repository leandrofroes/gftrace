#pragma once

#include <windows.h>

extern VOID AsmstdcallStub(VOID);

LPVOID JmpBackAddr;

LPVOID PerformHook(_In_ DWORD_PTR Src, _In_ DWORD_PTR Dest, _In_ SIZE_T Size);
VOID HookAsmstdcall();
VOID hk_Asmstdcall(_In_ LPVOID Cx);