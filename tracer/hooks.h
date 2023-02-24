#pragma once

#include <windows.h>

extern VOID AsmstdcallStub(VOID);

LPVOID JmpBackAddr;

LPVOID PerformHook(_In_ BYTE* Src, _In_ BYTE* Dest, _In_ SIZE_T Size);
LPVOID PerformHook32(_In_ BYTE* Src, _In_ BYTE* Dest, _In_ SIZE_T Size);
VOID HookAsmstdcall();
VOID hk_Asmstdcall(_In_ LPVOID Cx);