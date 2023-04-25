#pragma once

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_STR_SIZE 8192

typedef struct ASMSTDCALL_INFO {
	LPCSTR Name;
	FARPROC Addr;
} ASMSTDCALL_INFO;

struct ASMSTDCALL_INFO* TargetFuncsInfo;

CRITICAL_SECTION CriticalSection;
DWORD NumberOfTargetFuncs;
FARPROC pGetCommandLineW;
FARPROC pGetProcAddress;
BOOL IsReadyToLog;

VOID PrintError(_In_ LPCSTR Msg);
VOID PrintWinError(_In_ LPCSTR Msg, _In_ DWORD ErrorCode);
DWORD_PTR FindPattern(_In_ DWORD_PTR BaseAddr, _In_ SIZE_T Size, _In_ LPCSTR BytePattern, _In_ LPCSTR Mask);
VOID LogAPICall(_In_ LPCSTR FuncName, _In_ DWORD FuncArgc, _In_ DWORD_PTR Params, _In_ DWORD ReturnValue);
BOOL IsWideStr(_In_ BYTE* Addr);
BOOL IsSameStr(_In_ BYTE* TargetName, _In_ BYTE* Str);
BOOL IsValidStrMem(_In_ LPCVOID Addr);
BOOL IsValidMem(_In_ LPCVOID Addr);
VOID InitTargetFuncList();
VOID ResolveTargetFuncListAddresses();