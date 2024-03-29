#pragma once

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_STR_SIZE 8192

typedef struct FUNCINFO
{
	LPCSTR Name;
	FARPROC Addr;
} FUNCINFO;

struct FUNCINFO* TargetFuncsInfo;

typedef struct IATINFO
{
	ULONG_PTR Addr;
	BOOL IsAllowedToLog;
} IATINFO;

struct IATINFO* IatInfo;

CRITICAL_SECTION CriticalSection;
DWORD NumberOfTargetFuncs;
DWORD NumberOfIATEntries;
FARPROC pGetCommandLineW;
FARPROC pGetProcAddress;
BOOL bIsReadyToLog;

VOID PrintError(_In_ LPCSTR Msg);
VOID PrintWinError(_In_ LPCSTR Msg, _In_ DWORD ErrorCode);

ULONG_PTR FindPattern(_In_ ULONG_PTR BaseAddr, _In_ SIZE_T Size, _In_ LPCSTR BytePattern, _In_ LPCSTR Mask);

VOID LogAPICall(_In_ LPCSTR FuncName, _In_ DWORD Argc, _In_ ULONG_PTR Params, _In_ DWORD ReturnValue);
VOID LogGetProcAddressCall(_In_ ULONG_PTR Params, _In_ FARPROC ReturnValue);

BOOL IsWideStr(_In_ BYTE* Addr);
BOOL IsSameStr(_In_ BYTE* TargetName, _In_ BYTE* Str);
BOOL IsValidStrMem(_In_ LPCVOID Addr);

VOID InitTargetFuncList();
VOID ResolveTargetFuncListAddresses();
VOID InitIATDenyList();