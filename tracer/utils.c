#include "utils.h"
#include "pe.h"

VOID
PrintError(
	_In_ LPCSTR Msg
	)
{
	printf("\n[!] Error: %s!\n", Msg);
	ExitProcess(0);
}

VOID
PrintWinError(
	_In_ LPCSTR Msg,
	_In_ DWORD ErrorCode
	)
{
	printf("\n[!] Error: %s!\n[!] Error code: %u\n", Msg, ErrorCode);
	ExitProcess(0);
}

DWORD_PTR
FindPattern(
	_In_ DWORD_PTR BaseAddr,
	_In_ SIZE_T Size,
	_In_ LPCSTR BytePattern,
	_In_ LPCSTR Mask
	)
{
	SIZE_T PatternSize = strlen(Mask);
	BOOL bFound;

	for (SIZE_T i = 0; i < Size - PatternSize; i++)
	{
		bFound = TRUE;

		for (SIZE_T j = 0; j < PatternSize; j++)
		{
			bFound &= Mask[j] == '?' || BytePattern[j] == *((LPCSTR)BaseAddr + i + j);
		}

		if (bFound)
		{
			return (DWORD_PTR)(BaseAddr + i);
		}
	}

	return 0;
}

VOID
LogAPICall(
	_In_ LPCSTR FuncName,
	_In_ DWORD64 Argc,
	_In_ DWORD64* Params,
	_In_ DWORD64 ReturnValue
	)
{
	char* TempBuffer = calloc(MAX_STR_SIZE, 1);
	char FinalString[MAX_STR_SIZE] = { 0 };
	SIZE_T Size = MAX_STR_SIZE;

	snprintf(TempBuffer, Size, "- %s(", FuncName);
	strncat_s(FinalString, Size, TempBuffer, _TRUNCATE);

	//
	// Build the log entry string using the provided info (i.e. FuncName, Argc, Params, ReturnValue).
	//
	for (SIZE_T i = 0; i < Argc; i++)
	{
		DWORD64* Argv = ((DWORD64*)Params + i);

		//
		// Try to guess if the address is a string and if so, print it properly and if not, print as a hex value.
		//
		if (IsWideStr((BYTE*)*Argv))
		{
			LPCWSTR StrArg = (LPCWSTR)*Argv;
			if (wcslen((LPCWSTR)*Argv) > 2048)
			{
				StrArg = L"[string is too large]";
			}

			snprintf(TempBuffer, Size, "\"%ws\"", StrArg);
			strncat_s(FinalString, Size, TempBuffer, _TRUNCATE);
		}
		else
		{
			snprintf(TempBuffer, Size, "0x%llx", *Argv);
			strncat_s(FinalString, Size, TempBuffer, _TRUNCATE);
		}

		if (Argc > i + 1)
		{
			snprintf(TempBuffer, Size, ", ");
			strncat_s(FinalString, Size, TempBuffer, _TRUNCATE);
		}
	}

	snprintf(TempBuffer, Size, ") = 0x%llx (%d)", ReturnValue, (INT)ReturnValue);
	strncat_s(FinalString, Size, TempBuffer, _TRUNCATE);

	//
	// Print the final log entry string.
	//
	puts(FinalString);

	free(TempBuffer);
}

/*
* Since we are not using API signatures to know what is the type of each parameter we need to try to guess what it is.
* That's not good in general and handle these scenarios can be a pain. The implementation bellow is very bad but at
* least it works "ok" guessing if the provided address is a wide string or not.
*
* TODO: improve the function bellow.
*/
BOOL
IsWideStr(
	_In_ BYTE* Addr
	)
{
	if (!IsValidStrMem((LPCVOID)Addr))
	{
		return FALSE;
	}

	WORD RequiredLen = 6;

	for (SIZE_T i = 0; i < RequiredLen; i += 2)
	{
		if (Addr[i] > 0x7e || Addr[i] < 0x20 || Addr[i + 1] != '\0') 
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL
IsValidStrMem(
	_In_ LPCVOID Addr
	)
{
	if (!Addr)
	{
		return FALSE;
	}

	HANDLE hProcess = GetCurrentProcess();
	MEMORY_BASIC_INFORMATION Mbi = { 0 };

	if (!VirtualQueryEx(hProcess, Addr, &Mbi, sizeof(Mbi)))
	{
		PrintWinError("Failed to query virtual memory", GetLastError());
	}

	return Mbi.Protect == PAGE_READWRITE;
}

BOOL
IsSameStr(
	_In_ BYTE* Str1,
	_In_ BYTE* Str2
	)
{
	if (!Str1 || !Str2)
	{
		return FALSE;
	}

	SIZE_T StrLen1 = strlen(Str1);
	SIZE_T StrLen2 = strlen(Str2);

	if (StrLen1 != StrLen2)
	{
		return FALSE;
	}

	for (SIZE_T i = 0; i < StrLen1; i++)
	{
		char c1 = Str1[i];
		char c2 = Str2[i];

		c1 = tolower(c1);
		c2 = tolower(c2);

		if (c1 != c2)
		{
			return FALSE;
		}
	}

	return TRUE;
}

VOID
InitTargetFuncList()
{
	char ConfigFileFullPath[MAX_PATH] = { 0 };
	char CurrentModuleFilepath[MAX_PATH] = { 0 };

	DWORD Len = GetModuleFileNameA(GetModuleHandleA("gftrace.dll"), CurrentModuleFilepath, MAX_PATH);

	if (!Len)
	{
		PrintWinError("Failed to get the gftrace.dll module filepath", GetLastError());
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
		ConfigFileFullPath[i] = CurrentModuleFilepath[i];
		i++;
	} while (CurrentModuleFilepath[i] != '\0');

	LPCSTR ConfigFilename = "\\gftrace.cfg";

	SIZE_T ConfigFullPathSize = strlen(ConfigFileFullPath) + strlen(ConfigFilename) + 1;

	//
	// Build the gftrace.cfg full path.
	//
	strncat_s(ConfigFileFullPath, ConfigFullPathSize, ConfigFilename, _TRUNCATE);

	//
	// Check if the gftrace.cfg file exists in the expected directory.
	//
	if (GetFileAttributesA((LPCSTR)ConfigFileFullPath) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		PrintError("Failed to find the gftrace.cfg file in the current directory");
	}

	HANDLE hFile = CreateFileA(ConfigFileFullPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		PrintWinError("Failed to open the config file", GetLastError());
	}

	DWORD FileSizeHigh = 0;

	DWORD FileSize = GetFileSize(hFile, &FileSizeHigh);

	if (FileSize == INVALID_FILE_SIZE)
	{
		CloseHandle(hFile);
		PrintWinError("Failed to get config file size", GetLastError());
	}

	BYTE* FileContent = calloc(FileSize, 1);

	if (FileContent == NULL)
	{
		CloseHandle(hFile);
		PrintWinError("Failed to allocate memory for the config file content", GetLastError());
	}

	DWORD NumberOfBytesRead;

	if (!ReadFile(hFile, (LPVOID)FileContent, FileSize, &NumberOfBytesRead, NULL))
	{
		CloseHandle(hFile);
		PrintWinError("Failed to read the config file content", GetLastError());
	}

	NumberOfTargetFuncs = 0;

	//
	// Calculate the provided user list length.
	// 
	// TODO: improve the code bellow.
	//
	for (SIZE_T i = 0; i <= FileSize; i++)
	{
		if (FileContent[i] == ',' || i == FileSize)
		{
			NumberOfTargetFuncs++;
		}
	}

	SIZE_T ListSize = NumberOfTargetFuncs * sizeof(ASMSTDCALL_INFO);

	HANDLE hHeap = GetProcessHeap();

	if (hHeap == NULL)
	{
		CloseHandle(hFile);
		PrintWinError("Failed to get process heap", GetLastError());
	}

	//
	// Allocate memory for our global target function list.
	//
	TargetFuncsInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ListSize);

	if (TargetFuncsInfo == NULL)
	{
		CloseHandle(hFile);
		PrintWinError("Failed to allocate memory for the target function list", GetLastError());
	}

	LPCSTR TmpFuncName;
	SIZE_T j = 0;

	//
	// Go through the user-defined list and set each function name into our global function list.
	// 
	// TODO: improve the code bellow.
	//
	for (SIZE_T i = 0, x = 0; i <= FileSize; i++)
	{
		if (FileContent[i] == ',')
		{
			FileContent[i] = '\0';
			TmpFuncName = _strdup((LPCSTR)&FileContent[j]);

			if (TmpFuncName == NULL)
			{
				CloseHandle(hFile);
				PrintError("Failed to strdup API function name");
			}

			TargetFuncsInfo[x].Name = TmpFuncName;

			x++;
			j = i + 1;

			continue;
		}

		if (i == FileSize)
		{
			FileContent[i] = '\0';
			TmpFuncName = _strdup((LPCSTR)&FileContent[j]);

			if (TmpFuncName == NULL)
			{
				CloseHandle(hFile);
				PrintError("Failed to strdup API function name");
			}

			TargetFuncsInfo[x].Name = TmpFuncName;

			break;
		}
	}

	CloseHandle(hFile);
}

VOID
ResolveTargetFuncListAddresses()
{
	//
	// Go through each function name in our global list, resolve it's export address and add it to the list.
	//
	for (SIZE_T i = 0; i < NumberOfTargetFuncs; i++)
	{
		FARPROC ExportAddr = GetExportAddr(TargetFuncsInfo[i].Name);
		TargetFuncsInfo[i].Addr = ExportAddr;
	}
}