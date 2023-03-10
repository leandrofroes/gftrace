#include "hooks.h"
#include "utils.h"
#include "pe.h"

IsReadyToLog = FALSE;

LPVOID
PerformHook(
	_In_ BYTE* Src,
	_In_ BYTE* Dest,
	_In_ SIZE_T Len
	)
{
	CHAR HookBytes[] = {
		0x49, 0xbb, 0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf, // mov r11, <target_addr>
		0x41, 0xff, 0xe3,                                   // jmp r11
	};

	DWORD HookBytesLen = 13;
	DWORD OldProtection;

	//
	// Change memory permission of the region we want to modify the bytes.
	//
	if (!VirtualProtect((LPVOID)Src, Len, PAGE_EXECUTE_READWRITE, &OldProtection))
	{
		PrintWinError("Failed setting the hook memory region protection", GetLastError());
	}

	//
	// Write the HookBytes array with the correct dest address into the target address.
	//
	*(DWORD_PTR *)(HookBytes + 2) = Dest;
	memcpy((LPVOID)Src, (LPCVOID)HookBytes, sizeof(HookBytes));

	//
	// NOP the remaining hook bytes to make sure the instructions will be aligned.
	//
	for (SIZE_T i = HookBytesLen; i < Len; i++)
	{
		*(Src + i) = 0x90;
	}

	//
	// Restore the hook memory region permissions.
	//
	if (!VirtualProtect((LPVOID)Src, Len, OldProtection, &OldProtection))
	{
		PrintWinError("Failed setting the old memory protection", GetLastError());
	}

	//
	// Return the jump back address (i.e. the address to return after our hook is executed). 
	//
	return (LPVOID)((DWORD)Src + Len);
}

LPVOID
PerformHook32(
	_In_ BYTE* Src,
	_In_ BYTE* Dest,
	_In_ SIZE_T Len
	)
{
	DWORD HookBytesLen = 5;
	DWORD OldProtection;

	//
	// Change memory permission of the region we want to modify the bytes.
	//
	if (!VirtualProtect((LPVOID)Src, Len, PAGE_READWRITE, &OldProtection))
	{
		PrintWinError("Failed setting the hook memory region protection", GetLastError());
	}

	DWORD RelativeAddr = (DWORD)((DWORD)Dest - (DWORD)Src) - 5;

	//
	// Write the jmp <address> bytes into the target address.
	//
	*Src = 0xE9; // JMP
	*(DWORD_PTR*)(Src + 1) = RelativeAddr;

	//
	// NOP the remaining hook bytes to make sure the instructions will be aligned.
	//
	for (SIZE_T i = HookBytesLen; i < Len; i++)
	{
		*((BYTE*)Src + i) = 0x90;
	}

	//
	// Restore the hook memory region permissions.
	//
	if (!VirtualProtect((LPVOID)Src, Len, OldProtection, &OldProtection))
	{
		PrintWinError("Failed setting the old memory protection", GetLastError());
	}

	//
	// Return the jump back address (i.e. the address to return after our hook is executed). 
	//
	return (LPVOID)((DWORD)Src + Len);
}

VOID
HookAsmstdcall()
{
	//
	// Get the base address of the Golang module the gftrace DLL is injected into.
	//
	HMODULE GolangModuleBase = GetModuleHandleW(NULL);

	if (GolangModuleBase == NULL)
	{
		PrintWinError("Failed to get the Golang module base address", GetLastError());
	}

	//
	// Get the .text section header of the Golang module.
	//
	PIMAGE_SECTION_HEADER SectionHeader = GetSectionHeader((DWORD_PTR)GolangModuleBase, (BYTE*)".text");

	if (SectionHeader == NULL)
	{
		PrintError("Failed to get a pointer to the Golang module .text section");
	}

	//
	// Get the size of the .text section of the Golang module.
	//
	SIZE_T SectionSize = (SIZE_T)SectionHeader->Misc.VirtualSize;

	if (SectionSize == 0)
	{
		PrintError("Golang module .text section size is zero");
	}

#ifdef _WIN64
	//
	// https://github.com/golang/go/blob/da564d0006e2cc286fecb3cec94ed143a2667866/src/runtime/sys_windows_amd64.s#L15
	// 
	CHAR TargetAddrPattern[] = {
		0x65, 0x48, 0x8B, 0x3C, 0x25, 0x30, 0x00, 0x00, 0x00, // mov rdi, qword ptr gs:[0x30]
		0x8B, 0x47, 0x68,                                     // mov eax, dword ptr ds:[rdi+0x68]
		0x48, 0x89, 0x41, 0x28,                               // mov qword ptr ds:[rcx+0x28], rax
		0xC3                                                  // ret
	};

	LPCSTR Mask = "xxxxxxxxxxxxxxxxx";
	SIZE_T NumberOfBytesToHook = 0x10;
#else
	//
	// https://github.com/golang/go/blob/da564d0006e2cc286fecb3cec94ed143a2667866/src/runtime/sys_windows_386.s#L11
	// 
	CHAR TargetAddrPattern[] = {
		0x64, 0x8B, 0x05, 0x34, 0x00, 0x00, 0x00,	// mov eax, dword ptr fs:[0x34]
		0x89, 0x43, 0x14,							// mov dword ptr ds:[ebx+0x14], eax
		0xC3										// ret
};

	LPCSTR Mask = "xxxxxxxxxxx";
	SIZE_T NumberOfBytesToHook = 0x7;
#endif

	//
	// Attempt to find the target address we want to hook inside Asmstdcall function.
	//
	DWORD_PTR HookAddr = FindPattern((DWORD_PTR)GolangModuleBase, SectionSize, (LPCSTR)TargetAddrPattern, Mask);

	if (!HookAddr)
	{
		PrintError("Failed to find Asmstdcall code pattern");
	}

	//
	// Perform a mid function hook and sets the address to jump back when the hooking function execution is done.
	//
#ifdef _WIN64
	JmpBackAddr = PerformHook((BYTE*)HookAddr, (BYTE*)AsmstdcallStub, NumberOfBytesToHook);
#else
	JmpBackAddr = PerformHook32((BYTE*)HookAddr, (BYTE*)AsmstdcallStub, NumberOfBytesToHook);
#endif
}

VOID
hk_Asmstdcall(
	_In_ LPVOID Cx
	)
{
	//
	// Request the ownership of the critical section.
	//
	EnterCriticalSection(&CriticalSection);

	//
	// Get the address of the current Windows API function to be called by asmstdcall.
	//
	FARPROC FuncAddr = (FARPROC)*(DWORD_PTR*)Cx;

	//
	// Check if we are ready to start to log the API calls to the user.
	//
	if (IsReadyToLog)
	{
		DWORD_PTR FuncParams = (DWORD_PTR)*((DWORD_PTR*)Cx + 2);
		DWORD ReturnValue = (DWORD)*((DWORD_PTR*)Cx + 3);

		//
		// Make sure we also trace API functions resolved after the Golang runtime initialization.
		//
		if (FuncAddr == pGetProcAddress)
		{
			//
			// Get the second parameter passed to GetProcAddress() (lpProcName).
			//
			LPCSTR FuncName = (LPCSTR)(FuncParams + 1);

			//
			// Go through our target function list and check if the function address resolved by GetProcAddress 
			// is in our list and if not, add it.
			//
			for (SIZE_T i = 0; i < NumberOfTargetFuncs; i++)
			{
				if (!strcmp(TargetFuncsInfo[i].Name, FuncName) && TargetFuncsInfo[i].Addr == NULL)
				{
					TargetFuncsInfo[i].Addr = (FARPROC)ReturnValue;
				}
			}
		}

		//
		// Go through our target function list and check if the function called by Asmstdcall is wanted and if so, log it to the user.
		//
		for (SIZE_T i = 0; i < NumberOfTargetFuncs; i++)
		{
			FARPROC WantedFuncAddr = TargetFuncsInfo[i].Addr;

			if (FuncAddr == WantedFuncAddr)
			{
				DWORD FuncArgc = (DWORD)*((DWORD_PTR*)Cx + 1);
				LogAPICall(TargetFuncsInfo[i].Name, FuncArgc, FuncParams, ReturnValue);
			}
		}
	}

	//
	// Check if we should start to log the API calls by checking if the function called by Asmstdcall is GetCommandLineW().
	// Seems this function is part of the Golang "os" package initialization and is called before the main so we use it as a sentinel. 
	// 
	// TODO: If the binary doesn't use the "os" package it might not work so we need to find something more reliable.
	//
	if (FuncAddr == pGetCommandLineW && !IsReadyToLog)
	{
		IsReadyToLog = TRUE;

		//
		// Resolve the addresses of the user-defined functions to trace and fills our TargetFuncInfo global list.
		//
		ResolveTargetFuncListAddresses();

		//
		// Attempt to create a console in case we are injected into a GUI application.
		//
		if (AllocConsole())
		{
			FILE* fp = NULL;
			freopen_s(&fp, "CONOUT$", "w", stdout);
			SetConsoleTitle(TEXT("gftrace"));
		}

		//
		// Just some new line chars to make the output cleaner.
		//
		printf("\n\n");
	}

	//
	// Release ownership of the critical section.
	//
	LeaveCriticalSection(&CriticalSection);
}