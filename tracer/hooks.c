#include "hooks.h"
#include "utils.h"
#include "pe.h"

bIsReadyToLog = FALSE;

LPVOID
PerformHook(
	_In_ ULONG_PTR Src,
	_In_ ULONG_PTR Dest,
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
	// Change the memory permission of the region we want to modify the bytes.
	//
	if (!VirtualProtect((LPVOID)Src, Len, PAGE_EXECUTE_READWRITE, &OldProtection))
	{
		PrintWinError("Failed setting the hook memory region protection", GetLastError());
	}

	//
	// Write the HookBytes array with the correct dest address into the target address.
	//
	*(ULONG_PTR*)(HookBytes + 2) = Dest;
	RtlCopyMemory((LPVOID)Src, (LPCVOID)HookBytes, sizeof(HookBytes));

	//
	// NOP the remaining hook bytes to make sure the instructions will be properly aligned.
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
	return (LPVOID)(Src + Len);
}

LPVOID
PerformHook32(
	_In_ ULONG_PTR Src,
	_In_ ULONG_PTR Dest,
	_In_ SIZE_T Len
)
{
	DWORD HookBytesLen = 5;
	DWORD OldProtection;

	//
	// Change the memory permission of the region we want to modify the bytes.
	//
	if (!VirtualProtect((LPVOID)Src, Len, PAGE_READWRITE, &OldProtection))
	{
		PrintWinError("Failed setting the hook memory region protection", GetLastError());
	}

	ULONG_PTR RelativeAddr = (Dest - Src) - 5;

	//
	// Write the "jmp <address>" bytes into the target address.
	//
	*(BYTE*)Src = 0xE9; // JMP
	*(ULONG_PTR*)(Src + 1) = RelativeAddr;

	//
	// NOP the remaining hook bytes to make sure the instructions will be properly aligned.
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
	return (LPVOID)(Src + Len);
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
	PIMAGE_SECTION_HEADER SectionHeader = GetSectionHeader((ULONG_PTR)GolangModuleBase, (BYTE*)".text");

	if (SectionHeader == NULL)
	{
		PrintError("Failed to get a pointer to the Golang module .text section");
	}

	//
	// Get the size of the .text section of the Golang module.
	//
	SIZE_T SectionSize = (SIZE_T)SectionHeader->Misc.VirtualSize;

	if (!SectionSize)
	{
		PrintError("Golang module .text section size is zero");
	}

#ifdef _WIN64
	//
	// https://github.com/golang/go/blob/master/src/runtime/sys_windows_amd64.s#L15
	// 
	CHAR TargetAddrPattern[] = {
		0x65, 0x48, 0x8B, 0x3C, 0x25, 0x30, 0x00, 0x00, 0x00, // mov rdi, qword ptr gs:[0x30]
		0x8B, 0x47, 0x68,                                     // mov eax, dword ptr ds:[rdi+0x68]
		0x48, 0x89, 0x41, 0x28                               // mov qword ptr ds:[rcx+0x28], rax
	};

	LPCSTR Mask = "xxxxxxxxxxxxxxxx";
	SIZE_T NumberOfBytesToHook = 0x10;
#else
	//
	// https://github.com/golang/go/blob/master/src/runtime/sys_windows_386.s#L14
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
	ULONG_PTR HookAddr = FindPattern((ULONG_PTR)GolangModuleBase, SectionSize, (LPCSTR)TargetAddrPattern, Mask);

	if (!HookAddr)
	{
		PrintError("Failed to find Asmstdcall code pattern");
	}

	//
	// Perform a mid function hook and set the address to jump back when the hooking function execution is done.
	//
#ifdef _WIN64
	JmpBackAddr = PerformHook((ULONG_PTR)HookAddr, (ULONG_PTR)AsmstdcallStub, NumberOfBytesToHook);
#else
	JmpBackAddr = PerformHook32((ULONG_PTR)HookAddr, (ULONG_PTR)AsmstdcallStub, NumberOfBytesToHook);
#endif
}

VOID
hk_Asmstdcall(
	_In_ PLIBCALL Frame
)
{
	//
	// Request the ownership of the critical section.
	//
	EnterCriticalSection(&CriticalSection);

	//
	// Get the address of the current Windows API function to be called by asmstdcall.
	//
	ULONG_PTR FuncAddr = Frame->FuncAddr;

	//
	// Make sure we avoid the IAT entries not set by the user.
	//
	for (SIZE_T i = 0; i < NumberOfIATEntries; i++)
	{
		if (FuncAddr == IatInfo[i].Addr && !IatInfo[i].IsAllowedToLog)
		{
			goto Exit;
		}
	}

	//
	// Check if we are ready to start to log the API calls to the user.
	//
	if (bIsReadyToLog)
	{
		ULONG_PTR Params = Frame->Argv;
		ULONG_PTR ReturnValue = Frame->ReturnValue;

		//
		// Make sure we also trace API functions resolved after the Go runtime initialization.
		//
		if (FuncAddr == (ULONG_PTR)pGetProcAddress)
		{
			//
			// Get the second parameter passed to GetProcAddress() function (i.e. lpProcName).
			//
			LPCSTR FuncName = (LPCSTR)(Params + 1);

			//
			// Go through our target function list and check if the function address resolved by GetProcAddress 
			// is in our list and if not, add it.
			//
			for (SIZE_T i = 0; i < NumberOfTargetFuncs; i++)
			{
				if (!strncmp(TargetFuncsInfo[i].Name, FuncName, strlen(FuncName) + 1) && TargetFuncsInfo[i].Addr == NULL)
				{
					TargetFuncsInfo[i].Addr = (FARPROC)ReturnValue;
				}
			}
		}

		//
		// Check if the instructions in the received address is a JMP. If that's the case probably we are in a jump table.
		// Programs compiled with cgo/gcc usually would have this table containing a JMP to the real IAT entry so we need to handle these cases.
		// 
		// The JMP could be the IAT address address directly (x86) or an offset based on the current address (x64) hence we need to check our arch.
		//
		if (*(BYTE*)FuncAddr == 0xFF && *((BYTE*)FuncAddr + 1) == 0x25)
		{

#ifdef _WIN64
			DWORD offset = *(DWORD*)(FuncAddr + 2);
			FARPROC RealFuncEntry = *(FARPROC)(FuncAddr + offset + 6);
#else
			FARPROC RealFuncEntry = *(FARPROC)(FuncAddr + 2);
#endif
			if (RealFuncEntry)
			{
				BOOL bFuncFound = FALSE;

				//
				// Check if the function address is present in the IAT to make sure we get the correct address.
				//
				if (HasImport(RealFuncEntry))
				{
					//
					// Get the name of the imported function using it's IAT address.
					//
					LPCSTR FuncName = GetImportName(RealFuncEntry);

					if (FuncName != NULL)
					{
						for (SIZE_T i = 0; i < NumberOfTargetFuncs; i++)
						{
							if (!strncmp(TargetFuncsInfo[i].Name, FuncName, strlen(FuncName) + 1))
							{
								TargetFuncsInfo[i].Addr = (FARPROC)FuncAddr;
								bFuncFound = TRUE;
								break;
							}
						}

						for (SIZE_T i = 0; i < NumberOfIATEntries; i++)
						{
							if (!IatInfo[i].Addr)
							{
								if (bFuncFound)
								{
									IatInfo[i].IsAllowedToLog = TRUE;
								}

								IatInfo[i].Addr = FuncAddr;
								break;
							}
						}
					}
				}
			}
		}

		//
		// Go through our target function list and check if the function called by Asmstdcall is wanted and if so, log it to the user.
		//
		for (SIZE_T i = 0; i < NumberOfTargetFuncs; i++)
		{
			FARPROC WantedFuncAddr = TargetFuncsInfo[i].Addr;

			if (WantedFuncAddr)
			{
				if (FuncAddr == (ULONG_PTR)WantedFuncAddr)
				{
					if (!strcmp(TargetFuncsInfo[i].Name, "GetProcAddress"))
					{
						//
						// Since this is a special case we have a function to print it.
						//
						LogGetProcAddressCall(Params, (FARPROC)ReturnValue);
					}
					else
					{
						DWORD Argc = Frame->Argc;
						LogAPICall(TargetFuncsInfo[i].Name, Argc, Params, (DWORD)ReturnValue);
					}
				}
			}
		}
	}

	//
	// Check if we should start to log the API calls by checking if the function called by Asmstdcall is GetCommandLineW().
	// This function is part of the "os" package initialization and is called before the main package so we use it as a sentinel. 
	// 
	//
	if (FuncAddr == (ULONG_PTR)pGetCommandLineW && !bIsReadyToLog)
	{
		bIsReadyToLog = TRUE;

		//
		// Resolve the address of the user-defined functions to trace and fills our TargetFuncInfo global list.
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

Exit:

	//
	// Release ownership of the critical section.
	//
	LeaveCriticalSection(&CriticalSection);
}