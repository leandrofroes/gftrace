#include "pe.h"
#include "utils.h"

PIMAGE_NT_HEADERS64
GetNtHeader(
	_In_ DWORD_PTR ModuleBase
	)
{
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ModuleBase;

	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PrintError("The target process has an invalid DOS Signare");
	}

	PIMAGE_NT_HEADERS64 NtHeader = (IMAGE_NT_HEADERS64*)(ModuleBase + DosHeader->e_lfanew);

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		PrintError("The target process has an invalid PE Signare");
	}

	return NtHeader;
}

PIMAGE_NT_HEADERS32
GetNtHeader32(
	_In_ DWORD_PTR ModuleBase
	)
{
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ModuleBase;

	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PrintError("The target process has an invalid DOS Signare");
	}

	PIMAGE_NT_HEADERS32 NtHeader = (IMAGE_NT_HEADERS32*)(ModuleBase + DosHeader->e_lfanew);

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		PrintError("The target process has an invalid PE Signare");
	}

	return NtHeader;
}

PIMAGE_EXPORT_DIRECTORY
GetExportDirectory(
	_In_ DWORD_PTR ModuleBase
	)
{
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 NtHeader = GetNtHeader(ModuleBase);
	IMAGE_OPTIONAL_HEADER64 OptHeader = NtHeader->OptionalHeader;
#else
	PIMAGE_NT_HEADERS32 NtHeader = GetNtHeader32(ModuleBase);
	IMAGE_OPTIONAL_HEADER32 OptHeader = NtHeader->OptionalHeader;
#endif

	IMAGE_DATA_DIRECTORY ExportDataDir = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	DWORD ExportDirRva = ExportDataDir.VirtualAddress;

	if (!ExportDirRva)
	{
		return NULL;
	}

	return (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + ExportDirRva);
}

PIMAGE_IMPORT_DESCRIPTOR
GetImportDesc(
	_In_ DWORD_PTR ModuleBase
	)
{
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 NtHeader = GetNtHeader(ModuleBase);
	IMAGE_OPTIONAL_HEADER64 OptHeader = NtHeader->OptionalHeader;
#else
	PIMAGE_NT_HEADERS32 NtHeader = GetNtHeader32(ModuleBase);
	IMAGE_OPTIONAL_HEADER32 OptHeader = NtHeader->OptionalHeader;
#endif

	IMAGE_DATA_DIRECTORY ImportDataDir = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD ImportDirRva = ImportDataDir.VirtualAddress;

	if (!ImportDirRva)
	{
		return NULL;
	}

	return (PIMAGE_IMPORT_DESCRIPTOR)(ModuleBase + ImportDirRva);
}

PIMAGE_SECTION_HEADER
GetSectionHeader(
	_In_ DWORD_PTR ModuleBase,
	_In_ BYTE* SectionName
	)
{
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 NtHeader = GetNtHeader(ModuleBase);
#else
	PIMAGE_NT_HEADERS32 NtHeader = GetNtHeader32(ModuleBase);
#endif

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(NtHeader);
	DWORD NumberOfSections = NtHeader->FileHeader.NumberOfSections;

	if (NumberOfSections == 0)
	{
		PrintError("The number of sections of the target process is zero");
	}

	for (SIZE_T i = 0; i < NumberOfSections; i++)
	{
		if (IsSameStr((BYTE*)pSection->Name, SectionName))
		{
			return pSection;
		}

		pSection++;
	}

	return NULL;
}

FARPROC
GetExportAddr(
	_In_ LPCSTR ExportName
	)
{
#ifdef _WIN64
	PPEB Peb = (PPEB)__readgsqword(0x60);
#else
	PPEB Peb = (PPEB)__readfsdword(0x30);
#endif

	PLDR_DATA_TABLE_ENTRY CurrentModule = NULL;
	PLIST_ENTRY CurrentEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
	FARPROC ExportAddr;

	//
	// Go through each loaded module and try to find the target export address using the given export name.
	//
	while (CurrentEntry != &Peb->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		CurrentModule = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ExportAddr = ResolveExportAddr((DWORD_PTR)CurrentModule->DllBase, ExportName);

		if (ExportAddr != NULL)
		{
			return ExportAddr;
		}

		CurrentEntry = CurrentEntry->Flink;
	}

	return NULL;
}

FARPROC
ResolveExportAddr(
	_In_ DWORD_PTR ModuleBase,
	_In_ LPCSTR ExportName
	)
{
	PIMAGE_EXPORT_DIRECTORY ExportDir = GetExportDirectory(ModuleBase);

	if (ExportDir == NULL)
	{
		return NULL;
	}

	DWORD AddressOfNameRva = ExportDir->AddressOfNames;
	DWORD NumberOfNames = ExportDir->NumberOfNames;
	DWORD AddressOfNameOrdinals = ExportDir->AddressOfNameOrdinals;
	DWORD AddressOfFunctions = ExportDir->AddressOfFunctions;

	for (SIZE_T i = 0; i < NumberOfNames; i++)
	{
		DWORD NameRva = *(DWORD*)(ModuleBase + AddressOfNameRva + i * sizeof(DWORD));
		WORD OrdinalRva = *(WORD*)(ModuleBase + AddressOfNameOrdinals + i * sizeof(WORD));
		LPCSTR Name = (LPCSTR)(ModuleBase + NameRva);

		if (IsSameStr((BYTE*)ExportName, (BYTE*)Name))
		{
			DWORD ExportRva = *(DWORD*)(ModuleBase + AddressOfFunctions + OrdinalRva * sizeof(DWORD));

			return (FARPROC)(ModuleBase + ExportRva);
		}
	}

	return NULL;
}

LPCSTR
GetImportName(
	_In_ FARPROC ImportAddr
	)
{
	HMODULE ModuleBase = GetModuleHandle(NULL);
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = GetImportDesc((DWORD_PTR)ModuleBase);

	if (ImportDesc == NULL)
	{
		return NULL;
	}

	PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)ModuleBase + ImportDesc->OriginalFirstThunk);
	PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)ModuleBase + ImportDesc->FirstThunk);

	SIZE_T i = 0;

	while (ImportDesc[i++].OriginalFirstThunk)
	{
		while (OriginalFirstThunk->u1.Function)
		{
			if (!memcmp(&FirstThunk->u1.Function, ImportAddr, sizeof(FARPROC)))
			{
				PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)ModuleBase + OriginalFirstThunk->u1.AddressOfData);
				return (LPCSTR)ImportName->Name;
			}
			OriginalFirstThunk++;
			FirstThunk++;
		}
	}

	return NULL;
}

BOOL
HasImport(
	_In_ FARPROC ImportAddr
	)
{
	HMODULE ModuleBase = GetModuleHandleW(NULL);
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = GetImportDesc((DWORD_PTR)ModuleBase);

	if (ImportDesc == NULL)
	{
		return FALSE;
	}

	PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)ModuleBase + ImportDesc->FirstThunk);

	SIZE_T i = 0;

	while (ImportDesc[i++].FirstThunk)
	{
		while (FirstThunk->u1.Function)
		{
			if (!memcmp(&FirstThunk->u1.Function, ImportAddr, sizeof(FARPROC)))
			{
				return TRUE;
			}
			FirstThunk++;
		}
	}

	return FALSE;
}