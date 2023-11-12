# gftrace

A command line Windows API tracing tool for Golang binaries.

**Note:** This tool is a PoC and a work-in-progress prototype so please treat it as such. Feedbacks are always welcome!

## **How it works?**

Although Golang programs contains a lot of nuances regarding the way they are built and their behavior in runtime they still need to interact with the OS layer and that means at some point they do need to call functions from the Windows API.

The Go runtime package contains a function called [asmstdcall](https://github.com/golang/go/blob/master/src/runtime/sys_windows_amd64.s#L20) and this function is a kind of "gateway" used to interact with the Windows API. Since it's expected this function to call the Windows API functions we can assume it needs to have access to information such as the address of the function and it's parameters, and this is where things start to get more interesting.

Asmstdcall receives a single parameter which is pointer to something similar to the following structure:

```
struct LIBCALL {
	DWORD_PTR Addr;
	DWORD Argc;
	DWORD_PTR Argv;
	DWORD_PTR ReturnValue;
	
	[...]
}
```

Some of these fields are filled after the API function is called, like the return value, others are received by asmstdcall, like the function address, the number of arguments and the list of arguments. Regardless when those are set it's clear that the asmstdcall function manipulates a lot of interesting information regarding the execution of programs compiled in Golang.

The gftrace leverages asmstdcall and the way it works to monitor specific fields of the mentioned struct and log it to the user. The tool is capable of log the function name, it's parameters and also the return value of each Windows function called by a Golang application. All of it with no need to hook a single API function or have a signature for it.

The tool also tries to ignore all the noise from the Go runtime initialization and only log functions called after it (i.e. functions from the main package).

If you want to know more about this project and research check the [blogpost](https://leandrofroes.github.io/posts/An-in-depth-look-at-Golang-Windows-calls/).

## **Installation**

Download the latest [release](https://github.com/leandrofroes/gftrace/releases).

## **Usage**

1. Make sure gftrace.exe, gftrace.dll and gftrace.cfg are in the same directory.
2. Specify which API functions you want to trace in the gftrace.cfg file (the tool does not work without API filters applied).
3. Run gftrace.exe passing the target Golang program path as a parameter.

```
gftrace.exe <filepath> <params>
```

## **Configuration**

All you need to do is specify which functions you want to trace in the gftrace.cfg file, separating it by comma with no spaces:

```
CreateFileW,ReadFile,CreateProcessW
```

The exact Windows API functions a Golang method X of a package Y would call in a specific scenario can only be determined either by analysis of the method itself or trying to guess it. There's some interesting characteristics that can be used to determine it, for example, Golang applications seems to always prefer to call functions from the "Wide" and "Ex" set (e.g. CreateFileW, CreateProcessW, GetComputerNameExW, etc) so you can consider it during your analysis.

The default config file contains multiple functions in which I tested already (at least most part of them) and can say for sure they can be called by a Golang application at some point. I'll try to update it eventually.

## **Examples**

Tracing CreateFileW() and ReadFile() in a simple Golang file that calls "os.ReadFile" twice:

```
- CreateFileW("C:\Users\user\Desktop\doc.txt", 0x80000000, 0x3, 0x0, 0x3, 0x1, 0x0) = 0x168 (360)
- ReadFile(0x168, 0xc000108000, 0x200, 0xc000075d64, 0x0) = 0x1 (1)
- CreateFileW("C:\Users\user\Desktop\doc2.txt", 0x80000000, 0x3, 0x0, 0x3, 0x1, 0x0) = 0x168 (360)
- ReadFile(0x168, 0xc000108200, 0x200, 0xc000075d64, 0x0) = 0x1 (1)
```

Tracing CreateProcessW() in the TunnelFish malware:

```
- CreateProcessW("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell /c "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-Recipient | Select Name -ExpandProperty EmailAddresses -first 1 | Select SmtpAddress |  ft -hidetableheaders"", 0x0, 0x0, 0x1, 0x80400, "=C:=C:\Users\user\Desktop", 0x0, 0xc0000ace98, 0xc0000acd68) = 0x1 (1)
- CreateProcessW("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell /c "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-Recipient | Select Name -ExpandProperty EmailAddresses -first 1 | Select SmtpAddress |  ft -hidetableheaders"", 0x0, 0x0, 0x1, 0x80400, "=C:=C:\Users\user\Desktop", 0x0, 0xc0000c4ec8, 0xc0000c4d98) = 0x1 (1)
- CreateProcessW("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell /c "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-Recipient | Select Name -ExpandProperty EmailAddresses -first 1 | Select SmtpAddress |  ft -hidetableheaders"", 0x0, 0x0, 0x1, 0x80400, "=C:=C:\Users\user\Desktop", 0x0, 0xc00005eec8, 0xc00005ed98) = 0x1 (1)
- CreateProcessW("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell /c "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-Recipient | Select Name -ExpandProperty EmailAddresses -first 1 | Select SmtpAddress |  ft -hidetableheaders"", 0x0, 0x0, 0x1, 0x80400, "=C:=C:\Users\user\Desktop", 0x0, 0xc0000bce98, 0xc0000bcd68) = 0x1 (1)
- CreateProcessW("C:\WINDOWS\system32\cmd.exe", "cmd /c "wmic computersystem get domain"", 0x0, 0x0, 0x1, 0x80400, "=C:=C:\Users\user\Desktop", 0x0, 0xc0000c4ef0, 0xc0000c4dc0) = 0x1 (1)
- CreateProcessW("C:\WINDOWS\system32\cmd.exe", "cmd /c "wmic computersystem get domain"", 0x0, 0x0, 0x1, 0x80400, "=C:=C:\Users\user\Desktop", 0x0, 0xc0000acec0, 0xc0000acd90) = 0x1 (1)
- CreateProcessW("C:\WINDOWS\system32\cmd.exe", "cmd /c "wmic computersystem get domain"", 0x0, 0x0, 0x1, 0x80400, "=C:=C:\Users\user\Desktop", 0x0, 0xc0000bcec0, 0xc0000bcd90) = 0x1 (1)

[...]
```

Tracing multiple functions in the Sunshuttle malware:

```
- CreateFileW("config.dat.tmp", 0x80000000, 0x3, 0x0, 0x3, 0x1, 0x0) = 0xffffffffffffffff (-1)
- CreateFileW("config.dat.tmp", 0xc0000000, 0x3, 0x0, 0x2, 0x80, 0x0) = 0x198 (408)
- CreateFileW("config.dat.tmp", 0xc0000000, 0x3, 0x0, 0x3, 0x80, 0x0) = 0x1a4 (420)
- WriteFile(0x1a4, 0xc000112780, 0xeb, 0xc0000c79d4, 0x0) = 0x1 (1)
- GetAddrInfoW("reyweb.com", 0x0, 0xc000031f18, 0xc000031e88) = 0x0 (0)
- WSASocketW(0x2, 0x1, 0x0, 0x0, 0x0, 0x81) = 0x1f0 (496)
- WSASend(0x1f0, 0xc00004f038, 0x1, 0xc00004f020, 0x0, 0xc00004eff0, 0x0) = 0x0 (0)
- WSARecv(0x1f0, 0xc00004ef60, 0x1, 0xc00004ef48, 0xc00004efd0, 0xc00004ef18, 0x0) = 0xffffffff (-1)
- GetAddrInfoW("reyweb.com", 0x0, 0xc000031f18, 0xc000031e88) = 0x0 (0)
- WSASocketW(0x2, 0x1, 0x0, 0x0, 0x0, 0x81) = 0x200 (512)
- WSASend(0x200, 0xc00004f2b8, 0x1, 0xc00004f2a0, 0x0, 0xc00004f270, 0x0) = 0x0 (0)
- WSARecv(0x200, 0xc00004f1e0, 0x1, 0xc00004f1c8, 0xc00004f250, 0xc00004f198, 0x0) = 0xffffffff (-1)

[...]
```

Tracing multiple functions in the DeimosC2 framework agent:

```
- WSASocketW(0x2, 0x1, 0x0, 0x0, 0x0, 0x81) = 0x130 (304)
- setsockopt(0x130, 0xffff, 0x20, 0xc0000b7838, 0x4) = 0xffffffff (-1)
- socket(0x2, 0x1, 0x6) = 0x138 (312)
- WSAIoctl(0x138, 0xc8000006, 0xaf0870, 0x10, 0xb38730, 0x8, 0xc0000b746c, 0x0, 0x0) = 0x0 (0)
- GetModuleFileNameW(0x0, "C:\Users\user\Desktop\samples\deimos.exe", 0x400) = 0x2f (47)
- GetUserProfileDirectoryW(0x140, "C:\Users\user", 0xc0000b7a08) = 0x1 (1)
- LookupAccountSidw(0x0, 0xc00000e250, "user", 0xc0000b796c, "DESKTOP-TEST", 0xc0000b7970, 0xc0000b79f0) = 0x1 (1)
- NetUserGetInfo("DESKTOP-TEST", "user", 0xa, 0xc0000b7930) = 0x0 (0)
- GetComputerNameExW(0x5, "DESKTOP-TEST", 0xc0000b7b78) = 0x1 (1)
- GetAdaptersAddresses(0x0, 0x10, 0x0, 0xc000120000, 0xc0000b79d0) = 0x0 (0)
- CreateToolhelp32Snapshot(0x2, 0x0) = 0x1b8 (440)
- GetCurrentProcessId() = 0x2584 (9604)
- GetCurrentDirectoryW(0x12c, "C:\Users\user\AppData\Local\Programs\retoolkit\bin") = 0x39 (57)

[...]
```

## **Future features:**

- [x] Support inspection of 32 bits files.
- [x] Add support to files calling functions via the "IAT jmp table" instead of the API call directly in asmstdcall.
- [x] Add support to cmdline parameters for the target process
- [ ] Send the tracing log output to a file by default to make it better to filter. Currently there's no separation between the target file and gftrace output. An alternative is redirect gftrace output to a file using the command line.

## :warning: **Warning**

* The tool inspects the target binary dynamically and it means the file being traced is executed. If you're inspecting a malware or an unknown software please make sure you do it in a controlled environment.
* Golang programs can be very noisy depending the file and/or function being traced (e.g. VirtualAlloc is always called multiple times by the runtime package, CreateFileW is called multiple times before a call to CreateProcessW, etc). The tool ignores the Golang runtime initialization noise but after that it's up to the user to decide what functions are better to filter in each scenario.

## **License**

The gftrace is published under the GPL v3 License. Please refer to the file named LICENSE for more information.
