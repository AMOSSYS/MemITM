#include <Windows.h>
#include <stdio.h>

/*
    BUILD INSTRUCTIONS : don't forget /EHa and /MTd flags
*/

int inject(ULONG dwPid, PWCHAR dllPath)
{

    HANDLE hHandle;
    void* lpRemoteString;
    wchar_t szPath[MAX_PATH];

    hHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwPid);
    if (hHandle == NULL)
    {
        void* lpBuffer;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            ::GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
            (LPTSTR)&lpBuffer,
            0,
            NULL);
        printf("OpenProcess error: %S\n", (LPCTSTR)lpBuffer);
        LocalFree(lpBuffer);
    }

    lpRemoteString = VirtualAllocEx(hHandle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpRemoteString == NULL)
    {
        void* lpBuffer;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            ::GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
            (LPTSTR)&lpBuffer,
            0,
            NULL);
        printf("VirtualAllocEx error: %S\n", (LPCTSTR)lpBuffer);
        LocalFree(lpBuffer);
    }
    GetCurrentDirectory(sizeof(szPath), szPath);
    wcscat_s(szPath, dllPath);
    WriteProcessMemory(hHandle, lpRemoteString, (void*)szPath, sizeof(szPath) * 2, NULL);

    HANDLE hThread = CreateRemoteThread(hHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, lpRemoteString, 0, NULL);
    if (hThread == NULL)
    {
        void* lpBuffer;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            ::GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
            (LPTSTR)&lpBuffer,
            0,
            NULL);
        printf("CreateRemoteThread error: %S\n",(LPCTSTR)lpBuffer);
        LocalFree(lpBuffer);
    }

    WaitForSingleObject(hThread, INFINITE);
    DWORD dwModule;
    GetExitCodeThread(hThread, &dwModule);
    CloseHandle(hThread);
    VirtualFreeEx(hHandle, lpRemoteString, 0, MEM_FREE);

    CloseHandle(hHandle);
    return 0;
}

VOID GetSeDebugPrivilege() {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        goto end;
    
    if (!LookupPrivilegeValueA(NULL, (LPCSTR)"SeDebugPrivilege", &luid))
        goto end;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
        goto end;

end:
    if (hToken != NULL && CloseHandle != INVALID_HANDLE_VALUE)
        CloseHandle(hToken);

    return ;
}


int main(int argc, char** argv) {
    ULONG pid = 0;
    HANDLE hProcess = NULL;
    BOOL w64 = FALSE;
    SYSTEM_INFO sysInfo;

    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 0;
    }
    pid = atoi(argv[1]);

    GetSeDebugPrivilege();

    hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (hProcess == NULL) {
        printf("Error OpenProcess: %x\n",GetLastError());
    }
    GetSystemInfo(&sysInfo);
    IsWow64Process(hProcess, &w64);

    if(sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        w64 = TRUE;

#ifdef _WIN64
    if (w64 == TRUE) {
        printf("x86 process, inject with x86 version!\n");
    }
#else
    if (w64 == FALSE) {
        printf("x64 process, inject with x64 version!\n");
    }

#endif
    CloseHandle(hProcess);

#ifdef _WIN64
    return inject(pid, L"\\inject64.dll");
#else
    return inject(pid,L"\\inject.dll");
#endif


    return 0;
}