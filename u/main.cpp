#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

#define DEBUG_MODE 1
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define ThreadQuerySetWin32StartAddress 9

typedef LONG NTSTATUS;
typedef NTSTATUS(WINAPI* NTQUERYINFOMATIONTHREAD)(HANDLE, LONG, PVOID, ULONG, PULONG);

DWORD_PTR WINAPI GetThreadStartAddress(HANDLE hThread)
{
    NTSTATUS ntStatus;
    DWORD_PTR dwThreadStartAddr = 0;
    NTQUERYINFOMATIONTHREAD NtQueryInformationThread = nullptr;

    NtQueryInformationThread = (NTQUERYINFOMATIONTHREAD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInformationThread)
    {
        std::cerr << "Failed to get NtQueryInformationThread function address\n";
        return 0;
    }

    ntStatus = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwThreadStartAddr, sizeof(DWORD_PTR), nullptr);
    if (ntStatus != STATUS_SUCCESS)
    {
        std::cerr << "NtQueryInformationThread failed with status: " << ntStatus << "\n";
        return 0;
    }

    return dwThreadStartAddr;
}

DWORD_PTR* GetModuleInfo(DWORD pid, const wchar_t* target)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); // Removed TH32CS_SNAPMODULE32
    static DWORD_PTR moduleinfo[2] = { 0 };

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot failed with error: " << GetLastError() << "\n";
        return nullptr;
    }

    MODULEENTRY32 modEntry;
    modEntry.dwSize = sizeof(modEntry);

    if (!Module32First(hSnap, &modEntry))
    {
        std::cerr << "Module32First failed with error: " << GetLastError() << "\n";
        CloseHandle(hSnap);
        return nullptr;
    }

    do
    {
        wchar_t moduleName[MAX_MODULE_NAME32 + 1];
        MultiByteToWideChar(CP_ACP, 0, modEntry.szModule, -1, moduleName, MAX_MODULE_NAME32 + 1);

        if (_wcsicmp(moduleName, target) == 0)
        {
            moduleinfo[0] = (DWORD_PTR)modEntry.modBaseAddr;
            moduleinfo[1] = modEntry.modBaseSize;
            CloseHandle(hSnap);
            return moduleinfo;
        }
    } while (Module32Next(hSnap, &modEntry));

    CloseHandle(hSnap);
    return nullptr;
}

BOOL isTarget(HANDLE tHandle, DWORD pid, const wchar_t* target)
{
    DWORD_PTR ThreadStartAddr = GetThreadStartAddress(tHandle);
    if (!ThreadStartAddr)
    {
        std::cout << "Get start address of thread failed!\n";
        ExitProcess(1);
    }

    DWORD_PTR* retmoduleinfo = GetModuleInfo(pid, target);
    if (!retmoduleinfo)
    {
        std::cout << "Failed to get module information!\n";
        ExitProcess(1);
    }

    DWORD_PTR ModuleStart = retmoduleinfo[0];
    DWORD_PTR ModuleEnd = retmoduleinfo[0] + retmoduleinfo[1];

    if (DEBUG_MODE)
    {
        printf("THREAD START ADDR: %012llX\n", ThreadStartAddr);
        printf("MODULE START ADDR: %012llX\n", retmoduleinfo[0]);
        printf("MODULE END ADDR: %012llX\n", retmoduleinfo[0] + retmoduleinfo[1]);
    }

    if (ThreadStartAddr >= ModuleStart && ThreadStartAddr <= ModuleEnd)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

struct args
{
    HANDLE hThread;
};

void CrackAnyRun(LPVOID inargs)
{
    args* funcargs = (args*)inargs;
    HANDLE tHandle = funcargs->hThread;
    while (1)
    {
        SuspendThread(tHandle);
        std::cout << "Thread suspended\n";
        Sleep(24000);
        ResumeThread(tHandle);
        std::cout << "Thread resumed\n";
        Sleep(1000);
    }
}

int main()
{
    HANDLE tHandle, pHandle = nullptr, hToken;
    DWORD tid, pid = 0;
    LUID luid = { 0 };
    BOOL privRet = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        std::cerr << "OpenProcessToken failed with error: " << GetLastError() << "\n";
        return 1;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
        std::cerr << "LookupPrivilegeValue failed with error: " << GetLastError() << "\n";
        return 1;
    }

    TOKEN_PRIVILEGES tokenPriv = { 0 };
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        std::cerr << "AdjustTokenPrivileges failed with error: " << GetLastError() << "\n";
        return 1;
    }

    PROCESSENTRY32 pe;
    HANDLE hps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hps != INVALID_HANDLE_VALUE)
    {
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hps, &pe))
        {
            do
            {
                wchar_t processName[MAX_PATH];
                MultiByteToWideChar(CP_ACP, 0, pe.szExeFile, -1, processName, MAX_PATH);

                if (_wcsicmp(processName, L"main.exe") == 0)
                {
                    pid = pe.th32ProcessID;
                }
            } while (Process32Next(hps, &pe));
        }
        else
        {
            std::cerr << "Process32First failed with error: " << GetLastError() << "\n";
            return 1;
        }
    }
    else
    {
        std::cerr << "CreateToolhelp32Snapshot failed with error: " << GetLastError() << "\n";
        return 1;
    }

    if (pid == 0)
    {
        std::cerr << "Process not found!\n";
        return 1;
    }

    HANDLE hth = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hth != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(hth, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == pid)
                {
                    tHandle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (tHandle != INVALID_HANDLE_VALUE)
                    {
                        if (isTarget(tHandle, pid, L"ntdll.dll")) // add whatever dll you want
                        {
                            SuspendThread(tHandle);
                            if (DEBUG_MODE)
                            {
                                std::cout << "THREADID: " << te.th32ThreadID << "\n";
                            }
                        }
                        if (isTarget(tHandle, pid, L"libstdc++-6.dll")) // add whatever dll you want
                        {
                            HANDLE dupHandle;
                            if (DuplicateHandle(GetCurrentProcess(), tHandle, GetCurrentProcess(), &dupHandle, THREAD_SUSPEND_RESUME, FALSE, 0))
                            {
                                args thargs;
                                thargs.hThread = dupHandle;
                                CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)CrackAnyRun, &thargs, 0, nullptr);
                                CloseHandle(tHandle);
                                continue;
                            }
                        }
                        else
                        {
                            continue;
                        }
                        CloseHandle(tHandle);
                    }
                }
            } while (Thread32Next(hth, &te));
        }
        else
        {
            std::cerr << "Thread32First failed with error: " << GetLastError() << "\n";
            return 1;
        }
    }
    else
    {
        std::cerr << "CreateToolhelp32Snapshot failed with error: " << GetLastError() << "\n";
        return 1;
    }

    return 0;
}