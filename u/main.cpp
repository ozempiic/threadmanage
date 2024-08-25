#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include "include/threadutils.h"
#include "include/moduleutils.h"

#define DEBUG_MODE 1

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

    // Adjust privileges
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        std::cout << "OpenProcessToken failed with error: " << GetLastError() << "\n";
        return 1;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
        std::cout << "LookupPrivilegeValue failed with error: " << GetLastError() << "\n";
        return 1;
    }

    TOKEN_PRIVILEGES tokenPriv = { 0 };
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        std::cout << "AdjustTokenPrivileges failed with error: " << GetLastError() << "\n";
        return 1;
    }

    // Find target process
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

                if (_wcsicmp(processName, L"main.exe") == 0) // Change this to whatever executable you want
                {
                    pid = pe.th32ProcessID;
                }
            } while (Process32Next(hps, &pe));
        }
        else
        {
            std::cout << "Process32First failed with error: " << GetLastError() << "\n";
            return 1;
        }
    }
    else
    {
        std::cout << "CreateToolhelp32Snapshot failed with error: " << GetLastError() << "\n";
        return 1;
    }

    if (pid == 0)
    {
        std::cout << "Process not found!\n";
        return 1;
    }

    // Find threads in target process
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
                        if (isTarget(tHandle, pid, L"ntdll.dll"))
                        {
                            SuspendThread(tHandle);
                            std::cout << "THREADID: " << te.th32ThreadID << " Suspended for ntdll.dll\n";
                            ResumeThread(tHandle);
                        }
                        if (isTarget(tHandle, pid, L"kernel32.dll"))
                        {
                            HANDLE dupHandle;
                            if (DuplicateHandle(GetCurrentProcess(), tHandle, GetCurrentProcess(), &dupHandle, THREAD_SUSPEND_RESUME, FALSE, 0))
                            {
                                args thargs;
                                thargs.hThread = dupHandle;
                                CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)CrackAnyRun, &thargs, 0, nullptr);
                                std::cout << "THREADID: " << te.th32ThreadID << " Managed for kernel32.dll\n";
                                CloseHandle(tHandle);
                                continue;
                            }
                        }
                        CloseHandle(tHandle);
                    }
                }
            } while (Thread32Next(hth, &te));
        }
        else
        {
            std::cout << "Thread32First failed with error: " << GetLastError() << "\n";
            return 1;
        }
    }
    else
    {
        std::cout << "CreateToolhelp32Snapshot failed with error: " << GetLastError() << "\n";
        return 1;
    }

    return 0;
}
