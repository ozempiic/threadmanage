#include "threadutils.h"
#include <iostream>

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
