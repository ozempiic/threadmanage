#include "moduleutils.h"
#include "threadutils.h"
#include <iostream>

DWORD_PTR* GetModuleInfo(DWORD pid, const wchar_t* target)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
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
        std::cout << "Failed to get module information for " << target << "!\n";
        ExitProcess(1);
    }

    DWORD_PTR ModuleStart = retmoduleinfo[0];
    DWORD_PTR ModuleEnd = retmoduleinfo[0] + retmoduleinfo[1];

    // Debug print
    std::cout << "THREAD START ADDR: " << std::hex << ThreadStartAddr << std::endl;
    std::cout << "MODULE START ADDR: " << std::hex << retmoduleinfo[0] << std::endl;
    std::cout << "MODULE END   ADDR: " << std::hex << (retmoduleinfo[0] + retmoduleinfo[1]) << std::endl;

    std::wcout << "Checking thread for DLL: " << target << std::endl;

    if (ThreadStartAddr >= ModuleStart && ThreadStartAddr <= ModuleEnd)
    {
        std::cout << "Thread matched target DLL: " << target << "\n\n";
        return TRUE;
    }
    else
    {
        std::cout << "Thread did not match target DLL: " << target << "\n\n";
        return FALSE;
    }
}
