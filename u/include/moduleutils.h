#ifndef MODULEUTILS_H
#define MODULEUTILS_H

#include <windows.h>
#include <TlHelp32.h>

DWORD_PTR* GetModuleInfo(DWORD pid, const wchar_t* target);
BOOL isTarget(HANDLE tHandle, DWORD pid, const wchar_t* target);

#endif 