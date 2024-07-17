#ifndef THREADUTILS_H
#define THREADUTILS_H

#include <windows.h>

DWORD_PTR WINAPI GetThreadStartAddress(HANDLE hThread);

#endif // THREADUTILS_H
