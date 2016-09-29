#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "imports.h"
#include "ReflectiveDLLInjection.h"
#include "ApiSetMap.h"

void RefreshPE();
HMODULE CustomLoadLibrary(const PWCHAR wszFullDllName, const PWCHAR wszBaseDllName, ULONG_PTR pDllBase);
HMODULE GetLoadedLibrary(const PCHAR wszModule);
FARPROC WINAPI CustomGetProcAddressEx(HMODULE hModule, const PCHAR lpProcName, const PCHAR szOriginalModule);
VOID ScanAndFixModule(ULONG_PTR pKnown, ULONG_PTR pSuspect, PWCHAR wszBaseDllName);
VOID ScanAndFixSection(PCHAR szSectionName, PCHAR pKnown, PCHAR pSuspect, size_t stLength);