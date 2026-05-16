#include "hooksdetection.h"
#include "../core/utils.h"
#include "../core/structs.h"
#include "../syscall/syscall.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

static const char* libraries[] = {"kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "win32u.dll"};
static const char* commonkernel[] = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation"};
static const char* commonntdll[] = {"NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation", "NtCreateFile", "NtCreateProcess", "NtCreateSection", "NtCreateThread", "NtYieldExecution", "NtCreateUserProcess", "NtAllocateVirtualMemory"};
static const char* commonntdll2[] = {"NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation", "NtCreateFile", "NtCreateProcess", "NtCreateSection", "NtCreateThread", "NtYieldExecution", "NtCreateUserProcess", "NtAllocateVirtualMemory", "NtQueryInformationThread", "NtQueryVirtualMemory"};
static const char* commonuser32[] = {"FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput", "CreateWindowExW", "CreateWindowExA"};
static const char* commonwin32u[] = {"NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow"};

static BOOL bytehooked(BYTE b, BOOL allowff) {
    if (b == 0x90 || b == 0xE9) return TRUE;
    if (allowff && b == 0xFF) return TRUE;
    return FALSE;
}

static BOOL scanlist(HMODULE m, const char* const* fns, int count, BOOL allowff) {
    for (int i = 0; i < count; i++) {
        FARPROC f = exportaddr(m, fns[i]);
        if (!f) continue;
        BYTE b = readbyte((PVOID)f);
        if (bytehooked(b, allowff)) return TRUE;
    }
    return FALSE;
}

BOOL hdtdetecthooks(void) {
    for (size_t i = 0; i < sizeof(libraries)/sizeof(libraries[0]); i++) {
        HMODULE m = llmodule(libraries[i]);
        if (!m) continue;
        if (strcmp(libraries[i], "kernel32.dll") == 0) {
            if (scanlist(m, commonkernel, sizeof(commonkernel)/sizeof(commonkernel[0]), FALSE)) return TRUE;
        } else if (strcmp(libraries[i], "kernelbase.dll") == 0) {
            if (scanlist(m, commonkernel, sizeof(commonkernel)/sizeof(commonkernel[0]), TRUE)) return TRUE;
        } else if (strcmp(libraries[i], "ntdll.dll") == 0) {
            if (scanlist(m, commonntdll, sizeof(commonntdll)/sizeof(commonntdll[0]), TRUE)) return TRUE;
        } else if (strcmp(libraries[i], "user32.dll") == 0) {
            if (scanlist(m, commonuser32, sizeof(commonuser32)/sizeof(commonuser32[0]), FALSE)) return TRUE;
        } else if (strcmp(libraries[i], "win32u.dll") == 0) {
            if (scanlist(m, commonwin32u, sizeof(commonwin32u)/sizeof(commonwin32u[0]), TRUE)) return TRUE;
        }
    }
    return FALSE;
}

BOOL hdtdetectinlinehooks(const char* modulename, const char* const* fns, int count) {
    if (!modulename || !fns) return FALSE;
    HMODULE m = llmodule(modulename);
    if (!m) return FALSE;
    return scanlist(m, fns, count, TRUE);
}

BOOL hdtdetectguardpagehook(PVOID fn, BOOL viasyscall) {
    if (!fn) return FALSE;
    memorybasicinformation mbi = {0};
    SIZE_T retlen = 0;
    if (!queryvm(viasyscall, fn, &mbi, &retlen)) return FALSE;
    return (mbi.Protect & PAGE_GUARD) == PAGE_GUARD;
}

static BOOL scanguardlist(HMODULE m, const char* const* fns, int count, BOOL viasyscall) {
    for (int i = 0; i < count; i++) {
        FARPROC f = exportaddr(m, fns[i]);
        if (!f) continue;
        if (hdtdetectguardpagehook((PVOID)f, viasyscall)) return TRUE;
    }
    return FALSE;
}

BOOL hdtdetectguardpagehooks(BOOL viasyscall) {
    for (size_t i = 0; i < sizeof(libraries)/sizeof(libraries[0]); i++) {
        HMODULE m = llmodule(libraries[i]);
        if (!m) continue;
        if (strcmp(libraries[i], "kernel32.dll") == 0 || strcmp(libraries[i], "kernelbase.dll") == 0) {
            if (scanguardlist(m, commonkernel, sizeof(commonkernel)/sizeof(commonkernel[0]), viasyscall)) return TRUE;
        } else if (strcmp(libraries[i], "ntdll.dll") == 0) {
            if (scanguardlist(m, commonntdll2, sizeof(commonntdll2)/sizeof(commonntdll2[0]), viasyscall)) return TRUE;
        } else if (strcmp(libraries[i], "user32.dll") == 0) {
            if (scanguardlist(m, commonuser32, sizeof(commonuser32)/sizeof(commonuser32[0]), viasyscall)) return TRUE;
        } else if (strcmp(libraries[i], "win32u.dll") == 0) {
            if (scanguardlist(m, commonwin32u, sizeof(commonwin32u)/sizeof(commonwin32u[0]), viasyscall)) return TRUE;
        }
    }
    return FALSE;
}

static BOOL addressbelongstomain(PVOID addr, HMODULE main) {
    MODULEINFO mi = {0};
    if (!GetModuleInformation(GetCurrentProcess(), main, &mi, sizeof(mi))) return FALSE;
    ULONG_PTR a = (ULONG_PTR)addr;
    ULONG_PTR base = (ULONG_PTR)mi.lpBaseOfDll;
    return a >= base && a < base + mi.SizeOfImage;
}

BOOL hdtdetectselfhooks(void) {
    HMODULE main = GetModuleHandleW(NULL);
    if (!main) return FALSE;
    BYTE* base = (BYTE*)main;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return FALSE;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + ed.VirtualAddress);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfFunctions; i++) {
        if (!funcs[i]) continue;
        PVOID fn = base + funcs[i];
        if (!addressbelongstomain(fn, main)) continue;
        BYTE b = readbyte(fn);
        if (b == 0xE9 || b == 0xFF || b == 0x90) return TRUE;
    }
    return FALSE;
}
