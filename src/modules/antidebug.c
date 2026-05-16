#include "antidebug.h"
#include "../core/utils.h"
#include "../core/seh.h"
#include "../core/structs.h"
#include "../core/ntapi.h"
#include "../syscall/syscall.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define THREAD_HIDE_FROM_DEBUGGER      0x11

BOOL adbinvalidhandle(BOOL viasyscall) {
    HANDLE rnd = (HANDLE)(LONG_PTR)(0x10000 + (rand() & 0xFFFF));
    NTSTATUS s;
    if (viasyscall) s = sysntclose(rnd);
    else if (ntclose) s = ntclose(rnd);
    else { return !CloseHandle(rnd); }
    return s != STATUS_SUCCESS ? FALSE : FALSE;
}

BOOL adbprotectedhandle(BOOL viasyscall) {
    char name[64];
    sprintf(name, "novmmtx_%d", rand());
    HANDLE m = CreateMutexA(NULL, FALSE, name);
    if (!m) return FALSE;
    SetHandleInformation(m, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    BOOL result = FALSE;
    NTSTATUS s;
    if (viasyscall) s = sysntclose(m);
    else if (ntclose) s = ntclose(m);
    else s = CloseHandle(m) ? STATUS_SUCCESS : -1;
    if (s != STATUS_SUCCESS) result = TRUE;
    SetHandleInformation(m, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    if (ntclose) ntclose(m);
    else CloseHandle(m);
    return result;
}

BOOL adbisdebuggerpresent(void) {
    return IsDebuggerPresent();
}

BOOL adbbeingdebugged(void) {
    peb* p = pebptr();
    return p && p->BeingDebugged;
}

BOOL adbntglobalflag(void) {
    peb* p = pebptr();
    if (!p) return FALSE;
    return (p->NtGlobalFlag & 0x70) == 0x70;
}

BOOL adbprocessdebugflags(BOOL viasyscall) {
    ULONG flags = 0, ret = 0;
    NTSTATUS s;
    if (viasyscall) s = sysntqueryinformationprocess1(0x1F, &flags, sizeof(flags), &ret);
    else if (ntqueryinformationprocess) s = ntqueryinformationprocess((HANDLE)(LONG_PTR)-1, 0x1F, &flags, sizeof(flags), &ret);
    else return FALSE;
    return s == STATUS_SUCCESS && flags == 0;
}

BOOL adbprocessdebugport(BOOL viasyscall) {
    PVOID port = NULL;
    ULONG ret = 0;
    ULONG sz = sizeof(ULONG);
#if defined(_WIN64)
    sz = sizeof(ULONG) * 2;
#endif
    NTSTATUS s;
    if (viasyscall) s = sysntqueryinformationprocess2(7, &port, sz, ret);
    else if (ntqueryinformationprocess) s = ntqueryinformationprocess((HANDLE)(LONG_PTR)-1, 7, &port, sz, &ret);
    else return FALSE;
    return s == STATUS_SUCCESS && port != NULL;
}

BOOL adbprocessdebugobjecthandle(BOOL viasyscall) {
    PVOID h = NULL;
    ULONG ret = 0;
    ULONG sz = sizeof(ULONG);
#if defined(_WIN64)
    sz = sizeof(ULONG) * 2;
#endif
    NTSTATUS s;
    if (viasyscall) s = sysntqueryinformationprocess2(0x1E, &h, sz, 0);
    else if (ntqueryinformationprocess) s = ntqueryinformationprocess((HANDLE)(LONG_PTR)-1, 0x1E, &h, sz, &ret);
    else return FALSE;
    return s == STATUS_SUCCESS && h != NULL;
}

const char* adbantiattach(void) {
    HMODULE n = llmodule("ntdll.dll");
    if (!n) return "Failed";
    PVOID a = (PVOID)exportaddr(n, "DbgUiRemoteBreakin");
    PVOID b = (PVOID)exportaddr(n, "DbgBreakPoint");
    if (!a || !b) return "Failed";
    BYTE int3 = 0xCC;
    BYTE ret = 0xC3;
    BOOL ok1 = copymem(a, &int3, 1, TRUE);
    BOOL ok2 = copymem(b, &ret, 1, TRUE);
    return (ok1 && ok2) ? "Success" : "Failed";
}

static BOOL anybadwindow(const wchar_t* title, const char* const* bad, size_t count) {
    if (!title) return FALSE;
    for (size_t i = 0; i < count; i++) {
        if (containsiw(title, bad[i])) return TRUE;
    }
    return FALSE;
}

typedef struct {
    BOOL hit;
    const char* const* bad;
    size_t count;
} enumctx;

static BOOL CALLBACK enumcb(HWND h, LPARAM p) {
    enumctx* c = (enumctx*)p;
    int len = GetWindowTextLengthW(h);
    if (len <= 0) return TRUE;
    wchar_t* buf = (wchar_t*)malloc((len + 2) * sizeof(wchar_t));
    if (!buf) return TRUE;
    GetWindowTextW(h, buf, len + 1);
    buf[len] = 0;
    if (anybadwindow(buf, c->bad, c->count)) {
        c->hit = TRUE;
        SendMessageW(h, WM_CLOSE, 0, 0);
        free(buf);
        return FALSE;
    }
    free(buf);
    return TRUE;
}

BOOL adbfindwindow(void) {
    static const char* bad[] = {"x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "cheat engine", "cheatengine", "ida"};
    enumctx c = {FALSE, bad, sizeof(bad)/sizeof(bad[0])};
    EnumWindows(enumcb, (LPARAM)&c);
    return c.hit;
}

BOOL adbforegroundwindow(void) {
    static const char* bad[] = {"x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "debug", "debugger", "cheat engine", "cheatengine", "ida"};
    HWND h = GetForegroundWindow();
    if (!h) return FALSE;
    int len = GetWindowTextLengthW(h);
    if (len <= 0) return FALSE;
    wchar_t* buf = (wchar_t*)malloc((len + 2) * sizeof(wchar_t));
    if (!buf) return FALSE;
    GetWindowTextW(h, buf, len + 1);
    buf[len] = 0;
    BOOL hit = anybadwindow(buf, bad, sizeof(bad)/sizeof(bad[0]));
    free(buf);
    return hit;
}

const char* adbhidethreads(void) {
    if (!ntopenthread || !ntsetinformationthread) return "Failed";
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return "Failed";
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    BOOL anyfail = FALSE;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            objectattributes oa = {0};
            oa.Length = sizeof(oa);
            clientid ci;
            ci.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
            ci.UniqueThread = (HANDLE)(ULONG_PTR)te.th32ThreadID;
            HANDLE th = NULL;
            NTSTATUS s = ntopenthread(&th, 0x0020, &oa, &ci);
            if (s == STATUS_SUCCESS && th) {
                NTSTATUS s2 = ntsetinformationthread(th, THREAD_HIDE_FROM_DEBUGGER, NULL, 0);
                if (ntclose) ntclose(th);
                else CloseHandle(th);
                if (s2 != STATUS_SUCCESS) anyfail = TRUE;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return anyfail ? "Failed" : "Success";
}

BOOL adbticktiming(void) {
    DWORD a = GetTickCount();
    Sleep(0x10);
    return (GetTickCount() - a) > 0x10;
}

BOOL adboutputdebug(void) {
    SetLastError(0);
    OutputDebugStringA("just testing some stuff...");
    return GetLastError() == 0;
}

void adbollyformatexploit(void) {
    OutputDebugStringA("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
}

static int dbgbreakshell(void) {
    DebugBreak();
    return 0;
}

BOOL adbdebugbreak(void) {
    int dummy = 0;
    return !safeexec(&dbgbreakshell, &dummy);
}

BOOL adbhardwarebreakpoints(void) {
    if (!ntopenthread || !ntgetcontextthread) return FALSE;
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    BOOL hit = FALSE;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            objectattributes oa = {0};
            oa.Length = sizeof(oa);
            clientid ci;
            ci.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
            ci.UniqueThread = (HANDLE)(ULONG_PTR)te.th32ThreadID;
            HANDLE th = NULL;
            NTSTATUS s = ntopenthread(&th, THREAD_QUERY_INFORMATION, &oa, &ci);
            if (s == STATUS_SUCCESS && th) {
                CONTEXT ctx;
                memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (ntgetcontextthread(th, &ctx) == STATUS_SUCCESS) {
                    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7) hit = TRUE;
                }
                if (ntclose) ntclose(th);
                else CloseHandle(th);
            }
            if (hit) break;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hit;
}

BOOL adbparentprocess(BOOL viasyscall) {
    processbasicinformation pbi;
    memset(&pbi, 0, sizeof(pbi));
    NTSTATUS s;
    if (viasyscall) s = sysntqueryinformationprocess3(0, &pbi, sizeof(pbi), 0);
    else if (ntqueryinformationprocess) s = ntqueryinformationprocess((HANDLE)(LONG_PTR)-1, 0, &pbi, sizeof(pbi), NULL);
    else return FALSE;
    if (s != STATUS_SUCCESS) return FALSE;
    DWORD parent = (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId;
    if (parent == 0) return FALSE;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent);
    if (!h) return FALSE;
    char path[MAX_PATH] = {0};
    DWORD sz = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameA(h, 0, path, &sz);
    CloseHandle(h);
    if (!ok) return FALSE;
    const char* base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    if (_stricmp(base, "explorer.exe") == 0) return FALSE;
    if (_stricmp(base, "cmd.exe") == 0) return FALSE;
    return TRUE;
}

BOOL adbsetdebugfilterstate(void) {
    if (!ntsetdebugfilterstate) return FALSE;
    return ntsetdebugfilterstate(0, 0, TRUE) == STATUS_SUCCESS;
}

typedef int (*pgshell)(void);

BOOL adbpageguard(void) {
    SYSTEM_INFO si = {0};
    GetSystemInfo(&si);
    PVOID p = VirtualAlloc(NULL, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) return FALSE;
    memset(p, 0xC3, si.dwPageSize);
    DWORD old = 0;
    if (!VirtualProtect(p, si.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old)) {
        VirtualFree(p, 0, MEM_RELEASE);
        return FALSE;
    }
    int r = 0;
    BOOL ran = safeexec((sehshell)(LONG_PTR)p, &r);
    BOOL detected = ran;
    VirtualFree(p, 0, MEM_RELEASE);
    return detected;
}
