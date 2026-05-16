#include "utils.h"
#include "ntapi.h"
#include "seh.h"
#include "../syscall/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>

HMODULE llmodule(LPCSTR name) {
    HMODULE m = GetModuleHandleA(name);
    if (m) return m;
    if (sizeof(void*) == 8 && ldrgetdllhandleex && rtlinitunicodestring) {
        wchar_t wide[260];
        int len = MultiByteToWideChar(CP_ACP, 0, name, -1, wide, 260);
        if (len > 0) {
            unicodestring us = {0};
            rtlinitunicodestring(&us, wide);
            PVOID h = NULL;
            if (ldrgetdllhandleex(0, NULL, NULL, &us, &h) == STATUS_SUCCESS) {
                return (HMODULE)h;
            }
        }
    }
    return NULL;
}

HMODULE llmodulew(LPCWSTR name) {
    HMODULE m = GetModuleHandleW(name);
    if (m) return m;
    if (ldrgetdllhandleex && rtlinitunicodestring) {
        unicodestring us = {0};
        rtlinitunicodestring(&us, name);
        PVOID h = NULL;
        if (ldrgetdllhandleex(0, NULL, NULL, &us, &h) == STATUS_SUCCESS) {
            return (HMODULE)h;
        }
    }
    return NULL;
}

FARPROC llproc(HMODULE m, LPCSTR fn) {
    FARPROC p = GetProcAddress(m, fn);
    if (p) return p;
    if (sizeof(void*) == 8 && ldrgetprocedureaddressforcaller && rtlinitunicodestring && rtlunicodestringtoansistring) {
        wchar_t wide[260];
        int len = MultiByteToWideChar(CP_ACP, 0, fn, -1, wide, 260);
        if (len <= 0) return NULL;
        unicodestring us = {0};
        ansistring as = {0};
        rtlinitunicodestring(&us, wide);
        rtlunicodestringtoansistring(&as, &us, TRUE);
        PVOID f = NULL;
        ldrgetprocedureaddressforcaller(m, &as, 0, &f, 0, NULL);
        return (FARPROC)f;
    }
    return NULL;
}

FARPROC exportaddr(HMODULE m, LPCSTR fn) {
    if (!m || !fn) return NULL;
    BYTE* base = (BYTE*)m;
    IMAGE_DOS_HEADER dos;
    if (!safereadbytes(base, &dos, sizeof(dos))) return llproc(m, fn);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return llproc(m, fn);
    IMAGE_NT_HEADERS nt;
    if (!safereadbytes(base + dos.e_lfanew, &nt, sizeof(nt))) return llproc(m, fn);
    if (nt.Signature != IMAGE_NT_SIGNATURE) return llproc(m, fn);
    IMAGE_DATA_DIRECTORY ed = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress || !ed.Size) return llproc(m, fn);
    IMAGE_EXPORT_DIRECTORY exp;
    if (!safereadbytes(base + ed.VirtualAddress, &exp, sizeof(exp))) return llproc(m, fn);
    DWORD* funcs = (DWORD*)(base + exp.AddressOfFunctions);
    DWORD* names = (DWORD*)(base + exp.AddressOfNames);
    WORD*  ords  = (WORD*) (base + exp.AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp.NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (strcmp(name, fn) == 0) {
            WORD ord = ords[i];
            return (FARPROC)(base + funcs[ord]);
        }
    }
    return llproc(m, fn);
}

FARPROC exportaddrn(LPCSTR mod, LPCSTR fn) {
    HMODULE m = llmodule(mod);
    if (!m) return NULL;
    return exportaddr(m, fn);
}

PVOID allocshell(const BYTE* code, SIZE_T sz) {
    PVOID p = NULL;
    SIZE_T region = sz;
    NTSTATUS s = -1;
    if (ntallocatevirtualmemory) {
        s = ntallocatevirtualmemory((HANDLE)(LONG_PTR)-1, &p, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (s != STATUS_SUCCESS) {
        p = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!p) return NULL;
    }
    memcpy(p, code, sz);
    FlushInstructionCache(GetCurrentProcess(), p, sz);
    return p;
}

BOOL freeshell(PVOID p) {
    if (!p) return FALSE;
    if (ntfreevirtualmemory) {
        SIZE_T sz = 0;
        if (ntfreevirtualmemory((HANDLE)(LONG_PTR)-1, &p, &sz, MEM_RELEASE) == STATUS_SUCCESS) return TRUE;
    }
    return VirtualFree(p, 0, MEM_RELEASE);
}

BOOL protectmem(PVOID base, SIZE_T sz, ULONG newp, PULONG oldp) {
    if (ntprotectvirtualmemory) {
        PVOID b = base;
        SIZE_T r = sz;
        if (ntprotectvirtualmemory((HANDLE)(LONG_PTR)-1, &b, &r, newp, oldp) == STATUS_SUCCESS) return TRUE;
    }
    DWORD o = 0;
    if (VirtualProtect(base, sz, newp, &o)) {
        if (oldp) *oldp = o;
        return TRUE;
    }
    return FALSE;
}

BOOL copymem(PVOID dst, const void* src, SIZE_T sz, BOOL changeprot) {
    if (changeprot) {
        ULONG old = 0;
        if (!protectmem(dst, sz, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
        memcpy(dst, src, sz);
        FlushInstructionCache(GetCurrentProcess(), dst, sz);
        ULONG dummy = 0;
        protectmem(dst, sz, old, &dummy);
        return TRUE;
    }
    memcpy(dst, src, sz);
    return TRUE;
}

BYTE readbyte(PVOID p) {
    BYTE b = 0;
    safereadbyte(p, &b);
    return b;
}

peb* pebptr(void) {
#if defined(_M_X64) || defined(__x86_64__)
    return (peb*)__readgsqword(0x60);
#elif defined(_M_IX86) || defined(__i386__)
    return (peb*)__readfsdword(0x30);
#else
    return NULL;
#endif
}

BOOL getpeb(peb* out) {
    peb* p = pebptr();
    if (!p) return FALSE;
    memcpy(out, p, sizeof(peb));
    return TRUE;
}

BOOL containsi(const char* hay, const char* needle) {
    if (!hay || !needle) return FALSE;
    size_t hl = strlen(hay), nl = strlen(needle);
    if (nl == 0) return TRUE;
    if (nl > hl) return FALSE;
    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        for (; j < nl; j++) {
            if (tolower((unsigned char)hay[i + j]) != tolower((unsigned char)needle[j])) break;
        }
        if (j == nl) return TRUE;
    }
    return FALSE;
}

BOOL containsiw(const wchar_t* hay, const char* needle) {
    if (!hay || !needle) return FALSE;
    size_t hl = wcslen(hay), nl = strlen(needle);
    if (nl == 0) return TRUE;
    if (nl > hl) return FALSE;
    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        for (; j < nl; j++) {
            if (towlower(hay[i + j]) != tolower((unsigned char)needle[j])) break;
        }
        if (j == nl) return TRUE;
    }
    return FALSE;
}

void forceexit(void) {
    ExitProcess(0);
    *(volatile int*)0 = 42;
}

BOOL queryvm(BOOL viasyscall, PVOID base, memorybasicinformation* mbi, PSIZE_T retlen) {
    SIZE_T rl = 0;
    NTSTATUS s = -1;
    if (viasyscall) {
        s = sysntqueryvirtualmemory((HANDLE)(LONG_PTR)-1, base, 0, mbi, sizeof(*mbi), &rl);
    } else if (ntqueryvirtualmemory) {
        s = ntqueryvirtualmemory((HANDLE)(LONG_PTR)-1, base, 0, mbi, sizeof(*mbi), &rl);
    } else {
        MEMORY_BASIC_INFORMATION m = {0};
        SIZE_T r = VirtualQuery(base, &m, sizeof(m));
        if (r == 0) return FALSE;
        mbi->BaseAddress = m.BaseAddress;
        mbi->AllocationBase = m.AllocationBase;
        mbi->AllocationProtect = m.AllocationProtect;
        mbi->RegionSize = m.RegionSize;
        mbi->State = m.State;
        mbi->Protect = m.Protect;
        mbi->Type = m.Type;
        if (retlen) *retlen = r;
        return TRUE;
    }
    if (retlen) *retlen = rl;
    return s == STATUS_SUCCESS;
}

BOOL closehandlent(HANDLE h) {
    if (ntclose) return ntclose(h) == STATUS_SUCCESS;
    return CloseHandle(h);
}

void randstring(char* out, int min, int max) {
    static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    int range = max - min;
    int len = min + (range > 0 ? rand() % range : 0);
    for (int i = 0; i < len; i++) out[i] = alpha[rand() % (int)(sizeof(alpha) - 1)];
    out[len] = 0;
}
