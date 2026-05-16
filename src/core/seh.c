#include "seh.h"
#include <windows.h>
#include <string.h>
#include <setjmp.h>

static __thread int     sehactive = 0;
static __thread int     sehfailed = 0;
static __thread DWORD   sehcode   = 0;
static __thread jmp_buf sehbuf;

static LONG WINAPI sehhandler(EXCEPTION_POINTERS* info) {
    if (!sehactive) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    sehfailed = 1;
    sehcode = code;
    sehactive = 0;
    longjmp(sehbuf, 1);
    return EXCEPTION_CONTINUE_SEARCH;
}

static PVOID veh = NULL;

static void seh_ensureinstalled(void) {
    if (!veh) veh = AddVectoredExceptionHandler(1, sehhandler);
}

BOOL safereadbyte(PVOID addr, BYTE* out) {
    if (!addr || !out) return FALSE;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    DWORD bad = PAGE_NOACCESS | PAGE_GUARD;
    if (mbi.Protect & bad) return FALSE;
    *out = *(volatile BYTE*)addr;
    return TRUE;
}

BOOL safereadbytes(PVOID addr, void* out, SIZE_T sz) {
    if (!addr || !out || !sz) return FALSE;
    BYTE* dst = (BYTE*)out;
    BYTE* src = (BYTE*)addr;
    for (SIZE_T i = 0; i < sz; i++) {
        if (!safereadbyte(src + i, dst + i)) {
            dst[i] = 0;
            return FALSE;
        }
    }
    return TRUE;
}

BOOL safeexec(sehshell fn, int* outresult) {
    if (!fn) return FALSE;
    seh_ensureinstalled();
    sehfailed = 0;
    sehcode = 0;
    if (setjmp(sehbuf) == 0) {
        sehactive = 1;
        int r = fn();
        sehactive = 0;
        if (outresult) *outresult = r;
        return TRUE;
    }
    sehactive = 0;
    if (outresult) *outresult = 0;
    return FALSE;
}
