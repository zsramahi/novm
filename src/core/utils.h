#ifndef novmutils
#define novmutils

#include <windows.h>
#include "structs.h"

HMODULE  llmodule(LPCSTR name);
HMODULE  llmodulew(LPCWSTR name);
FARPROC  llproc(HMODULE m, LPCSTR fn);
FARPROC  exportaddr(HMODULE m, LPCSTR fn);
FARPROC  exportaddrn(LPCSTR mod, LPCSTR fn);

PVOID    allocshell(const BYTE* code, SIZE_T sz);
BOOL     freeshell(PVOID p);
BOOL     protectmem(PVOID base, SIZE_T sz, ULONG newp, PULONG oldp);
BOOL     copymem(PVOID dst, const void* src, SIZE_T sz, BOOL changeprot);
BYTE     readbyte(PVOID p);

BOOL     getpeb(peb* out);
peb*     pebptr(void);

BOOL     containsi(const char* hay, const char* needle);
BOOL     containsiw(const wchar_t* hay, const char* needle);
void     forceexit(void);

BOOL     queryvm(BOOL viasyscall, PVOID base, memorybasicinformation* mbi, PSIZE_T retlen);
BOOL     closehandlent(HANDLE h);

void     randstring(char* out, int min, int max);

#endif
