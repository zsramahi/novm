#ifndef novmsyscall
#define novmsyscall

#include <windows.h>
#include "../core/structs.h"

void  syscallinit(void);
const char* buildnumber(BOOL exitontamper, BOOL onlyshowontamper);
BOOL  buildnumbersaved(void);
BYTE  commonsyscallbyte(const char* fn);
BYTE  extractsyscallbyte(const BYTE* bytes, SIZE_T len, const char* fn);
BYTE  extractretvalue(const BYTE* bytes, SIZE_T len);
PVOID syscallcode(const char* dll, const char* fn);

NTSTATUS sysntclose(HANDLE h);
NTSTATUS sysntqueryinformationprocess1(ULONG cls, ULONG* info, ULONG sz, ULONG* retlen);
NTSTATUS sysntqueryinformationprocess2(ULONG cls, PVOID* info, ULONG sz, ULONG retlen);
NTSTATUS sysntqueryinformationprocess3(ULONG cls, processbasicinformation* info, ULONG sz, ULONG retlen);
NTSTATUS sysntquerysysteminfocodeintegrity(ULONG cls, systemcodeintegrityinformation* info, ULONG sz, ULONG* retlen);
NTSTATUS sysntquerysysteminfokerneldebug(ULONG cls, systemkerneldebuggerinformation* info, ULONG sz, ULONG* retlen);
NTSTATUS sysntquerysysteminfosecureboot(ULONG cls, systemsecurebootinformation* info, ULONG sz, ULONG* retlen);
NTSTATUS sysntqueryvirtualmemory(HANDLE h, PVOID base, ULONG cls, void* info, SIZE_T sz, PSIZE_T retlen);
NTSTATUS sysntqueryinformationthread(HANDLE h, ULONG cls, PVOID* info, ULONG sz, PVOID retlen);

extern BOOL syscalltampered;

#endif
