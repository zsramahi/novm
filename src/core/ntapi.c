#include "ntapi.h"

pntallocatevirtualmemory          ntallocatevirtualmemory          = NULL;
pntfreevirtualmemory              ntfreevirtualmemory              = NULL;
pntprotectvirtualmemory           ntprotectvirtualmemory           = NULL;
pntqueryvirtualmemory             ntqueryvirtualmemory             = NULL;
pntclose                          ntclose                          = NULL;
pntopenthread                     ntopenthread                     = NULL;
pntsetinformationthread           ntsetinformationthread           = NULL;
pntqueryinformationthread         ntqueryinformationthread         = NULL;
pntgetcontextthread               ntgetcontextthread               = NULL;
pntqueryinformationprocess        ntqueryinformationprocess        = NULL;
pntquerysysteminformation         ntquerysysteminformation         = NULL;
pntsetdebugfilterstate            ntsetdebugfilterstate            = NULL;
prtlgetversion                    rtlgetversion                    = NULL;
prtlinitunicodestring             rtlinitunicodestring             = NULL;
prtlunicodestringtoansistring     rtlunicodestringtoansistring     = NULL;
pldrgetdllhandleex                ldrgetdllhandleex                = NULL;
pldrgetprocedureaddressforcaller  ldrgetprocedureaddressforcaller  = NULL;

void ntapiload(void) {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) h = LoadLibraryA("ntdll.dll");
    if (!h) return;
    ntallocatevirtualmemory          = (pntallocatevirtualmemory)         (void(*)(void))GetProcAddress(h, "NtAllocateVirtualMemory");
    ntfreevirtualmemory              = (pntfreevirtualmemory)             (void(*)(void))GetProcAddress(h, "NtFreeVirtualMemory");
    ntprotectvirtualmemory           = (pntprotectvirtualmemory)          (void(*)(void))GetProcAddress(h, "NtProtectVirtualMemory");
    ntqueryvirtualmemory             = (pntqueryvirtualmemory)            (void(*)(void))GetProcAddress(h, "NtQueryVirtualMemory");
    ntclose                          = (pntclose)                         (void(*)(void))GetProcAddress(h, "NtClose");
    ntopenthread                     = (pntopenthread)                    (void(*)(void))GetProcAddress(h, "NtOpenThread");
    ntsetinformationthread           = (pntsetinformationthread)          (void(*)(void))GetProcAddress(h, "NtSetInformationThread");
    ntqueryinformationthread         = (pntqueryinformationthread)        (void(*)(void))GetProcAddress(h, "NtQueryInformationThread");
    ntgetcontextthread               = (pntgetcontextthread)              (void(*)(void))GetProcAddress(h, "NtGetContextThread");
    ntqueryinformationprocess        = (pntqueryinformationprocess)       (void(*)(void))GetProcAddress(h, "NtQueryInformationProcess");
    ntquerysysteminformation         = (pntquerysysteminformation)        (void(*)(void))GetProcAddress(h, "NtQuerySystemInformation");
    ntsetdebugfilterstate            = (pntsetdebugfilterstate)           (void(*)(void))GetProcAddress(h, "NtSetDebugFilterState");
    rtlgetversion                    = (prtlgetversion)                   (void(*)(void))GetProcAddress(h, "RtlGetVersion");
    rtlinitunicodestring             = (prtlinitunicodestring)            (void(*)(void))GetProcAddress(h, "RtlInitUnicodeString");
    rtlunicodestringtoansistring     = (prtlunicodestringtoansistring)    (void(*)(void))GetProcAddress(h, "RtlUnicodeStringToAnsiString");
    ldrgetdllhandleex                = (pldrgetdllhandleex)               (void(*)(void))GetProcAddress(h, "LdrGetDllHandleEx");
    ldrgetprocedureaddressforcaller  = (pldrgetprocedureaddressforcaller) (void(*)(void))GetProcAddress(h, "LdrGetProcedureAddressForCaller");
}
