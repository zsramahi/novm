#ifndef novmntapi
#define novmntapi

#include <windows.h>
#include "structs.h"

typedef NTSTATUS (NTAPI *pntallocatevirtualmemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pntfreevirtualmemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *pntprotectvirtualmemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pntqueryvirtualmemory)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pntclose)(HANDLE);
typedef NTSTATUS (NTAPI *pntopenthread)(PHANDLE, ACCESS_MASK, objectattributes*, clientid*);
typedef NTSTATUS (NTAPI *pntsetinformationthread)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pntqueryinformationthread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pntgetcontextthread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pntqueryinformationprocess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pntquerysysteminformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pntsetdebugfilterstate)(ULONG, ULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *prtlgetversion)(osversioninfoex*);
typedef VOID     (NTAPI *prtlinitunicodestring)(unicodestring*, PCWSTR);
typedef NTSTATUS (NTAPI *prtlunicodestringtoansistring)(ansistring*, const unicodestring*, BOOLEAN);
typedef NTSTATUS (NTAPI *pldrgetdllhandleex)(ULONG, PCWSTR, PCWSTR, const unicodestring*, PVOID*);
typedef NTSTATUS (NTAPI *pldrgetprocedureaddressforcaller)(PVOID, const ansistring*, USHORT, PVOID*, ULONG, PVOID);

extern pntallocatevirtualmemory          ntallocatevirtualmemory;
extern pntfreevirtualmemory              ntfreevirtualmemory;
extern pntprotectvirtualmemory           ntprotectvirtualmemory;
extern pntqueryvirtualmemory             ntqueryvirtualmemory;
extern pntclose                          ntclose;
extern pntopenthread                     ntopenthread;
extern pntsetinformationthread           ntsetinformationthread;
extern pntqueryinformationthread         ntqueryinformationthread;
extern pntgetcontextthread               ntgetcontextthread;
extern pntqueryinformationprocess        ntqueryinformationprocess;
extern pntquerysysteminformation         ntquerysysteminformation;
extern pntsetdebugfilterstate            ntsetdebugfilterstate;
extern prtlgetversion                    rtlgetversion;
extern prtlinitunicodestring             rtlinitunicodestring;
extern prtlunicodestringtoansistring     rtlunicodestringtoansistring;
extern pldrgetdllhandleex                ldrgetdllhandleex;
extern pldrgetprocedureaddressforcaller  ldrgetprocedureaddressforcaller;

void ntapiload(void);

#endif
