#include "antiinjection.h"
#include "../core/utils.h"
#include "../core/structs.h"
#include "../core/ntapi.h"
#include "../syscall/syscall.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef ProcessSignaturePolicy
#define ProcessSignaturePolicy 8
#endif

typedef BOOL (WINAPI *psetprocessmitigationpolicy)(int, PVOID, SIZE_T);

const char* aidlloadpolicy(void) {
    HMODULE k = llmodule("kernelbase.dll");
    if (!k) k = llmodule("kernel32.dll");
    if (!k) return "Failed";
    psetprocessmitigationpolicy fn = (psetprocessmitigationpolicy)(void(*)(void))exportaddr(k, "SetProcessMitigationPolicy");
    if (!fn) return "Failed";
    mitigationsigpolicy pol;
    pol.MicrosoftSignedOnly = 1;
    return fn(ProcessSignaturePolicy, &pol, sizeof(pol)) ? "Success" : "Failed";
}

typedef struct {
    PVOID base;
    SIZE_T size;
} modrange;

static int collectmodules(modrange* out, int max) {
    HANDLE proc = GetCurrentProcess();
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return 0;
    int n = (int)(needed / sizeof(HMODULE));
    if (n > max) n = max;
    int written = 0;
    for (int i = 0; i < n; i++) {
        MODULEINFO mi = {0};
        if (GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) {
            out[written].base = mi.lpBaseOfDll;
            out[written].size = mi.SizeOfImage;
            written++;
        }
    }
    return written;
}

static BOOL addressinrange(PVOID a, const modrange* r, int n) {
    ULONG_PTR ai = (ULONG_PTR)a;
    for (int i = 0; i < n; i++) {
        ULONG_PTR base = (ULONG_PTR)r[i].base;
        ULONG_PTR end = base + r[i].size;
        if (ai >= base && ai < end) return TRUE;
    }
    return FALSE;
}

BOOL aidcheckinjectedthreads(BOOL viasyscall, BOOL checkmodulerange) {
    if (!ntopenthread) return FALSE;
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    modrange mods[1024];
    int modcount = collectmodules(mods, 1024);
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
            NTSTATUS s = ntopenthread(&th, 0x0040, &oa, &ci);
            if (s != STATUS_SUCCESS || !th) continue;
            PVOID start = NULL;
            NTSTATUS qs;
            if (viasyscall) qs = sysntqueryinformationthread(th, 9, &start, sizeof(start), NULL);
            else if (ntqueryinformationthread) {
                ULONG ret = 0;
                qs = ntqueryinformationthread(th, 9, &start, sizeof(start), &ret);
            } else qs = -1;
            if (ntclose) ntclose(th);
            else CloseHandle(th);
            if (qs != STATUS_SUCCESS) continue;
            memorybasicinformation mbi = {0};
            SIZE_T retlen = 0;
            if (!queryvm(viasyscall, start, &mbi, &retlen)) continue;
            if (mbi.Type != MEM_IMAGE || mbi.State != MEM_COMMIT) { hit = TRUE; break; }
            if (checkmodulerange && !addressinrange(start, mods, modcount)) { hit = TRUE; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hit;
}

const char* aidcurrentclrmodule(void) {
    static const char* clrs[] = {"clr.dll", "coreclr.dll"};
    for (size_t i = 0; i < sizeof(clrs)/sizeof(clrs[0]); i++) {
        if (GetModuleHandleA(clrs[i])) return clrs[i];
    }
    return NULL;
}

BOOL aidsuspiciousbase(void) {
    peb p;
    if (!getpeb(&p)) return FALSE;
    HMODULE main = GetModuleHandleW(NULL);
    return p.ImageBaseAddress != (PVOID)main;
}

static int writechars(PVOID dst, const void* src, SIZE_T sz) {
    return copymem(dst, src, sz, TRUE) ? 0 : -1;
}

BOOL aidchangemoduleinfo(const char* modulename, DWORD flags) {
    char fallback[MAX_PATH] = {0};
    const char* finalname = modulename;
    if (!finalname) {
        GetModuleFileNameA(NULL, fallback, MAX_PATH);
        const char* base = strrchr(fallback, '\\');
        finalname = base ? base + 1 : fallback;
    }
    if (!finalname || !*finalname) return FALSE;
    HMODULE h = llmodule(finalname);
    if (!h) return FALSE;

    peb pebcopy;
    if (!getpeb(&pebcopy)) return FALSE;
    if (!pebcopy.Ldr) return FALSE;
    pebldrdata* ldr = (pebldrdata*)pebcopy.Ldr;
    PVOID f = ldr->InLoadOrderModuleList.Flink;
    PVOID start = f;

    char fakebuf[64];
    randstring(fakebuf, 6, 24);
    char fakedll[80];
    snprintf(fakedll, sizeof(fakedll), "%s.dll", fakebuf);
    wchar_t fakewide[80];
    int wn = MultiByteToWideChar(CP_ACP, 0, fakedll, -1, fakewide, 80);
    if (wn <= 0) return FALSE;

    BOOL pemask =
        (flags & (spoofentrypoint | spoofsizeofimage | spoofexecsectionrawsize |
                  spoofexecsectionrawpointer | spoofpesignature | spoofimagemagic |
                  spoofnotexenordll | spoofnumberofsections | spoofclearexecchars |
                  spoofexecsectionvirtualsize | spoofexecsectionname));

    DWORD secmask = (flags & (spoofexecsectionname | spoofexecsectionrawpointer |
                              spoofexecsectionrawsize | spoofclearexecchars | spoofexecsectionvirtualsize));

    for (int count = 0; count < 256 && f; count++) {
        ldrdatatableentry* entry = (ldrdatatableentry*)f;
        wchar_t* nameptr = entry->FullDllName.Buffer;
        int matches = 0;
        if (nameptr) {
            wchar_t finalwide[260] = {0};
            MultiByteToWideChar(CP_ACP, 0, finalname, -1, finalwide, 260);
            const wchar_t* tail = wcsrchr(nameptr, L'\\');
            tail = tail ? tail + 1 : nameptr;
            if (_wcsicmp(tail, finalwide) == 0) matches = 1;
            else if (_wcsicmp(nameptr, finalwide) == 0) matches = 1;
        }
        if (matches) {
            if (pemask) {
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)h;
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)h + dos->e_lfanew);

                IMAGE_NT_HEADERS ntcopy = *nt;

                if (flags & spoofentrypoint)
                    ntcopy.OptionalHeader.AddressOfEntryPoint = 0x1000 + (rand() % 0x1000);

                if (flags & spoofnumberofsections) {
                    int delta = rand() % 99;
                    ntcopy.FileHeader.NumberOfSections = (USHORT)(ntcopy.FileHeader.NumberOfSections + delta);
                }

                if (flags & spoofimagemagic)
                    ntcopy.OptionalHeader.Magic = (USHORT)(rand() & 0xFFFF);

                if (flags & spoofsizeofimage)
                    ntcopy.OptionalHeader.SizeOfImage = ntcopy.OptionalHeader.SizeOfImage + (rand() & 0xFFFF);

                if (flags & spoofnotexenordll) {
                    ntcopy.FileHeader.Characteristics &= (USHORT)~IMAGE_FILE_EXECUTABLE_IMAGE;
                    ntcopy.FileHeader.Characteristics &= (USHORT)~IMAGE_FILE_DLL;
                }

                if (flags & spoofpesignature)
                    ntcopy.Signature = 0x4D5A0000;

                if (secmask) {
                    BYTE* sechdrs = (BYTE*)IMAGE_FIRST_SECTION(nt);
                    USHORT secs = nt->FileHeader.NumberOfSections;
                    for (USHORT i = 0; i < secs; i++) {
                        IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)(sechdrs + i * sizeof(IMAGE_SECTION_HEADER));
                        if (sh->Characteristics & IMAGE_SCN_CNT_CODE) {
                            IMAGE_SECTION_HEADER scopy = *sh;
                            if (flags & spoofexecsectionname) {
                                char nm[16] = {0};
                                size_t maxname = IMAGE_SIZEOF_SHORT_NAME;
                                size_t taglen = strlen(fakebuf);
                                if (taglen > maxname - 1) taglen = maxname - 1;
                                nm[0] = '.';
                                memcpy(nm + 1, fakebuf, taglen);
                                memset(scopy.Name, 0, IMAGE_SIZEOF_SHORT_NAME);
                                memcpy(scopy.Name, nm, 1 + taglen);
                            }
                            if (flags & spoofexecsectionrawpointer)
                                scopy.PointerToRawData = (DWORD)rand();
                            if (flags & spoofexecsectionrawsize)
                                scopy.SizeOfRawData = (DWORD)rand();
                            if (flags & spoofclearexecchars)
                                scopy.Characteristics = 0;
                            if (flags & spoofexecsectionvirtualsize)
                                scopy.Misc.VirtualSize = scopy.Misc.VirtualSize + (rand() & 0xFFFF);
                            writechars(sh, &scopy, sizeof(scopy));
                            break;
                        }
                    }
                }
                writechars(nt, &ntcopy, sizeof(ntcopy));
            }

            ldrdatatableentry copy = *entry;
            if (flags & spoofbaseaddress) {
                ULONG_PTR rb = ((ULONG_PTR)(0x100 + rand() % 0x7000)) << 12;
                copy.DllBase = (PVOID)rb;
            }
            if (flags & spoofmodulename) {
                size_t bytes = (wcslen(fakewide) + 1) * sizeof(wchar_t);
                wchar_t* mem = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
                if (mem) {
                    memcpy(mem, fakewide, bytes);
                    copy.FullDllName.Buffer = mem;
                    copy.FullDllName.Length = (USHORT)((wcslen(fakewide)) * sizeof(wchar_t));
                    copy.FullDllName.MaximumLength = (USHORT)bytes;
                }
            }
            writechars(entry, &copy, sizeof(copy));
            return TRUE;
        }
        f = entry->InLoadOrderLinks.Flink;
        if (f == start) break;
    }
    return FALSE;
}

BOOL aidchangeclrmagic(void) {
    const char* clr = aidcurrentclrmodule();
    if (!clr) return FALSE;
    return aidchangemoduleinfo(clr, spoofimagemagic);
}
