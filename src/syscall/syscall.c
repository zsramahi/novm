#include "syscall.h"
#include "../core/utils.h"
#include "../core/ntapi.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wbemidl.h>
#include <objbase.h>
#include <oleauto.h>

typedef struct {
    const char* build;
    BYTE        num;
} buildmap;

typedef struct {
    const char*    name;
    BYTE           common;
    const buildmap* maps;
    int            count;
} syscallentry;

static const buildmap mapntclose[] = {
    {"7601", 0xF}, {"9200", 0xF}, {"9600", 0xF}, {"10240", 0xF}, {"10586", 0xF},
    {"14393", 0xF}, {"15063", 0xF}, {"16299", 0xF}, {"17134", 0xF}, {"17763", 0xF},
    {"18362", 0xF}, {"18363", 0xF}, {"19041", 0xF}, {"19042", 0xF}, {"19043", 0xF},
    {"19044", 0xF}, {"19045", 0xF}, {"22621", 0xF}, {"22631", 0xF}, {"25915", 0xF}, {"26000", 0xF}
};
static const buildmap mapntqip[] = {
    {"7601", 0x16}, {"9200", 0x17}, {"9600", 0x18}, {"10240", 0x19}, {"10586", 0x19},
    {"14393", 0x19}, {"15063", 0x19}, {"16299", 0x19}, {"17134", 0x19}, {"17763", 0x19},
    {"18362", 0x19}, {"18363", 0x19}, {"19041", 0x19}, {"19042", 0x19}, {"19043", 0x19},
    {"19044", 0x19}, {"19045", 0x19}, {"22621", 0x19}, {"22631", 0x19}, {"25915", 0x19}, {"26000", 0x19}
};
static const buildmap mapntqsi[] = {
    {"7601", 0x33}, {"9200", 0x34}, {"9600", 0x35}, {"10240", 0x36}, {"10586", 0x36},
    {"14393", 0x36}, {"15063", 0x36}, {"16299", 0x36}, {"17134", 0x36}, {"17763", 0x36},
    {"18362", 0x36}, {"18363", 0x36}, {"19041", 0x36}, {"19042", 0x36}, {"19043", 0x36},
    {"19044", 0x36}, {"19045", 0x36}, {"22621", 0x36}, {"22631", 0x36}, {"25915", 0x36}, {"26000", 0x36}
};
static const buildmap mapntqvm[] = {
    {"7601", 0x20}, {"9200", 0x21}, {"9600", 0x22}, {"10240", 0x23}, {"10586", 0x23},
    {"14393", 0x23}, {"15063", 0x23}, {"16299", 0x23}, {"17134", 0x23}, {"17763", 0x23},
    {"18362", 0x23}, {"18363", 0x23}, {"19041", 0x23}, {"19042", 0x23}, {"19043", 0x23},
    {"19044", 0x23}, {"19045", 0x23}, {"22621", 0x23}, {"22631", 0x23}, {"25915", 0x23}, {"26000", 0x23}
};
static const buildmap mapntqit[] = {
    {"7601", 0x22}, {"9200", 0x23}, {"9600", 0x24}, {"10240", 0x25}, {"10586", 0x25},
    {"14393", 0x25}, {"15063", 0x25}, {"16299", 0x25}, {"17134", 0x25}, {"17763", 0x25},
    {"18362", 0x25}, {"18363", 0x25}, {"19041", 0x25}, {"19042", 0x25}, {"19043", 0x25},
    {"19044", 0x25}, {"19045", 0x25}, {"22621", 0x25}, {"22631", 0x25}, {"25915", 0x25}, {"26000", 0x25}
};

static const syscallentry entries[] = {
    {"NtClose",                   0xF,  mapntclose, sizeof(mapntclose)/sizeof(mapntclose[0])},
    {"NtQueryInformationProcess", 0x19, mapntqip,   sizeof(mapntqip)/sizeof(mapntqip[0])},
    {"NtQuerySystemInformation",  0x36, mapntqsi,   sizeof(mapntqsi)/sizeof(mapntqsi[0])},
    {"NtQueryVirtualMemory",      0x23, mapntqvm,   sizeof(mapntqvm)/sizeof(mapntqvm[0])},
    {"NtQueryInformationThread",  0x25, mapntqit,   sizeof(mapntqit)/sizeof(mapntqit[0])},
};

static char        cachedbuild[32] = {0};
static BOOL        showedbefore    = FALSE;
BOOL syscalltampered = FALSE;

static int strieq(const char* a, const char* b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        int ca = tolower((unsigned char)*a), cb = tolower((unsigned char)*b);
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

void syscallinit(void) {
    cachedbuild[0] = 0;
    showedbefore = FALSE;
    syscalltampered = FALSE;
}

BYTE commonsyscallbyte(const char* fn) {
    for (size_t i = 0; i < sizeof(entries)/sizeof(entries[0]); i++) {
        if (strieq(entries[i].name, fn)) return entries[i].common;
    }
    return 0;
}

BYTE extractsyscallbyte(const BYTE* bytes, SIZE_T len, const char* fn) {
    BOOL retfound = FALSE;
    for (SIZE_T i = 0; i + 1 < len; i++) {
        if (bytes[i] == 0xB8) {
            if ((fn && retfound) || bytes[0] == 0xE9 || bytes[0] == 0x90) {
                BYTE c = commonsyscallbyte(fn);
                if (c != 0) return c;
            }
            return bytes[i + 1];
        }
        if (bytes[i] == 0xC3 || bytes[i] == 0xC2) retfound = TRUE;
    }
    return 0;
}

BYTE extractretvalue(const BYTE* bytes, SIZE_T len) {
    for (SIZE_T i = 0; i + 1 < len; i++) {
        if (bytes[i] == 0xC2) return bytes[i + 1];
    }
    return 0;
}

static const char* buildreg(void) {
    static char buf[32];
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return NULL;
    DWORD type = 0, sz = sizeof(buf);
    LONG r = RegQueryValueExA(key, "CurrentBuildNumber", NULL, &type, (LPBYTE)buf, &sz);
    RegCloseKey(key);
    if (r != ERROR_SUCCESS) return NULL;
    return buf;
}

static const char* buildwinapi(void) {
    static char buf[32];
    if (!rtlgetversion) return NULL;
    osversioninfoex vi = {0};
    vi.dwOSVersionInfoSize = (int)sizeof(vi);
    if (rtlgetversion(&vi) != STATUS_SUCCESS) return NULL;
    sprintf(buf, "%d", vi.dwBuildNumber);
    return buf;
}

static const char* buildwmi(void) {
    static char buf[32];
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL inited = SUCCEEDED(hr);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return NULL;
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    IWbemLocator* loc = NULL;
    if (FAILED(CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&loc)) || !loc) {
        if (inited) CoUninitialize();
        return NULL;
    }
    IWbemServices* svc = NULL;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    HRESULT cr = loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL, &svc);
    SysFreeString(ns);
    loc->lpVtbl->Release(loc);
    if (FAILED(cr) || !svc) {
        if (inited) CoUninitialize();
        return NULL;
    }
    CoSetProxyBlanket((IUnknown*)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT BuildNumber FROM Win32_OperatingSystem");
    IEnumWbemClassObject* en = NULL;
    HRESULT er = svc->lpVtbl->ExecQuery(svc, lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en);
    SysFreeString(lang);
    SysFreeString(query);
    const char* result = NULL;
    if (SUCCEEDED(er) && en) {
        IWbemClassObject* obj = NULL;
        ULONG ret = 0;
        if (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &ret) == S_OK && obj) {
            VARIANT v; VariantInit(&v);
            if (obj->lpVtbl->Get(obj, L"BuildNumber", 0, &v, NULL, NULL) == S_OK) {
                if (v.vt == VT_BSTR && v.bstrVal) {
                    int len = WideCharToMultiByte(CP_ACP, 0, v.bstrVal, -1, buf, sizeof(buf), NULL, NULL);
                    if (len > 0) result = buf;
                }
                VariantClear(&v);
            }
            obj->lpVtbl->Release(obj);
        }
        en->lpVtbl->Release(en);
    }
    svc->lpVtbl->Release(svc);
    if (inited) CoUninitialize();
    return result;
}

static BOOL istampered(const char* a, const char* b, const char* c) {
    if (!a || !b || !c) return TRUE;
    if (strcmp(a, b) != 0) return TRUE;
    if (strcmp(b, c) != 0) return TRUE;
    return FALSE;
}

static const char* mostmatching(const char* a, const char* b, const char* c) {
    if (!syscalltampered) return a ? a : (b ? b : c);
    if (a && b && strcmp(a, b) == 0) return a;
    if (a && c && strcmp(a, c) == 0) return a;
    if (b && c && strcmp(b, c) == 0) return b;
    return a ? a : (b ? b : c);
}

const char* buildnumber(BOOL exitontamper, BOOL onlyshowontamper) {
    if (cachedbuild[0]) return cachedbuild;
    const char* api = buildwinapi();
    const char* wmi = buildwmi();
    const char* reg = buildreg();
    if (istampered(api, wmi, reg)) {
        syscalltampered = TRUE;
        if (onlyshowontamper && !showedbefore) {
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO ci = {0};
            WORD orig = 0;
            if (GetConsoleScreenBufferInfo(h, &ci)) {
                orig = ci.wAttributes;
                SetConsoleTextAttribute(h, FOREGROUND_RED);
            }
            const char* msg = "\nThe build number may have been tampered with. Falling back to a best-match build...\n";
            DWORD w = 0;
            WriteFile(h, msg, (DWORD)strlen(msg), &w, NULL);
            if (orig) SetConsoleTextAttribute(h, orig);
            showedbefore = TRUE;
        } else if (exitontamper) {
            forceexit();
        }
    }
    const char* m = mostmatching(api, wmi, reg);
    if (m) {
        strncpy(cachedbuild, m, sizeof(cachedbuild) - 1);
        cachedbuild[sizeof(cachedbuild) - 1] = 0;
    }
    return cachedbuild[0] ? cachedbuild : NULL;
}

BOOL buildnumbersaved(void) {
    const char* b = cachedbuild[0] ? cachedbuild : buildnumber(FALSE, FALSE);
    if (!b) return FALSE;
    for (size_t i = 0; i < sizeof(entries)/sizeof(entries[0]); i++) {
        for (int j = 0; j < entries[i].count; j++) {
            if (strieq(entries[i].maps[j].build, b)) return TRUE;
        }
    }
    return FALSE;
}

PVOID syscallcode(const char* dll, const char* fn) {
    if (!cachedbuild[0]) buildnumber(FALSE, FALSE);
    BOOL extract = TRUE;
    BYTE num = 0;
    for (size_t i = 0; i < sizeof(entries)/sizeof(entries[0]); i++) {
        if (strieq(entries[i].name, fn)) {
            for (int j = 0; j < entries[i].count; j++) {
                if (strieq(entries[i].maps[j].build, cachedbuild)) {
                    extract = FALSE;
                    num = entries[i].maps[j].num;
                    break;
                }
            }
            if (extract) num = entries[i].common;
            break;
        }
    }
    FARPROC addr = exportaddrn(dll, fn);
    if (!addr) return NULL;
    BYTE buf[40] = {0};
    memcpy(buf, addr, sizeof(buf));
    if (extract) {
        BYTE n = extractsyscallbyte(buf, sizeof(buf), fn);
        if (n != 0) num = n;
    }
    if (num == 0) return NULL;
#if defined(_WIN64)
    BYTE code[] = {
        0x49, 0x89, 0xCA,
        0xB8, num, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    };
    return allocshell(code, sizeof(code));
#else
    BYTE retval = extractretvalue(buf, sizeof(buf));
    BYTE code[] = {
        0xB8, num, 0x00, 0x00, 0x00,
        0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,
        0xC2, retval, 0x00
    };
    return allocshell(code, sizeof(code));
#endif
}

typedef NTSTATUS (NTAPI *fnclose)(HANDLE);
typedef NTSTATUS (NTAPI *fnqip1)(HANDLE, ULONG, ULONG*, ULONG, ULONG*);
typedef NTSTATUS (NTAPI *fnqip2)(HANDLE, ULONG, PVOID*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnqip3)(HANDLE, ULONG, processbasicinformation*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnqsi)(ULONG, void*, ULONG, ULONG*);
typedef NTSTATUS (NTAPI *fnqvm)(HANDLE, PVOID, ULONG, void*, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *fnqit)(HANDLE, ULONG, PVOID*, ULONG, PVOID);

NTSTATUS sysntclose(HANDLE h) {
    PVOID s = syscallcode("ntdll.dll", "NtClose");
    if (!s) return -1;
    NTSTATUS r = ((fnclose)s)(h);
    freeshell(s);
    return r;
}

NTSTATUS sysntqueryinformationprocess1(ULONG cls, ULONG* info, ULONG sz, ULONG* retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQueryInformationProcess");
    if (!s) return -1;
    NTSTATUS r = ((fnqip1)s)((HANDLE)(LONG_PTR)-1, cls, info, sz, retlen);
    freeshell(s);
    return r;
}

NTSTATUS sysntqueryinformationprocess2(ULONG cls, PVOID* info, ULONG sz, ULONG retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQueryInformationProcess");
    if (!s) return -1;
    NTSTATUS r = ((fnqip2)s)((HANDLE)(LONG_PTR)-1, cls, info, sz, retlen);
    freeshell(s);
    return r;
}

NTSTATUS sysntqueryinformationprocess3(ULONG cls, processbasicinformation* info, ULONG sz, ULONG retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQueryInformationProcess");
    if (!s) return -1;
    NTSTATUS r = ((fnqip3)s)((HANDLE)(LONG_PTR)-1, cls, info, sz, retlen);
    freeshell(s);
    return r;
}

NTSTATUS sysntquerysysteminfocodeintegrity(ULONG cls, systemcodeintegrityinformation* info, ULONG sz, ULONG* retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQuerySystemInformation");
    if (!s) return -1;
    NTSTATUS r = ((fnqsi)s)(cls, info, sz, retlen);
    freeshell(s);
    return r;
}

NTSTATUS sysntquerysysteminfokerneldebug(ULONG cls, systemkerneldebuggerinformation* info, ULONG sz, ULONG* retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQuerySystemInformation");
    if (!s) return -1;
    NTSTATUS r = ((fnqsi)s)(cls, info, sz, retlen);
    freeshell(s);
    return r;
}

NTSTATUS sysntquerysysteminfosecureboot(ULONG cls, systemsecurebootinformation* info, ULONG sz, ULONG* retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQuerySystemInformation");
    if (!s) return -1;
    NTSTATUS r = ((fnqsi)s)(cls, info, sz, retlen);
    freeshell(s);
    return r;
}

NTSTATUS sysntqueryvirtualmemory(HANDLE h, PVOID base, ULONG cls, void* info, SIZE_T sz, PSIZE_T retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQueryVirtualMemory");
    if (!s) return -1;
    NTSTATUS r = ((fnqvm)s)(h, base, cls, info, sz, retlen);
    freeshell(s);
    return r;
}

NTSTATUS sysntqueryinformationthread(HANDLE h, ULONG cls, PVOID* info, ULONG sz, PVOID retlen) {
    PVOID s = syscallcode("ntdll.dll", "NtQueryInformationThread");
    if (!s) return -1;
    NTSTATUS r = ((fnqit)s)(h, cls, info, sz, retlen);
    freeshell(s);
    return r;
}
