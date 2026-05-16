#include "misc.h"
#include "../core/utils.h"
#include "../core/structs.h"
#include "../core/ntapi.h"
#include "../syscall/syscall.h"
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <stdio.h>
#include <string.h>

#define CODEINTEGRITY_OPTION_ENABLED   0x01
#define CODEINTEGRITY_OPTION_TESTSIGN  0x02

BOOL miscunsigneddriversallowed(BOOL viasyscall) {
    systemcodeintegrityinformation info = {0};
    info.Length = sizeof(info);
    ULONG retlen = 0;
    NTSTATUS s;
    if (viasyscall) s = sysntquerysysteminfocodeintegrity(0x67, &info, sizeof(info), &retlen);
    else if (ntquerysysteminformation) s = ntquerysysteminformation(0x67, &info, sizeof(info), &retlen);
    else return TRUE;
    if (s == STATUS_SUCCESS && retlen == sizeof(info)) {
        if (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) return FALSE;
    }
    return TRUE;
}

BOOL misctestsigneddriversallowed(BOOL viasyscall) {
    systemcodeintegrityinformation info = {0};
    info.Length = sizeof(info);
    ULONG retlen = 0;
    NTSTATUS s;
    if (viasyscall) s = sysntquerysysteminfocodeintegrity(0x67, &info, sizeof(info), &retlen);
    else if (ntquerysysteminformation) s = ntquerysysteminformation(0x67, &info, sizeof(info), &retlen);
    else return FALSE;
    if (s == STATUS_SUCCESS && retlen == sizeof(info)) {
        return (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) ? TRUE : FALSE;
    }
    return FALSE;
}

BOOL misckerneldebuggingenabled(BOOL viasyscall) {
    systemkerneldebuggerinformation info;
    info.KernelDebuggerEnabled = FALSE;
    info.KernelDebuggerNotPresent = TRUE;
    ULONG retlen = 0;
    NTSTATUS s;
    if (viasyscall) s = sysntquerysysteminfokerneldebug(0x23, &info, sizeof(info), &retlen);
    else if (ntquerysysteminformation) s = ntquerysysteminformation(0x23, &info, sizeof(info), &retlen);
    else return FALSE;
    if (s == STATUS_SUCCESS && retlen == sizeof(info)) {
        if (info.KernelDebuggerEnabled || !info.KernelDebuggerNotPresent) return TRUE;
    }
    return FALSE;
}

BOOL miscsecurebootenabled(BOOL viasyscall) {
    systemsecurebootinformation info = {0};
    ULONG retlen = 0;
    NTSTATUS s;
    if (viasyscall) s = sysntquerysysteminfosecureboot(0x91, &info, sizeof(info), &retlen);
    else if (ntquerysysteminformation) s = ntquerysysteminformation(0x91, &info, sizeof(info), &retlen);
    else return FALSE;
    if (s == STATUS_SUCCESS) return info.SecureBootEnabled ? TRUE : FALSE;
    return FALSE;
}

BOOL miscvbsenabled(void) {
    BOOL coinit = FALSE;
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) coinit = TRUE;
    else if (hr != RPC_E_CHANGED_MODE) return FALSE;
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    IWbemLocator* loc = NULL;
    if (FAILED(CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&loc)) || !loc) {
        if (coinit) CoUninitialize();
        return FALSE;
    }
    BSTR ns = SysAllocString(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption");
    IWbemServices* svc = NULL;
    HRESULT cr = loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL, &svc);
    SysFreeString(ns);
    loc->lpVtbl->Release(loc);
    if (FAILED(cr) || !svc) {
        if (coinit) CoUninitialize();
        return FALSE;
    }
    CoSetProxyBlanket((IUnknown*)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'");
    IEnumWbemClassObject* en = NULL;
    BOOL hit = FALSE;
    if (SUCCEEDED(svc->lpVtbl->ExecQuery(svc, lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en)) && en) {
        IWbemClassObject* obj = NULL;
        ULONG ret = 0;
        while (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &ret) == S_OK && obj) {
            VARIANT v; VariantInit(&v);
            if (obj->lpVtbl->Get(obj, L"ProtectionStatus", 0, &v, NULL, NULL) == S_OK) {
                if ((v.vt == VT_I4 && v.lVal == 1) || (v.vt == VT_UI4 && v.ulVal == 1)) hit = TRUE;
                VariantClear(&v);
            }
            obj->lpVtbl->Release(obj);
            if (hit) break;
        }
        en->lpVtbl->Release(en);
    }
    SysFreeString(lang); SysFreeString(query);
    svc->lpVtbl->Release(svc);
    if (coinit) CoUninitialize();
    return hit;
}

BOOL miscmemoryintegrityenabled(void) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return FALSE;
    DWORD type = 0, val = 0, sz = sizeof(val);
    LONG r = RegQueryValueExA(key, "Enabled", NULL, &type, (LPBYTE)&val, &sz);
    RegCloseKey(key);
    return (r == ERROR_SUCCESS && val == 1);
}

BOOL miscloadedasdll(void) {
    HMODULE main = GetModuleHandleW(NULL);
    if (!main) return FALSE;
    BYTE* base = (BYTE*)main;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    return (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;
}
