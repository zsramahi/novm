#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/ntapi.h"
#include "core/utils.h"
#include "syscall/syscall.h"
#include "modules/antivm.h"
#include "modules/antidebug.h"
#include "modules/antiinjection.h"
#include "modules/hooks.h"
#include "modules/hooksdetection.h"
#include "modules/misc.h"

typedef struct {
    const char* name;
    BOOL (*check)(void);
} avmcheckentry;

static BOOL avmw_anyrun(void)        { return avmanyrun(); }
static BOOL avmw_triage(void)        { return avmtriage(); }
static BOOL avmw_qemu(void)          { return avmqemu(); }
static BOOL avmw_parallels(void)     { return avmparallels(); }
static BOOL avmw_sandboxie(void)     { return avmsandboxie(); }
static BOOL avmw_comodo(void)        { return avmcomodo(); }
static BOOL avmw_cuckoo(void)        { return avmcuckoo(); }
static BOOL avmw_qihoo(void)         { return avmqihoo(); }
static BOOL avmw_blacklisted(void)   { return avmblacklistednames(); }
static BOOL avmw_vmwarevbox(void)    { return avmvmwarevbox(); }
static BOOL avmw_badfiles(void)      { return avmbadfiles(); }
static BOOL avmw_badprocs(void)      { return avmbadprocs(); }

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    (void)inst; (void)prev; (void)cmd; (void)show;
    srand((unsigned)time(NULL));
    ntapiload();
    syscallinit();
    buildnumber(FALSE, FALSE);

    static const avmcheckentry checks[] = {
        {"AnyRun",                &avmw_anyrun},
        {"Triage",                &avmw_triage},
        {"QEMU",                  &avmw_qemu},
        {"Parallels",             &avmw_parallels},
        {"Sandboxie",             &avmw_sandboxie},
        {"Comodo Sandbox",        &avmw_comodo},
        {"Cuckoo Sandbox",        &avmw_cuckoo},
        {"Qihoo 360 Sandbox",     &avmw_qihoo},
        {"Blacklisted Names",     &avmw_blacklisted},
        {"VMware/VirtualBox",     &avmw_vmwarevbox},
        {"Bad VM Files",          &avmw_badfiles},
        {"Bad VM Process Names",  &avmw_badprocs},
    };

    char body[2048];
    body[0] = 0;
    int hits = 0;
    for (size_t i = 0; i < sizeof(checks)/sizeof(checks[0]); i++) {
        if (checks[i].check()) {
            if (hits == 0) strcat(body, "Sandbox detected:\r\n");
            else strcat(body, "\r\n");
            strcat(body, checks[i].name);
            hits++;
        }
    }
    if (hits == 0) strcpy(body, "Real machine detected");

    MessageBoxA(NULL, body, "Result", MB_OK | MB_ICONWARNING);
    return 0;
}

int main(void) {
    return WinMain(GetModuleHandleW(NULL), NULL, GetCommandLineA(), SW_SHOWNORMAL);
}
