#include "hooks.h"
#include "../core/utils.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>

BOOL hookfunction(PVOID source, PVOID destination, BYTE original[6], BYTE hooked[6]) {
    if (!source || !destination) return FALSE;
    BYTE patch[6];
    patch[0] = 0x90;
    patch[1] = 0xE9;
#if defined(_WIN64)
    int64_t offset = (int64_t)((BYTE*)destination - (BYTE*)source) - 6;
    int32_t off32 = (int32_t)offset;
    memcpy(&patch[2], &off32, 4);
#else
    int32_t offset = (int32_t)((BYTE*)destination - (BYTE*)source) - 6;
    memcpy(&patch[2], &offset, 4);
#endif
    if (original) memcpy(original, source, 6);
    if (!copymem(source, patch, 6, TRUE)) return FALSE;
    if (hooked) memcpy(hooked, patch, 6);
    return TRUE;
}

void installuninstallhook(const BYTE code[6], PVOID fn) {
    if (!fn || !code) return;
    copymem(fn, code, 6, TRUE);
}

BOOL installhookwinapi(const char* dll, const char* fn, PVOID destination, BYTE original[6], BYTE hooked[6], PVOID* outfn) {
    if (!dll || !fn || !destination) return FALSE;
    PVOID source = (PVOID)exportaddrn(dll, fn);
    if (!source) return FALSE;
    if (outfn) *outfn = source;
    return hookfunction(source, destination, original, hooked);
}

BOOL preventunauthorizedfp(BOOL printaccess, PVOID* whitelisted, int wcount, PVOID* blacklisted, int bcount) {
    (void)printaccess;
    (void)whitelisted; (void)wcount;
    (void)blacklisted; (void)bcount;
    return FALSE;
}
