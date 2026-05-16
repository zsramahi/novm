#ifndef novmhooks
#define novmhooks

#include <windows.h>

BOOL hookfunction(PVOID source, PVOID destination, BYTE original[6], BYTE hooked[6]);
void installuninstallhook(const BYTE code[6], PVOID fn);
BOOL installhookwinapi(const char* dll, const char* fn, PVOID destination, BYTE original[6], BYTE hooked[6], PVOID* outfn);
BOOL preventunauthorizedfp(BOOL printaccess, PVOID* whitelisted, int wcount, PVOID* blacklisted, int bcount);

#endif
