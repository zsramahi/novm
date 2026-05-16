#ifndef novmhooksdetection
#define novmhooksdetection

#include <windows.h>

BOOL hdtdetecthooks(void);
BOOL hdtdetectinlinehooks(const char* modulename, const char* const* fns, int count);
BOOL hdtdetectguardpagehook(PVOID fn, BOOL viasyscall);
BOOL hdtdetectguardpagehooks(BOOL viasyscall);
BOOL hdtdetectselfhooks(void);

#endif
