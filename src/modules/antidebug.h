#ifndef novmantidebug
#define novmantidebug

#include <windows.h>

BOOL adbinvalidhandle(BOOL viasyscall);
BOOL adbprotectedhandle(BOOL viasyscall);
BOOL adbisdebuggerpresent(void);
BOOL adbbeingdebugged(void);
BOOL adbntglobalflag(void);
BOOL adbprocessdebugflags(BOOL viasyscall);
BOOL adbprocessdebugport(BOOL viasyscall);
BOOL adbprocessdebugobjecthandle(BOOL viasyscall);
const char* adbantiattach(void);
BOOL adbfindwindow(void);
BOOL adbforegroundwindow(void);
const char* adbhidethreads(void);
BOOL adbticktiming(void);
BOOL adboutputdebug(void);
void adbollyformatexploit(void);
BOOL adbdebugbreak(void);
BOOL adbhardwarebreakpoints(void);
BOOL adbparentprocess(BOOL viasyscall);
BOOL adbsetdebugfilterstate(void);
BOOL adbpageguard(void);

#endif
