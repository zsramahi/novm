#ifndef novmmisc
#define novmmisc

#include <windows.h>

BOOL miscunsigneddriversallowed(BOOL viasyscall);
BOOL misctestsigneddriversallowed(BOOL viasyscall);
BOOL misckerneldebuggingenabled(BOOL viasyscall);
BOOL miscsecurebootenabled(BOOL viasyscall);
BOOL miscvbsenabled(void);
BOOL miscmemoryintegrityenabled(void);
BOOL miscloadedasdll(void);

#endif
