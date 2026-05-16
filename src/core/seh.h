#ifndef novmseh
#define novmseh

#include <windows.h>

typedef int (*sehshell)(void);

BOOL safereadbyte(PVOID addr, BYTE* out);
BOOL safereadbytes(PVOID addr, void* out, SIZE_T sz);
BOOL safeexec(sehshell fn, int* outresult);

#endif
