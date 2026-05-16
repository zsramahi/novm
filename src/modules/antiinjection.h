#ifndef novmantiinjection
#define novmantiinjection

#include <windows.h>

#define spoofbaseaddress             (1u << 0)
#define spoofmodulename              (1u << 1)
#define spoofentrypoint              (1u << 2)
#define spoofsizeofimage             (1u << 3)
#define spoofnumberofsections        (1u << 4)
#define spoofimagemagic              (1u << 5)
#define spoofnotexenordll            (1u << 6)
#define spoofpesignature             (1u << 7)
#define spoofexecsectionname         (1u << 8)
#define spoofexecsectionrawsize      (1u << 9)
#define spoofexecsectionrawpointer   (1u << 10)
#define spoofclearexecchars          (1u << 11)
#define spoofexecsectionvirtualsize  (1u << 12)

const char* aidlloadpolicy(void);
BOOL aidcheckinjectedthreads(BOOL viasyscall, BOOL checkmodulerange);
BOOL aidchangemoduleinfo(const char* modulename, DWORD flags);
BOOL aidchangeclrmagic(void);
BOOL aidsuspiciousbase(void);
const char* aidcurrentclrmodule(void);

#endif
