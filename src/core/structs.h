#ifndef novmstructs
#define novmstructs

#include <windows.h>
#include <stdint.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000L
#endif

typedef LONG NTSTATUS;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} unicodestring;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ansistring;

typedef struct {
    LONG     Length;
    HANDLE   RootDirectory;
    PVOID    ObjectName;
    ULONG    Attributes;
    PVOID    SecurityDescriptor;
    PVOID    SecurityQualityOfService;
} objectattributes;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} clientid;

typedef struct {
    PVOID  Reserved1;
    PVOID  PebBaseAddress;
    PVOID  Reserved2_0;
    PVOID  Reserved2_1;
    ULONG_PTR UniqueProcessId;
    PVOID  InheritedFromUniqueProcessId;
} processbasicinformation;

typedef struct {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} systemcodeintegrityinformation;

typedef struct {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} systemkerneldebuggerinformation;

typedef struct {
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootCapable;
} systemsecurebootinformation;

typedef struct {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
} memorybasicinformation;

typedef struct {
    DWORD MicrosoftSignedOnly;
} mitigationsigpolicy;

typedef struct {
    PVOID Flink;
    PVOID Blink;
} listentry;

typedef struct {
    ULONG     Length;
    BYTE      Initialized;
    PVOID     SsHandle;
    listentry InLoadOrderModuleList;
    listentry InMemoryOrderModuleList;
    listentry InInitializationOrderModuleList;
    PVOID     EntryInProgress;
} pebldrdata;

typedef struct {
    listentry      InLoadOrderLinks;
    listentry      InMemoryOrderLinks;
    listentry      InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    unicodestring  FullDllName;
    unicodestring  BaseDllName;
} ldrdatatableentry;

typedef struct {
    BYTE  InheritedAddressSpace;
    BYTE  ReadImageFileExecOptions;
    BYTE  BeingDebugged;
    BYTE  SpareBool;
#ifdef _WIN64
    BYTE  Padding[4];
#endif
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
#ifdef _WIN64
    ULONG Padding2;
#endif
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
#ifdef _WIN64
    ULONG Padding3;
#endif
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
} peb;

typedef struct {
    int   dwOSVersionInfoSize;
    int   dwMajorVersion;
    int   dwMinorVersion;
    int   dwBuildNumber;
    int   dwPlatformId;
    WCHAR szCSDVersion[128];
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    BYTE   wProductType;
    BYTE   wReserved;
} osversioninfoex;

typedef struct {
    DWORD  vkCode;
    DWORD  scanCode;
    DWORD  flags;
    DWORD  time;
    ULONG_PTR dwExtraInfo;
} kbdllhookstruct;

#endif
