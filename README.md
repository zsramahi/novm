# NoVM

NoVM is a native Windows utility that detects virtual machines, sandboxes, debuggers, and injected code from a single self-contained binary. It runs a battery of host-environment checks and reports the result in a single message box.

The build is statically linked. The resulting executable depends only on stock Windows DLLs and the universal C runtime.

## Download

Latest builds are published on the [Releases](https://github.com/zsramahi/novm/releases) page. The current release ships `novm.exe` for x64 Windows.

## Usage

Run the executable directly:

```
novm.exe
```

NoVM evaluates every check wired into `main.c` and shows a single message box with the result.

- Real machine: `Real machine detected`
- One or more checks fired: `Sandbox detected:` followed by the name of each triggered check, one per line.

The process always exits with code 0. NoVM is a graphical binary and does not write to stdout.

## Build from source

### Prerequisites

- Windows 10 or newer (x64)
- MinGW-w64 with GCC 11 or newer (tested on 13.2.0, x86_64-posix-seh)
- The MinGW `bin` directory on `PATH`

The build script targets MinGW exclusively. MSVC is not supported because the codebase uses a portable vectored exception handler in place of `__try` / `__except`.

### Build

From the repository root:

```
build.bat
```

`build.bat` recursively compiles every `.c` file under `src/` into `bin/intermediates/` and links the final binary at `bin/novm.exe`.

Toolchain configuration:

- `-Wall -Wextra -O2 -std=c11`
- `-municode -DUNICODE -D_UNICODE -DCOBJMACROS -D_WIN32_WINNT=0x0601`
- `-static -mwindows`
- Linked libraries: `user32 advapi32 ole32 oleaut32 wbemuuid psapi shlwapi`

### Verify static linking

```
objdump -p bin\novm.exe | findstr "DLL Name"
```

Expected imports: `KERNEL32.dll`, `USER32.dll`, `ADVAPI32.dll`, `OLE32.dll`, `OLEAUT32.dll`, plus the universal CRT `api-ms-win-crt-*.dll` set. There should be no `libwinpthread-1.dll` or `libgcc_s_seh-1.dll` entries.

## Project layout

```
build.bat                    GCC build script (recursive)
src/
  main.c                     WinMain entry; wires the active checks
  core/
    structs.h                PEB, LDR, PE headers, MEMORY_BASIC_INFORMATION, CONTEXT
    ntapi.h / .c             ntdll function pointer cache
    utils.h / .c             Module and procedure resolution, shellcode allocation, memory copy, PEB access, string helpers
    seh.h / .c               Vectored exception handler with setjmp / longjmp shim
  syscall/
    syscall.h / .c           Per-build syscall numbers, build-tamper detection, syscall stub builder, public wrappers
  modules/
    antivm.h / .c            Sandbox and hypervisor detection, CPU feature probes
    antidebug.h / .c         Debugger presence checks, hardware breakpoints, anti-attach, page guard
    antiinjection.h / .c     Thread origin scan, PE header spoofer, DLL load policy
    hooks.h / .c             6-byte JMP rel32 hook installer
    hooksdetection.h / .c    Prologue and guard-page hook scanners
    misc.h / .c              Driver signing, kernel debugging, Secure Boot, VBS, HVCI
```

## Detection coverage

`main.c` runs the following anti-VM checks and reports any that match:

- AnyRun (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` against known sandbox GUIDs)
- Triage (HKCU desktop wallpaper hash prefix match)
- QEMU (driver scan in `%SystemRoot%\System32`)
- Parallels (driver scan)
- Sandboxie (loaded `SbieDll.dll`)
- Comodo Sandbox (loaded `cmdvrt32.dll` or `cmdvrt64.dll`)
- Cuckoo Sandbox (loaded `cuckoomon.dll`)
- Qihoo 360 Sandbox (loaded `SxIn.dll`)
- Blacklisted user names
- VMware and VirtualBox via WMI `Win32_ComputerSystem`
- VM-related driver files in `System32` and standard install directories
- VM-related process names (`vboxservice`, `VGAuthService`, `vmusrvc`, `qemu-ga`)

The remaining modules are exposed as a library surface and are wired off by default.

### antidebug

- `IsDebuggerPresent`
- PEB `BeingDebugged` direct read
- PEB `NtGlobalFlag` heap-debug bits
- `NtQueryInformationProcess` for `ProcessDebugFlags`, `ProcessDebugPort`, `ProcessDebugObjectHandle` (managed and direct-syscall paths)
- `NtClose` invalid-handle and protected-handle exception probes
- `DbgUiRemoteBreakin` and `DbgBreakPoint` patching
- Window title and foreground window scans against common debugger names
- `NtSetInformationThread(THREAD_HIDE_FROM_DEBUGGER)` across every thread
- `GetTickCount` and `Sleep` timing skew
- `OutputDebugString` last-error probe
- OllyDbg format-string crash trigger
- `DebugBreak` exception probe
- Hardware breakpoint scan via `NtGetContextThread` (Dr0 through Dr7) on every thread
- Parent-process whitelist (`explorer.exe`, `cmd.exe`)
- `NtSetDebugFilterState` lockdown
- `PAGE_GUARD` execute probe

### antiinjection

- `SetProcessMitigationPolicy(ProcessSignaturePolicy)` to refuse non-Microsoft DLLs
- Thread-origin scan: every thread's `Win32StartAddress` must reside in a `MEM_IMAGE` and `MEM_COMMIT` region inside a loaded module
- PEB-walking module info spoofer with selectable bits: base address, module name, entry point, size of image, number of sections, image magic, characteristics, PE signature, executable section name and raw size and raw pointer and characteristics and virtual size
- ImageBaseAddress vs main module base mismatch detection (process-hollowing canary)

### syscall

- Hand-written x64 (`mov r10, rcx ; mov eax, N ; syscall ; ret`) and x86 stubs
- Per-build-number tables for `NtClose`, `NtQueryInformationProcess`, `NtQuerySystemInformation`, `NtQueryVirtualMemory`, `NtQueryInformationThread`
- Build number cross-checked across `RtlGetVersion`, WMI `Win32_OperatingSystem`, and the registry. Mismatches are flagged as tampered and the most consistent value is used
- Public wrappers that allocate, invoke, and free the stub per call

### hooks

- 6-byte trampoline (`0x90` followed by `JMP rel32`) installer and uninstaller
- WinAPI hook helper that resolves the export and patches it with the trampoline

### hooks detection

- Prologue scan for `0xE9`, `0xFF`, `0x90` across known exports in `kernel32`, `kernelbase`, `ntdll`, `user32`, `win32u`
- Parameterised inline-hook scanner for arbitrary modules
- `PAGE_GUARD` scan over the same export set
- Self-module export prologue scan

### misc

- Unsigned and test-signed driver allowance via `NtQuerySystemInformation`
- Kernel debugger active flag
- Secure Boot status
- Virtualization-Based Security via WMI `Win32_EncryptableVolume`
- HVCI registry probe (`SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`)
- `IMAGE_FILE_DLL` self-check

## Design notes

**Structured exception handling on MinGW.** GCC for MinGW-w64 does not support `__try` / `__except` syntax. NoVM installs a vectored exception handler at first use. Inside `safeexec`, a `setjmp` snapshot is taken; on access violation, breakpoint, illegal instruction, or guard-page event, the handler `longjmp`s back. `safereadbyte` validates with `VirtualQuery` first, then dereferences. This keeps the AVX, RDRAND, and EFLAGS shellcode probes and the page-guard test working under GCC.

**Static linking.** `__thread` storage in `seh.c` would normally pull in `libwinpthread-1.dll` via emulated TLS. The build script passes `-static`, which embeds libgcc, libstdc++ machinery, and libwinpthread into the binary. The end result imports only operating-system DLLs.

**Module independence.** Each module under `src/modules/` depends only on `core/` and `syscall/`, never on its peers. A single `.c` file can be lifted into another project alongside the matching headers in `core/` and will compile.

## License

Use at your own risk. NoVM is a research and hardening tool, not a security product.
