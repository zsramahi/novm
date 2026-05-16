# novm

A native C port of the original C# NoVM project. Detects virtual machines, sandboxes, debuggers, and injected code from a single Win32 binary with no managed runtime, no external dependencies beyond Windows itself, and no PDB-style symbol exposure.

The .NET version relied on reflection, the CLR, and dynamic delegate invocation. This rewrite replaces all of that with direct ntdll function pointers, hand-built syscall stubs, and a vectored-exception SEH shim, then statically links libgcc and libwinpthread so the resulting `novm.exe` only imports stock Windows DLLs.

## download

Grab the latest build from the [Releases](https://github.com/zsramahi/novm/releases) page. The current release ships `novm.exe` for x64 Windows.

## usage

Double-click `novm.exe` or run it from a terminal.

```
novm.exe
```

The program runs every detection in `main.c`, then opens a single message box.

- Real machine: `Real machine detected`
- Anything matched: `Sandbox detected:` followed by the names of every triggered check, one per line.

Exit code is always 0. The binary is graphical, not console-based, so it doesn't print to stdout.

## setup (build from source)

### prerequisites

- Windows 10 or newer (x64)
- MinGW-w64 with GCC 11+ (tested on GCC 13.2.0, x86_64-posix-seh)
- The MinGW `bin/` directory on `PATH`

The build script uses MinGW exclusively. MSVC is not supported because the codebase deliberately avoids `__try`/`__except` in favour of a portable VEH shim.

### build

From the repo root:

```
build.bat
```

This recursively compiles every `.c` under `src/` into `bin/intermediates/` and links the final binary at `bin/novm.exe`.

Toolchain flags:

- `-Wall -Wextra -O2 -std=c11`
- `-municode -DUNICODE -D_UNICODE -DCOBJMACROS -D_WIN32_WINNT=0x0601`
- `-static -mwindows`
- Linked libs: `user32 advapi32 ole32 oleaut32 wbemuuid psapi shlwapi`

### verify static linking

```
objdump -p bin\novm.exe | findstr "DLL Name"
```

Expected imports: `KERNEL32.dll`, `USER32.dll`, `ADVAPI32.dll`, `OLE32.dll`, `OLEAUT32.dll`, plus the universal CRT `api-ms-win-crt-*.dll` set. No `libwinpthread-1.dll`, no `libgcc_s_seh-1.dll`.

## project layout

```
recode/
  build.bat                gcc build script (recursive)
  src/
    main.c                 winmain entry, wires the active checks
    core/
      structs.h            peb, ldr, pe headers, mbi, context
      ntapi.h / .c         ntdll function pointer cache
      utils.h / .c         module/proc resolution, shellcode alloc, copymem, peb access, string helpers
      seh.h / .c           vectored exception handler + setjmp/longjmp shim used in place of msvc __try
    syscall/
      syscall.h / .c       per-build syscall numbers, build-tamper detection, syscall stub builder, public wrappers
    modules/
      antivm.h / .c        sandbox + hypervisor detection, cpu feature probes
      antidebug.h / .c     debugger presence, hardware bp, anti-attach, page guard
      antiinjection.h / .c thread origin scan, pe header spoofer, dll load policy
      hooks.h / .c         6-byte jmp-rel32 hook installer
      hooksdetection.h / .c prologue and guard-page hook scanners
      misc.h / .c          driver signing, kernel debugging, secure boot, vbs, hvci
```

## what it checks

`main.c` runs the following 12 anti-vm checks and reports any that fire:

- AnyRun (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` against known sandbox GUIDs)
- Triage (HKCU desktop wallpaper hash prefix match)
- QEMU (driver scan in `%SystemRoot%\System32`)
- Parallels (driver scan)
- Sandboxie (loaded `SbieDll.dll`)
- Comodo Sandbox (loaded `cmdvrt32/64.dll`)
- Cuckoo Sandbox (loaded `cuckoomon.dll`)
- Qihoo 360 Sandbox (loaded `SxIn.dll`)
- Blacklisted user names
- VMware / VirtualBox via WMI `Win32_ComputerSystem`
- VM-related driver files in System32 (`VBoxMouse.sys`, `vmmouse.sys`, etc) and standard install directories
- VM-related process names (`vboxservice`, `VGAuthService`, `vmusrvc`, `qemu-ga`)

The other modules are exposed as a library surface and are wired off by default. They include:

### antidebug

- `IsDebuggerPresent`
- PEB `BeingDebugged` direct read
- PEB `NtGlobalFlag` heap-debug bits
- `NtQueryInformationProcess` for `ProcessDebugFlags`, `ProcessDebugPort`, `ProcessDebugObjectHandle` (managed and direct-syscall paths)
- `NtClose` invalid-handle and protected-handle exceptions
- `DbgUiRemoteBreakin` / `DbgBreakPoint` patching
- Window title scan and foreground window scan against the usual debugger names
- `NtSetInformationThread(THREAD_HIDE_FROM_DEBUGGER)` across every thread
- GetTickCount and Sleep timing skew
- `OutputDebugString` last-error probe
- OllyDbg format-string crash trigger
- `DebugBreak` exception probe
- Hardware breakpoint scan via `NtGetContextThread` (Dr0–Dr7) on every thread
- Parent-process whitelist (`explorer.exe`, `cmd.exe`)
- `NtSetDebugFilterState` lockdown
- `PAGE_GUARD` execute probe

### antiinjection

- `SetProcessMitigationPolicy(ProcessSignaturePolicy)` to refuse non-Microsoft DLLs
- Thread-origin scan: every thread's `Win32StartAddress` must land in a `MEM_IMAGE`/`MEM_COMMIT` region inside a loaded module
- PEB-walking module info spoofer with selectable bits: base address, module name, entry point, size of image, number of sections, image magic, characteristics, PE signature, exec section name/raw size/raw pointer/characteristics/virtual size
- `aidchangeclrmagic` shortcut for the original CLR-targeted variant
- ImageBaseAddress vs main module base mismatch detection (process-hollowing canary)

### syscall

- Hand-written x64 (`mov r10,rcx; mov eax,N; syscall; ret`) and x86 stubs
- Per-build-number tables for `NtClose`, `NtQueryInformationProcess`, `NtQuerySystemInformation`, `NtQueryVirtualMemory`, `NtQueryInformationThread`
- Build number cross-checked across `RtlGetVersion`, WMI `Win32_OperatingSystem`, and the registry. Mismatches are flagged as tampered and the most consistent value is used
- Public wrappers that allocate, invoke, and free the stub per call

### hooks

- 6-byte trampoline (`0x90` + `jmp rel32`) installer / uninstaller
- WinAPI hook helper that resolves the export and patches it with the trampoline
- The CLR-only `EnsureNonNullMethodInfo` interceptor from the original is intentionally not ported — there is no managed runtime here. The native primitives are present and ready to be wired into anything that needs them

### hooks detection

- Prologue scan for `0xE9` / `0xFF` / `0x90` across known exports in `kernel32`, `kernelbase`, `ntdll`, `user32`, `win32u`
- Parameterised `hdtdetectinlinehooks` for arbitrary modules
- `PAGE_GUARD` scan over the same export set
- Self-module export prologue scan against the running exe

### misc

- Unsigned and test-signed driver allowance via `NtQuerySystemInformation`
- Kernel debugger active flag
- Secure Boot status
- VBS via WMI `Win32_EncryptableVolume`
- HVCI registry probe (`SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`)
- `IMAGE_FILE_DLL` self-check (the closest native analog to the original "invoked assembly" check)

## design notes

**SEH on MinGW.** GCC for MinGW-w64 doesn't support `__try`/`__except` syntax, so this project installs a vectored exception handler at first use. Inside `safeexec`, a `setjmp` snapshot is taken; on access violation, breakpoint, illegal instruction, or guard-page event, the VEH `longjmp`s back. `safereadbyte` validates with `VirtualQuery` first, then dereferences. This keeps the AVX/RDRAND/EFLAGS shellcode probes and the page-guard test working under gcc.

**Static linking.** `__thread` storage in `seh.c` would normally pull in `libwinpthread-1.dll` via emulated TLS. The build script passes `-static` so libgcc, libstdc++ machinery, and libwinpthread get baked into the binary. The end result imports only OS DLLs.

**No symbols.** Every internal helper uses single-word lowercase names (`llmodule`, `exportaddr`, `pebptr`, `safeexec`). No comments are kept in source. Strings are minimal and intentional.

**Module independence.** Each module under `src/modules/` only depends on `core/` and `syscall/`, never on its peers. You can drop a single `.c` into another project, pull in the matching headers from `core/`, and it will compile.

## license

MIT (or whatever the upstream NoVM license dictates — preserved in spirit). Use at your own risk; this is a research and hardening tool, not a security product.

## credits

- Original [NoVM](https://github.com/zsramahi/NoVM) C# implementation by zsramahi
- C port and recode by cyendd
