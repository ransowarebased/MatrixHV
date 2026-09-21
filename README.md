# MatrixHV

MatrixHV is an Intel VT-x pre-boot hypervisor written in Rust for the
`x86_64-unknown-uefi` target. It starts under UEFI, establishes a resident L0
VMX environment on the available processors, and continues the Windows boot
path under EPT-backed virtualization.

## Current Scope

- Intel VMX capability validation and per-CPU VMX regions.
- Resident BSP and AP virtualization across UEFI-to-Windows transitions.
- EPT-backed guest execution with CPUID, MSR, XSETBV, VMCALL, and VMX-exit
  handling.
- Per-vCPU nested VMX state with controlled VMXON, VMXOFF, VMCLEAR, VMPTRLD,
  VMPTRST, VMREAD, and VMWRITE emulation.
- Serial observability for boot phases, resident state, VM exits, nested state,
  and failure conditions.

Nested VMX remains deliberately hidden from ordinary guest CPUID queries until
the instruction surface is complete enough to host an L1 hypervisor safely.

## Repository Layout

```text
MatrixHV/
|-- build.rs                  Build-time configuration validation and embedding
|-- scripts/                  Build, image, configuration, and packaging tools
|-- asm/                      AP startup assembly
|-- src/
|   |-- main.rs               UEFI entry point
|   |-- arch/x86_64/
|   |   |-- registers.rs      CPUID, MSR, control-register, and CPU primitives
|   |   `-- segmentation.rs   Segment and descriptor-table state
|   |-- boot/
|   |   |-- config.rs         Embedded configuration format and parser
|   |   |-- memory_map.rs     UEFI memory-map inspection
|   |   `-- services.rs       Boot environment and Windows loader integration
|   |-- core/
|   |   |-- vt_controls.rs    VM-execution, entry, and exit controls
|   |   |-- vt_entry.rs       VM-entry probes and state transitions
|   |   |-- vt_ept.rs         Extended Page Table construction
|   |   |-- vt_exits.rs       VM-exit decoding and dispatch support
|   |   |-- vt_resident.rs    Resident boot runtime and nested dispatch
|   |   |-- vt_state.rs       Guest and host VMCS state
|   |   |-- vt_vmcs.rs        VMCS lifecycle and access
|   |   |-- vt_vmcs_fields.rs VMCS field encodings
|   |   `-- vt_vmxon.rs       VMXON lifecycle
|   |-- guest/                Firmware probe and boot-vCPU orchestration
|   |-- memory/               Paging and resident-memory management
|   |-- nested/
|   |   |-- mod.rs            Nested VMX module surface
|   |   |-- capabilities.rs   Virtual capability and CPUID contracts
|   |   |-- state.rs          Per-vCPU nested operation state
|   |   `-- vmcs.rs           VMCS12 state, encodings, exit reasons, and instruction errors
|   |-- runtime/              Serial logging and runtime support
|   `-- smp/                  Topology, per-CPU state, and AP startup
`-- tests/nested.rs           Host-runnable nested-state contract tests
```

The nested subsystem is intentionally limited to these four cohesive source
files. New nested behavior belongs in an existing module unless it establishes
a genuinely distinct responsibility.

## Build and Test

Build artifacts must be written below `D:\Projetos\MatrixHV\builds`.

```powershell
cargo fmt -- --check
cargo check --target x86_64-unknown-uefi
cargo clippy --target x86_64-unknown-uefi -- -D warnings
rustc --edition=2024 --test tests\nested.rs -o builds\nested-tests.exe
.\builds\nested-tests.exe
.\scripts\build_debug.ps1
```

The boot image is not considered validated merely because it compiles. A
runtime milestone must boot Windows normally, preserve both vCPUs without a
resident failure signal, and remain stable while its counters continue to
advance.

## Local Tool, VM, and Validation Path Map

Use the paths below directly on the current development host. Do not recursively
scan entire drives or unrelated VM directories when these locations are
sufficient.

### Repository and Build Artifacts

- **Repository root**: `D:\Projetos\MatrixHV`
- **Build root**: `D:\Projetos\MatrixHV\builds`
- **Debug artifacts**: `D:\Projetos\MatrixHV\builds\debug`
- **Release artifacts**: `D:\Projetos\MatrixHV\builds\release`
- **Cargo target directory**: `D:\Projetos\MatrixHV\builds\.cargo-target`
- **Active configuration**: `D:\Projetos\MatrixHV\builds\MatrixConfig.bin`
- **Primary build scripts**: `D:\Projetos\MatrixHV\scripts\build_debug.ps1`, `build_release.ps1`, `make_config.ps1`, and `make_image.ps1`

### Approved VMware Target

- **Primary VMX**: `D:\Projetos\MatrixHV\builds\vmware-incremental\MatrixHV-Incremental.vmx`
- **Expected display name**: `MatrixHV Incremental Windows Test`
- **MatrixHV boot disk descriptor**: `D:\Projetos\MatrixHV\builds\vmware-incremental\MatrixHV-test.vmdk`
- **MatrixHV boot disk image**: `D:\Projetos\MatrixHV\builds\vmware-incremental\MatrixHV-test.img`
- **Windows backing disk**: `D:\Projetos\MatrixHV\builds\vmware-incremental\windows-base-clone.vmdk`
- **Serial log**: `D:\Projetos\MatrixHV\builds\vmware-incremental\matrixhv-serial.log`
- **CLI VNC capture script**: `D:\Projetos\MatrixHV\builds\vmware-incremental\capture-vnc.py`
- **VNC endpoint**: `127.0.0.1:5905`
- **GDB stub endpoint**: `127.0.0.1:8864`
- **Explicitly excluded VMX**: `N:\VMs\NoirVisor-Windows11-Guest\NoirVisor-Windows11-Nested.vmx`. This is a different VM that normally stops at a lock screen; do not use it as the primary validation target.
- **Other VM directory**: `N:\VMs\NoirVisor-Windows11-Guest`. Treat its contents as unrelated unless the user explicitly selects one of them.

### Native Windows Tools

- **VMware vmrun**: `N:\Progamas\VmWare Pro\vmrun.exe`
- **VMware Workstation**: `N:\Progamas\VmWare Pro\vmware.exe`
- **LLVM clang**: `C:\Program Files\LLVM\bin\clang.exe`
- **LLVM objdump**: `C:\Program Files\LLVM\bin\llvm-objdump.exe`
- **x86-64 ELF toolchain**: `D:\Programacao\x86_64-elf-tools-windows`
- **i686 ELF toolchain**: `D:\Programacao\i686-elf-tools-windows`
- **MSYS2 bash, when a Unix-style build script is unavoidable**: `C:\msys64\usr\bin\bash.exe`
- **Do not use WSL** for MatrixHV builds, payload generation, VMware control, or validation.

### IDA and Kernel Debugging

- **IDA headless executable**: `D:\Programacao\RE Tools\IDA Professional 9.4\idat.exe`
- **Current kernel IDB with symbols**: `C:\Temp\ntoskrnl-live.exe.i64`
- Kernel load addresses change on every boot. Rediscover the live kernel base, verify the kernel version, and update any process script that contains a hardcoded base before trusting its output.
- For headless IDA, use `idat.exe -A -t -S<script.py> -L<log>` and launch it with `Start-Process -WindowStyle Hidden`.
- For GDB remote debugging, use `load_debugger("gdb", True)`, `set_remote_debugger("127.0.0.1", "", 8864)`, and `start_process("", "", "")`.

### VMX Compatibility Assets

- **Pinned upstream checkout**: `D:\Projetos\MatrixHV\builds\kvm-unit-tests\src`
- **EFI-specific external worktree**: `D:\Projetos\MatrixHV\builds\kvm-unit-tests\src-efi`
- **Validated EFI build directory**: `D:\Projetos\MatrixHV\builds\kvm-unit-tests\build-efi-gcc64-pic`
- **Validated VMX EFI payload**: `D:\Projetos\MatrixHV\builds\kvm-unit-tests\build-efi-gcc64-pic\x86\vmx.efi`
- **Repository-side VMX compatibility driver**: `D:\Projetos\MatrixHV\tests\kvm_unit_nested.py`
- **Resident nested-state validator**: `D:\Projetos\MatrixHV\tests\nested_runtime.py`

### Operational Constraints

- Before starting VMware, run `vmrun.exe list` and verify that no conflicting VM is already using port `8864`.
- Never run the approved incremental VM and the excluded NoirVisor nested VM simultaneously when both are configured for port `8864`.
- Do not use Computer Use, simulated clicks, or keyboard automation for validation. Use VMware CLI control, the serial log, VNC capture, and headless IDA when required.
- After debugger collection, always resume the guest and disconnect the debugger. Never leave the VM paused accidentally.
- Restore the approved incremental VM to its powered-off state after validation unless the user explicitly requests otherwise.
- A commit that changes boot or nested virtualization behavior is allowed only after the exact milestone build reaches a functional Windows desktop and its corresponding nested state is verified. A passing build, UEFI callback, Windows logo, or black screen is insufficient.
