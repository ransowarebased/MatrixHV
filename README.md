# MatrixHV

MatrixHV is an experimental Intel VT-x (VMX) pre-boot hypervisor written in Rust (`#![no_std]`) and assembly for the `x86_64-unknown-uefi` target. It executes as a UEFI application, establishes a resident virtualization environment across all logical processors (bootstrap processor and application processors), initializes Extended Page Tables (EPT), and chainloads an EFI boot target (such as the Windows Boot Manager) under hardware virtualization.

The repository also includes **ROAD / neo**, a user-space host companion and telemetry agent, as well as test suites for offline validation of hypervisor memory mechanisms and instruction handling.

---

## Technical Overview

MatrixHV operates as a Type-1 (bare-metal) thin hypervisor initializing during the pre-boot firmware phase:

- **Pre-Boot UEFI Lifecycle**: Loads configuration from `\MatrixConfig.bin`, detects serial/COM1 logging targets, discovers boot targets (Windows Boot Manager, GRUB/shim, VeraCrypt), and configures per-CPU state.
- **Multi-Processor Resident Runtime**: Starts and virtualizes all Application Processors (APs) via INIT-SIPI-SIPI sequences, configuring individual VMCS structures, host page tables, and dedicated exit stacks.
- **Identity & Split EPT**: Implements an identity-mapped Extended Page Table baseline with split-view execute/read permissions, dynamic Copy-on-Write (CoW) page table splitting, and per-core alternate EPT banks.
- **Process-Scoped Interception**:
  - Gated by CR3 matching and hardware debug register filters (DR3 / DR7) to restrict VM-exits exclusively to targeted processes, preventing global performance degradation.
  - Time-leased session management with automatic reclamation upon expiry.
  - **CPUID Profiles**: Masked and spoofed CPUID emulation on VM-exit reason 10, combining native output with configurable profile masks.
  - **Private `KUSER_SHARED_DATA` (`0x7ffe0000`)**: Virtualized shadow view for the Windows user-shared data page, with atomic `KSYSTEM_TIME` clock synchronization (`High2Time` / `LowPart` / `High1Time`) updated via the VMX Preemption Timer (VM-exit reason 52).
  - **Syscall Routing**: Hardware execution breakpoint at the `LSTAR` entry (`KiSystemCall64`) that simulates an Intel `SYSRET64` privilege transition directly into a ring-3 user callback, bypassing kernel-mode transition, with an `FXSAVE` SIMD token bypass (`RFLAGS.RF`) for executing native syscalls.
- **Nested VMX (Research / Partial)**: Emulates a restricted contract of Intel VMX instructions (VMXON/VMXOFF, VMCLEAR, VMPTRLD/VMPTRST, VMREAD/VMWRITE, VMLAUNCH/VMRESUME), shadow VMCS12 state management, and exit reflection to L1.
- **Intel PT Diagnostics**: Support for Intel Processor Trace logging and performance counters.
- **Authenticated Hot Update**: Cryptographically signed in-memory resident core replacement mechanism (`update.rs`).

---

## Implementation Limits & Scope

To ensure clarity and avoid unrealistic expectations:

- **Hardware Architecture**: MatrixHV requires an **Intel x86-64 processor** with VMX and EPT support. **AMD processors (SVM / AMD-V) are not supported.**
- **Nested Virtualization is Experimental**: The nested VMX implementation covers a restricted architectural subset for hypervisor research. It does **not** provide full, bug-free compatibility with nested Hyper-V, Windows Virtualization-Based Security (VBS/HVCI), VMware, or KVM.
- **No Unconditional Stealth Guarantees**: While process-scoped CPUID masking, EPT split views, and debug register gates avoid global system hooks and SSDT modifications, this software does not guarantee undetectability against sophisticated heuristic or timing-based anti-cheat / anti-rootkit scanners.
- **Firmware Signing**: Loading development UEFI binaries requires a firmware configuration that permits unsigned or custom test-signed EFI applications (e.g., Secure Boot disabled or custom platform keys enrolled).

---

## Repository Layout

```
MatrixHV/
├── src/
│   ├── main.rs                 # UEFI entry point and boot coordination
│   ├── arch.rs                 # Low-level x86-64 MSR, CPUID, and register access
│   ├── boot/                   # Configuration, firmware services, SMP, and guest startup
│   ├── vmx/                    # VMX lifecycle, VMCS, controls, EPT, exits, and nested VMX
│   │   ├── asm/                # Assembly stubs for VM-entry, VM-exit, and control switches
│   │   ├── ept.rs              # Extended Page Tables structures and paging operations
│   │   ├── nested.rs           # Nested VMX instruction emulation and VMCS12 handling
│   │   └── vcpu.rs             # Virtual CPU state machine and per-core orchestration
│   ├── memory/                 # Memory access, tracking, and interception engines
│   │   ├── access.rs           # Physical and virtual memory translation
│   │   ├── interception.rs     # EPT split views, CPUID profiles, and syscall interception
│   │   └── tracking.rs         # Accessed and dirty bit tracking
│   ├── protocol.rs             # Hypervisor-to-host resident memory communication protocol
│   ├── update.rs               # Authenticated resident runtime hot-swap engine
│   ├── diagnostics.rs          # Diagnostic utilities and hardware checks
│   ├── logging.rs              # Serial (COM1) and resident memory logging
│   └── neo/                    # User-space companion CLI (telemetry, control, memory access)
├── scripts/                    # Automation scripts for build, image generation, and packaging
└── tests/                      # Unit tests, integration harnesses, and runtime verification
```

---

## Prerequisites

- **Toolchain**: Rust stable with the `x86_64-unknown-uefi` target.
- **Host Targets**: `x86_64-pc-windows-msvc` (for Windows host builds and tests) and optionally `x86_64-unknown-linux-musl` for `neo`.
- **System Tools**: PowerShell 5.1+, Python 3, and the MSVC C++ build tools / linker.

Install required Rust targets:
```powershell
rustup target add x86_64-unknown-uefi
rustup target add x86_64-pc-windows-msvc
```

---

## Building

### 1. Build MatrixHV (UEFI Hypervisor)

From the repository root:
```powershell
cargo build --release --target x86_64-unknown-uefi
```
The resulting UEFI binary will be produced at:
`builds/.cargo-target/x86_64-unknown-uefi/release/MatrixHV.efi`

### 2. Build ROAD / neo (Host Companion)

```powershell
cargo build --release --manifest-path src/neo/Cargo.toml --target x86_64-pc-windows-msvc
```
The executable will be located at:
`builds/.cargo-target/x86_64-pc-windows-msvc/release/neo.exe`

### 3. Automated Packaging Pipeline

To generate the complete release package (including bootable disk images when configured):
```powershell
.\scripts\build_release.ps1 -SkipImage -SkipPackage
```

---

## Configuration

MatrixHV reads configuration from `\MatrixConfig.bin` on the boot volume at startup:

```ini
MATRIXHV_CONFIG_V2
cpuidpresence=false
logger=true
VtNested=true
VmxTest=false
```

| Parameter | Default | Description |
|---|---|---|
| `cpuidpresence` | `false` | Sets hypervisor present bit policy in standard guest CPUID queries. |
| `logger` | `true` | Enables serial and resident in-memory debug logging. |
| `VtNested` | `true` | Enables exposure of the restricted nested VMX emulation path. |
| `VmxTest` | `false` | Directs execution to an external VMX test payload if present. |

Use `scripts/make_config.ps1` to regenerate or customize this configuration file.

---

## Testing & Validation

MatrixHV includes mock hardware test runners to validate instruction handlers, EPT permissions, and interception mechanisms on the development host:

```powershell
# Run the resident interception runtime test suite (62 mocked tests)
python tests/run_interception_runtime_tests.py

# Run the neo protocol and EPT split-view unit tests (54 tests)
cargo test --manifest-path src/neo/Cargo.toml --target x86_64-pc-windows-msvc interception_tests
```

---

## ROAD / neo CLI

`neo` provides an administrative interface for interacting with the resident hypervisor from user space:

```powershell
# Query hypervisor resident status
neo.exe matrix status

# Enable/disable telemetry collection
neo.exe telemetry enable
neo.exe telemetry disable

# Display help and available commands
neo.exe --help
```

---

## License

This project is licensed under the [MIT License](LICENSE).
