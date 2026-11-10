# MatrixHV

MatrixHV is an experimental Intel VT-x (VMX) pre-boot hypervisor written in Rust (`#![no_std]`) and assembly for the `x86_64-unknown-uefi` target. It executes as a UEFI application, establishes a resident virtualization environment across all logical processors (bootstrap processor and application processors), initializes Extended Page Tables (EPT), and chainloads an EFI boot target (such as the Windows Boot Manager) under hardware virtualization.

MatrixHV exposes a versioned instrumentation ABI through `matrixhv-protocol` and a reusable Rust client through `matrixhv-client`. Independent projects can call the operations exposed by a running MatrixHV core. Client programs run in the guest OS. The hypervisor performs the operations it exposes in VMX root. [Neo](https://github.com/ransowarebased/Neo) is a separate client for control and telemetry.

---

## Technical Overview

MatrixHV operates as a Type-1 (bare-metal) thin hypervisor initializing during the pre-boot firmware phase:

- **Pre-Boot UEFI Lifecycle**: Loads configuration from `\MatrixConfig.bin`, detects serial/COM1 logging targets, discovers boot targets (Windows Boot Manager, GRUB/shim, VeraCrypt), and configures per-CPU state.
- **Multi-Processor Resident Runtime**: Starts and virtualizes all Application Processors (APs) via INIT-SIPI-SIPI sequences, configuring individual VMCS structures, host page tables, and dedicated exit stacks.
- **Identity & Split EPT**: Implements an identity-mapped Extended Page Table baseline with split-view execute/read permissions, dynamic Copy-on-Write (CoW) page table splitting, and per-core alternate EPT banks.
- **Process-Scoped Instrumentation**: Interception sessions can be scoped to selected guest address spaces and use leases for automatic reclamation.
- **Nested VMX (Research / Partial)**: Emulates a restricted contract of Intel VMX instructions (VMXON/VMXOFF, VMCLEAR, VMPTRLD/VMPTRST, VMREAD/VMWRITE, VMLAUNCH/VMRESUME), shadow VMCS12 state management, and exit reflection to L1.
- **Intel PT Diagnostics**: Support for Intel Processor Trace logging and performance counters.
- **Authenticated Hot Update**: Cryptographically signed in-memory resident core replacement mechanism (`update.rs`).

---

## Implementation Limits & Scope

To ensure clarity and avoid unrealistic expectations:

- **Hardware Architecture**: MatrixHV requires an **Intel x86-64 processor** with VMX and EPT support. **AMD processors (SVM / AMD-V) are not supported.**
- **Nested Virtualization is Experimental**: The nested VMX implementation covers a restricted architectural subset for hypervisor research. It does **not** provide full, bug-free compatibility with nested Hyper-V, Windows Virtualization-Based Security (VBS/HVCI), VMware, or KVM.
- **Firmware Signing**: Loading development UEFI binaries requires a firmware configuration that permits unsigned or custom test-signed EFI applications (e.g., Secure Boot disabled or custom platform keys enrolled).

---

## Repository Layout

```
MatrixHV/
├── crates/
│   ├── matrixhv-protocol/      # Shared #[repr(C)] host/guest ABI (no_std)
│   └── matrixhv-client/        # Host-side packet builders + CPUID memory transport API
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
│   │   ├── observation.rs      # Hook data-shadow metadata (watch/context/event capture removed)
│   │   └── tracking.rs         # Accessed and dirty bit tracking
│   ├── update.rs               # Authenticated resident runtime hot-swap engine
│   ├── diagnostics.rs          # Diagnostic utilities and hardware checks
│   └── logging.rs              # Serial (COM1) and resident memory logging
├── scripts/                    # Automation scripts for build, image generation, and packaging
└── tests/                      # Unit tests, integration harnesses, and runtime verification
```

---

## Prerequisites

- **Toolchain**: Rust stable with the `x86_64-unknown-uefi` target.
- **System Tools**: PowerShell 5.1+, Python 3, and the MSVC C++ build tools / linker.

Install the required Rust target:
```powershell
rustup target add x86_64-unknown-uefi
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

### 2. Integrate a host program

Pin the client crate to a compatible MatrixHV revision in your project's Cargo manifest:
```toml
matrixhv-client = { git = "https://github.com/ransowarebased/MatrixHV", rev = "50292addaf4347a6eae58e1f594e4bbeeb978798" }
```

The client provides packet builders and the transport for the public memory and instrumentation ABI. The shared protocol crate defines the wire layouts and constants. See [Neo](https://github.com/ransowarebased/Neo) for a separate project that consumes both crates.

MatrixHV retains VM-exit diagnostics, Intel PT, and resident status. Protocol 9 retires application watchpoints, context sampling, stack walking, and event capture. For user-mode Windows debugging, use [x64dbg](https://x64dbg.com/). Boot the new EFI when migrating from protocol 8 because the resident state layout changed.

### 3. Automated Packaging Pipeline

To generate the release ZIP and bootable disk image:
```powershell
.\scripts\build_release.ps1
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
# Run the local hypervisor suites
python run_alltests.py

# Run host API tests without a resident hypervisor
cargo test --locked -p matrixhv-client
```

CLI, telemetry, and host-agent tests live in the Neo repository: https://github.com/ransowarebased/Neo.

---

## License

This project is licensed under the [MIT License](LICENSE).
