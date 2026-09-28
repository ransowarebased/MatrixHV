# MatrixHV

MatrixHV is an experimental Intel VT-x pre-boot hypervisor written in Rust for
`x86_64-unknown-uefi`. It starts as a UEFI application, prepares a resident VMX
environment on the bootstrap and application processors, and chainloads an EFI
boot target under virtualization.

**Nested virtualization is under development.** The repository implements a
subset of nested VMX and includes host tests for that subset. It does not establish
complete Hyper-V, VBS, HVCI, VMware, or KVM compatibility, production readiness,
or freedom from crashes. Passing host tests does not validate an operating-system
boot or a nested hypervisor workload.

## Implementation status

| Area | Present in the implementation | Validation limits |
| --- | --- | --- |
| UEFI boot | Configuration loading; Intel VMX checks; loader discovery for VeraCrypt, Ubuntu shim/GRUB, and Windows Boot Manager | Loader discovery does not prove compatibility with every firmware or OS configuration. |
| Resident virtualization | BSP/AP setup, per-CPU resources, host paging, EPT, runtime callbacks, and VM-exit handling | Stability must be checked on the actual processor, firmware, and guest workload. |
| Nested VMX | VMXON/VMXOFF, VMCLEAR, VMPTRLD/VMPTRST, VMREAD/VMWRITE, VMLAUNCH/VMRESUME, and VMCS12 state | This is a restricted VMX contract, not the complete Intel VMX feature set. |
| Nested execution | VMCS02 preparation, L2 state synchronization, exit reflection to L1, and MSR-list/bitmap composition | These mechanisms do not by themselves establish end-to-end L1 hypervisor compatibility. |
| Nested translation | EPT12/EPT01 composition into EPT02, cached roots, VPID handling, INVEPT/INVVPID, and EPTP-switch paths | Availability depends on the virtual capability contract and underlying hardware. |
| Diagnostics and control | Serial/framebuffer diagnostics, opt-in telemetry, and the ROAD `neo` host agent | Runtime activation and deactivation require separate live-system verification. |

Here, **L0** is MatrixHV, **L1** is the hypervisor running inside its guest, and
**L2** is a guest launched by L1. The capability masks in [src/nested.rs](src/nested.rs)
define the advertised nested contract. Unsupported features must not be inferred
from the presence of a related instruction handler or a successful startup probe.

The code contains caches and selective MSR passthrough intended to reduce work in
VM-exit paths. This README makes no quantified performance, undetectability, or
BSOD-prevention claims.

## Requirements

- An Intel x86-64 processor exposing VMX and the capabilities required by the
  configured execution path, including EPT. AMD SVM is not implemented.
- x64 UEFI firmware. Loading an unsigned development EFI requires a firmware
  policy that permits it; this repository does not provide a signing workflow.
- Rust **stable**, as selected by [rust-toolchain.toml](rust-toolchain.toml), and
  the `x86_64-unknown-uefi` target.
- For the Windows build scripts and host tests: PowerShell 5.1 or newer, Python 3,
  and the MSVC linker tools used by Rust's Windows host target.
- The full packaging pipeline also builds `neo` for
  `x86_64-pc-windows-msvc` and `x86_64-unknown-linux-musl`; those targets and their
  linker support must be available.

For a VM-based test, the outer hypervisor must expose Intel VMX/EPT to MatrixHV.
Run boot and activation experiments on a disposable test system with recoverable
boot media. `neo matrix on` already asks for confirmation because activation can
crash running emulators or virtual machines.

## Build

Build only the UEFI executable from the repository root:

```powershell
rustup target add x86_64-unknown-uefi
cargo build --release --target x86_64-unknown-uefi
```

The Cargo configuration places it at
`builds/.cargo-target/x86_64-unknown-uefi/release/MatrixHV.efi`.
`build.rs` creates `builds/MatrixConfig.bin` when it is missing or empty and
preserves an existing nonempty configuration.

To build and stage MatrixHV and both `neo` binaries without generating a disk
image or archive:

```powershell
rustup target add x86_64-pc-windows-msvc x86_64-unknown-linux-musl
.\scripts\build_release.ps1 -SkipImage -SkipPackage
```

For the complete image and archive pipeline:

```powershell
.\scripts\build_release.ps1
```

The PowerShell pipeline currently uses the fixed output root
`D:\Projetos\MatrixHV\builds`. Review the scripts before using another checkout
location. Release outputs include `builds/release/MatrixHV.efi`, the removable-media
loader at `builds/release/EFI/BOOT/BOOTX64.EFI`, `neo.exe`, `neo`, and, when requested,
`MatrixHV.img`. Generated artifacts remain ignored by Git.

The image contains the MatrixHV bootloader and configuration; it does not install
an operating system. VeraCrypt and VMX-test EFI payloads are optional external
inputs to the image scripts.

## Configuration

`MatrixConfig.bin` is a UTF-8 text file despite its extension. MatrixHV reads it
from `\MatrixConfig.bin` on the volume that loaded its EFI application:

```text
MATRIXHV_CONFIG_V2
cpuidpresence=false
logger=true
VtNested=true
VmxTest=false
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `cpuidpresence` | `false` | Controls the guest CPUID hypervisor-presence policy; this is not an undetectability guarantee. |
| `logger` | `true` | Enables runtime logging. |
| `VtNested` | `true` | Enables exposure of the restricted nested VMX contract. |
| `VmxTest` | `false` | Selects the external VMX-test boot path; requires `VtNested=true` and the test payload. |

Use the configuration generator to update the build copy:

```powershell
.\scripts\make_config.ps1 -VtNested false -VmxTest false
```

Changing the build copy does not update an already-created boot disk. Stage or
regenerate the media so its root contains the intended configuration.

## Tests and validation

Run the local Python runners and standalone Rust tests on the Windows development
host:

```powershell
python run_alltest.py
```

The runner discovers suites under `tests/`, compiles the host harnesses with
`rustc`, and writes generated test binaries and assembly under `builds/`.
It does not boot a VM or run the external nested compatibility suite.

For focused nested assembly checks:

```powershell
python tests/run_nested_ept.py
python tests/run_nested_logging.py
python tests/run_eptp_sync.py
```

Host assembly tests replace privileged operations with controlled stubs. They
check instruction handling, state transitions, translation, invalidation, and
failure paths without exercising the full processor/firmware/OS interaction.

External validation tools are separate:

- `tests/kvm_unit_nested.py` builds and checks selected cases from a pinned
  upstream `kvm-unit-tests` revision. Its presence is not evidence of a passing run.
- `tests/collect_boot_state.py` collects runtime state through an external
  debugger setup.
- `tests/nested_runtime.py` checks collected guest snapshots.

A compatibility result should identify the tested commit, CPU, firmware or outer
hypervisor, guest OS, nested workload, enabled features, and observed failures or
skips. Build success, mocked host tests, an OS logo, and a startup probe are
different levels of evidence.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | UEFI entry point and initial configuration/logging |
| `src/boot.rs` | Configuration parsing, firmware integration, and boot-target selection |
| `src/arch.rs` | x86-64 registers, CPUID/MSR access, and segmentation |
| `src/core/` | VMCS, VMX lifecycle, controls, EPT, guest state, and resident runtime |
| `src/core/vt_resident.rs` | Resident resources, initialization, and assembly integration |
| `src/asm/resident_island.S` | Resident dispatcher, common handlers, and runtime bridges |
| `src/asm/nested.S` | Nested handlers, L2 reflection, VMCS12 tables, and messages |
| `src/asm/eptp_switch.S` | Nested EPTP switching and synchronization |
| `src/asm/ept_cache.S` | Resident EPT cache-type updates |
| `src/asm/ap_startup.S`, `ap_launch.S`, `guest_boot.S` | Processor startup and guest boot assembly |
| `src/nested.rs` | Nested capability contract, VMCS12 definitions, and per-vCPU state |
| `src/memory.rs`, `src/smp.rs`, `src/guest.rs` | Memory, processor resources, and guest orchestration |
| `src/runtime.rs` | Logging and runtime diagnostics |
| `src/road/neo/` | Windows/Linux control, telemetry, and remote agent |
| `scripts/` | Configuration, builds, disk images, and packaging |
| `tests/` | Host harnesses and external validation tools |

The macros in `nested.S` expand at explicit points inside the copied resident
island. Separating the source files keeps the handlers and their RIP-relative
data in the same resident code region.

## ROAD / neo

`neo` provides an interactive console, MatrixHV status/control, telemetry capture,
and a remote agent. Basic local commands include:

```powershell
neo.exe matrix status
neo.exe telemetry enable
neo.exe -t --seconds 10
neo.exe telemetry disable
```

Telemetry collection starts disabled. Remote serving is optional; its transport
is plaintext and unauthenticated. When needed for testing, bind explicitly to a
trusted interface, for example `neo.exe serve --listen 127.0.0.1:4040`.
Run `neo.exe --help` for the current command syntax.

## License

MatrixHV is distributed under the [MIT License](LICENSE).
