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
|-- config/                   Binary boot configuration and reference sample
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
|   |   |-- instructions.rs   Architectural status and instruction errors
|   |   |-- state.rs          Per-vCPU nested operation state
|   |   |-- vmcs.rs           VMCS12 state and supported field encodings
|   |   `-- exits.rs          Nested VMX exit reasons
|   |-- runtime/              Serial logging and runtime support
|   `-- smp/                  Topology, per-CPU state, and AP startup
`-- tests/nested.rs           Host-runnable nested-state contract tests
```

The nested subsystem is intentionally limited to these six cohesive source
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
