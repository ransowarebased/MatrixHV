# MatrixHV: Intel VT-x Pre-Boot Hypervisor

[![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)](https://www.rust-lang.org/)
[![Target](https://img.shields.io/badge/target-x86__64--unknown--uefi-blue.svg)](https://uefi.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64%20(VBS%2FHVCI)-brightgreen.svg)]()

MatrixHV is a modern, bare-metal Intel VT-x Type-1 / pre-boot hypervisor written in idiomatic Rust targeting x86_64-unknown-uefi.

MatrixHV initializes directly from UEFI firmware during early boot, virtualizes all available physical CPU cores (Bootstrap Processor and Application Processors) before the operating system kernel starts, and seamlessly transitions execution into the Windows Boot Manager (ootmgfw.efi / winload.efi) under continuous hardware-assisted virtualization.

---

## Key Features

### 1. Bare-Metal UEFI Pre-Boot Virtualization
- **Firmware Integration**: Native UEFI application (BOOTX64.EFI) that sets up hypervisor memory regions, page tables, and VMX data structures using UEFI boot services before exit.
- **Multiprocessor Support (SMP)**: Discovers and initializes all APs (Application Processors) via INIT-SIPI-SIPI inter-processor interrupts, creating isolated per-CPU state structures (ResidentCpuResources).
- **Seamless Boot Chaining**: Hands off execution to the standard Windows OS loader while keeping the processor in VMX root operation.

### 2. High-Performance EPT (Extended Page Tables)
- **Identity-Mapped EPT**: Hardware-assisted Second Level Address Translation (SLAT) managing guest physical memory access.
- **Stealth & Page Concealment**: Capability to conceal hypervisor code, runtime stacks, MSR bitmaps, and page tables from guest operating systems and security agents.
- **Zero-Page Fault Interception**: Configurable read/write/execute permissions and fine-grained violation dispatch.

### 3. Nested Virtualization (Nested VMX for L1 & L2)
- **Full Hyper-V & VBS Compatibility**: Tested and validated with Windows 10/11 Virtualization-Based Security (VBS, Device Guard Status 2) and Hypervisor-Enforced Code Integrity (HVCI Service Status 2).
- **Dual Hardware VPID Retention**: Retains dedicated VPID tags for VTL0 (Standard Windows) and VTL1 (Secure Kernel) contexts, avoiding global TLB invalidations on virtual trust level transitions and preventing DPC watchdog timeouts (BSOD 0x133).
- **Fast VMCS12 Emulation**: 1024-byte direct index lookup table for VMCS field accesses, accelerating guest mread and mwrite operations.
- **Dual EPT02 Caching Pools**: Prevents repeated deep EPT page walks when switching between host and nested guest execution.

### 4. Zero-Cost MSR Passthrough & Exit Optimization
- **Hardware-Managed Contexts**: Passthrough enabled for performance-critical MSRs (IA32_FS_BASE, IA32_GS_BASE, IA32_KERNEL_GS_BASE, IA32_TSC_AUX), eliminating thousands of VM-exits per second on Windows thread swaps.
- **Adaptive Tracing**: Intelligent throttling of serial debug output to ensure fast boot times.

### 5. Automated Host Test Harness
- **Unit Test Assembly Runner**: Extracts core assembly routines (EPT resolution, VMCS sync, VPID caching, MSR lists) and executes them directly under standard Windows user mode with mocks, eliminating the need to boot a full virtual machine for basic verification.

---

## Repository Layout

`	ext
.
├── .cargo/                 # Cargo target configuration and flags
├── asm/                    # Low-level 16-bit / 32-bit AP startup assembly
├── scripts/                # Automated PowerShell build, image, and packaging scripts
│   ├── buildauto.ps1       # One-click build and image generation pipeline
│   ├── build_debug.ps1     # Builds debug UEFI binary
│   ├── build_release.ps1   # Builds optimized release UEFI binary
│   ├── clean.ps1           # Cleans build artifacts and caches
│   ├── make_config.ps1     # Generates embedded binary configuration
│   ├── make_image.ps1      # Creates FAT32 bootable GPT/MBR disk images
│   └── package.ps1         # Packages release archives
├── src/
│   ├── main.rs             # UEFI entry point and boot coordinator
│   ├── arch/               # Architecture-specific x86_64 primitives (registers, segmentation)
│   ├── boot/               # UEFI memory-map parser, config loader, and firmware services
│   ├── core/               # Core VMX engine (controls, VMCS, EPT, exits, resident loop)
│   ├── guest/              # Guest firmware probe and vCPU bootstrap orchestration
│   ├── memory/             # Paging, resident pools, and physical memory allocation
│   ├── nested/             # Nested VMX emulation (capabilities, VMCS12, state machines)
│   ├── road/               # Remote control, telemetry protocol, and agent interface
│   ├── runtime/            # Low-level UART 16550 serial logger and diagnostics
│   └── smp/                # Topology discovery, AP startup, and per-CPU state
├── tests/
│   ├── nested.rs           # Architectural capability and encoding tests
│   ├── nested_ept.rs       # Standalone host-runnable resident assembly test harness
│   └── run_nested_ept.py   # Test extractor and runner
├── Cargo.toml              # Project dependencies and workspace definition
├── rust-toolchain.toml     # Pinned Rust toolchain (nightly)
└── LICENSE                 # MIT License
`

---

## Prerequisites

1. **Rust Toolchain**:
   - Rust Nightly with the x86_64-unknown-uefi target installed:
     `powershell
     rustup default nightly
     rustup target add x86_64-unknown-uefi
     rustup component add rust-src llvm-tools-preview
     `
2. **PowerShell 5.1+ or 7+** (on Windows).
3. **Python 3.10+** (optional, required for running host assembly tests).
4. **Hardware Requirements**:
   - Intel Core / Xeon processor with Intel VT-x (VMX), EPT, and Unrestricted Guest support.

---

## Building

### Quick Build (Debug / Release)

To compile MatrixHV for UEFI:

`powershell
# Build release UEFI binary
.\scripts\build_release.ps1

# Or build debug UEFI binary
.\scripts\build_debug.ps1
`

The resulting binary will be placed under:
- uilds/release/MatrixHV.efi (or uilds/debug/MatrixHV.efi)

### Creating a Bootable Disk Image

To generate a bootable FAT32 raw disk image (MatrixHV.img) ready for VMware or QEMU:

`powershell
.\scripts\buildauto.ps1 -Configuration Release
`

This script will:
1. Compile the UEFI binary using Cargo.
2. Build the embedded binary configuration (MatrixConfig.bin).
3. Construct a virtual FAT32 UEFI boot disk containing \EFI\BOOT\BOOTX64.EFI.

---

## Testing & Quality Assurance

### 1. Running Host-Side Unit Tests

MatrixHV includes high-coverage host tests that validate VMX capability derivations, bitmasks, and field encodings:

`powershell
cargo test --test nested
`

### 2. Running Resident Assembly Mock Tests

To test the low-level resident assembly routines (EPT walks, VPID invalidation, VMCS field indexer) directly on your host machine without virtual machines:

`powershell
python tests\run_nested_ept.py
`

### 3. Clippy & Linter Validation

To ensure standard compliance without warnings:

`powershell
cargo fmt -- --check
cargo check --target x86_64-unknown-uefi
cargo clippy --target x86_64-unknown-uefi -- -D warnings
`

---

## Testing in a Virtual Machine

### VMware Workstation / ESXi
1. Create a Windows 10/11 x64 virtual machine.
2. Enable **Virtualize Intel VT-x/EPT or AMD-V/RVI** in VM Settings -> Processors.
3. Configure the VM to boot from UEFI.
4. Attach the generated MatrixHV.img or replace the EFI bootloader on the virtual disk with MatrixHV.efi renamed as BOOTX64.EFI.
5. Add a serial port connected to a named pipe or file to view resident diagnostics and telemetry in real time.

### QEMU / OVMF
`powershell
qemu-system-x86_64 -enable-kvm -cpu host -m 4G -bios path/to/OVMF.fd -drive format=raw,file=builds/release/MatrixHV.img -serial stdio
`

---

## Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository.
2. Create a feature branch: git checkout -b feature/my-new-feature.
3. Commit your changes: git commit -m "feat(vt_core): add new feature".
4. Push to the branch: git push origin feature/my-new-feature.
5. Open a Pull Request.

---

## License

This project is licensed under the [MIT License](LICENSE).
