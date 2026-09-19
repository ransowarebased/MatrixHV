# MatrixHV

MatrixHV is a high-performance Intel VT-x (VMX) Type-1 bare-metal pre-boot hypervisor written in modern Rust (`no_std`, `no_main`) targeting the `x86_64-unknown-uefi` environment.

## Overview

- **Core Engine**: Intel VT-x (VMX) L0 hypervisor with Extended Page Tables (EPT) and Virtual Processor IDs (VPID).
- **Nested Virtualization**: Emulates VMX for L1 hypervisors, synthesizing VMCS02 from VMCS01 and VMCS12, and composing two-dimensional nested page tables (EPT02).
- **Pre-Boot UEFI Execution**: Operates before OS handover, providing seamless chainloading for VeraCrypt Full Disk Encryption (`DcsBoot.efi`) and Windows Boot Manager (`bootmgfw.efi`).
- **Bare-Metal Diagnostics**: Direct 16550 UART serial logging (COM1, 115200 baud), VMCS state inspection, and EPT memory layout dumping.

---

## Repository Architecture & File Directory Map

The following map defines the canonical architectural layout, components, and responsibilities across the MatrixHV repository:

```text
MatrixHV/
├── Cargo.toml
│   Main Rust project manifest defining package metadata, dependencies,
│   feature flags, and build profiles.
│
├── Cargo.lock
│   Exact dependency version lockfile ensuring reproducible builds.
│
├── rust-toolchain.toml
│   Specifies the active Rust toolchain channel, components (clippy, rustfmt),
│   and targets (x86_64-unknown-uefi).
│
├── build.rs
│   Cargo build script executed prior to main compilation; centralizes build-time
│   code generation, artifact staging, and linker scripts.
│
├── README.md
│   General project overview, architecture philosophy, and documentation.
│
├── LICENSE
│   Project distribution and licensing terms.
│
├── .cargo/
│   └── config.toml
│       Cargo-specific build configurations, default UEFI target triple,
│       target-dir paths, and rustflags.
│
├── config/
│   ├── MatrixConfig.bin
│   │   Active binary configuration blob parsed and consumed by MatrixHV at boot.
│   │
│   └── MatrixConfig.example.bin
│       Reference or default baseline configuration template.
│
├── src/
│   ├── main.rs
│   │   Primary UEFI application entry point (`efi_main`); initializes serial logging,
│   │   UEFI helpers, and hands off execution to the boot subsystem.
│   │
│   ├── core/
│   │   Intel VT-x/VMX L0 hypervisor core engine.
│   │
│   │   ├── mod.rs
│   │   │   Declares and exports core hypervisor submodules.
│   │   │
│   │   ├── hypervisor.rs
│   │   │   Central hypervisor instance, lifecycle management, and global state.
│   │   │
│   │   ├── vt_init.rs
│   │   │   Initialization sequencing and setup logic for the VMX subsystem.
│   │   │
│   │   ├── vt_entry.rs
│   │   │   Handles transitions into VMX non-root operation (`VMLAUNCH` / `VMRESUME`).
│   │   │
│   │   ├── vt_exits.rs
│   │   │   Central dispatcher and routing entry point for intercepted VM-exits.
│   │   │
│   │   ├── vt_exit_reason.rs
│   │   │   Data types, bitfields, and enumeration of VM-exit reasons and qualification codes.
│   │   │
│   │   ├── vt_vmxon.rs
│   │   │   Management, allocation, and tracking of the 4KB-aligned VMXON region and VMX root mode.
│   │   │
│   │   ├── vt_vmcs.rs
│   │   │   Primary abstraction and lifecycle operations for the Virtual Machine Control Structure.
│   │   │
│   │   ├── vt_vmcs_fields.rs
│   │   │   Encoding identifiers, 16/32/64-bit field definitions, and constants for VMCS access.
│   │   │
│   │   ├── vt_controls.rs
│   │   │   Configuration of Pin-based, Primary/Secondary Processor-based, VM-Exit, and VM-Entry execution controls.
│   │   │
│   │   ├── vt_host.rs
│   │   │   Host architectural state restored by hardware upon VM-exit (CR0, CR3, CR4, RSP, RIP, segment selectors).
│   │   │
│   │   ├── vt_guest.rs
│   │   │   Guest architectural state configured in and loaded from the VMCS.
│   │   │
│   │   ├── vt_ept.rs
│   │   │   Extended Page Tables (EPT) root pointer (EPTP) configuration and L0 translation controls.
│   │   │
│   │   ├── vt_vpid.rs
│   │   │   Virtual Processor Identifier allocation and lifecycle management for TLB tagging.
│   │   │
│   │   ├── vt_invalidation.rs
│   │   │   Hardware invalidation wrappers for EPT (`INVEPT`) and VPID (`INVVPID`) contexts.
│   │   │
│   │   ├── vt_cpuid.rs
│   │   │   Guest CPUID instruction virtualization, feature masking, and synthetic leaf synthesis.
│   │   │
│   │   ├── vt_msr.rs
│   │   │   Model-Specific Register (MSR) virtualization, permission bitmap controls, and access handling.
│   │   │
│   │   ├── vt_interrupts.rs
│   │   │   Virtual interrupt injection, interruptibility state tracking, and interrupt-window exiting.
│   │   │
│   │   ├── vt_exceptions.rs
│   │   │   Exception intercept bitmap management and virtual event injection.
│   │   │
│   │   ├── vt_apic.rs
│   │   │   APIC virtualization controls, APIC-access page, and virtual-APIC register mappings.
│   │   │
│   │   ├── vt_timer.rs
│   │   │   VMX-preemption timer management and guest timer virtualization.
│   │   │
│   │   └── exit_handlers/
│   │       │   Specialized handlers for specific VM-exit reasons.
│   │       │
│   │       ├── mod.rs
│   │       │   Declares and dispatches dedicated VM-exit handlers.
│   │       │
│   │       ├── cpuid.rs
│   │       │   Handler for guest CPUID instruction intercepts.
│   │       │
│   │       ├── msr.rs
│   │       │   Handler for guest RDMSR and WRMSR access intercepts.
│   │       │
│   │       ├── io.rs
│   │       │   Handler for guest IN/OUT port I/O instruction intercepts.
│   │       │
│   │       ├── hlt.rs
│   │       │   Handler for guest HLT execution.
│   │       │
│   │       ├── cr_access.rs
│   │       │   Handler for guest Control Register (CR0, CR3, CR4, CR8) accesses.
│   │       │
│   │       ├── exceptions.rs
│   │       │   Handler for intercepted guest exceptions (#PF, #GP, #UD, #DB).
│   │       │
│   │       ├── interrupts.rs
│   │       │   Handler for external interrupts and NMI intercepts.
│   │       │
│   │       ├── ept_violation.rs
│   │       │   Handler for guest physical address access violations reported by EPT.
│   │       │
│   │       ├── ept_misconfig.rs
│   │       │   Handler for illegal or conflicting control bits in EPT paging structures.
│   │       │
│   │       └── vmx_instruction.rs
│   │           Handler for VMX instructions (VMCLEAR, VMLAUNCH, VMRESUME, VMPTRLD, etc.)
│   │           executed by the guest (crucial for nested virtualization).
│   │
│   ├── nested/
│   │   Nested VT-x subsystem; virtualizes Intel VMX for an L1 hypervisor running inside the guest.
│   │
│   │   ├── mod.rs
│   │   │   Declares and exports the nested virtualization subsystem.
│   │   │
│   │   ├── nested_vmx.rs
│   │   │   Core state management and abstractions for the virtual VMX environment presented to L1.
│   │   │
│   │   ├── nested_state.rs
│   │   │   Per-vCPU persistent state tracking the nested execution phase (Root, Non-Root, L1 vs L2).
│   │   │
│   │   ├── nested_capabilities.rs
│   │   │   Virtual VMX capabilities and MSRs (IA32_VMX_BASIC, PINBASED_CTLS, etc.) exposed to L1.
│   │   │
│   │   ├── nested_vmcs.rs
│   │   │   Common abstractions for handling multi-level VMCS structures.
│   │   │
│   │   ├── nested_vmcs12.rs
│   │   │   Representation of the VMCS data structure that L1 controls to run L2.
│   │   │
│   │   ├── nested_vmcs02.rs
│   │   │   Hardware VMCS synthesized by L0 combining L0 policies (VMCS01) and L1 controls (VMCS12) to execute L2.
│   │   │
│   │   ├── nested_vmcs_fields.rs
│   │   │   Field definitions, encodings, and layout validation rules for VMCS12.
│   │   │
│   │   ├── nested_controls.rs
│   │   │   Composes and merges L0 controls (VMCS01) with L1 controls (VMCS12) to produce VMCS02 controls.
│   │   │
│   │   ├── nested_vmxon.rs
│   │   │   Virtual VMXON emulation for L1, tracking virtual root operation.
│   │   │
│   │   ├── nested_vmxoff.rs
│   │   │   Virtual VMXOFF emulation for L1, resetting nested virtualization state.
│   │   │
│   │   ├── nested_vmclear.rs
│   │   │   Emulates VMCLEAR operations targeting L1's VMCS12 regions.
│   │   │
│   │   ├── nested_vmptrld.rs
│   │   │   Emulates VMPTRLD, activating L1's current VMCS12 pointer.
│   │   │
│   │   ├── nested_vmptrst.rs
│   │   │   Emulates VMPTRST, reading the active VMCS12 physical pointer back to L1.
│   │   │
│   │   ├── nested_vmread.rs
│   │   │   Emulates VMREAD, returning requested VMCS12 field values to L1.
│   │   │
│   │   ├── nested_vmwrite.rs
│   │   │   Emulates VMWRITE, validating and updating VMCS12 fields according to VMX specifications.
│   │   │
│   │   ├── nested_vmlaunch.rs
│   │   │   Emulates VMLAUNCH, performing consistency checks on VMCS12 and launching L2.
│   │   │
│   │   ├── nested_vmresume.rs
│   │   │   Emulates VMRESUME, verifying active state and resuming L2 execution.
│   │   │
│   │   ├── nested_invept.rs
│   │   │   Emulates INVEPT instructions executed by L1, flushing corresponding L0 shadow EPT structures.
│   │   │
│   │   ├── nested_invvpid.rs
│   │   │   Emulates INVVPID instructions executed by L1, invalidating virtual VPID contexts.
│   │   │
│   │   ├── nested_entry.rs
│   │   │   Prepares hardware state and VMCS02 for switching execution from L1 to L2.
│   │   │
│   │   ├── nested_exits.rs
│   │   │   Central router evaluating whether an L2 VM-exit belongs to L0 or must be reflected to L1.
│   │   │
│   │   ├── nested_exit_reflection.rs
│   │   │   Synthesizes VM-exit state in VMCS12 and resumes L1 at its configured host RIP/RSP.
│   │   │
│   │   ├── nested_exit_injection.rs
│   │   │   Injects synthetic exceptions and interrupts into the nested L1/L2 guest context.
│   │   │
│   │   ├── nested_ept.rs
│   │   │   Two-dimensional nested paging; merges L1 EPT (EPT12) with L0 EPT (EPT01) to build EPT02.
│   │   │
│   │   ├── nested_vpid.rs
│   │   │   Virtual VPID allocation and mapping for L1 and L2 execution spaces.
│   │   │
│   │   ├── nested_cpuid.rs
│   │   │   CPUID filtering and feature advertisement for nested guest environments.
│   │   │
│   │   ├── nested_msr.rs
│   │   │   Virtualization and access control for VMX MSRs queried by L1.
│   │   │
│   │   ├── nested_apic.rs
│   │   │   Virtual APIC state synchronization across L0, L1, and L2 hierarchies.
│   │   │
│   │   ├── nested_interrupts.rs
│   │   │   Coordinates virtual interrupt delivery and window exiting between L1 and L2.
│   │   │
│   │   ├── nested_exceptions.rs
│   │   │   Evaluates exception bitmaps to determine whether L0 or L1 handles L2 exceptions.
│   │   │
│   │   ├── nested_timer.rs
│   │   │   Virtualizes the VMX preemption timer and guest APIC timer for L1/L2.
│   │   │
│   │   └── nested_memory.rs
│   │       Manages shadow memory structures and nested page table caches.
│   │
│   ├── arch/
│   │   Physical x86-64 hardware abstraction layer.
│   │
│   │   ├── mod.rs
│   │   │   Declares supported target architectures.
│   │   │
│   │   └── x86_64/
│   │       ├── mod.rs
│   │       │   Exports specific x86-64 hardware abstraction components.
│   │       │
│   │       ├── cpu.rs
│   │       │   CPU feature detection, vendor identification, and baseline capability queries.
│   │       │
│   │       ├── cpuid.rs
│   │       │   Low-level wrapper executing the CPUID instruction.
│   │       │
│   │       ├── msr.rs
│   │       │   Low-level wrappers for reading (`RDMSR`) and writing (`WRMSR`) Model-Specific Registers.
│   │       │
│   │       ├── instructions.rs
│   │       │   Inline assembly wrappers for raw x86-64 architectural instructions.
│   │       │
│   │       ├── registers.rs
│   │       │   Types and definitions representing general-purpose and system architectural registers.
│   │       │
│   │       ├── control_regs.rs
│   │       │   Direct access and bitfield representations for CR0, CR2, CR3, CR4, and CR8.
│   │       │
│   │       ├── rflags.rs
│   │       │   RFLAGS register bitfield definitions and manipulation primitives.
│   │       │
│   │       ├── gdt.rs
│   │       │   Global Descriptor Table representation, descriptor encoding, and GDTR management.
│   │       │
│   │       ├── idt.rs
│   │       │   Interrupt Descriptor Table structures, gate descriptors, and IDTR management.
│   │       │
│   │       ├── tss.rs
│   │       │   64-bit Task State Segment (TSS) layout and interrupt stack table (IST) definitions.
│   │       │
│   │       ├── descriptors.rs
│   │       │   Common segment and gate descriptor types shared across table structures.
│   │       │
│   │       ├── segmentation.rs
│   │       │   x86-64 segment registers, base addresses, limits, and access rights management.
│   │       │
│   │       ├── interrupts.rs
│   │       │   Architectural interrupt management, flag controls (`CLI`/`STI`), and interrupt vectors.
│   │       │
│   │       ├── exceptions.rs
│   │       │   Standard x86 architecture exception vectors, error code formats, and classification.
│   │       │
│   │       ├── apic.rs
│   │       │   Common abstraction and interface for the Advanced Programmable Interrupt Controller.
│   │       │
│   │       ├── x2apic.rs
│   │       │   MSR-based x2APIC mode implementation, register offsets, and commands.
│   │       │
│   │       ├── lapic.rs
│   │       │   Memory-mapped Local APIC register access and state definitions.
│   │       │
│   │       ├── pat.rs
│   │       │   Page Attribute Table (PAT) MSR layout and memory caching type assignments.
│   │       │
│   │       ├── mtrr.rs
│   │       │   Memory Type Range Registers (MTRR) querying and physical caching attributes.
│   │       │
│   │       └── cache.rs
│   │           CPU cache management primitives (`INVD`, `WBINVD`, `CLFLUSH`).
│   │
│   ├── memory/
│   │   L0 host physical and virtual memory management subsystem.
│   │
│   │   ├── mod.rs
│   │   │   Declares and exports memory subsystem components.
│   │   │
│   │   ├── address.rs
│   │   │   Strongly-typed physical and virtual memory address wrappers and alignment helpers.
│   │   │
│   │   ├── physical.rs
│   │   │   Physical memory ranges, contiguous frame representations, and host RAM limits.
│   │   │
│   │   ├── virtual_address.rs
│   │   │   Canonical virtual memory address types and manipulation utilities.
│   │   │
│   │   ├── paging.rs
│   │   │   Standard 4-level x86-64 paging logic, translation walks, and page table operations.
│   │   │
│   │   ├── page_table.rs
│   │   │   Structure layouts for PML4, PDPT, PD, and PT entries and flag bitfields.
│   │   │
│   │   ├── frame_allocator.rs
│   │   │   Physical page frame allocator managing 4KB, 2MB, and 1GB physical allocations.
│   │   │
│   │   ├── page_allocator.rs
│   │   │   Runtime virtual memory and page allocation routines.
│   │   │
│   │   ├── pool.rs
│   │   │   Fixed-size block and object memory pools for high-frequency internal allocations.
│   │   │
│   │   ├── ept_allocator.rs
│   │   │   Specialized allocator guaranteeing 4KB-aligned, zeroed physical frames for EPT paging trees.
│   │   │
│   │   ├── ept_tables.rs
│   │   │   Data structures and bitfields representing EPT PML4E, PDPTE, PDE, and PTE entries.
│   │   │
│   │   ├── mapping.rs
│   │   │   Virtual-to-physical and guest-physical-to-host-physical mapping engines.
│   │   │
│   │   └── memory_type.rs
│   │       Memory caching types (Write-Back, Uncacheable, Write-Through, Write-Combining).
│   │
│   ├── guest/
│   │   Logical guest virtual machine (VM) and virtual CPU (vCPU) representations.
│   │
│   │   ├── mod.rs
│   │   │   Declares and exports guest state management modules.
│   │   │
│   │   ├── vcpu.rs
│   │   │   Virtual CPU instance coordinating execution loops, VMCS associations, and thread contexts.
│   │   │
│   │   ├── registers.rs
│   │   │   General-purpose register state (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15).
│   │   │
│   │   ├── segments.rs
│   │   │   Guest segment register state (CS, SS, DS, ES, FS, GS, TR, LDTR) including selectors, bases, limits, and access rights.
│   │   │
│   │   ├── state.rs
│   │   │   Aggregated architectural guest state, flags, and execution lifecycle status.
│   │   │
│   │   ├── memory.rs
│   │   │   Guest physical memory layout, EPT integration, and address space mappings.
│   │   │
│   │   ├── address_space.rs
│   │   │   Guest virtual and physical address space isolation abstractions.
│   │   │
│   │   ├── loader.rs
│   │   │   Guest image loader parsing and preparing guest environments for launch.
│   │   │
│   │   ├── image.rs
│   │   │   Binary image representations and headers (PE/COFF, raw boot images).
│   │   │
│   │   └── firmware.rs
│   │       Emulated or passthrough firmware state and metadata provided to the guest.
│   │
│   ├── smp/
│   │   Symmetric Multiprocessing (SMP) and multi-core management.
│   │
│   │   ├── mod.rs
│   │   │   Declares and exports SMP management components.
│   │   │
│   │   ├── per_cpu.rs
│   │   │   Per-logical-processor private storage, VMM stacks, and local pointers.
│   │   │
│   │   ├── topology.rs
│   │   │   Processor package, core, and hardware thread enumeration and topology tracking.
│   │   │
│   │   ├── startup.rs
│   │   │   Bootstrap processor (BSP) orchestrating multi-processor initialization.
│   │   │
│   │   ├── ap_startup.rs
│   │   │   Application Processor (AP) wake-up sequence using INIT-SIPI-SIPI IPIs.
│   │   │
│   │   ├── rendezvous.rs
│   │   │   Barriers and coordination primitives synchronizing all cores during mode switches.
│   │   │
│   │   └── cpu_mask.rs
│   │       CPU affinity masks and logical processor bitset operations.
│   │
│   ├── boot/
│   │   Pre-hypervisor bootstrap phase executing under the UEFI environment.
│   │
│   │   ├── mod.rs
│   │   │   Declares boot submodules and orchestrates early validation and chainloading.
│   │   │
│   │   ├── uefi.rs
│   │   │   Early UEFI environment configuration (watchdog timer, system table bindings).
│   │   │
│   │   ├── services.rs
│   │   │   Abstractions for querying and invoking UEFI Boot and Runtime Services.
│   │   │
│   │   ├── memory_map.rs
│   │   │   UEFI memory map snapshots, descriptor parsing, and conventional memory counting.
│   │   │
│   │   ├── exit_boot_services.rs
│   │   │   Transition logic for terminating UEFI Boot Services and claiming system memory.
│   │   │
│   │   ├── config.rs
│   │   │   Boot-time configuration parameters and early runtime settings.
│   │   │
│   │   ├── matrix_config.rs
│   │   │   Embedded loader and parser interface for `MatrixConfig.bin`.
│   │   │
│   │   ├── logger.rs
│   │   │   Pre-runtime logging backend directing diagnostic messages through UEFI console/serial.
│   │   │
│   │   └── loaders/
│   │       ├── mod.rs
│   │       │   Declares available guest OS chainloaders.
│   │       │
│   │       └── veracrypt.rs
│   │           Detection and chainloading for VeraCrypt DCS (`DcsBoot.efi`) and Windows (`bootmgfw.efi`).
│   │
│   ├── runtime/
│   │   Post-boot bare-metal runtime environment.
│   │
│   │   ├── mod.rs
│   │   │   Declares and exports core runtime modules.
│   │   │
│   │   ├── panic.rs
│   │   │   Bare-metal Rust panic handler reporting failures to serial before halting.
│   │   │
│   │   ├── serial.rs
│   │   │   UART 16550 serial port driver (COM1, 0x3F8) for unbuffered debug output.
│   │   │
│   │   ├── logger.rs
│   │   │   Global logging implementation integrating Rust `log` macros with the serial driver.
│   │   │
│   │   ├── sync.rs
│   │   │   Core synchronization primitives and atomic wrappers.
│   │   │
│   │   ├── spinlock.rs
│   │   │   Ticket and test-and-set spinlocks tailored for interrupt-safe bare-metal execution.
│   │   │
│   │   ├── once.rs
│   │   │   Thread-safe one-time initialization cell (`OnceCell` equivalent).
│   │   │
│   │   ├── cpu_local.rs
│   │   │   Fast GS-base or MSR-based access to the current processor's private data.
│   │   │
│   │   ├── percpu.rs
│   │   │   Memory management and layout definitions for per-CPU control blocks.
│   │   │
│   │   ├── heap.rs
│   │   │   Bare-metal heap memory manager backing dynamic allocations.
│   │   │
│   │   └── allocator.rs
│   │       Global Rust memory allocator (`#[global_allocator]`) implementation.
│   │
│   ├── diagnostics/
│   │   Hypervisor telemetry, observability, and debugging utilities.
│   │
│   │   ├── mod.rs
│   │   │   Declares and exports diagnostic utilities.
│   │   │
│   │   ├── vmcs_dump.rs
│   │   │   Structured formatting and serial dump of all VMCS fields (Guest, Host, Controls, Data).
│   │   │
│   │   ├── ept_dump.rs
│   │   │   Traversal and diagnostic visualization of active EPT paging tables and translation mappings.
│   │   │
│   │   ├── cpu_dump.rs
│   │   │   Dumps general-purpose registers, control registers, and CPUID capabilities.
│   │   │
│   │   ├── nested_dump.rs
│   │   │   Dumps nested virtualization state, including VMCS12 and VMCS02 comparisons.
│   │   │
│   │   ├── crash_dump.rs
│   │   │   Crash recorder capturing processor context upon triple faults or fatal VMM panics.
│   │   │
│   │   └── statistics.rs
│   │       VM-exit frequency counters, timing metrics, and performance telemetry.
│   │
│   └── config/
│       │   Binary configuration parsing and schema representation.
│       │
│       ├── mod.rs
│       │   Declares configuration structures and parsing functions.
│       │
│       ├── flags.rs
│       │   Feature toggles, hypervisor policies, and runtime control flags.
│       │
│       ├── parser.rs
│       │   Deserializer parsing raw binary streams into validated `MatrixConfig` structures.
│       │
│       └── format.rs
│           Header layout, magic constants, versions, and wire-format definitions for `MatrixConfig`.
│
├── asm/
│   │   Hand-written assembly routines for low-level context transitions.
│   │
│   ├── vm_entry.S
│   │   Saves host registers and executes `VMLAUNCH` or `VMRESUME` to enter guest mode.
│   │
│   ├── vm_exit.S
│   │   Hardware VM-exit landing point; saves guest general-purpose registers and invokes the Rust exit handler.
│   │
│   ├── ap_startup.S
│   │   16-bit real-mode reset stub transitioning Application Processors to 64-bit long mode.
│   │
│   └── interrupt_stubs.S
│       Low-level interrupt service routine (ISR) entry stubs for IDT exception vectors.
│
├── tests/
│   │   Host-runnable and unit test suites for MatrixHV components.
│   │
│   ├── vmx/
│   │   ├── vmxon.rs
│   │   │   Unit tests verifying VMXON region layout and capability alignment checks.
│   │   │
│   │   ├── vmcs.rs
│   │   │   Unit tests for VMCS field abstractions, revisions, and state builders.
│   │   │
│   │   ├── controls.rs
│   │   │   Tests for control bit composition, MSR boundary enforcement, and validation.
│   │   │
│   │   └── entry.rs
│   │       Tests verifying VM-entry prerequisite checks.
│   │
│   ├── ept/
│   │   ├── mapping.rs
│   │   │   Tests for EPT table creation, 4KB/2MB/1GB page mappings, and split logic.
│   │   │
│   │   ├── permissions.rs
│   │   │   Tests verifying EPT read, write, execute permissions and memory types.
│   │   │
│   │   └── invalidation.rs
│   │       Tests checking INVEPT descriptor encoding and invalidation scoping.
│   │
│   ├── nested/
│   │   ├── vmxon.rs
│   │   │   Tests validating L1 virtual VMXON semantics and error handling.
│   │   │
│   │   ├── vmcs12.rs
│   │   │   Tests for VMCS12 encoding, decoding, and field consistency verification.
│   │   │
│   │   ├── vmcs02.rs
│   │   │   Tests for VMCS02 synthesis combining VMCS01 and VMCS12.
│   │   │
│   │   ├── exit_reflection.rs
│   │   │   Tests verifying exit reflection routing decisions (L2 exit handled by L0 vs reflected to L1).
│   │   │
│   │   └── nested_ept.rs
│   │       Tests verifying nested two-dimensional address translation (EPT02).
│   │
│   ├── memory/
│   │   ├── allocator.rs
│   │   │   Tests for frame and heap allocators under allocation and deallocation cycles.
│   │   │
│   │   └── paging.rs
│   │       Tests for standard x86-64 page table translation routines.
│   │
│   └── config/
│       └── matrix_config.rs
│           Unit tests parsing valid, malformed, and boundary-condition `MatrixConfig.bin` payloads.
│
├── scripts/
│   │   PowerShell automation scripts for compilation, packaging, image creation, and virtualization.
│   │
│   ├── buildauto.ps1
│   │   Master automated pipeline orchestrating compilation, image generation, and packaging.
│   │
│   ├── build_debug.ps1
│   │   Compiles MatrixHV in Debug configuration with unoptimized debug symbols.
│   │
│   ├── build_release.ps1
│   │   Compiles MatrixHV in Release configuration with full optimizations (LTO, strip).
│   │
│   ├── make_image.ps1
│   │   Generates a raw FAT32 bootable disk image (`.img`) embedding the UEFI binary and optional payloads.
│   │
│   ├── make_config.ps1
│   │   Generates or serializes a binary `MatrixConfig.bin` file from input parameters.
│   │
│   ├── run_qemu.ps1
│   │   Automated script launching QEMU with OVMF UEFI firmware to test MatrixHV.
│   │
│   ├── run_qemu_nested.ps1
│   │   Launches QEMU with nested VT-x enabled (`-cpu host` or nested VMX flags).
│   │
│   ├── clean.ps1
│   │   Cleans target build directories, cached objects, and generated images.
│   │
│   └── package.ps1
│       Packages final deliverables into a distribution zip archive along with SHA-256 checksums.
│
├── tools/
│   │   Host-side CLI utilities supporting MatrixHV development.
│   │
│   ├── matrixconfig/
│   │   │   CLI tool for inspecting, editing, validating, and generating `MatrixConfig.bin` files.
│   │   └── ...
│   │
│   └── vmcsdump/
│       │   CLI parser and visualizer for raw VMCS binary dumps.
│       └── ...
│
└── builds/
    │   Output root for generated build artifacts (must remain ignored by Git).
    │
    ├── debug/
    │   ├── MatrixHV.efi
    │   │   Compiled UEFI binary in Debug mode.
    │   │
    │   ├── MatrixConfig.bin
    │   │   Debug configuration payload.
    │   │
    │   └── MatrixHV.img
    │       FAT32 bootable disk image for debug testing.
    │
    └── release/
        ├── MatrixHV.efi
        │   Optimized release UEFI binary.
        │
        ├── MatrixConfig.bin
        │   Release configuration payload.
        │
        └── MatrixHV.img
            Optimized FAT32 bootable disk image for deployment.
```
