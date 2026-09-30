use alloc::vec::Vec;

use core::arch::global_asm;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use uefi::Status;
use uefi::boot;
use uefi::mem::memory_map::MemoryType;
use uefi::proto::pi::mp::MpServices;

use crate::arch;
use crate::hv_core::vmcs::VmcsRegion;
use crate::hv_core::entry::{
    VmlaunchError, VmlaunchProbeResourceAddresses, VmlaunchProbeResources, VmlaunchReport,
};
use crate::hv_core::ept::{EptComposition, EptError, IdentityEpt};
use crate::hv_core::residency::{
    BOOT_GUEST_STACK_PAGES, HOST_STACK_PAGES, RESIDENT_BOOT_CONTEXT_PAGES, ResidentApLaunch,
    ResidentHostSelectors, ResidentHostTables, ResidentProbeError,
};
use crate::hv_core::vmxon::{self, VmxonRegion};
use crate::memory::{AddressConstraint, PAGE_SIZE, ResidentPages};
use crate::nested::{NestedVmxCapabilities, native_vmcs_shadowing_available};
use crate::runtime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TopologyReport {
    pub(crate) total_processors: usize,
    pub(crate) enabled_processors: usize,
    pub(crate) current_processor: usize,
    pub(crate) bsp_processor: usize,
    pub(crate) first_enabled_ap: Option<usize>,
}

pub(crate) fn enumerate() -> Result<TopologyReport, Status> {
    let handle = boot::get_handle_for_protocol::<MpServices>().map_err(|error| error.status())?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle).map_err(|error| error.status())?;
    let count = mp
        .get_number_of_processors()
        .map_err(|error| error.status())?;
    let current_processor = mp.who_am_i().map_err(|error| error.status())?;

    let mut bsp_processor = None;
    let mut first_enabled_ap = None;

    for processor_number in 0..count.total {
        let info = mp
            .get_processor_info(processor_number)
            .map_err(|error| error.status())?;
        runtime::info(format_args!(
            "smp processor={} id={:#x} bsp={} enabled={} healthy={} package={} core={} thread={}",
            processor_number,
            info.processor_id,
            info.is_bsp(),
            info.is_enabled(),
            info.is_healthy(),
            info.location.package,
            info.location.core,
            info.location.thread
        ));

        if info.is_bsp() {
            if bsp_processor.replace(processor_number).is_some() {
                return Err(Status::DEVICE_ERROR);
            }
        } else if info.is_enabled() && first_enabled_ap.is_none() {
            first_enabled_ap = Some(processor_number);
        }
    }

    let bsp_processor = bsp_processor.ok_or(Status::DEVICE_ERROR)?;
    Ok(TopologyReport {
        total_processors: count.total,
        enabled_processors: count.enabled,
        current_processor,
        bsp_processor,
        first_enabled_ap,
    })
}

const NESTED_VMXON_OPERAND_OFFSET: u64 = 8;
const NESTED_VMCS12_OPERAND_POINTER_OFFSET: usize = 16;
const NESTED_VMPTRST_DESTINATION_POINTER_OFFSET: usize = 24;
const NESTED_VMCS12_OPERAND_PAGE_OFFSET: u64 = PAGE_SIZE as u64;
const NESTED_VMPTRST_DESTINATION_OFFSET: u64 = NESTED_VMCS12_OPERAND_PAGE_OFFSET + 8;
const NESTED_EPT12_POINTER_OFFSET: usize = 32;
const NESTED_EPT_SOURCE_POINTER_OFFSET: usize = 40;
const NESTED_EPT_TARGET_POINTER_OFFSET: usize = 48;
pub(crate) const NESTED_EPT_SECOND_TARGET_POINTER_OFFSET: usize = 56;
pub(crate) const NESTED_EPT12_SOURCE_LEAF_POINTER_OFFSET: usize = 64;
pub(crate) const NESTED_INVEPT_DESCRIPTOR_OFFSET: usize = 72;
pub(crate) const NESTED_INVEPT_RIP_OFFSET: usize = 88;
pub(crate) const NESTED_INVEPT_AFTER_RIP_OFFSET: usize = 96;
pub(crate) const NESTED_INVVPID_DESCRIPTOR_OFFSET: usize = 104;
pub(crate) const NESTED_INVVPID_RIP_OFFSET: usize = 120;
pub(crate) const NESTED_INVVPID_AFTER_RIP_OFFSET: usize = 128;
pub(crate) const NESTED_EPT_SOURCE_MARKER: u64 = 0x4e45_5054_5352_4331;
pub(crate) const NESTED_EPT_TARGET_MARKER: u64 = 0x4e45_5054_5447_5431;
pub(crate) const NESTED_EPT_SECOND_TARGET_MARKER: u64 = 0x4e45_5054_5447_5432;
const NESTED_MSR_STATE_PAGES: usize = 10;

struct ResidentVmcsShadow {
    vmcs_region: VmcsRegion,
    vmread_bitmap: ResidentPages,
    vmwrite_bitmap: ResidentPages,
}

pub(crate) struct ResidentCpuResources {
    pub(crate) vmxon_region: VmxonRegion,
    pub(crate) vmcs_region: VmcsRegion,
    pub(crate) nested_vmcs02_region: VmcsRegion,
    vmcs_shadow: Option<ResidentVmcsShadow>,
    pub(crate) host_tables: ResidentHostTables,
    pub(crate) context_pages: ResidentPages,
    pub(crate) guest_stack: ResidentPages,
    pub(crate) host_stack: ResidentPages,
    pub(crate) resident_msr_state: ResidentPages,
    pub(crate) nested_msr_state: ResidentPages,
    pub(crate) nested_eptp_list: ResidentPages,
    pub(crate) nested_eptp_tables: ResidentPages,
    pub(crate) nested_vmxon_page: ResidentPages,
    pub(crate) nested_vmcs12_pages: ResidentPages,
    nested_ept_source_page: ResidentPages,
    nested_ept_target_page: ResidentPages,
    nested_ept_second_target_page: ResidentPages,
    nested_ept12: Option<IdentityEpt>,
    nested_ept02: Option<IdentityEpt>,
    nested_ept02_alternate: Option<IdentityEpt>,
    nested_ept_composition: Option<EptComposition>,
    nested_ept_alternate_composition: Option<EptComposition>,
    nested_ept12_source_leaf: u64,
    nested_ept12_source_leaf_attributes: u64,
}

impl ResidentCpuResources {
    pub(crate) fn allocate(
        vmx_basic: u64,
        fatal_handler: u64,
        gp_handler: u64,
        exception_stubs: u64,
    ) -> Result<Self, ResidentProbeError> {
        let vmxon_region = VmxonRegion::allocate(vmx_basic).map_err(ResidentProbeError::Vmxon)?;
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(vmxon::revision_id(vmx_basic));
        let mut nested_vmcs02_region = VmcsRegion::allocate(vmx_basic)?;
        nested_vmcs02_region.write_revision_id(vmxon::revision_id(vmx_basic));
        let vmcs_shadow = if native_vmcs_shadowing_available(unsafe {
            arch::read_msr(arch::IA32_VMX_PROCBASED_CTLS2)
        }) {
            let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
            vmcs_region.write_revision_id(vmxon::revision_id(vmx_basic) | (1 << 31));
            let bitmap_constraint = if vmxon::region_uses_32_bit_physical_addresses(vmx_basic) {
                AddressConstraint::Max(u32::MAX as u64)
            } else {
                AddressConstraint::Any
            };
            let vmread_bitmap =
                ResidentPages::allocate_initialized(1, bitmap_constraint, |bytes| {
                    bytes.fill(0xff);
                })
                .map_err(ResidentProbeError::Allocation)?;
            let vmwrite_bitmap =
                ResidentPages::allocate_initialized(1, bitmap_constraint, |bytes| {
                    bytes.fill(0xff);
                })
                .map_err(ResidentProbeError::Allocation)?;
            Some(ResidentVmcsShadow {
                vmcs_region,
                vmread_bitmap,
                vmwrite_bitmap,
            })
        } else {
            None
        };
        let host_tables = ResidentHostTables::allocate(
            fatal_handler,
            gp_handler,
            exception_stubs,
            ResidentHostSelectors::fixed(),
        )?;
        let context_pages =
            ResidentPages::allocate(RESIDENT_BOOT_CONTEXT_PAGES, AddressConstraint::Any)
                .map_err(ResidentProbeError::Allocation)?;
        // The OS loader accesses the firmware caller's stack before restoring firmware CR3.
        // Reserved pages can be absent from the loader's identity mapping.
        let guest_stack = ResidentPages::allocate_typed(
            BOOT_GUEST_STACK_PAGES,
            AddressConstraint::Any,
            MemoryType::LOADER_DATA,
        )
        .map_err(ResidentProbeError::Allocation)?;
        let host_stack = ResidentPages::allocate(HOST_STACK_PAGES, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let resident_msr_state = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_msr_state =
            ResidentPages::allocate(NESTED_MSR_STATE_PAGES, AddressConstraint::Any)
                .map_err(ResidentProbeError::Allocation)?;
        let nested_eptp_list = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_eptp_tables = ResidentPages::allocate(64, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_vmxon_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_vmcs12_pages = ResidentPages::allocate(2, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_ept_source_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_ept_target_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let nested_ept_second_target_page = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let capabilities = NestedVmxCapabilities::vmxon_vmxoff(vmx_basic);
        let nested_vmcs12_region = nested_vmcs12_pages.physical_address();
        let nested_vmcs12_operand = nested_vmcs12_region + NESTED_VMCS12_OPERAND_PAGE_OFFSET;
        let nested_vmptrst_destination = nested_vmcs12_region + NESTED_VMPTRST_DESTINATION_OFFSET;
        unsafe {
            let page = nested_vmxon_page.pointer().as_ptr();
            page.write_bytes(0, nested_vmxon_page.byte_len());
            page.cast::<u32>().write(capabilities.revision_id);
            page.add(NESTED_VMXON_OPERAND_OFFSET as usize)
                .cast::<u64>()
                .write(nested_vmxon_page.physical_address());
            page.add(NESTED_VMCS12_OPERAND_POINTER_OFFSET)
                .cast::<u64>()
                .write(nested_vmcs12_operand);
            page.add(NESTED_VMPTRST_DESTINATION_POINTER_OFFSET)
                .cast::<u64>()
                .write(nested_vmptrst_destination);

            let vmcs12 = nested_vmcs12_pages.pointer().as_ptr();
            vmcs12.write_bytes(0, nested_vmcs12_pages.byte_len());
            vmcs12.cast::<u32>().write(capabilities.revision_id);
            vmcs12
                .add(NESTED_VMCS12_OPERAND_PAGE_OFFSET as usize)
                .cast::<u64>()
                .write(nested_vmcs12_region);
            vmcs12
                .add(NESTED_VMPTRST_DESTINATION_OFFSET as usize)
                .cast::<u64>()
                .write(u64::MAX);
            nested_ept_source_page
                .pointer()
                .as_ptr()
                .cast::<u64>()
                .write(NESTED_EPT_SOURCE_MARKER);
            nested_ept_target_page
                .pointer()
                .as_ptr()
                .cast::<u64>()
                .write(NESTED_EPT_TARGET_MARKER);
            nested_ept_second_target_page
                .pointer()
                .as_ptr()
                .cast::<u64>()
                .write(NESTED_EPT_SECOND_TARGET_MARKER);
        }

        Ok(Self {
            vmxon_region,
            vmcs_region,
            nested_vmcs02_region,
            vmcs_shadow,
            host_tables,
            context_pages,
            guest_stack,
            host_stack,
            resident_msr_state,
            nested_msr_state,
            nested_eptp_list,
            nested_eptp_tables,
            nested_vmxon_page,
            nested_vmcs12_pages,
            nested_ept_source_page,
            nested_ept_target_page,
            nested_ept_second_target_page,
            nested_ept12: None,
            nested_ept02: None,
            nested_ept02_alternate: None,
            nested_ept_composition: None,
            nested_ept_alternate_composition: None,
            nested_ept12_source_leaf: 0,
            nested_ept12_source_leaf_attributes: 0,
        })
    }

    pub(crate) fn prepare_nested_ept(
        &mut self,
        ept01: &IdentityEpt,
        ept12_template: &IdentityEpt,
    ) -> Result<EptComposition, EptError> {
        let source_gpa = self.nested_ept_source_page.physical_address();
        let target_gpa = self.nested_ept_target_page.physical_address();
        let second_target_gpa = self.nested_ept_second_target_page.physical_address();
        let mut ept12 = ept12_template.clone_identity_tables()?;
        ept12.remap_page(source_gpa, target_gpa)?;
        let source_leaf = ept12.leaf_entry_physical_address(source_gpa)?;
        let source_leaf_attributes = ept12.leaf_entry_value(source_gpa)? & 0xfff;
        let mut ept02 = ept01.sparse_shadow()?;
        let composition = ept02.compose_page(&ept12, ept01, source_gpa)?;
        ept12.remap_page(source_gpa, second_target_gpa)?;
        let mut ept02_alternate = ept01.sparse_shadow()?;
        let alternate_composition = ept02_alternate.compose_page(&ept12, ept01, source_gpa)?;
        ept12.remap_page(source_gpa, target_gpa)?;
        unsafe {
            let metadata = self.nested_vmxon_page.pointer().as_ptr();
            metadata
                .add(NESTED_EPT12_POINTER_OFFSET)
                .cast::<u64>()
                .write(ept12.ept_pointer());
            metadata
                .add(NESTED_EPT_SOURCE_POINTER_OFFSET)
                .cast::<u64>()
                .write(source_gpa);
            metadata
                .add(NESTED_EPT_TARGET_POINTER_OFFSET)
                .cast::<u64>()
                .write(target_gpa);
            metadata
                .add(NESTED_EPT_SECOND_TARGET_POINTER_OFFSET)
                .cast::<u64>()
                .write(second_target_gpa);
            metadata
                .add(NESTED_EPT12_SOURCE_LEAF_POINTER_OFFSET)
                .cast::<u64>()
                .write(source_leaf);
            metadata
                .add(NESTED_INVEPT_DESCRIPTOR_OFFSET)
                .cast::<u64>()
                .write(ept12.ept_pointer());
            metadata
                .add(NESTED_INVEPT_DESCRIPTOR_OFFSET + size_of::<u64>())
                .cast::<u64>()
                .write(0);
            metadata
                .add(NESTED_INVVPID_DESCRIPTOR_OFFSET)
                .cast::<u64>()
                .write(1);
            metadata
                .add(NESTED_INVVPID_DESCRIPTOR_OFFSET + size_of::<u64>())
                .cast::<u64>()
                .write(0);
        }
        self.nested_ept12 = Some(ept12);
        self.nested_ept02 = Some(ept02);
        self.nested_ept02_alternate = Some(ept02_alternate);
        self.nested_ept_composition = Some(composition);
        self.nested_ept_alternate_composition = Some(alternate_composition);
        self.nested_ept12_source_leaf = source_leaf;
        self.nested_ept12_source_leaf_attributes = source_leaf_attributes;
        Ok(composition)
    }

    pub(crate) fn nested_vmxon_operand(&self) -> u64 {
        self.nested_vmxon_page.physical_address() + NESTED_VMXON_OPERAND_OFFSET
    }

    pub(crate) fn nested_vmxon_region(&self) -> u64 {
        self.nested_vmxon_page.physical_address()
    }

    pub(crate) fn nested_vmcs12_operand(&self) -> u64 {
        self.nested_vmcs12_pages.physical_address() + NESTED_VMCS12_OPERAND_PAGE_OFFSET
    }

    pub(crate) fn nested_vmcs12_region(&self) -> u64 {
        self.nested_vmcs12_pages.physical_address()
    }

    pub(crate) fn nested_vmptrst_destination(&self) -> u64 {
        self.nested_vmcs12_pages.physical_address() + NESTED_VMPTRST_DESTINATION_OFFSET
    }

    pub(crate) fn nested_vmcs02_region(&self) -> u64 {
        self.nested_vmcs02_region.physical_address()
    }

    pub(crate) fn vmcs_shadow_resources(&self) -> Option<(u64, u64, u64)> {
        self.vmcs_shadow.as_ref().map(|shadow| {
            (
                shadow.vmcs_region.physical_address(),
                shadow.vmread_bitmap.physical_address(),
                shadow.vmwrite_bitmap.physical_address(),
            )
        })
    }

    pub(crate) fn nested_ept12_pointer(&self) -> Option<u64> {
        self.nested_ept12.as_ref().map(IdentityEpt::ept_pointer)
    }

    pub(crate) fn nested_ept02_pointer(&self) -> Option<u64> {
        self.nested_ept02.as_ref().map(IdentityEpt::ept_pointer)
    }

    pub(crate) fn nested_ept02_alternate_pointer(&self) -> Option<u64> {
        self.nested_ept02_alternate
            .as_ref()
            .map(IdentityEpt::ept_pointer)
    }

    pub(crate) fn nested_ept02_table_pools(&self) -> Option<[(u64, usize, usize); 2]> {
        Some([
            self.nested_ept02.as_ref()?.protection_table_pool(),
            self.nested_ept02_alternate
                .as_ref()?
                .protection_table_pool(),
        ])
    }

    pub(crate) fn nested_ept_source_gpa(&self) -> u64 {
        self.nested_ept_source_page.physical_address()
    }

    pub(crate) fn nested_ept_target_gpa(&self) -> u64 {
        self.nested_ept_target_page.physical_address()
    }

    pub(crate) fn nested_ept_second_target_gpa(&self) -> u64 {
        self.nested_ept_second_target_page.physical_address()
    }

    pub(crate) fn nested_ept12_source_leaf(&self) -> u64 {
        self.nested_ept12_source_leaf
    }

    pub(crate) fn nested_ept12_source_leaf_attributes(&self) -> u64 {
        self.nested_ept12_source_leaf_attributes
    }

    pub(crate) fn nested_ept_composition(&self) -> Option<EptComposition> {
        self.nested_ept_composition
    }

    pub(crate) fn nested_ept_alternate_composition(&self) -> Option<EptComposition> {
        self.nested_ept_alternate_composition
    }

    pub(crate) fn nested_ept02_table_regions(&self) -> Vec<(u64, usize)> {
        let mut regions = self
            .nested_ept02
            .as_ref()
            .map(IdentityEpt::table_regions)
            .unwrap_or_default();
        if let Some(ept02) = &self.nested_ept02_alternate {
            regions.extend(ept02.table_regions());
        }
        regions
    }

    pub(crate) fn conceal_guest_access(
        &self,
        ept: &mut IdentityEpt,
        zero_page_physical_address: u64,
    ) -> Result<(), EptError> {
        ept.conceal_guest_access(
            self.nested_eptp_list.physical_address(),
            self.nested_eptp_list.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.nested_eptp_tables.physical_address(),
            self.nested_eptp_tables.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.vmxon_region.physical_address(),
            1,
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.vmcs_region.physical_address(),
            1,
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.nested_vmcs02_region.physical_address(),
            1,
            zero_page_physical_address,
        )?;
        if let Some(shadow) = &self.vmcs_shadow {
            ept.conceal_guest_access(
                shadow.vmcs_region.physical_address(),
                1,
                zero_page_physical_address,
            )?;
            ept.conceal_guest_access(
                shadow.vmread_bitmap.physical_address(),
                shadow.vmread_bitmap.pages(),
                zero_page_physical_address,
            )?;
            ept.conceal_guest_access(
                shadow.vmwrite_bitmap.physical_address(),
                shadow.vmwrite_bitmap.pages(),
                zero_page_physical_address,
            )?;
        }
        ept.conceal_guest_access(
            self.host_tables.pages.physical_address(),
            self.host_tables.pages.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.context_pages.physical_address(),
            self.context_pages.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.host_stack.physical_address(),
            self.host_stack.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.resident_msr_state.physical_address(),
            self.resident_msr_state.pages(),
            zero_page_physical_address,
        )?;
        ept.conceal_guest_access(
            self.nested_msr_state.physical_address(),
            self.nested_msr_state.pages(),
            zero_page_physical_address,
        )?;
        Ok(())
    }
}

pub(crate) fn allocate_resident_ap_resources(
    vmx_basic: u64,
    fatal_handler: u64,
    gp_handler: u64,
    exception_stubs: u64,
) -> Result<Vec<(usize, ResidentCpuResources)>, ResidentProbeError> {
    let topology = enumerate().map_err(ResidentProbeError::Allocation)?;
    if topology.total_processors > 64 || topology.bsp_processor != 0 {
        return Err(ResidentProbeError::Allocation(Status::UNSUPPORTED));
    }
    let mut ap_resources = Vec::new();
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    for processor_number in 0..topology.total_processors {
        let info = mp
            .get_processor_info(processor_number)
            .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
        if info.is_enabled() && !info.is_bsp() {
            ap_resources.push((
                processor_number,
                ResidentCpuResources::allocate(
                    vmx_basic,
                    fatal_handler,
                    gp_handler,
                    exception_stubs,
                )?,
            ));
        }
    }
    Ok(ap_resources)
}

const INTERRUPT_FLAG: u64 = 1 << 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuLocalState {
    pub(crate) apic_id: u32,
    pub(crate) cr0: u64,
    pub(crate) cr3: u64,
    pub(crate) cr4: u64,
    pub(crate) rflags: u64,
    pub(crate) dr7: u64,
    pub(crate) debugctl: u64,
    pub(crate) fs_base: u64,
    pub(crate) gs_base: u64,
    pub(crate) gdtr_base: u64,
    pub(crate) gdtr_limit: u16,
    pub(crate) idtr_base: u64,
    pub(crate) idtr_limit: u16,
}

impl CpuLocalState {
    fn capture() -> Self {
        let gdtr = arch::read_gdtr();
        let idtr = arch::read_idtr();
        Self {
            apic_id: arch::apic_id(),
            cr0: arch::read_cr0(),
            cr3: arch::read_cr3(),
            cr4: arch::read_cr4(),
            rflags: arch::read_rflags(),
            dr7: arch::read_dr7(),
            debugctl: unsafe { arch::read_msr(arch::IA32_DEBUGCTL) },
            fs_base: arch::ArchitecturalMsr::FsBase.read(),
            gs_base: arch::ArchitecturalMsr::GsBase.read(),
            gdtr_base: gdtr.base,
            gdtr_limit: gdtr.limit,
            idtr_base: idtr.base,
            idtr_limit: idtr.limit,
        }
    }

    fn vmx_state_restored(self, after: Self) -> bool {
        self.apic_id == after.apic_id
            && self.cr0 == after.cr0
            && self.cr3 == after.cr3
            && self.cr4 == after.cr4
            && (self.rflags ^ after.rflags) & INTERRUPT_FLAG == 0
            && self.dr7 == after.dr7
            && self.debugctl == after.debugctl
            && self.fs_base == after.fs_base
            && self.gs_base == after.gs_base
            && self.gdtr_base == after.gdtr_base
            && self.gdtr_limit == after.gdtr_limit
            && self.idtr_base == after.idtr_base
            && self.idtr_limit == after.idtr_limit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApplicationProcessorVmxProofReport {
    pub(crate) processor_number: usize,
    pub(crate) processor_id: u64,
    pub(crate) bsp_resources: VmlaunchProbeResourceAddresses,
    pub(crate) ap_resources: VmlaunchProbeResourceAddresses,
    pub(crate) initial_state: CpuLocalState,
    pub(crate) final_state: CpuLocalState,
    pub(crate) vmlaunch: VmlaunchReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationProcessorVmxProofError {
    Uefi(Status),
    ProcessorIsBsp,
    ProcessorDisabled,
    ResourceAllocation(VmlaunchError),
    ResourceAlias,
    BspProbe(VmlaunchError),
    BspStateNotRestored,
    CallbackDidNotRun,
    ApProbe(VmlaunchError),
    ApStateNotRestored,
}

struct ApProbeContext {
    resources: *mut VmlaunchProbeResources,
    initial_state: Option<CpuLocalState>,
    final_state: Option<CpuLocalState>,
    result: Option<Result<VmlaunchReport, VmlaunchError>>,
}

pub(crate) fn prove_application_processor_vmx(
    processor_number: usize,
) -> Result<ApplicationProcessorVmxProofReport, ApplicationProcessorVmxProofError> {
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    let processor_info = mp
        .get_processor_info(processor_number)
        .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    if processor_info.is_bsp() {
        return Err(ApplicationProcessorVmxProofError::ProcessorIsBsp);
    }
    if !processor_info.is_enabled() {
        return Err(ApplicationProcessorVmxProofError::ProcessorDisabled);
    }

    let mut bsp_resources = VmlaunchProbeResources::allocate()
        .map_err(ApplicationProcessorVmxProofError::ResourceAllocation)?;
    let mut ap_resources = VmlaunchProbeResources::allocate()
        .map_err(ApplicationProcessorVmxProofError::ResourceAllocation)?;
    let bsp_addresses = bsp_resources.addresses();
    let ap_addresses = ap_resources.addresses();
    if resources_alias(bsp_addresses, ap_addresses) {
        return Err(ApplicationProcessorVmxProofError::ResourceAlias);
    }

    runtime::info(format_args!(
        "smp vmx proof resources bsp vmxon={:#x} vmcs={:#x} guest_stack={:#x} ap vmxon={:#x} vmcs={:#x} guest_stack={:#x}",
        bsp_addresses.vmxon,
        bsp_addresses.vmcs,
        bsp_addresses.guest_stack,
        ap_addresses.vmxon,
        ap_addresses.vmcs,
        ap_addresses.guest_stack
    ));

    let bsp_initial = CpuLocalState::capture();
    bsp_resources
        .run()
        .map_err(ApplicationProcessorVmxProofError::BspProbe)?;
    let bsp_final = CpuLocalState::capture();
    if !bsp_initial.vmx_state_restored(bsp_final) {
        log_state_mismatch("bsp", bsp_initial, bsp_final);
        return Err(ApplicationProcessorVmxProofError::BspStateNotRestored);
    }

    let mut context = ApProbeContext {
        resources: &mut ap_resources,
        initial_state: None,
        final_state: None,
        result: None,
    };
    runtime::phase("smp.cpu1_vmx.startup_this_ap.start");
    mp.startup_this_ap(
        processor_number,
        application_processor_vmx_callback,
        (&mut context as *mut ApProbeContext).cast::<c_void>(),
        None,
        Some(Duration::from_secs(5)),
    )
    .map_err(|error| ApplicationProcessorVmxProofError::Uefi(error.status()))?;
    runtime::phase("smp.cpu1_vmx.startup_this_ap.returned");

    let initial_state = context
        .initial_state
        .ok_or(ApplicationProcessorVmxProofError::CallbackDidNotRun)?;
    let final_state = context
        .final_state
        .ok_or(ApplicationProcessorVmxProofError::CallbackDidNotRun)?;
    let vmlaunch = context
        .result
        .ok_or(ApplicationProcessorVmxProofError::CallbackDidNotRun)?
        .map_err(ApplicationProcessorVmxProofError::ApProbe)?;
    if !initial_state.vmx_state_restored(final_state) {
        log_state_mismatch("ap", initial_state, final_state);
        return Err(ApplicationProcessorVmxProofError::ApStateNotRestored);
    }
    runtime::info(format_args!(
        "smp cpu={processor_number} restored gdtr={:#x}/{} idtr={:#x}/{}",
        final_state.gdtr_base,
        final_state.gdtr_limit,
        final_state.idtr_base,
        final_state.idtr_limit
    ));

    Ok(ApplicationProcessorVmxProofReport {
        processor_number,
        processor_id: processor_info.processor_id,
        bsp_resources: bsp_addresses,
        ap_resources: ap_addresses,
        initial_state,
        final_state,
        vmlaunch,
    })
}

fn log_state_mismatch(processor: &str, before: CpuLocalState, after: CpuLocalState) {
    runtime::error(format_args!("smp {processor} state before={before:?}"));
    runtime::error(format_args!("smp {processor} state after={after:?}"));
}

extern "efiapi" fn application_processor_vmx_callback(argument: *mut c_void) {
    let context = unsafe { &mut *argument.cast::<ApProbeContext>() };
    let initial_state = CpuLocalState::capture();
    context.initial_state = Some(initial_state);
    runtime::info(format_args!(
        "smp cpu1 callback apic_id={:#x} cr0={:#x} cr3={:#x} cr4={:#x} rflags={:#x}",
        initial_state.apic_id,
        initial_state.cr0,
        initial_state.cr3,
        initial_state.cr4,
        initial_state.rflags
    ));
    runtime::phase("smp.cpu1_vmx.vmlaunch.start");
    let resources = unsafe { &mut *context.resources };
    context.result = Some(resources.run());
    context.final_state = Some(CpuLocalState::capture());
    runtime::phase("smp.cpu1_vmx.vmlaunch.returned");
}

fn resources_alias(
    left: VmlaunchProbeResourceAddresses,
    right: VmlaunchProbeResourceAddresses,
) -> bool {
    let left_addresses = [left.vmxon, left.vmcs, left.guest_stack];
    let right_addresses = [right.vmxon, right.vmcs, right.guest_stack];
    left_addresses
        .iter()
        .any(|left_address| right_addresses.contains(left_address))
}

struct ApBatchEntry {
    processor_number: usize,
    launch: *mut c_void,
}

struct ApBatchContext {
    mp: *const MpServices,
    entries: *const ApBatchEntry,
    entry_count: usize,
    callback_failed: AtomicBool,
}

pub(crate) fn launch_all(launches: &mut [ResidentApLaunch<'_>]) -> Result<(), ResidentProbeError> {
    if launches.is_empty() {
        return Ok(());
    }
    let handle = boot::get_handle_for_protocol::<MpServices>()
        .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle)
        .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    let entries: Vec<_> = launches
        .iter_mut()
        .map(|launch| ApBatchEntry {
            processor_number: launch.processor_number,
            launch: (launch as *mut ResidentApLaunch<'_>).cast(),
        })
        .collect();
    let context = ApBatchContext {
        mp: &*mp,
        entries: entries.as_ptr(),
        entry_count: entries.len(),
        callback_failed: AtomicBool::new(false),
    };
    // The blocking call keeps each AP's distinct launch resources alive until all callbacks end.
    mp.startup_all_aps(
        false,
        callback,
        (&context as *const ApBatchContext).cast_mut().cast(),
        None,
        Some(Duration::from_secs(10)),
    )
    .map_err(|error| ResidentProbeError::Allocation(error.status()))?;
    if context.callback_failed.load(Ordering::Acquire) {
        return Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR));
    }
    Ok(())
}

extern "efiapi" fn callback(argument: *mut c_void) {
    let context = unsafe { &*argument.cast::<ApBatchContext>() };
    let mp = unsafe { &*context.mp };
    let Ok(processor_number) = mp.who_am_i() else {
        context.callback_failed.store(true, Ordering::Release);
        return;
    };
    let entries = unsafe { core::slice::from_raw_parts(context.entries, context.entry_count) };
    let Some(entry) = entries
        .iter()
        .find(|entry| entry.processor_number == processor_number)
    else {
        context.callback_failed.store(true, Ordering::Release);
        return;
    };
    unsafe {
        matrixhv_ap_launch_asm(entry.launch);
    }
}

#[unsafe(no_mangle)]
unsafe extern "efiapi" fn matrixhv_ap_prepare(
    argument: *mut ResidentApLaunch<'_>,
    guest_rsp: u64,
    guest_rip: u64,
) -> u64 {
    let launch = unsafe { &mut *argument };
    match launch.prepare(guest_rsp, guest_rip) {
        Ok(nested_vmxon_operand) => nested_vmxon_operand,
        Err(error) => {
            crate::runtime::error(format_args!("smp resident AP prepare error={error:?}"));
            0
        }
    }
}

unsafe extern "efiapi" {
    fn matrixhv_ap_launch_asm(argument: *mut c_void);
}

#[unsafe(no_mangle)]
extern "efiapi" fn matrixhv_ap_launch_failed(flags: u64) -> ! {
    let error = crate::hv_core::vmcs::vmread(crate::hv_core::vmcs::VM_INSTRUCTION_ERROR);
    crate::runtime::error(format_args!(
        "smp resident AP VMLAUNCH failed flags={flags:#x} instruction_error={error:?}"
    ));
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

// The guest resumes on the firmware stack and returns through the original MP callback.
// Only the persistent exit stack and VMCS remain owned by root after this point.
global_asm!(
    include_str!("asm/ap_launch.S"),
    nested_probe_failed = const crate::hv_core::residency::RESIDENT_VMCALL_NESTED_PROBE_FAILED,
    guest_rip_field = const crate::nested::VMCS_FIELD_GUEST_RIP,
    guest_rsp_field = const crate::nested::VMCS_FIELD_GUEST_RSP,
    guest_rflags_field = const crate::nested::VMCS_FIELD_GUEST_RFLAGS,
    host_rip_field = const crate::nested::VMCS_FIELD_HOST_RIP,
    host_rsp_field = const crate::nested::VMCS_FIELD_HOST_RSP,
    exception_bitmap_field = const crate::nested::VMCS_FIELD_EXCEPTION_BITMAP,
    cr3_target_count_field = const crate::nested::VMCS_FIELD_CR3_TARGET_COUNT,
    guest_cr0_field = const crate::nested::VMCS_FIELD_GUEST_CR0,
    guest_cr3_field = const crate::nested::VMCS_FIELD_GUEST_CR3,
    guest_cr4_field = const crate::nested::VMCS_FIELD_GUEST_CR4,
    host_cr0_field = const crate::nested::VMCS_FIELD_HOST_CR0,
    host_cr3_field = const crate::nested::VMCS_FIELD_HOST_CR3,
    host_cr4_field = const crate::nested::VMCS_FIELD_HOST_CR4,
    guest_sysenter_cs_field = const crate::nested::VMCS_FIELD_GUEST_SYSENTER_CS,
    guest_sysenter_esp_field = const crate::nested::VMCS_FIELD_GUEST_SYSENTER_ESP,
    guest_sysenter_eip_field = const crate::nested::VMCS_FIELD_GUEST_SYSENTER_EIP,
    host_sysenter_cs_field = const crate::nested::VMCS_FIELD_HOST_SYSENTER_CS,
    host_sysenter_esp_field = const crate::nested::VMCS_FIELD_HOST_SYSENTER_ESP,
    host_sysenter_eip_field = const crate::nested::VMCS_FIELD_HOST_SYSENTER_EIP,
    pin_based_control_field = const crate::nested::VMCS_FIELD_PIN_BASED_VM_EXEC_CONTROL,
    primary_control_field = const crate::nested::VMCS_FIELD_CPU_BASED_VM_EXEC_CONTROL,
    secondary_control_field = const crate::nested::VMCS_FIELD_SECONDARY_VM_EXEC_CONTROL,
    vpid_field = const crate::nested::VMCS_FIELD_VPID,
    ept_pointer_field = const crate::nested::VMCS_FIELD_EPT_POINTER,
    vm_exit_controls_field = const crate::nested::VMCS_FIELD_VM_EXIT_CONTROLS,
    vm_entry_controls_field = const crate::nested::VMCS_FIELD_VM_ENTRY_CONTROLS,
    primary_activate_secondary_controls = const crate::nested::VMX_PRIMARY_ACTIVATE_SECONDARY_CONTROLS,
    secondary_enable_ept = const crate::nested::VMX_SECONDARY_ENABLE_EPT,
    secondary_enable_vpid = const crate::nested::VMX_SECONDARY_ENABLE_VPID,
    vm_exit_host_address_space_size = const crate::nested::VM_EXIT_HOST_ADDRESS_SPACE_SIZE,
    vm_entry_ia32e_mode_guest = const crate::nested::VM_ENTRY_IA32E_MODE_GUEST,
    ept_source_marker = const crate::smp::NESTED_EPT_SOURCE_MARKER,
    ept_target_marker = const crate::smp::NESTED_EPT_TARGET_MARKER,
    ept_second_target_marker = const crate::smp::NESTED_EPT_SECOND_TARGET_MARKER,
    exit_reason_field = const crate::nested::VMCS_FIELD_VM_EXIT_REASON,
    exit_instruction_len_field = const crate::nested::VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN,
    instruction_error_field = const crate::nested::VMCS_FIELD_VM_INSTRUCTION_ERROR,
    vmxon_active_error = const crate::nested::VMXON_IN_VMX_ROOT_ERROR,
    invalid_control_error = const crate::nested::VM_ENTRY_INVALID_CONTROL_FIELDS_ERROR,
    non_launched_error = const crate::nested::VMRESUME_NON_LAUNCHED_VMCS_ERROR,
    invalid_invalidation_operand_error = const crate::nested::INVALID_OPERAND_TO_INVEPT_INVVPID_ERROR,
    vmcs12_test_value = const crate::hv_core::residency::NESTED_VMCS12_TEST_VALUE,
    l2_vmcall_magic = const crate::hv_core::residency::NESTED_L2_VMCALL_MAGIC,
    l2_vmresume_magic = const crate::hv_core::residency::NESTED_L2_VMRESUME_MAGIC,
    l2_post_invept_magic = const crate::hv_core::residency::NESTED_L2_POST_INVEPT_MAGIC,
    sysenter_cs_msr = const crate::arch::IA32_SYSENTER_CS,
    sysenter_esp_msr = const crate::arch::IA32_SYSENTER_ESP,
    sysenter_eip_msr = const crate::arch::IA32_SYSENTER_EIP,
);
