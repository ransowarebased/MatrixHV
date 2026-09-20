extern crate alloc;

use alloc::vec::Vec;

use crate::hv_core::vt_ept::{EptComposition, EptError, IdentityEpt};
use crate::hv_core::vt_resident::{
    BOOT_GUEST_STACK_PAGES, HOST_STACK_PAGES, ResidentHostSelectors, ResidentHostTables,
    ResidentProbeError,
};
use crate::hv_core::vt_vmcs::VmcsRegion;
use crate::hv_core::vt_vmxon::{self, VmxonRegion};
use crate::memory::resident::{AddressConstraint, PAGE_SIZE, ResidentPages};
use crate::nested::capabilities::NestedVmxCapabilities;

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

pub(crate) struct ResidentCpuResources {
    pub(crate) vmxon_region: VmxonRegion,
    pub(crate) vmcs_region: VmcsRegion,
    pub(crate) nested_vmcs02_region: VmcsRegion,
    pub(crate) host_tables: ResidentHostTables,
    pub(crate) context_pages: ResidentPages,
    pub(crate) guest_stack: ResidentPages,
    pub(crate) host_stack: ResidentPages,
    pub(crate) resident_msr_state: ResidentPages,
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
    pub(crate) fn allocate(vmx_basic: u64, fatal_handler: u64) -> Result<Self, ResidentProbeError> {
        let vmxon_region = VmxonRegion::allocate(vmx_basic).map_err(ResidentProbeError::Vmxon)?;
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(vt_vmxon::revision_id(vmx_basic));
        let mut nested_vmcs02_region = VmcsRegion::allocate(vmx_basic)?;
        nested_vmcs02_region.write_revision_id(vt_vmxon::revision_id(vmx_basic));
        let host_tables =
            ResidentHostTables::allocate(fatal_handler, ResidentHostSelectors::fixed())?;
        let context_pages = ResidentPages::allocate(1, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let guest_stack = ResidentPages::allocate(BOOT_GUEST_STACK_PAGES, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let host_stack = ResidentPages::allocate(HOST_STACK_PAGES, AddressConstraint::Any)
            .map_err(ResidentProbeError::Allocation)?;
        let resident_msr_state = ResidentPages::allocate(1, AddressConstraint::Any)
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
            host_tables,
            context_pages,
            guest_stack,
            host_stack,
            resident_msr_state,
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
    ) -> Result<EptComposition, EptError> {
        let source_gpa = self.nested_ept_source_page.physical_address();
        let target_gpa = self.nested_ept_target_page.physical_address();
        let second_target_gpa = self.nested_ept_second_target_page.physical_address();
        let mut ept12 = IdentityEpt::build()?;
        ept12.remap_page(source_gpa, target_gpa)?;
        let source_leaf = ept12.leaf_entry_physical_address(source_gpa)?;
        let source_leaf_attributes = ept12.leaf_entry_value(source_gpa)? & 0xfff;
        let mut ept02 = ept01.clone_shadow()?;
        let composition = ept02.compose_page(&ept12, ept01, source_gpa)?;
        ept12.remap_page(source_gpa, second_target_gpa)?;
        let mut ept02_alternate = ept01.clone_shadow()?;
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

    pub(crate) fn deny_nested_ept02_regions(
        &mut self,
        regions: &[(u64, usize)],
    ) -> Result<(), EptError> {
        self.nested_ept02
            .as_mut()
            .ok_or(EptError::InvalidPageTable)?
            .deny_guest_access_to_regions(regions)?;
        self.nested_ept02_alternate
            .as_mut()
            .ok_or(EptError::InvalidPageTable)?
            .deny_guest_access_to_regions(regions)
    }

    pub(crate) fn deny_guest_access(&self, ept: &mut IdentityEpt) -> Result<(), EptError> {
        ept.deny_guest_access(self.vmxon_region.physical_address(), 1)?;
        ept.deny_guest_access(self.vmcs_region.physical_address(), 1)?;
        ept.deny_guest_access(self.nested_vmcs02_region.physical_address(), 1)?;
        ept.deny_guest_access(
            self.host_tables.pages.physical_address(),
            self.host_tables.pages.pages(),
        )?;
        ept.deny_guest_access(
            self.context_pages.physical_address(),
            self.context_pages.pages(),
        )?;
        ept.deny_guest_access(self.host_stack.physical_address(), self.host_stack.pages())?;
        ept.deny_guest_access(
            self.resident_msr_state.physical_address(),
            self.resident_msr_state.pages(),
        )?;
        Ok(())
    }
}
