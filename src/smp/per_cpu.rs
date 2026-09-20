use crate::hv_core::vt_ept::{EptError, IdentityEpt};
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
        })
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
