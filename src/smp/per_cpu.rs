use crate::hv_core::vt_ept::{EptError, IdentityEpt};
use crate::hv_core::vt_resident::{
    BOOT_GUEST_STACK_PAGES, HOST_STACK_PAGES, ResidentHostSelectors, ResidentHostTables,
    ResidentProbeError,
};
use crate::hv_core::vt_vmcs::VmcsRegion;
use crate::hv_core::vt_vmxon::{self, VmxonRegion};
use crate::memory::resident::{AddressConstraint, ResidentPages};
use crate::nested::nested_capabilities::NestedVmxCapabilities;

const NESTED_VMXON_OPERAND_OFFSET: u64 = 8;

pub(crate) struct ResidentCpuResources {
    pub(crate) vmxon_region: VmxonRegion,
    pub(crate) vmcs_region: VmcsRegion,
    pub(crate) host_tables: ResidentHostTables,
    pub(crate) context_pages: ResidentPages,
    pub(crate) guest_stack: ResidentPages,
    pub(crate) host_stack: ResidentPages,
    pub(crate) resident_msr_state: ResidentPages,
    pub(crate) nested_vmxon_page: ResidentPages,
}

impl ResidentCpuResources {
    pub(crate) fn allocate(vmx_basic: u64, fatal_handler: u64) -> Result<Self, ResidentProbeError> {
        let vmxon_region = VmxonRegion::allocate(vmx_basic).map_err(ResidentProbeError::Vmxon)?;
        let mut vmcs_region = VmcsRegion::allocate(vmx_basic)?;
        vmcs_region.write_revision_id(vt_vmxon::revision_id(vmx_basic));
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
        let capabilities = NestedVmxCapabilities::vmxon_vmxoff(vmx_basic);
        unsafe {
            let page = nested_vmxon_page.pointer().as_ptr();
            page.write_bytes(0, nested_vmxon_page.byte_len());
            page.cast::<u32>().write(capabilities.revision_id);
            page.add(NESTED_VMXON_OPERAND_OFFSET as usize)
                .cast::<u64>()
                .write(nested_vmxon_page.physical_address());
        }

        Ok(Self {
            vmxon_region,
            vmcs_region,
            host_tables,
            context_pages,
            guest_stack,
            host_stack,
            resident_msr_state,
            nested_vmxon_page,
        })
    }

    pub(crate) fn nested_vmxon_operand(&self) -> u64 {
        self.nested_vmxon_page.physical_address() + NESTED_VMXON_OPERAND_OFFSET
    }

    pub(crate) fn nested_vmxon_region(&self) -> u64 {
        self.nested_vmxon_page.physical_address()
    }

    pub(crate) fn deny_guest_access(&self, ept: &mut IdentityEpt) -> Result<(), EptError> {
        ept.deny_guest_access(self.vmxon_region.physical_address(), 1)?;
        ept.deny_guest_access(self.vmcs_region.physical_address(), 1)?;
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
