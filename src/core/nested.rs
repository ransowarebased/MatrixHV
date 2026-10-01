use super::ept::EptError;
use super::msr::{RESIDENT_MSR_SWITCH_CAPACITY, VmxMsrEntry, configure_resident_msr_switch};
use super::state::{ResidentHostTables, configure_resident_host};
use super::vmcs::*;
use super::vmxon::VmxInstructionResult;
use super::{controls, state, vmcs};
use crate::memory::{PAGE_SIZE, ResidentPages};
use crate::nested::{
    HostVmxCapabilities, IA32_VMX_BASIC_MSR, IA32_VMX_CR0_FIXED0_MSR, IA32_VMX_CR0_FIXED1_MSR,
    IA32_VMX_CR4_FIXED0_MSR, IA32_VMX_CR4_FIXED1_MSR, IA32_VMX_ENTRY_CTLS_MSR,
    IA32_VMX_EPT_VPID_CAP_MSR, IA32_VMX_EXIT_CTLS_MSR, IA32_VMX_MISC_MSR,
    IA32_VMX_PINBASED_CTLS_MSR, IA32_VMX_PROCBASED_CTLS_MSR, IA32_VMX_PROCBASED_CTLS2_MSR,
    IA32_VMX_TRUE_ENTRY_CTLS_MSR, IA32_VMX_TRUE_EXIT_CTLS_MSR, IA32_VMX_TRUE_PINBASED_CTLS_MSR,
    IA32_VMX_TRUE_PROCBASED_CTLS_MSR, IA32_VMX_VMCS_ENUM_MSR, NestedEptConfiguration,
    NestedMsrComposition, NestedVmcs12CoreState, NestedVmcs12SegmentState, NestedVmcs12State,
    NestedVmxCapabilities, NestedVmxState, VMX_BASIC_TRUE_CONTROLS,
};
use crate::{arch, hyperv};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NestedHardwareError {
    Vmclear(VmxInstructionResult),
    Vmcs(VmcsError),
    Controls(controls::VmxControlsError),
    Ept(EptError),
}
impl From<VmcsError> for NestedHardwareError {
    fn from(value: VmcsError) -> Self {
        Self::Vmcs(value)
    }
}
impl From<controls::VmxControlsError> for NestedHardwareError {
    fn from(value: controls::VmxControlsError) -> Self {
        Self::Controls(value)
    }
}
const NESTED_MSR_BITMAP_OFFSET: u64 = 0;
const NESTED_VMCS02_ENTRY_MSR_LIST_OFFSET: u64 = PAGE_SIZE as u64;
const NESTED_VMCS02_EXIT_STORE_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 4) as u64;
const NESTED_VMCS01_ENTRY_MSR_LIST_OFFSET: u64 = (PAGE_SIZE * 7) as u64;
pub(crate) const NESTED_GUEST_MSR_LIST_CAPACITY: usize = crate::nested::VMX_MSR_LIST_CAPACITY;
pub(crate) const NESTED_MSR_BITMAP_QWORD_COUNT: usize = PAGE_SIZE / size_of::<u64>();

pub(crate) fn configure_nested_msr_composition(
    nested_state: &mut NestedVmxState,
    l0_msr_bitmap: u64,
    l0_msr_guest_list: u64,
    nested_msr_state: u64,
) {
    let l0_msr_host_list =
        l0_msr_guest_list + (RESIDENT_MSR_SWITCH_CAPACITY * size_of::<VmxMsrEntry>()) as u64;
    nested_state.configure_msr_composition(NestedMsrComposition {
        l0_msr_bitmap,
        composed_msr_bitmap: nested_msr_state + NESTED_MSR_BITMAP_OFFSET,
        l0_msr_guest_list,
        l0_msr_host_list,
        vmcs02_entry_msr_list: nested_msr_state + NESTED_VMCS02_ENTRY_MSR_LIST_OFFSET,
        vmcs02_exit_store_msr_list: nested_msr_state + NESTED_VMCS02_EXIT_STORE_MSR_LIST_OFFSET,
        vmcs01_entry_msr_list: nested_msr_state + NESTED_VMCS01_ENTRY_MSR_LIST_OFFSET,
    });
}

pub(crate) struct NestedVmcs02Configuration<'a> {
    pub(crate) vmcs01_region: u64,
    pub(crate) vmcs02_region: u64,
    pub(crate) msr_bitmap: u64,
    pub(crate) ept_pointer: u64,
    pub(crate) msr_state: &'a ResidentPages,
    pub(crate) host_cr3: u64,
    pub(crate) host_tables: &'a ResidentHostTables,
    pub(crate) segments: arch::SegmentationState,
    pub(crate) host_rsp: u64,
    pub(crate) host_rip: u64,
    pub(crate) guest_rip: u64,
    pub(crate) guest_rsp: u64,
    pub(crate) guest_rflags: u64,
    pub(crate) l1_cr4: u64,
}

pub(crate) fn configure_nested_vmcs02(
    configuration: NestedVmcs02Configuration<'_>,
) -> Result<(), NestedHardwareError> {
    let clear = unsafe { vmcs::vmclear(configuration.vmcs02_region) };
    if clear != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmclear(clear));
    }
    let load = unsafe { vmcs::vmptrld(configuration.vmcs02_region) };
    if load != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmcs(VmcsError::Vmptrld(load)));
    }

    let configure_result = (|| -> Result<(), NestedHardwareError> {
        let mut controls =
            controls::configure_resident_boot(configuration.msr_bitmap, configuration.ept_pointer)?;
        controls::enable_resident_vpid(&mut controls, 2)?;
        if unsafe { arch::read_msr(arch::IA32_VMX_PROCBASED_CTLS2) }
            & (u64::from(crate::nested::VMX_SECONDARY_ENABLE_VM_FUNCTIONS) << 32)
            != 0
        {
            // Trap VMFUNC so L1 EPTPs are composed through EPT01 before use by L2.
            vmwrite(VM_FUNCTION_CONTROL, 0)?;
        }
        vmwrite(EXCEPTION_BITMAP, 0)?;
        configure_resident_msr_switch(configuration.msr_state)?;
        configure_resident_host(
            configuration.host_cr3,
            configuration.host_tables,
            configuration.segments,
        )?;
        state::configure_guest_with_rflags(
            configuration.guest_rip,
            configuration.guest_rsp,
            configuration.guest_rflags,
        )?;
        controls::virtualize_resident_cr4_vmxe(configuration.l1_cr4)?;
        vmwrite(HOST_RSP, configuration.host_rsp)?;
        vmwrite(HOST_RIP, configuration.host_rip)?;
        Ok(())
    })();

    // VMPTRLD of VMCS01 leaves VMCS02 active; flush it before BSP executes VMXOFF.
    let clear = unsafe { vmcs::vmclear(configuration.vmcs02_region) };
    let restore = unsafe { vmcs::vmptrld(configuration.vmcs01_region) };
    if restore != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmcs(VmcsError::Vmptrld(restore)));
    }
    if clear != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmclear(clear));
    }
    configure_result
}

pub(crate) fn configure_resident_vmcs_shadowing(
    controls: &mut controls::VmxControls,
    shadow_resources: Option<(u64, u64, u64)>,
) -> Result<Option<(u64, u64)>, NestedHardwareError> {
    let Some((shadow_vmcs, vmread_bitmap, vmwrite_bitmap)) = shadow_resources else {
        return Ok(None);
    };
    if !crate::nested::native_vmcs_shadowing_available(unsafe {
        arch::read_msr(arch::IA32_VMX_PROCBASED_CTLS2)
    }) {
        return Ok(None);
    }
    let clear = unsafe { vmcs::vmclear(shadow_vmcs) };
    if clear != VmxInstructionResult::Succeeded {
        return Err(NestedHardwareError::Vmclear(clear));
    }
    if controls::enable_resident_vmcs_shadowing(
        controls,
        shadow_vmcs,
        vmread_bitmap,
        vmwrite_bitmap,
    )? {
        Ok(Some((shadow_vmcs, vmread_bitmap)))
    } else {
        Ok(None)
    }
}

pub(crate) fn capture_nested_vmcs12_core_state(
    mut segments: arch::SegmentationState,
    l1_cr4: u64,
) -> NestedVmcs12CoreState {
    segments.tr = arch::vmx_usable_tr(segments.tr);
    let segment_state = |segment: arch::SegmentState| NestedVmcs12SegmentState {
        selector: segment.selector,
        base: segment.base,
        limit: segment.limit,
        access_rights: segment.access_rights,
    };
    NestedVmcs12CoreState {
        guest_cr0: arch::read_cr0(),
        guest_cr3: arch::read_cr3(),
        guest_cr4: l1_cr4,
        host_cr0: arch::read_cr0(),
        host_cr3: arch::read_cr3(),
        host_cr4: arch::read_cr4(),
        es: segment_state(segments.es),
        cs: segment_state(segments.cs),
        ss: segment_state(segments.ss),
        ds: segment_state(segments.ds),
        fs: segment_state(segments.fs),
        gs: segment_state(segments.gs),
        ldtr: segment_state(segments.ldtr),
        tr: segment_state(segments.tr),
        gdtr_base: segments.gdtr.base,
        gdtr_limit: segments.gdtr.limit,
        idtr_base: segments.idtr.base,
        idtr_limit: segments.idtr.limit,
        sysenter_cs: arch::ArchitecturalMsr::SysenterCs.read(),
        sysenter_esp: arch::ArchitecturalMsr::SysenterEsp.read(),
        sysenter_eip: arch::ArchitecturalMsr::SysenterEip.read(),
    }
}

pub(crate) fn nested_vmx_capabilities(
    host_vmx_basic: u64,
    options: crate::config::MatrixConfig,
) -> NestedVmxCapabilities {
    let has_true_controls = host_vmx_basic & VMX_BASIC_TRUE_CONTROLS != 0;
    let host = unsafe {
        HostVmxCapabilities {
            vmx_basic: host_vmx_basic,
            pinbased_ctls: arch::read_msr(IA32_VMX_PINBASED_CTLS_MSR),
            procbased_ctls: arch::read_msr(IA32_VMX_PROCBASED_CTLS_MSR),
            exit_ctls: arch::read_msr(IA32_VMX_EXIT_CTLS_MSR),
            entry_ctls: arch::read_msr(IA32_VMX_ENTRY_CTLS_MSR),
            misc: arch::read_msr(IA32_VMX_MISC_MSR),
            cr0_fixed0: arch::read_msr(IA32_VMX_CR0_FIXED0_MSR),
            cr0_fixed1: arch::read_msr(IA32_VMX_CR0_FIXED1_MSR),
            cr4_fixed0: arch::read_msr(IA32_VMX_CR4_FIXED0_MSR),
            cr4_fixed1: arch::read_msr(IA32_VMX_CR4_FIXED1_MSR),
            vmcs_enum: arch::read_msr(IA32_VMX_VMCS_ENUM_MSR),
            procbased_ctls2: arch::read_msr(IA32_VMX_PROCBASED_CTLS2_MSR),
            ept_vpid_cap: arch::read_msr(IA32_VMX_EPT_VPID_CAP_MSR),
            true_pinbased_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR)
            } else {
                0
            },
            true_procbased_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR)
            } else {
                0
            },
            true_exit_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR)
            } else {
                0
            },
            true_entry_ctls: if has_true_controls {
                arch::read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR)
            } else {
                0
            },
        }
    };
    let mut capabilities = NestedVmxCapabilities::from_host(host);
    crate::runtime::info(format_args!(
        "nested VMX host basic={:#x} misc={:#x} proc2={:#x} ept_vpid={:#x} guest misc={:#x} proc2={:#x} ept_vpid={:#x}",
        host.vmx_basic,
        host.misc,
        host.procbased_ctls2,
        host.ept_vpid_cap,
        capabilities.vmx_misc,
        capabilities.vmx_procbased_ctls2,
        capabilities.vmx_ept_vpid_cap,
    ));
    capabilities.expose_vmx = options.vt_nested;
    capabilities.vmx_procbased_ctls2 =
        hyperv::restrict_evmcs_controls(capabilities.vmx_procbased_ctls2, options.vt_evmcs);
    debug_assert_eq!(
        capabilities.vmx_msr(IA32_VMX_BASIC_MSR),
        Some(capabilities.vmx_basic)
    );
    capabilities
}

const _: () = assert!(
    (NESTED_GUEST_MSR_LIST_CAPACITY + RESIDENT_MSR_SWITCH_CAPACITY) * size_of::<VmxMsrEntry>()
        <= PAGE_SIZE * 3
);

impl From<EptError> for NestedHardwareError {
    fn from(value: EptError) -> Self {
        Self::Ept(value)
    }
}
pub(crate) struct CpuStateConfiguration {
    pub(crate) vmxon_operand: u64,
    pub(crate) vmxon_region: u64,
    pub(crate) vmcs12_operand: u64,
    pub(crate) vmcs12_region: u64,
    pub(crate) vmptrst_destination: u64,
    pub(crate) vmcs01_region: u64,
    pub(crate) vmcs02_region: u64,
    pub(crate) msr_guest_list: u64,
    pub(crate) msr_state: u64,
    pub(crate) ept12_pointer: u64,
    pub(crate) ept02_pointer: u64,
    pub(crate) ept02_alternate_pointer: u64,
    pub(crate) ept02_table_pools: [(u64, usize, usize); 2],
    pub(crate) source_gpa: u64,
    pub(crate) target_gpa: u64,
    pub(crate) second_target_gpa: u64,
    pub(crate) source_leaf: u64,
    pub(crate) source_leaf_attributes: u64,
    pub(crate) composition: super::ept::EptComposition,
    pub(crate) alternate: super::ept::EptComposition,
    pub(crate) eptp_list: u64,
    pub(crate) eptp_tables: u64,
    pub(crate) eptp_pages: u64,
    pub(crate) backing: *mut u8,
    pub(crate) backing_len: usize,
}

pub(crate) fn prepare_cpu_state(
    configuration: CpuStateConfiguration,
    options: crate::config::MatrixConfig,
    vmx_basic: u64,
    l1_cr4: u64,
    segments: arch::SegmentationState,
    vmcs_shadow: Option<(u64, u64)>,
    msr_bitmap: u64,
) -> Result<NestedVmxState, NestedHardwareError> {
    let nested_capabilities = nested_vmx_capabilities(vmx_basic, options);
    let mut nested_state = NestedVmxState::new(
        nested_capabilities,
        configuration.vmxon_operand,
        configuration.vmxon_region,
        NestedVmcs12State::new(
            nested_capabilities.revision_id,
            configuration.vmcs12_operand,
            configuration.vmcs12_region,
            configuration.vmptrst_destination,
        ),
        configuration.vmcs01_region,
        configuration.vmcs02_region,
    );
    nested_state.l1_cr4 = l1_cr4;
    if let Some((shadow_vmcs, vmread_bitmap)) = vmcs_shadow {
        nested_state.shadow_vmcs_region = shadow_vmcs;
        nested_state.shadow_vmread_bitmap = vmread_bitmap;
    }
    nested_state.evmcs_enabled = u64::from(options.vt_evmcs);
    configure_nested_msr_composition(
        &mut nested_state,
        msr_bitmap,
        configuration.msr_guest_list,
        configuration.msr_state,
    );
    nested_state.configure_ept(NestedEptConfiguration {
        ept12_pointer: configuration.ept12_pointer,
        ept02_pointer: configuration.ept02_pointer,
        source_gpa: configuration.source_gpa,
        target_gpa: configuration.target_gpa,
        composed_hpa: configuration.composition.host_physical_address,
        permissions: configuration.composition.permissions,
        alternate_ept02_pointer: configuration.ept02_alternate_pointer,
        second_target_gpa: configuration.second_target_gpa,
        source_leaf: configuration.source_leaf,
        source_leaf_attributes: configuration.source_leaf_attributes,
        alternate_composed_hpa: configuration.alternate.host_physical_address,
        alternate_permissions: configuration.alternate.permissions,
    });
    nested_state.configure_ept02_table_pools(configuration.ept02_table_pools);
    nested_state.eptp_shadow_list = configuration.eptp_list;
    nested_state.eptp_table_pool = configuration.eptp_tables;
    nested_state.eptp_table_pages = configuration.eptp_pages;
    nested_state.eptp_native_supported = u64::from(controls::native_eptp_switching_supported());
    nested_state.eptp_sync_apic_id = u64::from(arch::apic_id());
    nested_state
        .vmcs12
        .seed_core_state(capture_nested_vmcs12_core_state(segments, l1_cr4));
    unsafe {
        nested_state
            .vmcs12
            .seed_backing(core::slice::from_raw_parts_mut(
                configuration.backing,
                configuration.backing_len,
            ));
    }

    Ok(nested_state)
}
