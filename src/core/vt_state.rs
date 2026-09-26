use crate::arch;

use super::vmcs::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostStateReport {
    pub cr3: u64,
    pub cs_selector: u16,
    pub ss_selector: u16,
    pub tr_selector: u16,
    pub tr_base: u64,
    pub gdtr_base: u64,
    pub idtr_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestStateReport {
    pub cr3: u64,
    pub cr4: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cs_selector: u16,
    pub ss_selector: u16,
    pub tr_selector: u16,
}

pub fn configure_host() -> Result<HostStateReport, VmcsError> {
    configure_host_with_cr3(arch::read_cr3())
}

pub fn configure_host_with_cr3(host_cr3: u64) -> Result<HostStateReport, VmcsError> {
    let mut segments = arch::capture();
    segments.tr = arch::vmx_usable_tr(segments.tr);

    vmwrite(
        HOST_ES_SELECTOR,
        u64::from(host_selector(segments.es.selector)),
    )?;
    vmwrite(
        HOST_CS_SELECTOR,
        u64::from(host_selector(segments.cs.selector)),
    )?;
    vmwrite(
        HOST_SS_SELECTOR,
        u64::from(host_selector(segments.ss.selector)),
    )?;
    vmwrite(
        HOST_DS_SELECTOR,
        u64::from(host_selector(segments.ds.selector)),
    )?;
    vmwrite(
        HOST_FS_SELECTOR,
        u64::from(host_selector(segments.fs.selector)),
    )?;
    vmwrite(
        HOST_GS_SELECTOR,
        u64::from(host_selector(segments.gs.selector)),
    )?;
    vmwrite(
        HOST_TR_SELECTOR,
        u64::from(host_selector(segments.tr.selector)),
    )?;

    vmwrite(HOST_CR0, arch::read_cr0())?;
    vmwrite(HOST_CR3, host_cr3)?;
    vmwrite(HOST_CR4, arch::read_cr4())?;
    vmwrite(HOST_FS_BASE, segments.fs.base)?;
    vmwrite(HOST_GS_BASE, segments.gs.base)?;
    vmwrite(HOST_TR_BASE, segments.tr.base)?;
    vmwrite(HOST_GDTR_BASE, segments.gdtr.base)?;
    vmwrite(HOST_IDTR_BASE, segments.idtr.base)?;
    vmwrite(HOST_IA32_PAT, unsafe { arch::read_msr(arch::IA32_PAT) })?;
    vmwrite(HOST_IA32_EFER, unsafe { arch::read_msr(arch::IA32_EFER) })?;
    vmwrite(
        HOST_SYSENTER_CS,
        unsafe { arch::read_msr(arch::IA32_SYSENTER_CS) } & 0xffff_ffff,
    )?;
    vmwrite(HOST_SYSENTER_ESP, unsafe {
        arch::read_msr(arch::IA32_SYSENTER_ESP)
    })?;
    vmwrite(HOST_SYSENTER_EIP, unsafe {
        arch::read_msr(arch::IA32_SYSENTER_EIP)
    })?;

    Ok(HostStateReport {
        cr3: host_cr3,
        cs_selector: host_selector(segments.cs.selector),
        ss_selector: host_selector(segments.ss.selector),
        tr_selector: host_selector(segments.tr.selector),
        tr_base: segments.tr.base,
        gdtr_base: segments.gdtr.base,
        idtr_base: segments.idtr.base,
    })
}

pub fn configure_guest(guest_rip: u64, guest_rsp: u64) -> Result<GuestStateReport, VmcsError> {
    configure_guest_with_rflags(guest_rip, guest_rsp, 0x2)
}

pub fn configure_guest_with_rflags(
    guest_rip: u64,
    guest_rsp: u64,
    guest_rflags: u64,
) -> Result<GuestStateReport, VmcsError> {
    let mut segments = arch::capture();
    segments.tr = arch::vmx_usable_tr(segments.tr);
    let guest_rflags = guest_rflags | 0x2;

    write_segment(
        GUEST_ES_SELECTOR,
        GUEST_ES_BASE,
        GUEST_ES_LIMIT,
        GUEST_ES_AR_BYTES,
        segments.es,
    )?;
    write_segment(
        GUEST_CS_SELECTOR,
        GUEST_CS_BASE,
        GUEST_CS_LIMIT,
        GUEST_CS_AR_BYTES,
        segments.cs,
    )?;
    write_segment(
        GUEST_SS_SELECTOR,
        GUEST_SS_BASE,
        GUEST_SS_LIMIT,
        GUEST_SS_AR_BYTES,
        segments.ss,
    )?;
    write_segment(
        GUEST_DS_SELECTOR,
        GUEST_DS_BASE,
        GUEST_DS_LIMIT,
        GUEST_DS_AR_BYTES,
        segments.ds,
    )?;
    write_segment(
        GUEST_FS_SELECTOR,
        GUEST_FS_BASE,
        GUEST_FS_LIMIT,
        GUEST_FS_AR_BYTES,
        segments.fs,
    )?;
    write_segment(
        GUEST_GS_SELECTOR,
        GUEST_GS_BASE,
        GUEST_GS_LIMIT,
        GUEST_GS_AR_BYTES,
        segments.gs,
    )?;
    write_segment(
        GUEST_LDTR_SELECTOR,
        GUEST_LDTR_BASE,
        GUEST_LDTR_LIMIT,
        GUEST_LDTR_AR_BYTES,
        segments.ldtr,
    )?;
    write_segment(
        GUEST_TR_SELECTOR,
        GUEST_TR_BASE,
        GUEST_TR_LIMIT,
        GUEST_TR_AR_BYTES,
        segments.tr,
    )?;

    vmwrite(GUEST_GDTR_BASE, segments.gdtr.base)?;
    vmwrite(GUEST_GDTR_LIMIT, u64::from(segments.gdtr.limit))?;
    vmwrite(GUEST_IDTR_BASE, segments.idtr.base)?;
    vmwrite(GUEST_IDTR_LIMIT, u64::from(segments.idtr.limit))?;

    let guest_cr3 = arch::read_cr3();
    let guest_cr4 = arch::read_cr4();
    vmwrite(GUEST_CR0, arch::read_cr0())?;
    vmwrite(GUEST_CR3, guest_cr3)?;
    vmwrite(GUEST_CR4, guest_cr4)?;
    vmwrite(GUEST_DR7, arch::read_dr7())?;
    vmwrite(GUEST_RSP, guest_rsp)?;
    vmwrite(GUEST_RIP, guest_rip)?;
    vmwrite(GUEST_RFLAGS, guest_rflags)?;
    vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0)?;
    vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0)?;
    vmwrite(GUEST_ACTIVITY_STATE, 0)?;
    vmwrite(VMCS_LINK_POINTER, u64::MAX)?;
    vmwrite(GUEST_IA32_DEBUGCTL, unsafe {
        arch::read_msr(arch::IA32_DEBUGCTL)
    })?;
    vmwrite(GUEST_IA32_PAT, unsafe { arch::read_msr(arch::IA32_PAT) })?;
    vmwrite(GUEST_IA32_EFER, unsafe { arch::read_msr(arch::IA32_EFER) })?;
    vmwrite(
        GUEST_SYSENTER_CS,
        unsafe { arch::read_msr(arch::IA32_SYSENTER_CS) } & 0xffff_ffff,
    )?;
    vmwrite(GUEST_SYSENTER_ESP, unsafe {
        arch::read_msr(arch::IA32_SYSENTER_ESP)
    })?;
    vmwrite(GUEST_SYSENTER_EIP, unsafe {
        arch::read_msr(arch::IA32_SYSENTER_EIP)
    })?;

    Ok(GuestStateReport {
        cr3: guest_cr3,
        cr4: guest_cr4,
        rip: guest_rip,
        rsp: guest_rsp,
        rflags: guest_rflags,
        cs_selector: segments.cs.selector,
        ss_selector: segments.ss.selector,
        tr_selector: segments.tr.selector,
    })
}

fn host_selector(selector: u16) -> u16 {
    selector & !0x7
}

fn write_segment(
    selector_field: u64,
    base_field: u64,
    limit_field: u64,
    access_rights_field: u64,
    segment: arch::SegmentState,
) -> Result<(), VmcsError> {
    vmwrite(selector_field, u64::from(segment.selector))?;
    vmwrite(base_field, segment.base)?;
    vmwrite(limit_field, u64::from(segment.limit))?;
    vmwrite(access_rights_field, u64::from(segment.access_rights))?;
    Ok(())
}
