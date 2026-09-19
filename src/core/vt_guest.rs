use crate::arch::x86_64::{control_regs, msr, registers, segmentation};

use super::vt_vmcs::{VmcsError, vmwrite};
use super::vt_vmcs_fields::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestStateReport {
    pub cr3: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cs_selector: u16,
    pub ss_selector: u16,
    pub tr_selector: u16,
}

pub fn configure(guest_rip: u64, guest_rsp: u64) -> Result<GuestStateReport, VmcsError> {
    configure_with_rflags(guest_rip, guest_rsp, 0x2)
}

pub fn configure_with_rflags(
    guest_rip: u64,
    guest_rsp: u64,
    guest_rflags: u64,
) -> Result<GuestStateReport, VmcsError> {
    let mut segments = segmentation::capture();
    segments.tr = segmentation::vmx_usable_tr(segments.tr);
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

    let guest_cr3 = control_regs::read_cr3();
    vmwrite(GUEST_CR0, control_regs::read_cr0())?;
    vmwrite(GUEST_CR3, guest_cr3)?;
    vmwrite(GUEST_CR4, control_regs::read_cr4())?;
    vmwrite(GUEST_DR7, registers::read_dr7())?;
    vmwrite(GUEST_RSP, guest_rsp)?;
    vmwrite(GUEST_RIP, guest_rip)?;
    vmwrite(GUEST_RFLAGS, guest_rflags)?;
    vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0)?;
    vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0)?;
    vmwrite(GUEST_ACTIVITY_STATE, 0)?;
    vmwrite(VMCS_LINK_POINTER, u64::MAX)?;
    vmwrite(GUEST_IA32_DEBUGCTL, unsafe {
        msr::read(msr::IA32_DEBUGCTL)
    })?;
    vmwrite(GUEST_IA32_PAT, unsafe { msr::read(msr::IA32_PAT) })?;
    vmwrite(GUEST_IA32_EFER, unsafe { msr::read(msr::IA32_EFER) })?;
    vmwrite(
        GUEST_SYSENTER_CS,
        unsafe { msr::read(msr::IA32_SYSENTER_CS) } & 0xffff_ffff,
    )?;
    vmwrite(GUEST_SYSENTER_ESP, unsafe {
        msr::read(msr::IA32_SYSENTER_ESP)
    })?;
    vmwrite(GUEST_SYSENTER_EIP, unsafe {
        msr::read(msr::IA32_SYSENTER_EIP)
    })?;

    Ok(GuestStateReport {
        cr3: guest_cr3,
        rip: guest_rip,
        rsp: guest_rsp,
        rflags: guest_rflags,
        cs_selector: segments.cs.selector,
        ss_selector: segments.ss.selector,
        tr_selector: segments.tr.selector,
    })
}

fn write_segment(
    selector_field: u64,
    base_field: u64,
    limit_field: u64,
    access_rights_field: u64,
    segment: segmentation::SegmentState,
) -> Result<(), VmcsError> {
    vmwrite(selector_field, u64::from(segment.selector))?;
    vmwrite(base_field, segment.base)?;
    vmwrite(limit_field, u64::from(segment.limit))?;
    vmwrite(access_rights_field, u64::from(segment.access_rights))?;
    Ok(())
}
