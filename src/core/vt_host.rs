use crate::arch::x86_64::{control_regs, msr, segmentation};

use super::vt_vmcs::{VmcsError, vmwrite};
use super::vt_vmcs_fields::*;

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

pub fn configure() -> Result<HostStateReport, VmcsError> {
    configure_with_cr3(control_regs::read_cr3())
}

pub fn configure_with_cr3(host_cr3: u64) -> Result<HostStateReport, VmcsError> {
    let mut segments = segmentation::capture();
    segments.tr = segmentation::vmx_usable_tr(segments.tr);

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

    vmwrite(HOST_CR0, control_regs::read_cr0())?;
    vmwrite(HOST_CR3, host_cr3)?;
    vmwrite(HOST_CR4, control_regs::read_cr4())?;
    vmwrite(HOST_FS_BASE, segments.fs.base)?;
    vmwrite(HOST_GS_BASE, segments.gs.base)?;
    vmwrite(HOST_TR_BASE, segments.tr.base)?;
    vmwrite(HOST_GDTR_BASE, segments.gdtr.base)?;
    vmwrite(HOST_IDTR_BASE, segments.idtr.base)?;
    vmwrite(
        HOST_SYSENTER_CS,
        unsafe { msr::read(msr::IA32_SYSENTER_CS) } & 0xffff_ffff,
    )?;
    vmwrite(HOST_SYSENTER_ESP, unsafe {
        msr::read(msr::IA32_SYSENTER_ESP)
    })?;
    vmwrite(HOST_SYSENTER_EIP, unsafe {
        msr::read(msr::IA32_SYSENTER_EIP)
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

fn host_selector(selector: u16) -> u16 {
    selector & !0x7
}
