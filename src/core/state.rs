use super::vmcs::*;
use crate::arch;
use crate::memory::{AddressConstraint, PAGE_SIZE, ResidentPages};
use uefi::Status;

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
    vmwrite(HOST_IA32_PAT, arch::ArchitecturalMsr::Pat.read())?;
    vmwrite(HOST_IA32_EFER, arch::ArchitecturalMsr::Efer.read())?;
    vmwrite(
        HOST_SYSENTER_CS,
        arch::ArchitecturalMsr::SysenterCs.read() & 0xffff_ffff,
    )?;
    vmwrite(
        HOST_SYSENTER_ESP,
        arch::ArchitecturalMsr::SysenterEsp.read(),
    )?;
    vmwrite(
        HOST_SYSENTER_EIP,
        arch::ArchitecturalMsr::SysenterEip.read(),
    )?;

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
    vmwrite(GUEST_IA32_PAT, arch::ArchitecturalMsr::Pat.read())?;
    vmwrite(GUEST_IA32_EFER, arch::ArchitecturalMsr::Efer.read())?;
    vmwrite(
        GUEST_SYSENTER_CS,
        arch::ArchitecturalMsr::SysenterCs.read() & 0xffff_ffff,
    )?;
    vmwrite(
        GUEST_SYSENTER_ESP,
        arch::ArchitecturalMsr::SysenterEsp.read(),
    )?;
    vmwrite(
        GUEST_SYSENTER_EIP,
        arch::ArchitecturalMsr::SysenterEip.read(),
    )?;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostTablesError {
    Allocation(Status),
    InvalidCodeLayout,
}

const HOST_TABLE_PAGES: usize = 4;
const HOST_CODE_SELECTOR: u16 = 0x08;
const HOST_DATA_SELECTOR: u16 = 0x10;
const HOST_TSS_SELECTOR: u16 = 0x40;
const TSS_OFFSET: usize = 0x100;
const TSS_LIMIT: u32 = 0x67;
const IDT_ENTRY_COUNT: usize = 256;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    fn interrupt_gate(address: u64, code_selector: u16) -> Self {
        Self {
            offset_low: address as u16,
            selector: code_selector,
            ist: 0,
            attributes: 0x8e,
            offset_mid: (address >> 16) as u16,
            offset_high: (address >> 32) as u32,
            reserved: 0,
        }
    }
}

pub(crate) struct ResidentHostTables {
    pub(crate) pages: ResidentPages,
    pub(crate) gdt: u64,
    pub(crate) tss: u64,
    pub(crate) idt: u64,
    selectors: ResidentHostSelectors,
}

#[derive(Clone, Copy)]
pub(crate) struct ResidentHostSelectors {
    es: u16,
    cs: u16,
    ss: u16,
    ds: u16,
    fs: u16,
    gs: u16,
}

impl ResidentHostSelectors {
    pub(crate) fn inherited(segments: arch::SegmentationState) -> Result<Self, HostTablesError> {
        let selectors = Self {
            es: host_selector(segments.es.selector),
            cs: host_selector(segments.cs.selector),
            ss: host_selector(segments.ss.selector),
            ds: host_selector(segments.ds.selector),
            fs: host_selector(segments.fs.selector),
            gs: host_selector(segments.gs.selector),
        };
        if selectors.cs == 0 || !selectors.fit_before_tss() {
            return Err(HostTablesError::InvalidCodeLayout);
        }
        Ok(selectors)
    }

    pub(crate) fn fixed() -> Self {
        Self {
            es: HOST_DATA_SELECTOR,
            cs: HOST_CODE_SELECTOR,
            ss: HOST_DATA_SELECTOR,
            ds: HOST_DATA_SELECTOR,
            fs: HOST_DATA_SELECTOR,
            gs: HOST_DATA_SELECTOR,
        }
    }

    fn fit_before_tss(self) -> bool {
        [self.es, self.cs, self.ss, self.ds, self.fs, self.gs]
            .into_iter()
            .all(|selector| selector == 0 || usize::from(selector >> 3) < TSS_OFFSET / 8)
    }
}

impl ResidentHostTables {
    pub(crate) fn allocate(
        fatal_handler: u64,
        gp_handler: u64,
        exception_stubs: u64,
        selectors: ResidentHostSelectors,
    ) -> Result<Self, HostTablesError> {
        let pages = ResidentPages::allocate(HOST_TABLE_PAGES, AddressConstraint::Any)
            .map_err(HostTablesError::Allocation)?;
        let base = pages.physical_address();
        let gdt = base;
        let tss = base + TSS_OFFSET as u64;
        let idt = base + PAGE_SIZE as u64;

        unsafe {
            let gdt_pointer = gdt as *mut u64;
            gdt_pointer
                .add(usize::from(selectors.cs >> 3))
                .write(0x00af_9a00_0000_ffff);
            for selector in [
                selectors.es,
                selectors.ss,
                selectors.ds,
                selectors.fs,
                selectors.gs,
            ] {
                if selector != 0 && selector != selectors.cs {
                    gdt_pointer
                        .add(usize::from(selector >> 3))
                        .write(0x00cf_9200_0000_ffff);
                }
            }
            let (tss_low, tss_high) = tss_descriptor(tss);
            let tss_index = usize::from(HOST_TSS_SELECTOR >> 3);
            gdt_pointer.add(tss_index).write(tss_low);
            gdt_pointer.add(tss_index + 1).write(tss_high);

            (tss as *mut u8).write_bytes(0, (TSS_LIMIT + 1) as usize);
            ((tss + 36) as *mut u64).write_unaligned(base + 3 * PAGE_SIZE as u64);
            ((tss + 44) as *mut u64).write_unaligned(base + 4 * PAGE_SIZE as u64);
            ((tss + 102) as *mut u16).write_unaligned((TSS_LIMIT + 1) as u16);

            let idt_pointer = idt as *mut IdtEntry;
            for index in 0..IDT_ENTRY_COUNT {
                let mut entry = IdtEntry::interrupt_gate(
                    if index == 13 {
                        gp_handler
                    } else if index < 32 {
                        exception_stubs + (index * 16) as u64
                    } else {
                        fatal_handler
                    },
                    selectors.cs,
                );
                entry.ist = match index {
                    2 => 1,
                    8 => 2,
                    _ => 0,
                };
                idt_pointer.add(index).write(entry);
            }
        }

        Ok(Self {
            pages,
            gdt,
            tss,
            idt,
            selectors,
        })
    }
}

pub(crate) fn configure_resident_host(
    host_cr3: u64,
    tables: &ResidentHostTables,
    segments: arch::SegmentationState,
) -> Result<(), VmcsError> {
    vmwrite(HOST_ES_SELECTOR, u64::from(tables.selectors.es))?;
    vmwrite(HOST_CS_SELECTOR, u64::from(tables.selectors.cs))?;
    vmwrite(HOST_SS_SELECTOR, u64::from(tables.selectors.ss))?;
    vmwrite(HOST_DS_SELECTOR, u64::from(tables.selectors.ds))?;
    vmwrite(HOST_FS_SELECTOR, u64::from(tables.selectors.fs))?;
    vmwrite(HOST_GS_SELECTOR, u64::from(tables.selectors.gs))?;
    vmwrite(HOST_TR_SELECTOR, u64::from(HOST_TSS_SELECTOR))?;
    vmwrite(HOST_CR0, arch::read_cr0())?;
    vmwrite(HOST_CR3, host_cr3)?;
    vmwrite(HOST_CR4, arch::read_cr4())?;
    vmwrite(HOST_IA32_PAT, arch::ArchitecturalMsr::Pat.read())?;
    // Private host mappings use NX even when firmware leaves NXE disabled.
    vmwrite(HOST_IA32_EFER, arch::ArchitecturalMsr::Efer.read() | (1 << 11))?;
    vmwrite(HOST_FS_BASE, segments.fs.base)?;
    vmwrite(HOST_GS_BASE, tables.tss)?;
    vmwrite(HOST_TR_BASE, tables.tss)?;
    vmwrite(HOST_GDTR_BASE, tables.gdt)?;
    vmwrite(HOST_IDTR_BASE, tables.idt)?;
    vmwrite(
        HOST_SYSENTER_CS,
        arch::ArchitecturalMsr::SysenterCs.read() & 0xffff_ffff,
    )?;
    vmwrite(
        HOST_SYSENTER_ESP,
        arch::ArchitecturalMsr::SysenterEsp.read(),
    )?;
    vmwrite(
        HOST_SYSENTER_EIP,
        arch::ArchitecturalMsr::SysenterEip.read(),
    )?;
    Ok(())
}

fn tss_descriptor(base: u64) -> (u64, u64) {
    let limit = u64::from(TSS_LIMIT);
    let low = (limit & 0xffff)
        | ((base & 0xffff) << 16)
        | (((base >> 16) & 0xff) << 32)
        | (0x8b_u64 << 40)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

impl ResidentHostTables {
    pub(crate) unsafe fn bind_context(&self, host_rsp: u64, context: u64) {
        unsafe {
            ((self.tss + 112) as *mut u64).write(context);
            (host_rsp as *mut u64).write(context);
        }
    }
}
