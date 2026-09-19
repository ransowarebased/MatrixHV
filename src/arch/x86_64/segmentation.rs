use core::arch::asm;

use super::msr;

const SYNTHETIC_TR_SELECTOR: u16 = 0x40;
const SYNTHETIC_TR_LIMIT: u32 = 0x67;
const SYNTHETIC_TR_ACCESS_RIGHTS: u32 = 0x008b;

#[repr(C, align(16))]
struct SyntheticTss {
    bytes: [u8; 104],
}

static SYNTHETIC_TSS: SyntheticTss = SyntheticTss { bytes: [0; 104] };

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DescriptorTablePointer {
    pub limit: u16,
    pub base: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentState {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub access_rights: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentationState {
    pub es: SegmentState,
    pub cs: SegmentState,
    pub ss: SegmentState,
    pub ds: SegmentState,
    pub fs: SegmentState,
    pub gs: SegmentState,
    pub ldtr: SegmentState,
    pub tr: SegmentState,
    pub gdtr: DescriptorTablePointer,
    pub idtr: DescriptorTablePointer,
}

pub fn capture() -> SegmentationState {
    let gdtr = read_gdtr();
    let idtr = read_idtr();
    let mut state = SegmentationState {
        es: segment_from_gdt(read_es(), gdtr),
        cs: segment_from_gdt(read_cs(), gdtr),
        ss: segment_from_gdt(read_ss(), gdtr),
        ds: segment_from_gdt(read_ds(), gdtr),
        fs: segment_from_gdt(read_fs(), gdtr),
        gs: segment_from_gdt(read_gs(), gdtr),
        ldtr: segment_from_gdt(read_ldtr(), gdtr),
        tr: segment_from_gdt(read_tr(), gdtr),
        gdtr,
        idtr,
    };

    state.fs.base = unsafe { msr::read(msr::IA32_FS_BASE) };
    state.gs.base = unsafe { msr::read(msr::IA32_GS_BASE) };
    state
}

pub fn vmx_usable_tr(current: SegmentState) -> SegmentState {
    let access = current.access_rights;
    let valid_busy_tss = current.selector != 0
        && current.selector & 0x4 == 0
        && access & (1 << 16) == 0
        && access & 0xf == 0xb
        && access & 0x10 == 0
        && access & 0x80 != 0
        && current.base != 0;
    if valid_busy_tss {
        return current;
    }

    SegmentState {
        selector: SYNTHETIC_TR_SELECTOR,
        base: core::ptr::addr_of!(SYNTHETIC_TSS) as u64,
        limit: SYNTHETIC_TR_LIMIT,
        access_rights: SYNTHETIC_TR_ACCESS_RIGHTS,
    }
}

pub fn read_gdtr() -> DescriptorTablePointer {
    let mut pointer = DescriptorTablePointer::default();
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut pointer, options(nostack, preserves_flags));
    }
    pointer
}

pub fn read_idtr() -> DescriptorTablePointer {
    let mut pointer = DescriptorTablePointer::default();
    unsafe {
        asm!("sidt [{}]", in(reg) &mut pointer, options(nostack, preserves_flags));
    }
    pointer
}

fn segment_from_gdt(selector: u16, gdtr: DescriptorTablePointer) -> SegmentState {
    if selector & !0x7 == 0 {
        return SegmentState {
            selector,
            base: 0,
            limit: 0,
            access_rights: 1 << 16,
        };
    }

    let table_offset = usize::from(selector & !0x7);
    if table_offset + 7 > usize::from(gdtr.limit) {
        return SegmentState {
            selector,
            base: 0,
            limit: 0,
            access_rights: 1 << 16,
        };
    }

    let descriptor_address = gdtr.base.wrapping_add(table_offset as u64) as *const u64;
    let descriptor = unsafe { descriptor_address.read_unaligned() };
    let access = ((descriptor >> 40) & 0xff) as u32;
    let flags = ((descriptor >> 52) & 0xf) as u32;
    let mut limit = ((descriptor & 0xffff) | (((descriptor >> 48) & 0xf) << 16)) as u32;
    if flags & 0x8 != 0 {
        limit = (limit << 12) | 0xfff;
    }

    let mut base = ((descriptor >> 16) & 0xffff)
        | (((descriptor >> 32) & 0xff) << 16)
        | (((descriptor >> 56) & 0xff) << 24);
    if access & 0x10 == 0 {
        let high = unsafe { descriptor_address.add(1).read_unaligned() } & 0xffff_ffff;
        base |= high << 32;
    }

    SegmentState {
        selector,
        base,
        limit,
        access_rights: access | (flags << 12),
    }
}

macro_rules! selector_reader {
    ($name:ident, $segment:literal) => {
        fn $name() -> u16 {
            let selector: u16;
            unsafe {
                asm!(concat!("mov {0:x}, ", $segment), out(reg) selector, options(nomem, nostack, preserves_flags));
            }
            selector
        }
    };
}

selector_reader!(read_es, "es");
selector_reader!(read_cs, "cs");
selector_reader!(read_ss, "ss");
selector_reader!(read_ds, "ds");
selector_reader!(read_fs, "fs");
selector_reader!(read_gs, "gs");

fn read_ldtr() -> u16 {
    let selector: u16;
    unsafe {
        asm!("sldt {0:x}", out(reg) selector, options(nomem, nostack, preserves_flags));
    }
    selector
}

fn read_tr() -> u16 {
    let selector: u16;
    unsafe {
        asm!("str {0:x}", out(reg) selector, options(nomem, nostack, preserves_flags));
    }
    selector
}
