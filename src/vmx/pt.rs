use crate::memory::host::{AddressConstraint, ResidentPages};
use uefi::Status;

pub(crate) const BUFFER_BYTES: usize = crate::protocol::MATRIXHV_INTEL_PT_BUFFER_BYTES;
pub(crate) const TRACE_CONTROL: u64 = (1 << 0) | (1 << 2) | (1 << 8) | (1 << 13);

#[repr(C)]
#[derive(Default)]
pub(crate) struct TraceState {
    pub support: u64,
    pub armed: u64,
    pub owned: u64,
    pub table: u64,
    pub buffer: u64,
    pub bytes: u64,
    pub status: u64,
    pub output_pointer: u64,
    pub saved_control: u64,
    pub saved_status: u64,
    pub saved_base: u64,
    pub saved_pointer: u64,
    pub code_base: u64,
    pub code_bytes: u64,
    pub generation: u64,
}

pub(crate) fn supported(max_leaf: u32, leaf7_ebx: u32, pt_ecx: u32, vmx_misc: u64) -> bool {
    max_leaf >= 0x14 && leaf7_ebx & (1 << 25) != 0 && pt_ecx & 1 != 0 && vmx_misc & (1 << 14) != 0
}

pub(crate) struct TraceResources {
    pub pages: ResidentPages,
    table: u64,
    buffer: u64,
}

impl TraceResources {
    pub fn allocate() -> Result<Self, Status> {
        // One data region works on single-entry ToPA implementations too.
        // Over-allocation supplies the 64 KiB alignment required by size=4.
        let pages = ResidentPages::allocate(32, AddressConstraint::Any)?;
        let table = pages.physical_address();
        let buffer = (table + 4096 + BUFFER_BYTES as u64 - 1) & !(BUFFER_BYTES as u64 - 1);
        unsafe {
            (table as *mut u64).write(buffer | (4 << 6) | (1 << 4));
            (table as *mut u64).add(1).write(table | 1);
        }
        Ok(Self {
            pages,
            table,
            buffer,
        })
    }

    pub fn state(&self) -> TraceState {
        let max_leaf = crate::arch::leaf(0).eax;
        let available = supported(
            max_leaf,
            crate::arch::leaf_with_subleaf(7, 0).ebx,
            if max_leaf >= 0x14 {
                crate::arch::leaf_with_subleaf(0x14, 0).ecx
            } else {
                0
            },
            unsafe { crate::arch::read_msr(crate::vmx::nested::IA32_VMX_MISC_MSR) },
        );
        TraceState {
            support: if available { 1 } else { 2 },
            table: self.table,
            buffer: self.buffer,
            output_pointer: 0x7f,
            ..TraceState::default()
        }
    }
}
