use core::arch::asm;

use uefi::Status;

use crate::arch::x86_64::{control_regs, msr};
use crate::memory::resident::{AddressConstraint, ResidentPages};

const PAGE_SIZE: usize = 4096;
const IA32_VMX_BASIC_REVISION_MASK: u32 = 0x7fff_ffff;
const IA32_VMX_BASIC_REGION_SIZE_SHIFT: u64 = 32;
const IA32_VMX_BASIC_REGION_SIZE_MASK: u64 = 0x1fff;
const IA32_VMX_BASIC_PHYS_ADDR_WIDTH_BIT: u64 = 1 << 48;
const IA32_VMX_BASIC_MEMORY_TYPE_SHIFT: u64 = 50;
const IA32_VMX_BASIC_MEMORY_TYPE_MASK: u64 = 0xf;
const VMX_MEMORY_TYPE_WRITE_BACK: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxInstructionResult {
    Succeeded,
    VmFailInvalid,
    VmFailValid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxonError {
    InvalidRegionSize(u16),
    UnsupportedMemoryType(u8),
    InvalidControlRegisters,
    Allocation(Status),
    Instruction(VmxInstructionResult),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxonReport {
    pub revision_id: u32,
    pub region_size: u16,
    pub region_physical_address: u64,
    pub original_cr0: u64,
    pub original_cr4: u64,
    pub vmx_cr0: u64,
    pub vmx_cr4: u64,
}

pub struct VmxRootSession {
    report: VmxonReport,
    active: bool,
    interrupt_guard: InterruptGuard,
    vmxon_region: VmxonRegion,
}

pub(crate) struct BorrowedVmxRootSession<'a> {
    report: VmxonReport,
    active: bool,
    interrupt_guard: InterruptGuard,
    vmxon_region: &'a mut VmxonRegion,
}

impl VmxRootSession {
    pub fn report(&self) -> VmxonReport {
        self.report
    }
}

impl Drop for VmxRootSession {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                vmxoff();
            }
            self.active = false;
        }

        unsafe {
            control_regs::write_cr4(self.report.original_cr4);
            control_regs::write_cr0(self.report.original_cr0);
        }

        let _ = &self.interrupt_guard;
        let _ = &self.vmxon_region;
    }
}

impl BorrowedVmxRootSession<'_> {
    pub(crate) fn report(&self) -> VmxonReport {
        self.report
    }
}

impl Drop for BorrowedVmxRootSession<'_> {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                vmxoff();
            }
            self.active = false;
        }

        unsafe {
            control_regs::write_cr4(self.report.original_cr4);
            control_regs::write_cr0(self.report.original_cr0);
        }

        let _ = &self.interrupt_guard;
        let _ = &self.vmxon_region;
    }
}

pub(crate) struct VmxonRegion {
    pages: ResidentPages,
}

impl VmxonRegion {
    pub(crate) fn allocate(vmx_basic: u64) -> Result<Self, VmxonError> {
        let constraint = if vmx_basic & IA32_VMX_BASIC_PHYS_ADDR_WIDTH_BIT != 0 {
            AddressConstraint::Max(u32::MAX as u64)
        } else {
            AddressConstraint::Any
        };

        let pages = ResidentPages::allocate(1, constraint).map_err(VmxonError::Allocation)?;
        Ok(Self { pages })
    }

    pub(crate) fn physical_address(&self) -> u64 {
        self.pages.physical_address()
    }

    fn write_revision_id(&mut self, revision_id: u32) {
        unsafe {
            self.pages
                .pointer()
                .as_ptr()
                .cast::<u32>()
                .write(revision_id);
        }
    }
}

pub fn probe_vmxon() -> Result<VmxonReport, VmxonError> {
    let session = enter_vmx_root()?;
    let report = session.report();
    drop(session);
    Ok(report)
}

pub fn enter_vmx_root() -> Result<VmxRootSession, VmxonError> {
    let vmx_basic = unsafe { msr::read(msr::IA32_VMX_BASIC) };
    let state = VmxRootState::capture(vmx_basic)?;
    let vmxon_region = VmxonRegion::allocate(vmx_basic)?;
    enter_vmx_root_with_state(vmxon_region, state)
}

pub(crate) fn enter_vmx_root_with_borrowed_region(
    vmx_basic: u64,
    vmxon_region: &mut VmxonRegion,
) -> Result<BorrowedVmxRootSession<'_>, VmxonError> {
    let state = VmxRootState::capture(vmx_basic)?;
    vmxon_region.write_revision_id(state.revision_id);
    let region_physical_address = vmxon_region.physical_address();
    let (report, interrupt_guard) = activate_vmx_root(region_physical_address, state)?;

    Ok(BorrowedVmxRootSession {
        report,
        active: true,
        interrupt_guard,
        vmxon_region,
    })
}

struct VmxRootState {
    revision_id: u32,
    region_size: u16,
    original_cr0: u64,
    original_cr4: u64,
    vmx_cr0: u64,
    vmx_cr4: u64,
}

impl VmxRootState {
    fn capture(vmx_basic: u64) -> Result<Self, VmxonError> {
        let revision_id = revision_id(vmx_basic);
        let region_size = region_size(vmx_basic);
        let memory_type = memory_type(vmx_basic);

        if region_size == 0 || usize::from(region_size) > PAGE_SIZE {
            return Err(VmxonError::InvalidRegionSize(region_size));
        }
        if memory_type != VMX_MEMORY_TYPE_WRITE_BACK {
            return Err(VmxonError::UnsupportedMemoryType(memory_type));
        }

        let original_cr0 = control_regs::read_cr0();
        let original_cr4 = control_regs::read_cr4();
        let fixed_cr0_0 = unsafe { msr::read(msr::IA32_VMX_CR0_FIXED0) };
        let fixed_cr0_1 = unsafe { msr::read(msr::IA32_VMX_CR0_FIXED1) };
        let fixed_cr4_0 = unsafe { msr::read(msr::IA32_VMX_CR4_FIXED0) };
        let fixed_cr4_1 = unsafe { msr::read(msr::IA32_VMX_CR4_FIXED1) };

        let vmx_cr0 = (original_cr0 | fixed_cr0_0) & fixed_cr0_1;
        let vmx_cr4 = (original_cr4 | control_regs::CR4_VMXE | fixed_cr4_0) & fixed_cr4_1;
        if vmx_cr4 & control_regs::CR4_VMXE == 0 {
            return Err(VmxonError::InvalidControlRegisters);
        }

        Ok(Self {
            revision_id,
            region_size,
            original_cr0,
            original_cr4,
            vmx_cr0,
            vmx_cr4,
        })
    }
}

fn enter_vmx_root_with_state(
    mut vmxon_region: VmxonRegion,
    state: VmxRootState,
) -> Result<VmxRootSession, VmxonError> {
    vmxon_region.write_revision_id(state.revision_id);
    let region_physical_address = vmxon_region.physical_address();
    let (report, interrupt_guard) = activate_vmx_root(region_physical_address, state)?;

    Ok(VmxRootSession {
        report,
        active: true,
        interrupt_guard,
        vmxon_region,
    })
}

fn activate_vmx_root(
    region_physical_address: u64,
    state: VmxRootState,
) -> Result<(VmxonReport, InterruptGuard), VmxonError> {
    let interrupt_guard = InterruptGuard::disable();

    unsafe {
        control_regs::write_cr0(state.vmx_cr0);
        control_regs::write_cr4(state.vmx_cr4);
    }

    let instruction_result = unsafe { vmxon(region_physical_address) };
    if instruction_result != VmxInstructionResult::Succeeded {
        unsafe {
            control_regs::write_cr4(state.original_cr4);
            control_regs::write_cr0(state.original_cr0);
        }
        drop(interrupt_guard);
        return Err(VmxonError::Instruction(instruction_result));
    }

    Ok((
        VmxonReport {
            revision_id: state.revision_id,
            region_size: state.region_size,
            region_physical_address,
            original_cr0: state.original_cr0,
            original_cr4: state.original_cr4,
            vmx_cr0: state.vmx_cr0,
            vmx_cr4: state.vmx_cr4,
        },
        interrupt_guard,
    ))
}

pub fn vmx_basic() -> u64 {
    unsafe { msr::read(msr::IA32_VMX_BASIC) }
}

pub fn revision_id(vmx_basic: u64) -> u32 {
    (vmx_basic as u32) & IA32_VMX_BASIC_REVISION_MASK
}

pub fn region_uses_32_bit_physical_addresses(vmx_basic: u64) -> bool {
    vmx_basic & IA32_VMX_BASIC_PHYS_ADDR_WIDTH_BIT != 0
}

pub(crate) fn decode_flags(carry: u8, zero: u8) -> VmxInstructionResult {
    if carry != 0 {
        VmxInstructionResult::VmFailInvalid
    } else if zero != 0 {
        VmxInstructionResult::VmFailValid
    } else {
        VmxInstructionResult::Succeeded
    }
}

fn region_size(vmx_basic: u64) -> u16 {
    ((vmx_basic >> IA32_VMX_BASIC_REGION_SIZE_SHIFT) & IA32_VMX_BASIC_REGION_SIZE_MASK) as u16
}

fn memory_type(vmx_basic: u64) -> u8 {
    ((vmx_basic >> IA32_VMX_BASIC_MEMORY_TYPE_SHIFT) & IA32_VMX_BASIC_MEMORY_TYPE_MASK) as u8
}

unsafe fn vmxon(physical_address: u64) -> VmxInstructionResult {
    let carry: u8;
    let zero: u8;
    unsafe {
        asm!(
            "vmxon [{address}]",
            "setc {carry}",
            "setz {zero}",
            address = in(reg) &physical_address,
            carry = lateout(reg_byte) carry,
            zero = lateout(reg_byte) zero,
            options(nostack)
        );
    }
    decode_flags(carry, zero)
}

unsafe fn vmxoff() {
    unsafe {
        asm!("vmxoff", options(nostack));
    }
}

struct InterruptGuard {
    interrupts_were_enabled: bool,
}

impl InterruptGuard {
    fn disable() -> Self {
        let rflags: u64;
        unsafe {
            asm!("pushfq", "pop {}", out(reg) rflags, options(nomem));
            asm!("cli", options(nomem, nostack));
        }
        Self {
            interrupts_were_enabled: rflags & (1 << 9) != 0,
        }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        if self.interrupts_were_enabled {
            unsafe {
                asm!("sti", options(nomem, nostack));
            }
        }
    }
}
