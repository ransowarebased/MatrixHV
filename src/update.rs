use core::sync::atomic::AtomicU64;
use matrixhv_sdk::update::{Abi, BANK_PAGES, CHUNK_BYTES, REQUEST_BYTES, Transaction};

#[repr(C, align(16))]
pub struct RuntimeContext {
    pub lock: AtomicU64,
    pub abi: Abi,
    pub public_key: [u8; 32],
    pub staging: u64,
    pub banks: [u64; 2],
    pub bank_ptes: [[u64; BANK_PAGES]; 2],
    pub bank_idts: [[u64; 64]; 2],
    pub event_physical: u64,
    pub event_runtime: u64,
    pub status_offset: usize,
    pub masks_offsets: [usize; 5],
    pub cpu_states_offset: usize,
    pub host_rip_offset: usize,
    pub bindings: [u64; 6],
    pub transaction: Transaction,
    pub scratch: [[u8; REQUEST_BYTES + CHUNK_BYTES]; 64],
}

#[cfg(target_os = "uefi")]
pub(crate) mod runtime {
    use super::RuntimeContext;
    use core::sync::atomic::Ordering;
    use matrixhv_sdk::update::{
        BANK_BYTES, BANK_PAGES, BEGIN_OFF, CANCEL, CHECK_CPU, COMMIT, CpuMasks, Error, FINISH,
        MAX_PACKAGE_BYTES, PREPARE, PROBE_CPU, Package, Phase, QUERY, RECOVER, RECOVERED, Request,
        Status, UPLOAD, VALIDATE,
    };

    unsafe fn masks(context: &RuntimeContext, native: bool) -> CpuMasks {
        let base = if native {
            context.event_runtime
        } else {
            context.event_physical
        };
        let read = |index: usize| unsafe {
            ((base as usize + context.masks_offsets[index]) as *const u64).read_volatile()
        };
        CpuMasks {
            expected: read(0),
            active: read(1),
            stopped: read(2),
            failed: read(3),
            rearm: read(4),
        }
    }

    unsafe fn publish(context: &RuntimeContext, native: bool) {
        let base = if native {
            context.event_runtime
        } else {
            context.event_physical
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &context.transaction.status,
                (base as usize + context.status_offset) as *mut Status,
                1,
            );
        }
    }

    unsafe fn host_rip_pointer(context: &RuntimeContext, native: bool, cpu: usize) -> *mut u64 {
        let base = if native {
            context.event_runtime
        } else {
            context.event_physical
        };
        (base as usize
            + context.cpu_states_offset
            + cpu * context.abi.cpu_bytes as usize
            + context.host_rip_offset) as *mut u64
    }

    unsafe fn writable_bank(context: &RuntimeContext, bank: usize, flags: impl Fn(usize) -> u64) {
        for page in 0..BANK_PAGES {
            let pointer = context.bank_ptes[bank][page] as *mut u64;
            unsafe {
                let entry = pointer.read_volatile();
                pointer.write_volatile((entry & 0x000f_ffff_ffff_f000) | flags(page));
                core::arch::asm!("invlpg [{}]", in(reg) context.banks[bank] + (page * 4096) as u64, options(nostack, preserves_flags));
            }
        }
    }

    unsafe fn handle(
        context: &mut RuntimeContext,
        request: &Request<'_>,
        cpu: usize,
        native: bool,
        identity: *const [u8; 32],
        blocker: u32,
    ) -> Result<(), Error> {
        let masks = unsafe { masks(context, native) };
        if native && !matches!(request.operation, COMMIT | RECOVER | QUERY) {
            return Err(Error::State);
        }
        if request.operation != UPLOAD && !request.payload.is_empty() {
            return Err(Error::Format);
        }
        match request.operation {
            PREPARE => context
                .transaction
                .prepare(request.transaction, request.total_bytes, masks),
            UPLOAD => {
                context
                    .transaction
                    .require(request.transaction, Phase::Uploading)?;
                let staging = unsafe {
                    core::slice::from_raw_parts_mut(context.staging as *mut u8, MAX_PACKAGE_BYTES)
                };
                context.transaction.upload.write(
                    request.transaction,
                    request.offset,
                    request.payload,
                    staging,
                )?;
                context.transaction.status.received_bytes =
                    context.transaction.upload.received_bytes as u32;
                Ok(())
            }
            VALIDATE => {
                context
                    .transaction
                    .require(request.transaction, Phase::Uploading)?;
                if !context.transaction.upload.complete() {
                    return Err(Error::Incomplete);
                }
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        context.staging as *const u8,
                        context.transaction.upload.total_bytes,
                    )
                };
                let package = Package::parse(bytes, context.abi, &context.public_key)?;
                if package.version <= context.transaction.current_version {
                    return Err(Error::Version);
                }
                let bank = 1 - context.transaction.current_bank;
                if context.transaction.status.retained_banks & (1 << bank) != 0 {
                    return Err(Error::Retained);
                }
                unsafe {
                    writable_bank(context, bank, |_| 3 | (1 << 63));
                }
                let output = unsafe {
                    core::slice::from_raw_parts_mut(context.banks[bank] as *mut u8, BANK_BYTES)
                };
                let mut bindings = context.bindings;
                bindings[5] = package.version;
                package.relocate(output, &bindings)?;
                for cpu_index in 0..64 {
                    if context.transaction.expected_mask & (1 << cpu_index) != 0 {
                        let source = context.bank_idts[context.transaction.current_bank][cpu_index]
                            as *const u8;
                        let target = context.bank_idts[bank][cpu_index] as *mut u8;
                        if source.is_null() || target.is_null() {
                            return Err(Error::Cpu);
                        }
                        unsafe {
                            core::ptr::copy_nonoverlapping(source, target, 4096);
                        }
                        for vector in 0..256 {
                            let entry = unsafe { target.add(vector * 16) };
                            let offset = if vector == 13 {
                                package.exception_entries[1]
                            } else if vector < 32 {
                                package.exception_entries[2] + vector as u32 * 16
                            } else {
                                package.exception_entries[0]
                            };
                            let address = context.banks[bank] + u64::from(offset);
                            unsafe {
                                entry.cast::<u16>().write_unaligned(address as u16);
                                entry
                                    .add(6)
                                    .cast::<u16>()
                                    .write_unaligned((address >> 16) as u16);
                                entry
                                    .add(8)
                                    .cast::<u32>()
                                    .write_unaligned((address >> 32) as u32);
                            }
                        }
                    }
                }
                unsafe {
                    writable_bank(context, bank, |page| package.page_flags(page));
                }
                context.transaction.validated(
                    request.transaction,
                    &package,
                    context.banks[bank] + u64::from(package.dispatch),
                )
            }
            CHECK_CPU => {
                let reason = match blocker {
                    0 => Error::None,
                    14 => Error::NestedL2,
                    15 => Error::HyperV,
                    _ => Error::Cpu,
                };
                context
                    .transaction
                    .check_cpu(request.transaction, cpu, reason)
            }
            BEGIN_OFF => context.transaction.begin_off(request.transaction, masks),
            COMMIT => {
                if !native {
                    return Err(Error::State);
                }
                context.transaction.commit(request.transaction, masks)?;
                for index in 0..64 {
                    if context.transaction.expected_mask & (1 << index) != 0 {
                        let pointer = unsafe { host_rip_pointer(context, native, index) };
                        context.transaction.previous_host_rips[index] =
                            unsafe { pointer.read_volatile() };
                        unsafe {
                            pointer.write_volatile(context.transaction.pending_dispatch);
                        }
                        let idt_pointer = unsafe { pointer.sub(5) };
                        context.transaction.previous_idts[index] =
                            unsafe { idt_pointer.read_volatile() };
                        unsafe {
                            idt_pointer.write_volatile(
                                context.bank_idts[context.transaction.current_bank][index],
                            );
                        }
                    }
                }
                Ok(())
            }
            PROBE_CPU => {
                if identity.is_null() || native {
                    return Err(Error::Probe);
                }
                context.transaction.probe_cpu(
                    request.transaction,
                    cpu,
                    unsafe { &*identity },
                    masks,
                )
            }
            FINISH => {
                context.transaction.finish(request.transaction, masks)?;
                // Every running CPU has probed the new bank and completed its rearm.
                // The inactive IDTs are no longer hardware references and can be recycled.
                for index in 0..64 {
                    if context.transaction.expected_mask & (1 << index) != 0 {
                        unsafe {
                            (context.bank_idts[context.transaction.previous_bank][index]
                                as *mut u8)
                                .write_bytes(0, 4096);
                        }
                    }
                }
                context.transaction.previous_host_rips.fill(0);
                context.transaction.previous_idts.fill(0);
                Ok(())
            }
            CANCEL => context.transaction.cancel(request.transaction),
            RECOVER => {
                let swapped = context.transaction.status.phase == Phase::Activating as u32;
                context.transaction.recover(request.transaction, masks)?;
                if swapped {
                    for index in 0..64 {
                        if context.transaction.expected_mask & (1 << index) != 0 {
                            let pointer = unsafe { host_rip_pointer(context, native, index) };
                            unsafe {
                                pointer
                                    .write_volatile(context.transaction.previous_host_rips[index]);
                            }
                            unsafe {
                                pointer
                                    .sub(5)
                                    .write_volatile(context.transaction.previous_idts[index]);
                            }
                        }
                    }
                }
                Ok(())
            }
            RECOVERED => context.transaction.recovered(request.transaction, masks),
            QUERY => {
                if context.transaction.status.transaction != request.transaction {
                    return Err(Error::Transaction);
                }
                Ok(())
            }
            _ => Err(Error::Format),
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "efiapi" fn update_entry(
        context_pointer: *mut RuntimeContext,
        bytes_pointer: *const u8,
        length: usize,
        cpu_tag: u64,
        identity: *const [u8; 32],
        blocker: u32,
    ) -> u64 {
        if context_pointer.is_null()
            || bytes_pointer.is_null()
            || !(super::REQUEST_BYTES..=super::REQUEST_BYTES + super::CHUNK_BYTES).contains(&length)
        {
            return Error::Bounds as u64;
        }
        if unsafe { &*core::ptr::addr_of!((*context_pointer).lock) }
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Error::Busy as u64;
        }
        let context = unsafe { &mut *context_pointer };
        let native = cpu_tag >> 63 != 0;
        if native {
            context.event_runtime = identity as u64;
        }
        let cpu = (cpu_tag & 63) as usize;
        let result = (|| {
            let bytes = unsafe { core::slice::from_raw_parts(bytes_pointer, length) };
            let request = Request::parse(bytes)?;
            let result = unsafe { handle(context, &request, cpu, native, identity, blocker) };
            if request.operation != QUERY
                && request.transaction == context.transaction.status.transaction
            {
                context.transaction.status.error = result.err().unwrap_or(Error::None) as u32;
            }
            result
        })();
        unsafe {
            publish(context, native);
        }
        context.lock.store(0, Ordering::Release);
        result.err().unwrap_or(Error::None) as u64
    }
}
