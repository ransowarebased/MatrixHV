//! L2 RAM access through EPT12 and the existing protected EPT01 backend.
//! Walks never update EPT A/D bits or install/replace EPT02 mappings.
use super::access::resident::Environment;
use super::access::{PhysicalMemory, execute, page_mapping, transfer, translate};
use crate::protocol::memory::*;

pub(crate) trait HostMemory: PhysicalMemory {
    fn validate(&mut self, address: u64, write: bool) -> Result<(), Error>;
    fn synchronize(&mut self, operation: u64) -> bool;
    fn record(&mut self, phase: u64, address: u64, entry: u64, level: u64, status: u64);
    fn kernel_roots(
        &mut self,
        ept12: u64,
        syscall: u64,
        cr4: u64,
        roots: &mut [u64; ROOT_HISTORY_COUNT],
    );
}

pub(crate) fn admit_kernel_root(
    observed: [u64; 4],
    ept12: u64,
    syscall: u64,
    cr4: u64,
    roots: &mut [u64; ROOT_HISTORY_COUNT],
) {
    let [context, root, entry, mode] = observed;
    if context != ept12 & 0x000f_ffff_ffff_f000
        || context == 0
        || entry != syscall
        || syscall >> 47 != 0x1ffff
        || (mode ^ cr4) & (1 << 12) != 0
        || root == 0
        || root & !0x000f_ffff_ffff_f000 != 0
        || roots.contains(&root)
    {
        return;
    }
    if let Some(slot) = roots.iter_mut().find(|root| **root == 0) {
        *slot = root;
    }
}

pub(crate) struct Memory<'a, M: HostMemory> {
    host: &'a mut M,
    ept12: u64,
    mask: u64,
    target_writes: usize,
}

impl<'a, M: HostMemory> Memory<'a, M> {
    fn new(host: &'a mut M, ept12: u64, physical_bits: u32) -> Result<Self, Error> {
        if !(36..=52).contains(&physical_bits) {
            return Err(Error::Unsupported);
        }
        let mask = ((1_u64 << physical_bits) - 1) & !4095;
        // Only four-level, WB EPT is admitted. A/D mode is observational here.
        if ept12 & !(mask | 0x7f) != 0
            || ept12 & 0x3f != 0x1e
            || ept12 & mask == 0
            || ept12 >> 48 != 0
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            host,
            ept12,
            mask,
            target_writes: 0,
        })
    }

    fn mapped(&mut self, address: u64, write: bool) -> Result<u64, Error> {
        // Both EPT walks have four levels. Do not truncate GPA bits 48..51
        // even when the CPU's host physical-address width is larger.
        if address & !(self.mask | 4095) != 0 || address >> 48 != 0 {
            return Err(Error::Bounds);
        }
        let mut table = self.ept12 & self.mask;
        for shift in [39, 30, 21, 12] {
            if table >> 48 != 0 {
                return Err(Error::Bounds);
            }
            if !self.host.synchronize(3) {
                return Err(Error::Busy);
            }
            let mut bytes = [0; 8];
            let pointer = table + ((address >> shift) & 511) * 8;
            self.host.record(2, pointer, 0, shift, 0);
            self.host.read(pointer, &mut bytes)?;
            let entry = u64::from_le_bytes(bytes);
            self.host.record(2, pointer, entry, shift, 0);
            if entry & 1 == 0 || write && entry & 2 == 0 {
                return Err(Error::Permission);
            }
            let leaf = shift == 12 || entry & 128 != 0;
            // Intel SDM Vol. 3C, EPT entry formats: bits 63:52 are not
            // physical address bits; nonleaf bits 9/11 and disabled A/D bits
            // are ignored. Validate reserved address bits before masking.
            let address_mask = 0x000f_ffff_ffff_f000;
            if entry & address_mask & !self.mask != 0 || !leaf && entry & 0xf8 != 0 {
                return Err(Error::Format);
            }
            if leaf {
                // PTE bit 7 is ignored; only PDPTE/PDE bit 7 selects a large page.
                if shift == 39 || (entry >> 3) & 7 != 6 {
                    return Err(Error::Unsupported);
                }
                let page_mask = (1_u64 << shift) - 1;
                if entry & self.mask & page_mask != 0 {
                    return Err(Error::Format);
                }
                let physical = (entry & self.mask & !page_mask) | (address & page_mask);
                if physical >> 48 != 0 {
                    return Err(Error::Bounds);
                }
                self.host.validate(physical, write)?;
                return Ok(physical);
            }
            table = entry & self.mask;
        }
        Err(Error::Unmapped)
    }
}

impl<M: HostMemory> PhysicalMemory for Memory<'_, M> {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        if bytes.len() > 4096 - (address as usize & 4095) {
            return Err(Error::Bounds);
        }
        let physical = self.mapped(address, false)?;
        self.host.read(physical, bytes)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > 4096 - (address as usize & 4095) {
            return Err(Error::Bounds);
        }
        let physical = self.mapped(address, true)?;
        if !self.host.synchronize(3) {
            return Err(Error::Busy);
        }
        self.host.write(physical, bytes)?;
        self.target_writes += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct ResponsePage {
    physical: u64,
    length: usize,
}

pub(crate) fn request(
    host: &mut impl HostMemory,
    environment: &Environment,
    ept12: u64,
    caller_address: u64,
    packet: &mut [u8],
) -> Result<(), Error> {
    if !(HEADER_BYTES..=BUFFER_BYTES).contains(&packet.len()) {
        return Err(Error::Bounds);
    }
    host.record(1, caller_address, ept12, environment.caller_cr3, 0);
    if !host.synchronize(0) {
        host.record(4, 0, 0, 0, Error::Busy as u64);
        return Err(Error::Busy);
    }
    let result = request_locked(host, environment, ept12, caller_address, packet);
    host.synchronize(2);
    host.record(
        if result.is_ok() { 3 } else { 4 },
        0,
        0,
        0,
        result.as_ref().err().map_or(0, |error| *error as u64),
    );
    result
}

fn request_locked(
    host: &mut impl HostMemory,
    environment: &Environment,
    ept12: u64,
    caller_address: u64,
    packet: &mut [u8],
) -> Result<(), Error> {
    let mut memory = Memory::new(host, ept12, environment.physical_bits as u32)?;
    let la57 = environment.guest_cr4 & (1 << 12) != 0;
    // Pin every writable response page before any target store. A target may
    // alias the caller's page tables; reply to the validated original backing.
    let mut response = [ResponsePage::default(); BUFFER_BYTES / 4096 + 1];
    let mut cursor = 0;
    let mut pages = 0;
    while cursor < packet.len() {
        let address = caller_address
            .checked_add(cursor as u64)
            .ok_or(Error::Bounds)?;
        let physical = translate(
            &mut memory,
            environment.caller_cr3,
            address,
            la57,
            environment.physical_bits as u32,
            true,
            true,
        )?;
        let physical = memory.mapped(physical, true)?;
        let length = (4096 - (address as usize & 4095)).min(packet.len() - cursor);
        response[pages] = ResponsePage { physical, length };
        cursor += length;
        pages += 1;
    }
    let (_, copied) = transfer(
        &mut memory,
        environment.caller_cr3,
        caller_address,
        packet,
        la57,
        environment.physical_bits as u32,
        (false, true),
    );
    copied?;
    let operation = word(packet, 12);
    let result = if matches!(operation, INFO | READ | WRITE) {
        execute(&mut memory, packet, la57, environment.physical_bits as u32)
    } else {
        Err(Error::Unsupported)
    };
    packet[40..44].copy_from_slice(&(result.err().map_or(0, |error| error as u32)).to_le_bytes());
    packet[48..56].copy_from_slice(&environment.caller_cr3.to_le_bytes());
    packet[56..64].copy_from_slice(&environment.syscall.to_le_bytes());
    if operation == INFO {
        // No L1 CR3 history, tracking, hooks or profile capabilities escape here.
        packet[64..72].fill(0);
        packet[72..76].copy_from_slice(&L2_MEMORY_CAPABILITY.to_le_bytes());
        if packet.len() == INFO_BYTES {
            packet[HEADER_BYTES..].fill(0);
        }
        let mut roots = [0; ROOT_HISTORY_COUNT];
        memory.host.kernel_roots(
            ept12,
            environment.syscall,
            environment.guest_cr4,
            &mut roots,
        );
        // These are candidates, not trusted OS identities. Validate a fresh
        // supervisor executable LSTAR mapping in the caller's EPT12 namespace.
        // Neo then verifies the kernel's PE/PDB identity before resolving it.
        let mut count = 0;
        for root in roots.into_iter().filter(|root| *root != 0) {
            if !memory.host.synchronize(3) {
                break;
            }
            let Ok(mapping) = page_mapping(
                &mut memory,
                root,
                environment.syscall,
                la57,
                environment.physical_bits as u32,
            ) else {
                continue;
            };
            if !mapping.present || mapping.permissions & (4 | 8) != 8 {
                continue;
            }
            let mut byte = [0];
            if memory.read(mapping.physical_address, &mut byte).is_err() {
                continue;
            }
            if count == 0 {
                packet[64..72].copy_from_slice(&root.to_le_bytes());
            }
            if packet.len() == INFO_BYTES {
                packet[HEADER_BYTES + count * 8..HEADER_BYTES + (count + 1) * 8]
                    .copy_from_slice(&root.to_le_bytes());
            }
            count += 1;
            if count == 8 {
                break;
            }
        }
        packet[72..76]
            .copy_from_slice(&(L2_MEMORY_CAPABILITY | L2_KERNEL_ROOT_CAPABILITY).to_le_bytes());
    }
    cursor = 0;
    for page in &response[..pages] {
        let copied = if memory.host.synchronize(3) {
            memory
                .host
                .write(page.physical, &packet[cursor..cursor + page.length])
        } else {
            Err(Error::Busy)
        };
        if let Err(error) = copied {
            return Err(if memory.target_writes != 0 {
                Error::WriteResponseLost
            } else {
                error
            });
        }
        cursor += page.length;
    }
    Ok(())
}
