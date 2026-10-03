use crate::protocol::memory::*;

pub trait PhysicalMemory {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error>;
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error>;
}

fn set_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn translate(
    memory: &mut impl PhysicalMemory,
    cr3: u64,
    address: u64,
    la57: bool,
    physical_bits: u32,
    write: bool,
    user: bool,
) -> Result<u64, Error> {
    let space = TargetSpace {
        cr3,
        kernel_cr3: cr3,
        la57,
        physical_bits,
        layout: SoftPteLayout::default(),
        user,
        committed_protection: None,
    };
    match target_translate(memory, &space, cr3, address, write, 0)? {
        Backing::Physical(physical) => Ok(physical),
        Backing::Zero => Err(Error::Unmapped),
    }
}

pub fn transfer(
    memory: &mut impl PhysicalMemory,
    cr3: u64,
    address: u64,
    bytes: &mut [u8],
    la57: bool,
    physical_bits: u32,
    permissions: (bool, bool),
) -> (usize, Result<(), Error>) {
    let (write, user) = permissions;
    if address.checked_add(bytes.len() as u64).is_none() {
        return (0, Err(Error::Bounds));
    }
    let mut done = 0;
    while done < bytes.len() {
        let current = address + done as u64;
        let count = (4096 - (current as usize & 4095)).min(bytes.len() - done);
        let result = translate(memory, cr3, current, la57, physical_bits, write, user).and_then(
            |physical| {
                if write {
                    memory.write(physical, &bytes[done..done + count])
                } else {
                    memory.read(physical, &mut bytes[done..done + count])
                }
            },
        );
        if result.is_err() {
            return (done, result);
        }
        done += count;
    }
    (done, Ok(()))
}

struct TargetSpace {
    cr3: u64,
    kernel_cr3: u64,
    la57: bool,
    physical_bits: u32,
    layout: SoftPteLayout,
    user: bool,
    committed_protection: Option<u32>,
}

enum Backing {
    Physical(u64),
    Zero,
}

fn protection(entry: u64, mask: u64, write: bool) -> Result<(), Error> {
    let value = (entry & mask) >> mask.trailing_zeros();
    let basic = value & 7;
    if basic == 0 || value & 16 != 0 {
        return Err(Error::Permission);
    }
    if write {
        if basic == 5 || basic == 7 {
            return Err(Error::CopyOnWrite);
        }
        if basic != 4 && basic != 6 {
            return Err(Error::Permission);
        }
    }
    Ok(())
}

fn soft_backing(
    memory: &mut impl PhysicalMemory,
    space: &TargetSpace,
    entry: u64,
    address: u64,
    write: bool,
    depth: u32,
) -> Result<Backing, Error> {
    let layout = space.layout;
    if layout.transition == 0 || entry == 0 {
        return Err(Error::Unmapped);
    }
    if entry & layout.prototype != 0 {
        if depth >= 4 || entry & layout.prototype_read_only != 0 {
            return Err(Error::PrototypeUnresolved);
        }
        let shift = layout.prototype_address.trailing_zeros();
        let width = layout.prototype_address.count_ones();
        let raw = (entry & layout.prototype_address) >> shift;
        let prototype_address = (((raw << (64 - width)) as i64) >> (64 - width)) as u64;
        if prototype_address >> 63 == 0 || prototype_address & 7 != 0 {
            return Err(Error::PrototypeUnresolved);
        }
        let Backing::Physical(physical) = target_translate(
            memory,
            space,
            space.kernel_cr3,
            prototype_address,
            false,
            depth + 1,
        )?
        else {
            return Err(Error::PrototypeUnresolved);
        };
        let mut bytes = [0; 8];
        memory.read(physical, &mut bytes)?;
        let prototype = u64::from_le_bytes(bytes);
        if write {
            return Err(Error::CopyOnWrite);
        }
        if prototype & 1 != 0 {
            let mask = ((1u64 << space.physical_bits) - 1) & !4095;
            if prototype & 0x000f_ffff_ffff_f000 & !mask != 0 {
                return Err(Error::Bounds);
            }
            return Ok(Backing::Physical((prototype & mask) | (address & 4095)));
        }
        if prototype == 0 {
            return Err(Error::PrototypeUnresolved);
        }
        // A referenced prototype can itself be transitional or demand-zero.
        return soft_backing(memory, space, prototype, address, false, depth + 1);
    }
    if entry & layout.transition != 0 {
        protection(entry, layout.transition_protection, write)?;
        // Standby/modified frames cannot be pinned here; reads remain observational.
        if write {
            return Err(Error::Permission);
        }
        let frame =
            ((entry & layout.transition_frame) >> layout.transition_frame.trailing_zeros()) << 12;
        if frame >> space.physical_bits != 0 {
            return Err(Error::Bounds);
        }
        return Ok(Backing::Physical(frame | (address & 4095)));
    }
    protection(entry, layout.software_protection, write)?;
    if entry & layout.pagefile != 0 {
        return Err(Error::PagefileBacked);
    }
    if entry & !layout.software_protection != 0 {
        return Err(Error::Unmapped);
    }
    if write {
        return Err(Error::DemandZeroWrite);
    }
    Ok(Backing::Zero)
}

fn target_translate(
    memory: &mut impl PhysicalMemory,
    space: &TargetSpace,
    cr3: u64,
    address: u64,
    write: bool,
    depth: u32,
) -> Result<Backing, Error> {
    if depth > 4 {
        return Err(Error::PrototypeUnresolved);
    }
    if !(36..=52).contains(&space.physical_bits) {
        return Err(Error::Unsupported);
    }
    let sign_shift = if space.la57 { 7 } else { 16 };
    if ((address << sign_shift) as i64 >> sign_shift) as u64 != address {
        return Err(Error::Bounds);
    }
    let mask = ((1u64 << space.physical_bits) - 1) & !4095;
    if cr3 & !(mask | 4095) != 0 || cr3 & mask == 0 {
        return Err(Error::Bounds);
    }
    let mut table = cr3 & mask;
    let mut shift = if space.la57 { 48 } else { 39 };
    loop {
        let mut bytes = [0; 8];
        memory.read(table + ((address >> shift) & 511) * 8, &mut bytes)?;
        let entry = u64::from_le_bytes(bytes);
        if entry & 1 == 0 {
            if entry == 0 && depth == 0 && address >> 63 == 0 {
                if let Some(value) = space.committed_protection {
                    protection(u64::from(value), 31, write)?;
                    return if write {
                        Err(Error::DemandZeroWrite)
                    } else {
                        Ok(Backing::Zero)
                    };
                }
            }
            return if shift == 12 {
                soft_backing(memory, space, entry, address, write, depth)
            } else {
                Err(Error::Unmapped)
            };
        }
        if write && entry & 2 == 0 || space.user && entry & 4 == 0 {
            return Err(Error::Permission);
        }
        if entry & 0x000f_ffff_ffff_f000 & !mask != 0 {
            return Err(Error::Bounds);
        }
        let large = entry & 128 != 0 && shift != 12;
        if large && shift != 30 && shift != 21 {
            return Err(Error::Format);
        }
        if shift == 12 || large {
            if write && entry & space.layout.hardware_copy_on_write != 0 {
                return Err(Error::CopyOnWrite);
            }
            let page_mask = (1u64 << shift) - 1;
            if large && entry & mask & page_mask & !(1 << 12) != 0 {
                return Err(Error::Format);
            }
            return Ok(Backing::Physical(
                (entry & mask & !page_mask) | (address & page_mask),
            ));
        }
        table = entry & mask;
        shift -= 9;
    }
}

fn target_transfer(
    memory: &mut impl PhysicalMemory,
    space: &TargetSpace,
    address: u64,
    bytes: &mut [u8],
    write: bool,
) -> (usize, u32) {
    let mut done = 0;
    let mut status = 0;
    while done < bytes.len() {
        let current = address + done as u64;
        let count = (4096 - (current as usize & 4095)).min(bytes.len() - done);
        let cr3 = if current >> 63 != 0 {
            space.kernel_cr3
        } else {
            space.cr3
        };
        let result =
            target_translate(memory, space, cr3, current, write, 0).and_then(
                |backing| match backing {
                    Backing::Physical(physical) if write => {
                        memory.write(physical, &bytes[done..done + count])
                    }
                    Backing::Physical(physical) => {
                        memory.read(physical, &mut bytes[done..done + count])
                    }
                    Backing::Zero => {
                        bytes[done..done + count].fill(0);
                        status = ROAD_STATUS_DEMAND_ZERO;
                        Ok(())
                    }
                },
            );
        if let Err(error) = result {
            return (done, error as u32);
        }
        done += count;
    }
    (done, status)
}

pub fn execute(
    memory: &mut impl PhysicalMemory,
    packet: &mut [u8],
    la57: bool,
    physical_bits: u32,
) -> Result<(), Error> {
    if !(HEADER_BYTES..=BUFFER_BYTES).contains(&packet.len()) {
        return Err(Error::Bounds);
    }
    if quad(packet, 0) != MEMORY_MAGIC
        || word(packet, 8) != MEMORY_VERSION
        || word(packet, 36) as usize != packet.len()
        || word(packet, 44) != 0
    {
        return Err(Error::Format);
    }
    let operation = word(packet, 12);
    let count = word(packet, 32) as usize;
    if operation == INFO {
        return if count == 0 && matches!(packet.len(), HEADER_BYTES | INFO_BYTES) {
            Ok(())
        } else {
            Err(Error::Format)
        };
    }
    if !matches!(operation, READ | WRITE) || count == 0 || count > MAX_ITEMS {
        return Err(Error::Format);
    }
    let data_start = HEADER_BYTES + count * ITEM_BYTES;
    if data_start > packet.len() || quad(packet, 16) & !4095 == 0 {
        return Err(Error::Bounds);
    }
    // Validate the entire descriptor table before allowing any target writes.
    let mut previous_end = data_start;
    for index in 0..count {
        let item = HEADER_BYTES + index * ITEM_BYTES;
        let offset = word(packet, item + 8) as usize;
        let length = word(packet, item + 12) as usize;
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        if length == 0
            || word(packet, item + 16) > 1
            || (word(packet, item + 16) == 0 && word(packet, item + 20) != 0)
            || (word(packet, item + 16) == 1 && word(packet, item + 20) > 31)
            || offset < previous_end
            || end > packet.len()
            || quad(packet, item).checked_add(length as u64).is_none()
        {
            return Err(Error::Bounds);
        }
        previous_end = end;
    }
    let layout = SoftPteLayout::from_packet(packet);
    if !layout.validate() {
        return Err(Error::Format);
    }
    let target_cr3 = quad(packet, 16);
    let kernel_cr3 = quad(packet, 64);
    let user_cr3 = quad(packet, 72);
    let mut space = TargetSpace {
        cr3: if user_cr3 == 0 { target_cr3 } else { user_cr3 },
        kernel_cr3: if kernel_cr3 == 0 {
            target_cr3
        } else {
            kernel_cr3
        },
        la57,
        physical_bits,
        layout,
        user: false,
        committed_protection: None,
    };
    for index in 0..count {
        let item = HEADER_BYTES + index * ITEM_BYTES;
        let address = quad(packet, item);
        let offset = word(packet, item + 8) as usize;
        let length = word(packet, item + 12) as usize;
        space.committed_protection =
            (word(packet, item + 16) == 1).then(|| word(packet, item + 20));
        let (done, status) = target_transfer(
            memory,
            &space,
            address,
            &mut packet[offset..offset + length],
            operation == WRITE,
        );
        set_word(packet, item + 16, status);
        set_word(packet, item + 20, done as u32);
    }
    Ok(())
}

#[cfg(any(target_os = "uefi", test))]
pub(crate) mod resident {
    use super::*;
    const MASK: u64 = 0x000f_ffff_ffff_f000;

    #[repr(C)]
    pub struct Environment {
        pub caller_cr3: u64,
        pub guest_cr4: u64,
        pub ept: u64,
        pub host_cr3: u64,
        pub syscall: u64,
        pub kernel_cr3: u64,
        pub physical_bits: u64,
        pub root_history: u64,
    }

    struct Memory<'a> {
        environment: &'a Environment,
    }

    impl Memory<'_> {
        // Host tables are private, stable identity mappings cloned before boot.
        // Check them before dereferencing any guest-controlled physical address.
        fn host_address(&self, address: u64, write: bool) -> Result<u64, Error> {
            if address & !0x0000_7fff_ffff_ffff != 0 {
                return Err(Error::Bounds);
            }
            let mut table = self.environment.host_cr3 & MASK;
            for shift in [39, 30, 21, 12] {
                let entry = unsafe {
                    ((table + ((address >> shift) & 511) * 8) as *const u64).read_volatile()
                };
                if entry & 1 == 0 || write && entry & 2 == 0 {
                    return Err(Error::Permission);
                }
                if shift == 12 || (shift <= 30 && entry & 128 != 0) {
                    let page_mask = (1u64 << shift) - 1;
                    let mapped = (entry & MASK & !page_mask) | (address & page_mask);
                    return if mapped == address {
                        Ok(address)
                    } else {
                        Err(Error::Permission)
                    };
                }
                table = entry & MASK;
            }
            Err(Error::Unmapped)
        }

        fn mapped(&self, address: u64, write: bool) -> Result<u64, Error> {
            let mut table = self.environment.ept & MASK;
            for shift in [39, 30, 21, 12] {
                let pointer = self.host_address(table + ((address >> shift) & 511) * 8, false)?;
                let entry = unsafe { (pointer as *const u64).read_volatile() };
                if entry & 1 == 0 || write && entry & 2 == 0 {
                    return Err(Error::Permission);
                }
                if shift == 12 || (shift <= 30 && entry & 128 != 0) {
                    if (entry >> 3) & 7 != 6 {
                        return Err(Error::Permission);
                    }
                    let page_mask = (1u64 << shift) - 1;
                    let physical = (entry & MASK & !page_mask) | (address & page_mask);
                    // Concealed resident pages map to decoys; never expose those aliases.
                    if physical != address {
                        return Err(Error::Permission);
                    }
                    return self.host_address(physical, write);
                }
                table = entry & MASK;
            }
            Err(Error::Unmapped)
        }
    }

    impl PhysicalMemory for Memory<'_> {
        fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
            if bytes.len() > 4096 - (address as usize & 4095) {
                return Err(Error::Bounds);
            }
            let pointer = self.mapped(address, false)? as *const u8;
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = unsafe { pointer.add(index).read_volatile() };
            }
            Ok(())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
            if bytes.len() > 4096 - (address as usize & 4095) {
                return Err(Error::Bounds);
            }
            let pointer = self.mapped(address, true)? as *mut u8;
            for (index, byte) in bytes.iter().enumerate() {
                unsafe {
                    pointer.add(index).write_volatile(*byte);
                }
            }
            Ok(())
        }
    }

    pub unsafe extern "efiapi" fn memory_entry(
        scratch: *mut u8,
        caller_address: u64,
        length: usize,
        environment: *const Environment,
    ) -> u64 {
        if !(HEADER_BYTES..=BUFFER_BYTES).contains(&length) {
            return Error::Bounds as u64;
        }
        let environment = unsafe { &*environment };
        let la57 = environment.guest_cr4 & (1 << 12) != 0;
        let physical_bits = environment.physical_bits as u32;
        let mut memory = Memory { environment };
        let packet = unsafe { core::slice::from_raw_parts_mut(scratch, length) };
        // Preflight the writable response range before processing a write batch.
        let mut cursor = 0;
        while cursor < length {
            let Some(address) = caller_address.checked_add(cursor as u64) else {
                return Error::Bounds as u64;
            };
            let result = translate(
                &mut memory,
                environment.caller_cr3,
                address,
                la57,
                physical_bits,
                true,
                true,
            )
            .and_then(|physical| memory.mapped(physical, true));
            if let Err(error) = result {
                return error as u64;
            }
            cursor += (4096 - (address as usize & 4095)).min(length - cursor);
        }
        let (_, copied) = transfer(
            &mut memory,
            environment.caller_cr3,
            caller_address,
            packet,
            la57,
            physical_bits,
            (false, true),
        );
        if let Err(error) = copied {
            return error as u64;
        }
        let result = execute(&mut memory, packet, la57, physical_bits);
        set_word(packet, 40, result.err().map_or(0, |error| error as u32));
        packet[48..56].copy_from_slice(&environment.caller_cr3.to_le_bytes());
        packet[56..64].copy_from_slice(&environment.syscall.to_le_bytes());
        if word(packet, 12) == INFO {
            packet[64..72].copy_from_slice(&environment.kernel_cr3.to_le_bytes());
            if packet.len() == INFO_BYTES {
                for index in 0..ROOT_HISTORY_COUNT {
                    let root = if environment.root_history == 0 {
                        0
                    } else {
                        unsafe {
                            ((environment.root_history as *const u64).add(index)).read_volatile()
                        }
                    };
                    packet[HEADER_BYTES + index * 8..HEADER_BYTES + (index + 1) * 8]
                        .copy_from_slice(&root.to_le_bytes());
                }
            }
        }
        let (_, copied) = transfer(
            &mut memory,
            environment.caller_cr3,
            caller_address,
            packet,
            la57,
            physical_bits,
            (true, true),
        );
        copied.err().map_or(0, |error| error as u64)
    }
}
