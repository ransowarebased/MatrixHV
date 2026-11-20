use super::*;
use crate::memory::nested;

#[derive(Default)]
struct Barrier {
    operations: Vec<u64>,
    deny_acquire: bool,
    expired: bool,
    expire_after_target: Option<u64>,
}

unsafe extern "efiapi" fn barrier(context: u64, operation: u64) -> u64 {
    let state = unsafe { &mut *(context as *mut Barrier) };
    state.operations.push(operation);
    if let Some(address) = state.expire_after_target {
        state.expired |= unsafe { (address as *const u8).read() } == 42;
    }
    u64::from(match operation {
        0 => !state.deny_acquire,
        3 => !state.expired,
        _ => true,
    })
}

struct Fixture {
    machine: Machine,
    environment: access::resident::Environment,
    ept12: u64,
    buffer: u64,
    target: u64,
    next_target: u64,
    response_pt: u64,
    barrier: Box<Barrier>,
}

impl Fixture {
    fn new(request: &[u8]) -> Self {
        let (mut machine, mut environment, buffer, target) = Machine::setup(request);
        let next_target = machine.allocate();
        let ept12 = machine.allocate();
        let tables: [u64; 8] = std::array::from_fn(|_| machine.allocate());
        for (base, index) in [(0x1000, 0), (0x5000, 4)] {
            for level in 0..3 {
                unsafe {
                    (tables[index + level] as *mut u64).write(base + (level as u64 + 1) * 4096 | 7);
                }
            }
        }
        unsafe {
            (tables[3] as *mut u64).add(1).write(0xa007);
            (tables[7] as *mut u64).write(0xb007);
            (tables[7] as *mut u64).add(1).write(0xc007);
            (next_target as *mut u8).write(77);
        }
        for (index, physical) in tables.iter().enumerate() {
            machine.map(ept12, (index as u64 + 1) * 4096, *physical, 0x37);
        }
        for (gpa, physical) in [(0xa000, buffer), (0xb000, target), (0xc000, next_target)] {
            machine.map(ept12, gpa, physical, 0x37);
        }
        let mut index = 0;
        while index < machine.pages.len() {
            let address = machine.pages[index].0.as_ptr() as u64;
            machine.map(machine.ept, address, address, 0x37);
            index += 1;
        }
        machine.host_map_all();
        let mut state = Box::<Barrier>::default();
        environment.caller_cr3 = 0x1000;
        environment.kernel_cr3 = 0;
        environment.root_history = 0;
        environment.synchronize = barrier as *const () as u64;
        environment.boot_context = &mut *state as *mut Barrier as u64;
        Self {
            machine,
            environment,
            ept12,
            buffer,
            target,
            next_target,
            response_pt: tables[3],
            barrier: state,
        }
    }

    fn invoke(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert!(request.len() <= 4096);
        unsafe {
            std::ptr::copy_nonoverlapping(request.as_ptr(), self.buffer as *mut u8, request.len());
        }
        let mut scratch = vec![0xcc; request.len()];
        let mut memory = access::resident::Memory {
            environment: &self.environment,
        };
        nested::request(
            &mut memory,
            &self.environment,
            self.ept12 | 0x1e,
            0x1000,
            &mut scratch,
        )?;
        Ok(unsafe { std::slice::from_raw_parts(self.buffer as *const u8, request.len()) }.to_vec())
    }
}

#[test]
fn l2_read_write_uses_nonidentity_ept12_for_tables_and_payload() {
    let read = packet(
        READ,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![0; 1],
        }],
    )
    .unwrap();
    let mut fixture = Fixture::new(&read);
    let before = unsafe { ept_pointer(fixture.ept12, 0xb000, 12).read() };
    let response = fixture.invoke(&read).unwrap();
    assert_eq!(word(&response, 40), 0);
    assert_eq!(*response.last().unwrap(), 101);
    let write = packet(
        WRITE,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![42],
        }],
    )
    .unwrap();
    assert_eq!(word(&fixture.invoke(&write).unwrap(), 40), 0);
    assert_eq!(unsafe { (fixture.target as *const u8).read() }, 42);
    assert_eq!(
        unsafe { ept_pointer(fixture.ept12, 0xb000, 12).read() },
        before
    );
    assert_eq!(
        fixture
            .barrier
            .operations
            .iter()
            .filter(|op| **op != 3)
            .copied()
            .collect::<Vec<_>>(),
        [0, 2, 0, 2]
    );
}

#[test]
fn l2_write_checks_both_ept_layers_and_every_parent_permission() {
    let write = packet(
        WRITE,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![42],
        }],
    )
    .unwrap();
    for layer in 0..3 {
        let mut fixture = Fixture::new(&write);
        let pointer = match layer {
            0 => ept_pointer(fixture.ept12, 0xb000, 12),
            1 => ept_pointer(fixture.environment.ept, fixture.target, 12),
            _ => ept_pointer(fixture.ept12, 0xb000, 39),
        };
        unsafe {
            *pointer &= !2;
        }
        let response = fixture.invoke(&write);
        if layer == 2 {
            assert_eq!(response.unwrap_err(), Error::Permission);
        } else {
            let response = response.unwrap();
            assert_eq!(word(&response, HEADER_BYTES + 16), Error::Permission as u32);
            assert_eq!(word(&response, HEADER_BYTES + 20), 0);
        }
        assert_eq!(unsafe { (fixture.target as *const u8).read() }, 101);
    }
}

#[test]
fn l2_response_must_be_writable_before_any_target_write() {
    let write = packet(
        WRITE,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![42],
        }],
    )
    .unwrap();
    for guest in [false, true] {
        let mut fixture = Fixture::new(&write);
        let pointer = if guest {
            (fixture.response_pt + 8) as *mut u64
        } else {
            ept_pointer(fixture.ept12, 0xa000, 12)
        };
        unsafe {
            *pointer &= !2;
        }
        assert_eq!(fixture.invoke(&write).unwrap_err(), Error::Permission);
        assert_eq!(unsafe { (fixture.target as *const u8).read() }, 101);
        assert_eq!(fixture.barrier.operations.last(), Some(&2));
    }
}

#[test]
fn l2_info_and_unsupported_operations_never_advertise_l1_sessions() {
    let info = neo::memory::info_packet().unwrap();
    let mut fixture = Fixture::new(&info);
    fixture.environment.kernel_cr3 = 0xdead000;
    let response = fixture.invoke(&info).unwrap();
    assert_eq!(word(&response, 40), 0);
    assert_eq!(quad(&response, 48), 0x1000);
    assert_eq!(quad(&response, 64), 0);
    assert_eq!(
        word(&response, 72),
        L2_MEMORY_CAPABILITY | L2_KERNEL_ROOT_CAPABILITY
    );
    assert!(response[HEADER_BYTES..].iter().all(|value| *value == 0));
    for operation in [
        AD_START,
        INTERCEPT_STATUS,
        HOOK_INSTALL,
        CPUID_SET,
        EVENT_SET,
    ] {
        let mut request = info.clone();
        request[12..16].copy_from_slice(&operation.to_le_bytes());
        assert_eq!(
            word(&fixture.invoke(&request).unwrap(), 40),
            Error::Unsupported as u32
        );
    }
}

#[test]
fn l2_transport_fails_closed_on_barrier_failure_and_expiry() {
    let write = packet(
        WRITE,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![42],
        }],
    )
    .unwrap();
    for acquired in [false, true] {
        let mut fixture = Fixture::new(&write);
        fixture.barrier.deny_acquire = !acquired;
        fixture.barrier.expired = acquired;
        assert_eq!(fixture.invoke(&write).unwrap_err(), Error::Busy);
        assert_eq!(unsafe { (fixture.target as *const u8).read() }, 101);
        if acquired {
            assert_eq!(fixture.barrier.operations.last(), Some(&2));
        } else {
            assert_eq!(fixture.barrier.operations, [0]);
        }
    }
}

#[test]
fn l2_lost_reply_after_target_write_is_explicitly_nonretryable() {
    let write = packet(
        WRITE,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![42],
        }],
    )
    .unwrap();
    let mut fixture = Fixture::new(&write);
    fixture.barrier.expire_after_target = Some(fixture.target);
    assert_eq!(
        fixture.invoke(&write).unwrap_err(),
        Error::WriteResponseLost
    );
    assert_eq!(unsafe { (fixture.target as *const u8).read() }, 42);
    assert_eq!(fixture.barrier.operations.last(), Some(&2));
    assert_eq!(
        crate::output::classify(neo::memory::status_text(Error::WriteResponseLost as u32)),
        ("WRITE_COMMITTED_RESPONSE_LOST", false)
    );
}

#[test]
fn l2_reads_cross_page_boundaries_and_report_partial_writes() {
    let request = packet(
        WRITE,
        1,
        0x5000,
        &[Item {
            address: 4095,
            bytes: vec![23, 24],
        }],
    )
    .unwrap();
    let mut fixture = Fixture::new(&request);
    unsafe {
        *ept_pointer(fixture.ept12, 0xc000, 12) &= !2;
    }
    let response = fixture.invoke(&request).unwrap();
    assert_eq!(word(&response, HEADER_BYTES + 16), Error::Permission as u32);
    assert_eq!(word(&response, HEADER_BYTES + 20), 1);
    assert_eq!(
        unsafe { (fixture.target as *const u8).add(4095).read() },
        23
    );
    assert_eq!(unsafe { (fixture.next_target as *const u8).read() }, 77);
    let read = packet(
        READ,
        1,
        0x5000,
        &[Item {
            address: 4095,
            bytes: vec![0; 2],
        }],
    )
    .unwrap();
    let response = fixture.invoke(&read).unwrap();
    assert_eq!(&response[response.len() - 2..], &[23, 77]);
}

#[test]
fn l2_rejects_mmio_concealed_tables_and_malformed_ept_entries() {
    let read = packet(
        READ,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![0],
        }],
    )
    .unwrap();
    for case in 0..5 {
        let mut fixture = Fixture::new(&read);
        let leaf = ept_pointer(fixture.ept12, 0xb000, 12);
        unsafe {
            match case {
                0 => *leaf &= !0x38,
                1 => {
                    fixture.environment.physical_bits = 46;
                    *leaf |= 1 << 47;
                }
                2 => *ept_pointer(fixture.ept12, 0xb000, 39) |= 1 << 6,
                3 => *ept_pointer(fixture.environment.ept, fixture.target, 12) &= !0x38,
                _ => {
                    let decoy = fixture.machine.allocate();
                    fixture.machine.host_map_all();
                    *ept_pointer(fixture.environment.ept, fixture.target, 12) = decoy | 0x37;
                }
            }
        }
        let response = fixture.invoke(&read);
        if case == 2 {
            assert_eq!(response.unwrap_err(), Error::Format);
            continue;
        }
        let response = response.unwrap();
        assert_ne!(word(&response, HEADER_BYTES + 16), 0);
        assert_eq!(word(&response, HEADER_BYTES + 20), 0);
    }
    let mut fixture = Fixture::new(&read);
    let root = ept_pointer(fixture.environment.ept, fixture.ept12, 12);
    unsafe {
        *root &= !1;
    }
    assert_eq!(fixture.invoke(&read).unwrap_err(), Error::Permission);
}

#[test]
fn l2_reply_uses_pinned_backing_when_target_aliases_caller_page_tables() {
    let write = packet(
        WRITE,
        1,
        0x5000,
        &[Item {
            address: 8,
            bytes: vec![0; 8],
        }],
    )
    .unwrap();
    let mut fixture = Fixture::new(&write);
    unsafe {
        *ept_pointer(fixture.ept12, 0xb000, 12) = fixture.response_pt | 0x37;
    }
    let response = fixture.invoke(&write).unwrap();
    assert_eq!(word(&response, HEADER_BYTES + 16), 0);
    assert_eq!(word(&response, HEADER_BYTES + 20), 8);
    assert_eq!(
        unsafe { ((fixture.response_pt + 8) as *const u64).read() },
        0
    );
    assert_eq!(quad(&response, 48), 0x1000);
}

#[test]
fn l2_observational_walk_preserves_ad_bits_and_accepts_large_wb_leaves() {
    let read = packet(
        READ,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![0],
        }],
    )
    .unwrap();
    for shift in [21, 30] {
        let mut fixture = Fixture::new(&read);
        let page_mask = (1_u64 << shift) - 1;
        // Map a large L2 range to a host-aligned L1 range; only the actual
        // resident pages are backed by EPT01/host mappings in this fixture.
        let l2_address = fixture.target & page_mask;
        unsafe {
            *ept_pointer(fixture.ept12, 0xb000, 12) = fixture.target | 0x37;
            *ept_pointer(fixture.ept12, 1_u64 << 39, 39) = 0;
        }
        let l2_base = 1_u64 << 39;
        fixture
            .machine
            .map(fixture.ept12, l2_base, fixture.target & !page_mask, 0x37);
        let leaf = ept_pointer(fixture.ept12, l2_base, shift);
        unsafe {
            *leaf = (fixture.target & !page_mask) | 0x1b7;
        }
        let mut index = 0;
        while index < fixture.machine.pages.len() {
            let address = fixture.machine.pages[index].0.as_ptr() as u64;
            fixture
                .machine
                .map(fixture.machine.ept, address, address, 0x37);
            index += 1;
        }
        fixture.machine.host_map_all();
        // Point the process's L2 PTE at the large EPT leaf's offset.
        let target_pt_l1 =
            unsafe { ept_pointer(fixture.ept12, 0x8000, 12).read() } & 0x000f_ffff_ffff_f000;
        unsafe {
            (target_pt_l1 as *mut u64).write((l2_base + l2_address) | 7);
        }
        let before = unsafe { leaf.read() };
        fixture.ept12 |= 0x40;
        let response = fixture.invoke(&read).unwrap();
        assert_eq!(word(&response, HEADER_BYTES + 16), 0);
        assert_eq!(*response.last().unwrap(), 101);
        assert_eq!(unsafe { leaf.read() }, before);
    }
}

#[test]
fn l2_maximum_unaligned_packet_pins_all_seventeen_response_pages() {
    let request = packet(
        READ,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![0; BUFFER_BYTES - HEADER_BYTES - ITEM_BYTES],
        }],
    )
    .unwrap();
    let mut fixture = Fixture::new(&request[..HEADER_BYTES]);
    let mut buffers = vec![fixture.buffer];
    buffers.extend((0..16).map(|_| fixture.machine.allocate()));
    for (index, physical) in buffers.iter().enumerate() {
        let gpa = 0x10000 + index as u64 * 4096;
        fixture.machine.map(fixture.ept12, gpa, *physical, 0x37);
        unsafe {
            (fixture.response_pt as *mut u64)
                .add(index + 1)
                .write(gpa | 7);
        }
    }
    let mut index = 0;
    while index < fixture.machine.pages.len() {
        let address = fixture.machine.pages[index].0.as_ptr() as u64;
        fixture
            .machine
            .map(fixture.machine.ept, address, address, 0x37);
        index += 1;
    }
    fixture.machine.host_map_all();
    let mut cursor = 0;
    for (index, physical) in buffers.iter().enumerate() {
        let offset = usize::from(index == 0);
        let length = (4096 - offset).min(request.len() - cursor);
        unsafe {
            std::ptr::copy_nonoverlapping(
                request[cursor..].as_ptr(),
                (*physical as *mut u8).add(offset),
                length,
            );
        }
        cursor += length;
    }
    assert_eq!(cursor, BUFFER_BYTES);
    let mut scratch = vec![0; BUFFER_BYTES];
    let mut memory = access::resident::Memory {
        environment: &fixture.environment,
    };
    nested::request(
        &mut memory,
        &fixture.environment,
        fixture.ept12 | 0x1e,
        0x1001,
        &mut scratch,
    )
    .unwrap();
    let mut response = Vec::new();
    for (index, physical) in buffers.iter().enumerate() {
        let offset = usize::from(index == 0);
        let length = (4096 - offset).min(BUFFER_BYTES - response.len());
        response.extend_from_slice(unsafe {
            std::slice::from_raw_parts((*physical as *const u8).add(offset), length)
        });
    }
    assert_eq!(response, scratch);
    assert_eq!(word(&response, HEADER_BYTES + 20), 8192);
    assert_eq!(word(&response, HEADER_BYTES + 16), Error::Unmapped as u32);
}

#[test]
fn l2_explicit_kernel_root_is_used_without_borrowing_l1_root_history() {
    let mut read = packet(
        READ,
        1,
        0x1000,
        &[Item {
            address: 0xffff_8000_0000_0000,
            bytes: vec![0],
        }],
    )
    .unwrap();
    read[64..72].copy_from_slice(&0x5000_u64.to_le_bytes());
    let mut fixture = Fixture::new(&read);
    let pml4 = unsafe { ept_pointer(fixture.ept12, 0x5000, 12).read() } & 0x000f_ffff_ffff_f000;
    unsafe {
        (pml4 as *mut u64).add(256).write(0x6007);
    }
    let response = fixture.invoke(&read).unwrap();
    assert_eq!(word(&response, HEADER_BYTES + 16), 0);
    assert_eq!(*response.last().unwrap(), 101);
}

#[test]
fn four_level_ept_never_aliases_high_gpa_bits_to_low_ram() {
    let read = packet(
        READ,
        1,
        (1_u64 << 48) | 0x5000,
        &[Item {
            address: 0,
            bytes: vec![0],
        }],
    )
    .unwrap();
    let mut fixture = Fixture::new(&read);
    let response = fixture.invoke(&read).unwrap();
    assert_eq!(word(&response, HEADER_BYTES + 16), Error::Bounds as u32);
    assert_eq!(word(&response, HEADER_BYTES + 20), 0);
    let read = packet(
        READ,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![0],
        }],
    )
    .unwrap();
    unsafe {
        *ept_pointer(fixture.ept12, 0xb000, 12) |= 1 << 48;
    }
    let response = fixture.invoke(&read).unwrap();
    assert_eq!(word(&response, HEADER_BYTES + 16), Error::Bounds as u32);
    fixture.ept12 |= 1 << 48;
    assert_eq!(fixture.invoke(&read).unwrap_err(), Error::Unsupported);
}

#[test]
fn ept_ignored_software_bits_and_disabled_ad_flags_do_not_reject_valid_ram() {
    let read = packet(
        READ,
        1,
        0x5000,
        &[Item {
            address: 0,
            bytes: vec![0],
        }],
    )
    .unwrap();
    for flag in [
        1_u64 << 7,
        1 << 8,
        1 << 9,
        1 << 11,
        1 << 52,
        1 << 58,
        1 << 63,
    ] {
        let mut fixture = Fixture::new(&read);
        unsafe {
            *ept_pointer(fixture.ept12, 0xb000, 12) |= flag;
            if flag != 1 << 7 {
                for level in [39, 30, 21] {
                    *ept_pointer(fixture.ept12, 0xb000, level) |= flag;
                }
            }
        }
        let before = unsafe { ept_pointer(fixture.ept12, 0xb000, 12).read() };
        let response = fixture.invoke(&read).unwrap();
        assert_eq!(word(&response, HEADER_BYTES + 16), 0, "flag={flag:#x}");
        assert_eq!(*response.last().unwrap(), 101);
        let write = packet(
            WRITE,
            1,
            0x5000,
            &[Item {
                address: 0,
                bytes: vec![42],
            }],
        )
        .unwrap();
        let response = fixture.invoke(&write).unwrap();
        assert_eq!(word(&response, HEADER_BYTES + 16), 0, "flag={flag:#x}");
        assert_eq!(unsafe { (fixture.target as *const u8).read() }, 42);
        assert_eq!(
            unsafe { ept_pointer(fixture.ept12, 0xb000, 12).read() },
            before
        );
    }
}

#[test]
fn kernel_candidates_are_scoped_deduplicated_and_mode_checked() {
    let mut roots = [0; ROOT_HISTORY_COUNT];
    let syscall = 0xffff_f800_1234_0000;
    for observed in [
        [0x2000, 0x5000, syscall, 0],
        [0x2000, 0x5000, syscall, 0],
        [0x3000, 0x6000, syscall, 0],
        [0x2000, 0x7000, syscall + 1, 0],
        [0x2000, 0x8000, syscall, 1 << 12],
        [0x2000, 0x9001, syscall, 0],
        [0, 0x9000, syscall, 0],
    ] {
        nested::admit_kernel_root(observed, 0x201e, syscall, 0, &mut roots);
    }
    assert_eq!(roots[0], 0x5000);
    assert!(roots[1..].iter().all(|root| *root == 0));
    nested::admit_kernel_root([0x2000, 0x6000, syscall, 0], 0x201e, 0x1234, 0, &mut roots);
    assert_eq!(roots[1], 0);
}

struct ObservedMemory<'a> {
    inner: access::resident::Memory<'a>,
    observations: Vec<[u64; 4]>,
}
impl PhysicalMemory for ObservedMemory<'_> {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        self.inner.read(address, bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        self.inner.write(address, bytes)
    }
}
impl nested::HostMemory for ObservedMemory<'_> {
    fn validate(&mut self, address: u64, write: bool) -> Result<(), Error> {
        nested::HostMemory::validate(&mut self.inner, address, write)
    }
    fn synchronize(&mut self, operation: u64) -> bool {
        nested::HostMemory::synchronize(&mut self.inner, operation)
    }
    fn record(&mut self, phase: u64, address: u64, entry: u64, level: u64, status: u64) {
        nested::HostMemory::record(&mut self.inner, phase, address, entry, level, status)
    }
    fn kernel_roots(
        &mut self,
        ept: u64,
        syscall: u64,
        cr4: u64,
        roots: &mut [u64; ROOT_HISTORY_COUNT],
    ) {
        for observed in &self.observations {
            nested::admit_kernel_root(*observed, ept, syscall, cr4, roots);
        }
    }
}

#[test]
fn info_discovers_only_a_live_supervisor_executable_kernel_root() {
    let info = neo::memory::info_packet().unwrap();
    for case in 0..5 {
        let mut fixture = Fixture::new(&info);
        let syscall = 0xffff_8000_0000_0000;
        fixture.environment.syscall = syscall;
        let pml4 = unsafe { ept_pointer(fixture.ept12, 0x5000, 12).read() } & 0x000f_ffff_ffff_f000;
        let pdpt = unsafe { ept_pointer(fixture.ept12, 0x6000, 12).read() } & 0x000f_ffff_ffff_f000;
        let pd = unsafe { ept_pointer(fixture.ept12, 0x7000, 12).read() } & 0x000f_ffff_ffff_f000;
        let pt = unsafe { ept_pointer(fixture.ept12, 0x8000, 12).read() } & 0x000f_ffff_ffff_f000;
        unsafe {
            (pml4 as *mut u64).add(256).write(0x6003);
            (pdpt as *mut u64).write(0x7003);
            (pd as *mut u64).write(0x8003);
            (pt as *mut u64).write(0xb003);
            match case {
                1 => {
                    (pt as *mut u64).write(0);
                }
                2 => {
                    (pt as *mut u64).write(0x8000_0000_0000_b003);
                }
                3 => {
                    (pml4 as *mut u64).add(256).write(0x6007);
                    (pdpt as *mut u64).write(0x7007);
                    (pd as *mut u64).write(0x8007);
                    (pt as *mut u64).write(0xb007);
                }
                4 => {
                    *ept_pointer(fixture.ept12, 0xb000, 12) &= !1;
                }
                _ => {}
            }
        }
        let mut host = ObservedMemory {
            inner: access::resident::Memory {
                environment: &fixture.environment,
            },
            observations: vec![
                [fixture.ept12 + 4096, 0x1000, syscall, 0],
                [fixture.ept12, 0x5000, syscall, 0],
            ],
        };
        let mut scratch = vec![0; info.len()];
        nested::request(
            &mut host,
            &fixture.environment,
            fixture.ept12 | 0x1e,
            0x1000,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(word(&scratch, 40), 0);
        assert_eq!(quad(&scratch, 64), if case == 0 { 0x5000 } else { 0 });
        assert_eq!(quad(&scratch, HEADER_BYTES), quad(&scratch, 64));
        assert_eq!(quad(&scratch, HEADER_BYTES + 8), 0);
        assert_eq!(
            word(&scratch, 72),
            L2_MEMORY_CAPABILITY | L2_KERNEL_ROOT_CAPABILITY
        );
    }
}
