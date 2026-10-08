use crate::memory::access::PhysicalMemory;
use crate::memory::interception::{InterceptionMemory, Session};
use crate::memory::{interception, interception_packet};
use crate::protocol::memory::*;
use std::collections::BTreeMap;

const MASK: u64 = 0x000f_ffff_ffff_f000;
const ROOT: u64 = 0x3000;
const GPA: u64 = 0x80_0000;

struct Machine {
    pages: BTreeMap<u64, Box<[u8; 4096]>>,
    events: Vec<&'static str>,
    available: bool,
    split_available: bool,
    vmfunc_available: bool,
    barrier: bool,
    clock: u64,
    lease_available: bool,
    timing_available: bool,
    syscall_cr4: u64,
    denied_guard: Option<u64>,
    reclamation_allowed: bool,
    reclamation_ready: bool,
    failed_stores: BTreeMap<u64, usize>,
    failed_guards: BTreeMap<u64, usize>,
    failed_links: BTreeMap<u64, usize>,
}

impl Machine {
    fn new() -> Self {
        let mut machine = Self {
            pages: BTreeMap::new(),
            events: Vec::new(),
            available: true,
            split_available: true,
            vmfunc_available: true,
            barrier: true,
            clock: 1000,
            lease_available: true,
            timing_available: true,
            syscall_cr4: 0,
            denied_guard: None,
            reclamation_allowed: true,
            reclamation_ready: true,
            failed_stores: BTreeMap::new(),
            failed_guards: BTreeMap::new(),
            failed_links: BTreeMap::new(),
        };
        for page in [0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, GPA] {
            machine.pages.insert(page, Box::new([0; 4096]));
        }
        machine.store_entry(0x1000, 0x2007).unwrap();
        machine.store_entry(0x2000, 0xb7).unwrap();
        machine.store_entry(ROOT, 0x4007).unwrap();
        machine.store_entry(0x4000, 0x5007).unwrap();
        machine.store_entry(0x5000 + 2 * 8, 0x6007).unwrap();
        machine.store_entry(0x6000, GPA | 7).unwrap();
        machine.pages.get_mut(&GPA).unwrap().fill(0x90);
        machine
    }

    fn leaf(&self, ept: u64, gpa: u64) -> (u64, u32) {
        let mut table = ept & MASK;
        for shift in [39, 30, 21, 12] {
            let entry = self
                .table_entry(table + ((gpa >> shift) & 511) * 8)
                .unwrap();
            if shift == 12 || entry & 128 != 0 {
                return (entry, shift);
            }
            table = entry & MASK;
        }
        panic!("missing EPT leaf");
    }

    fn map_hook_page(&mut self, page_index: u64, gpa: u64) {
        self.store_entry(0x6000 + page_index * 8, gpa | 7).unwrap();
        self.pages
            .entry(gpa)
            .or_insert_with(|| Box::new([0x90; 4096]));
    }
}

impl PhysicalMemory for Machine {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        let page = self.pages.get(&(address & !4095)).ok_or(Error::Unmapped)?;
        let start = address as usize & 4095;
        bytes.copy_from_slice(&page[start..start + bytes.len()]);
        Ok(())
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        let page = self
            .pages
            .get_mut(&(address & !4095))
            .ok_or(Error::Unmapped)?;
        let start = address as usize & 4095;
        page[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

impl InterceptionMemory for Machine {
    fn syscall_context(&self) -> [u64; 3] {
        [0xffff800000400000, ROOT, self.syscall_cr4]
    }
    fn clock(&self) -> u64 {
        self.clock
    }
    fn clock_hz(&self) -> u64 {
        1000
    }
    fn timer_rate(&self) -> u32 {
        5
    }
    fn lease_available(&self) -> bool {
        self.lease_available
    }
    fn timing_available(&self) -> bool {
        self.timing_available
    }
    fn quiesce(&mut self) -> Result<(), Error> {
        self.events.push("quiesce");
        if self.barrier {
            Ok(())
        } else {
            Err(Error::Busy)
        }
    }
    fn flush(&mut self) {
        self.events.push("flush");
    }
    fn resume(&mut self) {
        self.events.push("resume");
    }
    fn base_ept(&self) -> u64 {
        0x105e
    }
    fn table_entry(&self, address: u64) -> Result<u64, Error> {
        let page = self.pages.get(&(address & !4095)).ok_or(Error::Unmapped)?;
        let start = address as usize & 4095;
        Ok(u64::from_le_bytes(
            page[start..start + 8].try_into().unwrap(),
        ))
    }
    fn store_entry(&mut self, address: u64, value: u64) -> Result<(), Error> {
        if value & 128 == 0 {
            if let Some(remaining) = self
                .failed_links
                .get_mut(&address)
                .filter(|remaining| **remaining != 0)
            {
                *remaining -= 1;
                return Err(Error::Permission);
            }
        }
        let failed = self
            .failed_stores
            .get_mut(&address)
            .filter(|remaining| **remaining != 0);
        if let Some(remaining) = failed {
            *remaining -= 1;
            return Err(Error::Permission);
        }
        if value & 2 == 0 {
            if let Some(remaining) = self
                .failed_guards
                .get_mut(&address)
                .filter(|remaining| **remaining != 0)
            {
                *remaining -= 1;
                return Err(Error::Permission);
            }
        }
        if self.denied_guard == Some(address) && value & 2 == 0 {
            return Err(Error::Permission);
        }
        let page = self
            .pages
            .entry(address & !4095)
            .or_insert_with(|| Box::new([0; 4096]));
        let start = address as usize & 4095;
        page[start..start + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn store_page(&mut self, address: u64, bytes: &[u8; 4096]) -> Result<(), Error> {
        self.pages.insert(address, Box::new(*bytes));
        Ok(())
    }
    fn available(&self) -> bool {
        self.available
    }
    fn split_available(&self) -> bool {
        self.split_available
    }
    fn split_reclamation_allowed(&self) -> bool {
        self.reclamation_allowed
    }
    fn split_reclamation_ready(&self, _: u64, _: u64) -> bool {
        self.reclamation_ready
    }
    fn vmfunc_available(&self) -> bool {
        self.vmfunc_available
    }
    fn write_original(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        self.write(address, bytes)
    }
}

fn session() -> Box<Session> {
    let allocation = std::alloc::Layout::new::<Session>();
    let mut session =
        unsafe { Box::from_raw(std::alloc::alloc_zeroed(allocation).cast::<Session>()) };
    session.initialize(0x1000_0000, u64::MAX);
    session
}

fn packet(arguments: &[&str]) -> Vec<u8> {
    interception_packet(
        &arguments
            .iter()
            .map(|argument| argument.to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn execute(session: &mut Session, machine: &mut Machine, packet: &mut [u8]) -> Result<(), Error> {
    unsafe { interception::execute(session, machine, packet, false, 48) }
}

fn cpuid_request() -> Vec<u8> {
    let mut request = vec![0; HEADER_BYTES + CPUID_RECORD_BYTES];
    for (offset, value) in [(0, MEMORY_MAGIC), (16, ROOT), (24, 0x7ffe0ff0),
                          (144, 0xffff_ffff_f000_0040), (152, 0x40)] {
        request[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let length = request.len() as u32;
    for (offset, value) in [(8, MEMORY_VERSION), (12, CPUID_SET), (32, 1), (36, length),
                          (132, 100), (HEADER_BYTES, 1)] {
        request[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, value) in [656981_u32, 0x200800, 33221631, 3219913727].into_iter().enumerate() {
        let offset = HEADER_BYTES + 16 + index * 4;
        request[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    request[HEADER_BYTES + 36..HEADER_BYTES + 40].copy_from_slice(&0xff00_0000_u32.to_le_bytes());
    request
}

fn syscall_request(machine: &mut Machine, token: u64) -> Vec<u8> {
    machine.store_entry(ROOT + 256 * 8, 0x4007).unwrap();
    machine.write(GPA, &[0x0f, 0x01, 0xf8]).unwrap();
    let mut request = cpuid_request();
    request.truncate(HEADER_BYTES);
    for (offset, value) in [(24, 0x400000_u64), (48, 0xffff800000400000), (80, token)] {
        request[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(12, SYSCALL_SET), (32, 0), (36, HEADER_BYTES as u32)] {
        request[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    request
}

#[test]
fn syscall_install_shares_the_owned_token_and_lease_with_cpuid_and_code_hooks() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut code = packet(&["hook", "install", "0x3000", "0x400009", "cc"]);
    execute(&mut session, &mut machine, &mut code).unwrap();
    let mut cpu = cpuid_request();
    cpu[80..88].copy_from_slice(&quad(&code, 80).to_le_bytes());
    execute(&mut session, &mut machine, &mut cpu).unwrap();
    let mut request = syscall_request(&mut machine, quad(&cpu, 80));
    execute(&mut session, &mut machine, &mut request).unwrap();
    let token = quad(&request, 80);
    assert_eq!(token, quad(&cpu, 80) + 1);
    assert_eq!(session.syscall.get_mut().token, token);
    assert_eq!(session.cpuid.get_mut().token, token);
    assert_eq!(word(&request, 104), 1);
    assert_eq!(word(&request, 108), 1);
    assert_eq!(word(&request, 128) & INTERCEPT_SYSCALL, INTERCEPT_SYSCALL);
    assert_eq!(session.lease_deadline.load(core::sync::atomic::Ordering::Acquire), 1100);
    let mut clear = request.clone();
    clear[12..16].copy_from_slice(&SYSCALL_CLEAR.to_le_bytes());
    execute(&mut session, &mut machine, &mut clear).unwrap();
    assert!(session.is_active());
    assert_eq!(session.syscall.get_mut().entry, 0);
    assert_eq!(word(&clear, 108), 0);
    assert_eq!(word(&clear, 104), 1);
    assert_eq!(word(&clear, 24), 1);
    assert_eq!(word(&clear, 128) & INTERCEPT_SYSCALL, 0);
    let mut release = packet(&["hook", "release", &token.to_string()]);
    execute(&mut session, &mut machine, &mut release).unwrap();
    assert!(!session.is_active());
    assert_eq!(session.cpuid.get_mut().count, 0);
}

#[test]
fn syscall_install_rejects_unowned_tokens_and_generic_debug_cannot_replace_it() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut request = syscall_request(&mut machine, 0);
    execute(&mut session, &mut machine, &mut request).unwrap();
    let token = quad(&request, 80);
    let mut stale = syscall_request(&mut machine, token - 1);
    assert_eq!(execute(&mut session, &mut machine, &mut stale), Err(Error::Session));
    let mut generic = packet(&["debug-registers", "set", "0x3000", "0x400000", "0x400100"]);
    assert_eq!(execute(&mut session, &mut machine, &mut generic), Err(Error::Busy));
    assert_eq!(session.syscall.get_mut().token, token);
    assert_eq!(session.syscall.get_mut().callback, 0x400000);
    let mut cpu = cpuid_request();
    cpu[80..88].copy_from_slice(&token.to_le_bytes());
    execute(&mut session, &mut machine, &mut cpu).unwrap();
    assert_eq!(session.syscall.get_mut().token, quad(&cpu, 80));
}

#[test]
fn syscall_validation_refuses_unsupported_entry_cet_la57_and_nonexecutable_callbacks() {
    for rejected in 0..8 {
        let mut machine = Machine::new();
        let mut session = session();
        let mut request = syscall_request(&mut machine, 0);
        let expected = match rejected {
            0 => { machine.syscall_cr4 = 1 << 23; Error::Unsupported }
            1 => { machine.syscall_cr4 = 1 << 12; Error::Unsupported }
            2 => { machine.write(GPA, &[0x90]).unwrap(); Error::Unsupported }
            3 => { machine.store_entry(0x6000, GPA | 3).unwrap(); Error::Permission }
            4 => { machine.store_entry(0x6000, GPA | 7 | (1 << 63)).unwrap(); Error::Permission }
            5 => { request[24..32].copy_from_slice(&0xffff800000400000_u64.to_le_bytes()); Error::Bounds }
            6 => { request[48..56].copy_from_slice(&0xffff800000400001_u64.to_le_bytes()); Error::Bounds }
            _ => { machine.store_entry(0x4000, 0x5003).unwrap(); Error::Permission }
        };
        assert_eq!(execute(&mut session, &mut machine, &mut request), Err(expected), "case={rejected}");
        assert!(!session.is_active());
        assert_eq!(session.configuration.get_mut().debug_count, 0);
        assert_eq!(session.syscall.get_mut().entry, 0);
        assert_eq!(machine.events.last(), Some(&"resume"));
    }
}

#[test]
fn syscall_clear_without_other_profiles_disables_the_session_and_expiry_restores_native_data() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut request = syscall_request(&mut machine, 0);
    execute(&mut session, &mut machine, &mut request).unwrap();
    let mut clear = request.clone();
    clear[12..16].copy_from_slice(&SYSCALL_CLEAR.to_le_bytes());
    execute(&mut session, &mut machine, &mut clear).unwrap();
    assert!(!session.is_active());
    let mut request = syscall_request(&mut machine, 0);
    execute(&mut session, &mut machine, &mut request).unwrap();
    machine.clock += 101;
    let mut status = packet(&["hook", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 112), INTERCEPT_REVOKED);
    assert_eq!(word(&status, 116), INTERCEPT_CAUSE_LEASE);
    assert_eq!(word(&status, 128) & INTERCEPT_SYSCALL, 0);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
}

#[test]
fn private_shared_data_traps_scoped_accesses_and_preserves_native_storage() {
    let mut machine = Machine::new();
    machine
        .store_entry(0x4000 + ((0x7ffe0000_u64 >> 30) & 511) * 8, 0x5007)
        .unwrap();
    machine
        .store_entry(0x5000 + ((0x7ffe0000_u64 >> 21) & 511) * 8, 0x7007)
        .unwrap();
    machine
        .store_entry(0x7000 + ((0x7ffe0000_u64 >> 12) & 511) * 8, GPA | 5)
        .unwrap();
    let mut session = session();
    let mut request = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x7ffe0000",
        &"33".repeat(4096),
    ]);
    request[128..132].copy_from_slice(&INTERCEPT_PRIVATE_SHARED_DATA.to_le_bytes());
    let original = machine.pages[&GPA].clone();
    let native_leaf = machine.leaf(machine.base_ept(), GPA);
    execute(&mut session, &mut machine, &mut request).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let shadow = machine.leaf(configuration.ept, GPA).0;
    assert_eq!(shadow & 7, 0);
    assert_ne!(shadow & MASK, GPA);
    assert_eq!(
        machine.leaf(configuration.data_ept, GPA).0 & (MASK | 7),
        GPA
    );
    for cpu_index in 0..64 {
        if configuration.cpu_mask & (1 << cpu_index) != 0 {
            assert_ne!(configuration.cpu_data[cpu_index], 0);
            assert_eq!(
                machine.leaf(configuration.cpu_data[cpu_index], GPA).0 & (MASK | 7),
                GPA
            );
        }
    }
    assert_eq!(machine.leaf(machine.base_ept(), GPA), native_leaf);
    assert_eq!(machine.pages[&GPA], original);
    assert_eq!(machine.pages[&(shadow & MASK)].as_ref(), &[0x33; 4096]);
    let mut cpu = cpuid_request();
    cpu[80..88].copy_from_slice(&configuration.token.to_le_bytes());
    execute(&mut session, &mut machine, &mut cpu).unwrap();
    assert_eq!(word(&cpu, 24), 1);
    assert_eq!(word(&cpu, 104), 1);
    assert_eq!(word(&cpu, 128), INTERCEPT_PRIVATE_SHARED_DATA);
    let token = quad(&cpu, 80);
    machine.map_hook_page(1, GPA + 4096);
    let shadow_page = shadow & MASK;
    machine.pages.get_mut(&shadow_page).unwrap()[0x900] = 0x42;
    let mut added = packet(&["hook", "add", &token.to_string(), "0x401008", "cc"]);
    execute(&mut session, &mut machine, &mut added).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(configuration.hook_count, 2);
    let shared_leaf = machine.leaf(configuration.ept, GPA).0;
    assert_eq!(shared_leaf & 7, 0);
    assert_eq!(
        machine.leaf(configuration.data_ept, GPA).0 & (MASK | 7),
        GPA
    );
    assert_eq!(machine.pages[&(shared_leaf & MASK)][0x900], 0x42);
    let code_leaf = machine.leaf(configuration.ept, GPA + 4096).0;
    assert_eq!(code_leaf & 7, 4);
    assert_eq!(machine.pages[&(code_leaf & MASK)][8], 0xcc);
    assert_eq!(machine.leaf(machine.base_ept(), GPA + 4096).0 & 7, 5);
    let code_id = quad(&added, HEADER_BYTES + 16);
    let mut rejected = packet(&["hook", "add", &token.to_string(), "0x401009", "cc"]);
    let spare_root = configuration.pool_base
        + ((configuration.bank ^ 1) * intercept_bank_pages(configuration.cpu_mask)) as u64 * 4096;
    machine.failed_stores.insert(spare_root, 1);
    assert_eq!(
        execute(&mut session, &mut machine, &mut rejected),
        Err(Error::Permission)
    );
    assert!(
        session.is_active(),
        "cause={}, state={}",
        session.cause.load(core::sync::atomic::Ordering::Acquire),
        session.active.load(core::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        machine.leaf(machine.base_ept(), GPA).0 & (MASK | 7),
        GPA | 7
    );
    let mut dropped = packet(&["hook", "remove", &token.to_string(), &code_id.to_string()]);
    execute(&mut session, &mut machine, &mut dropped).unwrap();
    assert_eq!(word(&dropped, 104), 1);
    assert_eq!(machine.leaf(machine.base_ept(), GPA + 4096).0 & 7, 7);
    let configuration = unsafe { &*session.configuration.get() };
    let shared_leaf = machine.leaf(configuration.ept, GPA).0;
    assert_eq!(machine.pages[&(shared_leaf & MASK)][0x900], 0x42);
    let mut release = packet(&["hook", "release", &token.to_string()]);
    execute(&mut session, &mut machine, &mut release).unwrap();
    assert!(!session.is_active());
    assert_eq!(machine.leaf(machine.base_ept(), GPA), native_leaf);
    assert_eq!(machine.pages[&GPA], original);
}

#[test]
fn private_shared_data_routes_only_user_reads_to_the_identity_page() {
    use crate::memory::interception::shared_data_target;
    let shadow = GPA + 4096;
    assert_eq!(
        shared_data_target(GPA, shadow, 0x7ffe03d8, 3, 1),
        Ok(shadow)
    );
    for linear in [0xfffff780000003d8, 0xfffff78000000718, 0x7ffe03d8] {
        for access in [1, 2, 3] {
            assert_eq!(shared_data_target(GPA, shadow, linear, 0, access), Ok(GPA));
        }
    }
    assert_eq!(
        shared_data_target(GPA, shadow, 0x7ffe03d8, 3, 2),
        Err(Error::Permission)
    );
    assert_eq!(
        shared_data_target(GPA, shadow, 0xfffff780000003d8, 3, 1),
        Err(Error::Permission)
    );
    assert_eq!(
        shared_data_target(GPA, shadow, 0x7ffe03d8, 1, 1),
        Err(Error::Permission)
    );
}

#[test]
fn private_shared_data_rejects_partial_pages_other_addresses_and_vmfunc() {
    for (address, length, flags) in [
        ("0x400000", 4096, INTERCEPT_PRIVATE_SHARED_DATA),
        ("0x7ffe0000", 4095, INTERCEPT_PRIVATE_SHARED_DATA),
        ("0x7ffe0000", 4096, INTERCEPT_PRIVATE_SHARED_DATA | INTERCEPT_VMFUNC),
        ("0x7ffe0000", 4096, INTERCEPT_PRIVATE_SHARED_DATA | INTERCEPT_NO_LEASE),
    ] {
        let mut machine = Machine::new();
        machine.store_entry(0x4000 + ((0x7ffe0000_u64 >> 30) & 511) * 8, 0x5007).unwrap();
        machine.store_entry(0x5000 + ((0x7ffe0000_u64 >> 21) & 511) * 8, 0x7007).unwrap();
        machine.store_entry(0x7000 + ((0x7ffe0000_u64 >> 12) & 511) * 8, GPA | 5).unwrap();
        let mut session = session();
        let native_leaf = machine.leaf(machine.base_ept(), GPA);
        let mut request = packet(&["hook", "install", "0x3000", address, &"33".repeat(length)]);
        request[128..132].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(execute(&mut session, &mut machine, &mut request), Err(Error::Format));
        assert!(!session.is_active());
        assert_eq!(machine.leaf(machine.base_ept(), GPA), native_leaf);
    }
}

#[test]
fn cpuid_identity_is_scoped_gated_and_preserves_the_native_apic_id() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut request = cpuid_request();
    execute(&mut session, &mut machine, &mut request).unwrap();
    assert_eq!(word(&request, 24), 1);
    assert_eq!(word(&request, 112), INTERCEPT_ACTIVE);
    let configuration = unsafe { &*session.configuration.get() };
    let profile = unsafe { &*session.cpuid.get() };
    let evaluate = |cr3, cpl, debug, selector| interception::cpuid_values(
        configuration, profile, cr3, cpl, debug, selector, [7, 0xab12_3456, 9, 11],
    );
    assert_eq!(evaluate(ROOT | 7, 3, [0x7ffe0ff0, 0x440], [1, 999]),
               Some([656981, 0xab20_0800, 33221631, 3219913727]));
    for (cr3, cpl, debug, selector) in [
        (ROOT + 4096, 3, [0x7ffe0ff0, 0x440], [1, 0]),
        (ROOT, 0, [0x7ffe0ff0, 0x440], [1, 0]),
        (ROOT, 3, [0x7ffe0ff1, 0x440], [1, 0]),
        (ROOT, 3, [0x7ffe0ff0, 0x400], [1, 0]),
        (ROOT, 3, [0x7ffe0ff0, 0x1000_0440], [1, 0]),
        (ROOT, 3, [0x7ffe0ff0, 0x440], [2, 0]),
    ] {
        assert_eq!(evaluate(cr3, cpl, debug, selector), None);
    }
}

#[test]
fn invalid_cpuid_records_cannot_replace_an_active_profile_or_hide_the_transport() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = cpuid_request();
    execute(&mut session, &mut machine, &mut install).unwrap();
    for forbidden in [0_u32, 0x8000_0000, MEMORY_LEAF, crate::protocol::MATRIXHV_STATUS_LEAF] {
        let mut invalid = cpuid_request();
        invalid[80..88].copy_from_slice(&1_u64.to_le_bytes());
        invalid[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&forbidden.to_le_bytes());
        assert_eq!(execute(&mut session, &mut machine, &mut invalid), Err(Error::Format));
        assert_eq!(unsafe { &*session.cpuid.get() }.records[0].leaf, 1);
        assert_eq!(unsafe { &*session.configuration.get() }.token, 1);
    }
    let mut stale = cpuid_request();
    assert_eq!(execute(&mut session, &mut machine, &mut stale), Err(Error::Session));
    let mut overlap = cpuid_request();
    overlap.extend_from_within(HEADER_BYTES..);
    let length = overlap.len() as u32;
    overlap[32..36].copy_from_slice(&2_u32.to_le_bytes());
    overlap[36..40].copy_from_slice(&length.to_le_bytes());
    overlap[80..88].copy_from_slice(&1_u64.to_le_bytes());
    assert_eq!(execute(&mut session, &mut machine, &mut overlap), Err(Error::Format));
    assert!(session.is_active());
}

#[test]
fn removing_hooks_preserves_cpuid_until_release_and_expired_profiles_cannot_reactivate() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = cpuid_request();
    execute(&mut session, &mut machine, &mut install).unwrap();
    let mut hooks = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut hooks).unwrap();
    assert_eq!(unsafe { &*session.cpuid.get() }.token, 2);
    let mut remove = packet(&["hook", "remove", "2"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert!(session.is_active());
    let mut clear = vec![0; HEADER_BYTES];
    clear[..8].copy_from_slice(&MEMORY_MAGIC.to_le_bytes());
    for (offset, value) in [(8, MEMORY_VERSION), (12, CPUID_CLEAR), (36, HEADER_BYTES as u32)] {
        clear[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    clear[80..88].copy_from_slice(&2_u64.to_le_bytes());
    execute(&mut session, &mut machine, &mut clear).unwrap();
    assert!(!session.is_active());
    assert_eq!(word(&clear, 24), 0);
    let mut reinstall = cpuid_request();
    execute(&mut session, &mut machine, &mut reinstall).unwrap();
    machine.clock += 101;
    let mut status = packet(&["hook", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert!(!session.is_active());
    assert_eq!(word(&status, 116), INTERCEPT_CAUSE_LEASE);
    let mut renew = packet(&["hook", "renew", "3"]);
    assert_eq!(execute(&mut session, &mut machine, &mut renew), Err(Error::Session));
}

#[test]
fn scoped_hook_splits_private_tables_and_preserves_original_code_and_neighbors() {
    let mut machine = Machine::new();
    let mut session = session();
    let original_tables = [
        machine.pages[&0x1000].clone(),
        machine.pages[&0x2000].clone(),
    ];
    let mut request = packet(&["hook", "install", "0x3005", "0x400008", "cc90"]);
    execute(&mut session, &mut machine, &mut request).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let (leaf, shift) = machine.leaf(configuration.ept, GPA);
    assert_eq!(configuration.roots, [ROOT, 0]);
    assert_eq!(configuration.ept & !MASK, machine.base_ept() & !MASK);
    assert_eq!(shift, 12);
    assert_eq!(leaf & 7, 4);
    assert_eq!(&machine.pages[&(leaf & MASK)][8..10], &[0xcc, 0x90]);
    assert_eq!(&machine.pages[&GPA][8..10], &[0x90, 0x90]);
    let (neighbor, _) = machine.leaf(configuration.ept, GPA + 4096);
    assert_eq!(neighbor & MASK, GPA + 4096);
    assert_eq!(neighbor & 7, 7);
    assert_eq!(machine.pages[&0x1000], original_tables[0]);
    assert_ne!(machine.pages[&0x2000], original_tables[1]);
    let (data_leaf, data_shift) = machine.leaf(configuration.data_ept, GPA);
    assert_eq!((data_leaf & MASK, data_leaf & 7, data_shift), (GPA, 1, 12));
    let (base_leaf, _) = machine.leaf(machine.base_ept(), GPA);
    assert_eq!((base_leaf & MASK, base_leaf & 7), (GPA, 5));
    assert_eq!(machine.events, ["quiesce", "flush", "resume"]);
    assert_eq!(word(&request, 104), 1);
    assert_eq!(word(&request, 112), INTERCEPT_ACTIVE);
}

#[test]
fn hooks_and_debug_redirects_share_scope_but_remove_independently_with_tokens() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut hook = packet(&["hook", "install", "0x3000", "0x400000", "cc"]);
    execute(&mut session, &mut machine, &mut hook).unwrap();
    let mut debug = packet(&["debug-registers", "set", "0x3001", "0x400000", "0x400100"]);
    execute(&mut session, &mut machine, &mut debug).unwrap();
    assert_eq!(word(&debug, 104), 1);
    assert_eq!(word(&debug, 108), 1);
    assert_eq!(quad(&debug, 80), 2);
    let mut stale = packet(&["hook", "remove", "1"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut stale),
        Err(Error::Session)
    );
    let mut remove = packet(&["hook", "remove", "2"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert!(session.is_active());
    assert_eq!(word(&remove, 104), 0);
    assert_eq!(word(&remove, 108), 1);
    let mut clear = packet(&["debug-registers", "clear", "2"]);
    execute(&mut session, &mut machine, &mut clear).unwrap();
    assert_eq!(word(&clear, 112), INTERCEPT_DISABLED);
    assert!(!session.is_active());
}

#[test]
fn rejected_debug_update_keeps_the_published_configuration_and_releases_barrier() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut first = packet(&["debug-registers", "set", "0x3000", "0x400000", "0x400100"]);
    execute(&mut session, &mut machine, &mut first).unwrap();
    for arguments in [
        vec!["debug-registers", "set", "0x4000", "0x400000", "0x400200"],
        vec![
            "debug-registers",
            "set",
            "0x3000",
            "0x800000000000",
            "0x400200",
        ],
        vec!["debug-registers", "set", "0x3000", "0x400000", "0x400000"],
        vec![
            "debug-registers",
            "set",
            "0x3000",
            "0x400000",
            "0x400100",
            "0x400000",
            "0x400200",
        ],
    ] {
        assert!(execute(&mut session, &mut machine, &mut packet(&arguments)).is_err());
        let configuration = unsafe { &*session.configuration.get() };
        assert_eq!(configuration.token, 1);
        assert_eq!(configuration.debug_count, 1);
        assert_eq!(configuration.debug[0].redirect, 0x400100);
        assert_eq!(machine.events.last(), Some(&"resume"));
    }
}

#[test]
fn invalid_hook_leaves_never_publish_an_alternate_ept() {
    for bad_entry in [0x87, 0x4000_00b7, 0xb1] {
        let mut machine = Machine::new();
        machine.store_entry(0x2000, bad_entry).unwrap();
        let mut session = session();
        let mut request = packet(&["hook", "install", "0x3000", "0x400000", "cc"]);
        assert_eq!(
            execute(&mut session, &mut machine, &mut request),
            Err(Error::Permission)
        );
        assert!(!session.is_active());
        assert_eq!(unsafe { &*session.configuration.get() }.hook_count, 0);
        assert_eq!(machine.events.last(), Some(&"resume"));
    }
}

#[test]
fn unavailable_or_failed_barrier_keeps_configuration_unpublished_and_status_readable() {
    let mut machine = Machine::new();
    let mut session = session();
    machine.barrier = false;
    let mut request = packet(&["debug-registers", "set", "0x3000", "0x400000", "0x400100"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut request),
        Err(Error::Busy)
    );
    assert_eq!(machine.events, ["quiesce"]);
    machine.barrier = true;
    machine.available = false;
    assert_eq!(
        execute(&mut session, &mut machine, &mut request),
        Err(Error::Unsupported)
    );
    assert_eq!(machine.events.last(), Some(&"resume"));
    let mut status = packet(&["hook", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 112), INTERCEPT_DISABLED);
}

#[test]
fn alternate_root_must_map_the_same_page_and_malformed_cli_never_invokes_transport() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut alias = packet(&[
        "hook",
        "install",
        "0x3001",
        "0x400000",
        "cc",
        "--alternate-cr3",
        "0x3002",
    ]);
    execute(&mut session, &mut machine, &mut alias).unwrap();
    assert_eq!(quad(&alias, 64), ROOT);
    for arguments in [
        vec!["hook", "install", "0x3000", "0x400fff", "cccc"],
        vec!["hook", "status", "extra"],
        vec!["hook", "remove"],
        vec!["debug-registers", "set", "0x3000"],
        vec![
            "debug-registers",
            "set",
            "0x3000",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "10",
        ],
        vec![
            "debug-registers",
            "set",
            "0x3000",
            "--alternate-cr3",
            "0x4000",
            "1",
            "2",
        ],
    ] {
        assert!(
            interception_packet(
                &arguments
                    .iter()
                    .map(|argument| argument.to_string())
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
    }
}

#[test]
fn revoked_session_requires_a_new_installation_and_advances_its_token() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut request = packet(&["debug-registers", "set", "0x3000", "0x400000", "0x400100"]);
    execute(&mut session, &mut machine, &mut request).unwrap();
    session.active.store(
        u64::from(INTERCEPT_REVOKED),
        std::sync::atomic::Ordering::Release,
    );
    let mut status = packet(&["debug-registers", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 112), INTERCEPT_REVOKED);
    execute(&mut session, &mut machine, &mut request).unwrap();
    assert_eq!(quad(&request, 80), 2);
}

#[test]
fn multiple_function_patches_share_one_shadow_page_without_losing_prior_bytes() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut request = packet(&[
        "hook", "install", "0x3000", "0x400008", "cc", "0x400100", "c3",
    ]);
    execute(&mut session, &mut machine, &mut request).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(configuration.hook_count, 1);
    let (leaf, _) = machine.leaf(configuration.ept, GPA);
    let shadow = &machine.pages[&(leaf & MASK)];
    assert_eq!(shadow[8], 0xcc);
    assert_eq!(shadow[0x100], 0xc3);
    assert_eq!(machine.pages[&GPA][8], 0x90);
    assert_eq!(machine.pages[&GPA][0x100], 0x90);
}

#[test]
fn split_hardware_is_required_for_hooks_but_not_for_debug_registers() {
    let mut machine = Machine::new();
    let mut session = session();
    machine.split_available = false;
    let mut hook = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut hook),
        Err(Error::Unsupported)
    );
    let mut debug = packet(&["debug-registers", "set", "0x3000", "0x400000", "0x400100"]);
    execute(&mut session, &mut machine, &mut debug).unwrap();
    assert_eq!(word(&debug, 108), 1);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
}

#[test]
fn conflicting_root_writes_preserve_original_data_and_revoke_the_profile() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut hook = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut hook).unwrap();
    assert_eq!(
        unsafe {
            interception::write_original(&mut *session, &mut machine, GPA + 8, &[0xc3, 0x42])
        },
        Err(Error::MergeConflict)
    );
    let configuration = unsafe { &*session.configuration.get() };
    let shadow = machine.leaf(configuration.ept, GPA).0 & MASK;
    assert_eq!(&machine.pages[&GPA][8..10], &[0xc3, 0x42]);
    assert_eq!(&machine.pages[&shadow][8..10], &[0xcc, 0x90]);
    assert!(!session.is_active());
    assert_eq!(
        session.cause.load(std::sync::atomic::Ordering::Acquire),
        u64::from(INTERCEPT_CAUSE_MERGE)
    );
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
    assert_eq!(&machine.events[3..], &["quiesce", "flush", "resume"]);
}

#[test]
fn removal_coalesces_owned_splits_and_reuses_them_after_a_grace_period() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut hook = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut hook).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let used = configuration.base_pool_used;
    let pointer = configuration.base_leaves[0];
    machine
        .store_entry(pointer, machine.table_entry(pointer).unwrap() | 0x300)
        .unwrap();
    let mut remove = packet(&["hook", "remove", "1"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA), (0x3b7, 30));
    assert_eq!(
        unsafe { &*session.configuration.get() }.base_pool_used,
        used
    );
    execute(&mut session, &mut machine, &mut hook).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(configuration.base_pool_used, used);
    assert_eq!(configuration.base_leaves[0], pointer);
    assert_eq!(quad(&hook, 80), 2);
}

#[test]
fn installing_and_removing_across_more_regions_than_the_pool_recycles_capacity() {
    let mut machine = Machine::new();
    let mut session = session();
    session.initialize(0x1000_0000, 1);
    for index in 0..INTERCEPT_BASE_TABLE_PAGES + 16 {
        let gpa = GPA + index as u64 * 0x20_0000;
        machine.map_hook_page(0, gpa);
        let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
        execute(&mut session, &mut machine, &mut install).unwrap();
        assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
        assert_eq!(machine.leaf(machine.base_ept(), gpa).0 & 7, 5);
        let token = quad(&install, 80).to_string();
        let mut remove = packet(&["hook", "remove", &token]);
        execute(&mut session, &mut machine, &mut remove).unwrap();
        assert_eq!(machine.leaf(machine.base_ept(), gpa), (0xb7, 30));
    }
}

#[test]
fn missing_flush_acknowledgements_quarantine_slots_until_capacity_recovers() {
    let mut machine = Machine::new();
    let mut session = session();
    session.initialize(0x1000_0000, 1);
    machine.reclamation_ready = false;
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let mut remove = packet(&["hook", "remove", "1"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(configuration.base_pool_used, 2);
    let base = configuration.pool_base + (2 * intercept_bank_pages(1)) as u64 * 4096;
    let retired = machine.pages[&base].clone();
    machine.map_hook_page(0, GPA + 0x20_0000);
    assert_eq!(
        execute(&mut session, &mut machine, &mut install),
        Err(Error::Busy)
    );
    assert_eq!(machine.pages[&base], retired);
    assert!(!session.is_active());
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 30);
    machine.barrier = false;
    assert_eq!(
        execute(&mut session, &mut machine, &mut install),
        Err(Error::Busy)
    );
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
    machine.barrier = true;
    machine.reclamation_ready = true;
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
    assert!(session.is_active());
}

#[test]
fn dropping_patches_coalesces_only_unused_regions_and_preserves_original_write_detection() {
    let mut machine = Machine::new();
    machine.map_hook_page(1, GPA + 0x20_0000);
    let mut session = session();
    session.initialize(0x1000_0000, 1 | (1 << 3));
    let mut install = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "0x400010",
        "c3",
        "0x401008",
        "cd",
        "--vmfunc",
        "--concurrent-writes",
        "--persistent-data",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let mut drop = packet(&["hook", "remove", "1", "1"]);
    execute(&mut session, &mut machine, &mut drop).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 12);
    assert_eq!(
        session
            .split_epoch
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    let mut drop = packet(&["hook", "remove", "1", "2"]);
    execute(&mut session, &mut machine, &mut drop).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(configuration.hook_count, 1);
    assert_eq!(configuration.base_pool_used, 3);
    assert_eq!(configuration.vmfunc, 1);
    assert_eq!(machine.leaf(machine.base_ept(), GPA), (GPA | 0xb7, 21));
    assert_eq!(machine.leaf(configuration.ept, GPA).1, 21);
    for cpu_index in [0, 3] {
        assert_eq!(machine.leaf(configuration.cpu_data[cpu_index], GPA).1, 21);
    }
    assert_eq!(machine.leaf(machine.base_ept(), GPA + 0x20_0000).0 & 7, 5);
    let shadow = machine.leaf(configuration.ept, GPA + 0x20_0000).0 & MASK;
    machine.events.clear();
    unsafe {
        interception::write_original(&mut *session, &mut machine, GPA + 0x20_0000 + 9, &[0x42])
    }
    .unwrap();
    assert!(machine.events.is_empty());
    assert_eq!(&machine.pages[&shadow][8..10], &[0xcd, 0x42]);
    let mut renew = packet(&["hook", "renew", "1"]);
    execute(&mut session, &mut machine, &mut renew).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
    assert_eq!(machine.leaf(machine.base_ept(), GPA + 0x20_0000).0 & 7, 5);
}

#[test]
fn nonuniform_children_and_preexisting_tables_are_never_reclaimed_as_owned_splits() {
    let mut machine = Machine::new();
    machine.store_entry(0x2000, 0x9007).unwrap();
    for index in 0..512 {
        machine
            .store_entry(0x9000 + index * 8, index * 0x20_0000 | 0xb7)
            .unwrap();
    }
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 1);
    let pointer = unsafe { &*session.configuration.get() }.base_leaves[0];
    machine
        .store_entry(pointer + 8, (GPA + 4096) | 0x35)
        .unwrap();
    let mut remove = packet(&["hook", "remove", "1"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 12);
    assert_eq!(machine.leaf(machine.base_ept(), GPA + 4096).0 & 7, 5);
    assert_eq!(
        session
            .split_epoch
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    machine
        .store_entry(pointer + 8, (GPA + 4096) | 0x37)
        .unwrap();
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA), (GPA | 0xb7, 21));
    assert_eq!(machine.table_entry(0x2000).unwrap(), 0x9007);
}

#[test]
fn active_access_dirty_tracking_defers_split_retirement_until_its_leaf_users_stop() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    machine.reclamation_allowed = false;
    let mut remove = packet(&["hook", "remove", "1"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 12);
    assert_eq!(
        session
            .split_epoch
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    machine.reclamation_allowed = true;
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 30);
}

#[test]
fn a_failed_parent_restore_rolls_back_the_detached_child_and_keeps_the_old_patch_set() {
    let mut machine = Machine::new();
    let second_gpa = GPA + (1 << 30);
    machine.store_entry(0x2008, (1 << 30) | 0xb7).unwrap();
    machine.map_hook_page(1, second_gpa);
    let mut session = session();
    let mut install = packet(&[
        "hook", "install", "0x3000", "0x400008", "cc", "0x401008", "c3",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let published = (
        configuration.ept,
        configuration.data_ept,
        configuration.generation,
    );
    let pointer = configuration.base_leaves[0];
    machine.failed_stores.insert(0x2000, 1);
    let mut drop = packet(&["hook", "remove", "1", "1"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut drop),
        Err(Error::Permission)
    );
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(
        (
            configuration.ept,
            configuration.data_ept,
            configuration.generation
        ),
        published
    );
    assert_eq!(configuration.base_leaves[0], pointer);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 5);
    assert_eq!(machine.leaf(machine.base_ept(), second_gpa).0 & 7, 5);
    assert!(session.is_active());
    let mut list = packet(&["hook", "list", "1"]);
    execute(&mut session, &mut machine, &mut list).unwrap();
    assert_eq!(word(&list, 32), 2);
    execute(&mut session, &mut machine, &mut drop).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 30);
    assert_eq!(machine.leaf(machine.base_ept(), second_gpa).0 & 7, 5);
}

#[test]
fn a_failed_private_build_reattaches_retired_tables_before_restoring_old_guards() {
    let mut machine = Machine::new();
    machine.map_hook_page(1, GPA + 0x20_0000);
    let mut session = session();
    let mut install = packet(&[
        "hook", "install", "0x3000", "0x400008", "cc", "0x401008", "c3",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let published = (
        configuration.ept,
        configuration.data_ept,
        configuration.generation,
    );
    machine
        .failed_guards
        .insert(configuration.base_leaves[1], 1);
    let mut drop = packet(&["hook", "remove", "1", "1"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut drop),
        Err(Error::Permission)
    );
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(
        (
            configuration.ept,
            configuration.data_ept,
            configuration.generation
        ),
        published
    );
    assert_eq!(configuration.base_pool_used, 3);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 5);
    assert_eq!(machine.leaf(machine.base_ept(), GPA + 0x20_0000).0 & 7, 5);
    assert!(session.is_active());
    execute(&mut session, &mut machine, &mut drop).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 21);
    let mut remove = packet(&["hook", "remove", "1"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 30);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 3);
}

#[test]
fn a_failed_removal_keeps_allocated_tables_until_a_later_release_can_retire_them() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let base_leaf = unsafe { &*session.configuration.get() }.base_leaves[0];
    let pd = machine.table_entry(0x2000).unwrap() & MASK;
    machine
        .failed_stores
        .insert(pd + ((GPA >> 21) & 511) * 8, 1);
    let mut remove = packet(&["hook", "remove", "1"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut remove),
        Err(Error::Permission)
    );
    assert!(!session.is_active());
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 12);
    assert_eq!(machine.table_entry(base_leaf).unwrap() & 7, 7);
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
    assert_eq!(
        session
            .split_epoch
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 30);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
}

#[test]
fn failed_reattachment_quarantines_revoked_leaf_references_until_reinstallation() {
    let mut machine = Machine::new();
    machine.map_hook_page(1, GPA + 0x20_0000);
    let mut session = session();
    let mut install = packet(&[
        "hook", "install", "0x3000", "0x400008", "cc", "0x401008", "c3",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let pointer = configuration.base_leaves[0];
    let pd = machine.table_entry(0x2000).unwrap() & MASK;
    machine.failed_links.insert(pd + ((GPA >> 21) & 511) * 8, 1);
    machine
        .failed_guards
        .insert(configuration.base_leaves[1], 1);
    let mut drop = packet(&["hook", "remove", "1", "1"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut drop),
        Err(Error::Permission)
    );
    assert!(!session.is_active());
    assert_eq!(machine.leaf(machine.base_ept(), GPA).1, 21);
    let revoked_table = machine.pages[&(pointer & !4095)].clone();
    let mut clear = packet(&["debug-registers", "clear", "1"]);
    execute(&mut session, &mut machine, &mut clear).unwrap();
    assert_eq!(machine.pages[&(pointer & !4095)], revoked_table);
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 3);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert!(session.is_active());
    let mut renew = packet(&["hook", "renew", "2"]);
    execute(&mut session, &mut machine, &mut renew).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 3);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 5);
    assert_eq!(machine.leaf(machine.base_ept(), GPA + 0x20_0000).0 & 7, 5);
}

#[test]
fn pool_exhaustion_preserves_active_patches_and_release_recovers_all_reclaimable_slots() {
    let mut machine = Machine::new();
    let mut session = session();
    session.initialize(0x1000_0000, 1);
    machine.reclamation_allowed = false;
    for index in 0..INTERCEPT_BASE_TABLE_PAGES - 1 {
        machine.map_hook_page(0, GPA + index as u64 * 0x20_0000);
        let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
        execute(&mut session, &mut machine, &mut install).unwrap();
        if index != INTERCEPT_BASE_TABLE_PAGES - 2 {
            let token = quad(&install, 80).to_string();
            let mut remove = packet(&["hook", "remove", &token]);
            execute(&mut session, &mut machine, &mut remove).unwrap();
        }
    }
    let configuration = unsafe { &*session.configuration.get() };
    let published = (
        configuration.ept,
        configuration.data_ept,
        configuration.generation,
    );
    let token = configuration.token.to_string();
    let active_gpa = configuration.pages[0];
    let shadow = machine.leaf(configuration.ept, active_gpa).0 & MASK;
    let before = machine.pages[&shadow].clone();
    assert_eq!(configuration.base_pool_used, INTERCEPT_BASE_TABLE_PAGES);
    machine.map_hook_page(1, GPA + (INTERCEPT_BASE_TABLE_PAGES - 1) as u64 * 0x20_0000);
    let mut add = packet(&["hook", "add", &token, "0x401008", "c3"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut add),
        Err(Error::Capacity)
    );
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(
        (
            configuration.ept,
            configuration.data_ept,
            configuration.generation
        ),
        published
    );
    assert_eq!(machine.pages[&shadow], before);
    assert_eq!(machine.leaf(machine.base_ept(), active_gpa).0 & 7, 5);
    assert!(session.is_active());
    machine.reclamation_allowed = true;
    let mut release = packet(&["hook", "release", &token]);
    execute(&mut session, &mut machine, &mut release).unwrap();
    assert_eq!(machine.leaf(machine.base_ept(), active_gpa).1, 30);
    let mut install = packet(&["hook", "install", "0x3000", "0x401008", "c3"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
}

#[test]
fn an_owned_split_with_a_parent_entry_at_physical_zero_has_an_independent_pool_slot() {
    let mut machine = Machine::new();
    machine.store_entry(0, 0xb7).unwrap();
    machine.store_entry(0x1000, 7).unwrap();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 5);
    let mut remove = packet(&["hook", "remove", "1"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(machine.table_entry(0).unwrap(), 0xb7);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
}

#[test]
fn repeated_unpublished_installation_failures_recover_their_base_tables() {
    let mut machine = Machine::new();
    let mut session = session();
    session.initialize(0x1000_0000, 1);
    for index in 0..INTERCEPT_BASE_TABLE_PAGES + 16 {
        machine.map_hook_page(0, GPA + index as u64 * 0x20_0000);
        let mut install = packet(&[
            "hook", "install", "0x3000", "0x400008", "cc", "0x400010", "c3",
        ]);
        let descriptor = HEADER_BYTES + ITEM_BYTES;
        install[descriptor..descriptor + 8].copy_from_slice(&0x500000u64.to_le_bytes());
        assert_eq!(
            execute(&mut session, &mut machine, &mut install),
            Err(Error::Unmapped)
        );
        assert!(!session.is_active());
        assert!(unsafe { &*session.configuration.get() }.base_pool_used <= 4);
    }
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let mut renew = packet(&["hook", "renew", "1"]);
    execute(&mut session, &mut machine, &mut renew).unwrap();
    assert_eq!(unsafe { &*session.configuration.get() }.base_pool_used, 2);
}

#[test]
fn a_bad_later_descriptor_never_publishes_partial_base_write_guards() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut hook = packet(&[
        "hook", "install", "0x3000", "0x400008", "cc", "0x400010", "c3",
    ]);
    let descriptor = HEADER_BYTES + ITEM_BYTES;
    hook[descriptor..descriptor + 8].copy_from_slice(&0x500000u64.to_le_bytes());
    assert_eq!(
        execute(&mut session, &mut machine, &mut hook),
        Err(Error::Unmapped)
    );
    assert!(!session.is_active());
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
    let mut valid = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut valid).unwrap();
    assert_eq!(quad(&valid, 80), 1);
}

#[test]
fn cooperative_vmfunc_list_admits_only_execute_and_read_only_original_data_roots() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut hook = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "--alternate-cr3",
        "0x3007",
        "--vmfunc",
    ]);
    assert_eq!(word(&hook, 128), INTERCEPT_VMFUNC);
    execute(&mut session, &mut machine, &mut hook).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(configuration.vmfunc, 1);
    assert_eq!(
        machine.table_entry(configuration.eptp_list).unwrap(),
        configuration.ept
    );
    assert_eq!(
        machine.table_entry(configuration.eptp_list + 8).unwrap(),
        configuration.data_ept
    );
    assert!(
        machine.pages[&configuration.eptp_list][16..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(machine.leaf(configuration.ept, GPA).0 & 7, 4);
    assert_eq!(machine.leaf(configuration.data_ept, GPA).0 & 7, 1);
    let mut status = packet(&["hook", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 128), INTERCEPT_VMFUNC);
}

#[test]
fn unsupported_vmfunc_requests_fail_before_base_guards_and_default_mtf_remains_available() {
    let mut machine = Machine::new();
    let mut session = session();
    machine.vmfunc_available = false;
    let mut native = packet(&["hook", "install", "0x3000", "0x400008", "cc", "--vmfunc"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut native),
        Err(Error::Unsupported)
    );
    assert!(!session.is_active());
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
    let mut default = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut default).unwrap();
    assert_eq!(word(&default, 128), 0);
}

#[test]
fn unknown_hook_flags_and_vmfunc_on_debug_commands_are_rejected() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut hook = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    hook[128..132].copy_from_slice(&32u32.to_le_bytes());
    assert_eq!(
        execute(&mut session, &mut machine, &mut hook),
        Err(Error::Format)
    );
    let arguments = [
        "debug-registers",
        "set",
        "0x3000",
        "0x400000",
        "0x400100",
        "--vmfunc",
    ]
    .map(str::to_owned);
    assert!(interception_packet(&arguments).is_err());
}

#[test]
fn dynamic_ids_preserve_neighbors_and_token_and_alternate_private_banks() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let first_id = quad(&install, HEADER_BYTES + 16);
    let first_ept = unsafe { &*session.configuration.get() }.ept;
    let mut add = packet(&["hook", "add", "1", "0x400010", "c3"]);
    execute(&mut session, &mut machine, &mut add).unwrap();
    let second_id = quad(&add, HEADER_BYTES + 16);
    assert!(second_id > first_id);
    assert_eq!(quad(&add, 80), 1);
    assert_eq!(quad(&add, 144), 2);
    assert_eq!(quad(&add, 152), 2);
    let configuration = unsafe { &*session.configuration.get() };
    assert_ne!(configuration.ept, first_ept);
    let shadow = machine.leaf(configuration.ept, GPA).0 & MASK;
    assert_eq!(
        (machine.pages[&shadow][8], machine.pages[&shadow][16]),
        (0xcc, 0xc3)
    );
    let mut drop = packet(&["hook", "remove", "1", &first_id.to_string()]);
    execute(&mut session, &mut machine, &mut drop).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let shadow = machine.leaf(configuration.ept, GPA).0 & MASK;
    assert_eq!(
        (machine.pages[&shadow][8], machine.pages[&shadow][16]),
        (0x90, 0xc3)
    );
    assert_eq!(quad(&drop, 152), 1);
    let mut list = packet(&["hook", "list", "1"]);
    execute(&mut session, &mut machine, &mut list).unwrap();
    assert_eq!(word(&list, 32), 1);
    assert_eq!(quad(&list, HEADER_BYTES), second_id);
    assert_eq!(quad(&list, HEADER_BYTES + 8), 0x400010);
    let mut final_drop = packet(&["hook", "remove", "1", &second_id.to_string()]);
    execute(&mut session, &mut machine, &mut final_drop).unwrap();
    assert!(!session.is_active());
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
    let mut reinstall = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut reinstall).unwrap();
    assert_eq!(quad(&reinstall, 80), 2);
    assert!(quad(&reinstall, HEADER_BYTES + 16) > second_id);
}

#[test]
fn rejected_dynamic_changes_leave_the_active_views_ids_and_guards_intact() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let ept = unsafe { &*session.configuration.get() }.ept;
    let mut overlap = packet(&["hook", "add", "1", "0x400008", "c390"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut overlap),
        Err(Error::Bounds)
    );
    let mut missing = packet(&["hook", "remove", "1", "999"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut missing),
        Err(Error::Session)
    );
    let mut stale = packet(&["hook", "add", "9", "0x400010", "c3"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut stale),
        Err(Error::Session)
    );
    // Remap a retained GVA before rebuilding. The old bank and guard survive.
    machine.store_entry(0x6000, (GPA + 4096) | 7).unwrap();
    let mut remapped = packet(&["hook", "add", "1", "0x400010", "c3"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut remapped),
        Err(Error::Remapped)
    );
    assert_eq!(unsafe { &*session.configuration.get() }.ept, ept);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 5);
    assert!(session.is_active());
    let mut list = packet(&["hook", "list", "1"]);
    execute(&mut session, &mut machine, &mut list).unwrap();
    assert_eq!(word(&list, 32), 1);
    assert_eq!(quad(&list, HEADER_BYTES), 1);
}

#[test]
fn leases_renew_without_changing_ids_and_expired_tokens_cannot_reactivate() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "--lease-ms",
        "100",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(quad(&install, 136), 100);
    machine.clock = 1050;
    let mut renew = packet(&["hook", "renew", "1", "--lease-ms", "200"]);
    execute(&mut session, &mut machine, &mut renew).unwrap();
    assert_eq!(quad(&renew, 80), 1);
    assert_eq!(quad(&renew, 136), 200);
    machine.clock = 1250;
    assert_eq!(
        execute(&mut session, &mut machine, &mut renew),
        Err(Error::Session)
    );
    assert!(!session.is_active());
    let mut status = packet(&["hook", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 112), INTERCEPT_REVOKED);
    assert_eq!(word(&status, 116), INTERCEPT_CAUSE_LEASE);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
}

#[test]
fn watchdog_and_timing_capabilities_are_checked_before_publication() {
    let mut machine = Machine::new();
    let mut session = session();
    machine.lease_available = false;
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut install),
        Err(Error::Unsupported)
    );
    machine.lease_available = true;
    machine.timing_available = false;
    let mut timing = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "--tsc-offset",
    ]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut timing),
        Err(Error::Unsupported)
    );
    assert!(!session.is_active());
    machine.timing_available = true;
    execute(&mut session, &mut machine, &mut timing).unwrap();
    assert_eq!(word(&timing, 128), INTERCEPT_TSC_OFFSET);
    let mut release = packet(&["hook", "release", "1"]);
    execute(&mut session, &mut machine, &mut release).unwrap();
    assert_eq!(word(&release, 112), INTERCEPT_DISABLED);
    assert_eq!(word(&release, 128), 0);
}

#[test]
fn explicit_no_lease_runs_without_a_watchdog_and_requires_manual_release() {
    let mut machine = Machine::new();
    let mut session = session();
    machine.lease_available = false;
    let mut request = packet(&["hook", "install", "0x3000", "0x400008", "cc", "--no-lease"]);
    execute(&mut session, &mut machine, &mut request).unwrap();
    assert_eq!(word(&request, 128), INTERCEPT_NO_LEASE);
    assert_eq!(word(&request, 132), 0);
    assert_eq!(session.tsc_hz.load(std::sync::atomic::Ordering::Acquire), 0);
    let token = quad(&request, 80).to_string();
    machine.clock = u64::MAX;
    let mut status = packet(&["hook", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 112), INTERCEPT_ACTIVE);
    let mut renewal = packet(&["hook", "renew", &token]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut renewal),
        Err(Error::Session)
    );
    renewal[128..132].copy_from_slice(&INTERCEPT_NO_LEASE.to_le_bytes());
    assert_eq!(
        execute(&mut session, &mut machine, &mut renewal),
        Err(Error::Format)
    );
    let mut added = packet(&["hook", "add", &token, "0x400010", "cd"]);
    execute(&mut session, &mut machine, &mut added).unwrap();
    assert_eq!(word(&added, 128), INTERCEPT_NO_LEASE);
    let mut release = packet(&["hook", "release", &token]);
    execute(&mut session, &mut machine, &mut release).unwrap();
    assert_eq!(word(&release, 112), INTERCEPT_DISABLED);
    assert_eq!(word(&release, 128), 0);
    let mut debug = packet(&[
        "debug-registers",
        "set",
        "0x3000",
        "0x400008",
        "0x400010",
        "--no-lease",
    ]);
    execute(&mut session, &mut machine, &mut debug).unwrap();
    assert_eq!(word(&debug, 128), INTERCEPT_NO_LEASE);
    assert_eq!(word(&debug, 108), 1);
    for arguments in [
        vec![
            "hook",
            "install",
            "0x3000",
            "0x400008",
            "cc",
            "--no-lease",
            "--lease-ms",
            "1000",
        ],
        vec!["hook", "renew", "1", "--no-lease"],
        vec!["hook", "status", "--no-lease"],
    ] {
        assert!(
            interception_packet(
                &arguments
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
    }
}

#[test]
fn default_and_persistent_profiles_isolate_read_execute_permissions_between_cpus() {
    for mode in [None, Some("--persistent-data"), Some("--vmfunc")] {
        let mut machine = Machine::new();
        let mut session = session();
        session.initialize(0x1000_0000, 1 | (1 << 3));
        let mut arguments = vec!["hook", "install", "0x3000", "0x400008", "cc"];
        if let Some(mode) = mode {
            arguments.push(mode);
        }
        let mut install = packet(&arguments);
        execute(&mut session, &mut machine, &mut install).unwrap();
        let profile = unsafe { &*session.configuration.get() };
        let execution_leaf = machine.leaf(profile.ept, GPA).0;
        let original_leaf = machine.leaf(profile.data_ept, GPA).0;
        assert_ne!(execution_leaf & MASK, original_leaf & MASK);
        assert_eq!(original_leaf & 7, 1);
        assert_ne!(profile.cpu_data[0], profile.cpu_data[3]);
        assert_eq!(profile.cpu_data[1], 0);
        let private_leaf = profile.cpu_leaves[0][0];
        machine.store_entry(private_leaf, original_leaf | 4).unwrap();
        assert_eq!(machine.leaf(profile.cpu_data[0], GPA).0 & 7, 5);
        assert_eq!(machine.leaf(profile.cpu_data[3], GPA).0, original_leaf);
        assert_eq!(machine.leaf(profile.data_ept, GPA).0, original_leaf);
        assert_eq!(machine.leaf(profile.ept, GPA).0, execution_leaf);
        machine.store_entry(private_leaf, original_leaf).unwrap();
        assert_eq!(machine.leaf(profile.cpu_data[0], GPA).0, original_leaf);
        let mut add = packet(&["hook", "add", "1", "0x400100", "c3"]);
        execute(&mut session, &mut machine, &mut add).unwrap();
        let profile = unsafe { &*session.configuration.get() };
        assert_eq!(machine.leaf(profile.cpu_data[0], GPA).0 & 7, 1);
        assert_eq!(machine.leaf(profile.cpu_data[3], GPA).0 & 7, 1);
    }
}

#[test]
fn concurrent_data_views_and_vmfunc_lists_are_private_to_each_cpu() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "--vmfunc",
        "--concurrent-writes",
        "--persistent-data",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let shared = machine.leaf(configuration.data_ept, GPA).0;
    for index in 0..64 {
        assert_eq!(machine.leaf(configuration.cpu_data[index], GPA).0, shared);
        assert_eq!(
            machine
                .table_entry(configuration.cpu_lists[index] + 8)
                .unwrap(),
            configuration.cpu_data[index]
        );
        assert_eq!(
            machine.table_entry(configuration.cpu_lists[index]).unwrap(),
            configuration.ept
        );
        assert_ne!(configuration.cpu_data[index], configuration.data_ept);
        if index != 0 {
            assert_ne!(
                configuration.cpu_leaves[index][0],
                configuration.cpu_leaves[0][0]
            );
        }
    }
    let first = configuration.cpu_leaves[0][0];
    machine
        .store_entry(first, machine.table_entry(first).unwrap() | 2)
        .unwrap();
    assert_eq!(machine.leaf(configuration.cpu_data[0], GPA).0 & 7, 3);
    assert_eq!(machine.leaf(configuration.cpu_data[1], GPA).0 & 7, 1);
    assert_eq!(machine.leaf(configuration.data_ept, GPA).0 & 7, 1);
    machine.events.clear();
    unsafe { interception::write_original(&mut *session, &mut machine, GPA + 9, &[0x42]) }.unwrap();
    assert!(machine.events.is_empty());
    let configuration = unsafe { &*session.configuration.get() };
    let shadow = machine.leaf(configuration.ept, GPA).0 & MASK;
    assert_eq!(
        (machine.pages[&shadow][8], machine.pages[&shadow][9]),
        (0xcc, 0x42)
    );
}

#[test]
fn registered_contexts_keep_the_filter_and_require_matching_hook_mappings() {
    let mut machine = Machine::new();
    machine.pages.insert(0x7000, Box::new([0; 4096]));
    machine.store_entry(0x7000, 0x4007).unwrap();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let mut add = packet(&["hook", "context-add", "1", "0x7005"]);
    execute(&mut session, &mut machine, &mut add).unwrap();
    assert_eq!(word(&add, 44), 2);
    assert_eq!(quad(&add, 80), 1);
    let mut list = packet(&["hook", "context-list", "1"]);
    execute(&mut session, &mut machine, &mut list).unwrap();
    assert_eq!(word(&list, 32), 2);
    assert_eq!(quad(&list, HEADER_BYTES + 8), 0x7000);
    let mut invalid = packet(&["hook", "context-add", "1", "0x9000"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut invalid),
        Err(Error::Unmapped)
    );
    let mut remove = packet(&["hook", "context-remove", "1", "0x7000"]);
    execute(&mut session, &mut machine, &mut remove).unwrap();
    assert_eq!(word(&remove, 44), 1);
    let mut primary = packet(&["hook", "context-remove", "1", "0x3000"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut primary),
        Err(Error::Session)
    );
}

#[test]
fn enabled_cpu_masks_pack_both_banks_without_allocating_disabled_cpu_views() {
    for cpu_mask in [1, 1 | (1 << 3) | (1 << 63), u64::MAX] {
        let mut machine = Machine::new();
        let mut session = session();
        session.initialize(0x1000_0000, cpu_mask);
        let mut install = packet(&[
            "hook",
            "install",
            "0x3000",
            "0x400008",
            "cc",
            "--vmfunc",
            "--concurrent-writes",
        ]);
        execute(&mut session, &mut machine, &mut install).unwrap();
        let mut add = packet(&["hook", "add", "1", "0x400100", "c3"]);
        execute(&mut session, &mut machine, &mut add).unwrap();
        let configuration = unsafe { &*session.configuration.get() };
        let bank_start = configuration.pool_base + intercept_bank_pages(cpu_mask) as u64 * 4096;
        assert_eq!(configuration.ept & MASK, bank_start);
        let mut cpu_slot = 0;
        for cpu_index in 0..64 {
            if cpu_mask & (1u64 << cpu_index) == 0 {
                assert_eq!(configuration.cpu_data[cpu_index], 0);
                assert_eq!(configuration.cpu_lists[cpu_index], 0);
                assert_eq!(configuration.cpu_leaves[cpu_index], [0; HOOK_MAX_PAGES]);
                continue;
            }
            let expected = bank_start
                + (INTERCEPT_TABLE_PAGES
                    + 2 * HOOK_MAX_PAGES
                    + 1
                    + cpu_slot * INTERCEPT_CPU_VIEW_PAGES) as u64
                    * 4096;
            assert_eq!(configuration.cpu_data[cpu_index] & MASK, expected);
            assert_eq!(
                machine.leaf(configuration.cpu_data[cpu_index], GPA).0 & 7,
                1
            );
            assert_eq!(
                machine
                    .table_entry(configuration.cpu_lists[cpu_index])
                    .unwrap(),
                configuration.ept
            );
            cpu_slot += 1;
        }
        let pool_end = configuration.pool_base + intercept_storage_pages(cpu_mask) as u64 * 4096;
        assert!(machine.pages.keys().all(|page| *page < pool_end));
        assert!(
            configuration.base_leaves[0]
                >= bank_start + intercept_bank_pages(cpu_mask) as u64 * 4096
        );
    }
    assert_eq!(intercept_storage_pages(1), 842);
    assert_eq!(intercept_storage_pages(u64::MAX), 13190);
}

#[test]
fn patch_capacity_counts_records_on_one_page_and_rejection_preserves_ids_and_views() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut arguments = vec![
        "hook".to_string(),
        "install".to_string(),
        "0x3000".to_string(),
    ];
    for index in 0..HOOK_MAX_PAGES {
        arguments.extend([format!("{:#x}", 0x400008 + index * 8), "cc".to_string()]);
    }
    let mut install = interception_packet(&arguments).unwrap();
    execute(&mut session, &mut machine, &mut install).unwrap();
    let configuration = unsafe { &*session.configuration.get() };
    let published = (
        configuration.ept,
        configuration.data_ept,
        configuration.generation,
    );
    assert_eq!(configuration.hook_count, 1);
    assert_eq!(quad(&install, 152), HOOK_MAX_PAGES as u64);
    let overflow_address = format!("{:#x}", 0x400008 + HOOK_MAX_PATCHES * 8);
    let mut overflow = packet(&["hook", "add", "1", &overflow_address, "c3"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut overflow),
        Err(Error::Capacity)
    );
    let configuration = unsafe { &*session.configuration.get() };
    assert_eq!(
        (
            configuration.ept,
            configuration.data_ept,
            configuration.generation
        ),
        published
    );
    assert!(session.is_active());
    let mut list = packet(&["hook", "list", "1"]);
    execute(&mut session, &mut machine, &mut list).unwrap();
    assert_eq!(word(&list, 32), HOOK_MAX_PAGES as u32);
    for index in 0..HOOK_MAX_PAGES {
        assert_eq!(
            quad(&list, HEADER_BYTES + index * ITEM_BYTES),
            index as u64 + 1
        );
    }
    let mut drop = packet(&["hook", "remove", "1", "1"]);
    execute(&mut session, &mut machine, &mut drop).unwrap();
    execute(&mut session, &mut machine, &mut overflow).unwrap();
    assert_eq!(
        quad(&overflow, HEADER_BYTES + 16),
        HOOK_MAX_PAGES as u64 + 1
    );
}

#[test]
fn cow_ept_shares_untouched_subtrees_and_bounds_private_allocations() {
    let mut machine = Machine::new();
    machine.store_entry(0x1008, 0x9007).unwrap();
    for index in 0..128 {
        let table = 0xa000 + index * 4096;
        machine.store_entry(0x9000 + index * 8, table | 7).unwrap();
        machine.store_entry(table, 0xb7).unwrap();
    }
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    let profile = unsafe { &*session.configuration.get() };
    assert_eq!(profile.pool_used, 8);
    assert_eq!(
        machine.table_entry((profile.ept & MASK) + 8).unwrap(),
        0x9007
    );
    assert_eq!(
        machine.table_entry((profile.data_ept & MASK) + 8).unwrap(),
        0x9007
    );
    assert_eq!(machine.table_entry(0x1008).unwrap(), 0x9007);
    assert_eq!(machine.table_entry(0x1000).unwrap(), 0x2007);
    assert_ne!(
        machine.table_entry(profile.ept & MASK).unwrap() & MASK,
        0x2000
    );
    assert_ne!(
        machine.table_entry(profile.data_ept & MASK).unwrap() & MASK,
        0x2000
    );
}

#[test]
fn three_way_merge_accepts_unrelated_and_convergent_writes_and_updates_its_baseline() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "--concurrent-writes",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    unsafe { interception::write_original(&mut *session, &mut machine, GPA + 9, &[0x42]) }.unwrap();
    unsafe { interception::write_original(&mut *session, &mut machine, GPA + 8, &[0xcc]) }.unwrap();
    assert!(session.is_active());
    let profile = unsafe { &*session.configuration.get() };
    let shadow = machine.leaf(profile.ept, GPA).0 & MASK;
    assert_eq!(&machine.pages[&shadow][8..10], &[0xcc, 0x42]);
    // After both versions converge, a subsequent original change is unilateral.
    unsafe { interception::write_original(&mut *session, &mut machine, GPA + 8, &[0xc3]) }.unwrap();
    assert_eq!(&machine.pages[&shadow][8..10], &[0xc3, 0x42]);
    assert!(session.is_active());
}

#[test]
fn a_no_op_patch_does_not_block_later_original_changes() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "90"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    unsafe { interception::write_original(&mut *session, &mut machine, GPA + 8, &[0xc3]) }.unwrap();
    let profile = unsafe { &*session.configuration.get() };
    let shadow = machine.leaf(profile.ept, GPA).0 & MASK;
    assert_eq!(machine.pages[&shadow][8], 0xc3);
    assert!(session.is_active());
}

#[test]
fn expired_status_revokes_before_reporting_and_new_installation_rotates_the_token() {
    let mut machine = Machine::new();
    machine.clock = u64::MAX - 50;
    let mut session = session();
    let mut install = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "--lease-ms",
        "100",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    machine.clock = 48;
    let mut status = packet(&["hook", "status"]);
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 112), INTERCEPT_ACTIVE);
    assert_eq!(quad(&status, 136), 1);
    machine.clock = 49;
    execute(&mut session, &mut machine, &mut status).unwrap();
    assert_eq!(word(&status, 112), INTERCEPT_REVOKED);
    assert_eq!(word(&status, 116), INTERCEPT_CAUSE_LEASE);
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(quad(&install, 80), 2);
    let mut stale = packet(&["hook", "renew", "1"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut stale),
        Err(Error::Session)
    );
}

#[test]
fn malformed_interception_headers_never_acquire_the_barrier_or_touch_memory() {
    let mut machine = Machine::new();
    let mut session = session();
    for length in 0..HEADER_BYTES {
        assert_eq!(
            execute(&mut session, &mut machine, &mut vec![0; length]),
            Err(Error::Format)
        );
    }
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    install[0] ^= 1;
    assert_eq!(
        execute(&mut session, &mut machine, &mut install),
        Err(Error::Format)
    );
    assert!(machine.events.is_empty());
    assert!(!session.is_active());
}

#[test]
fn concurrent_conflicts_retire_write_guards_and_release_both_locks() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&[
        "hook",
        "install",
        "0x3000",
        "0x400008",
        "cc",
        "--concurrent-writes",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(
        unsafe { interception::write_original(&mut *session, &mut machine, GPA + 8, &[0x42]) },
        Err(Error::MergeConflict)
    );
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
    assert_eq!(machine.events.last(), Some(&"resume"));
    execute(&mut session, &mut machine, &mut install).unwrap();
    unsafe { interception::write_original(&mut *session, &mut machine, GPA + 9, &[0x43]) }.unwrap();
    assert!(session.is_active());
}

#[test]
fn pcid_aliases_of_the_primary_root_are_reported_once() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&[
        "hook",
        "install",
        "0x3001",
        "0x400008",
        "cc",
        "--alternate-cr3",
        "0x3007",
    ]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert_eq!(word(&install, 44), 1);
    let mut list = packet(&["hook", "context-list", "1"]);
    execute(&mut session, &mut machine, &mut list).unwrap();
    assert_eq!(word(&list, 32), 1);
    assert_eq!(quad(&list, HEADER_BYTES), ROOT);
    assert_eq!(quad(&list, HEADER_BYTES + 8), 0);
}

#[test]
fn failed_guard_rollback_revokes_instead_of_publishing_partial_protection() {
    let mut machine = Machine::new();
    let mut session = session();
    let mut install = packet(&["hook", "install", "0x3000", "0x400008", "cc"]);
    execute(&mut session, &mut machine, &mut install).unwrap();
    machine.denied_guard = Some(unsafe { &*session.configuration.get() }.base_leaves[0]);
    let mut add = packet(&["hook", "add", "1", "0x400009", "cc"]);
    assert_eq!(
        execute(&mut session, &mut machine, &mut add),
        Err(Error::Permission)
    );
    assert!(!session.is_active());
    assert_eq!(
        session.cause.load(std::sync::atomic::Ordering::Acquire),
        u64::from(INTERCEPT_CAUSE_RUNTIME)
    );
    assert_eq!(machine.leaf(machine.base_ept(), GPA).0 & 7, 7);
    assert_eq!(machine.events.last(), Some(&"resume"));
    machine.denied_guard = None;
    execute(&mut session, &mut machine, &mut install).unwrap();
    assert!(session.is_active());
    assert_eq!(quad(&install, 80), 2);
}
