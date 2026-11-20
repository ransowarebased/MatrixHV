use std::arch::global_asm;

global_asm!(include_str!("../builds/boot-diagnostics-tests/boot-capture.S"));

unsafe extern "C" {
    fn test_boot_read(context: *mut Context, address: u64, value: *mut u64) -> u64;
    fn test_boot_capture(context: *mut Context, registers: *const u64) -> u64;
}

#[repr(C, align(4096))]
struct Page([u64; 512]);

impl Page {
    fn new() -> Box<Self> {
        Box::new(Self([0; 512]))
    }

    fn address(&self) -> u64 {
        self.0.as_ptr() as u64
    }
}

#[repr(C)]
struct Events {
    cpus: [u64; 64],
    init: u64,
    sipi: u64,
    halted: u64,
}

#[repr(C)]
struct Context {
    diagnostic: [u64; 32],
    event: u64,
    samples: u64,
    flight_sequence: u64,
    last_rip: u64,
    last_reason: u64,
    nested: u64,
    ept: u64,
    vmcs: [u64; 6],
    root_cr0: u64,
    root_pat: u64,
    denied_host_page: u64,
    host_mapping_calls: u64,
}

const ADDRESS: u64 = 0xffff_8000_0020_0000;
const HEADER: u64 = 0x424f_4f54_0002_0000;
const SENTINEL: u64 = u64::MAX;

struct Fixture {
    context: Box<Context>,
    events: Box<Events>,
    // Indexes zero through three are EPT tables; four through seven are
    // guest paging tables; eight and nine are guest payload pages.
    pages: Vec<Box<Page>>,
}

impl Fixture {
    fn new() -> Self {
        let mut pages = (0..10).map(|_| Page::new()).collect::<Vec<_>>();
        pages[0].0[0] = pages[1].address() | 7;
        pages[1].0[0] = pages[2].address() | 7;
        pages[2].0[0] = pages[3].address() | 7;
        for (gpa, page) in (1..=6).zip(4..10) {
            pages[3].0[gpa] = pages[page].address() | 0x37;
        }
        pages[4].0[256] = 0x2003;
        pages[5].0[0] = 0x3003;
        pages[6].0[1] = 0x4003;
        pages[7].0[0] = 0x5003;
        pages[7].0[1] = 0x6003;
        for index in 0..512 {
            pages[8].0[index] = 0x1111_0000_0000_0000 | index as u64;
            pages[9].0[index] = 0x2222_0000_0000_0000 | index as u64;
        }
        let mut events = Box::new(Events { cpus: [0; 64], init: 0x1234, sipi: 0x5678, halted: 0x9abc });
        let context = Box::new(Context {
            diagnostic: [0; 32], event: (&mut *events as *mut Events) as u64,
            samples: 0, flight_sequence: 0x123456, last_rip: 0xffff_8000_1234_5678,
            last_reason: 31, nested: 0, ept: pages[0].address() | 0x5e,
            vmcs: [0x8005_0033, 1 << 9, 0x20, 0x1000, ADDRESS + 0x20, ADDRESS + 0xfe0],
            root_cr0: 0x8001_0033, root_pat: 0x0007_0406_0007_0406,
            denied_host_page: 0, host_mapping_calls: 0,
        });
        Self { context, events, pages }
    }

    fn read(&mut self, address: u64) -> (u64, u64) {
        let mut value = 0;
        let valid = unsafe { test_boot_read(&mut *self.context, address, &mut value) };
        (valid, value)
    }

    fn capture(&mut self) -> [u64; 32] {
        let registers = (0..15).map(|index| 0xabcdef00 + index).collect::<Vec<u64>>();
        assert_eq!(unsafe { test_boot_capture(&mut *self.context, registers.as_ptr()) }, 1,
                   "capture must preserve all nonvolatile registers, RSI, and R8");
        self.context.diagnostic
    }
}

#[test]
fn exact_unaligned_code_qwords_and_cross_page_stack_are_observed() {
    let mut fixture = Fixture::new();
    fixture.context.vmcs[4] = ADDRESS + 0x23;
    fixture.context.diagnostic[3] = 0xdeadbeef;
    let observed = fixture.capture();
    assert_eq!(observed[0], HEADER | 0x3ff);
    assert_eq!(observed[1], fixture.context.root_cr0);
    assert_eq!(observed[2], fixture.context.root_pat);
    assert_eq!(observed[3], 0xdeadbeef);
    assert_eq!(&observed[4..15], &(0..11).map(|index| 0xabcdef00 + index).collect::<Vec<_>>());
    let expected_code = unsafe { std::ptr::read_unaligned((fixture.pages[8].address() + 0x23) as *const u64) };
    assert_eq!(observed[15], expected_code, "code starts exactly at RIP, without alignment");
    assert_eq!(&observed[17..21], &fixture.pages[8].0[508..512]);
    assert_eq!(&observed[21..25], &fixture.pages[9].0[..4]);
    assert_eq!(&observed[25..29], &[SENTINEL; 4]);
    assert_eq!(&observed[29..32], &[0x1234, 0x5678, 0x9abc]);
}

#[test]
fn crossing_qwords_and_noncanonical_addresses_fail_without_payload_access() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.read(ADDRESS + 4088), (1, fixture.pages[8].0[511]));
    for address in [ADDRESS + 4089, ADDRESS + 4095, 0x0000_8000_0020_0020] {
        fixture.context.host_mapping_calls = 0;
        assert_eq!(fixture.read(address), (0, SENTINEL));
        assert_eq!(fixture.context.host_mapping_calls, 0);
    }
}

#[test]
fn ept_unreadable_mmio_and_unmapped_host_payloads_are_never_dereferenced() {
    for kind in 0..3 {
        let mut fixture = Fixture::new();
        let unmapped = 0x0000_7000_0000_0000;
        fixture.pages[3].0[5] = match kind {
            0 => unmapped | 0x36,
            1 => unmapped | 7,
            _ => unmapped | 0x37,
        };
        if kind == 2 {
            fixture.context.denied_host_page = unmapped;
        }
        assert_eq!(fixture.read(ADDRESS + 0x20), (0, SENTINEL));
    }
}

#[test]
fn mmio_guest_paging_tables_are_rejected_before_reads() {
    let mut fixture = Fixture::new();
    fixture.pages[3].0[3] = 0x0000_7000_0000_0000 | 7;
    assert_eq!(fixture.read(ADDRESS + 0x20), (0, SENTINEL));
    assert_eq!(fixture.context.host_mapping_calls, 2);
}

#[test]
fn absent_guest_mapping_keeps_stack_sentinels_and_individual_validity_bits() {
    let mut fixture = Fixture::new();
    fixture.pages[7].0[1] = 0;
    let observed = fixture.capture();
    assert_eq!(observed[0], HEADER | 0x3f);
    assert_eq!(&observed[21..25], &[SENTINEL; 4]);
}

#[test]
fn l2_and_unsupported_paging_are_distinguished_without_guest_reads() {
    for kind in 0..3 {
        let mut fixture = Fixture::new();
        match kind {
            0 => fixture.context.nested = 1,
            1 => fixture.context.vmcs[0] &= !(1 << 31),
            _ => fixture.context.vmcs[1] = 0,
        }
        let observed = fixture.capture();
        assert_eq!(observed[0], HEADER | if kind == 0 { 1 << 10 } else { 1 << 11 });
        assert_eq!(&observed[15..25], &[SENTINEL; 10]);
        assert_eq!(fixture.context.host_mapping_calls, 0);
    }
}

#[test]
fn rotating_cpu_search_wraps_and_collects_the_populated_context() {
    let mut fixture = Fixture::new();
    fixture.context.samples = 63;
    fixture.events.cpus[2] = (&mut *fixture.context as *mut Context) as u64;
    let observed = fixture.capture();
    assert_eq!(&observed[25..29], &[2, 0x123456, 0xffff_8000_1234_5678, 31]);
}

#[test]
fn large_guest_pages_and_la57_use_the_same_guarded_payload_reader() {
    let mut large = Fixture::new();
    large.pages[6].0[1] = 0x83;
    assert_eq!(large.read(ADDRESS + 0x5020), (1, large.pages[8].0[4]));
    large.pages[6].0[1] = 0x2083;
    assert_eq!(large.read(ADDRESS + 0x5020), (0, SENTINEL));

    let mut la57 = Fixture::new();
    let mut l5 = Page::new();
    l5.0[511] = 0x1003;
    la57.pages[3].0[7] = l5.address() | 0x37;
    la57.context.vmcs[2] |= 1 << 12;
    la57.context.vmcs[3] = 0x7000;
    assert_eq!(la57.read(ADDRESS + 0x20), (1, la57.pages[8].0[4]));
}
