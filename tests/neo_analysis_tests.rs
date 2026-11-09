use neo::memory::{
    CpuidGate, CpuidRecord, InterceptionRequest, ObservationFilter, decode_page_batch,
    interception_packet,
};
use neo::protocol::memory::*;
use neo::unwind::{UnwindContext, unwind};
use neo::user::{self, Export, MemoryReader, Module, Pattern, PatternScanner, Section};
use std::collections::BTreeMap;

const BASE: u64 = 0x180000000;
const STACK: u64 = 0x100000;

#[derive(Default)]
struct Memory {
    regions: BTreeMap<u64, Vec<u8>>,
    reads: usize,
}

impl MemoryReader for Memory {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        assert!(HEADER_BYTES + ITEM_BYTES + length <= BUFFER_BYTES);
        self.reads += 1;
        let (base, bytes) = self
            .regions
            .range(..=address)
            .next_back()
            .ok_or("unmapped fixture")?;
        let offset = (address - base) as usize;
        bytes
            .get(offset..offset + length)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| "unmapped fixture".into())
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn pe() -> Vec<u8> {
    let mut bytes = vec![0; 0x5000];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 60, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 1);
    put16(&mut bytes, 0x94, 240);
    let optional = 0x98;
    put16(&mut bytes, optional, 0x20b);
    put32(&mut bytes, optional + 16, 0x1000);
    put32(&mut bytes, optional + 56, 0x5000);
    put32(&mut bytes, optional + 108, 16);
    let section = optional + 240;
    bytes[section..section + 5].copy_from_slice(b".text");
    put32(&mut bytes, section + 8, 0x1000);
    put32(&mut bytes, section + 12, 0x1000);
    put32(&mut bytes, section + 36, 0x60000020);
    bytes
}

fn module() -> Module {
    Module {
        base: BASE,
        size: 0x5000,
        entry_point: BASE + 0x1000,
        name: "sample.dll".into(),
        path: "sample.dll".into(),
        sections: vec![Section {
            name: ".text".into(),
            start: BASE + 0x1000,
            size: 0x1000,
            characteristics: 0x60000020,
        }],
        exports: vec![],
        export_error: None,
        exception_rva: 0x3000,
        exception_size: 12,
    }
}

fn unwind_fixture(codes: &[u8], prolog_size: u8, frame: u8) -> (Memory, Module) {
    let mut bytes = pe();
    put32(&mut bytes, 0x3000, 0x1000);
    put32(&mut bytes, 0x3004, 0x1100);
    put32(&mut bytes, 0x3008, 0x3100);
    bytes[0x3100] = 1;
    bytes[0x3101] = prolog_size;
    bytes[0x3102] = (codes.len() / 2) as u8;
    bytes[0x3103] = frame;
    bytes[0x3104..0x3104 + codes.len()].copy_from_slice(codes);
    bytes[0x1000..0x1100].fill(0x90);
    let mut memory = Memory::default();
    memory.regions.insert(BASE, bytes);
    memory.regions.insert(STACK, vec![0; 0x1000]);
    (memory, module())
}

fn context(offset: u64) -> UnwindContext {
    let mut registers = [0; 16];
    registers[4] = STACK;
    UnwindContext {
        rip: BASE + offset,
        rsp: STACK,
        registers,
    }
}

#[test]
fn cpuid_wire_records_have_reserved_padding_and_optional_debug_gate() {
    let mut request = InterceptionRequest {
        operation: CPUID_SET,
        cr3: 0x2000,
        token: 7,
        cpuid_records: vec![CpuidRecord {
            leaf: 7,
            subleaf: 1,
            subleaf_mask: u32::MAX,
            values: [1, 2, 4, 8],
            keep_masks: [!1, !2, !4, !8],
        }],
        ..Default::default()
    };
    let packet = interception_packet(&request).unwrap();
    assert_eq!(packet.len(), HEADER_BYTES + 48);
    assert_eq!(word(&packet, HEADER_BYTES + 12), 0);
    assert_eq!(word(&packet, HEADER_BYTES + 16), 1);
    assert_eq!(word(&packet, HEADER_BYTES + 32), !1);
    assert_eq!(quad(&packet, 24), 0);
    request.cpuid_gate = Some(CpuidGate {
        dr3: 0x7ffe0ff0,
        dr7_mask: 0xff,
        dr7_value: 0x40,
    });
    let packet = interception_packet(&request).unwrap();
    assert_eq!(quad(&packet, 24), 0x7ffe0ff0);
    assert_eq!(quad(&packet, 144), 0xff);
    assert_eq!(quad(&packet, 152), 0x40);
    request.cpuid_records.push(request.cpuid_records[0].clone());
    assert!(interception_packet(&request).is_err());
    request.cpuid_records.truncate(1);
    request.cpuid_records[0].leaf = MEMORY_LEAF;
    assert!(interception_packet(&request).is_err());
    request.operation = CPUID_CLEAR;
    assert_eq!(interception_packet(&request).unwrap().len(), HEADER_BYTES);
}

#[test]
fn filters_and_shared_data_validate_wire_bounds() {
    let mut request = InterceptionRequest {
        operation: WATCH_FILTER_SET,
        token: 1,
        filter: ObservationFilter {
            thread_teb: 0x123000,
            ranges: vec![(0x1000, 0x2000, false), (0x1100, 0x1200, true)],
        },
        ..Default::default()
    };
    let bytes = interception_packet(&request).unwrap();
    assert_eq!(bytes.len(), HEADER_BYTES + 48);
    assert_eq!(quad(&bytes, 24), 0x123000);
    assert_eq!(quad(&bytes, HEADER_BYTES + 40), 1);
    request.filter.ranges = vec![(1, 2, false); 17];
    assert!(interception_packet(&request).is_err());
    request = InterceptionRequest {
        operation: HOOK_INSTALL,
        cr3: 0x2000,
        flags: INTERCEPT_PRIVATE_SHARED_DATA,
        items: vec![neo::memory::Item {
            address: 0x7ffe0000,
            bytes: vec![0; 4096],
        }],
        ..Default::default()
    };
    assert!(interception_packet(&request).is_ok());
    request.flags |= INTERCEPT_NO_LEASE;
    assert!(interception_packet(&request).is_err());
    request.flags = INTERCEPT_PRIVATE_SHARED_DATA;
    request.items[0].bytes.pop();
    assert!(interception_packet(&request).is_err());
}

#[test]
fn resident_batches_allow_streaming_beyond_tracking_capacity_and_reject_bad_cursors() {
    let mut bytes = neo::memory::tracking_packet(AD_ENUMERATE, 0, TRACK_MAX_PAGES).unwrap();
    put64(&mut bytes, 16, 0x401000);
    put64(&mut bytes, 72, 0x800000000000);
    put32(&mut bytes, 32, 1);
    put64(&mut bytes, HEADER_BYTES, 0x2000);
    put64(&mut bytes, HEADER_BYTES + 8, 0x400000);
    let batch = decode_page_batch(&bytes, 0x2000, 0x400000).unwrap();
    assert_eq!(batch.pages, vec![(0x2000, 0x400000)]);
    assert_eq!(batch.next, 0x401000);
    put64(&mut bytes, 16, 0x400000);
    assert!(decode_page_batch(&bytes, 0x2000, 0x400000).is_err());
    assert!(decode_page_batch(&bytes[..100], 0x2000, 0).is_err());
}

#[test]
fn scan_finds_overlapping_wildcards_across_contiguous_batches_but_never_across_gaps() {
    let mut scanner = PatternScanner::new(Pattern::parse("AA ?? AA").unwrap());
    assert!(scanner.feed(0x1ffe, &[0xaa, 1], 10).is_empty());
    assert_eq!(
        scanner.feed(0x2000, &[0xaa, 2, 0xaa], 10),
        vec![0x1ffe, 0x2000]
    );
    scanner.gap();
    assert!(scanner.feed(0x2003, &[0xaa], 10).is_empty());
    assert!(scanner.feed(0x3000, &[1, 0xaa], 10).is_empty());
    assert!(Pattern::parse("?? ??").is_err());
    assert!(Pattern::parse("GG").is_err());
    assert!(Pattern::parse("A?").is_err());
}

#[test]
fn pe_exports_sections_forwarders_and_symbolic_addresses_are_resolved() {
    let mut bytes = pe();
    put32(&mut bytes, 0x98 + 112, 0x2000);
    put32(&mut bytes, 0x98 + 116, 0x400);
    put32(&mut bytes, 0x2010, 1);
    put32(&mut bytes, 0x2014, 2);
    put32(&mut bytes, 0x2018, 2);
    put32(&mut bytes, 0x201c, 0x2040);
    put32(&mut bytes, 0x2020, 0x2050);
    put32(&mut bytes, 0x2024, 0x2060);
    put32(&mut bytes, 0x2040, 0x1000);
    put32(&mut bytes, 0x2044, 0x2090);
    put32(&mut bytes, 0x2050, 0x2070);
    put32(&mut bytes, 0x2054, 0x2080);
    put16(&mut bytes, 0x2060, 0);
    put16(&mut bytes, 0x2062, 1);
    bytes[0x2070..0x2074].copy_from_slice(b"Foo\0");
    bytes[0x2080..0x2084].copy_from_slice(b"Bar\0");
    bytes[0x2090..0x209a].copy_from_slice(b"other.Baz\0");
    let mut memory = Memory::default();
    memory.regions.insert(BASE, bytes);
    let sample = user::read_module(
        &mut memory,
        BASE,
        0x5000,
        "sample.dll".into(),
        "sample.dll".into(),
    )
    .unwrap();
    assert_eq!(sample.sections[0].start, BASE + 0x1000);
    assert_eq!(sample.exports[1].forwarder.as_deref(), Some("other.Baz"));
    let mut missing_name = |address, length| {
        if address == BASE + 0x2080 {
            Err("export name page is not resident".into())
        } else {
            memory.read(address, length)
        }
    };
    let partial = user::read_module(
        &mut missing_name,
        BASE,
        0x5000,
        "sample.dll".into(),
        "sample.dll".into(),
    )
    .unwrap();
    assert_eq!(
        partial.export_error.as_deref(),
        Some("export name page is not resident")
    );
    let partial = [partial];
    assert_eq!(
        user::resolve_address(&partial, "sample!Foo").unwrap(),
        BASE + 0x1000
    );
    assert!(
        user::resolve_address(&partial, "sample!Bar")
            .unwrap_err()
            .contains("export table is incomplete")
    );
    let mut other = module();
    other.base += 0x10000;
    other.name = "other.dll".into();
    other.exports.push(Export {
        name: Some("Baz".into()),
        ordinal: 1,
        address: Some(other.base + 0x1000),
        forwarder: None,
    });
    let modules = [sample, other];
    assert_eq!(
        user::resolve_address(&modules, "SAMPLE!Foo").unwrap(),
        BASE + 0x1000
    );
    assert_eq!(
        user::resolve_address(&modules, "sample.dll+0x20").unwrap(),
        BASE + 0x20
    );
    assert_eq!(
        user::resolve_address(&modules, "sample!#1").unwrap(),
        BASE + 0x1000
    );
    assert_eq!(
        user::resolve_address(&modules, "sample!Bar").unwrap(),
        BASE + 0x11000
    );
    assert!(user::resolve_address(&modules, "sample!foo").is_err());
    assert!(user::resolve_address(&modules, "sample+0xffff").is_err());
    assert!(memory.reads < 30);
}

#[test]
fn malformed_pe_and_loader_cycles_fail_without_unbounded_reads() {
    let mut memory = Memory::default();
    let mut bytes = pe();
    put32(&mut bytes, 60, u32::MAX);
    memory.regions.insert(BASE, bytes);
    assert!(user::read_module(&mut memory, BASE, 0x5000, "bad".into(), "bad".into()).is_err());
    let mut loader = vec![0; 0x1000];
    put64(&mut loader, 0x18, 0x200100);
    put64(&mut loader, 0x120, 0x200210);
    put64(&mut loader, 0x128, 0x200210);
    put64(&mut loader, 0x210, 0x200210);
    put64(&mut loader, 0x218, 0x200120);
    put64(&mut loader, 0x230, BASE);
    put32(&mut loader, 0x240, 0x5000);
    memory.regions.insert(0x200000, loader);
    memory.regions.insert(BASE, pe());
    assert!(
        user::modules(&mut memory, 0x200000)
            .unwrap_err()
            .contains("loader list")
    );
}

#[test]
fn disassembly_labels_rip_relative_memory_and_calls_without_treating_constants_as_addresses() {
    let bytes = [
        0xe8, 0xfb, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00,
        0x00, 0x00,
    ];
    let instructions = user::disassemble(&[module()], BASE + 0x1000, &bytes, 20);
    assert_eq!(instructions.len(), 3);
    assert_eq!(instructions[0].targets[0].0, BASE + 0x1100);
    assert_eq!(instructions[1].targets[0].0, BASE + 0x101c);
    assert!(instructions[2].targets.is_empty());
    assert!(user::disassemble(&[], BASE, &[0x0f], 20).is_empty());
}

#[test]
fn pdata_unwinds_optimized_frames_without_rbp_and_handles_partial_prologs() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, BASE + 0x1200);
    let result = unwind(&mut memory, &[module.clone()], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames.len(), 2);
    assert_eq!(result.frames[0].method, "pdata");
    assert_eq!(result.frames[1].rsp, STACK + 48);
    assert_eq!(result.frames[1].method, "leaf");
    let result = unwind(&mut memory, &[module], context(0x1002), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames.len(), 1);
}

#[test]
fn epilog_simulation_uses_the_current_stack_instead_of_undoing_the_prolog_twice() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x1020..0x1026]
        .copy_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0x5b, 0xc3]);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, 0x1234);
    put64(memory.regions.get_mut(&STACK).unwrap(), 48, BASE + 0x1200);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "epilog");
    assert_eq!(result.frames[1].rsp, STACK + 56);
}

#[test]
fn unsupported_metadata_and_unmapped_stacks_return_partial_results() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x3100] = 3;
    let result = unwind(&mut memory, &[module.clone()], context(0x1020), 8);
    assert!(!result.complete);
    assert_eq!(result.frames.len(), 1);
    assert!(result.stop.contains("version 3"));
    memory.regions.get_mut(&BASE).unwrap()[0x3100] = 1;
    memory.regions.remove(&STACK);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(!result.complete);
    assert!(result.stop.contains("unmapped"));
}

#[test]
fn chained_unwind_metadata_is_applied_and_cycles_are_reported() {
    let (mut memory, module) = unwind_fixture(&[], 0, 0);
    let bytes = memory.regions.get_mut(&BASE).unwrap();
    bytes[0x3100] = 1 | (4 << 3);
    put32(bytes, 0x3104, 0x1000);
    put32(bytes, 0x3108, 0x1100);
    put32(bytes, 0x310c, 0x3200);
    bytes[0x3200..0x3206].copy_from_slice(&[1, 4, 1, 0, 4, 0x42]);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, BASE + 0x1200);
    let result = unwind(&mut memory, &[module.clone()], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[1].rsp, STACK + 48);
    put32(memory.regions.get_mut(&BASE).unwrap(), 0x310c, 0x3100);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(!result.complete);
    assert!(result.stop.contains("cyclic"));
}

#[test]
fn dynamic_frame_pointers_restore_saved_registers_from_the_fixed_frame_base() {
    let (mut memory, module) = unwind_fixture(&[8, 0x34, 2, 0, 4, 3, 2, 0x32, 1, 0x50], 8, 0x15);
    let mut current = context(0x1020);
    current.registers[5] = STACK + 0x110;
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 0x110, 0xabcdef);
    put64(stack, 0x120, 0);
    put64(stack, 0x128, BASE + 0x1200);
    let result = unwind(&mut memory, &[module], current, 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[1].rsp, STACK + 0x130);
}

#[test]
fn tail_jump_epilogs_and_machine_frames_preserve_the_callers_stack() {
    let (mut memory, module) = unwind_fixture(&[4, 0x42], 4, 0);
    memory.regions.get_mut(&BASE).unwrap()[0x1020..0x1029]
        .copy_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0xe9, 0xd7, 0x01, 0, 0]);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, BASE + 0x1200);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "epilog");
    let (mut memory, module) = unwind_fixture(&[0, 10], 0, 0);
    let stack = memory.regions.get_mut(&STACK).unwrap();
    put64(stack, 0, BASE + 0x1200);
    put64(stack, 8, 0x33);
    put64(stack, 24, STACK + 0x100);
    let result = unwind(&mut memory, &[module], context(0x1020), 8);
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[1].rsp, STACK + 0x100);
}

#[test]
fn context_record_registers_follow_windows_unwind_register_numbers() {
    let mut bytes = vec![0; CONTEXT_RECORD_BYTES];
    put64(&mut bytes, 24, BASE + 0x1000);
    put64(&mut bytes, 32, STACK);
    put64(&mut bytes, 200, 3);
    for index in 0..15 {
        put64(&mut bytes, 72 + index * 8, index as u64 + 100);
    }
    let context = UnwindContext::from_record(&bytes).unwrap();
    assert_eq!(context.registers[4], STACK);
    assert_eq!(context.registers[5], 104);
    assert_eq!(context.registers[15], 114);
    put64(&mut bytes, 200, 0);
    assert!(UnwindContext::from_record(&bytes).is_err());
}

#[test]
fn large_metadata_reads_are_split_with_room_for_the_header_and_descriptor() {
    let mut memory = Memory::default();
    memory.regions.insert(BASE, vec![0x5a; 150_000]);
    let bytes = user::read_exact(&mut memory, BASE, 150_000).unwrap();
    assert_eq!(bytes, vec![0x5a; 150_000]);
    assert_eq!(memory.reads, 3);
    assert!(user::read_exact(&mut memory, u64::MAX - 10, 20).is_err());
    assert!(user::read_exact(&mut memory, BASE, 16 * 1024 * 1024 + 1).is_err());
}

#[test]
fn dynamic_unwind_uses_captured_runtime_entries_outside_loaded_modules() {
    let (mut memory, _) = unwind_fixture(&[4, 0x42], 4, 0);
    put64(memory.regions.get_mut(&STACK).unwrap(), 40, 0);
    let table = neo::unwind::DynamicTable {
        base: BASE,
        start: BASE + 0x1000,
        end: BASE + 0x1100,
        address: BASE + 0x3000,
        count: 1,
        kind: 0,
    };
    let result = neo::unwind::unwind_with_tables(
        &mut memory,
        &[],
        &[table.clone()],
        context(0x1020),
        8,
        true,
    );
    assert!(result.complete, "{}", result.stop);
    assert_eq!(result.frames[0].method, "dynamic_pdata");
    let result = neo::unwind::unwind_with_tables(
        &mut memory,
        &[],
        &[neo::unwind::DynamicTable { kind: 2, ..table }],
        context(0x1020),
        8,
        true,
    );
    assert!(!result.complete);
    assert!(result.stop.contains("callback provider"));
}
