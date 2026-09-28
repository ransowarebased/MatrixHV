use std::arch::x86_64::__cpuid_count;
use std::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetActiveProcessorCount(group_number: u16) -> u32;
    fn GetSystemFirmwareTable(provider: u32, table: u32, buffer: *mut c_void, size: u32) -> u32;
}

fn main() {
    println!("active_processors={}", unsafe {
        GetActiveProcessorCount(0xffff)
    });
    let status = __cpuid_count(0x4d48_5652, 0);
    if status.eax == 0x4d48_5631 && status.edx >= 2 {
        let low = __cpuid_count(0x4d48_5652, 1);
        let high = __cpuid_count(0x4d48_5652, 2);
        let merge = |low: u32, high: u32| u64::from(low) | (u64::from(high) << 32);
        println!("matrixhv_init_cpu_mask={:#018x}", merge(low.eax, high.eax));
        println!("matrixhv_sipi_cpu_mask={:#018x}", merge(low.ebx, high.ebx));
        println!(
            "matrixhv_post_ebs_cpu_mask={:#018x}",
            merge(low.ecx, high.ecx)
        );
        println!(
            "matrixhv_halted_cpu_mask={:#018x}",
            merge(low.edx, high.edx)
        );
        let fault = __cpuid_count(0x4d48_5652, 3);
        println!(
            "matrixhv_failed_cpu={:#x} reason={:#x} qualification={:#x} stop={:#x}",
            fault.eax, fault.ebx, fault.ecx, fault.edx
        );
    }
    for (leaf, count) in [
        (0, 1),
        (1, 1),
        (4, 8),
        (7, 1),
        (0xb, 4),
        (0x15, 1),
        (0x16, 1),
        (0x1f, 4),
        (0x8000_0007, 1),
        (0x4d48_5652, 1),
    ] {
        for subleaf in 0..count {
            let value = __cpuid_count(leaf, subleaf);
            println!(
                "cpuid={leaf:08x}/{subleaf} eax={:08x} ebx={:08x} ecx={:08x} edx={:08x}",
                value.eax, value.ebx, value.ecx, value.edx
            );
            if leaf == 4 && value.eax & 31 == 0 {
                break;
            }
        }
    }
    let provider = u32::from_be_bytes(*b"ACPI");
    let table = u32::from_le_bytes(*b"APIC");
    let size = unsafe { GetSystemFirmwareTable(provider, table, std::ptr::null_mut(), 0) };
    assert!(size >= 44, "MADT unavailable");
    let mut data = vec![0_u8; size as usize];
    assert_eq!(
        unsafe { GetSystemFirmwareTable(provider, table, data.as_mut_ptr().cast(), size) },
        size
    );
    let mut cursor = 44;
    let mut enabled = 0;
    while cursor + 2 <= data.len() {
        let length = data[cursor + 1] as usize;
        assert!(
            length >= 2 && cursor + length <= data.len(),
            "Invalid MADT record"
        );
        let entry = &data[cursor..cursor + length];
        let processor = match (entry[0], length) {
            (0, 8) => Some((
                u32::from(entry[3]),
                u32::from_le_bytes(entry[4..8].try_into().unwrap()),
            )),
            (9, 16) => Some((
                u32::from_le_bytes(entry[4..8].try_into().unwrap()),
                u32::from_le_bytes(entry[8..12].try_into().unwrap()),
            )),
            _ => None,
        };
        if let Some((apic_id, flags)) = processor {
            println!("madt_apic_id={apic_id} flags={flags:#x}");
            enabled += u32::from(flags & 1 != 0);
        }
        cursor += length;
    }
    println!("madt_enabled_processors={enabled}");
}
