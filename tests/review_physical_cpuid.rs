use std::arch::x86_64::__cpuid_count;

fn main() {
    let queries = [
        (0, 0),
        (1, 0),
        (7, 0),
        (0xd, 0),
        (0xd, 1),
        (0x15, 0),
        (0x8000_0000, 0),
        (0x8000_0001, 0),
        (0x8000_0007, 0),
        (0x8000_0008, 0),
        (0x4000_0000, 0),
        (0x4000_0001, 0),
        (0x4000_0003, 0),
        (0x4000_0004, 0),
        (0x4000_0009, 0),
        (0x4000_000a, 0),
        (0x4d48_5652, 0),
    ];
    println!(
        "{{\"scope\":\"Read-only CPUID from the current physical Windows session, not the failed boot\",\"leaves\":["
    );
    for (index, (leaf, subleaf)) in queries.iter().copied().enumerate() {
        let result = __cpuid_count(leaf, subleaf);
        let separator = if index + 1 == queries.len() { "" } else { "," };
        println!(
            "{{\"leaf\":\"{leaf:#x}\",\"subleaf\":\"{subleaf:#x}\",\"eax\":\"{:#010x}\",\"ebx\":\"{:#010x}\",\"ecx\":\"{:#010x}\",\"edx\":\"{:#010x}\"}}{separator}",
            result.eax, result.ebx, result.ecx, result.edx
        );
    }
    println!("]}}");
}
