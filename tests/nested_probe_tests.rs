core::arch::global_asm!(include_str!("../builds/nested-probe-tests/probe.S"));

#[repr(C)]
struct ProbeContext {
    vmxon_gpa: u64,
    rip: u64,
    reason: u64,
    vmxon_hpa: u64,
    translations: u64,
}

unsafe extern "win64" {
    fn test_probe_invept(context: &mut ProbeContext) -> u32;
    fn test_probe_invvpid(context: &mut ProbeContext) -> u32;
}

#[test]
fn invalidation_probe_metadata_uses_the_translated_vmxon_page() {
    let stale_page = [0_u64; 17];
    let mut host_page = [0_u64; 17];
    let rip = 0x1234_5678;
    host_page[11] = rip;
    host_page[15] = rip;
    for (route, reason) in [
        (test_probe_invept as unsafe extern "win64" fn(&mut ProbeContext) -> u32, 50),
        (test_probe_invvpid as unsafe extern "win64" fn(&mut ProbeContext) -> u32, 53),
    ] {
        let mut context = ProbeContext {
            vmxon_gpa: stale_page.as_ptr() as u64,
            rip,
            reason,
            vmxon_hpa: host_page.as_ptr() as u64,
            translations: 0,
        };
        // The modeled guest and host pages are live inline arrays, with distinct addresses.
        assert_eq!(unsafe { route(&mut context) }, 1);
        assert_eq!(context.translations, 1);
    }
}

#[test]
fn revoked_vmxon_mapping_uses_regular_invalidation_without_reading_stale_metadata() {
    let mut stale_page = [0_u64; 17];
    let rip = 0x1234_5678;
    stale_page[11] = rip;
    stale_page[15] = rip;
    for (route, reason) in [
        (test_probe_invept as unsafe extern "win64" fn(&mut ProbeContext) -> u32, 50),
        (test_probe_invvpid as unsafe extern "win64" fn(&mut ProbeContext) -> u32, 53),
    ] {
        let mut context = ProbeContext {
            vmxon_gpa: stale_page.as_ptr() as u64,
            rip,
            reason,
            vmxon_hpa: 0,
            translations: 0,
        };
        assert_eq!(unsafe { route(&mut context) }, 2);
        assert_eq!(context.translations, 1);
        context.reason = 0;
        assert_eq!(unsafe { route(&mut context) }, 3);
    }
}
