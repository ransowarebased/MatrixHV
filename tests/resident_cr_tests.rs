use core::arch::global_asm;

global_asm!(include_str!("../builds/resident-msr-tests/resident-cr.S"));

unsafe extern "C" {
    fn test_write_cr(context: *mut u64, registers: *const u64) -> u32;
}

const VMCS: usize = 16;
const CR0_SHADOW: usize = VMCS + 1;
const CR0: usize = VMCS + 2;
const CR4: usize = VMCS + 3;
const CR4_SHADOW: usize = VMCS + 4;
const CR0_MASK: usize = VMCS + 5;
const CR4_MASK: usize = VMCS + 6;
const EFER: usize = VMCS + 7;
const ENTRY: usize = VMCS + 8;
const SECONDARY: usize = VMCS + 9;
const VPID: usize = VMCS + 10;
const CS_AR: usize = VMCS + 11;
const CR3: usize = VMCS + 12;
const TR_AR: usize = VMCS + 13;
const PDPTR0: usize = VMCS + 14;
const PDPTE_HOST: usize = 39;
const PE: u64 = 1;
const ET: u64 = 1 << 4;
const NE: u64 = 1 << 5;
const WP: u64 = 1 << 16;
const NW: u64 = 1 << 29;
const CD: u64 = 1 << 30;
const PG: u64 = 1 << 31;
const PAE: u64 = 1 << 5;
const LA57: u64 = 1 << 12;
const VMXE: u64 = 1 << 13;
const PCIDE: u64 = 1 << 17;
const CET: u64 = 1 << 23;
const LME: u64 = 1 << 8;
const LMA: u64 = 1 << 10;
const CS_LONG: u64 = 1 << 13;

fn context() -> [u64; 40] {
    let mut context = [0; 40];
    context[2] = PE | NE | PG;
    context[3] = u64::from(u32::MAX);
    context[4] = VMXE;
    context[5] = 0x01ff_ffff;
    context[13] = 48;
    context[CR0] = PE | ET | NE;
    context[CR0_SHADOW] = PE | ET | NE;
    context[CR0_MASK] = PG | CD | NW | NE | PE;
    context[CR4] = VMXE;
    context[CR4_MASK] = VMXE;
    context[TR_AR] = 0x8b;
    context[SECONDARY] = 1 << 5;
    context[VPID] = 1;
    context
}

fn write(context: &mut [u64; 40], control: u64, value: u64) -> u32 {
    context[0] = control;
    let mut registers = [0; 15];
    registers[0] = value;
    unsafe { test_write_cr(context.as_mut_ptr(), registers.as_ptr()) }
}

fn reject(mut context: [u64; 40], control: u64, value: u64) {
    context[0] = control;
    let before = context;
    assert_eq!(write(&mut context, control, value), 0, "CR{control}={value:#x}");
    assert_eq!(context, before, "a fault must preserve state and RIP");
}

#[test]
fn invalid_cr0_combinations_fault_before_writes_or_rip_advance() {
    reject(context(), 0, PG | ET | NE);
    reject(context(), 0, NW | PE | ET | NE);
}

#[test]
fn invalid_cr4_reserved_bits_fault_before_shadow_and_nested_state_changes() {
    let mut long_context = context();
    long_context[EFER] = LME | LMA;
    long_context[CS_AR] = CS_LONG;
    long_context[CR4] |= PAE;
    reject(long_context, 4, VMXE | PAE | (1 << 63));
    let mut context = context();
    context[5] &= !(1 << 22);
    reject(context, 4, VMXE | (1 << 22));
}

fn long_context() -> [u64; 40] {
    let mut context = context();
    context[CR0] |= PG;
    context[CR0_SHADOW] |= PG;
    context[CR4] |= PAE;
    context[EFER] = LME | LMA;
    context[CS_AR] = CS_LONG;
    context[ENTRY] = 1 << 9;
    context
}

fn pae_context(pdpte: &[u64; 4]) -> [u64; 40] {
    let mut context = context();
    context[CR4] |= PAE;
    context[CR4_SHADOW] = PAE;
    context[CR3] = 0x4000;
    context[PDPTE_HOST] = pdpte.as_ptr() as u64;
    context
}

fn loaded_pdptes(context: &[u64; 40]) -> [u64; 4] {
    [
        context[PDPTR0],
        context[PDPTR0 + 2],
        context[PDPTR0 + 4],
        context[PDPTR0 + 6],
    ]
}

#[test]
fn entering_pae_and_changing_cache_bits_reload_all_pdptes() {
    let pdpte = [0x2001, 0x3001, 0, 0x5001];
    let mut context = pae_context(&pdpte);
    assert_eq!(write(&mut context, 0, PE | ET | NE | PG), 1);
    assert_eq!(loaded_pdptes(&context), pdpte);

    let updated = [0x6001, 0x7001, 0x8001, 0];
    context[PDPTE_HOST] = updated.as_ptr() as u64;
    assert_eq!(write(&mut context, 0, PE | ET | NE | PG | CD), 1);
    assert_eq!(loaded_pdptes(&context), updated);
}

#[test]
fn cr4_pae_and_pge_changes_reload_pdptes_only_in_legacy_pae() {
    let pdpte = [0x2001, 0, 0, 0];
    let mut context = pae_context(&pdpte);
    context[CR0] |= PG;
    context[CR0_SHADOW] |= PG;
    context[CR4] = VMXE;
    context[CR4_SHADOW] = 0;
    assert_eq!(write(&mut context, 4, PAE), 1);
    assert_eq!(loaded_pdptes(&context), pdpte);

    let updated = [0, 0x9001, 0, 0];
    context[PDPTE_HOST] = updated.as_ptr() as u64;
    assert_eq!(write(&mut context, 4, PAE | (1 << 7)), 1);
    assert_eq!(loaded_pdptes(&context), updated);
}

#[test]
fn invalid_pdpte_faults_before_any_vmcs_write() {
    let pdpte = [0x2001, 0x3003, 0, 0];
    reject(pae_context(&pdpte), 0, PE | ET | NE | PG);
    let mut context = pae_context(&pdpte);
    context[CR0] |= PG;
    context[CR0_SHADOW] |= PG;
    reject(context, 4, PAE | (1 << 7));
}

#[test]
fn unmapped_pdpte_source_does_not_publish_guest_state() {
    let pdpte = [0x2001, 0, 0, 0];
    let mut context = pae_context(&pdpte);
    context[PDPTE_HOST] = 0;
    context[0] = 0;
    let before = context;
    assert_eq!(write(&mut context, 0, PE | ET | NE | PG), 3);
    assert_eq!(context, before);
}

#[test]
fn cr0_cache_and_paging_combinations_follow_architectural_fault_rules() {
    for flags in 0..16 {
        let value = ET | NE | u64::from(flags & 1 != 0) * PE
            | u64::from(flags & 2 != 0) * PG
            | u64::from(flags & 4 != 0) * NW
            | u64::from(flags & 8 != 0) * CD;
        let valid = value & (PE | PG) != PG && value & (NW | CD) != NW;
        let mut context = context();
        assert_eq!(write(&mut context, 0, value), u32::from(valid));
        assert_eq!(context[7], if valid { 4 } else { 0 });
        assert_eq!(context[9], u64::from(valid));
        assert_eq!(context[8], u64::from(valid));
    }
}

#[test]
fn operand_width_and_cr0_ignored_bits_match_real_and_long_modes() {
    let mut legacy = context();
    assert_eq!(write(&mut legacy, 0, (1 << 63) | PE | NE | 0x1ffa_ffc0), 1);
    assert_eq!(legacy[CR0_SHADOW], PE | ET | NE);
    assert_eq!(legacy[CR0], PE | ET | NE);
    let mut legacy = context();
    assert_eq!(write(&mut legacy, 4, (1 << 63) | PAE), 1);
    assert_eq!(legacy[CR4_SHADOW], PAE);
    assert_eq!(legacy[CR4], PAE | VMXE);
    reject(long_context(), 0, (1 << 32) | PE | ET | NE | PG);
}

#[test]
fn disabling_paging_observes_effective_pcid_and_current_code_mode() {
    reject(long_context(), 0, PE | ET | NE);
    let mut compatibility = long_context();
    compatibility[CS_AR] = 0;
    compatibility[CR4] |= PCIDE;
    compatibility[CR4_SHADOW] = 0;
    reject(compatibility, 0, PE | ET | NE);
    let mut compatibility = long_context();
    compatibility[CS_AR] = 0;
    assert_eq!(write(&mut compatibility, 0, PE | ET | NE), 1);
    assert_eq!(compatibility[EFER], LME);
    assert_eq!(compatibility[ENTRY] & (1 << 9), 0);
}

#[test]
fn long_mode_activation_requires_pae_legacy_code_and_a_32_bit_tss() {
    let mut missing_pae = context();
    missing_pae[EFER] = LME;
    reject(missing_pae, 0, PE | ET | NE | PG);
    let mut long_code = context();
    long_code[CR4] |= PAE;
    long_code[EFER] = LME;
    long_code[CS_AR] = CS_LONG;
    reject(long_code, 0, PE | ET | NE | PG);
    for tss_type in [1, 3] {
        let mut short_tss = context();
        short_tss[CR4] |= PAE;
        short_tss[EFER] = LME;
        short_tss[TR_AR] = 0x80 | tss_type;
        reject(short_tss, 0, PE | ET | NE | PG);
    }
    let mut valid = context();
    valid[CR4] |= PAE;
    valid[EFER] = LME;
    assert_eq!(write(&mut valid, 0, PE | ET | NE | PG), 1);
    assert_eq!(valid[EFER], LME | LMA);
    assert_eq!(valid[ENTRY] & (1 << 9), 1 << 9);
}

#[test]
fn cr4_long_mode_transitions_reject_pae_clear_and_la57_changes() {
    reject(long_context(), 4, VMXE);
    reject(long_context(), 4, VMXE | PAE | LA57);
    let mut five_level = long_context();
    five_level[CR4] |= LA57;
    reject(five_level, 4, VMXE | PAE);
    let mut valid = context();
    assert_eq!(write(&mut valid, 4, PAE | LA57), 1);
    assert_eq!(valid[1], PAE | LA57);
    assert_eq!(valid[CR4_SHADOW], PAE | LA57);
}

#[test]
fn pcid_enable_checks_lma_and_cr3_only_on_the_zero_to_one_transition() {
    reject(context(), 4, PAE | VMXE | PCIDE);
    let mut nonzero_pcid = long_context();
    nonzero_pcid[CR3] = 0x1234_5001;
    reject(nonzero_pcid, 4, VMXE | PAE | PCIDE);
    let mut valid = long_context();
    valid[CR3] = 0x1234_5000;
    assert_eq!(write(&mut valid, 4, VMXE | PAE | PCIDE), 1);
    let mut already_enabled = long_context();
    already_enabled[CR4] |= PCIDE;
    already_enabled[CR3] = 0x1234_5001;
    assert_eq!(write(&mut already_enabled, 4, VMXE | PAE | PCIDE), 1);
}

#[test]
fn vmx_root_writes_retain_the_advertised_fixed_bits() {
    let mut active = long_context();
    active[6] = 1;
    reject(active, 4, PAE);
    let mut active = context();
    active[6] = 1;
    reject(active, 0, PE | ET | NE);
    let mut active = long_context();
    active[6] = 1;
    active[3] &= !WP;
    reject(active, 0, PE | ET | NE | PG | WP);
    let mut active = long_context();
    active[6] = 1;
    assert_eq!(write(&mut active, 0, PE | ET | NE | PG | CD), 1);
    assert_eq!(write(&mut active, 4, VMXE | PAE), 1);
}

#[test]
fn cet_requires_effective_write_protection_without_using_stale_shadows() {
    reject(context(), 4, VMXE | CET);
    let mut enabled = context();
    enabled[CR4] |= CET;
    enabled[CR4_SHADOW] = 0;
    reject(enabled, 0, PE | ET | NE);
    let mut enabled = context();
    enabled[CR0] |= WP;
    enabled[CR0_SHADOW] &= !WP;
    assert_eq!(write(&mut enabled, 4, VMXE | CET), 1);
}

#[test]
fn every_gpr_source_and_the_guest_rsp_are_decoded_without_losing_the_frame() {
    for control in [0, 4] {
        for source in 0..16 {
            let mut context = context();
            context[0] = control | (source << 8);
            let value = if control == 0 { PE | ET | NE | CD } else { PAE };
            let mut registers = [0; 15];
            if source == 4 {
                context[VMCS] = value;
            } else {
                registers[if source < 4 { source } else { source - 1 } as usize] = value;
            }
            assert_eq!(unsafe { test_write_cr(context.as_mut_ptr(), registers.as_ptr()) }, 1);
            assert_eq!(context[if control == 0 { CR0_SHADOW } else { CR4_SHADOW }], value);
            assert_eq!(context[8], 1);
            assert_eq!(context[9], 1);
            assert_eq!(context[10], 1);
            assert_eq!(context[11], 1);
            assert_eq!(context[12], 0);
        }
    }
}

#[test]
fn successful_cr_writes_skip_invvpid_when_the_control_is_disabled() {
    let mut context = context();
    context[SECONDARY] = 0;
    assert_eq!(write(&mut context, 4, PAE), 1);
    assert_eq!(context[8], 0);
    assert_eq!(context[9], 1);
}
