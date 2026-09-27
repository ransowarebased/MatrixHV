from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "nested-ept-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/asm/resident_island.S").read_text()
switch_source = (project / "src/asm/eptp_switch.S").read_text()
exit_msr_start = source.index('.Lresident_nested_capture_vmcs02_guest_state:')
exit_msr_end = source.index('lea rsi, [rip + .Lresident_nested_guest_state_table]', exit_msr_start)
exit_msr_assembly = source[exit_msr_start:exit_msr_end].replace(
    "vmread r11, rax",
    "mov r11, qword ptr [r12 + {test_hardware} + rax * 8]\n"
    "push rax\nmov eax, 1\ntest eax, eax\npop rax",
)
(output / "resident-exit-msrs.S").write_text(exit_msr_assembly + "ret\n")
start = source.index('.Lresident_nested_resolve_ept02_violation:')
end = source.index('.Lresident_nested_host_msr_list_is_mapped:')
prepare_start = switch_source.index('.Lresident_nested_prepare_ept02:')
prepare_end = switch_source.index('.Lresident_nested_activate_vmcs02_ept:')
invept_start = source.index('.Lresident_nested_invalidate_ept12_context:')
invept_end = source.index('.Lresident_dispatch_invvpid:', invept_start)
assembly = (switch_source[prepare_start:prepare_end] + source[start:end] + source[invept_start:invept_end]).strip()
vmfunc_start = switch_source.index('.Lresident_nested_switch_eptp:')
vmfunc_end = switch_source.index('.Lresident_nested_prepare_ept02:', vmfunc_start)
address_start = source.index('.Lresident_nested_physical_address_is_valid:')
address_end = source.index('.Lresident_nested_resolve_ept02_violation:', address_start)
vmfunc_assembly = (switch_source[vmfunc_start:vmfunc_end] + source[address_start:address_end]).replace(
    '.Lresident_nested_physical_address_is_valid', '.Ltest_vmfunc_physical_address_is_valid'
).replace('.Lresident_nested_address_width_is_valid', '.Ltest_vmfunc_address_width_is_valid')
for suffix in ('invalid', 'valid'):
    vmfunc_assembly = vmfunc_assembly.replace(
        '.Lresident_nested_physical_address_' + suffix,
        '.Ltest_vmfunc_physical_address_' + suffix,
    )
assembly += '\n' + vmfunc_assembly
native_start = switch_source.index('.Lresident_nested_refresh_eptp_list:')
native_end = switch_source.index('.Lresident_nested_vmfunc:')
native = switch_source[native_start:native_end]
native = native.replace('.Lresident_dispatch_vmwrite_failed', '.Lresident_dispatch_vmread_failed')
native = native.replace(
    'vmwrite rax, r11',
    'mov qword ptr [r12 + {test_native_vmcs} + rax * 8], r11\n'
    'push rax\nmov eax, 1\ntest eax, eax\npop rax',
).replace(
    'vmread r10, rax',
    'mov r10, qword ptr [r12 + {test_native_vmcs} + rax * 8]\n'
    'push rax\nmov eax, 1\ntest eax, eax\npop rax',
)
assembly += '\n' + native
assembly = assembly.replace(
    '[rip + .Lresident_eptp_lists_live]', '[r12 + {test_lists_live}]'
)
flush_start = switch_source.index('.Lresident_nested_eptp_sync_flush_local:')
flush_end = switch_source.index('.Lresident_nested_eptp_sync_enter:', flush_start)
assembly += '\n' + switch_source[flush_start:flush_end]
assembly += (
    '\n.Lresident_nested_eptp_sync_acquire:\n'
    'inc qword ptr [r12 + {test_sync_requests}]\n'
    'mov rax, qword ptr [r12 + {test_sync_result}]\nret\n'
    '.Lresident_nested_eptp_sync_end:\n'
    'inc qword ptr [r12 + {test_sync_releases}]\nret\n'
    '.Lresident_nested_eptp_sync_poll:\nret\n'
)
macro_start = source.index('.macro resident_telemetry_counter ')
macro_end = source.index('.endm', macro_start) + len('.endm')
assembly = source[macro_start:macro_end] + "\n" + assembly
# Execute the production address walks; replace only privileged instructions.
assert assembly.count("vmread r8, rax") == 1
assert assembly.count("invept rax, xmmword ptr [rsp]") == 2
assembly = assembly.replace(
    "vmread r8, rax",
    "mov r8, qword ptr [r12 + {b_last_guest_physical_address}]\n"
    "mov eax, 1\ntest eax, eax",
).replace("invept rax, xmmword ptr [rsp]", "mov eax, 1\ntest eax, eax")
assembly += "\n.Lresident_dispatch_vmread_failed:\n.Lresident_dispatch_halt:\nud2\n"
(output / "resident-ept.S").write_text(assembly)
guest_start = source.index('.Lresident_nested_sync_vmcs02_guest_fields:')
guest_end = source.index('.Lresident_nested_capture_vmcs02_guest_state:')
table_start = source.index('.Lresident_nested_guest_state_table:')
table_end = source.index('.Lresident_nested_host_state_table:')
guest_assembly = (source[guest_start:guest_end] + source[table_start:table_end]).strip()
assert guest_assembly.count("vmwrite rax, r11") == 1
guest_assembly = guest_assembly.replace(
    "vmwrite rax, r11",
    "mov qword ptr [r12 + {test_hardware} + rdx * 8], r11\n"
    "inc qword ptr [r12 + {test_writes}]\nmov eax, 1\ntest eax, eax",
)
guest_assembly += "\n.Lresident_dispatch_vmwrite_failed:\nud2\n"
capture_start = source.index('.Lresident_nested_capture_vmcs02_guest_state_loop:')
capture_end = source.index('mov rax, {guest_gs_base}', capture_start)
rare_start = source.index('.Lresident_nested_materialize_guest_field:')
rare_end = source.index('.Lresident_nested_complete_vmcs02_msr_exit:', rare_start)
guest_assembly += "\n" + source[capture_start:capture_end].strip() + (
    "\nmov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields]\n"
    "mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rax\n"
    "mov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields + 8]\n"
    "mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending} + 8], rax\nret\n"
)
guest_assembly += source[rare_start:rare_end].strip()
assert guest_assembly.count("vmread r11, rax") == 3
guest_assembly = guest_assembly.replace(
    "vmread r11, rax",
    "cmp qword ptr [r12 + {test_selected_vmcs}], 2\n"
    "jne .Lresident_dispatch_halt\n"
    "mov r11, qword ptr [r12 + {test_hardware} + rdx * 8]\n"
    "inc qword ptr [r12 + {test_reads}]\n"
    "push rax\nmov eax, 1\ntest eax, eax\npop rax",
)
for region in ("01", "02"):
    guest_assembly = guest_assembly.replace(
        "vmptrld [r12 + {b_nested_vmcs" + region + "_region}]",
        "mov rax, qword ptr [r12 + {b_nested_vmcs" + region + "_region}]\n"
        "mov qword ptr [r12 + {test_selected_vmcs}], rax\n"
        "inc qword ptr [r12 + {test_switches}]\n"
        "mov eax, 1\ntest eax, eax",
    )
(output / "resident-guest.S").write_text(guest_assembly)
control_start = source.index('.Lresident_vmcs12_field_index:')
control_end = source.index('.Lresident_nested_merge_vmcs02_controls:')
lookup_start = source.index('.Lresident_vmcs12_field_index_table:')
lookup_end = source.index('.balign', lookup_start)
control_assembly = (source[control_start:control_end] + source[lookup_start:lookup_end]).strip()
assert control_assembly.count("vmwrite rax, r11") == 1
control_assembly = control_assembly.replace(
    "vmwrite rax, r11",
    "mov qword ptr [r12 + {test_hardware} + rdx * 8], r11\n"
    "inc qword ptr [r12 + {test_writes}]\n"
    "push rax\nmov eax, 1\ntest eax, eax\npop rax",
)
(output / "resident-controls.S").write_text(control_assembly)
vpid_start = source.index('.Lresident_nested_prepare_vpid02:')
vpid_end = source.index('.Lresident_nested_compose_vmcs02_msr_lists:')
invalidation_start = source.index('.Lresident_nested_invvpid_validate:')
invalidation_end = source.index('.Lresident_nested_invalid_invalidation_operand:')
vpid_assembly = (source[vpid_start:vpid_end] + source[invalidation_start:invalidation_end]).strip()
assert vpid_assembly.count("invvpid rax, xmmword ptr [rsp]") == 1
vpid_assembly = vpid_assembly.replace(
    "invvpid rax, xmmword ptr [rsp]",
    "inc qword ptr [r12 + {test_flushes}]\n"
    "mov qword ptr [r12 + {test_kind}], rax\n"
    "mov rax, qword ptr [rsp]\nmov qword ptr [r12 + {test_tag}], rax\n"
    "mov eax, 1\ntest eax, eax",
).replace(
    "call .Lresident_nested_write_vmcs02_control",
    "mov qword ptr [r12 + {test_selected_tag}], r11",
)
vpid_assembly += (
    "\n.Lresident_nested_succeed:\nxor eax, eax\nret\n"
    ".Lresident_nested_invalid_invalidation_operand:\nmov eax, 1\nret\n"
)
(output / "resident-vpid.S").write_text(vpid_assembly)
msr_start = source.index('.Lresident_nested_complete_vmcs02_msr_exit:')
msr_end = source.index('.Lresident_nested_restore_l1_host_state:')
mapped_start = source.index('.Lresident_nested_host_msr_list_is_mapped:')
mapped_end = source.index('.Lresident_nested_exit_store_list_is_safe:')
msr_assembly = (source[msr_start:msr_end] + source[mapped_start:mapped_end]).strip()
msr_assembly = msr_assembly.replace(
    'call .Lresident_nested_eptp_before_root_write',
    'call .Ltest_msr_root_write',
)
msr_assembly += '\n.Ltest_msr_root_write:\nret\n'
msr_assembly = msr_assembly.replace(
    "vmwrite rax, r11",
    "inc qword ptr [r12 + {test_writes}]\n"
    "mov qword ptr [r12 + {test_hardware} + rax * 8], r11\n"
    "push rax\nmov eax, 1\ntest eax, eax\npop rax",
)
msr_assembly += "\n.data\n.balign 8\nmatrixhv_resident_island_msr_switch_count:\n.quad 1\n.text\n"
(output / "resident-msr-exit.S").write_text(msr_assembly)
address_start = source.index('.Lresident_nested_physical_address_is_valid:')
address_end = source.index('.Lresident_nested_resolve_ept02_violation:', address_start)
address_assembly = source[address_start:address_end].strip()
(output / "resident-address.S").write_text(address_assembly)
snapshot_start = source.index('.Lresident_nested_snapshot_vmcs01_effective_state:')
snapshot_end = source.index('.Lresident_nested_sync_vmcs02_guest_state:')
snapshot_assembly = source[snapshot_start:snapshot_end].strip()
snapshot_assembly = snapshot_assembly.replace(
    "vmread r11, rax",
    "inc qword ptr [r12 + {test_reads}]\n"
    "mov r11, qword ptr [r12 + {test_hardware} + rax * 8]\n"
    "mov eax, 1\ntest eax, eax",
)
(output / "resident-snapshot.S").write_text(snapshot_assembly)
success_start = source.index('.Lresident_nested_succeed:')
success_end = source.index('.Lresident_nested_inject_pf_write:', success_start)
success_assembly = source[success_start:success_end].strip()
success_assembly = success_assembly.replace(
    ".Lresident_nested_succeed:", ".Ltest_nested_success:"
).replace(
    "vmread r11, rax",
    "mov r11, qword ptr [r12 + {test_rflags}]\nmov eax, 1\ntest eax, eax",
).replace(
    "vmwrite rax, r11",
    "mov qword ptr [r12 + {test_rflags}], r11\n"
    "inc qword ptr [r12 + {test_writes}]\nmov eax, 1\ntest eax, eax",
).replace(
    "call .Lresident_advance_guest_rip", "inc qword ptr [r12 + {test_advances}]"
).replace("jmp .Lresident_dispatch_resume", "ret")
(output / "resident-success.S").write_text(success_assembly)
bitmap_start = source.index('.Lresident_nested_merge_msr_bitmap_loop:')
bitmap_end = source.index('jmp .Lresident_nested_use_composed_msr_bitmap', bitmap_start)
bitmap_assembly = source[bitmap_start:bitmap_end].strip()
(output / "resident-msr-bitmap.S").write_text(bitmap_assembly + "\nret\n")
executable = output / "nested-ept-tests.exe"
merge_start = source.index('.Lresident_nested_merge_vmcs02_controls:')
primary_start = source.index('mov rax, {cpu_based_vm_exec_control}', merge_start)
primary_end = source.index('bt r11, 21', primary_start)
secondary_start = source.index('mov rax, {secondary_vm_exec_control}', primary_end)
secondary_end = source.index('mov rax, {vm_exit_controls}', secondary_start)
merge_assembly = (source[primary_start:primary_end] + source[secondary_start:secondary_end]).strip()
merge_assembly = merge_assembly.replace(
    ".Lresident_nested_write_vmcs02_control", ".Ltest_capture_vmcs02_control"
)
merge_assembly += (
    "\nret\n.Ltest_capture_vmcs02_control:\n"
    "mov qword ptr [r12 + {test_hardware} + rax * 8], r11\nret\n"
)
(output / "resident-intercepts.S").write_text(merge_assembly)
policy_start = source.index('bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 28', merge_start)
policy_end = source.index('.Lresident_nested_merge_msr_bitmap_done:', policy_start)
policy_assembly = source[policy_start:policy_end].replace(
    '.Lresident_nested_', '.Ltest_msr_policy_'
)
policy_assembly += (
    '\nret\n.Ltest_msr_policy_host_page_is_mapped:\n'
    'mov eax, dword ptr [r12 + {test_mapped}]\nret\n'
    '.Ltest_msr_policy_write_vmcs02_control:\n'
    'mov qword ptr [r12 + {test_selected}], r11\nret\n'
)
(output / "resident-msr-policy.S").write_text(policy_assembly)
subprocess.run(
    ["rustc", "--edition=2024", "--test", str(project / "tests/nested_ept.rs"),
     "-o", str(executable)], check=True, cwd=project,
)
subprocess.run([str(executable)], check=True, cwd=project)
