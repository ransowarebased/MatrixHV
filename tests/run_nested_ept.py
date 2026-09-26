import json
from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "nested-ept-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/core/vt_resident.rs").read_text()
start = source.index('    ".Lresident_nested_resolve_ept02_violation:",')
end = source.index('    ".Lresident_nested_host_msr_list_is_mapped:",')
prepare_start = source.index('    ".Lresident_nested_prepare_ept02:",')
prepare_end = source.index('    ".Lresident_nested_activate_vmcs02_ept:",')
invept_start = source.index('    ".Lresident_nested_invalidate_ept12_context:",')
invept_end = source.index('    ".Lresident_dispatch_invept_all_contexts:",', invept_start)
assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, (
        source[prepare_start:prepare_end] + source[start:end] + source[invept_start:invept_end]
    ).splitlines())
    if line.startswith('"')
)
# Execute the production address walks; replace only privileged instructions.
assert assembly.count("vmread r8, rax") == 1
assert assembly.count("invept rax, xmmword ptr [rsp]") == 1
assembly = assembly.replace(
    "vmread r8, rax",
    "mov r8, qword ptr [r12 + {b_last_guest_physical_address}]\n"
    "mov eax, 1\ntest eax, eax",
).replace("invept rax, xmmword ptr [rsp]", "mov eax, 1\ntest eax, eax")
assembly += "\n.Lresident_dispatch_vmread_failed:\n.Lresident_dispatch_halt:\nud2\n"
(output / "resident-ept.S").write_text(assembly)
guest_start = source.index('    ".Lresident_nested_sync_vmcs02_guest_fields:",')
guest_end = source.index('    ".Lresident_nested_capture_vmcs02_guest_state:",')
table_start = source.index('    ".Lresident_nested_guest_state_table:",')
table_end = source.index('    ".Lresident_nested_host_state_table:",')
guest_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, (source[guest_start:guest_end] + source[table_start:table_end]).splitlines())
    if line.startswith('"')
)
assert guest_assembly.count("vmwrite rax, r11") == 1
guest_assembly = guest_assembly.replace(
    "vmwrite rax, r11",
    "mov qword ptr [r12 + {test_hardware} + rdx * 8], r11\n"
    "inc qword ptr [r12 + {test_writes}]\nmov eax, 1\ntest eax, eax",
)
guest_assembly += "\n.Lresident_dispatch_vmwrite_failed:\nud2\n"
capture_start = source.index('    ".Lresident_nested_capture_vmcs02_guest_state_loop:",')
capture_end = source.index('    "mov rax, {guest_gs_base}",', capture_start)
rare_start = source.index('    ".Lresident_nested_materialize_guest_field:",')
rare_end = source.index('    ".Lresident_nested_complete_vmcs02_msr_exit:",', rare_start)
guest_assembly += "\n" + "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, source[capture_start:capture_end].splitlines())
    if line.startswith('"')
) + (
    "\nmov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields]\n"
    "mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rax\n"
    "mov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields + 8]\n"
    "mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending} + 8], rax\nret\n"
)
guest_assembly += "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, source[rare_start:rare_end].splitlines())
    if line.startswith('"')
)
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
control_start = source.index('    ".Lresident_vmcs12_field_index:",')
control_end = source.index('    ".Lresident_nested_merge_vmcs02_controls:",')
lookup_start = source.index('    ".Lresident_vmcs12_field_index_table:",')
lookup_end = source.index('    ".balign', lookup_start)
control_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, (source[control_start:control_end] + source[lookup_start:lookup_end]).splitlines())
    if line.startswith('"')
)
assert control_assembly.count("vmwrite rax, r11") == 1
control_assembly = control_assembly.replace(
    "vmwrite rax, r11",
    "mov qword ptr [r12 + {test_hardware} + rdx * 8], r11\n"
    "inc qword ptr [r12 + {test_writes}]\n"
    "push rax\nmov eax, 1\ntest eax, eax\npop rax",
)
(output / "resident-controls.S").write_text(control_assembly)
vpid_start = source.index('    ".Lresident_nested_prepare_vpid02:",')
vpid_end = source.index('    ".Lresident_nested_compose_vmcs02_msr_lists:",')
invalidation_start = source.index('    ".Lresident_nested_invvpid_validate:",')
invalidation_end = source.index('    ".Lresident_nested_invalid_invalidation_operand:",')
vpid_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, (
        source[vpid_start:vpid_end] + source[invalidation_start:invalidation_end]
    ).splitlines())
    if line.startswith('"')
)
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
msr_start = source.index('    ".Lresident_nested_complete_vmcs02_msr_exit:",')
msr_end = source.index('    ".Lresident_nested_restore_l1_host_state:",')
mapped_start = source.index('    ".Lresident_nested_host_msr_list_is_mapped:",')
mapped_end = source.index('    ".Lresident_nested_exit_store_list_is_safe:",')
msr_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, (
        source[msr_start:msr_end] + source[mapped_start:mapped_end]
    ).splitlines())
    if line.startswith('"')
)
msr_assembly = msr_assembly.replace(
    "vmwrite rax, r11",
    "inc qword ptr [r12 + {test_writes}]\n"
    "mov qword ptr [r12 + {test_hardware} + rax * 8], r11\n"
    "push rax\nmov eax, 1\ntest eax, eax\npop rax",
)
msr_assembly += "\n.data\n.balign 8\nmatrixhv_resident_island_msr_switch_count:\n.quad 1\n.text\n"
(output / "resident-msr-exit.S").write_text(msr_assembly)
address_start = source.index('    ".Lresident_nested_physical_address_is_valid:",')
address_end = source.index('    ".Lresident_nested_prepare_ept02:",')
address_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, source[address_start:address_end].splitlines())
    if line.startswith('"')
)
(output / "resident-address.S").write_text(address_assembly)
snapshot_start = source.index('    ".Lresident_nested_snapshot_vmcs01_effective_state:",')
snapshot_end = source.index('    ".Lresident_nested_sync_vmcs02_guest_state:",')
snapshot_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, source[snapshot_start:snapshot_end].splitlines())
    if line.startswith('"')
)
snapshot_assembly = snapshot_assembly.replace(
    "vmread r11, rax",
    "inc qword ptr [r12 + {test_reads}]\n"
    "mov r11, qword ptr [r12 + {test_hardware} + rax * 8]\n"
    "mov eax, 1\ntest eax, eax",
)
(output / "resident-snapshot.S").write_text(snapshot_assembly)
success_start = source.index('    ".Lresident_nested_succeed:",')
success_end = source.index('    ".Lresident_nested_inject_pf_write:",', success_start)
success_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, source[success_start:success_end].splitlines())
    if line.startswith('"')
)
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
bitmap_start = source.index('    ".Lresident_nested_merge_msr_bitmap_loop:",')
bitmap_end = source.index('    "jmp .Lresident_nested_use_composed_msr_bitmap",', bitmap_start)
bitmap_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, source[bitmap_start:bitmap_end].splitlines())
    if line.startswith('"')
)
(output / "resident-msr-bitmap.S").write_text(bitmap_assembly + "\nret\n")
executable = output / "nested-ept-tests.exe"
subprocess.run(
    ["rustc", "--edition=2024", "--test", str(project / "tests/nested_ept.rs"),
     "-o", str(executable)], check=True, cwd=project,
)
subprocess.run([str(executable)], check=True, cwd=project)
