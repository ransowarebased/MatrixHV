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
)
vpid_assembly += (
    "\n.Lresident_nested_succeed:\nxor eax, eax\nret\n"
    ".Lresident_nested_invalid_invalidation_operand:\nmov eax, 1\nret\n"
)
(output / "resident-vpid.S").write_text(vpid_assembly)
msr_start = source.index('    ".Lresident_nested_complete_vmcs02_msr_exit:",')
msr_end = source.index('    ".Lresident_nested_activate_vmcs01_msr_entry:",')
mapped_start = source.index('    ".Lresident_nested_host_msr_list_is_mapped:",')
mapped_end = source.index('    ".Lresident_nested_exit_store_list_is_safe:",')
msr_assembly = "\n".join(
    json.loads(line.rstrip(","))
    for line in map(str.strip, (
        source[msr_start:msr_end] + source[mapped_start:mapped_end]
    ).splitlines())
    if line.startswith('"')
)
(output / "resident-msr-exit.S").write_text(msr_assembly)
executable = output / "nested-ept-tests.exe"
subprocess.run(
    ["rustc", "--edition=2024", "--test", str(project / "tests/nested_ept.rs"),
     "-o", str(executable)], check=True, cwd=project,
)
subprocess.run([str(executable)], check=True, cwd=project)
