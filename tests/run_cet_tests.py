"""Exercise the production nested CET VMCS transfer and saved-MSR paths."""

from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds/cet-state-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/asm/nested.S").read_text(encoding="utf-8")
transfer_start = source.index(".Lresident_nested_select_vmcs_inherit_cet:")
transfer_end = source.index(".Lresident_nested_sync_vmcs02_guest_state:", transfer_start)
saved_start = source.index(".Lresident_nested_read_saved_msr:")
saved_end = source.index(".Lresident_nested_store_current_vmcs12:", saved_start)
assembly = source[transfer_start:transfer_end] + source[saved_start:saved_end]
fields = {
    "vm_entry_controls": 0, "guest_s_cet": 1, "guest_ssp": 2,
    "guest_interrupt_ssp_table": 3, "guest_pat": 4, "guest_efer": 5,
    "guest_ia32_debugctl": 6, "guest_fs_base": 7, "guest_gs_base": 8,
    "guest_sysenter_cs": 9, "guest_sysenter_esp": 10, "guest_sysenter_eip": 11,
    "efer_msr": 0xc0000080, "fs_base_msr": 0xc0000100,
    "gs_base_msr": 0xc0000101, "sysenter_cs_msr": 0x174,
    "sysenter_esp_msr": 0x175, "sysenter_eip_msr": 0x176,
}
assembly = re.sub(r"\{(\w+)\}", lambda match: str(fields[match[1]]), assembly)
assembly = re.sub(
    r"vmread (r\w+), rax",
    r"push rdx\nmov rdx, [r12]\nmov \1, [rdx + rax * 8]\npop rdx\ncmp r12, 0",
    assembly,
)
assembly = re.sub(
    r"vmwrite rax, (r\w+)",
    r"push rdx\nmov rdx, [r12]\nmov [rdx + rax * 8], \1\npop rdx\ncmp r12, 0",
    assembly,
)
assembly = assembly.replace(
    "vmptrld [rdi]", "mov rax, [rdi]\nmov [r12], rax\ncmp r12, 0"
)
assembly += """
.Lresident_guarded_rdmsr:
    inc qword ptr [r12 + 16]
    mov rax, [r12 + 8]
    mov rdx, rax
    shr rdx, 32
    mov eax, eax
    clc
    ret
.Lresident_dispatch_vmread_failed:
.Lresident_dispatch_vmwrite_failed:
.Lresident_dispatch_halt:
    ud2
.globl test_cet_select
test_cet_select:
    push rdi
    push r12
    mov r12, rcx
    mov rdi, rdx
    call .Lresident_nested_select_vmcs_inherit_cet
    pop r12
    pop rdi
    ret
.globl test_cet_saved_msr
test_cet_saved_msr:
    push r12
    mov r12, rcx
    mov ecx, edx
    call .Lresident_nested_read_saved_msr
    pop r12
    ret
"""
(output / "handlers.S").write_text(".text\n" + assembly, encoding="utf-8")
executable = output / "cet-state-tests.exe"
subprocess.run(
    ["rustc", "--edition=2024", "-Dwarnings", "--test",
     str(project / "tests/cet_runtime_tests.rs"), "-o", str(executable)],
    cwd=project, check=True,
)
subprocess.run([str(executable)], cwd=project, check=True)
