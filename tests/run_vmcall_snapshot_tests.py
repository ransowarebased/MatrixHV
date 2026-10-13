"""Execute production VMCALL snapshot helpers with modeled VMCS reads."""
from pathlib import Path
import re
import subprocess

project = Path(__file__).resolve().parents[1]
output = project / "builds/vmcall-snapshot-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/asm/diagnostics.S").read_text()


def macro(name):
    return source.split(".macro " + name + "\n", 1)[1].split(".endm", 1)[0]


assembly = macro("matrixhv_island_vmcall_snapshot")
assembly += "\n.data\n" + macro("matrixhv_island_vmcall_snapshot_state") + "\n.text\n"
query = source.split(".Lresident_dispatch_cpuid_vmcall_snapshot:\n", 1)[1]
query = query.split(".Lresident_dispatch_cpuid_ept_stall_diagnostics:\n", 1)[0]
assembly += "\n.Lresident_dispatch_cpuid_vmcall_snapshot:\n" + query
values = dict(b_processor_number=0, b_telemetry_active=8, b_last_reason=16,
              b_hyperv_timing_supported=24, b_nested_evmcs_enabled=32,
              vmcall_reason=18, vmcall_snapshot_words=32, vmcall_snapshot_subleaf=0x620,
              guest_rip=0, guest_rsp=1, guest_cr3=2, guest_rflags=3, guest_cr0=4,
              guest_cr4=5, guest_efer=6, guest_ss_ar_bytes=7, exit_instruction_len=8,
              vm_entry_intr_info_field=9)
assembly = re.sub(r"\{(\w+)\}", lambda match: str(values[match[1]]), assembly)
assembly = assembly.replace("vmread r11, rax", "call .Ltest_vmread")
assembly += """
.Ltest_vmread:
cmp rax, qword ptr [r12 + 40]
je .Ltest_vmread_failed
mov r11, qword ptr [r12 + 48 + rax * 8]
cmp r12, 0
ret
.Ltest_vmread_failed:
stc
ret
.globl test_capture_vmcall
test_capture_vmcall:
push r12
push r13
push r14
sub rsp, 128
mov r12, rcx
mov r13, rdx
mov r14, r8
xor ecx, ecx
.Ltest_copy_input:
mov rax, [r13 + rcx * 8]
mov [rsp + rcx * 8], rax
inc ecx
cmp ecx, 15
jb .Ltest_copy_input
call .Lresident_capture_public_vmcall
test r14, r14
jz .Ltest_capture_done
call .Lresident_complete_public_vmcall
.Ltest_capture_done:
xor ecx, ecx
.Ltest_copy_output:
mov rax, [rsp + rcx * 8]
mov [r13 + rcx * 8], rax
inc ecx
cmp ecx, 15
jb .Ltest_copy_output
call .Lresident_vmcall_snapshot_address
mov rax, r10
jnc .Ltest_capture_valid
xor eax, eax
.Ltest_capture_valid:
add rsp, 128
pop r14
pop r13
pop r12
ret
.globl test_complete_vmcall
test_complete_vmcall:
push r12
sub rsp, 128
mov r12, rcx
mov [rsp], rdx
call .Lresident_complete_public_vmcall
add rsp, 128
pop r12
ret
.globl test_query_vmcall
test_query_vmcall:
push r13
mov r13, r8
mov r8, rcx
mov ecx, edx
jmp .Lresident_dispatch_cpuid_vmcall_snapshot
.Lresident_dispatch_cpuid_diagnostic_zero:
xor eax, eax
xor edx, edx
.Lresident_dispatch_cpuid_vmx_pair:
mov [r13], rax
mov [r13 + 8], rdx
pop r13
ret
"""
(output / "snapshot.S").write_text(".text\n" + assembly)
binary = output / "vmcall_snapshot_tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test",
                str(project / "tests/vmcall_snapshot_tests.rs"), "-o", str(binary)], check=True, cwd=project)
subprocess.run([str(binary)], check=True, cwd=project)
