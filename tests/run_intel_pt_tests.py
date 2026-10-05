"""Execute the resident Intel PT state machine with modeled MSR accesses."""
from pathlib import Path
import re
import subprocess

project = Path(__file__).resolve().parents[1]
output = project / "builds/intel-pt-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/pt.rs").read_text()
definitions = source[source.index("#[repr(C)]"):source.index("pub(crate) struct TraceResources")]
(output / "definitions.rs").write_text(definitions)
fields = re.findall(r"pub (\w+): u64,", definitions)
values = {"b_pt_" + name: index * 8 for index, name in enumerate(fields)}
values.update(b_last_reason=len(fields) * 8, cpuid_reason=10,
              b_nested_host_misc=(len(fields) + 1) * 8,
              matrixhv_status_leaf=0x4d485652, pt_control=0x2105,
              pt_buffer_bytes=65536, pt_subleaf=0x600, pt_data_subleaf=0x1000,
              event_ebs_seen=64, b_canary_start=0, b_canary_end=0,
              boot_canary_start=0x4856424f4f544331, boot_canary_end=0x4856424f4f544332)
assembly = (project / "src/vmx/asm/pt.S").read_text()
assembly = re.sub(r"\{(\w+)\}", lambda match: str(values[match[1]]), assembly)
assembly = re.sub(r"^cpuid$", "call .Ltest_pt_cpuid", assembly, flags=re.M)
assembly = ".text\n" + assembly + "\nmatrixhv_island_pt\n"
assembly += r"""
.Ltest_pt_cpuid:
mov r11d, eax
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
test r11d, r11d
jz .Ltest_pt_leaf0
cmp r11d, 7
je .Ltest_pt_leaf7
mov ecx, dword ptr [r13 + 128]
ret
.Ltest_pt_leaf0:
mov eax, dword ptr [r13 + 112]
ret
.Ltest_pt_leaf7:
mov ebx, dword ptr [r13 + 120]
ret
.Lresident_rdmsr_instruction:
inc qword ptr [rbx + 32]
cmp ecx, dword ptr [rbx + 48]
je .Ltest_read_fault
mov r11d, 0
cmp ecx, 0x570
je .Ltest_read
mov r11d, 8
cmp ecx, 0x571
je .Ltest_read
mov r11d, 16
cmp ecx, 0x560
je .Ltest_read
mov r11d, 24
.Ltest_read:
mov rax, qword ptr [rbx + r11]
mov rdx, rax
shr rdx, 32
mov eax, eax
clc
ret
.Ltest_read_fault:
mov qword ptr [rbx + 48], 0
stc
ret
.Lresident_wrmsr_instruction:
inc qword ptr [rbx + 40]
cmp ecx, dword ptr [rbx + 56]
je .Ltest_write_fault
shl rdx, 32
or rax, rdx
mov r11d, 0
cmp ecx, 0x570
je .Ltest_write_control
mov r11d, 8
cmp ecx, 0x571
je .Ltest_write
mov r11d, 16
cmp ecx, 0x560
je .Ltest_write
mov r11d, 24
jmp .Ltest_write
.Ltest_write_control:
test al, 1
jnz .Ltest_write
test byte ptr [rbx], 1
jz .Ltest_write
mov rdx, qword ptr [rbx + 72]
shl rdx, 32
or rdx, 0x7f
mov qword ptr [rbx + 24], rdx
mov rdx, qword ptr [rbx + 80]
mov qword ptr [rbx + 8], rdx
.Ltest_write:
mov qword ptr [rbx + r11], rax
clc
ret
.Ltest_write_fault:
mov qword ptr [rbx + 56], 0
stc
ret
.macro test_interval name, helper
.globl \name
\name:
push rbx
push r12
mov r12, rcx
mov rbx, rdx
push r9
push r8
popfq
call \helper
pushfq
pop rax
add rsp, 8
pop r12
pop rbx
ret
.endm
test_interval test_enter, .Lresident_pt_enter
test_interval test_leave, .Lresident_pt_leave
.globl test_code_base
test_code_base:
lea rax, [rip + matrixhv_resident_island_start]
ret
.globl test_request
test_request:
push rbx
push rdi
push r12
push r13
mov r12, rcx
mov r8, rcx
mov r9, rdx
mov r13, rdx
cmp eax, eax
cmp dword ptr [rdx + 88], 0
je .Lresident_pt_query
cmp dword ptr [rdx + 88], 1
je .Lresident_pt_start
cmp dword ptr [rdx + 88], 2
je .Lresident_pt_stop
mov ecx, dword ptr [rdx + 88]
jmp .Lresident_pt_data
.Lresident_dispatch_cpuid_diagnostic_zero:
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_vmx_pair:
mov rbx, rax
shr rbx, 32
mov rcx, rdx
shr rdx, 32
.Lresident_dispatch_cpuid_diagnostic_store:
mov dword ptr [r13 + 96], eax
mov dword ptr [r13 + 100], ebx
mov dword ptr [r13 + 104], ecx
mov dword ptr [r13 + 108], edx
pop r13
pop r12
pop rdi
pop rbx
ret
matrixhv_resident_island_start:
.zero 16
matrixhv_resident_island_end:
"""
(output / "pt.S").write_text(assembly)
binary = output / "intel_pt_tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test",
                str(project / "tests/intel_pt_tests.rs"), "-o", str(binary)], cwd=project, check=True)
subprocess.run([str(binary)], cwd=project, check=True)
