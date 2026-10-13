"""Execute the resident DEBUGCTL handler with guarded MSR and VMCS models."""
from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds/debugctl-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/asm/msr.S").read_text(encoding="utf-8")
start = source.index(".Lresident_dispatch_wrmsr_debugctl:")
end = source.index(".Lresident_dispatch_wrmsr_fs_base:", start)
handler = source[start:end].replace("{guest_ia32_debugctl}", "0")
handler = handler.replace(
    "vmwrite rax, r11",
    "mov [r12 + 8], r11\ninc qword ptr [r12 + 48]\ncmp r12, 0",
)
assembly = r"""
.text
.globl test_debugctl_write
test_debugctl_write:
push r12
sub rsp, 32
mov r12, rcx
mov eax, edx
mov [rsp], rax
shr rdx, 32
mov [rsp + 16], rdx
mov ecx, 0x1d9
jmp .Lresident_dispatch_wrmsr_debugctl
.Lresident_guarded_rdmsr:
inc qword ptr [r12 + 24]
cmp qword ptr [r12 + 112], 0
jne .Ltest_debugctl_fault
mov rax, [r12]
mov rdx, rax
shr rdx, 32
mov eax, eax
clc
ret
.Lresident_guarded_wrmsr:
inc qword ptr [r12 + 32]
mov r8, [r12 + 32]
cmp r8, [r12 + 64]
je .Ltest_debugctl_fault
shl rdx, 32
or rax, rdx
mov r8, [r12 + 16]
not r8
test r8, rax
jnz .Ltest_debugctl_fault
mov r8, [r12 + 32]
mov [r12 + 72 + r8 * 8], rax
mov [r12], rax
mov r8d, eax
and r8d, 0xc0
cmp r8d, 0xc0
jne .Ltest_debugctl_write_done
inc qword ptr [r12 + 40]
.Ltest_debugctl_write_done:
clc
ret
.Ltest_debugctl_fault:
stc
ret
.Lresident_advance_guest_rip:
inc qword ptr [r12 + 56]
ret
.Lresident_dispatch_resume:
mov eax, 1
jmp .Ltest_debugctl_done
.Lresident_dispatch_inject_gp:
xor eax, eax
jmp .Ltest_debugctl_done
.Lresident_dispatch_vmwrite_failed:
.Lresident_dispatch_halt:
inc qword ptr [r12 + 120]
mov eax, 3
.Ltest_debugctl_done:
add rsp, 32
pop r12
ret
"""
(output / "debugctl.S").write_text(assembly + handler, encoding="utf-8")
binary = output / "resident_debugctl_tests.exe"
subprocess.run(
    ["rustc", "--edition=2024", "-Dwarnings", "--test",
     str(project / "tests/resident_debugctl_tests.rs"), "-o", str(binary)],
    cwd=project, check=True,
)
subprocess.run([str(binary)], cwd=project, check=True)
