"""Execute the boot capture assembly against synthetic guest and EPT pages."""

from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "boot-diagnostics-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/asm/boot_diagnostics.S").read_text(encoding="utf-8")
constants = {
    "b_boot_diagnostic": 0,
    "b_event_context": 256,
    "b_diagnostic_samples": 264,
    "b_flight_sequence": 272,
    "b_last_guest_rip": 280,
    "b_last_reason": 288,
    "b_nested_l2_active": 296,
    "b_cache_ept_pointer": 304,
    "event_cpu_contexts": 0,
    "event_init_cpu_mask": 512,
    "event_sipi_cpu_mask": 520,
    "event_halted_cpu_mask": 528,
    "guest_cr0": 0,
    "vm_entry_controls": 1,
    "guest_cr4": 2,
    "guest_cr3": 3,
    "guest_rip": 4,
    "guest_rsp": 5,
    "host_page_address_mask": 0x000f_ffff_ffff_f000,
}
source = re.sub(r"\{(\w+)\}", lambda item: str(constants[item[1]]), source)
source = re.sub(
    r"vmread (\w+), rax",
    r"mov \1, qword ptr [r12 + 312 + rax * 8]\ncmp r12, 0",
    source,
)
source = source.replace("mov rax, cr0", "mov rax, qword ptr [r12 + 360]")
source = source.replace("rdmsr", "mov rax, qword ptr [r12 + 368]\nmov rdx, rax\nshr rdx, 32")
wrapper = r"""
.text
matrixhv_boot_diagnostics
.globl test_boot_read
test_boot_read:
push r12
sub rsp, 32
mov r12, rcx
mov r10, rdx
call .Lresident_boot_diagnostic_read_qword
mov qword ptr [r8], rax
setnc al
movzx eax, al
add rsp, 32
pop r12
ret
.globl test_boot_capture
test_boot_capture:
push rbx
push rbp
push rdi
push rsi
push r12
push r13
push r14
push r15
sub rsp, 40
mov qword ptr [rsp + 24], rcx
mov qword ptr [rsp + 32], rdx
mov r12, rcx
mov rsi, rdx
mov ebx, 0x11111111
mov ebp, 0x22222222
mov edi, 0x33333333
mov r13d, 0x55555555
mov r14d, 0x66666666
mov r15d, 0x77777777
mov r8d, 0x13572468
call .Lresident_boot_diagnostic_capture
cmp r8, 0x13572468
jne .Ltest_boot_capture_corrupt
cmp rbx, 0x11111111
jne .Ltest_boot_capture_corrupt
cmp rbp, 0x22222222
jne .Ltest_boot_capture_corrupt
cmp rdi, 0x33333333
jne .Ltest_boot_capture_corrupt
cmp r13, 0x55555555
jne .Ltest_boot_capture_corrupt
cmp r14, 0x66666666
jne .Ltest_boot_capture_corrupt
cmp r15, 0x77777777
jne .Ltest_boot_capture_corrupt
cmp rsi, qword ptr [rsp + 32]
jne .Ltest_boot_capture_corrupt
cmp r12, qword ptr [rsp + 24]
jne .Ltest_boot_capture_corrupt
mov eax, 1
jmp .Ltest_boot_capture_return
.Ltest_boot_capture_corrupt:
xor eax, eax
.Ltest_boot_capture_return:
add rsp, 40
pop r15
pop r14
pop r13
pop r12
pop rsi
pop rdi
pop rbp
pop rbx
ret
.Lresident_ept01_host_page_is_mapped:
inc qword ptr [r12 + 384]
mov rax, r11
and rax, -4096
cmp rax, qword ptr [r12 + 376]
sete al
xor al, 1
movzx eax, al
ret
"""
(output / "boot-capture.S").write_text(source + wrapper, encoding="utf-8")
binary = output / "boot_diagnostics_tests.exe"
subprocess.run(
    ["rustc", "--edition=2024", "-Dwarnings", "--test",
     str(project / "tests/boot_diagnostics_tests.rs"), "-o", str(binary)],
    cwd=project, check=True,
)
subprocess.run([str(binary)], cwd=project, check=True)
