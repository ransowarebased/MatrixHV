"""Execute resident privilege, XSETBV and VMRESUME guards with modeled VMX I/O."""
from pathlib import Path
import re
import subprocess

project = Path(__file__).resolve().parents[1]
output = project / "builds/exit-guard-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/asm/exits.S").read_text()
diagnostics = (project / "src/asm/diagnostics.S").read_text()

def macro_body(text, name):
    return text.split(".macro " + name + "\n", 1)[1].split(".endm", 1)[0]

privilege = macro_body(source, "matrixhv_resident_guest_privilege")
privilege = privilege.replace("vmread r11, rax", "mov r11, [r12 + rax * 8]\ncmp r12, 0")
xsetbv = macro_body(source, "matrixhv_resident_xsetbv")
xsetbv = re.sub(r"^resident_telemetry_counter[^\n]*\n", "", xsetbv, flags=re.M)
xsetbv = xsetbv.replace("vmread r11, rax", "mov r11, [r12 + rax * 8]\ncmp r12, 0")
xsetbv = xsetbv.replace("mov r11, cr4", "mov r11, [r12 + 40]")
# MOV CR4 leaves condition flags undefined. Model a CPU that clears CF.
xsetbv = xsetbv.replace("mov cr4, r10", "mov [r12 + 40], r10\nclc")
xsetbv = xsetbv.replace("mov cr4, r11", "mov [r12 + 40], r11\nclc")
failure = macro_body(diagnostics, "matrixhv_diagnostic_vmresume_failure")
failure = re.sub(r"^resident_diagnostic_message[^\n]*\n", "", failure, flags=re.M)
failure = failure.replace("vmread r11, rax", "inc qword ptr [r12 + 64]\nmov r11, [r12 + 56]\ncmp r12, 0")
values = dict(guest_cr0=0, guest_rflags=1, guest_ss_ar_bytes=2, guest_cr4=3,
              b_vmresume_status_flags=48, vm_instruction_error=0,
              b_stop_result=72, b_event_context=80, event_ebs_seen=0,
              b_nested_eptp_sync_safe=0, b_canary_start=8, b_canary_end=16,
              b_root_vmx_active=24,
              boot_canary_start=0x4856424f4f544331, boot_canary_end=0x4856424f4f544332)
assembly = re.sub(r"\{(\w+)\}", lambda match: str(values[match[1]]), privilege + xsetbv)
assembly += """
.Lresident_dispatch_vmread_failed:
.Lresident_dispatch_vmwrite_failed:
ud2
.Lresident_guarded_xsetbv:
bt qword ptr [r12 + 32], 0
ret
.Lresident_advance_guest_rip:
inc qword ptr [r12 + 88]
ret
.Lresident_dispatch_resume:
mov eax, 1
jmp .Ltest_xsetbv_done
.Lresident_dispatch_inject_gp:
xor eax, eax
jmp .Ltest_xsetbv_done
.Lresident_dispatch_inject_ud:
mov eax, 2
.Ltest_xsetbv_done:
add rsp, 32
pop r12
ret
.Lresident_serial_hex64:
.Lresident_serial_state:
ret
.Lresident_paint_byte:
ud2
.globl test_guest_privilege
test_guest_privilege:
push r12
mov r12, rcx
call .Lresident_guest_privilege
setnc al
movzx eax, al
pop r12
ret
.globl test_xsetbv_guard
test_xsetbv_guard:
push r12
mov r12, rcx
sub rsp, 32
mov qword ptr [rsp], 0
mov qword ptr [rsp + 8], 0
mov qword ptr [rsp + 16], 0
jmp .Lresident_dispatch_xsetbv
.globl test_vmresume_diagnostic
test_vmresume_diagnostic:
push r12
mov r12, rcx
"""
failure = re.sub(r"\{(\w+)\}", lambda match: str(values[match[1]]), failure)
assembly += failure + "\npop r12\nret\n"
entry = macro_body(source, "matrixhv_island_dispatch")
entry = entry.split("mov rax, {exit_reason}", 1)[0]
entry = entry.replace(".globl matrixhv_resident_dispatch_entry", "")
entry = entry.replace("matrixhv_resident_dispatch_entry:", ".Ltest_dispatch_entry:")
entry = re.sub(r"\{(\w+)\}", lambda match: str(values[match[1]]), entry)
assembly += """
.globl test_dispatch_canaries
test_dispatch_canaries:
push rbx
push rbp
push rsi
push rdi
push r12
push r13
push r14
push r15
push rcx
""" + entry + """
mov eax, 1
jmp .Ltest_dispatch_done
matrixhv_resident_island_fatal:
xor eax, eax
.Ltest_dispatch_done:
add rsp, 128
pop r15
pop r14
pop r13
pop r12
pop rdi
pop rsi
pop rbp
pop rbx
ret
"""
(output / "guards.S").write_text(".text\n" + assembly)
binary = output / "exit_guard_tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test",
                str(project / "tests/exit_guard_tests.rs"), "-o", str(binary)], cwd=project, check=True)
subprocess.run([str(binary)], cwd=project, check=True)
