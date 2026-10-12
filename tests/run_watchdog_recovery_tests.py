"""Execute production invalidation and reset paths with modeled privileged I/O."""

from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds/watchdog-recovery-tests"
output.mkdir(parents=True, exist_ok=True)
assembly = ".text\n"
paths = [
    ("ept_sync", "eptp_switch.S", "invept"),
    ("ept_cache", "ept_cache.S", "invept"),
    ("ept_nested", "nested.S", "invept"),
    ("vpid", "exits.S", "invvpid"),
]
for name, path, instruction in paths:
    source = (project / "src/vmx/asm" / path).read_text()
    instruction_start = source.index(instruction + " rax, xmmword ptr [rsp]")
    start = source.rfind("sub rsp, 16", 0, instruction_start)
    end = source.index("jna .Lresident_invalidation_failed", instruction_start)
    body = source[start:end + len("jna .Lresident_invalidation_failed")]
    body = re.sub(r"\{\w+\}", "0", body)
    body = body.replace(".Lresident_", f".L{name}_").replace(".Lap_", f".L{name}_")
    sequence = [0]

    def model_instruction(_):
        index = sequence[0]
        sequence[0] += 1
        return f"""
        mov r10, qword ptr [r12 + 8]
        mov qword ptr [r12 + 24 + r10 * 8], rax
        mov r9, qword ptr [rsp]
        mov qword ptr [r12 + 40 + r10 * 8], r9
        inc qword ptr [r12 + 8]
        bt qword ptr [r12 + 16], r10
        jnc .L{name}_success_{index}
        cmp qword ptr [r12 + 64], 0
        jne .L{name}_carry_{index}
        xor r10d, r10d
        jmp .L{name}_status_{index}
    .L{name}_carry_{index}:
        stc
        jmp .L{name}_status_{index}
    .L{name}_success_{index}:
        mov r10d, 1
        test r10d, r10d
    .L{name}_status_{index}:
        """

    body = re.sub(rf"{instruction} rax, xmmword ptr \[rsp\]", model_instruction, body)
    assert sequence[0] == 2
    assembly += f"""
    .globl test_{name}
    test_{name}:
        push r12
        mov r12, rcx
        mov r11, qword ptr [r12]
    {body}
        mov eax, 1
        pop r12
        ret
    .L{name}_invalidation_failed:
        mov qword ptr [r12 + 56], 1
        xor eax, eax
        pop r12
        ret
    """

diagnostics = (project / "src/asm/diagnostics.S").read_text()
fault_sources = [
    ((project / "src/vmx/asm/exits.S").read_text(), ".Lresident_host_exception:", "call .Lresident_pt_freeze"),
    (diagnostics, ".Lresident_host_gp_fatal:", "call .Lresident_pt_freeze"),
    (diagnostics, "matrixhv_resident_island_fatal:", "mov r8, qword ptr"),
]
for index, (source, label, first_context_use) in enumerate(fault_sources):
    start = source.index(label) + len(label)
    guard = source[start:source.index(first_context_use, start)].replace("cli", "nop")
    guard = guard.replace(".Lresident_platform_reset_cf9", ".Ltest_fault_reset")
    assembly += f"""
.globl test_fault_guard_{index}
test_fault_guard_{index}:
mov qword ptr [rip + .Lresident_host_fault_active], rcx
{guard}
mov eax, 1
ret
"""
assembly += """
.Ltest_fault_reset:
xor eax, eax
ret
.data
.balign 8
.Lresident_host_fault_active:
.quad 0
.text
"""
serial = diagnostics[diagnostics.index(".Lresident_serial_write:"):diagnostics.index("matrixhv_resident_nested_tables")]
serial = serial.replace("{log_serial_sink}", "1").replace("{serial_status_port}", "0x3fd")
serial = serial.replace("{serial_port}", "0x3f8").replace("{serial_transmit_empty}", "0x20")
serial = serial.replace("{serial_wait_limit}", "8").replace("{b_serial_lock}", "0")
serial = serial.replace("in al, dx", "inc qword ptr [r12 + 8]\nmov al, byte ptr [r12 + 32]")
serial = serial.replace("out dx, al", "inc qword ptr [r12 + 16]\nmov byte ptr [r12 + 24], al")
assert "{" not in serial
assembly += """
.globl test_serial
test_serial:
push r12
mov r12, rcx
mov byte ptr [rip + matrixhv_resident_island_log_backend], 1
mov al, dl
call .Lresident_serial_char
setc al
movzx eax, al
pop r12
ret
.globl test_retired_serial
test_retired_serial:
push r12
push rsi
mov r12, rcx
mov byte ptr [rip + matrixhv_resident_island_log_backend], 0
test edx, edx
jz .Ltest_retired_character
cmp edx, 1
je .Ltest_retired_string
mov eax, 0x1234
call .Lresident_serial_hex64
jmp .Ltest_retired_done
.Ltest_retired_string:
lea rsi, [rip + .Ltest_retired_text]
mov r9d, 1
call .Lresident_serial_write
jmp .Ltest_retired_done
.Ltest_retired_character:
mov al, 10
call .Lresident_serial_char
.Ltest_retired_done:
setc al
movzx eax, al
pop rsi
pop r12
ret
.Ltest_retired_text:
.ascii "A"
.globl test_serial_enabled
test_serial_enabled:
movzx eax, byte ptr [rip + matrixhv_resident_island_log_backend]
ret
""" + serial + """
.data
matrixhv_resident_island_log_backend:
.byte 1
.text
"""

control = (project / "src/vmx/asm/control.S").read_text()
off_paths = re.findall(r"vmxoff\n[^\n]+", control)
assert len(off_paths) == 3
assert [path.splitlines()[1] for path in off_paths] == [
    "jna .Lresident_platform_reset", "jna .Lresident_platform_reset_cf9", "jna .Lresident_platform_reset",
]
for index, body in enumerate(off_paths):
    body = body.replace("vmxoff", "test_off_status")
    body = re.sub(r"\.Lresident_platform_reset(?:_cf9)?", f".Ltest_off_reset_{index}", body)
    assembly += f"""
.globl test_vmxoff_{index}
test_vmxoff_{index}:
{body}
mov eax, 1
ret
.Ltest_off_reset_{index}:
xor eax, eax
ret
"""
assembly = r"""
.macro test_off_status
test ecx, ecx
jz .Ltest_off_ok\@
cmp ecx, 1
je .Ltest_off_carry\@
xor eax, eax
jmp .Ltest_off_done\@
.Ltest_off_carry\@:
stc
jmp .Ltest_off_done\@
.Ltest_off_ok\@:
mov eax, 1
test eax, eax
.Ltest_off_done\@:
.endm
""" + assembly
reset = diagnostics[diagnostics.index(".Lresident_platform_reset:"):]
reset = reset[:reset.index(".endm")]
reset = reset.replace("cli", "nop").replace("{event_reset_io}", "0")
reset = reset.replace("mov r8, qword ptr [rip + matrixhv_resident_island_event_context]", "mov r8, r12")
reset = reset.replace("out dx, al", "test_reset_out")
reset = reset.replace("out 0x64, al", "mov dx, 0x64\ntest_reset_out")
reset = reset.replace("in al, 0x64", "inc qword ptr [r12 + 16]\nmov al, byte ptr [r12 + 8]")
reset = reset.replace("lidt [rip + .Lresident_platform_reset_empty_idt]", "inc qword ptr [r12 + 96]")
reset = reset.replace("int3", "jmp .Ltest_reset_done")
assembly += """
.macro test_reset_out
mov r10, qword ptr [r12 + 24]
movzx r11d, dx
mov qword ptr [r12 + 32 + r10 * 8], r11
movzx r11d, al
mov qword ptr [r12 + 64 + r10 * 8], r11
inc qword ptr [r12 + 24]
.endm
.globl test_reset
test_reset:
push r12
mov r12, rcx
jmp .Lresident_platform_reset
.Ltest_reset_done:
pop r12
ret
""" + reset
(output / "recovery.S").write_text(assembly)

interception = (project / "src/memory/interception.rs").read_text()
start = interception.index("    fn invalidate(ept:")
end = interception.index("    fn entry_bits(", start)
invalidation = interception[start:end]
invalidation, count = re.subn(
    r"unsafe\s*\{\s*core::arch::asm!\([^;]+;\s*\}",
    "failed = model_invalidate(kind, descriptor.0);", invalidation,
)
assert count == 1 and "asm!" not in invalidation
(output / "invalidation.rs").write_text(invalidation)
binary = output / "watchdog_recovery_tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test",
                str(project / "tests/watchdog_recovery_tests.rs"), "-o", str(binary)],
               cwd=project, check=True)
subprocess.run([str(binary)], cwd=project, check=True)
