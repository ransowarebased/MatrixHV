from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "resident-visual-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/asm/resident_island.S").read_text(encoding="utf-8")
start = source.index('.globl matrixhv_resident_ebs_callback')
end = source.index('.Lresident_serial_state:', start)
hex_start = source.index('.Lresident_paint_hex:', end)
hex_end = source.index('.Lresident_serial_write:', hex_start)
emit_start = source.index('.Lresident_diagnostic_emit_value:', end)
serial_char_start = source.index('.Lresident_serial_char:', hex_end)
serial_hex_start = source.index('.Lresident_serial_hex64:', serial_char_start)
serial_hex_end = source.index('.Lresident_vmcs12_field_index_table:', serial_hex_start)
msr_start = source.index('.Lresident_guarded_rdmsr:')
msr_end = source.index('.globl matrixhv_resident_island_gp', msr_start)
gp_end = source.index('.Lresident_host_gp_fatal:', msr_end)
exception_start = source.index('.globl matrixhv_resident_exception_stubs', gp_end)
exception_end = source.index('.globl matrixhv_resident_island_fatal', exception_start)
timer_start = source.index('.Lresident_reload_diagnostic_timer:')
timer_end = source.index('.Lresident_dispatch_resume:', timer_start)
timer_assembly = source[timer_start:timer_end].strip()
timer_assembly = timer_assembly.replace("rdtsc", "mov rax, rdi\nmov rdx, rdi\nshr rdx, 32")
timer_assembly = timer_assembly.replace(
    "vmwrite rax, r11", "mov [rbx], r11\nmov [rbx + 8], rax\ncmp r11, 0"
)
timer_assembly += "\n.Lresident_dispatch_vmwrite_failed:\nud2"
boot_timer_start = source.index('.Lresident_dispatch_boot_timer:')
boot_timer_end = source.index('.Lresident_boot_timer_retry_event:', boot_timer_start)
boot_timer = source[boot_timer_start:boot_timer_end]
boot_timer = boot_timer.replace("rdtsc", "mov rax, qword ptr [rip + test_visual_tsc]\nmov rdx, rax\nshr rdx, 32")
boot_timer = boot_timer.replace("vmread r11, rax", "mov r11, [r12 + {test_pin_controls}]\ncmp r12, 0")
boot_timer = boot_timer.replace("vmwrite rax, r11", "mov [r12 + {test_pin_controls}], r11\ncmp r12, 0")
timer_assembly += "\n" + boot_timer + """
.Lresident_boot_timer_retry_event:
    ret
.Lresident_diagnostic_snapshot:
    inc qword ptr [r12 + {test_snapshot_count}]
    ret
.Lresident_dispatch_unsupported:
.Lresident_dispatch_vmread_failed:
    ud2
"""
assembly = (
    source[start:end]
    + source[emit_start:hex_start]
    + source[hex_start:hex_end]
    + source[hex_end:serial_char_start]
    + source[serial_hex_start:serial_hex_end]
    + source[msr_start:gp_end]
    + ".balign 16\n"
    + source[exception_start:exception_end]
).strip()
assembly = assembly.replace(
    ".Lresident_host_nmi_return:\npop rax\niretq",
    ".Lresident_host_nmi_return:\npop rax\njmp .Ltest_nmi_return",
).replace("mov rax, qword ptr gs:[112]", "mov rax, qword ptr [rip + matrixhv_resident_island_event_context]")
assembly = assembly.replace(
    "jz .Lresident_host_gp_fatal", "jz .Ltest_gp_unhandled"
).replace("iretq", "jmp .Ltest_gp_return")
assembly = (
    assembly.replace("cli", "nop")
    .replace("mov rdx, cr2", "mov edx, 0x12345678")
    .replace("matrixhv_resident_island_fatal", ".Ltest_exception_return")
    .replace(".Lresident_island_fatal_owned", ".Ltest_exception_return")
    .replace(".Lresident_island_fatal_serial", ".Ltest_exception_return")
)
assembly += "\njmp .Ltest_exception_return"
assembly = assembly.replace("rdtsc", "mov rax, qword ptr [rip + test_visual_tsc]\nmov rdx, rax\nshr rdx, 32")
screen = (project / "src/boot.rs").read_text(encoding="utf-8")


def marker_constant(name):
    return int(re.search(rf"const {name}: usize = (\d+);", screen).group(1))


wrappers = """
.data
.balign 8
.globl test_visual_tsc
test_visual_tsc:
    .quad 1000
.text
.Lresident_nested_eptp_sync_host_nmi:
    xor eax, eax
    ret
.globl test_claim_diagnostic
test_claim_diagnostic:
    mov r8, rcx
    call .Lresident_claim_diagnostic
    sete al
    movzx eax, al
    ret
.globl test_set_backend
test_set_backend:
    mov byte ptr [rip + matrixhv_resident_island_log_backend], cl
    mov qword ptr [rip + .Ltest_serial_length], 0
    ret
.globl test_copy_serial
test_copy_serial:
    push rsi
    push rdi
    mov rdi, rcx
    mov rax, qword ptr [rip + .Ltest_serial_length]
    cmp rax, rdx
    cmova rax, rdx
    mov rcx, rax
    lea rsi, [rip + .Ltest_serial_bytes]
    rep movsb
    pop rdi
    pop rsi
    ret
.globl test_emit_value
test_emit_value:
    mov rax, rdx
    mov edx, r8d
    mov r8, rcx
    mov ecx, edx
    jmp .Lresident_diagnostic_emit_value
.Lresident_serial_char:
    push rcx
    push rdx
    mov rcx, qword ptr [rip + .Ltest_serial_length]
    cmp rcx, 4096
    jae .Ltest_serial_char_done
    lea rdx, [rip + .Ltest_serial_bytes]
    mov byte ptr [rdx + rcx], al
    inc rcx
    mov qword ptr [rip + .Ltest_serial_length], rcx
.Ltest_serial_char_done:
    pop rdx
    pop rcx
    ret
.globl test_paint_stage
test_paint_stage:
    mov r8, rcx
    mov ecx, edx
    jmp .Lresident_paint_stage
.globl test_paint_byte
test_paint_byte:
    mov eax, edx
    mov edx, r8d
    mov r8, rcx
    mov ecx, edx
    jmp .Lresident_paint_byte
.globl test_paint_hex
test_paint_hex:
    mov rax, rdx
    mov edx, r8d
    mov r8, rcx
    mov ecx, edx
    jmp .Lresident_paint_hex
.globl test_msr_fault_fixup
test_msr_fault_fixup:
    mov rax, rcx
    jmp .Lresident_msr_fault_fixup
.globl test_read_fault_rip
test_read_fault_rip:
    lea rax, [rip + .Lresident_rdmsr_instruction]
    ret
.globl test_write_fault_rip
test_write_fault_rip:
    lea rax, [rip + .Lresident_wrmsr_instruction]
    ret
.globl test_xsetbv_fault_rip
test_xsetbv_fault_rip:
    lea rax, [rip + .Lresident_xsetbv_instruction]
    ret
.globl test_fault_resume_rip
test_fault_resume_rip:
    lea rax, [rip + .Lresident_msr_fault_return]
    ret
.globl test_gp_frame
test_gp_frame:
    push rbx
    mov rbx, rcx
    sub rsp, 48
    mov r10, qword ptr [rbx + 8]
    mov qword ptr [rsp], r10
    mov r10, qword ptr [rbx]
    mov qword ptr [rsp + 8], r10
    mov qword ptr [rsp + 16], 8
    mov qword ptr [rsp + 24], 2
    mov qword ptr [rsp + 32], 0
    mov qword ptr [rsp + 40], 0
    mov rax, qword ptr [rbx + 16]
    mov rdx, qword ptr [rbx + 24]
    jmp matrixhv_resident_island_gp
.Ltest_gp_unhandled:
    mov qword ptr [rbx + 56], 1
    pop rdx
    pop rax
    add rsp, 8
.Ltest_gp_return:
    mov r10, qword ptr [rsp]
    mov qword ptr [rbx + 32], r10
    mov qword ptr [rbx + 40], rax
    mov qword ptr [rbx + 48], rdx
    add rsp, 40
    pop rbx
    ret
.globl test_exception_frame
test_exception_frame:
    push rbx
    mov rbx, rdx
    mov qword ptr [rip + matrixhv_resident_island_event_context], rbx
    mov r10d, ecx
    push 0
    push 0
    push 2
    push 8
    push r9
    mov eax, 0x60227d00
    bt eax, ecx
    jnc .Ltest_exception_enter
    push r8
.Ltest_exception_enter:
    lea r11, [rip + matrixhv_resident_exception_stubs]
    shl r10, 4
    add r11, r10
    jmp r11
.Ltest_exception_return:
    add rsp, 56
    pop rbx
    ret
.Ltest_nmi_return:
    add rsp, 40
    pop rbx
    ret
.data
.balign 8
matrixhv_resident_island_event_context:
    .quad 0
matrixhv_resident_island_log_backend:
    .byte 2
.balign 8
.Ltest_serial_length:
    .quad 0
.Ltest_serial_bytes:
    .zero 4096
.text
"""
(output / "resident-visual.S").write_text(wrappers + assembly, encoding="utf-8")
timer_wrapper = """
.text
.globl test_dispatch_timer
test_dispatch_timer:
    push r12
    mov r12, rcx
    call .Lresident_dispatch_boot_timer
    pop r12
    ret
.globl test_reload_timer
test_reload_timer:
    push rbx
    push rdi
    push r12
    mov r12, rcx
    mov rdi, rdx
    mov rbx, r8
    call .Lresident_reload_diagnostic_timer
    pop r12
    pop rdi
    pop rbx
    ret
"""
(output / "resident-timer.S").write_text(timer_wrapper + timer_assembly, encoding="utf-8")
cases = (project / "tests/resident_visual.rs").read_text(encoding="utf-8")
constants = f"""
const MARKER_SIDE: usize = {marker_constant('RESIDENT_MARKER_SIZE')};
const MARKER_STEP: usize = {marker_constant('RESIDENT_MARKER_STEP')};
const MARKER_ROW_STEP: usize = {marker_constant('RESIDENT_MARKER_ROW_STEP')};
const HEX_Y: usize = {marker_constant('RESIDENT_HEX_Y')};
const HEX_ROW_STEP: usize = {marker_constant('RESIDENT_HEX_ROW_STEP')};
const HEX_ROWS: usize = {marker_constant('RESIDENT_HEX_ROWS')};
const HEX_COLUMN_STEP: usize = {marker_constant('RESIDENT_HEX_COLUMN_STEP')};
"""
harness = output / "harness.rs"
harness.write_text(constants + cases, encoding="utf-8")
binary = output / "resident-visual-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
