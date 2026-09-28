"""Execute the resident VMX lifecycle handlers with host-side VMCS and UART stubs."""

import ast
from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "nested-logging-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/asm/resident_island.S").read_text(encoding="utf-8")
start = source.index(".Lresident_dispatch_vmxon:")
end = source.index(".Lresident_nested_vmfail_with_error:", start)
success = source.index(".Lresident_nested_succeed:", end)
success_end = source.index(".Lresident_nested_inject_pf_write:", success)
macro = source.index(".macro resident_telemetry_counter ")
macro_end = source.index(".endm", macro) + len(".endm")
assembly = source[macro:macro_end] + "\n" + source[start:end] + source[success:success_end]
assembly = assembly.replace("vmread r11, rax", "call .Ltest_vmread")
assembly = assembly.replace("vmwrite rax, r11", "call .Ltest_vmwrite")
constants = {"guest_cs_selector": 0, "guest_rflags": 1, "exception_bitmap": 2,
             "vmxon_in_vmx_root_error": 15, "vmx_status_flags_clear_mask": ~0x8d5}
for name in ("nested_vmxon_message", "nested_vmxoff_message", "nested_pointer_message",
             "state_rip", "state_newline"):
    label = ".L" + name
    literal = re.search(re.escape(label) + r':\s*\.ascii ("[^\n]+")', source)[1]
    constants[name + "_len"] = len(ast.literal_eval(literal))
    assembly += f"\n{label}:\n.ascii {literal}\n"
assembly += """
.text
.globl test_vmx_lifecycle
test_vmx_lifecycle:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov r12, rcx
    test edx, edx
    jnz .Ltest_vmxoff
    call .Lresident_dispatch_vmxon
    jmp .Ltest_return
.Ltest_vmxoff:
    call .Lresident_dispatch_vmxoff
.Ltest_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
.Ltest_vmread:
    xor r11d, r11d
    cmp eax, 1
    jne .Ltest_vmread_ready
    mov r11, [r12 + {b_test_rflags}]
.Ltest_vmread_ready:
    mov eax, 1
    test eax, eax
    ret
.Ltest_vmwrite:
    cmp eax, 1
    jne .Ltest_vmwrite_ready
    mov [r12 + {b_test_rflags}], r11
.Ltest_vmwrite_ready:
    mov eax, 1
    test eax, eax
    ret
.Lresident_nested_decode_memory_operand:
    lea r10, [r12 + {b_test_operand}]
    clc
    ret
.Lresident_nested_physical_address_is_valid:
    mov eax, 1
    ret
.Lresident_nested_store_current_vmcs12:
    inc qword ptr [r12 + {b_test_stores}]
    ret
.Lresident_advance_guest_rip:
    add qword ptr [r12 + {b_test_rip}], 3
    ret
.Lresident_serial_write:
    add qword ptr [r12 + {b_test_serial_bytes}], r9
    ret
.Lresident_serial_hex64:
    add qword ptr [r12 + {b_test_serial_bytes}], 16
    ret
.Lresident_dispatch_resume:
    xor eax, eax
    ret
.Lresident_nested_inject_ud:
.Lresident_nested_inject_gp:
.Lresident_nested_inject_pf_read:
.Lresident_nested_vmfail_invalid_vmxon_address:
.Lresident_nested_vmfail_invalid_vmxon_revision:
.Lresident_nested_vmfail_with_error:
.Lresident_dispatch_vmread_failed:
.Lresident_dispatch_vmwrite_failed:
    mov eax, 1
    ret
"""
names = sorted(set(re.findall(r"\{(b_[a-z0-9_]+)\}", assembly)) | {"b_telemetry_probe_active"})
offsets = {name: index * 8 for index, name in enumerate(names)}
assembly = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(
    offsets[match[1]] if match[1] in offsets else constants[match[1]]
), assembly)
(output / "lifecycle.S").write_text(assembly, encoding="utf-8")
mapping = "fn offset(name: &str) -> usize { match name {\n"
mapping += "\n".join(f'"{name}" => {value // 8},' for name, value in offsets.items())
mapping += '\n_ => panic!("unknown lifecycle field {name}"),\n} }\n'
(output / "offsets.rs").write_text(mapping, encoding="utf-8")
display_start = source.index(".Lresident_framebuffer_active:")
display_end = source.index(".Lresident_paint_byte:", display_start)
hex_start = source.index(".Lresident_paint_hex:")
hex_end = source.index(".Lresident_diagnostic_name_offsets:", hex_start)
display = source[display_start:display_end] + source[hex_start:hex_end]
display = display.replace("rdtsc", "mov eax, 1000\nxor edx, edx")
display_constants = {
    "log_framebuffer_sink": 2, "event_ebs_seen": 0,
    "event_visual_base": 8, "event_visual_stride_bytes": 16,
    "event_visual_deadline": 24,
    "visual_marker_row_step": 16, "visual_marker_step_bytes": 64,
    "visual_marker_side": 8, "visual_hex_last_row": 35,
    "visual_hex_column_step_bytes": 640, "visual_hex_row_step": 12,
    "visual_hex_y": 64,
}
display = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(display_constants[match[1]]), display)
display += """
.text
.globl test_resident_display
test_resident_display:
    mov byte ptr [rip + matrixhv_resident_island_log_backend], 2
    mov r8, rcx
    mov ecx, 1
    test edx, edx
    jz .Lresident_paint_stage
    mov rax, 0x123456789abcdef0
    jmp .Lresident_paint_hex
.data
matrixhv_resident_island_log_backend:
    .byte 2
"""
(output / "display.S").write_text(display, encoding="utf-8")
binary = output / "nested-logging-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(project / "tests/nested_logging.rs"),
                "-o", str(binary)], check=True, cwd=project)
subprocess.run([str(binary)], check=True, cwd=project)
