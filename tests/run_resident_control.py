from pathlib import Path
import re
import subprocess


from resident_assembly import read_resident_assembly


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "resident-control-tests"
output.mkdir(parents=True, exist_ok=True)
source = read_resident_assembly(project)


def section(start, end):
    first = source.index(start)
    return source[first:source.index(end, first)]


entry = section("matrixhv_resident_dispatch_entry:", ".Lresident_control_rearm_done:")
reason = section(".Lresident_dispatch_reason_ready:", "and eax, 0xffff")
assembly = "\n".join([
    section(".macro resident_control_on_restore_msr ", ".macro resident_control_native_checkpoint "),
    entry,
    ".Lresident_control_rearm_done:",
    reason,
    "xor eax, eax\njmp .Ltest_dispatch_return",
    section(".Lresident_control_off_native:", ".Lresident_set_variable_on:"),
    section(".Lresident_control_on_root_cleanup:", ".Lresident_control_capture_native:"),
])

offsets = {}
sizes = {}
for prefix in ("control_cpu_", "probe_", "b_", "event_"):
    cursor = 0
    names = set(re.findall(r"\{(" + prefix + r"[a-z0-9_]+)\}", assembly))
    if prefix == "control_cpu_":
        names.add("control_cpu_native_snapshot_count")
    for name in sorted(names):
        if name in {"control_cpu_state_size", "probe_state_size"}:
            continue
        offsets[name] = cursor
        size = 72 if name == "control_cpu_on_native_msrs" else 8
        if name == "event_control_cpu_states":
            size = sizes["control_cpu_"] * 64
        elif name == "event_control_probe_states":
            size = sizes["probe_"] * 64
        elif name == "event_control_completion_sequences":
            size = 64 * 8
        cursor += size
    sizes[prefix] = cursor

constants = {
    "control_cpu_state_size": sizes["control_cpu_"],
    "probe_state_size": sizes["probe_"],
    "native_stack_bytes": 4096, "native_recovery_pml4": 4096,
    "boot_canary_start": 0x12345678, "boot_canary_end": 0x87654321,
    "host_page_address_mask": 0x000FFFFFFFFFF000,
    "exit_reason": 0, "exit_qualification": 1, "vm_entry_msr_load_count": 2,
    "spec_ctrl_msr": 0x48,
}
assembly = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(
    offsets[match[1]] if match[1] in offsets else constants[match[1]]
), assembly)

model_fields = {
    "clear_fail": 1, "clear_count": 1, "off_count": 1,
    "vmcs_active": 1, "dirty_vmcs": 1, "backing_vmcs": 1,
    "history": 1, "reason": 1, "qualification": 1,
    "msr_rearm_count": 1, "entry_msr_count": 1,
    "cr0": 1, "cr4": 1, "dr7": 1, "cr3_count": 1, "cr3_values": 2,
    "gdt_base": 1, "gdt_limit": 1, "idt_base": 1, "idt_limit": 1,
    "selectors": 8, "msr_mask": 1, "msrs": 9,
}
model_offsets = {}
cursor = 0
for name, count in model_fields.items():
    model_offsets[name] = cursor
    cursor += count * 8

helpers = r"""
.text
.macro test_note field, value
    pushfq
    push rsi
    mov rsi, qword ptr [rip + test_model]
    mov qword ptr [rsi + \field], \value
    pop rsi
    popfq
.endm
.macro test_vmclear
    push rax
    push rdx
    mov rax, qword ptr [rip + test_model]
    inc qword ptr [rax + $clear_count]
    shl qword ptr [rax + $history], 4
    or qword ptr [rax + $history], 1
    cmp qword ptr [rax + $clear_fail], 0
    jne .Ltest_clear_failure\@
    mov rdx, qword ptr [rax + $dirty_vmcs]
    mov qword ptr [rax + $backing_vmcs], rdx
    mov qword ptr [rax + $vmcs_active], 0
    cmp rax, 0
    jmp .Ltest_clear_done\@
.Ltest_clear_failure\@:
    cmp qword ptr [rax + $clear_fail], 1
    jne .Ltest_clear_valid\@
    cmp rax, 0
    stc
    jmp .Ltest_clear_done\@
.Ltest_clear_valid\@:
    cmp rax, rax
.Ltest_clear_done\@:
    pop rdx
    pop rax
.endm
.macro test_vmxoff
    push rax
    mov rax, qword ptr [rip + test_model]
    inc qword ptr [rax + $off_count]
    shl qword ptr [rax + $history], 4
    or qword ptr [rax + $history], 2
    cmp qword ptr [rax + $vmcs_active], 0
    je .Ltest_off_preserved\@
    mov qword ptr [rax + $backing_vmcs], 0
.Ltest_off_preserved\@:
    mov qword ptr [rax + $vmcs_active], 0
    cmp rax, 0
    pop rax
.endm
.macro test_vmread
    push rsi
    mov rsi, qword ptr [rip + test_model]
    cmp eax, 0
    jne .Ltest_read_qualification\@
    mov r11, qword ptr [rsi + $reason]
    jmp .Ltest_read_done\@
.Ltest_read_qualification\@:
    mov r11, qword ptr [rsi + $qualification]
.Ltest_read_done\@:
    cmp rsi, 0
    pop rsi
.endm
.macro test_vmwrite
    push rax
    mov rax, qword ptr [rip + test_model]
    inc qword ptr [rax + $msr_rearm_count]
    mov qword ptr [rax + $entry_msr_count], r11
    cmp rax, 0
    pop rax
.endm
.macro test_write_cr3 value
    pushfq
    push rax
    push rsi
    mov rsi, qword ptr [rip + test_model]
    mov rax, qword ptr [rsi + $cr3_count]
    mov qword ptr [rsi + $cr3_values + rax * 8], \value
    inc qword ptr [rsi + $cr3_count]
    shl qword ptr [rsi + $history], 4
    add rax, 3
    or qword ptr [rsi + $history], rax
    pop rsi
    pop rax
    popfq
.endm
.macro test_load_table displacement, base_field, limit_field
    pushfq
    push rax
    push rsi
    mov rsi, qword ptr [rip + test_model]
    mov rax, qword ptr [rsp + 24 + \displacement + 2]
    mov qword ptr [rsi + \base_field], rax
    movzx eax, word ptr [rsp + 24 + \displacement]
    mov qword ptr [rsi + \limit_field], rax
    pop rsi
    pop rax
    popfq
.endm
.macro test_segment index
    pushfq
    push rax
    push rsi
    mov rsi, qword ptr [rip + test_model]
    movzx eax, ax
    mov qword ptr [rsi + $selectors + (\index * 8)], rax
    pop rsi
    pop rax
    popfq
.endm
.macro test_far_return
    pushfq
    push rax
    push rsi
    mov rsi, qword ptr [rip + test_model]
    mov rax, qword ptr [rsp + 32]
    mov qword ptr [rsi + $selectors], rax
    pop rsi
    pop rax
    popfq
    lea rsp, [rsp + 16]
.endm
.macro test_wrmsr
    pushfq
    push rsi
    push rdi
    push r11
    mov rsi, qword ptr [rip + test_model]
    lea rdi, [rip + test_msr_indices]
    xor r11d, r11d
.Ltest_msr_find\@:
    cmp ecx, dword ptr [rdi + r11 * 4]
    je .Ltest_msr_found\@
    inc r11d
    cmp r11d, 9
    jb .Ltest_msr_find\@
    ud2
.Ltest_msr_found\@:
    mov qword ptr [rsi + $msrs + r11 * 8], rax
    bts qword ptr [rsi + $msr_mask], r11
    pop r11
    pop rdi
    pop rsi
    popfq
.endm
"""
helpers = re.sub(r"\$([a-z0-9_]+)", lambda match: str(model_offsets[match[1]]), helpers)

replacements = {
    "vmread r11, rax": "test_vmread",
    "vmwrite rax, r11": "test_vmwrite", "vmxoff": "test_vmxoff",
    "mov cr0, r11": f'test_note {model_offsets["cr0"]}, r11',
    "mov cr4, r11": f'test_note {model_offsets["cr4"]}, r11',
    "mov dr7, rax": f'test_note {model_offsets["dr7"]}, rax',
    "mov cr3, r11": "test_write_cr3 r11", "mov cr3, rdx": "test_write_cr3 rdx",
    "lgdt [rsp]": f'test_load_table 0, {model_offsets["gdt_base"]}, {model_offsets["gdt_limit"]}',
    "lidt [rsp + 16]": f'test_load_table 16, {model_offsets["idt_base"]}, {model_offsets["idt_limit"]}',
    "retfq": "test_far_return", "wrmsr": "test_wrmsr", "lldt ax": "test_segment 6",
    "ltr ax": "test_segment 7\nor byte ptr [rdx + rax + 5], 2",
}
for index, name in enumerate(("ss", "es", "ds", "fs", "gs"), start=1):
    replacements[f"mov {name}, ax"] = f"test_segment {index}"
assembly = "\n".join(
    "test_vmclear" if line.startswith("vmclear ") else replacements.get(line, line)
    for line in assembly.splitlines()
)

wrappers = r"""
.text
.globl test_control_runtime_base
test_control_runtime_base:
    lea rax, [rip + matrixhv_resident_set_variable]
    ret
.globl test_control_restore_address
test_control_restore_address:
    lea rax, [rip + .Lresident_control_on_native_restore]
    ret
.macro test_setup
    mov qword ptr [rip + test_model], rdx
    mov qword ptr [rip + matrixhv_resident_bridge_context], rcx
    mov r10, rcx
    mov r9, r8
    imul r9, @state_size
    lea r9, [r10 + r9 + @states]
.endm
.globl test_control_off
test_control_off:
    test_setup
    pushfq
    jmp .Lresident_control_off_native
.globl test_control_cleanup
test_control_cleanup:
    test_setup
    push r12
    pushfq
    mov qword ptr [r9 + @caller_rsp], rsp
    jmp .Lresident_control_on_root_cleanup
.globl test_control_dispatch
test_control_dispatch:
    mov qword ptr [rip + test_model], r8
    mov qword ptr [rip + matrixhv_resident_bridge_context], rdx
    mov r8, r9
    imul r9, @state_size
    lea r9, [rdx + r9 + @states]
    mov r10, rdx
    push r12
    pushfq
    mov qword ptr [r9 + @caller_rsp], rsp
    mov r12, qword ptr [r9 + @sequence]
    sub rsp, 8
    mov qword ptr [rsp], rcx
    jmp matrixhv_resident_dispatch_entry
.Lresident_control_capture_native:
    pushfq
    inc qword ptr [r9 + @snapshot_count]
    popfq
    ret
.Lresident_dispatch_unsupported:
    movabs rax, 0x8000000000000003
.Ltest_dispatch_return:
    mov qword ptr [rsp], rax
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    add rsp, 8
    popfq
    pop r12
    ret
.Lresident_dispatch_vmread_failed:
.Lresident_dispatch_vmwrite_failed:
matrixhv_resident_island_fatal:
    ud2
matrixhv_resident_set_variable:
    ud2
.data
.balign 8
test_model:
    .quad 0
matrixhv_resident_bridge_context:
    .quad 0
matrixhv_resident_island_msr_switch_count:
    .quad 1
test_msr_indices:
    .long 0x1d9, 0x277, 0xc0000080, 0xc0000100, 0xc0000101, 0x174, 0x175, 0x176, 0x48
"""
wrapper_offsets = {
    "state_size": sizes["control_cpu_"], "states": offsets["event_control_cpu_states"],
    "caller_rsp": offsets["control_cpu_native_caller_rsp"],
    "sequence": offsets["control_cpu_sequence"],
    "snapshot_count": offsets["control_cpu_native_snapshot_count"],
}
wrappers = re.sub(r"@([a-z0-9_]+)", lambda match: str(wrapper_offsets[match[1]]), wrappers)
(output / "resident-control.S").write_text(helpers + assembly + "\n" + wrappers, encoding="utf-8")

mapping = "fn offset(name: &str) -> usize { match name {\n"
mapping += "\n".join(f'    "{name}" => {value // 8},' for name, value in offsets.items())
mapping += '\n    _ => panic!("unknown control field {name}"),\n} }\n'
for name, prefix in (("BOOT_WORDS", "b_"), ("EVENT_WORDS", "event_"),
                     ("STATE_WORDS", "control_cpu_"), ("PROBE_WORDS", "probe_")):
    mapping += f"const {name}: usize = {sizes[prefix] // 8};\n"
mapping += "#[repr(C)]\n#[derive(Default)]\nstruct Model {\n"
mapping += "\n".join(
    f"    {name}: " + ("u64," if count == 1 else f"[u64; {count}],")
    for name, count in model_fields.items()
)
mapping += "\n}\n"
(output / "offsets.rs").write_text(mapping, encoding="utf-8")
executable = output / "resident-control-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(project / "tests/resident_control.rs"),
                "-o", str(executable)], check=True, cwd=project)
subprocess.run([str(executable)], check=True, cwd=project)
