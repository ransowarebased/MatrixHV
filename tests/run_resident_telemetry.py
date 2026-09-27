from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "resident-telemetry-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/asm/resident_island.S").read_text(encoding="utf-8")
start = source.index('.Lresident_dispatch_cpuid_diagnostic:')
end = source.index('.Lresident_dispatch_cpuid_standard:', start)
trace_start = source.index('.Lresident_nested_record_failure:')
trace_end = source.index('.Lresident_dispatch_cpuid:', trace_start)
assembly = source[trace_start:trace_end] + "\n" + source[start:end]
profile_start = source.index('.Lresident_profile_exit_handler:')
profile_end = source.index('.Lresident_dispatch_halt:', profile_start)
assembly += "\n" + source[profile_start:profile_end]
macro_start = source.index('.macro resident_telemetry_counter ')
macro_end = source.index('.endm', macro_start) + len('.endm')
assembly = source[macro_start:macro_end] + "\n" + assembly
names = sorted(set(re.findall(r"\{((?:b_|event_)[a-z0-9_]+)\}", assembly)))
offsets = {}
cursor = 0
for name in names:
    offsets[name] = cursor
    cursor += 512 if name == "event_cpu_contexts" else (
        192 * 8 if name == "b_nested_failure_trace" else (
        56 if name in {"b_watchdog_before", "b_watchdog_after", "b_watchdog_resume", "b_entry_failure_guest"}
        else 32 if name == "b_nested_exit_handler_cycles" else 8
        )
    )
constants = {
    "cpuid_reason": 10, "matrixhv_status_leaf": 0x4D485652,
    "ept_violation_reason": 48, "invept_reason": 50, "preemption_timer_reason": 52,
    "vmread_reason": 23, "vmwrite_reason": 25, "vmlaunch_reason": 20, "vmresume_reason": 24,
    "log_serial_sink": 1,
    "nested_failure_trace_capacity": 32,
    "nested_failure_trace_limit": 0x161,
    "guest_rip": 0, "guest_rsp": 1, "guest_rflags": 2,
    "guest_cr0": 3, "guest_cr3": 4, "guest_cr4": 5, "guest_efer": 6,
}
assembly = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(
    (offsets if match[1] in offsets else constants)[match[1]]
), assembly)
assembly = assembly.replace("rdtsc", "mov eax, 100\nxor edx, edx")
assembly = assembly.replace("vmread r11, rax",
    "lea r11, [rip + test_guest_state]\nmov r11, [r11 + rax * 8]\ncmp r12, 0")
wrappers = """
.text
.globl test_watchdog_begin
test_watchdog_begin:
    push r12
    mov r12, rcx
    mov r10d, [r12 + LAST_RAX_OFFSET]
    call .Lresident_telemetry_begin
    call .Lresident_watchdog_begin
    pop r12
    ret
.globl test_watchdog_complete
test_watchdog_complete:
    push r12
    mov r12, rcx
    call .Lresident_watchdog_handler_returned
    call .Lresident_watchdog_resuming
    pop r12
    ret
.globl test_counter
test_counter:
    push r12
    mov r12, rcx
    stc
    resident_telemetry_counter inc, EXIT_COUNT_OFFSET, ACTIVE_OFFSET
    pushfq
    pop rax
    pop r12
    ret
.globl test_profile_exit
test_profile_exit:
    push r12
    mov r12, rcx
    call .Lresident_profile_exit_handler
    pop r12
    ret
.globl test_nested_failure_record
test_nested_failure_record:
    push r12
    mov r12, rcx
    mov r10, r8
    mov r8, rdx
    call .Lresident_nested_record_failure
    pop r12
    ret
.globl test_diagnostic
test_diagnostic:
    push rbx
    push r12
    push r13
    mov r12, rcx
    mov [r12 + EVENT_OFFSET], rdx
    mov ecx, r8d
    mov r13, r9
    sub rsp, 32
    jmp .Lresident_dispatch_cpuid_diagnostic
.Lresident_dispatch_cpuid_advance:
    mov eax, [rsp]
    mov [r13], eax
    mov eax, [rsp + 24]
    mov [r13 + 4], eax
    mov eax, [rsp + 8]
    mov [r13 + 8], eax
    mov eax, [rsp + 16]
    mov [r13 + 12], eax
    add rsp, 32
    pop r13
    pop r12
    pop rbx
    ret
.Lresident_dispatch_vmread_failed:
    ud2
.data
.balign 8
test_guest_state:
    .quad 0x123456789abcdef0, 0xabcdef0123456780, 0x202, 0x80000011, 0x1000, 0x2000, 0x500
matrixhv_resident_island_log_backend:
    .byte 0
.text
"""
wrappers = wrappers.replace("EVENT_OFFSET", str(offsets["b_event_context"]))
wrappers = wrappers.replace("LAST_RAX_OFFSET", str(offsets["b_last_rax"]))
wrappers = wrappers.replace("EXIT_COUNT_OFFSET", str(offsets["b_exit_count"]))
wrappers = wrappers.replace("ACTIVE_OFFSET", str(offsets["b_telemetry_active"]))
counter_macro, assembly = assembly.split('.endm', 1)
(output / "resident-telemetry.S").write_text(
    counter_macro + '.endm\n' + wrappers + "\n" + assembly, encoding="utf-8"
)
mapping = "fn offset(name: &str) -> usize { match name {\n"
mapping += "\n".join(f'    "{name}" => {value // 8},' for name, value in offsets.items())
mapping += '\n    _ => panic!("unknown telemetry field {name}"),\n} }\n'
(output / "offsets.rs").write_text(mapping, encoding="utf-8")
executable = output / "resident-telemetry-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(project / "tests/resident_telemetry.rs"),
                "-o", str(executable)], check=True, cwd=project)
subprocess.run([str(executable)], check=True, cwd=project)
