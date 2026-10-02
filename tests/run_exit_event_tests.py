"""Compile the resident event handlers with deterministic VMCS operations."""
from pathlib import Path
import re
import subprocess


PROJECT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT / "builds/exit-event-tests"
OUTPUT.mkdir(parents=True, exist_ok=True)
EXITS = (PROJECT / "src/asm/exits.S").read_text(encoding="utf-8")
NESTED = (PROJECT / "src/asm/nested.S").read_text(encoding="utf-8")


def section(source: str, first: str, last: str) -> str:
    start = source.index(first)
    return source[start:source.index(last, start)]


fields = {
    "b_last_reason": 0,
    "b_last_qualification": 8,
    "b_last_guest_rip": 16,
    "b_last_instruction_len": 24,
    "idt_vectoring_info_field": 0,
    "pin_based_vm_exec_control": 1,
    "guest_interruptibility_info": 2,
    "vm_entry_intr_info_field": 3,
    "idt_vectoring_error_code": 4,
    "vm_entry_exception_error_code": 5,
    "exit_instruction_len": 6,
    "vm_entry_instruction_len": 7,
    "guest_cr0": 8,
    "guest_activity_state": 9,
    "guest_cs_ar_bytes": 10,
    "guest_rflags": 11,
    "guest_ia32_debugctl": 12,
    "guest_pending_dbg_exceptions": 13,
    "guest_rip": 14,
    "guest_efer": 15,
    "ept_violation_reason": 48,
}

event = (
    section(EXITS, ".Lresident_dispatch_inject_gp_vmcs:", ".Lresident_advance_guest_rip:")
    + section(EXITS, ".Lresident_advance_guest_rip:", ".Lresident_dispatch_vmwrite_failed:")
    + section(EXITS, ".Lresident_retry_ept_event:", ".endm")
)
event = re.sub(r"\{(\w+)\}", lambda match: str(fields[match[1]]), event)
event = re.sub(
    r"vmread (r\w+), rax",
    r"mov \1, [r12 + 64 + rax * 8]\ncmp r12, 0",
    event,
)
event = re.sub(
    r"vmwrite rax, (r\w+)",
    r"mov [r12 + 64 + rax * 8], \1\ncmp r12, 0",
    event,
)
assert not re.search(r"(?m)^vm(?:read|write) ", event)

arm = section(EXITS, ".Lresident_host_arm_nmi_window:", "matrixhv_island_host_fatal")
arm_fields = {
    "cpu_based_vm_exec_control": 0,
    "b_nested_l2_active": 0,
    "b_nested_vmcs02_control_cache_valid": 8,
    "b_root_vmx_active": 32,
}
arm = re.sub(r"\{(\w+)\}", lambda match: str(arm_fields[match[1]]), arm)
arm = arm.replace("vmread rdx, rax", "mov rdx, [rcx + 24]\ncmp rcx, 0")
arm = arm.replace("vmwrite rax, rdx", "mov [rcx + 24], rdx\ncmp rcx, 0")
assert not re.search(r"(?m)^vm(?:read|write) ", arm)

window = section(NESTED, ".Lresident_dispatch_nmi_window:", ".Lresident_dispatch_invept_software_prepare:")
window_fields = {
    "cpu_based_vm_exec_control": 0,
    "b_nmi_pending": 0,
    "b_nested_l2_active": 8,
    "b_nested_vmcs12_pin_based_control": 16,
    "b_nested_l2_nmi_exit_pending": 24,
    "b_nested_vmcs02_launched": 32,
    "b_last_reason": 40,
    "b_last_qualification": 48,
    "b_last_instruction_len": 56,
    "b_nested_vmcs02_control_cache_valid": 64,
}
window = re.sub(r"\{(\w+)\}", lambda match: str(window_fields[match[1]]), window)
window = window.replace("vmread r11, rax", "mov r11, [r12 + 88]\ncmp r12, 0")
window = window.replace("vmwrite rax, r11", "mov [r12 + 88], r11\ncmp r12, 0")
assert not re.search(r"(?m)^vm(?:read|write) ", window)

delivery = section(EXITS, ".Lresident_deliver_pending_nmi:", ".endm")
delivery_fields = dict(
    window_fields,
    vm_entry_intr_info_field=1,
    guest_interruptibility_info=2,
    guest_pending_dbg_exceptions=3,
    guest_activity_state=4,
)
delivery = re.sub(r"\{(\w+)\}", lambda match: str(delivery_fields[match[1]]), delivery)
delivery = delivery.replace("vmread r11, rax", "mov r11, [r12 + 88 + rax * 8]\ncmp r12, 0")
delivery = delivery.replace("vmwrite rax, r11", "mov [r12 + 88 + rax * 8], r11\ncmp r12, 0")
assert not re.search(r"(?m)^vm(?:read|write) ", delivery)

entry = ""
for label in (".Lresident_nested_l2_launch_registers:", ".Lresident_nested_l2_resume_registers:"):
    entry += section(NESTED, label, "pop rax") + "ret\n"

assembly = ".text\n" + event + arm + window + delivery + entry + """
.Lresident_dispatch_vmread_failed:
.Lresident_dispatch_vmwrite_failed:
.Lresident_dispatch_event_corrupt:
ud2
.Lresident_dispatch_resume:
.Lresident_watchdog_handler_returned:
.Lresident_sync_ept_cache:
.Lresident_nested_refresh_eptp_list:
.Lresident_profile_exit_handler:
.Lresident_watchdog_resuming:
.Lresident_nested_eptp_sync_enter:
.Lresident_nested_prepare_full_msr_entry:
ret
.Lresident_boot_timer_retry_event:
mov qword ptr [r12 + 80], 3
ret
.Lresident_nested_l2_resume_ept:
mov qword ptr [r12 + 80], 2
ret
.Lresident_nested_l2_reflect_generic:
mov qword ptr [r12 + 80], 1
ret
.globl test_event_gp
test_event_gp:
push r12
mov r12, rcx
call .Lresident_dispatch_inject_gp_vmcs
pop r12
ret
.globl test_event_advance
test_event_advance:
push r12
mov r12, rcx
call .Lresident_advance_guest_rip
pop r12
ret
.globl test_event_retry
test_event_retry:
push r12
mov r12, rcx
call .Lresident_retry_ept_event
pop r12
ret
.globl test_host_arm_nmi_window
test_host_arm_nmi_window:
mov rax, rcx
call .Lresident_host_arm_nmi_window
ret
.globl test_nested_nmi_window
test_nested_nmi_window:
push r12
mov r12, rcx
call .Lresident_dispatch_nmi_window
pop r12
ret
.globl test_deliver_pending_nmi
test_deliver_pending_nmi:
push r12
mov r12, rcx
call .Lresident_deliver_pending_nmi
pop r12
ret
.globl test_nested_l2_launch_entry
test_nested_l2_launch_entry:
push r12
mov r12, rcx
call .Lresident_nested_l2_launch_registers
pop r12
ret
.globl test_nested_l2_resume_entry
test_nested_l2_resume_entry:
push r12
mov r12, rcx
call .Lresident_nested_l2_resume_registers
pop r12
ret
"""
(OUTPUT / "event.S").write_text(assembly, encoding="utf-8")
binary = OUTPUT / "exit_event_tests.exe"
subprocess.run(
    ["rustc", "--edition=2024", "-Dwarnings", "--test",
     str(PROJECT / "tests/exit_event_tests.rs"), "-o", str(binary)],
    cwd=PROJECT,
    check=True,
)
subprocess.run([str(binary)], cwd=PROJECT, check=True)
