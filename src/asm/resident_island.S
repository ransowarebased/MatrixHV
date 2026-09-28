.text
// Preserve the caller's flags when collection is disabled, including VMX status.
.macro resident_telemetry_counter operation, field_offset, active_offset
pushfq
cmp qword ptr [r12 + \active_offset], 0
je .Lresident_telemetry_counter_skip\@
popfq
\operation qword ptr [r12 + \field_offset]
jmp .Lresident_telemetry_counter_done\@
.Lresident_telemetry_counter_skip\@:
popfq
.Lresident_telemetry_counter_done\@:
.endm
.macro resident_control_probe_vmread field, field_offset
mov rax, \field
vmread r11, rax
jna .Lresident_control_probe_failed
mov qword ptr [rsi + \field_offset], r11
.endm
.macro resident_control_save_host field, index
mov rax, \field
vmread r11, rax
jna .Lresident_control_probe_failed
mov qword ptr [rsi + {control_cpu_host_fields} + (\index * 8)], r11
.endm
.macro resident_control_off_save_host field, index
mov rax, \field
vmread r11, rax
jna .Lresident_control_off_failed
mov qword ptr [rsi + {control_cpu_host_fields} + (\index * 8)], r11
.endm
.macro resident_control_off_patch_host host_field, guest_field
mov rax, \guest_field
vmread r11, rax
jna .Lresident_control_off_restore
mov rax, \host_field
vmwrite rax, r11
jna .Lresident_control_off_restore
.endm
.macro resident_control_off_patch_selector host_field, guest_field
mov rax, \guest_field
vmread r11, rax
jna .Lresident_control_off_restore
and r11d, 0xfff8
mov rax, \host_field
vmwrite rax, r11
jna .Lresident_control_off_restore
.endm
.macro resident_control_off_restore_host field, index
mov rax, \field
mov r11, qword ptr [rsi + {control_cpu_host_fields} + (\index * 8)]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.endm
.macro resident_control_off_vmread field, field_offset
mov rax, \field
vmread r11, rax
jna .Lresident_control_off_failed
mov qword ptr [r10 + \field_offset], r11
.endm
.macro resident_control_on_restore_host field, index
mov rax, \field
mov rdx, qword ptr [r9 + {control_cpu_host_fields} + (\index * 8)]
vmwrite rax, rdx
jna .Lresident_control_on_root_failed
.endm
.macro resident_control_on_write field, value
mov rax, \field
mov rdx, \value
vmwrite rax, rdx
jna .Lresident_control_on_root_failed
.endm
.macro resident_control_on_write_msr msr_index, field, index
mov ecx, \msr_index
rdmsr
shl rdx, 32
or rdx, rax
mov qword ptr [r9 + {control_cpu_on_native_msrs} + (\index * 8)], rdx
mov eax, \field
vmwrite rax, rdx
jna .Lresident_control_on_root_failed
.endm
.macro resident_control_on_restore_msr msr_index, index
mov rax, qword ptr [r9 + {control_cpu_on_native_msrs} + (\index * 8)]
mov rdx, rax
shr rdx, 32
mov ecx, \msr_index
wrmsr
.endm
.macro resident_control_native_checkpoint stage
mov qword ptr [r9 + {control_cpu_stage}], \stage
call .Lresident_control_capture_native
.endm
.globl matrixhv_resident_guest_probe_asm
matrixhv_resident_guest_probe_asm:
vmcall
ud2
.globl matrixhv_resident_probe_run_asm
matrixhv_resident_probe_run_asm:
push rbx
push rbp
push rdi
push rsi
push r12
push r13
push r14
push r15
mov qword ptr [rcx + 0], rsp
lea rax, [rip + 9f]
mov qword ptr [rcx + 8], rax
sgdt [rcx + 88]
sidt [rcx + 98]
mov rax, {host_rsp}
vmwrite rax, rdx
jc 3f
jz 3f
mov rax, {host_rip}
vmwrite rax, r8
jc 4f
jz 4f
vmlaunch
jc 1f
jz 2f
mov eax, 5
jmp 8f
1:
mov eax, 1
jmp 8f
2:
mov eax, 2
jmp 8f
3:
mov eax, 3
jmp 8f
4:
mov eax, 4
jmp 8f
9:
lgdt [r10 + 88]
lidt [r10 + 98]
xor eax, eax
8:
pop r15
pop r14
pop r13
pop r12
pop rsi
pop rdi
pop rbp
pop rbx
ret
.globl matrixhv_resident_boot_run_asm
matrixhv_resident_boot_run_asm:
push rbx
push rbp
push rdi
push rsi
push r12
push r13
push r14
push r15
mov qword ptr [rcx + {b_root_rsp}], rsp
lea rax, [rip + .Lresident_boot_return]
mov qword ptr [rcx + {b_return_rip}], rax
sgdt [rcx + {b_gdtr}]
sidt [rcx + {b_idtr}]
fxsave64 [rcx + {b_fx}]
mov rax, {host_rsp}
vmwrite rax, rdx
jc .Lresident_boot_rsp_fail
jz .Lresident_boot_rsp_fail
mov rax, {host_rip}
vmwrite rax, r8
jc .Lresident_boot_rip_fail
jz .Lresident_boot_rip_fail
mov rax, qword ptr [rcx + {b_nested_vmxon_operand}]
vmlaunch
jc .Lresident_boot_fail_invalid
jz .Lresident_boot_fail_valid
mov eax, 5
jmp .Lresident_boot_failure_restore
.Lresident_boot_fail_invalid:
mov eax, 1
jmp .Lresident_boot_failure_restore
.Lresident_boot_fail_valid:
mov eax, 2
jmp .Lresident_boot_failure_restore
.Lresident_boot_rsp_fail:
mov eax, 3
jmp .Lresident_boot_failure_restore
.Lresident_boot_rip_fail:
mov eax, 4
.Lresident_boot_failure_restore:
fxrstor64 [rcx + {b_fx}]
jmp .Lresident_boot_pop
.Lresident_boot_return:
lgdt [r12 + {b_gdtr}]
lidt [r12 + {b_idtr}]
fxrstor64 [r12 + {b_fx}]
xor eax, eax
.Lresident_boot_pop:
pop r15
pop r14
pop r13
pop r12
pop rsi
pop rdi
pop rbp
pop rbx
ret

.globl matrixhv_resident_startup_halt_asm
matrixhv_resident_startup_halt_asm:
.Lresident_startup_halt:
cli
hlt
jmp .Lresident_startup_halt

.section .text.matrixhv_resident_island,"ax"
.p2align 4
.globl matrixhv_resident_island_start
.globl matrixhv_resident_island_entry
matrixhv_resident_island_start:
matrixhv_resident_island_entry:
cld
mov r10, qword ptr [rsp]
mov rax, cr3
mov qword ptr [r10 + 32], rax
mov rax, {guest_cr3}
vmread r11, rax
jc matrixhv_resident_island_fatal
jz matrixhv_resident_island_fatal
mov qword ptr [r10 + 40], r11
mov rax, {exit_reason}
vmread r11, rax
jc matrixhv_resident_island_fatal
jz matrixhv_resident_island_fatal
mov qword ptr [r10 + 48], r11
mov rax, {guest_rip}
vmread r11, rax
jc matrixhv_resident_island_fatal
jz matrixhv_resident_island_fatal
mov qword ptr [r10 + 56], r11
mov rax, {complete}
mov qword ptr [r10 + 72], rax
mov rax, qword ptr [r10 + 16]
mov cr3, rax
mov rsp, qword ptr [r10 + 0]
jmp qword ptr [r10 + 8]
.globl matrixhv_resident_dispatch_entry
matrixhv_resident_dispatch_entry:
cld
push r15
push r14
push r13
push r12
push r11
push r10
push r9
push r8
push rdi
push rsi
push rbp
push rbx
push rdx
push rcx
push rax
mov r12, qword ptr [rsp + 120]
test r12, r12
jz matrixhv_resident_island_fatal
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
mov rax, {boot_canary_start}
cmp qword ptr [r12 + {b_canary_start}], rax
jne matrixhv_resident_island_fatal
mov rax, {boot_canary_end}
cmp qword ptr [r12 + {b_canary_end}], rax
jne matrixhv_resident_island_fatal
mov rax, {exit_reason}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_last_reason}], r11
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_control_rearm_done
mov rcx, qword ptr [r12 + {b_processor_number}]
cmp rcx, 64
jae .Lresident_control_rearm_done
bt qword ptr [rdi + {event_control_rearm_mask}], rcx
jnc .Lresident_control_rearm_done
test r11d, 0x80000000
jnz .Lresident_control_on_entry_failed
lock btr qword ptr [rdi + {event_control_rearm_mask}], rcx
mov eax, {vm_entry_msr_load_count}
mov r11, qword ptr [rip + matrixhv_resident_island_msr_switch_count]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_control_rearm_done:
call .Lresident_nested_eptp_sync_poll
mov rax, {guest_rip}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_last_guest_rip}], r11
mov r10d, dword ptr [rsp]
call .Lresident_telemetry_begin
resident_telemetry_counter inc, {b_exit_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_normal_exit_recorded
mov rax, qword ptr [rsp]
mov qword ptr [r12 + {b_last_rax}], rax
mov rax, qword ptr [rsp + 8]
mov qword ptr [r12 + {b_last_rcx}], rax
mov rax, qword ptr [rsp + 16]
mov qword ptr [r12 + {b_last_rdx}], rax
mov rax, cr3
mov qword ptr [r12 + {b_last_host_cr3}], rax
mov eax, dword ptr [r12 + {b_last_reason}]
cmp eax, {preemption_timer_reason}
je .Lresident_normal_exit_recorded
mov qword ptr [r12 + {b_last_normal_reason}], rax
mov qword ptr [r12 + {b_last_normal_rip}], r11
.Lresident_normal_exit_recorded:
mov rax, {exit_instruction_len}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_last_instruction_len}], r11
mov rax, {exit_qualification}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_last_qualification}], r11
call .Lresident_nested_eptp_sync_exit_nmi
test eax, eax
jz .Lresident_dispatch_external_exit
cmp qword ptr [r12 + {b_nested_l2_active}], 0
je .Lresident_boot_timer_retry_event
mov qword ptr [r12 + {b_nested_vmcs02_launched}], 1
jmp .Lresident_nested_l2_resume_ept
.Lresident_dispatch_external_exit:
call .Lresident_watchdog_begin
mov rax, cr3
cmp rax, qword ptr [r12 + {b_expected_host_cr3}]
jne .Lresident_dispatch_host_cr3_mismatch
cmp qword ptr [r12 + {b_processor_number}], 0
jne .Lresident_visual_first_exit_done
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_visual_first_exit_done
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_framebuffer_sink}
jz .Lresident_visual_first_exit_done
cmp qword ptr [r12 + {b_visual_first_exit_seen}], 0
jne .Lresident_visual_first_exit_done
mov r10, qword ptr [r12 + {b_event_context}]
test r10, r10
jz .Lresident_visual_first_exit_call
cmp qword ptr [r10 + {event_ebs_seen}], 0
jne .Lresident_visual_first_exit_done
.Lresident_visual_first_exit_call:
mov rcx, qword ptr [r12 + {b_last_reason}]
xor edx, edx
mov r8, qword ptr [r12 + {b_last_guest_physical_address}]
mov r9, qword ptr [r12 + {b_last_guest_rip}]
mov r10, qword ptr [r12 + {b_last_qualification}]
call .Lresident_visual_callback
test rax, rax
jz .Lresident_visual_first_exit_done
mov qword ptr [r12 + {b_visual_first_exit_seen}], 1
.Lresident_visual_first_exit_done:
cmp qword ptr [r12 + {b_nested_l2_active}], 1
je .Lresident_nested_l2_reflect
cmp qword ptr [r12 + {b_nested_vmcs01_msr_entry_composed}], 0
je .Lresident_dispatch_vmcs01_msr_entry_ready
mov rax, {vm_entry_msr_load_addr}
mov r11, qword ptr [r12 + {b_nested_l0_msr_guest_list}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {vm_entry_msr_load_count}
mov r11d, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [r12 + {b_nested_vmcs01_msr_entry_composed}], 0
.Lresident_dispatch_vmcs01_msr_entry_ready:
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_dispatch_after_events
mov rax, {event_magic}
cmp qword ptr [rdi + {event_magic_offset}], rax
jne .Lresident_dispatch_event_corrupt
mov rax, {event_canary}
cmp qword ptr [rdi + {event_canary_offset}], rax
jne .Lresident_dispatch_event_corrupt
cmp qword ptr [rdi + {event_ebs_seen}], 0
je .Lresident_dispatch_check_va
mov rcx, qword ptr [r12 + {b_processor_number}]
cmp rcx, 64
jae .Lresident_post_ebs_cpu_seen
bt qword ptr [rdi + {event_post_ebs_cpu_mask}], rcx
jc .Lresident_post_ebs_cpu_seen
lock bts qword ptr [rdi + {event_post_ebs_cpu_mask}], rcx
.Lresident_post_ebs_cpu_seen:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_check_va
inc qword ptr [r12 + {b_post_ebs_count}]
cmp qword ptr [r12 + {b_processor_number}], 0
jne .Lresident_dispatch_check_va
cmp qword ptr [rdi + {event_diagnostic_halted}], 0
jne .Lresident_dispatch_after_events
mov rcx, qword ptr [r12 + {b_post_ebs_count}]
cmp rcx, 8
ja .Lresident_post_ebs_progress_done
add ecx, 20
mov r8, rdi
call .Lresident_paint_stage
.Lresident_post_ebs_progress_done:
// Keep diagnostic refreshes bounded and reduce MMIO traffic after the first exits.
cmp qword ptr [r12 + {b_diagnostic_expired}], 0
jne .Lresident_post_ebs_snapshot_done
mov rcx, qword ptr [r12 + {b_post_ebs_count}]
cmp rcx, 65536
ja .Lresident_post_ebs_snapshot_done
cmp rcx, 32
jbe .Lresident_post_ebs_snapshot
lea rax, [rcx - 1]
test rax, rcx
jnz .Lresident_post_ebs_snapshot_done
.Lresident_post_ebs_snapshot:
mov r8, rdi
call .Lresident_diagnostic_snapshot
.Lresident_post_ebs_snapshot_done:
cmp qword ptr [r12 + {b_post_ebs_count}], 1
jne .Lresident_dispatch_check_va
mov r8, rdi
mov ecx, 2
call .Lresident_paint_stage
mov eax, dword ptr [r12 + {b_last_reason}]
mov ecx, 5
call .Lresident_paint_byte
lea rsi, [rip + .Lpost_ebs_exit_message]
mov r9d, {post_ebs_exit_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
.Lresident_dispatch_check_va:
cmp qword ptr [rdi + {event_va_seen}], 0
je .Lresident_dispatch_after_events
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_after_events
inc qword ptr [r12 + {b_post_va_count}]
cmp qword ptr [r12 + {b_processor_number}], 0
jne .Lresident_dispatch_after_events
cmp qword ptr [r12 + {b_post_va_count}], 1
jne .Lresident_dispatch_after_events
cmp qword ptr [rdi + {event_diagnostic_halted}], 0
jne .Lresident_dispatch_after_events
mov r8, rdi
mov ecx, 3
call .Lresident_paint_stage
call .Lresident_diagnostic_snapshot
lea rsi, [rip + .Lpost_va_exit_message]
mov r9d, {post_va_exit_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
.Lresident_dispatch_after_events:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_reason
cmp qword ptr [r12 + {b_start_checkpoint_seen}], 0
je .Lresident_dispatch_reason
resident_telemetry_counter inc, {b_post_start_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_post_start_count}], 1
jne .Lresident_dispatch_reason
lea rsi, [rip + .Lfirst_start_exit_message]
mov r9d, {first_start_exit_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
.Lresident_dispatch_reason:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_reason_ready
mov qword ptr [r12 + {b_watchdog_phase}], 3
.Lresident_dispatch_reason_ready:
mov rax, qword ptr [r12 + {b_last_reason}]
test eax, 0x80000000
jnz .Lresident_dispatch_unsupported
and eax, 0xffff
cmp eax, 0
je .Lresident_dispatch_exception
cmp eax, 8
je .Lresident_dispatch_nmi_window
cmp eax, 3
je .Lresident_ap_init
cmp eax, 4
je .Lresident_ap_sipi
cmp eax, 28
je .Lresident_ap_cr_access
cmp eax, 13
je .Lresident_dispatch_cache_flush
cmp eax, 54
je .Lresident_dispatch_cache_flush
cmp eax, {ept_violation_reason}
je .Lresident_dispatch_ept_violation
cmp eax, {vmclear_reason}
je .Lresident_dispatch_vmclear
cmp eax, {vmlaunch_reason}
je .Lresident_dispatch_vmlaunch
cmp eax, {vmptrld_reason}
je .Lresident_dispatch_vmptrld
cmp eax, {vmptrst_reason}
je .Lresident_dispatch_vmptrst
cmp eax, {vmread_reason}
je .Lresident_dispatch_vmread
cmp eax, {vmresume_reason}
je .Lresident_dispatch_vmresume
cmp eax, {vmwrite_reason}
je .Lresident_dispatch_vmwrite
cmp eax, {vmxon_reason}
je .Lresident_dispatch_vmxon
cmp eax, {vmxoff_reason}
je .Lresident_dispatch_vmxoff
cmp eax, {invept_reason}
je .Lresident_dispatch_invept
cmp eax, {invvpid_reason}
je .Lresident_dispatch_invvpid
cmp eax, {cpuid_reason}
je .Lresident_dispatch_cpuid
cmp eax, {vmcall_reason}
je .Lresident_dispatch_vmcall
cmp eax, {rdmsr_reason}
je .Lresident_dispatch_rdmsr
cmp eax, {wrmsr_reason}
je .Lresident_dispatch_wrmsr
cmp eax, {xsetbv_reason}
je .Lresident_dispatch_xsetbv
cmp eax, {preemption_timer_reason}
je .Lresident_dispatch_boot_timer
jmp .Lresident_dispatch_unsupported
matrixhv_resident_ap_startup
.Lresident_dispatch_cache_flush:
call .Lresident_msr_privilege
jc .Lresident_dispatch_inject_gp
// INVD must not discard dirty host state on a CPU shared with the guest.
wbinvd
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
matrixhv_resident_nested_reflection
.Lresident_dispatch_ept_violation:
mov rax, {guest_physical_address}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_last_guest_physical_address}], r11
test byte ptr [r12 + {b_last_qualification}], 2
jz .Lresident_dispatch_ept_probe_check
mov r8, r11
call .Lresident_nested_translate_eptp_list_address
test eax, eax
jz .Lresident_dispatch_ept_probe_check
bt qword ptr [rdx], 55
jnc .Lresident_dispatch_ept_probe_check
call .Lresident_nested_eptp_release_sources
jmp .Lresident_dispatch_resume
.Lresident_dispatch_ept_probe_check:
mov r11, qword ptr [r12 + {b_last_guest_physical_address}]
mov r10, r11
and r10, -4096
cmp r10, qword ptr [r12 + {b_ept_test_gpa}]
jne .Lresident_dispatch_ept_unexpected
mov r10, qword ptr [r12 + {b_last_guest_rip}]
cmp r10, qword ptr [r12 + {b_ept_probe_fault_rip}]
jne .Lresident_dispatch_ept_unexpected
mov r10, qword ptr [r12 + {b_last_qualification}]
and r10d, 7
cmp r10, {ept_test_read_access}
jne .Lresident_dispatch_ept_unexpected
mov qword ptr [r12 + {b_ept_test_violation_seen}], 1
lea rsi, [rip + .Lept_test_violation_message]
mov r9d, {ept_test_violation_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_last_guest_physical_address}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lept_violation_rip]
mov r9d, {ept_violation_rip_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_last_guest_rip}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lept_violation_read]
mov r9d, {ept_violation_read_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_last_qualification}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_newline]
mov r9d, {state_newline_len}
call .Lresident_serial_write
mov r10, qword ptr [r12 + {b_ept_probe_resume_rip}]
mov rax, {guest_rip}
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_dispatch_ept_unexpected:
lea rsi, [rip + .Lept_unexpected_violation_message]
mov r9d, {ept_unexpected_violation_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_last_guest_physical_address}]
call .Lresident_serial_hex64
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
matrixhv_resident_nested_handlers
.Lresident_dispatch_cpuid:
resident_telemetry_counter inc, {b_cpuid_count}, {b_telemetry_active}
mov eax, dword ptr [rsp + 0]
mov ecx, dword ptr [rsp + 8]
mov r8d, eax
cmp r8d, {matrixhv_status_leaf}
je .Lresident_dispatch_cpuid_matrixhv
cpuid
mov qword ptr [rsp + 0], rax
mov qword ptr [rsp + 24], rbx
mov qword ptr [rsp + 8], rcx
mov qword ptr [rsp + 16], rdx
cmp r8d, {hypervisor_leaf_start}
jb .Lresident_dispatch_cpuid_standard
cmp r8d, {hypervisor_leaf_end}
ja .Lresident_dispatch_cpuid_standard
resident_telemetry_counter inc, {b_cpuid_hypervisor_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_cpuid_presence}], 0
jne .Lresident_dispatch_cpuid_hypervisor_present
mov qword ptr [rsp + 0], 0
mov qword ptr [rsp + 24], 0
mov qword ptr [rsp + 8], 0
mov qword ptr [rsp + 16], 0
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_cpuid_advance
mov qword ptr [r12 + {b_cpuid_hypervisor_eax}], 0
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_hypervisor_present:
mov r10d, dword ptr [rsp + 0]
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_cpuid_hypervisor_recorded
mov qword ptr [r12 + {b_cpuid_hypervisor_eax}], r10
.Lresident_dispatch_cpuid_hypervisor_recorded:
cmp r8d, {hyperv_features_leaf}
jne .Lresident_dispatch_cpuid_advance
and dword ptr [rsp + 0], {hyperv_guest_idle_access_mask}
and dword ptr [rsp + 16], {hyperv_guest_idle_feature_mask}
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_matrixhv:
resident_telemetry_counter inc, {b_cpuid_hypervisor_count}, {b_telemetry_active}
test ecx, ecx
jnz .Lresident_dispatch_cpuid_diagnostic
mov r10d, {matrixhv_status_signature_eax}
mov qword ptr [rsp + 0], r10
mov r10d, {matrixhv_status_signature_ebx}
mov qword ptr [rsp + 24], r10
mov r10d, {matrixhv_status_signature_ecx}
mov qword ptr [rsp + 8], r10
mov r10d, {matrixhv_status_protocol}
mov qword ptr [rsp + 16], r10
jmp .Lresident_dispatch_cpuid_advance
// Diagnostic subleaves expose bounded snapshots, never guest-selected memory.
.Lresident_dispatch_cpuid_diagnostic:
xor eax, eax
xor ebx, ebx
xor edx, edx
mov r9, qword ptr [r12 + {b_event_context}]
test r9, r9
jz .Lresident_dispatch_cpuid_diagnostic_zero
mov r8, r12
// A nonzero high word selects a bounded resident CPU slot; zero selects this CPU.
mov r10d, ecx
shr r10d, 16
and ecx, 0xffff
test r10d, r10d
jz .Lresident_dispatch_cpuid_target_ready
dec r10d
cmp r10d, 64
jae .Lresident_dispatch_cpuid_diagnostic_zero
mov r8, qword ptr [r9 + {event_cpu_contexts} + r10 * 8]
test r8, r8
jz .Lresident_dispatch_cpuid_diagnostic_zero
.Lresident_dispatch_cpuid_target_ready:
cmp ecx, 1
je .Lresident_dispatch_cpuid_masks_low
cmp ecx, 2
je .Lresident_dispatch_cpuid_masks_high
cmp ecx, 3
jne .Lresident_dispatch_cpuid_diagnostic_extended
mov eax, dword ptr [r9 + {event_failed_processor}]
mov ebx, dword ptr [r9 + {event_failed_exit_reason}]
mov ecx, dword ptr [r9 + {event_failed_qualification}]
mov edx, dword ptr [r9 + {event_failed_stop_result}]
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_masks_high:
add r9, 4
.Lresident_dispatch_cpuid_masks_low:
mov eax, dword ptr [r9 + {event_init_cpu_mask}]
mov ebx, dword ptr [r9 + {event_sipi_cpu_mask}]
mov ecx, dword ptr [r9 + {event_post_ebs_cpu_mask}]
mov edx, dword ptr [r9 + {event_halted_cpu_mask}]
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_diagnostic_extended:
cmp ecx, 4
jb .Lresident_dispatch_cpuid_diagnostic_zero
cmp ecx, 30
jbe .Lresident_dispatch_cpuid_diagnostic_pair
cmp ecx, 31
je .Lresident_dispatch_cpuid_nested_state
cmp ecx, 32
je .Lresident_dispatch_cpuid_fault_low
cmp ecx, 33
je .Lresident_dispatch_cpuid_fault_high
cmp ecx, 34
je .Lresident_dispatch_cpuid_capabilities
cmp ecx, 35
je .Lresident_dispatch_cpuid_lease
cmp ecx, 36
je .Lresident_dispatch_cpuid_registered_cpus
cmp ecx, 37
je .Lresident_dispatch_cpuid_telemetry_state
cmp ecx, 38
jb .Lresident_dispatch_cpuid_diagnostic_zero
cmp ecx, 46
jbe .Lresident_dispatch_cpuid_profile_pair
cmp ecx, 47
je .Lresident_dispatch_cpuid_vmx_secondary
cmp ecx, 48
je .Lresident_dispatch_cpuid_vmx_misc
cmp ecx, 49
je .Lresident_dispatch_cpuid_ept_recycling
cmp ecx, 50
je .Lresident_dispatch_cpuid_control_stage
cmp ecx, 51
je .Lresident_dispatch_cpuid_native_count
cmp ecx, 52
je .Lresident_dispatch_cpuid_native_layout
cmp ecx, 53
je .Lresident_dispatch_cpuid_control_failure
cmp ecx, 0x4000
jae .Lresident_dispatch_cpuid_native_snapshot
cmp ecx, 0x100
je .Lresident_dispatch_cpuid_nested_failure_count
cmp ecx, 0x101
jb .Lresident_dispatch_cpuid_diagnostic_zero
cmp ecx, {nested_failure_trace_limit}
jb .Lresident_dispatch_cpuid_nested_failure_record
cmp ecx, 0x200
je .Lresident_dispatch_cpuid_watchdog_start
cmp ecx, 0x201
je .Lresident_dispatch_cpuid_watchdog_stop
cmp ecx, 0x202
je .Lresident_dispatch_cpuid_telemetry_enable
cmp ecx, 0x203
je .Lresident_dispatch_cpuid_telemetry_disable
cmp ecx, 0x300
jb .Lresident_dispatch_cpuid_diagnostic_zero
cmp ecx, 0x340
jae .Lresident_dispatch_cpuid_diagnostic_zero
sub ecx, 0x300
shl ecx, 4
lea r10, [r8 + {b_nested_exit_reason_counts}]
mov rax, qword ptr [r10 + rcx]
mov rdx, qword ptr [r10 + rcx + 8]
mov rcx, rdx
shr rdx, 32
mov rbx, rax
shr rbx, 32
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_diagnostic_pair:
sub ecx, 4
lea r9, [rip + .Lresident_diagnostic_pair_offsets]
jmp .Lresident_dispatch_cpuid_pair_load
.Lresident_dispatch_cpuid_profile_pair:
sub ecx, 38
lea r9, [rip + .Lresident_profile_pair_offsets]
.Lresident_dispatch_cpuid_pair_load:
mov r10d, dword ptr [r9 + rcx * 8]
mov edx, dword ptr [r9 + rcx * 8 + 4]
mov rax, qword ptr [r8 + r10]
mov rdx, qword ptr [r8 + rdx]
mov rcx, rdx
shr rdx, 32
mov rbx, rax
shr rbx, 32
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_nested_state:
mov eax, dword ptr [r8 + {b_nested_active}]
mov ebx, dword ptr [r8 + {b_nested_l2_active}]
mov ecx, dword ptr [r8 + {b_nested_l2_last_exit_reason}]
mov edx, dword ptr [r8 + {b_nested_instruction_error}]
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_vmx_secondary:
mov rax, qword ptr [r8 + {b_nested_host_procbased_ctls2}]
mov rdx, qword ptr [r8 + {b_nested_vmx_procbased_ctls2}]
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_dispatch_cpuid_vmx_misc:
mov rax, qword ptr [r8 + {b_nested_host_misc}]
mov rdx, qword ptr [r8 + {b_nested_vmx_misc}]
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_dispatch_cpuid_ept_recycling:
mov rax, qword ptr [r8 + {b_nested_ept02_recycle_count}]
mov rdx, qword ptr [r8 + {b_nested_ept02_table_eviction_count}]
.Lresident_dispatch_cpuid_vmx_pair:
mov rbx, rax
shr rbx, 32
mov rcx, rdx
shr rdx, 32
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_control_stage:
mov r10d, dword ptr [r8 + {b_processor_number}]
imul r10, {control_cpu_state_size}
lea r10, [r9 + r10 + {event_control_cpu_states}]
mov rax, qword ptr [r10 + {control_cpu_stage}]
mov rdx, qword ptr [r10 + {control_cpu_phase}]
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_dispatch_cpuid_control_failure:
mov r10d, dword ptr [r8 + {b_processor_number}]
imul r10, {control_cpu_state_size}
lea r10, [r9 + r10 + {event_control_cpu_states}]
mov rax, qword ptr [r10 + {control_cpu_on_failure_reason}]
mov rdx, qword ptr [r10 + {control_cpu_on_failure_qualification}]
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_dispatch_cpuid_native_count:
mov r10d, dword ptr [r8 + {b_processor_number}]
imul r10, {control_cpu_state_size}
lea r10, [r9 + r10 + {event_control_cpu_states}]
mov rax, qword ptr [r10 + {control_cpu_native_snapshot_count}]
mov rdx, qword ptr [r10 + {control_cpu_sequence}]
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_dispatch_cpuid_native_layout:
mov eax, {native_snapshot_size}
mov ebx, {native_snapshot_stack}
mov ecx, {native_stack_bytes}
mov edx, {native_snapshot_capacity}
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_native_snapshot:
cmp ecx, {native_snapshot_leaf_limit}
jae .Lresident_dispatch_cpuid_diagnostic_zero
sub ecx, 0x4000
mov eax, ecx
xor edx, edx
mov r10d, {native_snapshot_pairs}
div r10d
mov r11d, dword ptr [r8 + {b_processor_number}]
imul r11, {control_cpu_state_size}
lea r11, [r9 + r11 + {event_control_cpu_states}]
cmp rax, qword ptr [r11 + {control_cpu_native_snapshot_count}]
jae .Lresident_dispatch_cpuid_diagnostic_zero
mov r11, qword ptr [r11 + {control_cpu_native_storage_physical}]
test r11, r11
jz .Lresident_dispatch_cpuid_diagnostic_zero
imul rax, {native_snapshot_size}
lea r10, [r11 + rax + {native_snapshots_offset}]
shl edx, 4
add r10, rdx
mov rax, qword ptr [r10]
mov rdx, qword ptr [r10 + 8]
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_dispatch_cpuid_nested_failure_count:
mov eax, dword ptr [r8 + {b_nested_failure_count}]
mov ebx, dword ptr [r8 + {b_nested_failure_count} + 4]
mov ecx, {nested_failure_trace_capacity}
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_nested_failure_record:
sub ecx, 0x101
mov eax, ecx
xor edx, edx
mov r10d, 3
div r10d
cmp eax, dword ptr [r8 + {b_nested_failure_count}]
jae .Lresident_dispatch_cpuid_nested_failure_record_missing
imul eax, 48
lea r10, [r8 + {b_nested_failure_trace}]
add r10, rax
shl edx, 4
add r10, rdx
mov rax, qword ptr [r10]
mov rdx, qword ptr [r10 + 8]
mov rbx, rax
shr rbx, 32
mov rcx, rdx
shr rdx, 32
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_nested_failure_record_missing:
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_registered_cpus:
xor ecx, ecx
xor eax, eax
.Lresident_dispatch_cpuid_registered_cpu:
cmp qword ptr [r9 + {event_cpu_contexts} + rcx * 8], 0
je .Lresident_dispatch_cpuid_registered_cpu_next
bts rax, rcx
.Lresident_dispatch_cpuid_registered_cpu_next:
inc ecx
cmp ecx, 64
jb .Lresident_dispatch_cpuid_registered_cpu
mov rbx, rax
shr rbx, 32
xor ecx, ecx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_fault_low:
mov rax, qword ptr [r9 + {event_host_fault_vector}]
mov rcx, qword ptr [r9 + {event_host_fault_error_code}]
mov rbx, rax
shr rbx, 32
mov rdx, rcx
shr rdx, 32
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_fault_high:
mov rax, qword ptr [r9 + {event_host_fault_rip}]
mov rdx, qword ptr [r9 + {event_host_fault_address}]
mov rcx, rdx
shr rdx, 32
mov rbx, rax
shr rbx, 32
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_capabilities:
mov eax, 0xffff
mov ebx, dword ptr [r8 + {b_processor_number}]
mov rcx, qword ptr [r8 + {b_watchdog_deadline}]
test rcx, rcx
jz .Lresident_dispatch_cpuid_capabilities_inactive
rdtsc
shl rdx, 32
or rax, rdx
cmp rax, rcx
setb cl
movzx ecx, cl
mov eax, 0xffff
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_capabilities_inactive:
xor ecx, ecx
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_lease:
mov rax, qword ptr [r8 + {b_watchdog_tsc_hz}]
mov rdx, qword ptr [r8 + {b_watchdog_deadline}]
mov rcx, rdx
shr rdx, 32
mov rbx, rax
shr rbx, 32
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_watchdog_start:
cmp qword ptr [r8 + {b_telemetry_enabled}], 0
je .Lresident_dispatch_cpuid_watchdog_stop
rdtsc
shl rdx, 32
or rax, rdx
mov r10, qword ptr [r8 + {b_watchdog_tsc_hz}]
imul r10, 15
add rax, r10
mov qword ptr [r8 + {b_watchdog_deadline}], rax
mov eax, 1
xor ecx, ecx
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_watchdog_stop:
mov qword ptr [r8 + {b_watchdog_deadline}], 0
xor eax, eax
xor ecx, ecx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_telemetry_enable:
mov qword ptr [r8 + {b_telemetry_enabled}], 1
jmp .Lresident_dispatch_cpuid_telemetry_state
.Lresident_dispatch_cpuid_telemetry_disable:
mov qword ptr [r8 + {b_telemetry_enabled}], 0
mov qword ptr [r8 + {b_watchdog_deadline}], 0
.Lresident_dispatch_cpuid_telemetry_state:
mov eax, dword ptr [r8 + {b_telemetry_enabled}]
xor ecx, ecx
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_dispatch_cpuid_diagnostic_zero:
xor ecx, ecx
.Lresident_dispatch_cpuid_diagnostic_store:
mov qword ptr [rsp], rax
mov qword ptr [rsp + 24], rbx
mov qword ptr [rsp + 8], rcx
mov qword ptr [rsp + 16], rdx
jmp .Lresident_dispatch_cpuid_advance
.balign 8
.Lresident_diagnostic_pair_offsets:
.long {b_watchdog_sequence}, {b_watchdog_phase}
.long {b_watchdog_exit_count}, {b_watchdog_handler_returns}
.long {b_watchdog_resume_failures}, {b_nested_l2_entry_count}
.long {b_nested_failure_count}, {b_nested_entry_rejection_count}
.long {b_watchdog_last_reason}, {b_watchdog_last_rip}
.long {b_entry_failure_state}, {b_entry_failure_exit}
.long {b_entry_failure_tsc}, {b_ept_violation_read}
.long {b_ept_violation_write}, {b_ept_violation_execute}
.long {b_cr3_exits}, {b_eptp_switches}
.long {b_mtf_exits}, {b_invept_exits}
.long {b_preemption_timer_exits}, {b_nested_invept_count}
.long {b_nested_ept_composition_count}, {b_nested_ept02_invalidation_count}
.long {b_nested_l2_exit_count}, {b_nested_l2_resume_count}
.long {b_watchdog_before}, {b_watchdog_before} + 8
.long {b_watchdog_before} + 16, {b_watchdog_before} + 24
.long {b_watchdog_before} + 32, {b_watchdog_before} + 40
.long {b_watchdog_before} + 48, {b_watchdog_after}
.long {b_watchdog_after} + 8, {b_watchdog_after} + 16
.long {b_watchdog_after} + 24, {b_watchdog_after} + 32
.long {b_watchdog_after} + 40, {b_watchdog_after} + 48
.long {b_watchdog_resume}, {b_watchdog_resume} + 8
.long {b_watchdog_resume} + 16, {b_watchdog_resume} + 24
.long {b_watchdog_resume} + 32, {b_watchdog_resume} + 40
.long {b_watchdog_resume} + 48, {b_entry_failure_guest}
.long {b_entry_failure_guest} + 8, {b_entry_failure_guest} + 16
.long {b_entry_failure_guest} + 24, {b_entry_failure_guest} + 32
.long {b_entry_failure_guest} + 40, {b_entry_failure_guest} + 48
.Lresident_profile_pair_offsets:
.long {b_rdmsr_count}, {b_wrmsr_count}
.long {b_cpuid_count}, {b_nested_invvpid_count}
.long {b_nested_exit_reason_counts} + 23 * 8, {b_nested_exit_reason_counts} + 25 * 8
.long {b_nested_exit_reason_counts} + 20 * 8, {b_nested_exit_reason_counts} + 24 * 8
.long {b_last_normal_reason}, {b_last_rcx}
.long {b_nested_exit_handler_cycles}, {b_nested_exit_handler_cycles} + 8
.long {b_nested_exit_handler_cycles} + 16, {b_nested_exit_handler_cycles} + 24
.long {b_last_normal_rip}, {b_watchdog_tsc_hz}
.long {b_nested_ept02_table_pool_used}, {b_nested_ept02_cached_table_pool_used}
.Lresident_telemetry_begin:
// Latch counters for the entire exit so remote toggles cannot leave the sequence odd.
mov rax, qword ptr [r12 + {b_telemetry_enabled}]
or rax, qword ptr [r12 + {b_telemetry_probe_active}]
mov qword ptr [r12 + {b_telemetry_active}], rax
cmp qword ptr [r12 + {b_last_reason}], {cpuid_reason}
jne .Lresident_telemetry_profile
cmp r10d, {matrixhv_status_leaf}
jne .Lresident_telemetry_profile
mov qword ptr [r12 + {b_telemetry_active}], 0
.Lresident_telemetry_profile:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_telemetry_begin_done
lfence
rdtsc
shl rdx, 32
or rax, rdx
mov qword ptr [r12 + {b_nested_exit_started_tsc}], rax
// Keep rates per physical CPU; VMCS12 counters migrate with the saved VMCS.
mov eax, dword ptr [r12 + {b_last_reason}]
and eax, 0xffff
cmp eax, 128
jae .Lresident_telemetry_begin_done
inc qword ptr [r12 + {b_nested_exit_reason_counts} + rax * 8]
.Lresident_telemetry_begin_done:
ret
.Lresident_watchdog_begin:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_watchdog_handler_start_done
cmp qword ptr [r12 + {b_last_reason}], {cpuid_reason}
jne .Lresident_watchdog_begin_observed
cmp dword ptr [r12 + {b_last_rax}], {matrixhv_status_leaf}
je .Lresident_watchdog_begin_done
.Lresident_watchdog_begin_observed:
inc qword ptr [r12 + {b_watchdog_sequence}]
mov rax, qword ptr [r12 + {b_exit_count}]
mov qword ptr [r12 + {b_watchdog_exit_count}], rax
mov qword ptr [r12 + {b_watchdog_phase}], 0
mov rax, qword ptr [r12 + {b_last_reason}]
mov qword ptr [r12 + {b_watchdog_last_reason}], rax
mov rax, qword ptr [r12 + {b_last_guest_rip}]
mov qword ptr [r12 + {b_watchdog_last_rip}], rax
mov eax, dword ptr [r12 + {b_last_reason}]
and eax, 0xffff
cmp eax, {ept_violation_reason}
jne .Lresident_watchdog_count_cr3
mov rax, qword ptr [r12 + {b_last_qualification}]
bt rax, 0
jnc .Lresident_watchdog_ept_write
inc qword ptr [r12 + {b_ept_violation_read}]
.Lresident_watchdog_ept_write:
bt rax, 1
jnc .Lresident_watchdog_ept_execute
inc qword ptr [r12 + {b_ept_violation_write}]
.Lresident_watchdog_ept_execute:
bt rax, 2
jnc .Lresident_watchdog_count_done
inc qword ptr [r12 + {b_ept_violation_execute}]
jmp .Lresident_watchdog_count_done
.Lresident_watchdog_count_cr3:
cmp eax, 28
jne .Lresident_watchdog_count_mtf
mov rax, qword ptr [r12 + {b_last_qualification}]
and eax, 0x3f
cmp eax, 3
jne .Lresident_watchdog_count_done
inc qword ptr [r12 + {b_cr3_exits}]
jmp .Lresident_watchdog_count_done
.Lresident_watchdog_count_mtf:
cmp eax, 37
jne .Lresident_watchdog_count_timer
inc qword ptr [r12 + {b_mtf_exits}]
jmp .Lresident_watchdog_count_done
.Lresident_watchdog_count_timer:
cmp eax, {preemption_timer_reason}
jne .Lresident_watchdog_count_done
inc qword ptr [r12 + {b_preemption_timer_exits}]
.Lresident_watchdog_count_done:
mov rax, qword ptr [r12 + {b_watchdog_deadline}]
test rax, rax
jz .Lresident_watchdog_check_entry_failure
mov r11, rax
rdtsc
shl rdx, 32
or rax, rdx
cmp rax, r11
jb .Lresident_watchdog_capture_before
mov qword ptr [r12 + {b_watchdog_deadline}], 0
jmp .Lresident_watchdog_check_entry_failure
.Lresident_watchdog_capture_before:
lea r10, [r12 + {b_watchdog_before}]
call .Lresident_watchdog_capture
.Lresident_watchdog_check_entry_failure:
mov eax, dword ptr [r12 + {b_last_reason}]
test eax, 0x80000000
jz .Lresident_watchdog_begin_done
and eax, 0xffff
cmp eax, 33
jne .Lresident_watchdog_begin_done
cmp qword ptr [r12 + {b_entry_failure_state}], 0
jne .Lresident_watchdog_begin_done
mov qword ptr [r12 + {b_entry_failure_state}], 1
mov rax, qword ptr [r12 + {b_last_reason}]
mov qword ptr [r12 + {b_entry_failure_exit}], rax
rdtsc
shl rdx, 32
or rax, rdx
mov qword ptr [r12 + {b_entry_failure_tsc}], rax
lea r10, [r12 + {b_entry_failure_guest}]
call .Lresident_watchdog_capture
mov qword ptr [r12 + {b_entry_failure_state}], 2
.Lresident_watchdog_begin_done:
cmp qword ptr [r12 + {b_last_reason}], {cpuid_reason}
jne .Lresident_watchdog_handler_started
cmp dword ptr [r12 + {b_last_rax}], {matrixhv_status_leaf}
je .Lresident_watchdog_handler_start_done
.Lresident_watchdog_handler_started:
mov qword ptr [r12 + {b_watchdog_phase}], 3
.Lresident_watchdog_handler_start_done:
ret
.Lresident_watchdog_handler_returned:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_watchdog_after_handler_done
cmp qword ptr [r12 + {b_last_reason}], {cpuid_reason}
jne .Lresident_watchdog_after_handler_observed
cmp dword ptr [r12 + {b_last_rax}], {matrixhv_status_leaf}
je .Lresident_watchdog_after_handler_done
.Lresident_watchdog_after_handler_observed:
mov qword ptr [r12 + {b_watchdog_phase}], 4
inc qword ptr [r12 + {b_watchdog_handler_returns}]
cmp qword ptr [r12 + {b_watchdog_deadline}], 0
je .Lresident_watchdog_after_handler_done
lea r10, [r12 + {b_watchdog_after}]
call .Lresident_watchdog_capture
.Lresident_watchdog_after_handler_done:
ret
.Lresident_watchdog_resuming:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_watchdog_resume_ready
cmp qword ptr [r12 + {b_last_reason}], {cpuid_reason}
jne .Lresident_watchdog_resume_observed
cmp dword ptr [r12 + {b_last_rax}], {matrixhv_status_leaf}
je .Lresident_watchdog_resume_ready
.Lresident_watchdog_resume_observed:
mov qword ptr [r12 + {b_watchdog_phase}], 1
cmp qword ptr [r12 + {b_watchdog_deadline}], 0
je .Lresident_watchdog_resume_commit
lea r10, [r12 + {b_watchdog_resume}]
call .Lresident_watchdog_capture
.Lresident_watchdog_resume_commit:
inc qword ptr [r12 + {b_watchdog_sequence}]
.Lresident_watchdog_resume_ready:
ret
.Lresident_watchdog_capture:
mov rax, {guest_rip}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r10], r11
mov rax, {guest_rsp}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r10 + 8], r11
mov rax, {guest_rflags}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r10 + 16], r11
mov rax, {guest_cr0}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r10 + 24], r11
mov rax, {guest_cr3}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r10 + 32], r11
mov rax, {guest_cr4}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r10 + 40], r11
mov rax, {guest_efer}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r10 + 48], r11
ret
.Lresident_dispatch_cpuid_standard:
cmp r8d, 1
jne .Lresident_dispatch_cpuid_advance
resident_telemetry_counter inc, {b_cpuid_leaf1_count}, {b_telemetry_active}
mov r10d, dword ptr [rsp + 8]
and r10d, {cpuid_vmx_clear_mask}
and r10d, {cpuid_osxsave_clear_mask}
mov rax, {guest_cr4}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11, {cr4_osxsave_mask}
jz .Lresident_dispatch_cpuid_osxsave_ready
or r10d, {cpuid_osxsave_set_mask}
.Lresident_dispatch_cpuid_osxsave_ready:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_cpuid_vmx_ready
or r10d, {cpuid_vmx_set_mask}
.Lresident_dispatch_cpuid_vmx_ready:
cmp qword ptr [r12 + {b_cpuid_presence}], 0
je .Lresident_dispatch_cpuid_presence_hidden
or r10d, {cpuid_hypervisor_set_mask}
jmp .Lresident_dispatch_cpuid_presence_ready
.Lresident_dispatch_cpuid_presence_hidden:
and r10d, {cpuid_hypervisor_clear_mask}
.Lresident_dispatch_cpuid_presence_ready:
mov qword ptr [rsp + 8], r10
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_cpuid_advance
mov qword ptr [r12 + {b_cpuid_leaf1_ecx}], r10
.Lresident_dispatch_cpuid_advance:
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_rdmsr:
resident_telemetry_counter inc, {b_rdmsr_count}, {b_telemetry_active}
call .Lresident_msr_privilege
jc .Lresident_dispatch_inject_gp
mov ecx, dword ptr [rsp + 8]
cmp ecx, {platform_id_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {apic_base_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {xss_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {feature_control_msr}
je .Lresident_dispatch_rdmsr_feature_control
cmp ecx, {vmx_basic_msr}
je .Lresident_dispatch_rdmsr_vmx_basic
cmp ecx, {vmx_pinbased_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_pinbased_ctls
cmp ecx, {vmx_procbased_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_procbased_ctls
cmp ecx, {vmx_exit_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_exit_ctls
cmp ecx, {vmx_entry_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_entry_ctls
cmp ecx, {vmx_misc_msr}
je .Lresident_dispatch_rdmsr_vmx_misc
cmp ecx, {vmx_cr0_fixed0_msr}
je .Lresident_dispatch_rdmsr_vmx_cr0_fixed0
cmp ecx, {vmx_cr0_fixed1_msr}
je .Lresident_dispatch_rdmsr_vmx_cr0_fixed1
cmp ecx, {vmx_cr4_fixed0_msr}
je .Lresident_dispatch_rdmsr_vmx_cr4_fixed0
cmp ecx, {vmx_cr4_fixed1_msr}
je .Lresident_dispatch_rdmsr_vmx_cr4_fixed1
cmp ecx, {vmx_vmcs_enum_msr}
je .Lresident_dispatch_rdmsr_vmx_vmcs_enum
cmp ecx, {vmx_procbased_ctls2_msr}
je .Lresident_dispatch_rdmsr_vmx_procbased_ctls2
cmp ecx, {vmx_ept_vpid_cap_msr}
je .Lresident_dispatch_rdmsr_vmx_ept_vpid_cap
cmp ecx, {vmx_true_pinbased_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_true_pinbased_ctls
cmp ecx, {vmx_true_procbased_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_true_procbased_ctls
cmp ecx, {vmx_true_exit_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_true_exit_ctls
cmp ecx, {vmx_true_entry_ctls_msr}
je .Lresident_dispatch_rdmsr_vmx_true_entry_ctls
cmp ecx, {vmx_vmfunc_msr}
je .Lresident_dispatch_rdmsr_vmx_vmfunc
cmp ecx, {bios_sign_id_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {mtrrcap_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {pkg_energy_status_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {rapl_power_unit_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {dram_energy_status_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {pp0_energy_status_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {pp1_energy_status_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {x2apic_msr_base}
jb .Lresident_dispatch_rdmsr_before_x2apic
cmp ecx, {x2apic_msr_end}
jbe .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_before_x2apic:
cmp ecx, {mtrr_physbase0_msr}
jb .Lresident_dispatch_rdmsr_after_variable_mtrr
mov r10d, ecx
mov ecx, {mtrrcap_msr}
rdmsr
and eax, 0xff
shl eax, 1
add eax, {mtrr_physbase0_msr}
cmp r10d, eax
jae .Lresident_dispatch_rdmsr_after_variable_mtrr
mov ecx, r10d
jmp .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_after_variable_mtrr:
mov ecx, dword ptr [rsp + 8]
cmp ecx, {mtrr_fix64k_00000_msr}
je .Lresident_dispatch_rdmsr_fixed_mtrr
cmp ecx, {mtrr_fix16k_80000_msr}
je .Lresident_dispatch_rdmsr_fixed_mtrr
cmp ecx, {mtrr_fix16k_a0000_msr}
je .Lresident_dispatch_rdmsr_fixed_mtrr
cmp ecx, {mtrr_fix4k_c0000_msr}
jb .Lresident_dispatch_rdmsr_after_fixed_mtrr
cmp ecx, {mtrr_fix4k_f8000_msr}
jbe .Lresident_dispatch_rdmsr_fixed_mtrr
.Lresident_dispatch_rdmsr_after_fixed_mtrr:
cmp ecx, {mtrr_def_type_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {hyperv_hypercall_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {hyperv_vp_index_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {hyperv_simp_msr}
je .Lresident_dispatch_rdmsr_passthrough
mov eax, ecx
sub eax, {hyperv_reference_tsc_msr}
cmp eax, {hyperv_reference_time_msr_span}
jbe .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {sysenter_cs_msr}
je .Lresident_dispatch_rdmsr_sysenter_cs
cmp ecx, {sysenter_esp_msr}
je .Lresident_dispatch_rdmsr_sysenter_esp
cmp ecx, {sysenter_eip_msr}
je .Lresident_dispatch_rdmsr_sysenter_eip
cmp ecx, {efer_msr}
je .Lresident_dispatch_rdmsr_efer
cmp ecx, {gs_base_msr}
je .Lresident_dispatch_rdmsr_gs_base
cmp ecx, {fs_base_msr}
je .Lresident_dispatch_rdmsr_fs_base
cmp ecx, {amd_sev_status_msr}
je .Lresident_dispatch_rdmsr_zero
cmp ecx, {kernel_gs_base_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, 0x480
jb .Lresident_dispatch_rdmsr_not_vmx
cmp ecx, 0x49f
jbe .Lresident_dispatch_inject_gp
.Lresident_dispatch_rdmsr_not_vmx:
jmp .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_feature_control:
mov r11, qword ptr [r12 + {b_nested_feature_control}]
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
jne .Lresident_dispatch_rdmsr_nested_value
and r11, -5
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_basic:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_basic}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_pinbased_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_pinbased_ctls}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_procbased_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_exit_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_exit_ctls}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_entry_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_entry_ctls}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_misc:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_misc}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_cr0_fixed0:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed0}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_cr0_fixed1:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed1}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_cr4_fixed0:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed0}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_cr4_fixed1:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed1}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_vmcs_enum:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_vmcs_enum}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_procbased_ctls2:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls2}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_ept_vpid_cap:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_ept_vpid_cap}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_true_pinbased_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
bt qword ptr [r12 + {b_nested_vmx_basic}], 55
jnc .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_true_pinbased_ctls}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_true_procbased_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
bt qword ptr [r12 + {b_nested_vmx_basic}], 55
jnc .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_true_procbased_ctls}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_true_exit_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
bt qword ptr [r12 + {b_nested_vmx_basic}], 55
jnc .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_true_exit_ctls}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_vmfunc:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
bt qword ptr [r12 + {b_nested_vmx_procbased_ctls2}], 45
jnc .Lresident_dispatch_inject_gp
mov r11d, 1
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vmx_true_entry_ctls:
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_inject_gp
bt qword ptr [r12 + {b_nested_vmx_basic}], 55
jnc .Lresident_dispatch_inject_gp
mov r11, qword ptr [r12 + {b_nested_vmx_true_entry_ctls}]
.Lresident_dispatch_rdmsr_nested_value:
mov eax, r11d
mov qword ptr [rsp + 0], rax
shr r11, 32
mov eax, r11d
mov qword ptr [rsp + 16], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_rdmsr_zero:
xor r11d, r11d
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_fixed_mtrr:
mov r10d, ecx
mov ecx, {mtrrcap_msr}
rdmsr
test eax, 0x100
jz .Lresident_dispatch_inject_gp
mov ecx, r10d
jmp .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_passthrough:
call .Lresident_guarded_rdmsr
jc .Lresident_dispatch_inject_gp
mov qword ptr [rsp + 0], rax
mov qword ptr [rsp + 16], rdx
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_rdmsr_sysenter_cs:
mov rax, {guest_sysenter_cs}
jmp .Lresident_dispatch_rdmsr_vmcs_value
.Lresident_dispatch_rdmsr_fs_base:
mov rax, {guest_fs_base}
jmp .Lresident_dispatch_rdmsr_vmcs_value
.Lresident_dispatch_rdmsr_sysenter_esp:
mov rax, {guest_sysenter_esp}
jmp .Lresident_dispatch_rdmsr_vmcs_value
.Lresident_dispatch_rdmsr_sysenter_eip:
mov rax, {guest_sysenter_eip}
.Lresident_dispatch_rdmsr_vmcs_value:
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov eax, r11d
mov qword ptr [rsp + 0], rax
shr r11, 32
mov eax, r11d
mov qword ptr [rsp + 16], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_rdmsr_efer:
mov rax, {guest_efer}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov eax, r11d
mov qword ptr [rsp + 0], rax
shr r11, 32
mov eax, r11d
mov qword ptr [rsp + 16], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_rdmsr_gs_base:
mov rax, {guest_gs_base}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov eax, r11d
mov qword ptr [rsp + 0], rax
shr r11, 32
mov eax, r11d
mov qword ptr [rsp + 16], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr:
resident_telemetry_counter inc, {b_wrmsr_count}, {b_telemetry_active}
call .Lresident_msr_privilege
jc .Lresident_dispatch_inject_gp
mov ecx, dword ptr [rsp + 8]
cmp ecx, {apic_base_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {xss_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {bios_sign_id_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {mtrr_def_type_msr}
je .Lresident_dispatch_wrmsr_mtrr
cmp ecx, {x2apic_msr_base}
jb .Lresident_dispatch_wrmsr_before_x2apic
cmp ecx, {x2apic_msr_end}
jbe .Lresident_dispatch_wrmsr_passthrough
.Lresident_dispatch_wrmsr_before_x2apic:
cmp ecx, {mtrr_physbase0_msr}
jb .Lresident_dispatch_wrmsr_after_variable_mtrr
mov r10d, ecx
mov ecx, {mtrrcap_msr}
rdmsr
and eax, 0xff
shl eax, 1
add eax, {mtrr_physbase0_msr}
cmp r10d, eax
jae .Lresident_dispatch_wrmsr_after_variable_mtrr
mov ecx, r10d
jmp .Lresident_dispatch_wrmsr_mtrr
.Lresident_dispatch_wrmsr_after_variable_mtrr:
mov ecx, dword ptr [rsp + 8]
cmp ecx, {mtrr_fix64k_00000_msr}
je .Lresident_dispatch_wrmsr_fixed_mtrr
cmp ecx, {mtrr_fix16k_80000_msr}
je .Lresident_dispatch_wrmsr_fixed_mtrr
cmp ecx, {mtrr_fix16k_a0000_msr}
je .Lresident_dispatch_wrmsr_fixed_mtrr
cmp ecx, {mtrr_fix4k_c0000_msr}
jb .Lresident_dispatch_wrmsr_after_fixed_mtrr
cmp ecx, {mtrr_fix4k_f8000_msr}
jbe .Lresident_dispatch_wrmsr_fixed_mtrr
.Lresident_dispatch_wrmsr_after_fixed_mtrr:
cmp ecx, {hyperv_guest_os_id_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {hyperv_hypercall_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {hyperv_reference_tsc_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {hyperv_vp_assist_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {hyperv_simp_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {hyperv_sint3_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {hyperv_stimer0_config_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {hyperv_stimer0_count_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {sysenter_cs_msr}
je .Lresident_dispatch_wrmsr_sysenter_cs
cmp ecx, {sysenter_esp_msr}
je .Lresident_dispatch_wrmsr_sysenter_esp
cmp ecx, {sysenter_eip_msr}
je .Lresident_dispatch_wrmsr_sysenter_eip
cmp ecx, {gs_base_msr}
je .Lresident_dispatch_wrmsr_gs_base
cmp ecx, {fs_base_msr}
je .Lresident_dispatch_wrmsr_fs_base
cmp ecx, {kernel_gs_base_msr}
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, {feature_control_msr}
je .Lresident_dispatch_inject_gp
cmp ecx, 0x480
jb .Lresident_dispatch_wrmsr_not_vmx
cmp ecx, 0x49f
jbe .Lresident_dispatch_inject_gp
.Lresident_dispatch_wrmsr_not_vmx:
cmp ecx, {efer_msr}
jne .Lresident_dispatch_wrmsr_passthrough
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
shl rdx, 32
or rax, rdx
mov r11, rax
mov eax, {guest_cr0}
vmread r9, rax
jna .Lresident_dispatch_vmread_failed
mov eax, {guest_efer}
vmread r8, rax
jna .Lresident_dispatch_vmread_failed
mov eax, 0x80000001
xor ecx, ecx
cpuid
call .Lresident_validate_efer
jc .Lresident_dispatch_inject_gp
mov rax, {guest_efer}
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_efer_write_recorded
mov qword ptr [r12 + {b_last_efer_write}], r11
.Lresident_efer_write_recorded:
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_fs_base:
mov r10, {guest_fs_base}
jmp .Lresident_dispatch_wrmsr_vmcs_value
.Lresident_dispatch_wrmsr_sysenter_cs:
mov r10, {guest_sysenter_cs}
jmp .Lresident_dispatch_wrmsr_vmcs_value
.Lresident_dispatch_wrmsr_sysenter_esp:
mov r10, {guest_sysenter_esp}
jmp .Lresident_dispatch_wrmsr_vmcs_value
.Lresident_dispatch_wrmsr_sysenter_eip:
mov r10, {guest_sysenter_eip}
.Lresident_dispatch_wrmsr_vmcs_value:
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
shl rdx, 32
or rax, rdx
mov r11, rax
cmp r10, {guest_sysenter_cs}
je .Lresident_dispatch_wrmsr_sysenter_selector
mov eax, {guest_cr4}
vmread r9, rax
jna .Lresident_dispatch_vmread_failed
call .Lresident_validate_canonical_msr
jc .Lresident_dispatch_inject_gp
jmp .Lresident_dispatch_wrmsr_vmcs_validated
.Lresident_dispatch_wrmsr_sysenter_selector:
mov rax, r11
shr rax, 32
jnz .Lresident_dispatch_inject_gp
.Lresident_dispatch_wrmsr_vmcs_validated:
vmwrite r10, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_gs_base:
mov r10, {guest_gs_base}
jmp .Lresident_dispatch_wrmsr_vmcs_value
.Lresident_dispatch_wrmsr_fixed_mtrr:
mov r10d, ecx
mov ecx, {mtrrcap_msr}
rdmsr
test eax, 0x100
jz .Lresident_dispatch_inject_gp
mov ecx, r10d
.Lresident_dispatch_wrmsr_mtrr:
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_inject_gp
mov qword ptr [r12 + {b_mtrr_dirty}], 1
call .Lresident_update_dirty_mtrrs
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_passthrough:
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_inject_gp
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_xsetbv:
resident_telemetry_counter inc, {b_xsetbv_count}, {b_telemetry_active}
mov eax, {guest_cr4}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x40000
jz .Lresident_dispatch_inject_ud
call .Lresident_msr_privilege
jc .Lresident_dispatch_inject_gp
cmp dword ptr [rsp + 8], 0
jne .Lresident_dispatch_inject_gp
mov r11, cr4
mov r10, r11
or r10, 0x40000
mov cr4, r10
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
xor ecx, ecx
call .Lresident_guarded_xsetbv
mov cr4, r11
jc .Lresident_dispatch_inject_gp
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_vmcall:
resident_telemetry_counter inc, {b_vmcall_count}, {b_telemetry_active}
mov rax, qword ptr [rsp + 0]
mov r11, 0x4856415052454144
cmp rax, r11
je .Lresident_ap_ready
mov r11, {start_checkpoint_magic}
cmp rax, r11
je .Lresident_dispatch_start_checkpoint
mov r11, {bridge_probe_vmcall}
cmp rax, r11
je .Lresident_dispatch_control_probe
mov r11, {bridge_off_prepare_vmcall}
cmp rax, r11
je .Lresident_dispatch_control_off_prepare
mov r11, {bridge_off_commit_vmcall}
cmp rax, r11
je .Lresident_dispatch_control_off_unexpected
mov r11, {stop_magic}
cmp rax, r11
je .Lresident_dispatch_stop
mov r11, {nested_probe_failed_magic}
cmp rax, r11
je .Lresident_dispatch_nested_probe_failed
cmp eax, {vmware_hypervisor_magic}
je .Lresident_dispatch_vmware_hypercall
jmp .Lresident_dispatch_unsupported
.Lresident_dispatch_vmware_hypercall:
mov rax, qword ptr [rsp + 0]
mov rcx, qword ptr [rsp + 8]
mov rdx, qword ptr [rsp + 16]
mov rbx, qword ptr [rsp + 24]
mov rsi, qword ptr [rsp + 40]
mov rdi, qword ptr [rsp + 48]
mov dx, {vmware_hypervisor_port}
in eax, dx
mov qword ptr [rsp + 0], rax
mov qword ptr [rsp + 8], rcx
mov qword ptr [rsp + 16], rdx
mov qword ptr [rsp + 24], rbx
mov qword ptr [rsp + 40], rsi
mov qword ptr [rsp + 48], rdi
mov r12, qword ptr [rsp + 120]
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_start_checkpoint:
mov qword ptr [r12 + {b_start_checkpoint_seen}], 1
lea rsi, [rip + .Lstart_checkpoint_message]
mov r9d, {start_checkpoint_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_control_probe:
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_control_probe_failed
cmp qword ptr [rdi + {event_ebs_seen}], 1
jne .Lresident_control_probe_failed
cmp qword ptr [rdi + {event_va_seen}], 1
jne .Lresident_control_probe_failed
cmp qword ptr [rdi + {event_control_va_error}], 0
jne .Lresident_control_probe_failed
cmp qword ptr [r12 + {b_nested_l2_active}], 0
jne .Lresident_control_probe_failed
cmp qword ptr [r12 + {b_nested_active}], 0
jne .Lresident_control_probe_failed
mov rcx, qword ptr [r12 + {b_processor_number}]
cmp rcx, 64
jae .Lresident_control_probe_failed
mov r8, rcx
mov eax, dword ptr [rdi + {event_control_apic_ids} + rcx * 4]
cmp eax, dword ptr [rsp + 16]
jne .Lresident_control_probe_failed
bt qword ptr [rdi + {event_control_active_mask}], rcx
jnc .Lresident_control_probe_failed
bt qword ptr [rdi + {event_control_failed_mask}], rcx
jc .Lresident_control_probe_failed
mov rax, {guest_cr3}
vmread r11, rax
jna .Lresident_control_probe_failed
test r11, r11
jz .Lresident_control_probe_failed
imul rcx, {probe_state_size}
lea rsi, [rdi + {event_control_probe_states}]
add rsi, rcx
mov r11, qword ptr [rsp + 8]
mov qword ptr [rsi + {probe_sequence}], r11
resident_control_probe_vmread {guest_rip}, {probe_guest_rip}
resident_control_probe_vmread {guest_rsp}, {probe_guest_rsp}
resident_control_probe_vmread {guest_rflags}, {probe_guest_rflags}
resident_control_probe_vmread {guest_cr0}, {probe_guest_cr0}
resident_control_probe_vmread {guest_cr3}, {probe_guest_cr3}
resident_control_probe_vmread {guest_cr4}, {probe_guest_cr4}
resident_control_probe_vmread {guest_efer}, {probe_guest_efer}
resident_control_probe_vmread {guest_pat}, {probe_guest_pat}
resident_control_probe_vmread {guest_gdtr_base}, {probe_guest_gdtr_base}
resident_control_probe_vmread {guest_gdtr_limit}, {probe_guest_gdtr_limit}
resident_control_probe_vmread {guest_idtr_base}, {probe_guest_idtr_base}
resident_control_probe_vmread {guest_idtr_limit}, {probe_guest_idtr_limit}
resident_control_probe_vmread {guest_cs_selector}, {probe_guest_cs_selector}
resident_control_probe_vmread {guest_ss_selector}, {probe_guest_ss_selector}
resident_control_probe_vmread {guest_tr_selector}, {probe_guest_tr_selector}
resident_control_probe_vmread {guest_tr_ar_bytes}, {probe_guest_tr_access}
resident_control_probe_vmread {guest_tr_base}, {probe_guest_tr_base}
resident_control_probe_vmread {guest_tr_limit}, {probe_guest_tr_limit}
resident_control_probe_vmread {guest_fs_base}, {probe_guest_fs_base}
resident_control_probe_vmread {guest_gs_base}, {probe_guest_gs_base}
resident_control_probe_vmread {guest_es_selector}, {probe_guest_es_selector}
resident_control_probe_vmread {guest_ds_selector}, {probe_guest_ds_selector}
resident_control_probe_vmread {guest_fs_selector}, {probe_guest_fs_selector}
resident_control_probe_vmread {guest_gs_selector}, {probe_guest_gs_selector}
resident_control_probe_vmread {guest_ldtr_selector}, {probe_guest_ldtr_selector}
resident_control_probe_vmread {guest_dr7}, {probe_guest_dr7}
resident_control_probe_vmread {cr4_read_shadow}, {probe_guest_cr4_read_shadow}
resident_control_probe_vmread {guest_interruptibility_info}, {probe_guest_interruptibility}
resident_control_probe_vmread {idt_vectoring_info_field}, {probe_idt_vectoring}
resident_control_probe_vmread {vm_entry_intr_info_field}, {probe_vm_entry_intr_info}
mov r11, qword ptr [rdi + {event_runtime_get_variable}]
mov qword ptr [rsi + {probe_runtime_get_variable}], r11
mov r11, qword ptr [rdi + {event_runtime_set_variable}]
mov qword ptr [rsi + {probe_runtime_set_variable}], r11
mov r11, qword ptr [rdi + {event_runtime_context}]
mov qword ptr [rsi + {probe_runtime_context}], r11
mov rcx, r8
imul rcx, {control_cpu_state_size}
lea rsi, [rdi + {event_control_cpu_states}]
add rsi, rcx
resident_control_save_host {host_es_selector}, 0
resident_control_save_host {host_cs_selector}, 1
resident_control_save_host {host_ss_selector}, 2
resident_control_save_host {host_ds_selector}, 3
resident_control_save_host {host_fs_selector}, 4
resident_control_save_host {host_gs_selector}, 5
resident_control_save_host {host_tr_selector}, 6
resident_control_save_host {host_cr0}, 7
resident_control_save_host {host_cr3}, 8
resident_control_save_host {host_cr4}, 9
resident_control_save_host {host_pat}, 10
resident_control_save_host {host_efer}, 11
resident_control_save_host {host_fs_base}, 12
resident_control_save_host {host_gs_base}, 13
resident_control_save_host {host_tr_base}, 14
resident_control_save_host {host_gdtr_base}, 15
resident_control_save_host {host_idtr_base}, 16
resident_control_save_host {host_sysenter_cs}, 17
resident_control_save_host {host_sysenter_esp}, 18
resident_control_save_host {host_sysenter_eip}, 19
resident_control_save_host {host_rsp}, 20
resident_control_save_host {host_rip}, 21
mov rax, {bridge_probe_result}
jmp .Lresident_control_probe_complete
.Lresident_control_probe_failed:
xor eax, eax
.Lresident_control_probe_complete:
mov qword ptr [rsp], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_control_off_prepare:
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_control_off_failed
cmp qword ptr [rdi + {event_ebs_seen}], 1
jne .Lresident_control_off_failed
cmp qword ptr [rdi + {event_va_seen}], 1
jne .Lresident_control_off_failed
cmp qword ptr [rdi + {event_control_va_error}], 0
jne .Lresident_control_off_failed
cmp qword ptr [r12 + {b_nested_l2_active}], 0
jne .Lresident_control_off_failed
cmp qword ptr [r12 + {b_nested_active}], 0
jne .Lresident_control_off_failed
cmp qword ptr [r12 + {b_nmi_pending}], 0
jne .Lresident_control_off_failed
mov r8, qword ptr [rsp + 56]
cmp r8, 64
jae .Lresident_control_off_failed
cmp r8, qword ptr [r12 + {b_processor_number}]
jne .Lresident_control_off_failed
mov eax, dword ptr [rdi + {event_control_apic_ids} + r8 * 4]
cmp eax, dword ptr [rsp + 16]
jne .Lresident_control_off_failed
bt qword ptr [rdi + {event_control_active_mask}], r8
jnc .Lresident_control_off_failed
bt qword ptr [rdi + {event_control_stopped_mask}], r8
jc .Lresident_control_off_failed
bt qword ptr [rdi + {event_control_failed_mask}], r8
jc .Lresident_control_off_failed
mov rcx, r8
imul rcx, {control_cpu_state_size}
lea rsi, [rdi + {event_control_cpu_states}]
add rsi, rcx
cmp qword ptr [rsi + {control_cpu_phase}], 0
jne .Lresident_control_off_failed
cmp qword ptr [rsi + {control_cpu_vmxon_region}], 0
je .Lresident_control_off_failed
cmp qword ptr [rsi + {control_cpu_vmcs_region}], 0
je .Lresident_control_off_failed
vmptrst qword ptr [rsi + {control_cpu_current_vmcs}]
mov rax, qword ptr [rsi + {control_cpu_current_vmcs}]
cmp rax, qword ptr [rsi + {control_cpu_vmcs_region}]
jne .Lresident_control_off_failed
mov rcx, r8
imul rcx, {probe_state_size}
lea r10, [rdi + {event_control_probe_states}]
add r10, rcx
mov r11, qword ptr [rsp + 8]
test r11, r11
jz .Lresident_control_off_failed
mov qword ptr [rsi + {control_cpu_sequence}], r11
mov qword ptr [r10 + {probe_sequence}], r11
mov eax, {guest_cs_selector}
vmread r11, rax
jna .Lresident_control_off_failed
test r11d, 7
jnz .Lresident_control_off_failed
mov eax, {guest_ss_selector}
vmread r11, rax
jna .Lresident_control_off_failed
test r11d, 7
jnz .Lresident_control_off_failed
mov eax, {guest_ldtr_selector}
vmread r11, rax
jna .Lresident_control_off_failed
test r11d, r11d
jnz .Lresident_control_off_failed
mov eax, {guest_tr_selector}
vmread r11, rax
jna .Lresident_control_off_failed
test r11d, 7
jnz .Lresident_control_off_failed
mov eax, {guest_tr_limit}
vmread r11, rax
jna .Lresident_control_off_failed
cmp r11, 0x67
jne .Lresident_control_off_failed
mov eax, {vm_entry_intr_info_field}
vmread r11, rax
jna .Lresident_control_off_failed
test r11d, 0x80000000
jnz .Lresident_control_off_failed
mov eax, {idt_vectoring_info_field}
vmread r11, rax
jna .Lresident_control_off_failed
test r11d, 0x80000000
jnz .Lresident_control_off_failed
mov eax, {guest_interruptibility_info}
vmread r11, rax
jna .Lresident_control_off_failed
test r11d, r11d
jnz .Lresident_control_off_failed
resident_control_off_vmread {guest_es_selector}, {probe_guest_es_selector}
resident_control_off_vmread {guest_ds_selector}, {probe_guest_ds_selector}
resident_control_off_vmread {guest_fs_selector}, {probe_guest_fs_selector}
resident_control_off_vmread {guest_gs_selector}, {probe_guest_gs_selector}
resident_control_off_vmread {guest_cs_selector}, {probe_guest_cs_selector}
resident_control_off_vmread {guest_ss_selector}, {probe_guest_ss_selector}
resident_control_off_vmread {guest_tr_selector}, {probe_guest_tr_selector}
resident_control_off_vmread {guest_tr_base}, {probe_guest_tr_base}
resident_control_off_vmread {guest_tr_limit}, {probe_guest_tr_limit}
resident_control_off_vmread {guest_gdtr_base}, {probe_guest_gdtr_base}
resident_control_off_vmread {guest_gdtr_limit}, {probe_guest_gdtr_limit}
resident_control_off_vmread {guest_idtr_base}, {probe_guest_idtr_base}
resident_control_off_vmread {guest_idtr_limit}, {probe_guest_idtr_limit}
resident_control_off_vmread {guest_fs_base}, {probe_guest_fs_base}
resident_control_off_vmread {guest_gs_base}, {probe_guest_gs_base}
resident_control_off_vmread {guest_cr4}, {probe_guest_cr4}
resident_control_off_vmread {cr4_read_shadow}, {probe_guest_cr4_read_shadow}
resident_control_off_vmread {guest_dr7}, {probe_guest_dr7}
mov r11, qword ptr [r10 + {probe_guest_cr4}]
and r11, -1 - {cr4_vmxe}
mov rax, qword ptr [r10 + {probe_guest_cr4_read_shadow}]
and rax, {cr4_vmxe}
or r11, rax
mov qword ptr [rsi + {control_cpu_native_cr4}], r11
mov r11, qword ptr [r10 + {probe_guest_dr7}]
mov qword ptr [rsi + {control_cpu_guest_dr7}], r11
mov r11, qword ptr [r10 + {probe_guest_gdtr_limit}]
mov qword ptr [rsi + {control_cpu_guest_gdtr_limit}], r11
mov r11, qword ptr [r10 + {probe_guest_idtr_limit}]
mov qword ptr [rsi + {control_cpu_guest_idtr_limit}], r11
resident_control_off_save_host {host_es_selector}, 0
resident_control_off_save_host {host_cs_selector}, 1
resident_control_off_save_host {host_ss_selector}, 2
resident_control_off_save_host {host_ds_selector}, 3
resident_control_off_save_host {host_fs_selector}, 4
resident_control_off_save_host {host_gs_selector}, 5
resident_control_off_save_host {host_tr_selector}, 6
resident_control_off_save_host {host_cr0}, 7
resident_control_off_save_host {host_cr3}, 8
resident_control_off_save_host {host_cr4}, 9
resident_control_off_save_host {host_pat}, 10
resident_control_off_save_host {host_efer}, 11
resident_control_off_save_host {host_fs_base}, 12
resident_control_off_save_host {host_gs_base}, 13
resident_control_off_save_host {host_tr_base}, 14
resident_control_off_save_host {host_gdtr_base}, 15
resident_control_off_save_host {host_idtr_base}, 16
resident_control_off_save_host {host_sysenter_cs}, 17
resident_control_off_save_host {host_sysenter_esp}, 18
resident_control_off_save_host {host_sysenter_eip}, 19
resident_control_off_save_host {host_rsp}, 20
resident_control_off_save_host {host_rip}, 21
mov eax, {pin_based_vm_exec_control}
vmread r11, rax
jna .Lresident_control_off_failed
mov qword ptr [rsi + {control_cpu_pin_based_controls}], r11
mov eax, {vm_exit_msr_load_count}
vmread r11, rax
jna .Lresident_control_off_failed
mov qword ptr [rsi + {control_cpu_exit_msr_load_count}], r11
resident_control_off_patch_selector {host_es_selector}, {guest_es_selector}
resident_control_off_patch_selector {host_cs_selector}, {guest_cs_selector}
resident_control_off_patch_selector {host_ss_selector}, {guest_ss_selector}
resident_control_off_patch_selector {host_ds_selector}, {guest_ds_selector}
resident_control_off_patch_selector {host_fs_selector}, {guest_fs_selector}
resident_control_off_patch_selector {host_gs_selector}, {guest_gs_selector}
resident_control_off_patch_selector {host_tr_selector}, {guest_tr_selector}
resident_control_off_patch_host {host_cr0}, {guest_cr0}
resident_control_off_patch_host {host_cr3}, {guest_cr3}
mov eax, {guest_cr4}
vmread r11, rax
jna .Lresident_control_off_restore
or r11, {cr4_vmxe}
mov eax, {host_cr4}
vmwrite rax, r11
jna .Lresident_control_off_restore
resident_control_off_patch_host {host_pat}, {guest_pat}
resident_control_off_patch_host {host_efer}, {guest_efer}
resident_control_off_patch_host {host_fs_base}, {guest_fs_base}
resident_control_off_patch_host {host_gs_base}, {guest_gs_base}
resident_control_off_patch_host {host_tr_base}, {guest_tr_base}
resident_control_off_patch_host {host_gdtr_base}, {guest_gdtr_base}
resident_control_off_patch_host {host_idtr_base}, {guest_idtr_base}
resident_control_off_patch_host {host_sysenter_cs}, {guest_sysenter_cs}
resident_control_off_patch_host {host_sysenter_esp}, {guest_sysenter_esp}
resident_control_off_patch_host {host_sysenter_eip}, {guest_sysenter_eip}
resident_control_off_patch_host {host_rsp}, {guest_rsp}
lea r11, [rip + .Lresident_control_off_native]
lea rax, [rip + matrixhv_resident_set_variable]
sub r11, rax
add r11, qword ptr [rdi + {event_runtime_set_variable}]
mov eax, {host_rip}
vmwrite rax, r11
jna .Lresident_control_off_restore
mov eax, {guest_interruptibility_info}
mov r11d, 8
vmwrite rax, r11
jna .Lresident_control_off_restore
mov eax, {pin_based_vm_exec_control}
mov r11, qword ptr [rsi + {control_cpu_pin_based_controls}]
and r11d, 0xffffffbf
vmwrite rax, r11
jna .Lresident_control_off_restore
mov eax, {vm_exit_msr_load_count}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_control_off_restore
mov qword ptr [rsi + {control_cpu_phase}], 1
mov rax, {bridge_off_prepared_result}
mov qword ptr [rsp], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_control_off_restore:
resident_control_off_restore_host {host_es_selector}, 0
resident_control_off_restore_host {host_cs_selector}, 1
resident_control_off_restore_host {host_ss_selector}, 2
resident_control_off_restore_host {host_ds_selector}, 3
resident_control_off_restore_host {host_fs_selector}, 4
resident_control_off_restore_host {host_gs_selector}, 5
resident_control_off_restore_host {host_tr_selector}, 6
resident_control_off_restore_host {host_cr0}, 7
resident_control_off_restore_host {host_cr3}, 8
resident_control_off_restore_host {host_cr4}, 9
resident_control_off_restore_host {host_pat}, 10
resident_control_off_restore_host {host_efer}, 11
resident_control_off_restore_host {host_fs_base}, 12
resident_control_off_restore_host {host_gs_base}, 13
resident_control_off_restore_host {host_tr_base}, 14
resident_control_off_restore_host {host_gdtr_base}, 15
resident_control_off_restore_host {host_idtr_base}, 16
resident_control_off_restore_host {host_sysenter_cs}, 17
resident_control_off_restore_host {host_sysenter_esp}, 18
resident_control_off_restore_host {host_sysenter_eip}, 19
resident_control_off_restore_host {host_rsp}, 20
resident_control_off_restore_host {host_rip}, 21
mov eax, {guest_interruptibility_info}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {pin_based_vm_exec_control}
mov r11, qword ptr [rsi + {control_cpu_pin_based_controls}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {vm_exit_msr_load_count}
mov r11, qword ptr [rsi + {control_cpu_exit_msr_load_count}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [rsi + {control_cpu_phase}], 0
.Lresident_control_off_failed:
xor eax, eax
mov qword ptr [rsp], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_control_off_unexpected:
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_control_off_failed
mov rcx, qword ptr [r12 + {b_processor_number}]
cmp rcx, 64
jae .Lresident_control_off_failed
imul rcx, {control_cpu_state_size}
lea rsi, [rdi + {event_control_cpu_states}]
add rsi, rcx
cmp qword ptr [rsi + {control_cpu_phase}], 1
jne .Lresident_control_off_failed
jmp .Lresident_control_off_restore
.Lresident_dispatch_stop:
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_dispatch_stop_record
cmp qword ptr [rdi + {event_ebs_seen}], 0
jne .Lresident_dispatch_post_ebs_stop
.Lresident_dispatch_stop_record:
mov rax, qword ptr [rsp + 16]
mov qword ptr [r12 + {b_stop_result}], rax
lea rsi, [rip + .Lstart_returned_message]
mov r9d, {start_returned_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Lresident_dispatch_post_ebs_stop:
lea rsi, [rip + .Lpost_ebs_stop_message]
mov r9d, {post_ebs_stop_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Lresident_dispatch_nested_probe_failed:
lea rsi, [rip + .Lnested_failure_message]
mov r9d, {nested_failure_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Lresident_dispatch_unsupported:
mov rax, {unsupported_stop}
mov qword ptr [r12 + {b_stop_result}], rax
lea rsi, [rip + .Lunsupported_exit_message]
mov r9d, {unsupported_exit_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Lresident_dispatch_host_cr3_mismatch:
lea rsi, [rip + .Lhost_cr3_mismatch_message]
mov r9d, {host_cr3_mismatch_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Lresident_dispatch_event_corrupt:
lea rsi, [rip + .Levent_corrupt_message]
mov r9d, {event_corrupt_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Lresident_dispatch_vmread_failed:
lea rsi, [rip + .Lvmread_failed_message]
mov r9d, {vmread_failed_message_len}
call .Lresident_serial_write
jmp .Lresident_dispatch_halt
.Lresident_dispatch_inject_gp:
mov eax, dword ptr [r12 + {b_last_reason}]
sub eax, {rdmsr_reason}
cmp eax, 1
ja .Lresident_dispatch_inject_gp_event
resident_telemetry_counter inc, {b_msr_gp_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_inject_gp_event
mov eax, dword ptr [rsp + 8]
mov qword ptr [r12 + {b_last_gp_msr}], rax
.Lresident_dispatch_inject_gp_event:
mov rax, {vm_entry_exception_error_code}
xor r10d, r10d
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
mov rax, {vm_entry_intr_info_field}
mov r10d, 0x80000b0d
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_advance_guest_rip:
mov r10, qword ptr [r12 + {b_last_guest_rip}]
add r10, qword ptr [r12 + {b_last_instruction_len}]
mov rax, {guest_rip}
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
ret
.Lresident_dispatch_vmwrite_failed:
lea rsi, [rip + .Lvmwrite_failed_message]
mov r9d, {vmwrite_failed_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Lresident_dispatch_boot_timer:
cmp qword ptr [r12 + {b_diagnostic_interval}], 0
je .Lresident_dispatch_unsupported
rdtsc
shl rdx, 32
or rax, rdx
add rax, qword ptr [r12 + {b_diagnostic_interval}]
mov qword ptr [r12 + {b_diagnostic_deadline}], rax
mov r8, qword ptr [r12 + {b_event_context}]
test r8, r8
jz .Lresident_boot_timer_retry_event
cmp qword ptr [r8 + {event_ebs_seen}], 0
je .Lresident_boot_timer_retry_event
rdtsc
shl rdx, 32
or rax, rdx
cmp rax, qword ptr [r8 + {event_visual_deadline}]
jae .Lresident_boot_timer_expire
inc qword ptr [r12 + {b_diagnostic_samples}]
jmp .Lresident_boot_timer_snapshot
// The boot display uses elapsed time, independent of user telemetry collection.
.Lresident_boot_timer_expire:
call .Lresident_framebuffer_active
mov rax, {pin_based_vm_exec_control}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
btr r11d, 6
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
btr qword ptr [r12 + {b_nested_vmcs01_pin_based_controls}], 6
mov qword ptr [r12 + {b_diagnostic_interval}], 0
mov qword ptr [r12 + {b_diagnostic_expired}], 1
jmp .Lresident_boot_timer_retry_event
.Lresident_boot_timer_snapshot:
cmp qword ptr [r8 + {event_diagnostic_halted}], 0
jne .Lresident_boot_timer_retry_event
call .Lresident_diagnostic_snapshot
.Lresident_boot_timer_retry_event:
// A timer exit can interrupt event delivery; retry the undelivered event.
mov rax, {idt_vectoring_info_field}
vmread r10, rax
jna .Lresident_dispatch_vmread_failed
bt r10d, 31
jc .Lresident_boot_timer_event_valid
xor r10d, r10d
jmp .Lresident_boot_timer_event_ready
.Lresident_boot_timer_event_valid:
and r10d, 0x80000fff
bt r10d, 11
jnc .Lresident_boot_timer_event_type
mov rax, {idt_vectoring_error_code}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov rax, {vm_entry_exception_error_code}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_boot_timer_event_type:
mov edx, r10d
and edx, 0x700
cmp edx, 0x200
jne .Lresident_boot_timer_software_event
mov rax, {guest_interruptibility_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
btr r11, 3
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_boot_timer_event_ready
.Lresident_boot_timer_software_event:
cmp edx, 0x400
jb .Lresident_boot_timer_event_ready
cmp edx, 0x600
ja .Lresident_boot_timer_event_ready
mov rax, {exit_instruction_len}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov rax, {vm_entry_instruction_len}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_boot_timer_event_ready:
mov rax, {vm_entry_intr_info_field}
vmwrite rax, r10
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_reload_diagnostic_timer:
cmp qword ptr [r12 + {b_diagnostic_interval}], 0
je .Lresident_reload_diagnostic_done
rdtsc
shl rdx, 32
or rax, rdx
mov r11, qword ptr [r12 + {b_diagnostic_deadline}]
sub r11, rax
jbe .Lresident_reload_diagnostic_due
mov ecx, dword ptr [r12 + {b_diagnostic_rate}]
shr r11, cl
cmp r11, 2
jb .Lresident_reload_diagnostic_due
mov eax, 0xffffffff
cmp r11, rax
cmova r11, rax
jmp .Lresident_reload_diagnostic_write
.Lresident_reload_diagnostic_due:
mov r11d, 2
.Lresident_reload_diagnostic_write:
// Keep a fixed deadline across ordinary exits so MSR traffic cannot starve sampling.
mov rax, {vmx_preemption_timer_value}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_reload_diagnostic_done:
ret
.Lresident_dispatch_resume:
call .Lresident_watchdog_handler_returned
call .Lresident_sync_ept_cache
call .Lresident_deliver_pending_nmi
call .Lresident_reload_diagnostic_timer
call .Lresident_profile_exit_handler
call .Lresident_watchdog_resuming
call .Lresident_nested_eptp_sync_enter
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
vmresume
push r15
push r14
push r13
push r12
push r11
push r10
push r9
push r8
push rdi
push rsi
push rbp
push rbx
push rdx
push rcx
push rax
mov r12, qword ptr [rsp + 120]
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_dispatch_vmresume_error_normal
mov rcx, qword ptr [r12 + {b_processor_number}]
cmp rcx, 64
jae .Lresident_dispatch_vmresume_error_normal
imul rcx, {control_cpu_state_size}
lea rsi, [rdi + {event_control_cpu_states}]
add rsi, rcx
cmp qword ptr [rsi + {control_cpu_phase}], 1
jne .Lresident_dispatch_vmresume_error_normal
mov rdi, qword ptr [r12 + {b_event_context}]
mov rcx, qword ptr [r12 + {b_processor_number}]
imul rcx, {control_cpu_state_size}
lea rsi, [rdi + {event_control_cpu_states}]
add rsi, rcx
resident_control_off_restore_host {host_es_selector}, 0
resident_control_off_restore_host {host_cs_selector}, 1
resident_control_off_restore_host {host_ss_selector}, 2
resident_control_off_restore_host {host_ds_selector}, 3
resident_control_off_restore_host {host_fs_selector}, 4
resident_control_off_restore_host {host_gs_selector}, 5
resident_control_off_restore_host {host_tr_selector}, 6
resident_control_off_restore_host {host_cr0}, 7
resident_control_off_restore_host {host_cr3}, 8
resident_control_off_restore_host {host_cr4}, 9
resident_control_off_restore_host {host_pat}, 10
resident_control_off_restore_host {host_efer}, 11
resident_control_off_restore_host {host_fs_base}, 12
resident_control_off_restore_host {host_gs_base}, 13
resident_control_off_restore_host {host_tr_base}, 14
resident_control_off_restore_host {host_gdtr_base}, 15
resident_control_off_restore_host {host_idtr_base}, 16
resident_control_off_restore_host {host_sysenter_cs}, 17
resident_control_off_restore_host {host_sysenter_esp}, 18
resident_control_off_restore_host {host_sysenter_eip}, 19
resident_control_off_restore_host {host_rsp}, 20
resident_control_off_restore_host {host_rip}, 21
mov eax, {guest_interruptibility_info}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {pin_based_vm_exec_control}
mov r11, qword ptr [rsi + {control_cpu_pin_based_controls}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {vm_exit_msr_load_count}
mov r11, qword ptr [rsi + {control_cpu_exit_msr_load_count}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [rsi + {control_cpu_phase}], 0
mov qword ptr [rsp], 0
jmp .Lresident_dispatch_resume
.Lresident_dispatch_vmresume_error_normal:
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
mov r12, qword ptr [rsp]
resident_telemetry_counter inc, {b_watchdog_sequence}, {b_telemetry_active}
cmp qword ptr [r12 + {b_telemetry_active}], 0
je 991f
mov qword ptr [r12 + {b_watchdog_phase}], 2
991:
resident_telemetry_counter inc, {b_watchdog_resume_failures}, {b_telemetry_active}
lea rsi, [rip + .Lvmresume_failed_message]
mov r9d, {vmresume_failed_message_len}
call .Lresident_serial_write
mov rax, {vm_instruction_error}
vmread r11, rax
jc .Lresident_dispatch_vmresume_error_unknown
jz .Lresident_dispatch_vmresume_error_unknown
mov rax, r11
jmp .Lresident_dispatch_vmresume_error_print
.Lresident_dispatch_vmresume_error_unknown:
mov rax, -1
.Lresident_dispatch_vmresume_error_print:
mov qword ptr [r12 + {b_stop_result}], rax
mov r8, qword ptr [r12 + {b_event_context}]
test r8, r8
jz .Lresident_dispatch_vmresume_error_drawn
cmp qword ptr [r8 + {event_ebs_seen}], 0
je .Lresident_dispatch_vmresume_error_drawn
mov ecx, 13
call .Lresident_paint_byte
.Lresident_dispatch_vmresume_error_drawn:
mov rax, qword ptr [r12 + {b_stop_result}]
call .Lresident_serial_hex64
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
// Separate emulated VMCS access, entry, EPT invalidation, and other exit costs.
.Lresident_profile_exit_handler:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_profile_exit_handler_done
mov ecx, 2
mov r11d, dword ptr [r12 + {b_last_reason}]
cmp r11d, {vmread_reason}
je .Lresident_profile_vmcs_access
cmp r11d, {vmwrite_reason}
je .Lresident_profile_vmcs_access
cmp r11d, {vmresume_reason}
je .Lresident_profile_nested_entry
cmp r11d, {vmlaunch_reason}
je .Lresident_profile_nested_entry
cmp r11d, {invept_reason}
jne .Lresident_profile_accumulate
mov ecx, 3
jmp .Lresident_profile_accumulate
.Lresident_profile_vmcs_access:
xor ecx, ecx
jmp .Lresident_profile_accumulate
.Lresident_profile_nested_entry:
mov ecx, 1
.Lresident_profile_accumulate:
lfence
rdtsc
shl rdx, 32
or rax, rdx
sub rax, qword ptr [r12 + {b_nested_exit_started_tsc}]
add qword ptr [r12 + {b_nested_exit_handler_cycles} + rcx * 8], rax
.Lresident_profile_exit_handler_done:
ret
.Lresident_dispatch_halt:
mov r10, qword ptr [r12 + {b_event_context}]
test r10, r10
jz .Lresident_visual_halt_pre_ebs
mov rcx, qword ptr [r12 + {b_processor_number}]
cmp rcx, 64
jae .Lresident_halted_cpu_recorded
lock bts qword ptr [r10 + {event_halted_cpu_mask}], rcx
.Lresident_halted_cpu_recorded:
mov rax, -1
lock cmpxchg qword ptr [r10 + {event_failed_processor}], rcx
jne .Lresident_first_cpu_failure_recorded
mov rax, qword ptr [r12 + {b_last_reason}]
mov qword ptr [r10 + {event_failed_exit_reason}], rax
mov rax, qword ptr [r12 + {b_last_qualification}]
mov qword ptr [r10 + {event_failed_qualification}], rax
mov rax, qword ptr [r12 + {b_stop_result}]
mov qword ptr [r10 + {event_failed_stop_result}], rax
.Lresident_first_cpu_failure_recorded:
cmp qword ptr [r10 + {event_ebs_seen}], 0
je .Lresident_visual_halt_pre_ebs
mov r8, r10
call .Lresident_claim_diagnostic
jne .Lresident_dispatch_halt_now
mov ecx, 4
call .Lresident_paint_stage
call .Lresident_diagnostic_snapshot
jmp .Lresident_dispatch_halt_now
.Lresident_visual_halt_pre_ebs:
cmp qword ptr [r12 + {b_processor_number}], 0
jne .Lresident_dispatch_halt_now
mov rcx, qword ptr [r12 + {b_last_reason}]
mov edx, 1
mov r8, qword ptr [r12 + {b_last_guest_physical_address}]
mov r9, qword ptr [r12 + {b_last_guest_rip}]
mov r10, qword ptr [r12 + {b_last_qualification}]
call .Lresident_visual_callback
.Lresident_dispatch_halt_now:
cli
.Lresident_dispatch_halt_loop:
hlt
jmp .Lresident_dispatch_halt_loop
.Lresident_visual_callback:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_framebuffer_sink}
jz .Lresident_visual_callback_disabled
mov rax, qword ptr [r12 + {b_event_context}]
test rax, rax
jz .Lresident_visual_callback_disabled
cmp qword ptr [rax + {event_ebs_seen}], 0
jne .Lresident_visual_callback_disabled
push r15
mov r15, rsp
and rsp, -16
sub rsp, 560
mov qword ptr [rsp + 32], r10
fxsave64 [rsp + 48]
call qword ptr [rip + matrixhv_resident_island_visual_callback]
fxrstor64 [rsp + 48]
mov rsp, r15
pop r15
.Lresident_visual_callback_disabled:
ret
.Lresident_msr_privilege:
mov rax, {guest_cr0}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 1
jz .Lresident_msr_privilege_ok
mov rax, {guest_rflags}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x20000
jnz .Lresident_msr_privilege_fault
mov rax, {guest_cs_selector}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 3
jnz .Lresident_msr_privilege_fault
.Lresident_msr_privilege_ok:
clc
ret
.Lresident_msr_privilege_fault:
stc
ret
.Lresident_deliver_pending_nmi:
cmp qword ptr [r12 + {b_nmi_pending}], 0
je .Lresident_deliver_nmi_done
// An NMI received while root services L1 is delivered to L1 on return.
cmp qword ptr [r12 + {b_nested_l2_active}], 0
je .Lresident_deliver_nmi_check_event
bt qword ptr [r12 + {b_nested_vmcs12_pin_based_control}], 3
jc .Lresident_deliver_nmi_done
.Lresident_deliver_nmi_check_event:
mov eax, {vm_entry_intr_info_field}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
bt r11d, 31
jc .Lresident_deliver_nmi_window
mov eax, {guest_interruptibility_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0xb
jnz .Lresident_deliver_nmi_window
mov eax, {guest_activity_state}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
cmp r11d, 3
je .Lresident_deliver_nmi_done
xor eax, eax
xchg qword ptr [r12 + {b_nmi_pending}], rax
mov eax, {vm_entry_intr_info_field}
mov r11d, 0x80000202
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {guest_activity_state}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_deliver_nmi_done
.Lresident_deliver_nmi_window:
mov eax, {cpu_based_vm_exec_control}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
bts r11, 22
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
cmp qword ptr [r12 + {b_nested_l2_active}], 0
je .Lresident_deliver_nmi_done
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid} + 8], 0
.Lresident_deliver_nmi_done:
ret
// Validate emulated MSRs before changing VMCS state; faults belong to the guest.
.Lresident_validate_efer:
mov rax, r11
and rax, -3330
jnz .Lresident_invalid_msr_value
test r11d, 1
jz .Lresident_efer_check_lme
bt edx, 11
jnc .Lresident_invalid_msr_value
.Lresident_efer_check_lme:
test r11d, 0x100
jz .Lresident_efer_check_nxe
bt edx, 29
jnc .Lresident_invalid_msr_value
.Lresident_efer_check_nxe:
test r11d, 0x800
jz .Lresident_efer_check_paging
bt edx, 20
jnc .Lresident_invalid_msr_value
.Lresident_efer_check_paging:
bt r9, 31
jnc .Lresident_efer_preserve_lma
mov rax, r11
xor rax, r8
test eax, 0x100
jnz .Lresident_invalid_msr_value
.Lresident_efer_preserve_lma:
and r11, -1025
and r8d, 0x400
or r11, r8
clc
ret
.Lresident_validate_canonical_msr:
mov rax, r11
bt r9, 12
jc .Lresident_msr_canonical_57
shl rax, 16
sar rax, 16
jmp .Lresident_msr_canonical_compare
.Lresident_msr_canonical_57:
shl rax, 7
sar rax, 7
.Lresident_msr_canonical_compare:
cmp rax, r11
jne .Lresident_invalid_msr_value
clc
ret
.Lresident_invalid_msr_value:
stc
ret
.Lresident_guarded_rdmsr:
.Lresident_rdmsr_instruction:
rdmsr
clc
ret
.Lresident_guarded_wrmsr:
.Lresident_wrmsr_instruction:
wrmsr
clc
ret
.Lresident_guarded_xsetbv:
.Lresident_xsetbv_instruction:
xsetbv
clc
ret
.Lresident_msr_fault_return:
stc
ret
.Lresident_msr_fault_fixup:
lea rdx, [rip + .Lresident_rdmsr_instruction]
cmp rax, rdx
je .Lresident_msr_fault_match
lea rdx, [rip + .Lresident_wrmsr_instruction]
cmp rax, rdx
je .Lresident_msr_fault_match
lea rdx, [rip + .Lresident_xsetbv_instruction]
cmp rax, rdx
je .Lresident_msr_fault_match
xor eax, eax
ret
.Lresident_msr_fault_match:
lea rax, [rip + .Lresident_msr_fault_return]
ret
.globl matrixhv_resident_island_gp
matrixhv_resident_island_gp:
push rax
push rdx
// The #GP frame contains an error code before RIP; the two saved registers add 16 bytes.
mov rax, qword ptr [rsp + 24]
call .Lresident_msr_fault_fixup
test rax, rax
jz .Lresident_host_gp_fatal
mov qword ptr [rsp + 24], rax
pop rdx
pop rax
add rsp, 8
iretq
.Lresident_host_gp_fatal:
mov r8, qword ptr [rip + matrixhv_resident_island_event_context]
test r8, r8
jz matrixhv_resident_island_fatal
call .Lresident_claim_diagnostic
jne .Lresident_island_fatal_serial
mov rax, qword ptr [rsp + 24]
mov qword ptr [r8 + {event_host_fault_rip}], rax
mov rax, qword ptr [rsp + 16]
mov qword ptr [r8 + {event_host_fault_error_code}], rax
mov qword ptr [r8 + {event_host_fault_vector}], 13
jmp .Lresident_island_fatal_owned
// Fixed-size entries normalize exception frames to vector, error code, and RIP.
.balign 16
.globl matrixhv_resident_exception_stubs
matrixhv_resident_exception_stubs:
.set .Lresident_exception_vector, 0
.rept 32
.if .Lresident_exception_vector == 2
jmp .Lresident_host_nmi
.else
.if ((0x60227d00 >> .Lresident_exception_vector) & 1) == 0
push 0
.endif
push .Lresident_exception_vector
jmp .Lresident_host_exception
.endif
.balign 16
.set .Lresident_exception_vector, .Lresident_exception_vector + 1
.endr
.Lresident_host_exception:
cli
mov r8, qword ptr [rip + matrixhv_resident_island_event_context]
test r8, r8
jz matrixhv_resident_island_fatal
call .Lresident_claim_diagnostic
jne .Lresident_island_fatal_serial
mov rax, qword ptr [rsp]
xor edx, edx
cmp eax, 14
jne .Lresident_host_exception_address
mov rdx, cr2
.Lresident_host_exception_address:
mov qword ptr [r8 + {event_host_fault_address}], rdx
mov rax, qword ptr [rsp + 8]
mov qword ptr [r8 + {event_host_fault_error_code}], rax
mov rax, qword ptr [rsp + 16]
mov qword ptr [r8 + {event_host_fault_rip}], rax
mov rax, qword ptr [rsp]
mov qword ptr [r8 + {event_host_fault_vector}], rax
jmp .Lresident_island_fatal_owned
.Lresident_host_nmi:
push rax
mov rax, qword ptr gs:[112]
test rax, rax
jz .Lresident_host_nmi_return
cmp qword ptr [rax + {b_nested_eptp_sync_nmi}], 0
jne .Lresident_host_sync_nmi
mov qword ptr [rax + {b_nmi_pending}], 1
cmp qword ptr [rax + {b_telemetry_enabled}], 0
je .Lresident_host_nmi_return
inc qword ptr [rax + {b_nmi_count}]
.Lresident_host_nmi_return:
pop rax
iretq
.Lresident_host_sync_nmi:
push rcx
push rdx
push rbx
push rbp
push rsi
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
mov r12, rax
cld
call .Lresident_nested_eptp_sync_host_nmi
test eax, eax
jnz .Lresident_host_sync_nmi_return
mov qword ptr [r12 + {b_nmi_pending}], 1
cmp qword ptr [r12 + {b_telemetry_enabled}], 0
je .Lresident_host_sync_nmi_return
inc qword ptr [r12 + {b_nmi_count}]
.Lresident_host_sync_nmi_return:
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rbp
pop rbx
pop rdx
pop rcx
jmp .Lresident_host_nmi_return
.globl matrixhv_resident_island_fatal
matrixhv_resident_island_fatal:
cli
mov r8, qword ptr [rip + matrixhv_resident_island_event_context]
test r8, r8
jz .Lresident_island_fatal_serial
call .Lresident_claim_diagnostic
jne .Lresident_island_fatal_serial
.Lresident_island_fatal_owned:
mov ecx, 29
call .Lresident_paint_stage
mov rax, qword ptr [r8 + {event_host_fault_vector}]
mov ecx, 10
call .Lresident_paint_hex
mov rax, qword ptr [r8 + {event_host_fault_rip}]
mov ecx, 11
call .Lresident_paint_hex
mov rax, qword ptr [r8 + {event_host_fault_error_code}]
mov ecx, 12
call .Lresident_paint_hex
mov rax, qword ptr [r8 + {event_host_fault_address}]
mov ecx, 13
call .Lresident_paint_hex
.Lresident_island_fatal_serial:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz 1f
mov dx, {serial_port}
mov al, 0x21
out dx, al
1:
hlt
jmp 1b
.globl matrixhv_resident_ebs_callback
matrixhv_resident_ebs_callback:
// Keep the notification independent of protocols, locks, and display MMIO.
mov r8, rdx
cmp qword ptr [r8 + {event_ebs_seen}], 0
jne .Lresident_ebs_callback_done
mov r9, qword ptr [r8 + {event_tsc_hz}]
imul r9, 40
rdtsc
shl rdx, 32
or rax, rdx
add rax, r9
mov qword ptr [r8 + {event_visual_deadline}], rax
mov qword ptr [r8 + {event_ebs_seen}], 1
.Lresident_ebs_callback_done:
ret
.globl matrixhv_resident_va_callback
matrixhv_resident_va_callback:
push rbx
sub rsp, 48
mov qword ptr [rsp + 40], rdx
mov qword ptr [rdx + {event_va_seen}], 1
lea rdx, [rip + matrixhv_resident_original_get_variable]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rip + matrixhv_resident_original_set_variable]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rip + matrixhv_resident_runtime_get_variable]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rip + matrixhv_resident_runtime_set_variable]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rip + matrixhv_resident_bridge_context]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
mov rbx, qword ptr [rsp + 40]
mov qword ptr [rsp + 32], 0
.Lresident_va_native_storage_next:
mov rdx, qword ptr [rsp + 32]
imul rdx, {control_cpu_state_size}
lea rdx, [rbx + rdx + {event_control_cpu_states} + {control_cpu_native_storage_runtime}]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
inc qword ptr [rsp + 32]
cmp qword ptr [rsp + 32], 64
jb .Lresident_va_native_storage_next
jmp .Lresident_va_done
.Lresident_va_failed:
mov rbx, qword ptr [rsp + 40]
mov qword ptr [rbx + {event_control_va_error}], rax
.Lresident_va_done:
mov rbx, qword ptr [rsp + 40]
mov rax, qword ptr [rip + matrixhv_resident_runtime_get_variable]
mov qword ptr [rbx + {event_runtime_get_variable}], rax
mov rax, qword ptr [rip + matrixhv_resident_runtime_set_variable]
mov qword ptr [rbx + {event_runtime_set_variable}], rax
mov rax, qword ptr [rip + matrixhv_resident_bridge_context]
mov qword ptr [rbx + {event_runtime_context}], rax
add rsp, 48
pop rbx
ret

.globl matrixhv_resident_get_variable
matrixhv_resident_get_variable:
call .Lresident_bridge_match
test eax, eax
jz .Lresident_get_variable_forward
test r9, r9
jz .Lresident_bridge_invalid_parameter
mov r10, qword ptr [rsp + 40]
cmp qword ptr [r9], {bridge_status_size}
jae .Lresident_get_variable_capacity_ok
mov qword ptr [r9], {bridge_status_size}
movabs rax, 0x8000000000000005
ret
.Lresident_get_variable_capacity_ok:
mov qword ptr [r9], {bridge_status_size}
test r10, r10
jz .Lresident_bridge_invalid_parameter
mov r11, qword ptr [rip + matrixhv_resident_bridge_context]
test r11, r11
jz .Lresident_bridge_unsupported
movabs rax, {bridge_magic}
mov qword ptr [r10 + {bridge_status_magic}], rax
mov dword ptr [r10 + {bridge_status_version}], {bridge_version}
mov dword ptr [r10 + {bridge_status_capabilities}], 3
push rbx
call .Lresident_bridge_apic_id
pop rbx
mov dword ptr [r10 + {bridge_status_apic_id}], eax
mov eax, dword ptr [r11 + {event_control_processor_count}]
mov dword ptr [r10 + {bridge_status_processor_count}], eax
mov rax, qword ptr [r11 + {event_control_expected_mask}]
mov qword ptr [r10 + {bridge_status_expected_mask}], rax
mov rax, qword ptr [r11 + {event_control_failed_mask}]
or rax, qword ptr [r11 + {event_halted_cpu_mask}]
mov qword ptr [r10 + {bridge_status_failed_mask}], rax
not rax
and rax, qword ptr [r11 + {event_control_active_mask}]
mov qword ptr [r10 + {bridge_status_active_mask}], rax
mov rax, qword ptr [r11 + {event_control_stopped_mask}]
mov qword ptr [r10 + {bridge_status_stopped_mask}], rax
mov rax, qword ptr [r11 + {event_ebs_seen}]
mov qword ptr [r10 + {bridge_status_ebs_seen}], rax
mov rax, qword ptr [r11 + {event_va_seen}]
mov qword ptr [r10 + {bridge_status_va_seen}], rax
mov rax, qword ptr [r11 + {event_control_va_error}]
mov qword ptr [r10 + {bridge_status_va_error}], rax
mov qword ptr [r10 + {bridge_status_completion_sequence}], 0
test r8, r8
jz .Lresident_get_variable_apic_ids
mov dword ptr [r8], 7
.Lresident_get_variable_apic_ids:
xor r8d, r8d
.Lresident_get_variable_apic_next:
mov eax, dword ptr [r11 + {event_control_apic_ids} + r8 * 4]
mov dword ptr [r10 + {bridge_status_apic_ids} + r8 * 4], eax
inc r8d
cmp r8d, 64
jb .Lresident_get_variable_apic_next
xor r8d, r8d
.Lresident_get_variable_probe_zero:
mov qword ptr [r10 + {bridge_status_probe_snapshot} + r8 * 8], 0
inc r8d
cmp r8d, {probe_state_qwords}
jb .Lresident_get_variable_probe_zero
mov r9d, dword ptr [r10 + {bridge_status_apic_id}]
xor r8d, r8d
.Lresident_get_variable_probe_find:
cmp dword ptr [r11 + {event_control_apic_ids} + r8 * 4], r9d
je .Lresident_get_variable_probe_copy_setup
inc r8d
cmp r8d, 64
jb .Lresident_get_variable_probe_find
jmp .Lresident_get_variable_done
.Lresident_get_variable_probe_copy_setup:
mov rax, qword ptr [r11 + {event_control_completion_sequences} + r8 * 8]
mov qword ptr [r10 + {bridge_status_completion_sequence}], rax
imul r8, {probe_state_size}
lea rdx, [r11 + {event_control_probe_states}]
add rdx, r8
xor r8d, r8d
.Lresident_get_variable_probe_copy:
mov rax, qword ptr [rdx + r8 * 8]
mov qword ptr [r10 + {bridge_status_probe_snapshot} + r8 * 8], rax
inc r8d
cmp r8d, {probe_state_qwords}
jb .Lresident_get_variable_probe_copy
.Lresident_get_variable_done:
xor eax, eax
ret
.Lresident_get_variable_forward:
jmp qword ptr [rip + matrixhv_resident_original_get_variable]

.globl matrixhv_resident_set_variable
matrixhv_resident_set_variable:
call .Lresident_bridge_match
test eax, eax
jz .Lresident_set_variable_forward
cmp r8d, 7
jne .Lresident_bridge_invalid_parameter
cmp r9, {bridge_request_size}
jne .Lresident_bridge_invalid_parameter
mov r10, qword ptr [rsp + 40]
test r10, r10
jz .Lresident_bridge_invalid_parameter
mov r11, qword ptr [rip + matrixhv_resident_bridge_context]
test r11, r11
jz .Lresident_bridge_unsupported
mov rax, {bridge_magic}
cmp qword ptr [r10 + {bridge_request_magic}], rax
jne .Lresident_bridge_unsupported
cmp dword ptr [r10 + {bridge_request_version}], {bridge_version}
jne .Lresident_bridge_unsupported
mov eax, dword ptr [r10 + {bridge_request_operation}]
cmp eax, {bridge_probe_operation}
je .Lresident_set_variable_operation_valid
cmp eax, 2
je .Lresident_set_variable_operation_valid
cmp eax, 1
jne .Lresident_bridge_unsupported
.Lresident_set_variable_operation_valid:
cmp qword ptr [r10 + {bridge_request_sequence}], 0
je .Lresident_bridge_invalid_parameter
cmp dword ptr [r10 + {bridge_request_reserved}], 0
jne .Lresident_bridge_invalid_parameter
cmp qword ptr [r11 + {event_ebs_seen}], 1
jne .Lresident_bridge_unsupported
cmp qword ptr [r11 + {event_va_seen}], 1
jne .Lresident_bridge_unsupported
cmp qword ptr [r11 + {event_control_va_error}], 0
jne .Lresident_bridge_unsupported
push rbx
mov edx, dword ptr [r10 + {bridge_request_apic_id}]
push rdx
call .Lresident_bridge_apic_id
pop rdx
pop rbx
cmp eax, edx
jne .Lresident_bridge_unsupported
cmp dword ptr [r10 + {bridge_request_operation}], {bridge_probe_operation}
je .Lresident_set_variable_probe
cmp dword ptr [r10 + {bridge_request_operation}], 2
je .Lresident_set_variable_off
jmp .Lresident_set_variable_on
.Lresident_set_variable_probe:
mov rcx, qword ptr [r10 + {bridge_request_sequence}]
mov rax, {bridge_probe_vmcall}
vmcall
mov r11, {bridge_probe_result}
cmp rax, r11
jne .Lresident_bridge_unsupported
xor eax, eax
ret
.Lresident_set_variable_off:
xor r8d, r8d
mov edx, dword ptr [r10 + {bridge_request_apic_id}]
.Lresident_set_variable_off_find:
cmp dword ptr [r11 + {event_control_apic_ids} + r8 * 4], edx
je .Lresident_set_variable_off_ready
inc r8d
cmp r8d, 64
jb .Lresident_set_variable_off_find
jmp .Lresident_bridge_unsupported
.Lresident_set_variable_off_ready:
mov rcx, qword ptr [r10 + {bridge_request_sequence}]
pushfq
cli
mov rax, {bridge_off_prepare_vmcall}
vmcall
mov r11, {bridge_off_prepared_result}
cmp rax, r11
jne .Lresident_set_variable_off_failed
mov rax, {bridge_off_commit_vmcall}
vmcall
.Lresident_set_variable_off_failed:
popfq
jmp .Lresident_bridge_unsupported
.Lresident_control_off_native:
mov r10, qword ptr [rip + matrixhv_resident_bridge_context]
mov r11, r8
imul r11, {control_cpu_state_size}
lea r9, [r10 + {event_control_cpu_states}]
add r9, r11
// Commit the complete VMCS to its backing region before leaving VMX operation.
mov qword ptr [r9 + {control_cpu_stage}], 0
vmclear qword ptr [r9 + {control_cpu_vmcs_region}]
ja .Lresident_control_off_vmcs_preserved
mov qword ptr [r9 + {control_cpu_stage}], 134
lock bts qword ptr [r10 + {event_control_failed_mask}], r8
.Lresident_control_off_vmcs_preserved:
vmxoff
mov r11, qword ptr [r9 + {control_cpu_native_cr4}]
mov cr4, r11
mov r11, r8
imul r11, {probe_state_size}
lea r11, [r10 + r11 + {event_control_probe_states}]
sub rsp, 32
mov ax, word ptr [r9 + {control_cpu_guest_gdtr_limit}]
mov word ptr [rsp], ax
mov rax, qword ptr [r11 + {probe_guest_gdtr_base}]
mov qword ptr [rsp + 2], rax
mov ax, word ptr [r9 + {control_cpu_guest_idtr_limit}]
mov word ptr [rsp + 16], ax
mov rax, qword ptr [r11 + {probe_guest_idtr_base}]
mov qword ptr [rsp + 18], rax
lgdt [rsp]
lidt [rsp + 16]
add rsp, 32
mov rax, qword ptr [r9 + {control_cpu_guest_dr7}]
mov dr7, rax
mov ax, word ptr [r11 + {probe_guest_es_selector}]
mov es, ax
mov ax, word ptr [r11 + {probe_guest_ds_selector}]
mov ds, ax
mov ax, word ptr [r11 + {probe_guest_fs_selector}]
mov fs, ax
mov ax, word ptr [r11 + {probe_guest_gs_selector}]
mov gs, ax
mov rax, qword ptr [r11 + {probe_guest_fs_base}]
mov rdx, rax
shr rdx, 32
mov ecx, 0xc0000100
wrmsr
mov rax, qword ptr [r11 + {probe_guest_gs_base}]
mov rdx, rax
shr rdx, 32
mov ecx, 0xc0000101
wrmsr
mov qword ptr [r9 + {control_cpu_phase}], 2
lock btr qword ptr [r10 + {event_control_active_mask}], r8
lock bts qword ptr [r10 + {event_control_stopped_mask}], r8
mov rax, qword ptr [r9 + {control_cpu_sequence}]
xchg qword ptr [r10 + {event_control_completion_sequences} + r8 * 8], rax
cmp qword ptr [r9 + {control_cpu_stage}], 134
je .Lresident_control_off_preservation_failed
popfq
xor eax, eax
ret
.Lresident_control_off_preservation_failed:
popfq
movabs rax, 0x8000000000000007
ret
.Lresident_set_variable_on:
xor r8d, r8d
mov edx, dword ptr [r10 + {bridge_request_apic_id}]
.Lresident_set_variable_on_find:
cmp dword ptr [r11 + {event_control_apic_ids} + r8 * 4], edx
je .Lresident_set_variable_on_ready
inc r8d
cmp r8d, 64
jb .Lresident_set_variable_on_find
jmp .Lresident_bridge_unsupported
.Lresident_set_variable_on_ready:
mov rcx, qword ptr [r10 + {bridge_request_sequence}]
mov r10, r11
mov r11, r8
imul r11, {control_cpu_state_size}
lea r9, [r10 + {event_control_cpu_states}]
add r9, r11
cmp qword ptr [r9 + {control_cpu_phase}], 2
jne .Lresident_bridge_unsupported
bt qword ptr [r10 + {event_control_stopped_mask}], r8
jnc .Lresident_bridge_unsupported
bt qword ptr [r10 + {event_control_active_mask}], r8
jc .Lresident_bridge_unsupported
bt qword ptr [r10 + {event_control_failed_mask}], r8
jc .Lresident_bridge_unsupported
cmp qword ptr [r9 + {control_cpu_native_storage_runtime}], 0
je .Lresident_bridge_unsupported
push r12
mov r12, rcx
pushfq
cli
mov qword ptr [r9 + {control_cpu_native_caller_rsp}], rsp
mov qword ptr [r9 + {control_cpu_sequence}], r12
mov qword ptr [r9 + {control_cpu_native_snapshot_count}], 0
mov qword ptr [r9 + {control_cpu_on_failure_reason}], 0
mov qword ptr [r9 + {control_cpu_on_failure_qualification}], 0
mov rsp, qword ptr [r9 + {control_cpu_native_storage_runtime}]
add rsp, {native_stack_bytes}
resident_control_native_checkpoint 1
// The recovery CR3 must retain the physical bridge while mapping its runtime alias.
lea rax, [rip + .Lresident_control_on_recovery_switch]
lea rdx, [rip + matrixhv_resident_dispatch_entry]
sub rax, rdx
add rax, qword ptr [r9 + {control_cpu_host_fields} + (21 * 8)]
lea rdx, [rip + .Lresident_control_on_native_restore]
xor rax, rdx
shr rax, 39
test eax, 0x1ff
jz .Lresident_control_on_preflight_failed
mov r11, r8
imul r11, {probe_state_size}
lea r11, [r10 + r11 + {event_control_probe_states}]
mov ax, es
cmp ax, word ptr [r11 + {probe_guest_es_selector}]
jne .Lresident_control_on_preflight_failed
mov ax, cs
cmp ax, word ptr [r11 + {probe_guest_cs_selector}]
jne .Lresident_control_on_preflight_failed
mov ax, ss
cmp ax, word ptr [r11 + {probe_guest_ss_selector}]
jne .Lresident_control_on_preflight_failed
mov ax, ds
cmp ax, word ptr [r11 + {probe_guest_ds_selector}]
jne .Lresident_control_on_preflight_failed
mov ax, fs
cmp ax, word ptr [r11 + {probe_guest_fs_selector}]
jne .Lresident_control_on_preflight_failed
mov ax, gs
cmp ax, word ptr [r11 + {probe_guest_gs_selector}]
jne .Lresident_control_on_preflight_failed
str ax
cmp ax, word ptr [r11 + {probe_guest_tr_selector}]
jne .Lresident_control_on_preflight_failed
sldt ax
cmp ax, word ptr [r11 + {probe_guest_ldtr_selector}]
jne .Lresident_control_on_preflight_failed
sub rsp, 32
sgdt [rsp]
sidt [rsp + 16]
mov ax, word ptr [rsp]
cmp ax, word ptr [r11 + {probe_guest_gdtr_limit}]
jne .Lresident_control_on_table_failed
mov rax, qword ptr [rsp + 2]
cmp rax, qword ptr [r11 + {probe_guest_gdtr_base}]
jne .Lresident_control_on_table_failed
mov ax, word ptr [rsp + 16]
cmp ax, word ptr [r11 + {probe_guest_idtr_limit}]
jne .Lresident_control_on_table_failed
mov rax, qword ptr [rsp + 18]
cmp rax, qword ptr [r11 + {probe_guest_idtr_base}]
jne .Lresident_control_on_table_failed
add rsp, 32
push rbx
mov eax, 1
cpuid
pop rbx
bt ecx, 5
jnc .Lresident_control_on_preflight_failed
mov rax, cr4
mov qword ptr [r9 + {control_cpu_on_original_cr4}], rax
test rax, {cr4_vmxe}
jnz .Lresident_control_on_busy
mov ecx, 0x486
rdmsr
shl rdx, 32
or rax, rdx
mov rdx, cr0
mov r11, rdx
and r11, rax
cmp r11, rax
jne .Lresident_control_on_preflight_failed
mov ecx, 0x487
rdmsr
shl rdx, 32
or rax, rdx
not rax
mov rdx, cr0
test rdx, rax
jnz .Lresident_control_on_preflight_failed
mov ecx, 0x488
rdmsr
shl rdx, 32
or rax, rdx
mov rdx, qword ptr [r9 + {control_cpu_on_original_cr4}]
or rdx, {cr4_vmxe}
mov r11, rdx
and r11, rax
cmp r11, rax
jne .Lresident_control_on_preflight_failed
mov ecx, 0x489
rdmsr
shl rdx, 32
or rax, rdx
not rax
mov rdx, qword ptr [r9 + {control_cpu_on_original_cr4}]
or rdx, {cr4_vmxe}
test rdx, rax
jnz .Lresident_control_on_preflight_failed
mov rax, 2
mov rdx, 3
lock cmpxchg qword ptr [r9 + {control_cpu_phase}], rdx
jne .Lresident_control_on_preflight_failed
resident_control_native_checkpoint 2
mov qword ptr [r9 + {control_cpu_sequence}], r12
mov r11, qword ptr [r9 + {control_cpu_on_original_cr4}]
or r11, {cr4_vmxe}
mov cr4, r11
resident_control_native_checkpoint 3
mfence
vmxon qword ptr [r9 + {control_cpu_vmxon_region}]
jna .Lresident_control_on_vmxon_failed
resident_control_native_checkpoint 4
vmclear qword ptr [r9 + {control_cpu_vmcs_region}]
jna .Lresident_control_on_root_failed
resident_control_native_checkpoint 10
vmptrld qword ptr [r9 + {control_cpu_vmcs_region}]
jna .Lresident_control_on_root_failed
resident_control_native_checkpoint 5
.Lresident_control_on_vmcs_ready:
resident_control_on_restore_host {host_es_selector}, 0
resident_control_on_restore_host {host_cs_selector}, 1
resident_control_on_restore_host {host_ss_selector}, 2
resident_control_on_restore_host {host_ds_selector}, 3
resident_control_on_restore_host {host_fs_selector}, 4
resident_control_on_restore_host {host_gs_selector}, 5
resident_control_on_restore_host {host_tr_selector}, 6
resident_control_on_restore_host {host_cr0}, 7
resident_control_on_restore_host {host_cr3}, 8
resident_control_on_restore_host {host_cr4}, 9
resident_control_on_restore_host {host_pat}, 10
resident_control_on_restore_host {host_efer}, 11
resident_control_on_restore_host {host_fs_base}, 12
resident_control_on_restore_host {host_gs_base}, 13
resident_control_on_restore_host {host_tr_base}, 14
resident_control_on_restore_host {host_gdtr_base}, 15
resident_control_on_restore_host {host_idtr_base}, 16
resident_control_on_restore_host {host_sysenter_cs}, 17
resident_control_on_restore_host {host_sysenter_esp}, 18
resident_control_on_restore_host {host_sysenter_eip}, 19
resident_control_on_restore_host {host_rsp}, 20
resident_control_on_restore_host {host_rip}, 21
resident_control_native_checkpoint 6
mov eax, {pin_based_vm_exec_control}
mov rdx, qword ptr [r9 + {control_cpu_pin_based_controls}]
vmwrite rax, rdx
jna .Lresident_control_on_root_failed
mov eax, {vm_exit_msr_load_count}
mov rdx, qword ptr [r9 + {control_cpu_exit_msr_load_count}]
vmwrite rax, rdx
jna .Lresident_control_on_root_failed
resident_control_on_write {vm_entry_msr_load_count}, 0
mov rdx, cr0
mov qword ptr [r9 + {control_cpu_on_native_cr0}], rdx
resident_control_on_write {guest_cr0}, rdx
mov rdx, cr3
mov qword ptr [r9 + {control_cpu_on_native_cr3}], rdx
resident_control_on_write {guest_cr3}, rdx
resident_control_on_write {guest_cr4}, cr4
mov rdx, qword ptr [r9 + {control_cpu_on_original_cr4}]
mov eax, {cr4_read_shadow}
vmwrite rax, rdx
jna .Lresident_control_on_root_failed
mov rdx, dr7
mov qword ptr [r9 + {control_cpu_on_native_dr7}], rdx
resident_control_on_write {guest_dr7}, rdx
resident_control_on_write {guest_rsp}, rsp
lea rdx, [rip + .Lresident_control_on_guest]
mov eax, {guest_rip}
vmwrite rax, rdx
jna .Lresident_control_on_root_failed
resident_control_on_write {guest_rflags}, 2
resident_control_on_write {guest_pending_dbg_exceptions}, 0
resident_control_on_write {guest_interruptibility_info}, 0
resident_control_on_write {guest_activity_state}, 0
resident_control_on_write {vm_entry_intr_info_field}, 0
resident_control_on_write {vmcs_link_pointer}, -1
resident_control_on_write_msr 0x1d9, {guest_ia32_debugctl}, 0
resident_control_on_write_msr 0x277, {guest_pat}, 1
resident_control_on_write_msr 0xc0000080, {guest_efer}, 2
resident_control_on_write_msr 0xc0000100, {guest_fs_base}, 3
resident_control_on_write_msr 0xc0000101, {guest_gs_base}, 4
resident_control_on_write_msr 0x174, {guest_sysenter_cs}, 5
resident_control_on_write_msr 0x175, {guest_sysenter_esp}, 6
resident_control_on_write_msr 0x176, {guest_sysenter_eip}, 7
cmp qword ptr [rip + matrixhv_resident_island_msr_switch_count], 0
je .Lresident_control_on_native_msrs_saved
mov ecx, {spec_ctrl_msr}
rdmsr
shl rdx, 32
or rdx, rax
mov qword ptr [r9 + {control_cpu_on_native_msrs} + (8 * 8)], rdx
.Lresident_control_on_native_msrs_saved:
resident_control_native_checkpoint 7
sub rsp, 16
mov eax, {ept_pointer}
vmread rdx, rax
jna .Lresident_control_on_invalidation_failed
mov qword ptr [rsp], rdx
mov qword ptr [rsp + 8], 0
mov eax, 1
resident_control_native_checkpoint 11
invept rax, xmmword ptr [rsp]
jna .Lresident_control_on_invalidation_failed
mov eax, {secondary_vm_exec_control}
vmread rdx, rax
jna .Lresident_control_on_invalidation_failed
test edx, 0x20
jz .Lresident_control_on_invalidation_done
mov eax, {virtual_processor_id}
vmread rdx, rax
jna .Lresident_control_on_invalidation_failed
mov qword ptr [rsp], rdx
mov qword ptr [rsp + 8], 0
mov eax, 1
resident_control_native_checkpoint 12
invvpid rax, xmmword ptr [rsp]
jna .Lresident_control_on_invalidation_failed
.Lresident_control_on_invalidation_done:
add rsp, 16
resident_control_native_checkpoint 8
mfence
lock bts qword ptr [r10 + {event_control_rearm_mask}], r8
vmlaunch
lock btr qword ptr [r10 + {event_control_rearm_mask}], r8
jmp .Lresident_control_on_root_failed
.Lresident_control_on_guest:
resident_control_native_checkpoint 9
mov qword ptr [r9 + {control_cpu_phase}], 0
lock btr qword ptr [r10 + {event_control_stopped_mask}], r8
lock bts qword ptr [r10 + {event_control_active_mask}], r8
mov rax, qword ptr [r9 + {control_cpu_sequence}]
xchg qword ptr [r10 + {event_control_completion_sequences} + r8 * 8], rax
mov rsp, qword ptr [r9 + {control_cpu_native_caller_rsp}]
popfq
pop r12
xor eax, eax
ret
.Lresident_control_on_invalidation_failed:
add rsp, 16
resident_control_native_checkpoint 132
jmp .Lresident_control_on_root_cleanup
.Lresident_control_on_table_failed:
add rsp, 32
.Lresident_control_on_preflight_failed:
resident_control_native_checkpoint 128
mov rsp, qword ptr [r9 + {control_cpu_native_caller_rsp}]
popfq
pop r12
jmp .Lresident_bridge_unsupported
.Lresident_control_on_busy:
resident_control_native_checkpoint 129
mov rsp, qword ptr [r9 + {control_cpu_native_caller_rsp}]
popfq
pop r12
movabs rax, 0x800000000000000f
ret
.Lresident_control_on_vmxon_failed:
resident_control_native_checkpoint 130
mov r11, qword ptr [r9 + {control_cpu_on_original_cr4}]
mov cr4, r11
mov qword ptr [r9 + {control_cpu_phase}], 2
mov rsp, qword ptr [r9 + {control_cpu_native_caller_rsp}]
popfq
pop r12
movabs rax, 0x800000000000000f
ret
.Lresident_control_on_root_failed:
resident_control_native_checkpoint 131
.Lresident_control_on_root_cleanup:
lock btr qword ptr [r10 + {event_control_rearm_mask}], r8
vmclear qword ptr [r9 + {control_cpu_vmcs_region}]
ja .Lresident_control_on_vmcs_preserved
mov qword ptr [r9 + {control_cpu_stage}], 134
lock bts qword ptr [r10 + {event_control_failed_mask}], r8
.Lresident_control_on_vmcs_preserved:
vmxoff
.Lresident_control_on_native_failed:
mov r11, qword ptr [r9 + {control_cpu_on_original_cr4}]
mov cr4, r11
mov qword ptr [r9 + {control_cpu_phase}], 2
mov rsp, qword ptr [r9 + {control_cpu_native_caller_rsp}]
popfq
pop r12
movabs rax, 0x8000000000000007
ret
.Lresident_control_on_entry_failed:
// VM-entry failure loads HOST_RIP/CR3/RSP; only an armed activation may return natively.
mov rsi, rcx
imul rsi, {control_cpu_state_size}
add rsi, rdi
add rsi, {event_control_cpu_states}
cmp qword ptr [rsi + {control_cpu_phase}], 3
jne .Lresident_dispatch_unsupported
mov qword ptr [rsi + {control_cpu_on_failure_reason}], r11
mov eax, {exit_qualification}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_last_qualification}], r11
mov qword ptr [rsi + {control_cpu_on_failure_qualification}], r11
mov qword ptr [rsi + {control_cpu_stage}], 133
lock btr qword ptr [rdi + {event_control_rearm_mask}], rcx
mov r13, rsi
mov r14, rcx
mov r15, rdi
// Copy the immutable root PML4, then borrow only the native code's PML4 entry.
mov rdi, qword ptr [r13 + {control_cpu_native_storage_physical}]
add rdi, {native_recovery_pml4}
mov rbx, rdi
mov rsi, qword ptr [r12 + {b_expected_host_cr3}]
mov rdx, {host_page_address_mask}
and rsi, rdx
mov ecx, 512
rep movsq
lea rax, [rip + .Lresident_control_on_native_restore]
lea rdx, [rip + matrixhv_resident_set_variable]
sub rax, rdx
add rax, qword ptr [r15 + {event_runtime_set_variable}]
mov rcx, rax
shr rcx, 39
and ecx, 0x1ff
mov rsi, qword ptr [r13 + {control_cpu_on_native_cr3}]
mov rdx, {host_page_address_mask}
and rsi, rdx
mov rdx, qword ptr [rsi + rcx * 8]
mov qword ptr [rbx + rcx * 8], rdx
vmclear qword ptr [r13 + {control_cpu_vmcs_region}]
ja .Lresident_control_on_entry_vmcs_preserved
mov qword ptr [r13 + {control_cpu_stage}], 134
lock bts qword ptr [r15 + {event_control_failed_mask}], r14
.Lresident_control_on_entry_vmcs_preserved:
vmxoff
mov rdx, qword ptr [r13 + {control_cpu_on_native_cr3}]
mov r11, qword ptr [r13 + {control_cpu_on_native_cr0}]
mov cr0, r11
mov r11, qword ptr [r13 + {control_cpu_on_original_cr4}]
// Flush root global translations before entering the native address space.
and r11, -129
mov cr4, r11
mov r11, rbx
mov r8, r14
mov r10, qword ptr [r15 + {event_runtime_context}]
mov r9, r8
imul r9, {control_cpu_state_size}
lea r9, [r10 + r9 + {event_control_cpu_states}]
mov rcx, qword ptr [r13 + {control_cpu_native_storage_runtime}]
add rcx, {native_stack_bytes}
mov rbx, qword ptr [rsp + 24]
mov rbp, qword ptr [rsp + 32]
mov rsi, qword ptr [rsp + 40]
mov rdi, qword ptr [rsp + 48]
mov r12, qword ptr [rsp + 88]
mov r13, qword ptr [rsp + 96]
mov r14, qword ptr [rsp + 104]
mov r15, qword ptr [rsp + 112]
mov rsp, rcx
.Lresident_control_on_recovery_switch:
mov cr3, r11
jmp rax
.Lresident_control_on_native_restore:
// Both CR3s map this runtime instruction; the caller's page tables can now take over.
mov cr3, rdx
mov r11, r8
imul r11, {probe_state_size}
lea r11, [r10 + r11 + {event_control_probe_states}]
sub rsp, 32
mov ax, word ptr [r11 + {probe_guest_gdtr_limit}]
mov word ptr [rsp], ax
mov rax, qword ptr [r11 + {probe_guest_gdtr_base}]
mov qword ptr [rsp + 2], rax
mov ax, word ptr [r11 + {probe_guest_idtr_limit}]
mov word ptr [rsp + 16], ax
mov rax, qword ptr [r11 + {probe_guest_idtr_base}]
mov qword ptr [rsp + 18], rax
lgdt [rsp]
lidt [rsp + 16]
add rsp, 32
movzx eax, word ptr [r11 + {probe_guest_cs_selector}]
push rax
lea rax, [rip + .Lresident_control_on_native_segments]
push rax
retfq
.Lresident_control_on_native_segments:
mov ax, word ptr [r11 + {probe_guest_ss_selector}]
mov ss, ax
mov ax, word ptr [r11 + {probe_guest_es_selector}]
mov es, ax
mov ax, word ptr [r11 + {probe_guest_ds_selector}]
mov ds, ax
mov ax, word ptr [r11 + {probe_guest_fs_selector}]
mov fs, ax
mov ax, word ptr [r11 + {probe_guest_gs_selector}]
mov gs, ax
xor eax, eax
lldt ax
movzx eax, word ptr [r11 + {probe_guest_tr_selector}]
mov rdx, qword ptr [r11 + {probe_guest_gdtr_base}]
and byte ptr [rdx + rax + 5], 0xfd
ltr ax
resident_control_on_restore_msr 0x1d9, 0
resident_control_on_restore_msr 0x277, 1
resident_control_on_restore_msr 0xc0000080, 2
resident_control_on_restore_msr 0xc0000100, 3
resident_control_on_restore_msr 0xc0000101, 4
resident_control_on_restore_msr 0x174, 5
resident_control_on_restore_msr 0x175, 6
resident_control_on_restore_msr 0x176, 7
cmp qword ptr [r9 + {control_cpu_exit_msr_load_count}], 0
je .Lresident_control_on_native_debug_restore
resident_control_on_restore_msr {spec_ctrl_msr}, 8
.Lresident_control_on_native_debug_restore:
mov rax, qword ptr [r9 + {control_cpu_on_native_dr7}]
mov dr7, rax
call .Lresident_control_capture_native
jmp .Lresident_control_on_native_failed
.Lresident_control_capture_native:
// The saved return address is the native instruction following this checkpoint.
// Only the dedicated runtime stack is copied; its complete allocation is mapped.
pushfq
push rax
push rcx
push rdx
push rbx
push rbp
push rsi
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
mov rbx, qword ptr [rsp + 48]
mov rax, qword ptr [rbx + {control_cpu_native_snapshot_count}]
cmp rax, {native_snapshot_capacity}
jae .Lresident_control_capture_native_done
imul rax, {native_snapshot_size}
mov rsi, qword ptr [rbx + {control_cpu_native_storage_runtime}]
lea rdi, [rsi + rax + {native_snapshots_offset}]
mov rax, qword ptr [rbx + {control_cpu_stage}]
mov qword ptr [rdi + {native_snapshot_stage}], rax
mov rax, qword ptr [rsp + 128]
mov qword ptr [rdi + {native_snapshot_rip}], rax
lea rax, [rsp + 136]
mov qword ptr [rdi + {native_snapshot_rsp}], rax
mov rax, qword ptr [rsp + 120]
mov qword ptr [rdi + {native_snapshot_rflags}], rax
mov rax, cr0
mov qword ptr [rdi + {native_snapshot_cr0}], rax
mov rax, cr3
mov qword ptr [rdi + {native_snapshot_cr3}], rax
mov rax, cr4
mov qword ptr [rdi + {native_snapshot_cr4}], rax
mov rax, qword ptr [rbx + {control_cpu_native_caller_rsp}]
mov qword ptr [rdi + {native_snapshot_caller_rsp}], rax
mov qword ptr [rdi + {native_snapshot_stack_limit}], rsi
lea rax, [rsi + {native_stack_bytes}]
mov qword ptr [rdi + {native_snapshot_stack_base}], rax
mov ecx, 15
lea rdx, [rsp + 112]
lea r8, [rdi + {native_snapshot_gprs}]
.Lresident_control_capture_native_register:
mov rax, qword ptr [rdx]
mov qword ptr [r8], rax
sub rdx, 8
add r8, 8
dec ecx
jnz .Lresident_control_capture_native_register
rdtsc
shl rdx, 32
or rax, rdx
mov qword ptr [rdi + {native_snapshot_tsc}], rax
add rdi, {native_snapshot_stack}
mov ecx, {native_stack_bytes} / 8
cld
rep movsq
mfence
inc qword ptr [rbx + {control_cpu_native_snapshot_count}]
.Lresident_control_capture_native_done:
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rbp
pop rbx
pop rdx
pop rcx
pop rax
popfq
ret
.Lresident_set_variable_forward:
jmp qword ptr [rip + matrixhv_resident_original_set_variable]

.Lresident_bridge_invalid_parameter:
movabs rax, 0x8000000000000002
ret
.Lresident_bridge_unsupported:
movabs rax, 0x8000000000000003
ret

.Lresident_bridge_match:
test rcx, rcx
jz .Lresident_bridge_no_match
test rdx, rdx
jz .Lresident_bridge_no_match
mov rax, qword ptr [rdx]
cmp rax, qword ptr [rip + .Lresident_bridge_guid]
jne .Lresident_bridge_no_match
mov rax, qword ptr [rdx + 8]
cmp rax, qword ptr [rip + .Lresident_bridge_guid + 8]
jne .Lresident_bridge_no_match
lea r11, [rip + .Lresident_bridge_name]
xor r10d, r10d
.Lresident_bridge_name_next:
mov ax, word ptr [rcx + r10 * 2]
cmp ax, word ptr [r11 + r10 * 2]
jne .Lresident_bridge_no_match
test ax, ax
jz .Lresident_bridge_matched
inc r10d
cmp r10d, 16
jb .Lresident_bridge_name_next
.Lresident_bridge_no_match:
xor eax, eax
ret
.Lresident_bridge_matched:
mov eax, 1
ret
.Lresident_bridge_apic_id:
mov eax, 0
cpuid
cmp eax, 0x1f
jb .Lresident_bridge_apic_leaf_b
mov eax, 0x1f
xor ecx, ecx
cpuid
test ebx, ebx
jnz .Lresident_bridge_apic_ready
.Lresident_bridge_apic_leaf_b:
mov eax, 0xb
xor ecx, ecx
cpuid
test ebx, ebx
jnz .Lresident_bridge_apic_ready
mov eax, 1
cpuid
mov edx, ebx
shr edx, 24
.Lresident_bridge_apic_ready:
mov eax, edx
ret
// First-fault ownership is shared by every CPU and never waits on a lock.
.Lresident_claim_diagnostic:
xor eax, eax
mov edx, 1
lock cmpxchg qword ptr [r8 + {event_diagnostic_halted}], rdx
ret
// CF reports an active post-EBS display window. Preserve the value and row
// registers used by every painter; expiry retires the shared framebuffer sink.
.Lresident_framebuffer_active:
test r8, r8
jz .Lresident_framebuffer_inactive
cmp qword ptr [r8 + {event_ebs_seen}], 0
je .Lresident_framebuffer_inactive
push rax
push rdx
rdtsc
shl rdx, 32
or rax, rdx
cmp rax, qword ptr [r8 + {event_visual_deadline}]
pop rdx
pop rax
jb .Lresident_framebuffer_enabled
and byte ptr [rip + matrixhv_resident_island_log_backend], 0xfd
mov qword ptr [r8 + {event_visual_base}], 0
.Lresident_framebuffer_inactive:
clc
ret
.Lresident_framebuffer_enabled:
stc
ret
.Lresident_paint_stage:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_framebuffer_sink}
jz .Lresident_paint_stage_done
call .Lresident_framebuffer_active
jnc .Lresident_paint_stage_done
lea eax, [rcx - 1]
cmp eax, 28
ja .Lresident_paint_stage_done
mov r9, qword ptr [r8 + {event_visual_base}]
test r9, r9
jz .Lresident_paint_stage_done
mov r10, qword ptr [r8 + {event_visual_stride_bytes}]
xor edx, edx
cmp eax, 28
jne .Lresident_paint_stage_grid
mov eax, 4
jmp .Lresident_paint_stage_position
.Lresident_paint_stage_grid:
cmp eax, 4
jb .Lresident_paint_stage_position
sub eax, 4
mov edx, 1
cmp eax, 8
jb .Lresident_paint_stage_position
sub eax, 8
mov edx, 2
cmp eax, 8
jb .Lresident_paint_stage_position
sub eax, 8
mov edx, 3
.Lresident_paint_stage_position:
imul edx, edx, {visual_marker_row_step}
imul rdx, r10
add r9, rdx
imul eax, eax, {visual_marker_step_bytes}
add r9, rax
xor edx, edx
.Lresident_paint_stage_row:
mov r11, r9
mov eax, {visual_marker_side}
.Lresident_paint_stage_column:
mov dword ptr [r11], -1
add r11, 4
dec eax
jne .Lresident_paint_stage_column
add r9, r10
inc edx
cmp edx, {visual_marker_side}
jne .Lresident_paint_stage_row
sfence
.Lresident_paint_stage_done:
ret
.Lresident_paint_byte:
push r13
push r14
mov r13d, eax
mov r14d, ecx
xor ecx, ecx
.Lresident_paint_byte_bit:
bt r13d, ecx
jnc .Lresident_paint_byte_next
push rcx
add ecx, r14d
call .Lresident_paint_stage
pop rcx
.Lresident_paint_byte_next:
inc ecx
cmp ecx, 8
jne .Lresident_paint_byte_bit
pop r14
pop r13
ret
.Lresident_serial_state:
.Lresident_diagnostic_snapshot:
cmp byte ptr [rip + matrixhv_resident_island_log_backend], 0
je .Lresident_diagnostic_snapshot_done
push r8
mov r8, qword ptr [r12 + {b_event_context}]
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jnz .Lresident_diagnostic_snapshot_ready
test r8, r8
jz .Lresident_diagnostic_snapshot_restore
cmp qword ptr [r8 + {event_ebs_seen}], 0
je .Lresident_diagnostic_snapshot_restore
.Lresident_diagnostic_snapshot_ready:
mov rax, qword ptr [r12 + {b_post_ebs_count}]
mov ecx, 0
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_reason}]
mov ecx, 1
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_guest_rip}]
mov ecx, 2
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_rcx}]
mov ecx, 3
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_msr_gp_count}]
mov ecx, 4
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_gp_msr}]
mov ecx, 5
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_guest_physical_address}]
mov ecx, 6
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_qualification}]
mov ecx, 7
call .Lresident_diagnostic_emit_value
mov eax, {event_post_ebs_cpu_mask}
call .Lresident_snapshot_event_value
mov ecx, 8
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_processor_number}]
mov ecx, 9
call .Lresident_diagnostic_emit_value
mov eax, {event_host_fault_vector}
call .Lresident_snapshot_event_value
mov ecx, 10
call .Lresident_diagnostic_emit_value
mov eax, {event_host_fault_rip}
call .Lresident_snapshot_event_value
mov ecx, 11
call .Lresident_diagnostic_emit_value
mov eax, {event_host_fault_error_code}
call .Lresident_snapshot_event_value
mov ecx, 12
call .Lresident_diagnostic_emit_value
mov eax, {event_host_fault_address}
call .Lresident_snapshot_event_value
mov ecx, 13
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_diagnostic_samples}]
mov ecx, 14
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_normal_reason}]
mov ecx, 15
call .Lresident_diagnostic_emit_value
mov rax, {guest_cr0}
call .Lresident_snapshot_vmread
mov ecx, 16
call .Lresident_diagnostic_emit_value
mov rax, {guest_cr3}
call .Lresident_snapshot_vmread
cmp rax, -1
je .Lresident_snapshot_cr3_ready
mov qword ptr [r12 + {b_last_guest_cr3}], rax
.Lresident_snapshot_cr3_ready:
mov ecx, 17
call .Lresident_diagnostic_emit_value
mov rax, {guest_cr4}
call .Lresident_snapshot_vmread
mov ecx, 18
call .Lresident_diagnostic_emit_value
mov rax, {guest_efer}
call .Lresident_snapshot_vmread
mov ecx, 19
call .Lresident_diagnostic_emit_value
mov rax, {guest_rflags}
call .Lresident_snapshot_vmread
mov ecx, 20
call .Lresident_diagnostic_emit_value
mov rax, {guest_activity_state}
call .Lresident_snapshot_vmread
mov ecx, 21
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_normal_rip}]
mov ecx, 22
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_efer_write}]
mov ecx, 23
call .Lresident_diagnostic_emit_value
mov rax, {guest_rsp}
call .Lresident_snapshot_vmread
mov ecx, 24
call .Lresident_diagnostic_emit_value
mov rax, {guest_interruptibility_info}
call .Lresident_snapshot_vmread
mov ecx, 25
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_rdmsr_count}]
mov ecx, 26
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_wrmsr_count}]
mov ecx, 27
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_nested_l2_entry_count}]
mov ecx, 28
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_nested_failure_count}]
mov ecx, 29
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_nested_instruction_error}]
mov ecx, 30
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_diagnostic_expired}]
mov ecx, 31
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_instruction_len}]
mov ecx, 32
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_host_cr3}]
mov ecx, 33
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_rax}]
mov ecx, 34
call .Lresident_diagnostic_emit_value
mov rax, qword ptr [r12 + {b_last_rdx}]
mov ecx, 35
call .Lresident_diagnostic_emit_value
mov al, 0x0a
call .Lresident_serial_char
.Lresident_diagnostic_snapshot_restore:
pop r8
.Lresident_diagnostic_snapshot_done:
ret
.Lresident_snapshot_event_value:
test r8, r8
jz .Lresident_snapshot_event_missing
mov rax, qword ptr [r8 + rax]
ret
.Lresident_snapshot_event_missing:
mov rax, -1
ret
.Lresident_snapshot_vmread:
vmread r11, rax
mov rax, -1
jna .Lresident_snapshot_vmread_done
mov rax, r11
.Lresident_snapshot_vmread_done:
ret
.Lresident_diagnostic_emit_value:
push rax
push rcx
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_framebuffer_sink}
jz .Lresident_diagnostic_emit_serial
test r8, r8
jz .Lresident_diagnostic_emit_serial
call .Lresident_paint_hex
.Lresident_diagnostic_emit_serial:
pop rcx
pop rax
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz .Lresident_diagnostic_emit_done
cmp ecx, 35
ja .Lresident_diagnostic_emit_done
push rax
push rcx
push r8
push r9
push rbx
push r13
push rsi
mov al, 0x20
call .Lresident_serial_char
mov ecx, dword ptr [rsp + 40]
lea rdx, [rip + .Lresident_diagnostic_name_offsets]
movzx eax, word ptr [rdx + rcx * 2]
lea rsi, [rip + .Lresident_diagnostic_names]
add rsi, rax
lea rdx, [rip + .Lresident_diagnostic_name_lengths]
movzx r9d, byte ptr [rdx + rcx]
call .Lresident_serial_write
mov al, 0x3d
call .Lresident_serial_char
mov al, 0x30
call .Lresident_serial_char
mov al, 0x78
call .Lresident_serial_char
mov rax, qword ptr [rsp + 48]
call .Lresident_serial_hex64
pop rsi
pop r13
pop rbx
pop r9
pop r8
pop rcx
pop rax
.Lresident_diagnostic_emit_done:
ret
.Lresident_paint_hex:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_framebuffer_sink}
jz .Lresident_paint_hex_done
call .Lresident_framebuffer_active
jnc .Lresident_paint_hex_done
cmp ecx, {visual_hex_last_row}
ja .Lresident_paint_hex_done
cmp qword ptr [r8 + {event_visual_base}], 0
je .Lresident_paint_hex_done
push rbx
push rdi
push rsi
push r13
push r14
mov rsi, rax
mov edi, ecx
and edi, 15
mov rbx, qword ptr [r8 + {event_visual_stride_bytes}]
mov r13d, ecx
shr r13d, 4
imul r13d, r13d, {visual_hex_column_step_bytes}
and ecx, 15
imul ecx, ecx, {visual_hex_row_step}
add ecx, {visual_hex_y}
imul rcx, rbx
add r13, qword ptr [r8 + {event_visual_base}]
add r13, rcx
xor r14d, r14d
.Lresident_paint_hex_cell:
mov eax, edi
test r14d, r14d
jz .Lresident_paint_hex_glyph
mov eax, 16
cmp r14d, 1
je .Lresident_paint_hex_glyph
mov ecx, 17
sub ecx, r14d
shl ecx, 2
mov rax, rsi
shr rax, cl
and eax, 15
.Lresident_paint_hex_glyph:
imul eax, eax, 5
lea r10, [rip + .Lresident_hex_digits]
add r10, rax
mov r11, r13
xor edx, edx
.Lresident_paint_hex_row:
mov eax, edx
shr eax, 1
movzx r9d, byte ptr [r10 + rax]
xor ecx, ecx
.Lresident_paint_hex_column:
xor eax, eax
cmp ecx, 6
jae .Lresident_paint_hex_pixel
mov eax, ecx
shr eax, 1
neg eax
add eax, 2
bt r9d, eax
sbb eax, eax
.Lresident_paint_hex_pixel:
mov dword ptr [r11 + rcx * 4], eax
inc ecx
cmp ecx, 8
jne .Lresident_paint_hex_column
add r11, rbx
inc edx
cmp edx, 10
jne .Lresident_paint_hex_row
add r13, 32
inc r14d
cmp r14d, 18
jne .Lresident_paint_hex_cell
sfence
pop r14
pop r13
pop rsi
pop rdi
pop rbx
.Lresident_paint_hex_done:
ret
.Lresident_hex_digits:
.byte 7, 5, 5, 5, 7
.byte 2, 6, 2, 2, 7
.byte 7, 1, 7, 4, 7
.byte 7, 1, 7, 1, 7
.byte 5, 5, 7, 1, 1
.byte 7, 4, 7, 1, 7
.byte 7, 4, 7, 5, 7
.byte 7, 1, 2, 2, 2
.byte 7, 5, 7, 5, 7
.byte 7, 5, 7, 1, 7
.byte 7, 5, 7, 5, 5
.byte 6, 5, 6, 5, 6
.byte 7, 4, 4, 4, 7
.byte 6, 5, 5, 5, 6
.byte 7, 4, 7, 4, 7
.byte 7, 4, 7, 4, 4
.byte 0, 0, 0, 0, 0
.Lresident_diagnostic_name_offsets:
.short .Lresident_diagnostic_name_0 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_1 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_2 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_3 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_4 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_5 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_6 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_7 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_8 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_9 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_10 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_11 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_12 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_13 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_14 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_15 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_16 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_17 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_18 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_19 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_20 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_21 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_22 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_23 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_24 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_25 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_26 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_27 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_28 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_29 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_30 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_31 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_32 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_33 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_34 - .Lresident_diagnostic_names
.short .Lresident_diagnostic_name_35 - .Lresident_diagnostic_names
.Lresident_diagnostic_name_lengths:
.byte 5, 6, 3, 3, 12, 11, 3, 13, 8, 3, 10, 8, 10, 8, 13, 13, 3, 9, 3, 4, 6, 8, 10, 10, 3, 16, 5, 5, 10, 15, 12, 7, 3, 8, 3, 3
.Lresident_diagnostic_names:
.Lresident_diagnostic_name_0:
.ascii "exits"
.Lresident_diagnostic_name_1:
.ascii "reason"
.Lresident_diagnostic_name_2:
.ascii "rip"
.Lresident_diagnostic_name_3:
.ascii "rcx"
.Lresident_diagnostic_name_4:
.ascii "msr_gp_count"
.Lresident_diagnostic_name_5:
.ascii "last_gp_msr"
.Lresident_diagnostic_name_6:
.ascii "gpa"
.Lresident_diagnostic_name_7:
.ascii "qualification"
.Lresident_diagnostic_name_8:
.ascii "cpu_mask"
.Lresident_diagnostic_name_9:
.ascii "cpu"
.Lresident_diagnostic_name_10:
.ascii "host_fault"
.Lresident_diagnostic_name_11:
.ascii "host_rip"
.Lresident_diagnostic_name_12:
.ascii "host_error"
.Lresident_diagnostic_name_13:
.ascii "host_cr2"
.Lresident_diagnostic_name_14:
.ascii "timer_samples"
.Lresident_diagnostic_name_15:
.ascii "normal_reason"
.Lresident_diagnostic_name_16:
.ascii "cr0"
.Lresident_diagnostic_name_17:
.ascii "guest_cr3"
.Lresident_diagnostic_name_18:
.ascii "cr4"
.Lresident_diagnostic_name_19:
.ascii "efer"
.Lresident_diagnostic_name_20:
.ascii "rflags"
.Lresident_diagnostic_name_21:
.ascii "activity"
.Lresident_diagnostic_name_22:
.ascii "normal_rip"
.Lresident_diagnostic_name_23:
.ascii "efer_write"
.Lresident_diagnostic_name_24:
.ascii "rsp"
.Lresident_diagnostic_name_25:
.ascii "interruptibility"
.Lresident_diagnostic_name_26:
.ascii "rdmsr"
.Lresident_diagnostic_name_27:
.ascii "wrmsr"
.Lresident_diagnostic_name_28:
.ascii "l2_entries"
.Lresident_diagnostic_name_29:
.ascii "nested_failures"
.Lresident_diagnostic_name_30:
.ascii "nested_error"
.Lresident_diagnostic_name_31:
.ascii "expired"
.Lresident_diagnostic_name_32:
.ascii "len"
.Lresident_diagnostic_name_33:
.ascii "host_cr3"
.Lresident_diagnostic_name_34:
.ascii "rax"
.Lresident_diagnostic_name_35:
.ascii "rdx"
.Lresident_serial_write:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz .Lresident_serial_write_done
test r9d, r9d
jz .Lresident_serial_write_done
lodsb
call .Lresident_serial_char
dec r9d
jmp .Lresident_serial_write
.Lresident_serial_write_done:
ret
.Lresident_serial_char:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz .Lresident_serial_char_done
mov r10b, al
call .Lresident_serial_acquire
mov dx, {serial_status_port}
mov ecx, {serial_wait_limit}
.Lresident_serial_wait:
in al, dx
test al, {serial_transmit_empty}
jnz .Lresident_serial_ready
dec ecx
jnz .Lresident_serial_wait
cmp r10b, 0x0a
je .Lresident_serial_release
ret
.Lresident_serial_char_done:
ret
.Lresident_serial_ready:
mov dx, {serial_port}
mov al, r10b
out dx, al
cmp r10b, 0x0a
je .Lresident_serial_release
ret
.Lresident_serial_acquire:
mov rcx, qword ptr [r12 + {b_serial_lock}]
test rcx, rcx
jz .Lresident_serial_acquire_done
mov rdx, r12
.Lresident_serial_acquire_retry:
cmp qword ptr [rcx], r12
je .Lresident_serial_acquire_done
xor eax, eax
lock cmpxchg qword ptr [rcx], rdx
je .Lresident_serial_acquire_done
pause
jmp .Lresident_serial_acquire_retry
.Lresident_serial_acquire_done:
ret
.Lresident_serial_release:
mov rcx, qword ptr [r12 + {b_serial_lock}]
test rcx, rcx
jz .Lresident_serial_release_done
cmp qword ptr [rcx], r12
jne .Lresident_serial_release_done
mov qword ptr [rcx], 0
.Lresident_serial_release_done:
ret
.Lresident_serial_hex64:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz .Lresident_serial_hex64_done
mov rbx, rax
mov r13d, 16
.Lresident_serial_hex64_loop:
rol rbx, 4
mov al, bl
and al, 0x0f
cmp al, 9
jbe .Lresident_serial_hex64_digit
add al, 0x37
jmp .Lresident_serial_hex64_emit
.Lresident_serial_hex64_digit:
add al, 0x30
.Lresident_serial_hex64_emit:
call .Lresident_serial_char
dec r13d
jnz .Lresident_serial_hex64_loop
.Lresident_serial_hex64_done:
ret
matrixhv_resident_nested_tables
.Lpost_ebs_exit_message:
.ascii "[MATRIXHV][RESIDENT] HV:POST_EBS_VMEXIT"
.Lpost_ebs_exit_message_end:
.Lpost_va_exit_message:
.ascii "[MATRIXHV][RESIDENT] HV:POST_VA_VMEXIT"
.Lpost_va_exit_message_end:
.Lfirst_start_exit_message:
.ascii "[MATRIXHV][RESIDENT] HV:START_IMAGE_FIRST_EXIT"
.Lfirst_start_exit_message_end:
.Lstart_checkpoint_message:
.ascii "[MATRIXHV][RESIDENT] HV:START_IMAGE_CHECKPOINT_RESUME"
.Lstart_checkpoint_message_end:
.Lstart_returned_message:
.ascii "[MATRIXHV][RESIDENT] HV:START_IMAGE_RETURNED"
.Lstart_returned_message_end:
.Lpost_ebs_stop_message:
.ascii "[MATRIXHV][RESIDENT] HV:POST_EBS_TERMINAL_VMCALL"
.Lpost_ebs_stop_message_end:
.Lunsupported_exit_message:
.ascii "[MATRIXHV][RESIDENT] HV:UNSUPPORTED_EXIT"
.Lunsupported_exit_message_end:
matrixhv_resident_nested_entry_failure_message
.Lhost_cr3_mismatch_message:
.ascii "[MATRIXHV][RESIDENT] HV:HOST_CR3_MISMATCH"
.Lhost_cr3_mismatch_message_end:
.Levent_corrupt_message:
.ascii "[MATRIXHV][RESIDENT] HV:EVENT_CONTEXT_CORRUPT"
.Levent_corrupt_message_end:
.Lvmread_failed_message:
.ascii "[MATRIXHV][RESIDENT] HV:VMREAD_FAILED\r\n"
.Lvmread_failed_message_end:
.Lvmwrite_failed_message:
.ascii "[MATRIXHV][RESIDENT] HV:VMWRITE_FAILED"
.Lvmwrite_failed_message_end:
.Lvmresume_failed_message:
.ascii "[MATRIXHV][RESIDENT] HV:VMRESUME_FAILED error=0x"
.Lvmresume_failed_message_end:
.Lept_test_violation_message:
.ascii "[MATRIXHV][RESIDENT] HV:EPT_VIOLATION_TEST gpa=0x"
.Lept_test_violation_message_end:
.Lept_unexpected_violation_message:
.ascii "[MATRIXHV][RESIDENT] HV:EPT_VIOLATION_UNEXPECTED gpa=0x"
.Lept_unexpected_violation_message_end:
.Lept_violation_rip:
.ascii " rip=0x"
.Lept_violation_rip_end:
.Lept_violation_read:
.ascii " access=read qual=0x"
.Lept_violation_read_end:
matrixhv_resident_nested_messages
.Lstate_reason:
.ascii " reason=0x"
.Lstate_reason_end:
.Lstate_rip:
.ascii " rip=0x"
.Lstate_rip_end:
.Lstate_newline:
.ascii "\r\n"
.Lstate_newline_end:
.globl matrixhv_resident_island_log_backend
matrixhv_resident_island_log_backend:
.byte 0
.balign 8
.globl matrixhv_resident_island_msr_switch_count
matrixhv_resident_island_msr_switch_count:
.quad 0
.globl matrixhv_resident_island_visual_callback
matrixhv_resident_island_visual_callback:
.quad 0
.globl matrixhv_resident_island_event_context
matrixhv_resident_island_event_context:
.quad 0
.balign 8
.globl matrixhv_resident_original_get_variable
matrixhv_resident_original_get_variable:
.quad 0
.globl matrixhv_resident_original_set_variable
matrixhv_resident_original_set_variable:
.quad 0
.globl matrixhv_resident_convert_pointer
matrixhv_resident_convert_pointer:
.quad 0
.globl matrixhv_resident_bridge_context
matrixhv_resident_bridge_context:
.quad 0
.globl matrixhv_resident_runtime_get_variable
matrixhv_resident_runtime_get_variable:
.quad 0
.globl matrixhv_resident_runtime_set_variable
matrixhv_resident_runtime_set_variable:
.quad 0
.Lresident_bridge_guid:
.byte 0x24, 0xe8, 0x30, 0xa8, 0xa4, 0x19, 0xc4, 0x42
.byte 0x91, 0x78, 0x81, 0xee, 0x63, 0xc1, 0x35, 0xcc
.Lresident_bridge_name:
.short 0x004d, 0x0061, 0x0074, 0x0072, 0x0069, 0x0078, 0x0048, 0x0056
.short 0x0043, 0x006f, 0x006e, 0x0074, 0x0072, 0x006f, 0x006c, 0
.globl matrixhv_resident_island_end
matrixhv_resident_ept_cache
matrixhv_resident_eptp_switch
matrixhv_resident_island_end:
.text
