// Resident handlers use R12=ResidentBootContext and the 120-byte GPR frame at
// RSP: RAX, RCX, RDX, RBX, RBP, RSI, RDI, R8..R15; guest RSP stays in VMCS.
// b_* offsets come from the Rust ABI. Scratch GPRs/flags may change; results
// update this frame or VMCS, then jump to resume, exception injection, L1
// reflection or terminal diagnostics. Internal calls balance their stack and
// use no EFI shadow space; only the guarded visual callback uses the EFI ABI.
// SIMD state is untouched here. VMX status flags are consumed before helpers.
.macro matrixhv_island_ept_violation
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
matrixhv_diagnostic_ept_probe
mov r10, qword ptr [r12 + {b_ept_probe_resume_rip}]
mov rax, {guest_rip}
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_dispatch_ept_unexpected:
matrixhv_diagnostic_ept_unexpected
jmp .Lresident_dispatch_halt
.endm

.macro matrixhv_island_cpuid
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
matrixhv_resident_hyperv_cpuid
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
.endm

.macro matrixhv_island_cpuid_standard
.Lresident_dispatch_cpuid_standard:
cmp r8d, 1
jne .Lresident_dispatch_cpuid_advance
resident_telemetry_counter inc, {b_cpuid_leaf1_count}, {b_telemetry_active}
matrixhv_nested_cpuid_feature_base
and r10d, {cpuid_osxsave_clear_mask}
mov rax, {guest_cr4}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11, {cr4_osxsave_mask}
jz .Lresident_dispatch_cpuid_osxsave_ready
or r10d, {cpuid_osxsave_set_mask}
.Lresident_dispatch_cpuid_osxsave_ready:
matrixhv_nested_cpuid_vmx_exposure
matrixhv_hyperv_cpuid_presence_policy
mov qword ptr [rsp + 8], r10
matrixhv_diagnostic_cpuid_leaf1
.Lresident_dispatch_cpuid_advance:
call .Lresident_advance_guest_rip
cmp qword ptr [r12 + {b_nested_l2_active}], 1
je .Lresident_nested_l2_resume_ept
jmp .Lresident_dispatch_resume
.endm

.macro matrixhv_island_vmcall
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
resident_diagnostic_state .Lstart_checkpoint_message, {start_checkpoint_message_len}
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.endm

.macro matrixhv_island_events
.Lresident_dispatch_stop:
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_dispatch_stop_record
cmp qword ptr [rdi + {event_ebs_seen}], 0
jne .Lresident_dispatch_post_ebs_stop
.Lresident_dispatch_stop_record:
mov rax, qword ptr [rsp + 16]
mov qword ptr [r12 + {b_stop_result}], rax
resident_diagnostic_state .Lstart_returned_message, {start_returned_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_post_ebs_stop:
resident_diagnostic_state .Lpost_ebs_stop_message, {post_ebs_stop_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_nested_probe_failed:
resident_diagnostic_state .Lnested_failure_message, {nested_failure_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_unsupported:
mov rax, {unsupported_stop}
mov qword ptr [r12 + {b_stop_result}], rax
resident_diagnostic_state .Lunsupported_exit_message, {unsupported_exit_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_host_cr3_mismatch:
resident_diagnostic_state .Lhost_cr3_mismatch_message, {host_cr3_mismatch_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_event_corrupt:
resident_diagnostic_state .Levent_corrupt_message, {event_corrupt_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_vmread_failed:
resident_diagnostic_message .Lvmread_failed_message, {vmread_failed_message_len}
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
cmp qword ptr [r12 + {b_nested_l2_active}], 1
jne .Lresident_dispatch_inject_gp_vmcs
bt dword ptr [r12 + {b_nested_vmcs12_exception_bitmap}], 13
jc .Lresident_nested_l2_msr_gp
.Lresident_dispatch_inject_gp_vmcs:
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
resident_diagnostic_state .Lvmwrite_failed_message, {vmwrite_failed_message_len}
jmp .Lresident_dispatch_halt
.endm

.macro matrixhv_island_timer_event
matrixhv_island_boot_timer
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
.endm

.macro matrixhv_island_nmi_delivery
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
.endm

.macro matrixhv_island_host_exceptions
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
matrixhv_island_host_fatal
.endm

// VM-exit entry contract: VMCS HOST_RSP points at a boot-context pointer on a 16-byte-aligned root stack. Saves all 15 guest GPRs (120 bytes); r12 identifies the context throughout dispatch. Helpers preserve that frame and either return, resume, reflect to L1, or halt. No Rust or firmware entry is reachable after EBS.
.macro matrixhv_island_dispatch
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
matrixhv_island_control_rearm
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
matrixhv_island_first_exit_visual
cmp qword ptr [r12 + {b_nested_l2_active}], 1
je .Lresident_nested_l2_route
matrixhv_resident_nested_l1_msr_rearm
matrixhv_island_event_observation
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
matrixhv_island_cache_flush
matrixhv_resident_nested_reflection
matrixhv_island_ept_violation
matrixhv_resident_nested_handlers
matrixhv_island_cpuid
matrixhv_island_observation
matrixhv_island_cpuid_standard
matrixhv_resident_msr_access
matrixhv_island_vmcall
matrixhv_island_requests
matrixhv_island_events
matrixhv_island_timer_event
matrixhv_island_sampling
.Lresident_dispatch_resume:
cmp qword ptr [r12 + {b_nested_l2_active}], 1
jne .Lresident_dispatch_resume_l1
call .Lresident_nested_restore_internal_msr_entry
jmp .Lresident_nested_l2_resume
.Lresident_dispatch_resume_l1:
call .Lresident_watchdog_handler_returned
call .Lresident_sync_ept_cache
call .Lresident_deliver_pending_nmi
call .Lresident_reload_diagnostic_timer
call .Lresident_sample_framebuffer_on_exit
call .Lresident_profile_exit_handler
call .Lresident_watchdog_resuming
call .Lresident_nested_eptp_sync_enter
call .Lresident_nested_prepare_full_msr_entry
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
call .Lresident_nested_restore_root_spec_ctrl
matrixhv_island_control_resume_recovery
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
matrixhv_diagnostic_vmresume_failure
jmp .Lresident_dispatch_halt
// Separate emulated VMCS access, entry, EPT invalidation, and other exit costs.
matrixhv_island_profile
matrixhv_island_halt_observation
.Lresident_dispatch_halt_now:
cli
.Lresident_dispatch_halt_loop:
hlt
jmp .Lresident_dispatch_halt_loop
.endm

// CR0/CR4 and VPID contract: r12 is the boot context; rsp addresses the saved guest GPR frame. Writes hardware state and read shadows together, commits EFER/entry mode, then retires translations. Scratch GPRs and flags are clobbered; successful writes advance RIP and resume, failures use common dispatch errors. The TLB helper balances a 16-byte descriptor on the stack and preserves the guest frame.
.macro matrixhv_island_cr_access
.Lresident_ap_cr_access:
    mov r11, [r12 + {b_last_qualification}]
    test r11d, 0x30
    jnz .Lresident_dispatch_unsupported
    mov eax, r11d
    shr eax, 8
    and eax, 15
    cmp eax, 4
    je .Lap_cr_source_rsp
    lea rdx, [rip + .Lap_gpr_offsets]
    movzx eax, byte ptr [rdx + rax]
    mov r10, [rsp + rax]
    jmp .Lap_cr_value
.Lap_cr_source_rsp:
    mov rax, {guest_rsp}
    vmread r10, rax
    jc .Lresident_dispatch_vmread_failed
    jz .Lresident_dispatch_vmread_failed
.Lap_cr_value:
    and r11d, 15
    cmp r11d, 0
    je .Lap_write_cr0
    cmp r11d, 4
    jne .Lresident_dispatch_unsupported
    mov [r12 + {b_nested_l1_cr4}], r10
    mov rax, {cr4_read_shadow}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    or r10, 0x2000
    mov rax, {guest_cr4}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    jmp .Lap_cr_done
// Unrestricted guest allows PE/PG to clear; NE and VMXE remain set in the hardware state.
.Lap_write_cr0:
    mov rax, {cr0_read_shadow}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    or r10, 0x20
    mov rax, {guest_cr0}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    mov rax, {guest_efer}
    vmread r11, rax
    jc .Lresident_dispatch_vmread_failed
    jz .Lresident_dispatch_vmread_failed
    and r11, -1025
    bt r10, 31
    jnc .Lap_cr_efer
    test r11, 0x100
    jz .Lap_cr_efer
    or r11, 0x400
.Lap_cr_efer:
    vmwrite rax, r11
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    mov rax, {vm_entry_controls}
    vmread r10, rax
    jc .Lresident_dispatch_vmread_failed
    jz .Lresident_dispatch_vmread_failed
    and r10, -513
    test r11, 0x400
    jz .Lap_cr_entry
    or r10, 0x200
.Lap_cr_entry:
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
.Lap_cr_done:
    call .Lresident_update_dirty_mtrrs
    call .Lap_flush_guest_tlb
    call .Lresident_advance_guest_rip
    jmp .Lresident_dispatch_resume

// VMWRITE does not perform the TLB invalidation of INIT or MOV CR0/CR4.
// Retained VPID translations must not carry firmware mappings into the OS.
.Lap_flush_guest_tlb:
    mov eax, {secondary_vm_exec_control}
    vmread r11, rax
    jna .Lresident_dispatch_vmread_failed
    bt r11d, 5
    jnc .Lap_flush_guest_tlb_done
    mov eax, {virtual_processor_id}
    vmread r11, rax
    jna .Lresident_dispatch_vmread_failed
    sub rsp, 16
    mov qword ptr [rsp], r11
    mov qword ptr [rsp + 8], 0
    mov eax, 1
    invvpid rax, xmmword ptr [rsp]
    lea rsp, [rsp + 16]
    jna .Lresident_dispatch_halt
.Lap_flush_guest_tlb_done:
    ret

.Lap_gpr_offsets:
    .byte 0, 8, 16, 24, 0, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112
.p2align 3
.endm

// XSETBV architectural exit: R12=context, saved ECX/EDX/EAX in dispatcher frame. Validate guest CR4, privilege and selector, temporarily enable root OSXSAVE and restore CR4 before checking CF from guarded execution. Scratch GPRs/flags change; frame/stack remain intact. Success retains the guest XCR0 write and advances RIP/resumes; invalid state injects UD/GP. No direct SIMD/FPU accesses.
.macro matrixhv_resident_xsetbv
.Lresident_dispatch_xsetbv:
resident_telemetry_counter inc, {b_xsetbv_count}, {b_telemetry_active}
mov eax, {guest_cr4}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x40000
jz .Lresident_dispatch_inject_ud
call .Lresident_guest_privilege
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
.endm

// Guarded XSETBV: ECX=index, EDX:EAX=value. Host GP recovery returns CF=1, success returns CF=0; other flags may change. GPRs/frame and the balanced return stack are preserved; success retains architectural XCR0 effects, without directly accessing SIMD/FPU state.
.macro matrixhv_resident_guarded_xsetbv
.Lresident_guarded_xsetbv:
.Lresident_xsetbv_instruction:
xsetbv
clc
ret
.endm

// Access fault recovery: GP entry saves RAX/RDX ahead of error code/RIP. Fixup accepts RAX=fault RIP, returns RAX=recovery RIP or zero and clobbers RDX/flags. Recognize only owner-exported RDMSR/WRMSR/XSETBV instruction labels. Matched faults restore GPRs, discard the error code and IRETQ; unowned faults enter terminal diagnostics. No SIMD or EFI calls.
.macro matrixhv_resident_access_faults
.Lresident_access_fault_return:
stc
ret
.Lresident_access_fault_fixup:
lea rdx, [rip + .Lresident_rdmsr_instruction]
cmp rax, rdx
je .Lresident_access_fault_match
lea rdx, [rip + .Lresident_wrmsr_instruction]
cmp rax, rdx
je .Lresident_access_fault_match
lea rdx, [rip + .Lresident_xsetbv_instruction]
cmp rax, rdx
je .Lresident_access_fault_match
xor eax, eax
ret
.Lresident_access_fault_match:
lea rax, [rip + .Lresident_access_fault_return]
ret
.globl matrixhv_resident_island_gp
matrixhv_resident_island_gp:
push rax
push rdx
// The #GP frame contains an error code before RIP; the two saved registers add 16 bytes.
mov rax, qword ptr [rsp + 24]
call .Lresident_access_fault_fixup
test rax, rax
jz .Lresident_host_gp_fatal
mov qword ptr [rsp + 24], rax
pop rdx
pop rax
add rsp, 8
iretq
matrixhv_island_gp_diagnostic
.endm

// Shared privilege check: R12=context, EAX/R11/flags are scratch. Return CF=0 for real mode or ring zero, CF=1 for virtual-8086/nonzero-CPL callers; VMREAD failure takes common dispatch errors. Stack/R12/SIMD unchanged.
.macro matrixhv_resident_guest_privilege
.Lresident_guest_privilege:
mov rax, {guest_cr0}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 1
jz .Lresident_guest_privilege_ok
mov rax, {guest_rflags}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x20000
jnz .Lresident_guest_privilege_fault
mov rax, {guest_cs_selector}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 3
jnz .Lresident_guest_privilege_fault
.Lresident_guest_privilege_ok:
clc
ret
.Lresident_guest_privilege_fault:
stc
ret
.endm
