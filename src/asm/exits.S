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
call .Lresident_retry_ept_event
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
// SMX is outside the resident L1 contract; GETSEC is not emulated.
and r10d, -65
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

// Private lifecycle and boot commands are reserved for the guest kernel.
// VMCALL exits from non-root mode at every CPL, so hardware cannot enforce this.
.macro resident_private_vmcall code, target
mov r11, \code
cmp rax, r11
jne 991f
call .Lresident_guest_privilege
jc .Lresident_dispatch_inject_gp
jmp \target
991:
.endm

.macro matrixhv_island_vmcall
.Lresident_dispatch_vmcall:
resident_telemetry_counter inc, {b_vmcall_count}, {b_telemetry_active}
mov rax, qword ptr [rsp + 0]
resident_private_vmcall 0x4856415052454144, .Lresident_ap_ready
resident_private_vmcall {start_checkpoint_magic}, .Lresident_dispatch_start_checkpoint
resident_private_vmcall {bridge_probe_vmcall}, .Lresident_dispatch_control_probe
resident_private_vmcall {bridge_off_prepare_vmcall}, .Lresident_dispatch_control_off_prepare
resident_private_vmcall {bridge_off_commit_vmcall}, .Lresident_dispatch_control_off_unexpected
resident_private_vmcall {update_vmcall}, .Lresident_dispatch_update
resident_private_vmcall {stop_magic}, .Lresident_dispatch_stop
mov r11, {nested_probe_failed_magic}
cmp rax, r11
jne .Lresident_dispatch_vmcall_public
cmp qword ptr [r12 + {b_telemetry_probe_active}], 0
je .Lresident_dispatch_inject_gp
resident_private_vmcall {nested_probe_failed_magic}, .Lresident_dispatch_nested_probe_failed
.Lresident_dispatch_vmcall_public:
cmp eax, {vmware_hypervisor_magic}
je .Lresident_dispatch_vmware_hypercall
jmp .Lresident_dispatch_hyperv_hypercall
matrixhv_resident_hyperv_hypercall
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
mov qword ptr [r12 + {b_telemetry_probe_active}], 0
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
cmp qword ptr [r12 + {b_telemetry_probe_active}], 0
je .Lresident_dispatch_inject_gp
resident_diagnostic_state .Lnested_failure_message, {nested_failure_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_unsupported:
mov rax, {unsupported_stop}
mov qword ptr [r12 + {b_stop_result}], rax
resident_diagnostic_state .Lunsupported_exit_message, {unsupported_exit_message_len}
jmp .Lresident_dispatch_halt
.Lresident_dispatch_task_switch_excluded:
mov rax, {unsupported_stop}
mov qword ptr [r12 + {b_stop_result}], rax
lea rsi, [rip + .Ll1_task_switch_excluded_message]
mov r9d, {task_switch_excluded_message_len}
call .Lresident_serial_write
call .Lresident_serial_state
jmp .Lresident_dispatch_halt
.Ll1_task_switch_excluded_message:
.ascii "[MATRIXHV][RESIDENT] HV:L1_CONTRACT_EXCLUDES_HARDWARE_TASK_SWITCH\r\n"
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
mov r10d, 0x8000030d
mov eax, {guest_cr0}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11b, 1
jz .Lresident_dispatch_inject_gp_info_ready
or r10d, 0x800
.Lresident_dispatch_inject_gp_info_ready:
mov eax, {vm_entry_intr_info_field}
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_advance_guest_rip:
mov r10, qword ptr [r12 + {b_last_guest_rip}]
add r10, qword ptr [r12 + {b_last_instruction_len}]
mov eax, {guest_cs_ar_bytes}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x2000
jz .Lresident_advance_guest_rip_legacy
mov eax, {guest_efer}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x400
jnz .Lresident_advance_guest_rip_width_ready
.Lresident_advance_guest_rip_legacy:
// CS.D controls operand/address defaults; sequential EIP remains 32 bits.
mov r10d, r10d
.Lresident_advance_guest_rip_width_ready:
mov rax, {guest_rip}
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
mov eax, {guest_interruptibility_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
and r11d, -4
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {guest_rflags}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov r10d, r11d
and r10d, 0x100
mov eax, {guest_ia32_debugctl}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 2
jz .Lresident_advance_guest_rip_debug_check
xor r10d, r10d
.Lresident_advance_guest_rip_debug_check:
mov eax, {guest_pending_dbg_exceptions}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r10d, r10d
jz .Lresident_advance_guest_rip_debug_ready
bts r11, 14
.Lresident_advance_guest_rip_debug_ready:
mov eax, {guest_pending_dbg_exceptions}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_advance_guest_rip_done:
ret
.Lresident_dispatch_vmwrite_failed:
resident_diagnostic_state .Lvmwrite_failed_message, {vmwrite_failed_message_len}
jmp .Lresident_dispatch_halt
.Lresident_retry_ept_event:
// Qualification bit 12 is defined only when IDT vectoring is invalid.
mov eax, {idt_vectoring_info_field}
vmread r10, rax
jna .Lresident_dispatch_vmread_failed
bt r10d, 31
jc .Lresident_retry_interrupted_event_valid
cmp dword ptr [r12 + {b_last_reason}], {ept_violation_reason}
jne .Lresident_retry_interrupted_event_done
test qword ptr [r12 + {b_last_qualification}], 0x1000
jz .Lresident_retry_interrupted_event_done
mov eax, {pin_based_vm_exec_control}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x20
jz .Lresident_retry_interrupted_event_done
mov eax, {guest_interruptibility_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
bts r11, 3
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_retry_interrupted_event_done
.Lresident_retry_interrupted_event:
mov eax, {idt_vectoring_info_field}
vmread r10, rax
jna .Lresident_dispatch_vmread_failed
bt r10d, 31
jnc .Lresident_retry_interrupted_event_done
.Lresident_retry_interrupted_event_valid:
mov eax, {vm_entry_intr_info_field}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
bt r11d, 31
jc .Lresident_retry_interrupted_event_conflict
and r10d, 0x80000fff
bt r10d, 11
jnc .Lresident_retry_interrupted_event_type
mov eax, {idt_vectoring_error_code}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov eax, {vm_entry_exception_error_code}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_retry_interrupted_event_type:
mov edx, r10d
and edx, 0x700
cmp edx, 0x200
jne .Lresident_retry_interrupted_event_software
mov eax, {guest_interruptibility_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
btr r11, 3
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_retry_interrupted_event_write
.Lresident_retry_interrupted_event_software:
cmp edx, 0x400
jb .Lresident_retry_interrupted_event_write
cmp edx, 0x600
ja .Lresident_retry_interrupted_event_write
mov eax, {exit_instruction_len}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov eax, {vm_entry_instruction_len}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_retry_interrupted_event_write:
mov eax, {vm_entry_intr_info_field}
vmwrite rax, r10
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_retry_interrupted_event_done
.Lresident_retry_interrupted_event_conflict:
// A new exception takes precedence. Intel's exception-class matrix determines
// when delivery of the first exception instead produces #DF or shutdown.
mov edx, r10d
and edx, 0x700
cmp edx, 0x300
jne .Lresident_retry_interrupted_event_done
mov edx, r11d
and edx, 0x700
cmp edx, 0x300
jne .Lresident_retry_interrupted_event_done
mov eax, r10d
and eax, 0xff
cmp eax, 31
ja .Lresident_dispatch_event_corrupt
cmp eax, 8
je .Lresident_retry_interrupted_event_first_double_fault
cmp eax, 14
je .Lresident_retry_interrupted_event_first_page_fault
cmp eax, 0
je .Lresident_retry_interrupted_event_second_contributory
cmp eax, 10
jb .Lresident_retry_interrupted_event_done
cmp eax, 13
ja .Lresident_retry_interrupted_event_done
.Lresident_retry_interrupted_event_second_contributory:
mov eax, r11d
and eax, 0xff
cmp eax, 31
ja .Lresident_dispatch_event_corrupt
cmp eax, 0
je .Lresident_retry_interrupted_event_make_double_fault
cmp eax, 10
jb .Lresident_retry_interrupted_event_done
cmp eax, 13
ja .Lresident_retry_interrupted_event_done
jmp .Lresident_retry_interrupted_event_make_double_fault
.Lresident_retry_interrupted_event_first_page_fault:
mov eax, r11d
and eax, 0xff
cmp eax, 31
ja .Lresident_dispatch_event_corrupt
cmp eax, 14
je .Lresident_retry_interrupted_event_make_double_fault
cmp eax, 0
je .Lresident_retry_interrupted_event_make_double_fault
cmp eax, 10
jb .Lresident_retry_interrupted_event_done
cmp eax, 13
ja .Lresident_retry_interrupted_event_done
.Lresident_retry_interrupted_event_make_double_fault:
mov eax, {vm_entry_exception_error_code}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {guest_cr0}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov r10d, 0x80000308
test r11b, 1
jz .Lresident_retry_interrupted_event_double_fault_ready
or r10d, 0x800
.Lresident_retry_interrupted_event_double_fault_ready:
mov eax, {vm_entry_intr_info_field}
vmwrite rax, r10
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_retry_interrupted_event_done
.Lresident_retry_interrupted_event_first_double_fault:
mov eax, r11d
and eax, 0xff
cmp eax, 14
je .Lresident_retry_interrupted_event_shutdown
cmp eax, 0
je .Lresident_retry_interrupted_event_shutdown
cmp eax, 10
jb .Lresident_retry_interrupted_event_done
cmp eax, 13
ja .Lresident_retry_interrupted_event_done
.Lresident_retry_interrupted_event_shutdown:
mov eax, {vm_entry_intr_info_field}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov eax, {guest_activity_state}
mov r11d, 2
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_retry_interrupted_event_done:
ret
.endm

.macro matrixhv_island_timer_event
matrixhv_island_boot_timer
.Lresident_boot_timer_retry_event:
// A timer exit can interrupt event delivery; retry the undelivered event.
call .Lresident_retry_interrupted_event
jmp .Lresident_dispatch_resume
.endm

.macro matrixhv_island_nmi_delivery
.Lresident_deliver_pending_nmi:
cmp qword ptr [r12 + {b_nmi_pending}], 0
je .Lresident_deliver_nmi_done
cmp qword ptr [r12 + {b_nested_l2_active}], 0
je .Lresident_deliver_nmi_check_event
// VMCS02 may use a control snapshot taken before the host NMI arrived.
// Arm the selected VMCS so its NMI-window exit can reflect the event to L1.
bt qword ptr [r12 + {b_nested_vmcs12_pin_based_control}], 3
jc .Lresident_deliver_nmi_window
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
mov eax, {guest_pending_dbg_exceptions}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x5000
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
call .Lresident_host_arm_nmi_window
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
mov rax, r12
call .Lresident_host_arm_nmi_window
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
.Lresident_host_arm_nmi_window:
// A physical NMI may arrive after the dispatcher's final pending check.
// Arming an exit here also covers the interval immediately before VMRESUME.
cmp qword ptr [rax + {b_root_vmx_active}], 0
je .Lresident_host_arm_nmi_window_inactive
push rcx
push rdx
mov rcx, rax
mov eax, {cpu_based_vm_exec_control}
vmread rdx, rax
jna .Lresident_host_arm_nmi_window_done
bts rdx, 22
vmwrite rax, rdx
jna .Lresident_host_arm_nmi_window_done
cmp qword ptr [rcx + {b_nested_l2_active}], 0
je .Lresident_host_arm_nmi_window_done
mov qword ptr [rcx + {b_nested_vmcs02_control_cache_valid}], 0
mov qword ptr [rcx + {b_nested_vmcs02_control_cache_valid} + 8], 0
.Lresident_host_arm_nmi_window_done:
mov rax, rcx
pop rdx
pop rcx
ret
.Lresident_host_arm_nmi_window_inactive:
ret
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
mov rax, {boot_canary_start}
cmp qword ptr [r12 + {b_canary_start}], rax
jne matrixhv_resident_island_fatal
mov rax, {boot_canary_end}
cmp qword ptr [r12 + {b_canary_end}], rax
jne matrixhv_resident_island_fatal
mov qword ptr [r12 + {b_root_vmx_active}], 1
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
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
call .Lresident_flight_record_exit
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
mov eax, dword ptr [r12 + {b_last_reason}]
and eax, 0xffff
cmp eax, {vmcall_reason}
jne .Lresident_update_l2_checked
mov rax, {update_vmcall}
cmp qword ptr [rsp], rax
jne .Lresident_update_l2_checked
cmp qword ptr [r12 + {b_nested_l2_active}], 0
jne .Lresident_dispatch_update_l2_reject
.Lresident_update_l2_checked:
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
cmp eax, 9
je .Lresident_dispatch_task_switch_excluded
cmp eax, 11
je .Lresident_dispatch_inject_ud
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
// PUSH/MOV preserve the VMRESUME status; capture it before any helper.
pushfq
pop qword ptr [r12 + {b_vmresume_status_flags}]
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
call .Lresident_flight_record_entry_failure
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
mov qword ptr [r12 + {b_flight_frozen}], 1
cli
.Lresident_dispatch_halt_loop:
hlt
jmp .Lresident_dispatch_halt_loop
.endm

// CR0/CR4 and VPID contract: r12 is the boot context; rsp addresses the saved guest GPR frame. Validate architectural transitions against visible control registers and stage legacy PAE PDPTEs before writing guest state. Successful writes commit EFER/entry mode, retire translations and advance RIP; invalid values inject GP without changing state. Scratch GPRs and flags are clobbered. The TLB helper balances a 16-byte descriptor and preserves the guest frame.
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
    mov ebx, r11d
    and ebx, 15
    cmp ebx, 0
    je .Lap_cr_read_state
    cmp ebx, 4
    jne .Lresident_dispatch_unsupported
.Lap_cr_read_state:
    mov eax, {guest_efer}
    vmread r11, rax
    jna .Lresident_dispatch_vmread_failed
    mov eax, {guest_cs_ar_bytes}
    vmread rdx, rax
    jna .Lresident_dispatch_vmread_failed
    test r11d, 0x400
    jz .Lap_cr_source_32
    test edx, 0x2000
    jnz .Lap_cr_source_ready
.Lap_cr_source_32:
    mov r10d, r10d
.Lap_cr_source_ready:
    // Unmasked bits can change without an exit, so a read shadow alone is stale.
    mov eax, {guest_cr0}
    vmread r8, rax
    jna .Lresident_dispatch_vmread_failed
    mov eax, {cr0_guest_host_mask}
    vmread rdi, rax
    jna .Lresident_dispatch_vmread_failed
    mov eax, {cr0_read_shadow}
    vmread rsi, rax
    jna .Lresident_dispatch_vmread_failed
    and rsi, rdi
    not rdi
    and r8, rdi
    or r8, rsi
    mov eax, {guest_cr4}
    vmread r9, rax
    jna .Lresident_dispatch_vmread_failed
    mov eax, {cr4_guest_host_mask}
    vmread rdi, rax
    jna .Lresident_dispatch_vmread_failed
    mov eax, {cr4_read_shadow}
    vmread rsi, rax
    jna .Lresident_dispatch_vmread_failed
    and rsi, rdi
    not rdi
    and r9, rdi
    or r9, rsi
    cmp ebx, 0
    je .Lap_write_cr0
    mov rsi, [r12 + {b_nested_vmx_cr4_fixed1}]
    not rsi
    test r10, rsi
    jnz .Lresident_dispatch_inject_gp
    test r11d, 0x400
    jz .Lap_cr4_paging_ready
    test r10d, 0x20
    jz .Lresident_dispatch_inject_gp
    mov rsi, r9
    xor rsi, r10
    test esi, 0x1000
    jnz .Lresident_dispatch_inject_gp
.Lap_cr4_paging_ready:
    test r10d, 0x20000
    jz .Lap_cr4_pcid_ready
    test r11d, 0x400
    jz .Lresident_dispatch_inject_gp
    test r9d, 0x20000
    jnz .Lap_cr4_pcid_ready
    mov eax, {guest_cr3}
    vmread rsi, rax
    jna .Lresident_dispatch_vmread_failed
    test esi, 0xfff
    jnz .Lresident_dispatch_inject_gp
.Lap_cr4_pcid_ready:
    test r10d, 0x800000
    jz .Lap_cr4_cet_ready
    test r8d, 0x10000
    jz .Lresident_dispatch_inject_gp
.Lap_cr4_cet_ready:
    cmp qword ptr [r12 + {b_nested_active}], 0
    je .Lap_cr4_valid
    mov rsi, [r12 + {b_nested_vmx_cr4_fixed0}]
    mov rdi, r10
    and rdi, rsi
    cmp rdi, rsi
    jne .Lresident_dispatch_inject_gp
.Lap_cr4_valid:
    // Legacy PAE keeps four PDPTE registers outside the architectural CRs.
    test r8d, 0x80000000
    jz .Lap_cr4_commit
    test r10d, 0x20
    jz .Lap_cr4_commit
    test r11d, 0x100
    jnz .Lap_cr4_commit
    mov rsi, r9
    xor rsi, r10
    test esi, 0x1000b0
    jz .Lap_cr4_commit
    call .Lap_reload_pdpte
.Lap_cr4_commit:
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
    mov rsi, r10
    shr rsi, 32
    jnz .Lresident_dispatch_inject_gp
    // Low reserved bits are ignored and ET is permanently set on Intel 64.
    and r10d, 0xe005003f
    or r10d, 0x10
    bt r10d, 31
    jnc .Lap_cr0_paging_disabled
    test r10b, 1
    jz .Lresident_dispatch_inject_gp
    test r11d, 0x100
    jz .Lap_cr0_paging_ready
    test r9d, 0x20
    jz .Lresident_dispatch_inject_gp
    bt r8d, 31
    jc .Lap_cr0_paging_ready
    test edx, 0x2000
    jnz .Lresident_dispatch_inject_gp
    mov eax, {guest_tr_ar_bytes}
    vmread rsi, rax
    jna .Lresident_dispatch_vmread_failed
    and esi, 15
    cmp esi, 1
    je .Lresident_dispatch_inject_gp
    cmp esi, 3
    je .Lresident_dispatch_inject_gp
    jmp .Lap_cr0_paging_ready
.Lap_cr0_paging_disabled:
    test r9d, 0x20000
    jnz .Lresident_dispatch_inject_gp
    test r11d, 0x400
    jz .Lap_cr0_paging_ready
    test edx, 0x2000
    jnz .Lresident_dispatch_inject_gp
.Lap_cr0_paging_ready:
    test r10d, 0x20000000
    jz .Lap_cr0_cache_ready
    test r10d, 0x40000000
    jz .Lresident_dispatch_inject_gp
.Lap_cr0_cache_ready:
    test r9d, 0x800000
    jz .Lap_cr0_cet_ready
    test r10d, 0x10000
    jz .Lresident_dispatch_inject_gp
.Lap_cr0_cet_ready:
    cmp qword ptr [r12 + {b_nested_active}], 0
    je .Lap_cr0_valid
    mov rsi, [r12 + {b_nested_vmx_cr0_fixed0}]
    mov rdi, r10
    and rdi, rsi
    cmp rdi, rsi
    jne .Lresident_dispatch_inject_gp
    mov rsi, [r12 + {b_nested_vmx_cr0_fixed1}]
    not rsi
    test r10, rsi
    jnz .Lresident_dispatch_inject_gp
.Lap_cr0_valid:
    test r10d, 0x80000000
    jz .Lap_cr0_commit
    test r9d, 0x20
    jz .Lap_cr0_commit
    test r11d, 0x100
    jnz .Lap_cr0_commit
    mov rsi, r8
    xor rsi, r10
    test esi, 0xe0000000
    jz .Lap_cr0_commit
    call .Lap_reload_pdpte
.Lap_cr0_commit:
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

// A 32-byte CR3-aligned PDPTE table cannot cross a 4-KiB page. Resolve that
// guest-physical page through EPT01, validate every present PDPTE, then publish
// the staged values. No guest control state changes on a validation fault.
.Lap_reload_pdpte:
    sub rsp, 32
    mov r14, rsp
    push r10
    mov eax, {guest_cr3}
    vmread r11, rax
    jna .Lap_pdpte_vmread_failed
    and r11d, -32
    call .Lresident_ept01_page_is_readable
    test eax, eax
    jz .Lap_pdpte_unmapped
    mov r15, r11
    mov ecx, dword ptr [r12 + {b_nested_physical_address_bits}]
    cmp ecx, 32
    jb .Lap_pdpte_unmapped
    cmp ecx, 52
    ja .Lap_pdpte_unmapped
    mov rsi, -1
    shl rsi, cl
    or rsi, 0x1e6
    xor edi, edi
.Lap_pdpte_stage_next:
    mov r11, qword ptr [r15 + rdi * 8]
    test r11b, 1
    jz .Lap_pdpte_stage_value
    test r11, rsi
    jnz .Lap_pdpte_invalid
.Lap_pdpte_stage_value:
    mov qword ptr [r14 + rdi * 8], r11
    inc edi
    cmp edi, 4
    jb .Lap_pdpte_stage_next
    mov eax, {guest_pdptr0}
    xor edi, edi
.Lap_pdpte_commit_next:
    mov r11, qword ptr [r14 + rdi * 8]
    vmwrite rax, r11
    jna .Lap_pdpte_vmwrite_failed
    add eax, 2
    inc edi
    cmp edi, 4
    jb .Lap_pdpte_commit_next
    pop r10
    add rsp, 32
    ret
.Lap_pdpte_invalid:
    pop r10
    add rsp, 40
    jmp .Lresident_dispatch_inject_gp
.Lap_pdpte_unmapped:
    pop r10
    add rsp, 40
    jmp .Lresident_dispatch_halt
.Lap_pdpte_vmread_failed:
    pop r10
    add rsp, 40
    jmp .Lresident_dispatch_vmread_failed
.Lap_pdpte_vmwrite_failed:
    pop r10
    add rsp, 40
    jmp .Lresident_dispatch_vmwrite_failed

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

// XSETBV architectural exit: R12=context, saved ECX/EDX/EAX in dispatcher frame. Validate guest CR4, privilege and selector, temporarily enable root OSXSAVE and capture guarded CF before restoring CR4. Scratch GPRs/flags change; frame/stack remain intact. Success retains the guest XCR0 write and advances RIP/resumes; invalid state injects UD/GP. No direct SIMD/FPU accesses.
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
sbb r10d, r10d
mov cr4, r11
test r10d, r10d
jnz .Lresident_dispatch_inject_gp
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
// VMX defines CPL from SS.DPL, including unrestricted guest states.
mov rax, {guest_ss_ar_bytes}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x60
jnz .Lresident_guest_privilege_fault
.Lresident_guest_privilege_ok:
clc
ret
.Lresident_guest_privilege_fault:
stc
ret
.endm
