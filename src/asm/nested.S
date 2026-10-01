// These macros expand inside the resident island at their original locations.
// Handlers share the dispatcher register frame: r12 is ResidentBootContext,
// and rsp points to the saved guest GPRs unless a helper saves more registers.
// Keep code, RIP-relative tables, and messages within the copied island.
// Dispatch and reflection clobber scratch GPRs/flags, preserve R12 and SIMD,
// and commit explicit guest results to the frame or VMCS12. Internal helpers
// balance pushes/descriptors before RET; VMX CF/ZF checks precede any helper.
// Transitions select VMCS01/02, restore their MSR lists, and jump to resume,
// L1 reflection, guest VMfail or common VMCS errors. b_* offsets describe the
// per-CPU nested state; translation helpers validate EPT01 before dereferencing.

.macro matrixhv_resident_nested_reflection
.Lresident_nested_l2_route:
// The private diagnostic leaf belongs to L0 even when the caller runs in L2.
// All architectural and Hyper-V CPUID leaves remain under L1's control.
cmp dword ptr [r12 + {b_last_reason}], 10
jne .Lresident_nested_l2_reflect
cmp dword ptr [rsp], {matrixhv_status_leaf}
jne .Lresident_nested_l2_reflect
mov qword ptr [r12 + {b_nested_vmcs02_launched}], 1
jmp .Lresident_dispatch_cpuid
.Lresident_nested_l2_reflect:
call .Lresident_nested_flush_l1_shadow
call .Lresident_nested_capture_native_eptp
mov eax, dword ptr [r12 + {b_last_reason}]
test eax, eax
jne .Lresident_nested_check_nmi_window
bt qword ptr [r12 + {b_nested_vmcs12_pin_based_control}], 3
jc .Lresident_nested_nmi_reflect_ready
mov eax, {exit_intr_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
and r11d, 0x800007ff
cmp r11d, 0x80000202
je .Lresident_dispatch_nmi
jmp .Lresident_nested_nmi_reflect_ready
.Lresident_nested_check_nmi_window:
cmp eax, 8
jne .Lresident_nested_nmi_reflect_ready
bt qword ptr [r12 + {b_nested_vmcs12_primary_control}], 22
jnc .Lresident_dispatch_nmi_window
.Lresident_nested_nmi_reflect_ready:
mov r10, qword ptr [r12 + {b_last_reason}]
test r10d, 0x80000000
jnz .Lresident_nested_l2_failure_dump
mov qword ptr [r12 + {b_nested_vmcs02_launched}], 1
jmp .Lresident_nested_l2_reflect_after_failure_dump
matrixhv_diagnostic_nested_entry_failure
.Lresident_nested_l2_reflect_after_failure_dump:
mov r10, qword ptr [r12 + {b_last_reason}]
mov eax, r10d
and eax, 0xffff
cmp eax, {ept_violation_reason}
jne .Lresident_nested_l2_probe_reflection
call .Lresident_nested_resolve_ept02_violation
test eax, eax
jnz .Lresident_nested_l2_resume_ept
cmp qword ptr [r12 + {b_nested_eptp_write_retry}], 0
je .Lresident_nested_l2_ept_reflect
call .Lresident_nested_eptp_release_sources
jmp .Lresident_nested_l2_resume_ept
.Lresident_nested_l2_ept_reflect:
mov r10, qword ptr [r12 + {b_last_reason}]
jmp .Lresident_nested_l2_reflect_generic
.Lresident_nested_l2_probe_reflection:
cmp eax, {rdmsr_reason}
je .Lresident_nested_l2_msr_read
cmp eax, {wrmsr_reason}
je .Lresident_nested_l2_msr_write
jmp .Lresident_nested_l2_probe_non_msr
.Lresident_nested_l2_msr_read:
xor edx, edx
jmp .Lresident_nested_l2_msr_origin
.Lresident_nested_l2_msr_write:
mov edx, 1
.Lresident_nested_l2_msr_origin:
mov ecx, dword ptr [rsp + 8]
call .Lresident_nested_msr_exit_requested
mov r10, qword ptr [r12 + {b_last_reason}]
test eax, eax
jnz .Lresident_nested_l2_reflect_generic
// An emulated MSR exit consumed the previous entry event. Preserve any fault
// injected by its handler when returning directly to L2.
mov eax, {vm_entry_intr_info_field}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
cmp r10d, {rdmsr_reason}
je .Lresident_dispatch_rdmsr
jmp .Lresident_dispatch_wrmsr
.Lresident_nested_l2_msr_gp:
// Hardware already captured L2 state at the private MSR exit. Reflect the
// emulated fault if L1 intercepts #GP, with the instruction still unretired.
mov qword ptr [r12 + {b_nested_l2_msr_gp_pending}], 1
mov qword ptr [r12 + {b_last_reason}], 0
mov qword ptr [r12 + {b_last_qualification}], 0
mov qword ptr [r12 + {b_last_instruction_len}], 0
xor r10d, r10d
jmp .Lresident_nested_l2_reflect_generic
.Lresident_nested_l2_probe_non_msr:
mov eax, r10d
and eax, 0xffff
cmp eax, {vmfunc_reason}
je .Lresident_nested_vmfunc
cmp qword ptr [r12 + {b_telemetry_probe_active}], 0
je .Lresident_nested_l2_reflect_generic
cmp qword ptr [r12 + {b_nested_l2_exit_count}], 3
jae .Lresident_nested_l2_reflect_generic
cmp eax, {vmcall_reason}
jne .Lresident_dispatch_halt
cmp qword ptr [r12 + {b_nested_l2_exit_count}], 0
je .Lresident_nested_l2_ept_probe_first
cmp qword ptr [r12 + {b_nested_l2_exit_count}], 1
je .Lresident_nested_l2_ept_probe_before_invept
cmp qword ptr [r12 + {b_nested_l2_exit_count}], 2
je .Lresident_nested_l2_ept_probe_after_invept
jmp .Lresident_nested_l2_reflect_generic
.Lresident_nested_l2_ept_probe_first:
mov r11, qword ptr [rsp + 96]
mov qword ptr [r12 + {b_nested_ept_observed_value}], r11
mov rax, {nested_ept_target_marker}
cmp r11, rax
jne .Lresident_dispatch_halt
resident_telemetry_counter inc, {b_nested_ept_probe_count}, {b_telemetry_active}
jmp .Lresident_nested_l2_ept_probe_done
.Lresident_nested_l2_ept_probe_before_invept:
mov r11, qword ptr [rsp + 96]
mov qword ptr [r12 + {b_nested_ept_observed_value_before_invept}], r11
mov rax, {nested_ept_target_marker}
cmp r11, rax
jne .Lresident_dispatch_halt
resident_telemetry_counter inc, {b_nested_ept_probe_count}, {b_telemetry_active}
jmp .Lresident_nested_l2_ept_probe_done
.Lresident_nested_l2_ept_probe_after_invept:
mov r11, qword ptr [rsp + 96]
mov qword ptr [r12 + {b_nested_ept_observed_value_after_invept}], r11
mov rax, {nested_ept_second_target_marker}
cmp r11, rax
jne .Lresident_dispatch_halt
resident_telemetry_counter inc, {b_nested_ept_probe_count}, {b_telemetry_active}
.Lresident_nested_l2_reflect_generic:
.Lresident_nested_l2_ept_probe_done:
mov eax, r10d
and eax, 0xffff
cmp eax, 44
jae .Lresident_nested_l2_exit_count_ready
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_l2_exit_count_ready
inc dword ptr [r12 + {b_nested_reflected_exit_counts} + rax * 4]
.Lresident_nested_l2_exit_count_ready:
resident_telemetry_counter inc, {b_nested_l2_exit_count}, {b_telemetry_active}
resident_telemetry_counter inc, {b_nested_l1_reflection_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_l2_resume_count}], 0
je .Lresident_nested_l2_reflect_resume_counted
resident_telemetry_counter inc, {b_nested_l2_resume_exit_count}, {b_telemetry_active}
.Lresident_nested_l2_reflect_resume_counted:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_l2_reason_recorded
mov qword ptr [r12 + {b_nested_l2_last_exit_reason}], r10
.Lresident_nested_l2_reason_recorded:
mov qword ptr [r12 + {b_nested_vmcs12_exit_reason}], r10
mov r11, qword ptr [r12 + {b_last_instruction_len}]
mov qword ptr [r12 + {b_nested_vmcs12_exit_instruction_len}], r11
mov rax, {exit_instruction_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_exit_instruction_info}], r11
mov rax, {guest_linear_address}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 116 * 8], r11
mov r11, qword ptr [r12 + {b_last_qualification}]
mov eax, r10d
and eax, 0xffff
cmp eax, {vm_entry_failure_msr_loading_reason}
jne .Lresident_nested_l2_qualification_ready
test r10d, 0x80000000
jz .Lresident_nested_l2_qualification_ready
cmp r11, qword ptr [r12 + {b_nested_entry_msr_prefix_count}]
jbe .Lresident_nested_l2_qualification_ready
sub r11, qword ptr [r12 + {b_nested_entry_msr_prefix_count}]
.Lresident_nested_l2_qualification_ready:
mov qword ptr [r12 + {b_nested_vmcs12_exit_qualification}], r11
mov eax, r10d
and eax, 0xffff
cmp eax, {ept_violation_reason}
je .Lresident_nested_l2_capture_guest_physical_address
cmp eax, {ept_misconfiguration_reason}
jne .Lresident_nested_l2_guest_physical_address_ready
.Lresident_nested_l2_capture_guest_physical_address:
mov r11, qword ptr [r12 + {b_last_guest_physical_address}]
mov qword ptr [r12 + {b_nested_vmcs12_guest_physical_address}], r11
.Lresident_nested_l2_guest_physical_address_ready:
mov r11, qword ptr [r12 + {b_last_guest_rip}]
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_l2_rip_recorded
mov qword ptr [r12 + {b_nested_l2_last_exit_rip}], r11
.Lresident_nested_l2_rip_recorded:
mov qword ptr [r12 + {b_nested_vmcs12_guest_rip}], r11
mov rax, {guest_rsp}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_guest_rsp}], r11
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_l2_rsp_recorded
mov qword ptr [r12 + {b_nested_l2_last_exit_rsp}], r11
.Lresident_nested_l2_rsp_recorded:
mov rax, {guest_rflags}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_guest_rflags}], r11
cmp qword ptr [r12 + {b_nested_l2_msr_gp_pending}], 0
je .Lresident_nested_l2_capture_exit_interrupt
mov qword ptr [r12 + {b_nested_l2_msr_gp_pending}], 0
mov r11d, 0x80000b0d
mov qword ptr [r12 + {b_nested_vmcs12_vm_exit_intr_info}], r11
mov qword ptr [r12 + {b_nested_vmcs12_vm_exit_intr_error}], 0
jmp .Lresident_nested_l2_exit_interrupt_ready
.Lresident_nested_l2_capture_exit_interrupt:
mov rax, {exit_intr_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_vm_exit_intr_info}], r11
mov rax, {exit_intr_error_code}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_vm_exit_intr_error}], r11
.Lresident_nested_l2_exit_interrupt_ready:
mov rax, {idt_vectoring_info_field}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_idt_vectoring_info}], r11
mov rax, {idt_vectoring_error_code}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs12_idt_vectoring_error}], r11
call .Lresident_nested_capture_vmcs02_guest_state
mov r10, qword ptr [r12 + {b_nested_vmcs12_exit_reason}]
call .Lresident_nested_complete_vmcs02_msr_exit
mov r10, qword ptr [r12 + {b_nested_vmcs12_exit_reason}]
test r10d, 0x80000000
jnz .Lresident_nested_l2_entry_failure
btr qword ptr [r12 + {b_nested_vmcs12_vm_entry_intr_info}], 31
jmp .Lresident_nested_l2_mark_launched
.Lresident_nested_l2_entry_failure:
cmp qword ptr [r12 + {b_nested_l2_entry_was_resume}], 1
jne .Lresident_nested_l2_launch_state_ready
.Lresident_nested_l2_mark_launched:
mov qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_launched}
.Lresident_nested_l2_launch_state_ready:
// Publish the consumed event before L1 can reuse the shared eVMCS page.
call .Lresident_hyperv_evmcs_store
mov qword ptr [r12 + {b_nested_l2_active}], 0
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
call .Lresident_nested_activate_vmcs01_msr_entry
call .Lresident_nested_restore_l1_host_state
mov rax, {guest_rip}
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rip}]
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
mov rax, {guest_rsp}
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rsp}]
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
mov rax, {guest_rflags}
mov r11, 2
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
mov rax, {guest_interruptibility_info}
xor r11d, r11d
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
mov rax, {vm_entry_intr_info_field}
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
matrixhv_diagnostic_nested_exit
.endm

.macro matrixhv_resident_nested_handlers
.Lresident_nested_msr_exit_requested:
push r14
push r15
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 28
jnc .Lresident_nested_msr_exit_requested_yes
mov r14d, ecx
xor r15d, r15d
cmp ecx, 0x1fff
jbe .Lresident_nested_msr_exit_bitmap_index
sub r14d, 0xc0000000
cmp r14d, 0x1fff
ja .Lresident_nested_msr_exit_requested_yes
mov r15d, 1024
.Lresident_nested_msr_exit_bitmap_index:
test edx, edx
jz .Lresident_nested_msr_exit_bitmap_read
add r15d, 2048
.Lresident_nested_msr_exit_bitmap_read:
mov eax, r14d
shr eax, 5
lea r15d, [r15 + rax * 4]
and r14d, 31
mov r11, qword ptr [r12 + {b_nested_vmcs12_msr_bitmap}]
call .Lresident_ept01_page_is_readable
test eax, eax
jz .Lresident_nested_msr_exit_requested_yes
bt dword ptr [r11 + r15], r14d
setc al
movzx eax, al
jmp .Lresident_nested_msr_exit_requested_done
.Lresident_nested_msr_exit_requested_yes:
mov eax, 1
.Lresident_nested_msr_exit_requested_done:
pop r15
pop r14
ret
.Lresident_nested_read_gpr:
cmp eax, 15
ja .Lresident_dispatch_halt
cmp eax, 4
je .Lresident_nested_read_gpr_rsp
lea rdx, [rip + .Lresident_guest_gpr_offsets]
movzx edx, byte ptr [rdx + rax]
mov r11, qword ptr [r15 + rdx]
ret
.Lresident_nested_read_gpr_rsp:
mov rax, {guest_rsp}
vmread r11, rax
ret
.Lresident_nested_write_gpr:
cmp eax, 15
ja .Lresident_dispatch_halt
cmp eax, 4
je .Lresident_nested_write_gpr_rsp
lea rdx, [rip + .Lresident_guest_gpr_offsets]
movzx edx, byte ptr [rdx + rax]
mov qword ptr [r15 + rdx], r11
ret
.Lresident_nested_write_gpr_rsp:
mov rax, {guest_rsp}
vmwrite rax, r11
ret
.Lresident_nested_decode_memory_operand:
lea r15, [rsp + 8]
mov rax, {exit_instruction_info}
vmread r13, rax
mov r14, qword ptr [r12 + {b_last_qualification}]
mov eax, r13d
shr eax, 7
and eax, 7
cmp eax, 1
je .Lresident_nested_operand_sign_extend_32
test eax, eax
jne .Lresident_nested_operand_base
movsx r14, r14w
jmp .Lresident_nested_operand_base
.Lresident_nested_operand_sign_extend_32:
movsxd r14, r14d
.Lresident_nested_operand_base:
bt r13d, 27
jc .Lresident_nested_operand_index
mov eax, r13d
shr eax, 23
and eax, 15
call .Lresident_nested_read_gpr
add r14, r11
.Lresident_nested_operand_index:
bt r13d, 22
jc .Lresident_nested_operand_truncate
mov eax, r13d
shr eax, 18
and eax, 15
call .Lresident_nested_read_gpr
mov ecx, r13d
and ecx, 3
shl r11, cl
add r14, r11
.Lresident_nested_operand_truncate:
mov eax, r13d
shr eax, 7
and eax, 7
cmp eax, 1
je .Lresident_nested_operand_truncate_32
test eax, eax
jne .Lresident_nested_operand_segment
movzx r14d, r14w
jmp .Lresident_nested_operand_segment
.Lresident_nested_operand_truncate_32:
mov r14d, r14d
.Lresident_nested_operand_segment:
mov eax, r13d
shr eax, 15
and eax, 7
cmp eax, 0
je .Lresident_nested_operand_segment_es
cmp eax, 1
je .Lresident_nested_operand_segment_cs
cmp eax, 2
je .Lresident_nested_operand_segment_ss
cmp eax, 3
je .Lresident_nested_operand_segment_ds
cmp eax, 4
je .Lresident_nested_operand_segment_fs
cmp eax, 5
je .Lresident_nested_operand_segment_gs
jmp .Lresident_dispatch_halt
.Lresident_nested_operand_segment_es:
mov rax, {guest_es_base}
jmp .Lresident_nested_operand_segment_read
.Lresident_nested_operand_segment_cs:
mov rax, {guest_cs_base}
jmp .Lresident_nested_operand_segment_read
.Lresident_nested_operand_segment_ss:
mov rax, {guest_ss_base}
jmp .Lresident_nested_operand_segment_read
.Lresident_nested_operand_segment_ds:
mov rax, {guest_ds_base}
jmp .Lresident_nested_operand_segment_read
.Lresident_nested_operand_segment_fs:
mov rax, {guest_fs_base}
jmp .Lresident_nested_operand_segment_read
.Lresident_nested_operand_segment_gs:
mov rax, {guest_gs_base}
.Lresident_nested_operand_segment_read:
vmread r11, rax
add r14, r11
mov qword ptr [r12 + {b_nested_operand_linear_address}], r14
mov r10, r14
call .Lresident_nested_translate_linear_address
ret
.Lresident_nested_operand_width:
mov eax, {guest_cs_ar_bytes}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov ecx, 4
bt r11d, 13
jnc .Lresident_nested_operand_width_done
mov ecx, 8
.Lresident_nested_operand_width_done:
ret
// Validate every page before writing, including EPT01 permissions. The operand
// scratch area holds at most a 16-byte invalidation descriptor.
.Lresident_nested_prepare_operand_range:
push rdi
push r13
sub rsp, 48
mov qword ptr [rsp], rcx
mov qword ptr [rsp + 8], rdx
mov r10, qword ptr [r12 + {b_nested_operand_linear_address}]
mov qword ptr [rsp + 16], r10
mov eax, r10d
and eax, 4095
mov r13d, 4096
sub r13d, eax
cmp r13, rcx
cmova r13, rcx
mov qword ptr [rsp + 24], r13
call .Lresident_nested_translate_linear_address
jc .Lresident_nested_operand_range_failed
mov r11, r10
mov edx, dword ptr [rsp + 8]
call .Lresident_ept01_page_translate
test eax, eax
jz .Lresident_nested_operand_range_failed
mov qword ptr [rsp + 32], r11
mov rax, qword ptr [rsp]
sub rax, qword ptr [rsp + 24]
mov qword ptr [rsp + 40], rax
jz .Lresident_nested_operand_range_ready
mov r10, qword ptr [rsp + 16]
add r10, qword ptr [rsp + 24]
mov qword ptr [rsp + 16], r10
call .Lresident_nested_translate_linear_address
jc .Lresident_nested_operand_range_failed
mov r11, r10
mov edx, dword ptr [rsp + 8]
call .Lresident_ept01_page_translate
test eax, eax
jz .Lresident_nested_operand_range_failed
.Lresident_nested_operand_range_ready:
mov r10, qword ptr [rsp + 32]
mov r8, qword ptr [rsp + 24]
mov r9, qword ptr [rsp + 40]
add rsp, 48
pop r13
pop rdi
clc
ret
.Lresident_nested_operand_range_failed:
mov r10, qword ptr [rsp + 16]
add rsp, 48
pop r13
pop rdi
stc
ret
.Lresident_nested_read_operand_range:
push rsi
push rdi
mov edx, 1
call .Lresident_nested_prepare_operand_range
jc .Lresident_nested_read_operand_failed
mov rsi, r10
lea rdi, [r12 + {b_nested_operand_data}]
mov qword ptr [rdi], 0
mov qword ptr [rdi + 8], 0
mov rcx, r8
cld
rep movsb
mov rsi, r11
mov rcx, r9
rep movsb
lea r10, [r12 + {b_nested_operand_data}]
pop rdi
pop rsi
clc
ret
.Lresident_nested_read_operand_failed:
pop rdi
pop rsi
stc
ret
.Lresident_nested_write_operand_range:
push rsi
push rdi
push rcx
call .Lresident_nested_eptp_before_root_write
pop rcx
mov edx, 3
call .Lresident_nested_prepare_operand_range
jc .Lresident_nested_write_operand_failed
lea rsi, [r12 + {b_nested_operand_data}]
mov rdi, r10
mov rcx, r8
cld
rep movsb
mov rdi, r11
mov rcx, r9
rep movsb
pop rdi
pop rsi
clc
ret
.Lresident_nested_write_operand_failed:
pop rdi
pop rsi
stc
ret
.Lresident_nested_translate_linear_address:
mov rdi, r10
mov rax, {guest_cr0}
vmread r11, rax
bt r11, 31
jnc .Lresident_nested_translate_identity
mov rdx, {host_page_address_mask}
mov rax, {vm_entry_controls}
vmread r11, rax
bt r11, 9
jnc .Lresident_nested_translate_legacy
mov rax, {guest_cr4}
vmread r11, rax
mov ecx, 39
bt r11, 12
jnc .Lresident_nested_translate_long_root
mov ecx, 48
.Lresident_nested_translate_long_root:
mov rax, {guest_cr3}
vmread r11, rax
and r11, rdx
.Lresident_nested_translate_long_level:
mov rax, rdi
shr rax, cl
and eax, 0x1ff
mov r11, qword ptr [r11 + rax * 8]
test r11b, 1
jz .Lresident_nested_translate_failure
cmp ecx, 30
je .Lresident_nested_translate_long_1g
cmp ecx, 21
je .Lresident_nested_translate_long_2m
cmp ecx, 12
je .Lresident_nested_translate_long_4k
and r11, rdx
sub ecx, 9
jmp .Lresident_nested_translate_long_level
.Lresident_nested_translate_long_1g:
test r11b, 0x80
jz .Lresident_nested_translate_long_next
mov r10, r11
mov rax, 0x000fffffc0000000
and r10, rax
mov eax, edi
and eax, 0x3fffffff
or r10, rax
clc
ret
.Lresident_nested_translate_long_2m:
test r11b, 0x80
jz .Lresident_nested_translate_long_next
mov r10, r11
mov rax, 0x000fffffffe00000
and r10, rax
mov eax, edi
and eax, 0x1fffff
or r10, rax
clc
ret
.Lresident_nested_translate_long_next:
and r11, rdx
sub ecx, 9
jmp .Lresident_nested_translate_long_level
.Lresident_nested_translate_long_4k:
and r11, rdx
mov r10, rdi
and r10d, 0xfff
or r10, r11
clc
ret
.Lresident_nested_translate_legacy:
mov rax, {guest_cr4}
vmread r13, rax
bt r13, 5
jnc .Lresident_nested_translate_legacy_32
mov rax, {guest_cr3}
vmread r11, rax
and r11, -32
mov eax, edi
shr eax, 30
and eax, 3
mov r11, qword ptr [r11 + rax * 8]
test r11b, 1
jz .Lresident_nested_translate_failure
and r11, rdx
mov eax, edi
shr eax, 21
and eax, 0x1ff
mov r11, qword ptr [r11 + rax * 8]
test r11b, 1
jz .Lresident_nested_translate_failure
test r11b, 0x80
jnz .Lresident_nested_translate_long_2m
and r11, rdx
mov eax, edi
shr eax, 12
and eax, 0x1ff
mov r11, qword ptr [r11 + rax * 8]
test r11b, 1
jz .Lresident_nested_translate_failure
jmp .Lresident_nested_translate_long_4k
.Lresident_nested_translate_legacy_32:
mov rax, {guest_cr3}
vmread r11, rax
and r11d, 0xfffff000
mov eax, edi
shr eax, 22
mov r11d, dword ptr [r11 + rax * 4]
test r11b, 1
jz .Lresident_nested_translate_failure
test r11b, 0x80
jz .Lresident_nested_translate_legacy_4k
bt r13, 4
jnc .Lresident_nested_translate_failure
and r11d, 0xffc00000
mov r10d, edi
and r10d, 0x3fffff
or r10, r11
clc
ret
.Lresident_nested_translate_legacy_4k:
and r11d, 0xfffff000
mov eax, edi
shr eax, 12
and eax, 0x3ff
mov r11d, dword ptr [r11 + rax * 4]
test r11b, 1
jz .Lresident_nested_translate_failure
and r11d, 0xfffff000
mov r10d, edi
and r10d, 0xfff
or r10, r11
clc
ret
.Lresident_nested_translate_identity:
mov r10, rdi
clc
ret
.Lresident_nested_translate_failure:
mov r10, rdi
stc
ret
.Lresident_nested_physical_address_is_valid:
test r11, 0xfff
jnz .Lresident_nested_physical_address_invalid
.Lresident_nested_address_width_is_valid:
mov ecx, dword ptr [r12 + {b_nested_physical_address_bits}]
test ecx, ecx
jz .Lresident_nested_physical_address_invalid
cmp ecx, 64
jae .Lresident_nested_physical_address_valid
mov rax, r11
shr rax, cl
test rax, rax
jnz .Lresident_nested_physical_address_invalid
.Lresident_nested_physical_address_valid:
mov eax, 1
ret
.Lresident_nested_physical_address_invalid:
xor eax, eax
ret
.Lresident_nested_resolve_ept02_violation:
mov qword ptr [r12 + {b_nested_eptp_write_retry}], 0
xor r14d, r14d
xor r15d, r15d
mov rax, {guest_physical_address}
vmread r8, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_last_guest_physical_address}], r8
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_ept02_unresolved
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jnc .Lresident_nested_ept02_unresolved
mov r9, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]
mov edi, 1
call .Lresident_nested_translate_ept02
cmp eax, 2
je .Lresident_nested_ept02_misconfigured
test eax, eax
jz .Lresident_nested_ept02_unresolved
mov eax, dword ptr [r12 + {b_last_qualification}]
and eax, 7
cmp qword ptr [r12 + {b_nested_ept02_mbec}], 0
je .Lresident_nested_ept02_access_mask_ready
test eax, 4
jz .Lresident_nested_ept02_access_mask_ready
bt dword ptr [r12 + {b_last_qualification}], 9
jnc .Lresident_nested_ept02_access_mask_ready
xor eax, 0x404
.Lresident_nested_ept02_access_mask_ready:
mov edx, r14d
and edx, eax
cmp edx, eax
jne .Lresident_nested_ept02_unresolved
mov r9, qword ptr [r12 + {b_nested_ept02_pointer}]
mov rdx, {host_page_address_mask}
and r9, rdx
mov rcx, r8
shr rcx, 39
and ecx, 0x1ff
mov r10, qword ptr [r9 + rcx * 8]
test r10, 0x407
jnz .Lresident_nested_ept02_pml4_ready
mov rdx, rcx
call .Lresident_nested_allocate_ept02_table
test r11, r11
jz .Lresident_nested_ept02_recycle
mov r10, r11
or r10, 0x407
mov qword ptr [r9 + rdx * 8], r10
.Lresident_nested_ept02_pml4_ready:
mov r9, r10
mov rdx, {host_page_address_mask}
and r9, rdx
mov rcx, r8
shr rcx, 30
and ecx, 0x1ff
mov r10, qword ptr [r9 + rcx * 8]
test r10, 0x407
jnz .Lresident_nested_ept02_pdpt_ready
mov rdx, rcx
call .Lresident_nested_allocate_ept02_table
test r11, r11
jz .Lresident_nested_ept02_recycle
mov r10, r11
or r10, 0x407
mov qword ptr [r9 + rdx * 8], r10
.Lresident_nested_ept02_pdpt_ready:
test r10b, 0x80
jnz .Lresident_nested_ept02_recycle
mov r9, r10
mov rdx, {host_page_address_mask}
and r9, rdx
mov rcx, r8
shr rcx, 21
and ecx, 0x1ff
mov r10, qword ptr [r9 + rcx * 8]
test r10, 0x407
jnz .Lresident_nested_ept02_pd_ready
test r15b, 0x80
jnz .Lresident_nested_ept02_install_large_leaf
mov rdx, rcx
call .Lresident_nested_allocate_ept02_leaf_table
test r11, r11
jz .Lresident_nested_ept02_recycle
mov r10, r11
or r10, 0x407
mov qword ptr [r9 + rdx * 8], r10
.Lresident_nested_ept02_pd_ready:
test r10b, 0x80
jz .Lresident_nested_ept02_pt_ready
test r15b, 0x80
jnz .Lresident_nested_ept02_install_large_leaf
jmp .Lresident_nested_ept02_recycle
.Lresident_nested_ept02_pt_ready:
mov r9, r10
mov rdx, {host_page_address_mask}
and r9, rdx
mov rcx, r8
shr rcx, 12
and ecx, 0x1ff
and r15d, 0x338
jmp .Lresident_nested_ept02_install_leaf
.Lresident_nested_ept02_install_large_leaf:
and r13, -2097152
.Lresident_nested_ept02_install_leaf:
or r13, r14
or r13, r15
mov rbp, qword ptr [r9 + rcx * 8]
mov qword ptr [r9 + rcx * 8], r13
resident_telemetry_counter inc, {b_nested_ept_composition_count}, {b_telemetry_active}
test ebp, 0x407
jz .Lresident_nested_ept02_installed
resident_telemetry_counter inc, {b_nested_ept02_invalidation_count}, {b_telemetry_active}
call .Lresident_nested_flush_ept02
.Lresident_nested_ept02_installed:
mov eax, 1
ret
.Lresident_nested_ept02_recycle:
resident_telemetry_counter inc, {b_nested_ept02_recycle_count}, {b_telemetry_active}
// Exhausting L0's translation cache is not an EPT12 permission violation.
// INVEPT retires the old translations before the table pages are reused.
call .Lresident_nested_invalidate_ept02
jmp .Lresident_nested_resolve_ept02_violation
.Lresident_nested_ept02_misconfigured:
// L1 may deliberately use W=1/R=0 entries to request an EPT-misconfiguration
// exit. Reflect reason 49 before treating the entry as a table or a mapping.
mov qword ptr [r12 + {b_last_reason}], {ept_misconfiguration_reason}
mov qword ptr [r12 + {b_last_qualification}], 0
xor eax, eax
ret
.Lresident_nested_ept02_unresolved:
mov r10, qword ptr [r12 + {b_last_qualification}]
and r10, -121
mov rax, r14
and eax, 7
shl rax, 3
or r10, rax
mov rax, r14
and eax, 0x400
shr rax, 4
or r10, rax
mov qword ptr [r12 + {b_last_qualification}], r10
xor eax, eax
ret
.macro resident_nested_ept12_permissions
mov ecx, dword ptr [r12 + {b_nested_ept02_mbec}]
shl ecx, 10
or ecx, 7
mov eax, r10d
and eax, ecx
and r14d, eax
// Presence belongs to this entry. Accumulated access rights are evaluated
// only after the walk, so an earlier denial cannot hide a malformed entry.
test eax, eax
jz .Lresident_nested_translate_ept02_failed
and eax, 3
cmp eax, 2
je .Lresident_nested_translate_ept02_misconfigured
.endm
.Lresident_nested_translate_ept02:
mov rbp, r9
xor r14d, r14d
xor r15d, r15d
mov rdx, {host_page_address_mask}
and r9, rdx
mov r14d, 7
cmp qword ptr [r12 + {b_nested_ept02_mbec}], 0
je .Lresident_nested_ept12_mode_ready
or r14d, 0x400
.Lresident_nested_ept12_mode_ready:
call .Lresident_nested_map_ept12_table
test eax, eax
jz .Lresident_nested_translate_ept02_failed
mov rcx, r8
shr rcx, 39
and ecx, 0x1ff
lea rsi, [r9 + rcx * 8]
mov r10, qword ptr [rsi]
resident_nested_ept12_permissions
call .Lresident_nested_track_ept12_access
test eax, eax
jz .Lresident_nested_translate_ept02_failed
mov r9, r10
mov rdx, {host_page_address_mask}
and r9, rdx
call .Lresident_nested_map_ept12_table
test eax, eax
jz .Lresident_nested_translate_ept02_failed
mov rcx, r8
shr rcx, 30
and ecx, 0x1ff
lea rsi, [r9 + rcx * 8]
mov r10, qword ptr [rsi]
resident_nested_ept12_permissions
call .Lresident_nested_track_ept12_access
test eax, eax
jz .Lresident_nested_translate_ept02_failed
test r10b, 0x80
jnz .Lresident_nested_ept12_1g_leaf
mov r9, r10
mov rdx, {host_page_address_mask}
and r9, rdx
call .Lresident_nested_map_ept12_table
test eax, eax
jz .Lresident_nested_translate_ept02_failed
mov rcx, r8
shr rcx, 21
and ecx, 0x1ff
lea rsi, [r9 + rcx * 8]
mov r10, qword ptr [rsi]
resident_nested_ept12_permissions
call .Lresident_nested_track_ept12_access
test eax, eax
jz .Lresident_nested_translate_ept02_failed
test r10b, 0x80
jnz .Lresident_nested_ept12_2m_leaf
mov r9, r10
mov rdx, {host_page_address_mask}
and r9, rdx
call .Lresident_nested_map_ept12_table
test eax, eax
jz .Lresident_nested_translate_ept02_failed
mov rcx, r8
shr rcx, 12
and ecx, 0x1ff
lea rsi, [r9 + rcx * 8]
mov r10, qword ptr [rsi]
resident_nested_ept12_permissions
call .Lresident_nested_track_ept12_access
test eax, eax
jz .Lresident_nested_translate_ept02_failed
mov r13, r10
mov rdx, {host_page_address_mask}
and r13, rdx
mov eax, r8d
and eax, 0xfff
add r13, rax
jmp .Lresident_nested_ept12_translation_ready
.Lresident_nested_ept12_2m_leaf:
mov r15d, 0x80
mov r13, r10
mov rdx, {host_page_address_mask}
and r13, rdx
and r13, -2097152
mov eax, r8d
and eax, 0x1fffff
add r13, rax
jmp .Lresident_nested_ept12_translation_ready
.Lresident_nested_ept12_1g_leaf:
mov r15d, 0x80
mov r13, r10
mov rdx, {host_page_address_mask}
and r13, rdx
and r13, -1073741824
mov eax, r8d
and eax, 0x3fffffff
add r13, rax
.Lresident_nested_ept12_translation_ready:
mov ebx, r10d
and ebx, 0x38
and r13, -4096
// Large composed leaves require uniform permissions and translations in both EPTs.
mov r9, qword ptr [r12 + {b_nested_ept01_pointer}]
mov rdx, {host_page_address_mask}
and r9, rdx
mov rcx, r13
shr rcx, 39
and ecx, 0x1ff
mov r10, qword ptr [r9 + rcx * 8]
mov eax, r10d
and eax, 7
mov ecx, eax
and ecx, 4
shl ecx, 8
or eax, ecx
and r14, rax
test eax, eax
jz .Lresident_nested_translate_ept02_failed
mov r9, r10
and r9, rdx
mov rcx, r13
shr rcx, 30
and ecx, 0x1ff
mov r10, qword ptr [r9 + rcx * 8]
mov eax, r10d
and eax, 7
mov ecx, eax
and ecx, 4
shl ecx, 8
or eax, ecx
and r14, rax
test eax, eax
jz .Lresident_nested_translate_ept02_failed
test r10b, 0x80
jnz .Lresident_nested_ept01_30_leaf
mov r9, r10
and r9, rdx
mov rcx, r13
shr rcx, 21
and ecx, 0x1ff
mov r10, qword ptr [r9 + rcx * 8]
mov eax, r10d
and eax, 7
mov ecx, eax
and ecx, 4
shl ecx, 8
or eax, ecx
and r14, rax
test eax, eax
jz .Lresident_nested_translate_ept02_failed
test r10b, 0x80
jnz .Lresident_nested_ept01_21_leaf
mov r9, r10
and r9, rdx
mov rcx, r13
shr rcx, 12
and ecx, 0x1ff
mov r10, qword ptr [r9 + rcx * 8]
mov eax, r10d
and eax, 7
mov ecx, eax
and ecx, 4
shl ecx, 8
or eax, ecx
and r14, rax
test eax, eax
jz .Lresident_nested_translate_ept02_failed
xor r15d, r15d
mov eax, r13d
and eax, 0xfff
mov r13, r10
and r13, rdx
or r13, rax
jmp .Lresident_nested_ept01_translation_ready
.Lresident_nested_ept01_21_leaf:
mov eax, r13d
and eax, 2097151
mov r13, r10
and r13, rdx
and r13, -2097152
or r13, rax
jmp .Lresident_nested_ept01_translation_ready
.Lresident_nested_ept01_30_leaf:
mov eax, r13d
and eax, 1073741823
mov r13, r10
and r13, rdx
and r13, -1073741824
or r13, rax
jmp .Lresident_nested_ept01_translation_ready
.Lresident_nested_ept01_translation_ready:
test edi, edi
jz .Lresident_nested_ept01_tracking_ready
test byte ptr [r12 + {b_last_qualification}], 2
jz .Lresident_nested_ept01_tracking_ready
bt r10, 55
jnc .Lresident_nested_ept01_tracking_ready
mov qword ptr [r12 + {b_nested_eptp_write_retry}], 1
.Lresident_nested_ept01_tracking_ready:
cmp ebx, 0x30
jne .Lresident_nested_ept02_memory_type_ready
mov eax, r10d
and eax, 0x38
cmp eax, 0x30
jne .Lresident_nested_ept02_memory_type_ready
or r15d, 0x30
.Lresident_nested_ept02_memory_type_ready:
and r13, -4096
test bpl, 0x40
jz .Lresident_nested_translate_ept02_success
// Hardware A/D keeps guest page walks classified as writes. EPT12 tracking is
// maintained in software; clean leaves remain write-protected until first use.
or r15d, 0x300
bt qword ptr [rsi], 9
jc .Lresident_nested_translate_ept02_success
test edi, edi
jz .Lresident_nested_ept02_clean_leaf
test byte ptr [r12 + {b_last_qualification}], 2
jz .Lresident_nested_ept02_clean_leaf
test r14b, 2
jz .Lresident_nested_translate_ept02_success
test r11b, 2
jz .Lresident_nested_ept12_write_denied
lock bts qword ptr [rsi], 9
jmp .Lresident_nested_translate_ept02_success
.Lresident_nested_ept02_clean_leaf:
and r14d, -3
.Lresident_nested_translate_ept02_success:
mov eax, 1
ret
.Lresident_nested_translate_ept02_misconfigured:
mov eax, 2
ret
.Lresident_nested_translate_ept02_failed:
xor eax, eax
ret
.Lresident_nested_track_ept12_access:
test bpl, 0x40
jz .Lresident_nested_ept12_access_ready
test r10d, 0x100
jnz .Lresident_nested_ept12_access_ready
test edi, edi
jz .Lresident_nested_translate_ept02_failed
test r11b, 2
jz .Lresident_nested_ept12_write_denied
lock bts qword ptr [rsi], 8
.Lresident_nested_ept12_access_ready:
mov eax, 1
ret
.Lresident_nested_ept12_write_denied:
bt r11, 55
jnc .Lresident_nested_translate_ept02_failed
mov qword ptr [r12 + {b_nested_eptp_write_retry}], 1
jmp .Lresident_nested_translate_ept02_failed
// EPT12 table pointers belong to L1's physical address space, including its
// root. Return the host table in R9 and effective EPT01 permissions in R11.
// A/D updates must honor write protection on the backing table page.
.Lresident_nested_map_ept12_table:
push r8
mov r8, r9
call .Lresident_nested_translate_eptp_list_address
mov r9, r11
mov r11, r10
test eax, eax
jz .Lresident_nested_map_ept12_done
bt qword ptr [rdx], 55
jnc .Lresident_nested_map_ept12_done
bts r11, 55
.Lresident_nested_map_ept12_done:
pop r8
ret
.Lresident_nested_allocate_ept02_table:
mov rax, qword ptr [r12 + {b_nested_ept02_table_pool_used}]
cmp rax, qword ptr [r12 + {b_nested_ept02_table_pool_pages}]
jae .Lresident_nested_allocate_ept02_table_failed
mov r11, rax
shl r11, 12
add r11, qword ptr [r12 + {b_nested_ept02_table_pool}]
inc qword ptr [r12 + {b_nested_ept02_table_pool_used}]
.Lresident_nested_clear_ept02_table:
mov rdi, r11
xor eax, eax
mov ecx, 512
cld
rep stosq
ret
.Lresident_nested_allocate_ept02_table_failed:
xor r11d, r11d
ret
.Lresident_nested_allocate_ept02_leaf_table:
mov rax, qword ptr [r12 + {b_nested_ept02_table_pool_used}]
cmp rax, qword ptr [r12 + {b_nested_ept02_table_pool_pages}]
jb .Lresident_nested_allocate_ept02_table
call .Lresident_nested_recycle_ept02_leaf_table
test r11, r11
jnz .Lresident_nested_clear_ept02_table
ret
// Only leaf-table allocation can recycle a PT: its ancestors are already
// present, so unlinking a different PT cannot invalidate the caller's path.
// Rotate through pool indices to avoid repeatedly evicting the first region.
.Lresident_nested_recycle_ept02_leaf_table:
push r8
push r9
push rdx
push r13
push r14
push r15
push rsi
push rbp
sub rsp, 32
mov qword ptr [rsp], 0
mov qword ptr [rsp + 8], -1
mov qword ptr [rsp + 16], 0
mov qword ptr [rsp + 24], -1
mov rbp, {host_page_address_mask}
mov r8, qword ptr [r12 + {b_nested_ept02_pointer}]
and r8, rbp
xor r9d, r9d
.Lresident_nested_recycle_ept02_pml4:
mov r13, qword ptr [r8 + r9 * 8]
test r13, 0x407
jz .Lresident_nested_recycle_ept02_next_pml4
and r13, rbp
xor r14d, r14d
.Lresident_nested_recycle_ept02_pdpt:
mov r15, qword ptr [r13 + r14 * 8]
test r15, 0x407
jz .Lresident_nested_recycle_ept02_next_pdpt
test r15b, 0x80
jnz .Lresident_nested_recycle_ept02_next_pdpt
and r15, rbp
xor esi, esi
.Lresident_nested_recycle_ept02_pd:
lea r10, [r15 + rsi * 8]
mov rax, qword ptr [r10]
test rax, 0x407
jz .Lresident_nested_recycle_ept02_next_pd
test al, 0x80
jnz .Lresident_nested_recycle_ept02_next_pd
and rax, rbp
sub rax, qword ptr [r12 + {b_nested_ept02_table_pool}]
shr rax, 12
cmp rax, qword ptr [r12 + {b_nested_ept02_table_pool_pages}]
jae .Lresident_nested_recycle_ept02_next_pd
cmp rax, qword ptr [rsp + 24]
jae .Lresident_nested_recycle_ept02_cursor
mov qword ptr [rsp + 16], r10
mov qword ptr [rsp + 24], rax
.Lresident_nested_recycle_ept02_cursor:
cmp rax, qword ptr [r12 + {b_nested_ept02_eviction_cursor}]
jb .Lresident_nested_recycle_ept02_next_pd
cmp rax, qword ptr [rsp + 8]
jae .Lresident_nested_recycle_ept02_next_pd
mov qword ptr [rsp], r10
mov qword ptr [rsp + 8], rax
cmp rax, qword ptr [r12 + {b_nested_ept02_eviction_cursor}]
je .Lresident_nested_recycle_ept02_select
.Lresident_nested_recycle_ept02_next_pd:
inc esi
cmp esi, 512
jb .Lresident_nested_recycle_ept02_pd
.Lresident_nested_recycle_ept02_next_pdpt:
inc r14d
cmp r14d, 512
jb .Lresident_nested_recycle_ept02_pdpt
.Lresident_nested_recycle_ept02_next_pml4:
inc r9d
cmp r9d, 512
jb .Lresident_nested_recycle_ept02_pml4
.Lresident_nested_recycle_ept02_select:
mov r10, qword ptr [rsp]
mov rax, qword ptr [rsp + 8]
test r10, r10
jnz .Lresident_nested_recycle_ept02_unlink
mov r10, qword ptr [rsp + 16]
mov rax, qword ptr [rsp + 24]
test r10, r10
jz .Lresident_nested_recycle_ept02_missing
.Lresident_nested_recycle_ept02_unlink:
mov r11, qword ptr [r10]
and r11, rbp
mov qword ptr [rsp], r11
mov qword ptr [r10], 0
inc rax
cmp rax, qword ptr [r12 + {b_nested_ept02_table_pool_pages}]
jb .Lresident_nested_recycle_ept02_cursor_ready
xor eax, eax
.Lresident_nested_recycle_ept02_cursor_ready:
mov qword ptr [r12 + {b_nested_ept02_eviction_cursor}], rax
// Retire translations before the caller clears and republishes the PT page.
call .Lresident_nested_flush_ept02
resident_telemetry_counter inc, {b_nested_ept02_invalidation_count}, {b_telemetry_active}
resident_telemetry_counter inc, {b_nested_ept02_table_eviction_count}, {b_telemetry_active}
mov r11, qword ptr [rsp]
jmp .Lresident_nested_recycle_ept02_return
.Lresident_nested_recycle_ept02_missing:
xor r11d, r11d
.Lresident_nested_recycle_ept02_return:
add rsp, 32
pop rbp
pop rsi
pop r15
pop r14
pop r13
pop rdx
pop r9
pop r8
ret
.Lresident_nested_invalidate_ept02:
resident_telemetry_counter inc, {b_nested_ept02_invalidation_count}, {b_telemetry_active}
mov r8, qword ptr [r12 + {b_nested_ept02_pointer}]
mov rdx, {host_page_address_mask}
and r8, rdx
mov rdi, r8
mov ecx, 512
xor eax, eax
cld
rep stosq
// The empty root disconnects every old table. Allocation clears each
// recycled page before publishing it; INVEPT retires cached translations.
mov qword ptr [r12 + {b_nested_ept02_table_pool_used}], 0
.Lresident_nested_flush_ept02:
sub rsp, 16
mov r11, qword ptr [r12 + {b_nested_ept02_pointer}]
mov qword ptr [rsp], r11
mov qword ptr [rsp + 8], 0
mov eax, 1
invept rax, xmmword ptr [rsp]
lea rsp, [rsp + 16]
jna .Lresident_dispatch_halt
resident_telemetry_counter inc, {b_invept_exits}, {b_telemetry_active}
ret
// Re-read both EPT levels before retaining a cached leaf across an L1 invalidation.
// Revoked access and split large pages are removed before the hardware INVEPT.
.Lresident_nested_revalidate_ept02:
cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0
je .Lresident_nested_invalidate_ept02
// Revalidate populated entries instead of discarding a dense working set;
// a root reset would force a new EPT violation for every unchanged mapping.
resident_telemetry_counter inc, {b_nested_ept02_invalidation_count}, {b_telemetry_active}
mov rdi, qword ptr [r12 + {b_nested_ept02_pointer}]
mov rax, {host_page_address_mask}
and rdi, rax
xor r8d, r8d
mov ecx, 39
call .Lresident_nested_revalidate_ept02_table
jmp .Lresident_nested_flush_ept02
.Lresident_nested_revalidate_ept02_table:
sub rsp, 48
mov qword ptr [rsp], rdi
mov qword ptr [rsp + 8], r8
mov qword ptr [rsp + 16], rcx
mov qword ptr [rsp + 24], 0
.Lresident_nested_revalidate_ept02_entry:
mov rax, qword ptr [rsp + 24]
mov rdi, qword ptr [rsp]
// Empty slots dominate sparse EPT trees. Keep the cursor in registers until
// a present entry needs a recursive walk or translation, which clobbers them.
.Lresident_nested_revalidate_ept02_scan:
mov r10, qword ptr [rdi + rax * 8]
test r10, 0x407
jnz .Lresident_nested_revalidate_ept02_present
inc eax
cmp eax, 512
jb .Lresident_nested_revalidate_ept02_scan
jmp .Lresident_nested_revalidate_ept02_done
.Lresident_nested_revalidate_ept02_present:
mov qword ptr [rsp + 24], rax
lea rdi, [rdi + rax * 8]
mov rcx, qword ptr [rsp + 16]
shl rax, cl
mov r8, qword ptr [rsp + 8]
or r8, rax
cmp ecx, 12
je .Lresident_nested_revalidate_ept02_leaf
test r10b, 0x80
jnz .Lresident_nested_revalidate_ept02_leaf
mov rdi, {host_page_address_mask}
and rdi, r10
sub ecx, 9
call .Lresident_nested_revalidate_ept02_table
jmp .Lresident_nested_revalidate_ept02_next
.Lresident_nested_revalidate_ept02_leaf:
mov qword ptr [rsp + 32], rdi
mov r9, qword ptr [r12 + {b_nested_ept12_pointer}]
xor edi, edi
call .Lresident_nested_translate_ept02
cmp eax, 1
jne .Lresident_nested_revalidate_ept02_remove
cmp qword ptr [rsp + 16], 12
je .Lresident_nested_revalidate_ept02_small_leaf
cmp qword ptr [rsp + 16], 21
jne .Lresident_nested_revalidate_ept02_remove
test r15b, 0x80
jz .Lresident_nested_revalidate_ept02_remove
and r13, -2097152
jmp .Lresident_nested_revalidate_ept02_write
.Lresident_nested_revalidate_ept02_small_leaf:
and r15d, 0x338
.Lresident_nested_revalidate_ept02_write:
or r13, r14
or r13, r15
mov rdi, qword ptr [rsp + 32]
cmp qword ptr [rdi], r13
je .Lresident_nested_revalidate_ept02_next
mov qword ptr [rdi], r13
jmp .Lresident_nested_revalidate_ept02_next
.Lresident_nested_revalidate_ept02_remove:
mov rdi, qword ptr [rsp + 32]
mov qword ptr [rdi], 0
.Lresident_nested_revalidate_ept02_next:
inc qword ptr [rsp + 24]
cmp qword ptr [rsp + 24], 512
jne .Lresident_nested_revalidate_ept02_entry
.Lresident_nested_revalidate_ept02_done:
add rsp, 48
ret
matrixhv_ept01_host_mapping_validation
.Lresident_nested_host_msr_list_is_mapped:
test r10d, r10d
jz .Lresident_nested_host_msr_list_is_mapped_success
mov r8, r11
mov r9d, r10d
shl r9, 4
add r9, r8
jc .Lresident_nested_host_msr_list_is_unmapped
dec r9
and r8, -4096
and r9, -4096
.Lresident_nested_host_msr_list_page_loop:
mov r11, r8
call .Lresident_ept01_host_page_is_mapped
test eax, eax
jz .Lresident_nested_host_msr_list_is_unmapped
cmp r8, r9
je .Lresident_nested_host_msr_list_is_mapped_success
add r8, 4096
jmp .Lresident_nested_host_msr_list_page_loop
.Lresident_nested_host_msr_list_is_mapped_success:
mov eax, 1
ret
.Lresident_nested_host_msr_list_is_unmapped:
xor eax, eax
ret
// Capture root-switched and time-sensitive MSRs before restoring host state.
// Other entries are read from the saved guest VMCS or with a guarded RDMSR.
.Lresident_nested_msr_requires_hardware_store:
mov eax, dword ptr [rsi]
cmp eax, {spec_ctrl_msr}
je .Lresident_nested_msr_hardware_store
cmp eax, {kernel_gs_base_msr}
je .Lresident_nested_msr_hardware_store
cmp eax, {tsc_aux_msr}
je .Lresident_nested_msr_hardware_store
cmp eax, {star_msr}
je .Lresident_nested_msr_hardware_store
cmp eax, {lstar_msr}
je .Lresident_nested_msr_hardware_store
cmp eax, {cstar_msr}
je .Lresident_nested_msr_hardware_store
cmp eax, {fmask_msr}
je .Lresident_nested_msr_hardware_store
cmp eax, {tsc_msr}
je .Lresident_nested_msr_hardware_store
xor eax, eax
ret
.Lresident_nested_msr_hardware_store:
mov eax, 1
ret
.Lresident_nested_read_saved_msr:
mov eax, ecx
shr eax, 8
cmp eax, 8
je .Lresident_nested_read_saved_msr_invalid
mov eax, {guest_pat}
cmp ecx, 0x277
je .Lresident_nested_read_saved_msr_vmcs
mov eax, {guest_efer}
cmp ecx, {efer_msr}
je .Lresident_nested_read_saved_msr_vmcs
mov eax, {guest_ia32_debugctl}
cmp ecx, 0x1d9
je .Lresident_nested_read_saved_msr_vmcs
mov eax, {guest_fs_base}
cmp ecx, {fs_base_msr}
je .Lresident_nested_read_saved_msr_vmcs
mov eax, {guest_gs_base}
cmp ecx, {gs_base_msr}
je .Lresident_nested_read_saved_msr_vmcs
mov eax, {guest_sysenter_cs}
cmp ecx, {sysenter_cs_msr}
je .Lresident_nested_read_saved_msr_vmcs
mov eax, {guest_sysenter_esp}
cmp ecx, {sysenter_esp_msr}
je .Lresident_nested_read_saved_msr_vmcs
mov eax, {guest_sysenter_eip}
cmp ecx, {sysenter_eip_msr}
je .Lresident_nested_read_saved_msr_vmcs
call .Lresident_guarded_rdmsr
jc .Lresident_nested_read_saved_msr_done
shl rdx, 32
or rax, rdx
clc
.Lresident_nested_read_saved_msr_done:
ret
.Lresident_nested_read_saved_msr_invalid:
stc
ret
.Lresident_nested_read_saved_msr_vmcs:
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov rax, r11
clc
ret
.Lresident_nested_store_current_vmcs12:
cmp qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jne .Lresident_nested_store_current_vmcs12_done
call .Lresident_nested_materialize_vmcs02_rare_state
matrixhv_hyperv_evmcs_skip_backing_store
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
cmp r11, -1
je .Lresident_nested_store_current_vmcs12_done
push r11
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_dispatch_halt
mov rdi, r11
mov rax, {vmcs12_backing_magic}
mov qword ptr [rdi + {vmcs12_backing_magic_offset}], rax
add rdi, {vmcs12_backing_state_offset}
lea rsi, [r12 + {b_nested_vmcs12_operand}]
mov ecx, {vmcs12_backing_qword_count}
cld
rep movsq
pop r11
.Lresident_nested_store_current_vmcs12_done:
ret
.Lresident_nested_initialize_vmcs12_backing:
call .Lresident_nested_eptp_before_root_write
mov rax, {vmcs12_backing_magic}
cmp qword ptr [r11 + {vmcs12_backing_magic_offset}], rax
je .Lresident_nested_initialize_vmcs12_backing_done
lea rdi, [r11 + {vmcs12_backing_state_offset}]
xor eax, eax
mov ecx, {vmcs12_backing_qword_count}
cld
rep stosq
mov rax, qword ptr [r12 + {b_nested_vmcs12_revision_id}]
mov qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_revision_id_offset}], rax
mov qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_launch_state_offset}], {vmcs12_launch_state_clear}
.Lresident_nested_initialize_vmcs12_backing_mark:
mov rax, {vmcs12_backing_magic}
mov qword ptr [r11 + {vmcs12_backing_magic_offset}], rax
.Lresident_nested_initialize_vmcs12_backing_done:
ret
.Lresident_nested_load_vmcs12_backing:
lea rsi, [r11 + {vmcs12_backing_state_offset}]
lea rdi, [r12 + {b_nested_vmcs12_operand}]
mov ecx, {vmcs12_backing_qword_count}
cld
rep movsq
ret
matrixhv_hyperv_evmcs_handlers
.Lresident_dispatch_vmclear:
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_read
mov ecx, 8
call .Lresident_nested_read_operand_range
jc .Lresident_nested_inject_pf_read
mov r14, qword ptr [r12 + {b_nested_operand_linear_address}]
mov r11, qword ptr [r10]
mov qword ptr [r12 + {b_nested_last_operand}], r11
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_vmclear_invalid_address
cmp r11, qword ptr [r12 + {b_nested_vmxon_region}]
je .Lresident_nested_vmclear_vmxon_pointer
matrixhv_hyperv_evmcs_vmclear_route
.Lresident_nested_vmclear_ordinary:
mov r11, qword ptr [r12 + {b_nested_last_operand}]
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_nested_vmclear_invalid_address
bt dword ptr [r11], 31
jnc .Lresident_nested_vmclear_software
bt qword ptr [r12 + {b_nested_vmx_procbased_ctls2}], 46
jnc .Lresident_nested_vmclear_software
call .Lresident_nested_eptp_before_root_write
push r11
vmclear [rsp]
lea rsp, [rsp + 8]
jna .Lresident_dispatch_halt
// VMCLEAR does not require the region's revision to match.
mov rax, qword ptr [r12 + {b_nested_last_operand}]
cmp rax, qword ptr [r12 + {b_nested_current_vmcs}]
jne .Lresident_nested_succeed
mov qword ptr [r12 + {b_nested_current_vmcs}], -1
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jmp .Lresident_nested_succeed
.Lresident_nested_vmclear_software:
push r11
call .Lresident_nested_materialize_vmcs02_rare_state
pop r11
xor r13d, r13d
mov rax, qword ptr [r12 + {b_nested_last_operand}]
cmp rax, qword ptr [r12 + {b_nested_current_vmcs}]
jne .Lresident_nested_vmclear_not_current
mov r13d, 1
matrixhv_hyperv_evmcs_clear_current
push r11
call .Lresident_nested_store_current_vmcs12
pop r11
.Lresident_nested_vmclear_not_current:
call .Lresident_nested_initialize_vmcs12_backing
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_vmclear_counted
inc qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_vmclear_count_offset}]
.Lresident_nested_vmclear_counted:
mov qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_launch_state_offset}], {vmcs12_launch_state_clear}
vmclear [r12 + {b_nested_vmcs02_region}]
jna .Lresident_dispatch_halt
mov qword ptr [r12 + {b_nested_vmcs02_launched}], 0
mov qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid} + 8], 0
test r13d, r13d
jz .Lresident_nested_succeed
mov rax, qword ptr [r11 + {vmcs12_backing_state_offset} + {vmcs12_vmclear_count_offset}]
mov qword ptr [r12 + {b_nested_vmclear_count}], rax
mov qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_clear}
mov qword ptr [r12 + {b_nested_current_vmcs}], -1
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
call .Lresident_nested_shadow_intercept_reads
jmp .Lresident_nested_succeed
matrixhv_hyperv_evmcs_vmclear
.Lresident_nested_vmclear_invalid_address:
mov r10d, {vmclear_invalid_physical_address_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_vmclear_vmxon_pointer:
mov r10d, {vmclear_vmxon_pointer_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_dispatch_vmlaunch:
resident_telemetry_counter inc, {b_nested_vmlaunch_count}, {b_telemetry_active}
resident_telemetry_counter inc, {b_nested_entry_rejection_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
matrixhv_hyperv_evmcs_launch_selection
.Lresident_nested_vmlaunch_vmcs_ready:
cmp qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jne .Lresident_nested_vmfail_invalid_no_current_vmcs
cmp qword ptr [r12 + {b_nested_current_vmcs}], -1
je .Lresident_nested_vmfail_invalid_no_current_vmcs
mov rax, {guest_interruptibility_info}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 2
jnz .Lresident_nested_entry_mov_ss
cmp qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_clear}
jne .Lresident_nested_vmlaunch_non_clear
call .Lresident_nested_validate_entry
test r10d, r10d
jnz .Lresident_nested_vmfail_with_error
call .Lresident_nested_snapshot_vmcs01_effective_state
resident_telemetry_counter dec, {b_nested_entry_rejection_count}, {b_telemetry_active}
mov qword ptr [r12 + {b_nested_l2_entry_was_resume}], 0
mov qword ptr [r12 + {b_nested_l2_active}], 1
resident_telemetry_counter inc, {b_nested_l2_entry_count}, {b_telemetry_active}
vmptrld [r12 + {b_nested_vmcs02_region}]
jna .Lresident_dispatch_halt
call .Lresident_nested_prepare_ept02
call .Lresident_nested_merge_vmcs02_controls
call .Lresident_nested_sync_vmcs02_guest_state
call .Lresident_nested_activate_vmcs02_ept
mov rax, {guest_rip}
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_rsp}
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_rflags}
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_l2_enter
.Lresident_nested_vmlaunch_non_clear:
mov r10d, {vmlaunch_non_clear_vmcs_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_dispatch_vmptrld:
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_read
mov ecx, 8
call .Lresident_nested_read_operand_range
jc .Lresident_nested_inject_pf_read
mov r14, qword ptr [r12 + {b_nested_operand_linear_address}]
mov r11, qword ptr [r10]
mov qword ptr [r12 + {b_nested_last_operand}], r11
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_vmptrld_invalid_address
cmp r11, qword ptr [r12 + {b_nested_vmxon_region}]
je .Lresident_nested_vmptrld_vmxon_pointer
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_nested_vmptrld_invalid_address
mov edx, dword ptr [r11]
and edx, 0x7fffffff
cmp rdx, qword ptr [r12 + {b_nested_vmcs12_revision_id}]
jne .Lresident_nested_vmptrld_bad_revision
bt dword ptr [r11], 31
jc .Lresident_nested_vmptrld_shadow
mov rax, qword ptr [r12 + {b_nested_last_operand}]
cmp rax, qword ptr [r12 + {b_nested_current_vmcs}]
je .Lresident_nested_vmptrld_state_ready
push r11
call .Lresident_nested_store_current_vmcs12
pop r11
call .Lresident_nested_initialize_vmcs12_backing
call .Lresident_nested_load_vmcs12_backing
.Lresident_nested_vmptrld_state_ready:
mov qword ptr [r12 + {b_nested_vmcs12_operand}], r14
mov rax, qword ptr [r12 + {b_nested_last_operand}]
mov qword ptr [r12 + {b_nested_vmcs12_region}], rax
mov qword ptr [r12 + {b_nested_current_vmcs_hpa}], r11
mov rax, qword ptr [r12 + {b_nested_last_operand}]
mov qword ptr [r12 + {b_nested_current_vmcs}], rax
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
resident_hyperv_evmcs_reset
call .Lresident_nested_shadow_sync
resident_telemetry_counter inc, {b_nested_vmptrld_count}, {b_telemetry_active}
jmp .Lresident_nested_succeed
.Lresident_nested_vmptrld_shadow:
bt qword ptr [r12 + {b_nested_vmx_procbased_ctls2}], 46
jnc .Lresident_nested_vmptrld_bad_revision
push r11
call .Lresident_nested_store_current_vmcs12
pop r11
mov qword ptr [r12 + {b_nested_current_vmcs_hpa}], r11
mov rax, qword ptr [r12 + {b_nested_last_operand}]
mov qword ptr [r12 + {b_nested_current_vmcs}], rax
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 1
resident_hyperv_evmcs_reset
call .Lresident_nested_shadow_intercept_reads
resident_telemetry_counter inc, {b_nested_vmptrld_count}, {b_telemetry_active}
jmp .Lresident_nested_succeed
.Lresident_nested_vmptrld_invalid_address:
mov r10d, {vmptrld_invalid_physical_address_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_vmptrld_vmxon_pointer:
mov r10d, {vmptrld_vmxon_pointer_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_vmptrld_bad_revision:
mov r10d, {vmptrld_incorrect_revision_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_dispatch_vmptrst:
resident_telemetry_counter inc, {b_nested_vmptrst_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_write
mov r10, qword ptr [r12 + {b_nested_operand_linear_address}]
mov qword ptr [r12 + {b_nested_vmptrst_destination}], r10
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
mov qword ptr [r12 + {b_nested_operand_data}], r11
mov qword ptr [r12 + {b_nested_last_stored_pointer}], r11
mov ecx, 8
call .Lresident_nested_write_operand_range
jc .Lresident_nested_inject_pf_write
jmp .Lresident_nested_succeed
.Lresident_dispatch_vmwrite:
resident_telemetry_counter inc, {b_nested_vmwrite_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
resident_hyperv_evmcs_require_ordinary
cmp qword ptr [r12 + {b_nested_current_vmcs}], -1
je .Lresident_nested_vmfail_invalid_no_current_vmcs
mov rax, {exit_instruction_info}
vmread r13, rax
mov eax, r13d
shr eax, 28
and eax, 15
mov r15, rsp
call .Lresident_nested_read_gpr
mov r10, r11
mov qword ptr [r12 + {b_nested_last_vmcs_field}], r10
bt r13d, 10
jnc .Lresident_nested_vmwrite_memory_value
mov eax, r13d
shr eax, 3
and eax, 15
mov r15, rsp
call .Lresident_nested_read_gpr
jmp .Lresident_nested_vmwrite_operands_ready
.Lresident_nested_vmwrite_memory_value:
mov rbx, r10
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_read
call .Lresident_nested_operand_width
call .Lresident_nested_read_operand_range
jc .Lresident_nested_inject_pf_read
mov r11, qword ptr [r10]
mov r10, rbx
.Lresident_nested_vmwrite_operands_ready:
call .Lresident_nested_shadow_field_available
test eax, eax
jz .Lresident_nested_unsupported_vmcs_field
cmp qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jne .Lresident_nested_native_shadow_vmwrite
cmp r10, {vmcs_field_guest_rip}
je .Lresident_nested_vmwrite_guest_rip
cmp r10, {vmcs_field_guest_rsp}
je .Lresident_nested_vmwrite_guest_rsp
cmp r10, {vmcs_field_guest_rflags}
je .Lresident_nested_vmwrite_guest_rflags
cmp r10, {vmcs_field_host_rsp}
je .Lresident_nested_vmwrite_host_rsp
cmp r10, {vmcs_field_host_rip}
je .Lresident_nested_vmwrite_host_rip
cmp r10, {vmcs_field_instruction_error}
je .Lresident_nested_vmwrite_instruction_error
cmp r10, {vmcs_field_exit_reason}
je .Lresident_nested_vmwrite_exit_reason
cmp r10, {vmcs_field_exit_instruction_len}
je .Lresident_nested_vmwrite_exit_instruction_len
cmp r10, {vmcs_field_exit_qualification}
je .Lresident_nested_vmwrite_exit_qualification
mov rdx, r10
mov rax, r10
and rax, 0x6000
cmp rax, 0x2000
jne .Lresident_nested_vmwrite_extended_lookup
and rdx, -2
.Lresident_nested_vmwrite_extended_lookup:
call .Lresident_vmcs12_field_index
cmp eax, {vmcs12_extended_field_count}
jb .Lresident_nested_vmwrite_extended
mov r10d, {vmcs_unsupported_component_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_vmwrite_extended:
push rax
mov eax, r10d
and eax, 0xc00
cmp eax, 0x400
pop rax
jne .Lresident_nested_vmwrite_extended_writable
bt qword ptr [r12 + {b_nested_vmx_misc}], 29
jnc .Lresident_nested_vmwrite_read_only
.Lresident_nested_vmwrite_extended_writable:
call .Lresident_nested_materialize_guest_field
cmp rdx, r10
je .Lresident_nested_vmwrite_extended_full
shl r11, 32
mov rsi, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rax * 8]
mov esi, esi
or r11, rsi
.Lresident_nested_vmwrite_extended_full:
mov esi, r10d
and esi, 0x6000
cmp esi, 0x4000
jne .Lresident_nested_vmwrite_extended_width_ready
mov r11d, r11d
.Lresident_nested_vmwrite_extended_width_ready:
mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rax * 8], r11
jmp .Lresident_nested_succeed
.Lresident_nested_vmwrite_instruction_error:
lea rdi, [r12 + {b_nested_instruction_error}]
jmp .Lresident_nested_vmwrite_exit_dword
.Lresident_nested_vmwrite_exit_reason:
lea rdi, [r12 + {b_nested_vmcs12_exit_reason}]
jmp .Lresident_nested_vmwrite_exit_dword
.Lresident_nested_vmwrite_exit_instruction_len:
lea rdi, [r12 + {b_nested_vmcs12_exit_instruction_len}]
.Lresident_nested_vmwrite_exit_dword:
mov r11d, r11d
jmp .Lresident_nested_vmwrite_exit_field
.Lresident_nested_vmwrite_exit_qualification:
lea rdi, [r12 + {b_nested_vmcs12_exit_qualification}]
.Lresident_nested_vmwrite_exit_field:
bt qword ptr [r12 + {b_nested_vmx_misc}], 29
jnc .Lresident_nested_vmwrite_read_only
mov qword ptr [rdi], r11
jmp .Lresident_nested_succeed
.Lresident_nested_vmwrite_read_only:
mov r10d, {vmwrite_read_only_component_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_vmwrite_guest_rip:
mov qword ptr [r12 + {b_nested_vmcs12_guest_rip}], r11
jmp .Lresident_nested_succeed
.Lresident_nested_vmwrite_guest_rsp:
mov qword ptr [r12 + {b_nested_vmcs12_guest_rsp}], r11
jmp .Lresident_nested_succeed
.Lresident_nested_vmwrite_guest_rflags:
mov qword ptr [r12 + {b_nested_vmcs12_guest_rflags}], r11
jmp .Lresident_nested_succeed
.Lresident_nested_vmwrite_host_rsp:
mov qword ptr [r12 + {b_nested_vmcs12_host_rsp}], r11
mov rax, {vmcs_field_host_rsp}
call .Lresident_nested_shadow_write
jmp .Lresident_nested_succeed
.Lresident_nested_vmwrite_host_rip:
mov qword ptr [r12 + {b_nested_vmcs12_host_rip}], r11
mov rax, {vmcs_field_host_rip}
call .Lresident_nested_shadow_write
jmp .Lresident_nested_succeed

.Lresident_nested_shadow_intercept_reads:
mov rdi, qword ptr [r12 + {b_nested_shadow_vmread_bitmap}]
test rdi, rdi
jz .Lresident_nested_shadow_intercept_done
or byte ptr [rdi + {vmcs_shadow_read_byte_offset}], {vmcs_shadow_read_bypass_mask}
.Lresident_nested_shadow_intercept_done:
ret

.Lresident_nested_shadow_sync:
cmp qword ptr [r12 + {b_nested_shadow_vmcs_region}], 0
je .Lresident_nested_shadow_sync_done
cmp qword ptr [r12 + {b_telemetry_probe_active}], 0
jne .Lresident_nested_shadow_intercept_reads
cmp qword ptr [r12 + {b_nested_probe_complete}], 0
je .Lresident_nested_shadow_intercept_reads
vmptrld [r12 + {b_nested_shadow_vmcs_region}]
jna .Lresident_dispatch_halt
mov rax, {host_rsp}
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rsp}]
vmwrite rax, r11
jna .Lresident_dispatch_halt
mov rax, {host_rip}
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rip}]
vmwrite rax, r11
jna .Lresident_dispatch_halt
vmclear [r12 + {b_nested_shadow_vmcs_region}]
jna .Lresident_dispatch_halt
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
mov rdi, qword ptr [r12 + {b_nested_shadow_vmread_bitmap}]
and byte ptr [rdi + {vmcs_shadow_read_byte_offset}], {vmcs_shadow_read_trap_mask}
.Lresident_nested_shadow_sync_done:
ret

.Lresident_nested_shadow_write:
cmp qword ptr [r12 + {b_nested_shadow_vmcs_region}], 0
je .Lresident_nested_shadow_write_done
cmp qword ptr [r12 + {b_telemetry_probe_active}], 0
jne .Lresident_nested_shadow_write_done
cmp qword ptr [r12 + {b_nested_probe_complete}], 0
je .Lresident_nested_shadow_write_done
vmptrld [r12 + {b_nested_shadow_vmcs_region}]
jna .Lresident_dispatch_halt
vmwrite rax, r11
jna .Lresident_dispatch_halt
vmclear [r12 + {b_nested_shadow_vmcs_region}]
jna .Lresident_dispatch_halt
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
.Lresident_nested_shadow_write_done:
ret
.Lresident_nested_translate_current_vmcs:
push r10
push r11
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_dispatch_halt
mov qword ptr [r12 + {b_nested_current_vmcs_hpa}], r11
pop r11
pop r10
ret
.Lresident_nested_native_shadow_vmwrite:
call .Lresident_nested_eptp_before_root_write
call .Lresident_nested_translate_current_vmcs
vmptrld [r12 + {b_nested_current_vmcs_hpa}]
jna .Lresident_dispatch_halt
// Native access preserves the implementation-defined shadow VMCS layout.
vmwrite r10, r11
pushfq
pop rbx
jmp .Lresident_nested_native_shadow_complete
.Lresident_nested_native_shadow_vmread:
call .Lresident_nested_eptp_before_root_write
call .Lresident_nested_translate_current_vmcs
vmptrld [r12 + {b_nested_current_vmcs_hpa}]
jna .Lresident_dispatch_halt
vmread r11, r10
pushfq
pop rbx
.Lresident_nested_native_shadow_complete:
vmclear [r12 + {b_nested_current_vmcs_hpa}]
jna .Lresident_dispatch_halt
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
test bl, 0x41
jnz .Lresident_nested_native_shadow_failed
cmp dword ptr [r12 + {b_last_reason}], {vmread_reason}
je .Lresident_nested_vmread_value
jmp .Lresident_nested_succeed
.Lresident_nested_native_shadow_failed:
mov rax, {guest_rflags}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
and r11, {vmx_status_flags_clear_mask}
and ebx, 0x41
or r11, rbx
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume

// Flush hardware-cached writes before L1 can move or inspect its shadow region.
.Lresident_nested_flush_l1_shadow:
test dword ptr [r12 + {b_last_reason}], 0x80000000
jnz .Lresident_nested_flush_l1_shadow_done
bt dword ptr [r12 + {b_nested_last_merged_secondary_controls}], 14
jnc .Lresident_nested_flush_l1_shadow_done
cmp qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 23 * 8], -1
je .Lresident_nested_flush_l1_shadow_done
vmclear [r12 + {b_nested_vmcs12_extended_fields} + 23 * 8]
jna .Lresident_dispatch_halt
.Lresident_nested_flush_l1_shadow_done:
ret
.Lresident_nested_shadow_field_available:
mov rax, r10
and rax, -2
cmp rax, 0x2026
je .Lresident_nested_shadow_field_check
cmp rax, 0x2028
je .Lresident_nested_shadow_field_check
mov eax, 1
ret
.Lresident_nested_shadow_field_check:
bt qword ptr [r12 + {b_nested_vmx_procbased_ctls2}], 46
setc al
movzx eax, al
ret
.Lresident_nested_unsupported_vmcs_field:
mov r10d, {vmcs_unsupported_component_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_dispatch_vmread:
resident_telemetry_counter inc, {b_nested_vmread_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
resident_hyperv_evmcs_require_ordinary
cmp qword ptr [r12 + {b_nested_current_vmcs}], -1
je .Lresident_nested_vmfail_invalid_no_current_vmcs
mov rax, {exit_instruction_info}
vmread r13, rax
mov eax, r13d
shr eax, 28
and eax, 15
mov r15, rsp
call .Lresident_nested_read_gpr
mov r10, r11
mov qword ptr [r12 + {b_nested_last_vmcs_field}], r10
call .Lresident_nested_shadow_field_available
test eax, eax
jz .Lresident_nested_unsupported_vmcs_field
cmp qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jne .Lresident_nested_native_shadow_vmread
cmp r10, {vmcs_field_guest_rip}
je .Lresident_nested_vmread_guest_rip
cmp r10, {vmcs_field_guest_rsp}
je .Lresident_nested_vmread_guest_rsp
cmp r10, {vmcs_field_guest_rflags}
je .Lresident_nested_vmread_guest_rflags
cmp r10, {vmcs_field_host_rsp}
je .Lresident_nested_vmread_host_rsp
cmp r10, {vmcs_field_host_rip}
je .Lresident_nested_vmread_host_rip
cmp r10, {vmcs_field_instruction_error}
je .Lresident_nested_vmread_instruction_error
cmp r10, {vmcs_field_exit_reason}
je .Lresident_nested_vmread_exit_reason
cmp r10, {vmcs_field_exit_instruction_len}
je .Lresident_nested_vmread_exit_instruction_len
cmp r10, {vmcs_field_exit_qualification}
je .Lresident_nested_vmread_exit_qualification
mov rdx, r10
mov rax, r10
and rax, 0x6000
cmp rax, 0x2000
jne .Lresident_nested_vmread_extended_lookup
and rdx, -2
.Lresident_nested_vmread_extended_lookup:
call .Lresident_vmcs12_field_index
cmp eax, {vmcs12_extended_field_count}
jb .Lresident_nested_vmread_extended
mov r10d, {vmcs_unsupported_component_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_vmread_extended:
call .Lresident_nested_materialize_guest_field
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rax * 8]
cmp rdx, r10
je .Lresident_nested_vmread_value
shr r11, 32
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_instruction_error:
mov r11, qword ptr [r12 + {b_nested_instruction_error}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_exit_reason:
mov r11, qword ptr [r12 + {b_nested_vmcs12_exit_reason}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_exit_instruction_len:
mov r11, qword ptr [r12 + {b_nested_vmcs12_exit_instruction_len}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_exit_qualification:
mov r11, qword ptr [r12 + {b_nested_vmcs12_exit_qualification}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_guest_rsp:
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_guest_rflags:
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_host_rsp:
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rsp}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_host_rip:
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_rip}]
jmp .Lresident_nested_vmread_value
.Lresident_nested_vmread_guest_rip:
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]
cmp qword ptr [r12 + {b_nested_vmcs12_probe_complete}], 0
jne .Lresident_nested_vmread_value
mov qword ptr [r12 + {b_nested_vmcs12_probe_complete}], 1
cmp qword ptr [r12 + {b_nested_vmxoff_count}], 0
jne .Lresident_nested_vmread_value
matrixhv_diagnostic_vmcs12_probe
.Lresident_nested_vmread_value:
mov rbx, r11
bt r13d, 10
jnc .Lresident_nested_vmread_memory_destination
mov eax, r13d
shr eax, 3
and eax, 15
mov r11, rbx
mov r15, rsp
call .Lresident_nested_write_gpr
jmp .Lresident_nested_succeed
.Lresident_nested_vmread_memory_destination:
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_write
mov qword ptr [r12 + {b_nested_operand_data}], rbx
call .Lresident_nested_operand_width
call .Lresident_nested_write_operand_range
jc .Lresident_nested_inject_pf_write
jmp .Lresident_nested_succeed
.Lresident_nested_validate_entry:
bt qword ptr [r12 + {b_nested_vmx_basic}], 55
jnc .Lresident_nested_validate_legacy_controls
mov edx, dword ptr [r12 + {b_nested_vmcs12_pin_based_control}]
mov r11, qword ptr [r12 + {b_nested_vmx_true_pinbased_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
mov edx, dword ptr [r12 + {b_nested_vmcs12_primary_control}]
mov r11, qword ptr [r12 + {b_nested_vmx_true_procbased_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
bt edx, 31
jnc .Lresident_nested_validate_true_secondary_done
mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]
mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls2}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_true_secondary_done:
mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}]
mov r11, qword ptr [r12 + {b_nested_vmx_true_exit_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}]
mov r11, qword ptr [r12 + {b_nested_vmx_true_entry_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
jmp .Lresident_nested_validate_neutral_controls
.Lresident_nested_validate_legacy_controls:
mov edx, dword ptr [r12 + {b_nested_vmcs12_pin_based_control}]
mov r11, qword ptr [r12 + {b_nested_vmx_pinbased_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
mov edx, dword ptr [r12 + {b_nested_vmcs12_primary_control}]
mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
bt edx, 31
jnc .Lresident_nested_validate_legacy_secondary_done
mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]
mov r11, qword ptr [r12 + {b_nested_vmx_procbased_ctls2}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_legacy_secondary_done:
mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}]
mov r11, qword ptr [r12 + {b_nested_vmx_exit_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}]
mov r11, qword ptr [r12 + {b_nested_vmx_entry_ctls}]
call .Lresident_nested_control_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_neutral_controls:
call .Lresident_nested_validate_shadow_controls
test eax, eax
jz .Lresident_nested_validate_invalid_controls
cmp qword ptr [r12 + {b_nested_vmcs12_cr3_target_count}], 4
ja .Lresident_nested_validate_invalid_controls
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 25
jnc .Lresident_nested_validate_io_bitmaps_done
mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_a}]
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_b}]
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_io_bitmaps_done:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 28
jnc .Lresident_nested_validate_msr_bitmap_done
mov r11, qword ptr [r12 + {b_nested_vmcs12_msr_bitmap}]
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_msr_bitmap_done:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 21
jnc .Lresident_nested_validate_tpr_shadow_done
cmp dword ptr [r12 + {b_nested_vmcs12_tpr_threshold}], 15
ja .Lresident_nested_validate_invalid_controls
mov r11, qword ptr [r12 + {b_nested_vmcs12_virtual_apic_page}]
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_tpr_shadow_done:
mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_count}]
call .Lresident_nested_msr_list_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}]
call .Lresident_nested_msr_list_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_count}]
call .Lresident_nested_msr_list_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
call .Lresident_nested_entry_event_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_ept:
call .Lresident_nested_validate_vm_functions
test eax, eax
jz .Lresident_nested_validate_invalid_controls
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_validate_host_state
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 22
jnc .Lresident_nested_validate_mbec_done
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jnc .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_mbec_done:
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jnc .Lresident_nested_validate_vpid
mov r11, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]
call .Lresident_nested_eptp_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_vpid:
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 5
jnc .Lresident_nested_validate_host_state
cmp word ptr [r12 + {b_nested_vmcs12_vpid}], 0
je .Lresident_nested_validate_invalid_controls
.Lresident_nested_validate_host_state:
mov rax, qword ptr [r12 + {b_nested_vmcs12_host_rip}]
mov r11, rax
shl r11, 16
sar r11, 16
cmp rax, r11
jne .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_host_cr0}]
mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed0}]
mov rcx, rax
and rcx, r11
cmp rcx, r11
jne .Lresident_nested_validate_invalid_host_state
mov r11, qword ptr [r12 + {b_nested_vmx_cr0_fixed1}]
not r11
test rax, r11
jnz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_host_cr4}]
mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed0}]
mov rcx, rax
and rcx, r11
cmp rcx, r11
jne .Lresident_nested_validate_invalid_host_state
mov r11, qword ptr [r12 + {b_nested_vmx_cr4_fixed1}]
not r11
test rax, r11
jnz .Lresident_nested_validate_invalid_host_state
bt rax, 5
jnc .Lresident_nested_validate_invalid_host_state
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr3}]
call .Lresident_nested_address_width_is_valid
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 43 * 8]
test ax, 7
jnz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 44 * 8]
test ax, 7
jnz .Lresident_nested_validate_invalid_host_state
test ax, ax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 45 * 8]
test ax, 7
jnz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 46 * 8]
test ax, 7
jnz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 47 * 8]
test ax, 7
jnz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 48 * 8]
test ax, 7
jnz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 49 * 8]
test ax, 7
jnz .Lresident_nested_validate_invalid_host_state
test ax, ax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 60 * 8]
call .Lresident_nested_value_is_canonical
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 61 * 8]
call .Lresident_nested_value_is_canonical
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 62 * 8]
call .Lresident_nested_value_is_canonical
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 63 * 8]
call .Lresident_nested_value_is_canonical
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 64 * 8]
call .Lresident_nested_value_is_canonical
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_host_sysenter_esp}]
call .Lresident_nested_value_is_canonical
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
mov rax, qword ptr [r12 + {b_nested_vmcs12_host_sysenter_eip}]
call .Lresident_nested_value_is_canonical
test eax, eax
jz .Lresident_nested_validate_invalid_host_state
resident_telemetry_counter inc, {b_nested_vmcs12_control_validation_count}, {b_telemetry_active}
xor r10d, r10d
ret
.Lresident_nested_validate_invalid_controls:
mov r10d, {vm_entry_invalid_control_fields_error}
ret
.Lresident_nested_validate_invalid_host_state:
mov r10d, {vm_entry_invalid_host_state_field_error}
ret
.Lresident_nested_control_is_valid:
mov eax, edx
mov ecx, r11d
and eax, ecx
cmp eax, ecx
jne .Lresident_nested_control_invalid
shr r11, 32
not r11d
test edx, r11d
jnz .Lresident_nested_control_invalid
mov eax, 1
ret
.Lresident_nested_control_invalid:
xor eax, eax
ret
.Lresident_nested_validate_shadow_controls:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_shadow_controls_valid
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 14
jnc .Lresident_nested_shadow_controls_valid
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 120 * 8]
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_shadow_controls_done
call .Lresident_ept01_host_page_is_mapped
test eax, eax
jz .Lresident_nested_shadow_controls_done
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 121 * 8]
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_shadow_controls_done
call .Lresident_ept01_host_page_is_mapped
test eax, eax
jz .Lresident_nested_shadow_controls_done
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 23 * 8]
cmp r11, -1
je .Lresident_nested_shadow_controls_valid
// Hardware checks alignment, revision, and shadow type as guest-state checks.
// Unmapped addresses must never be passed through to a hardware VMCS link.
call .Lresident_ept01_host_page_is_mapped
ret
.Lresident_nested_shadow_controls_valid:
mov eax, 1
.Lresident_nested_shadow_controls_done:
ret
.Lresident_nested_msr_list_is_valid:
test r10d, r10d
jz .Lresident_nested_msr_list_valid
cmp r10d, {nested_guest_msr_list_capacity}
ja .Lresident_nested_msr_list_invalid
test r11b, 15
jnz .Lresident_nested_msr_list_invalid
call .Lresident_nested_address_width_is_valid
test eax, eax
jz .Lresident_nested_msr_list_invalid
mov eax, r10d
shl rax, 4
dec rax
add r11, rax
jc .Lresident_nested_msr_list_invalid
call .Lresident_nested_address_width_is_valid
ret
.Lresident_nested_msr_list_valid:
mov eax, 1
ret
.Lresident_nested_msr_list_invalid:
xor eax, eax
ret
.Lresident_nested_entry_event_is_valid:
mov eax, dword ptr [r12 + {b_nested_vmcs12_vm_entry_intr_info}]
test eax, 0x80000000
jz .Lresident_nested_entry_event_valid
test eax, 0x7ffff000
jnz .Lresident_nested_entry_event_invalid
mov edx, eax
shr edx, 8
and edx, 7
cmp edx, 1
je .Lresident_nested_entry_event_invalid
mov ecx, eax
and ecx, 0xff
cmp edx, 7
jne .Lresident_nested_entry_event_check_nmi
test ecx, ecx
jnz .Lresident_nested_entry_event_invalid
.Lresident_nested_entry_event_check_nmi:
cmp edx, 2
jne .Lresident_nested_entry_event_check_exception
cmp ecx, 2
jne .Lresident_nested_entry_event_invalid
.Lresident_nested_entry_event_check_exception:
cmp edx, 3
jne .Lresident_nested_entry_event_check_error_code
cmp ecx, 31
ja .Lresident_nested_entry_event_invalid
cmp ecx, 8
je .Lresident_nested_entry_event_requires_error_code
cmp ecx, 10
je .Lresident_nested_entry_event_requires_error_code
cmp ecx, 11
je .Lresident_nested_entry_event_requires_error_code
cmp ecx, 12
je .Lresident_nested_entry_event_requires_error_code
cmp ecx, 13
je .Lresident_nested_entry_event_requires_error_code
cmp ecx, 14
je .Lresident_nested_entry_event_requires_error_code
cmp ecx, 17
je .Lresident_nested_entry_event_requires_error_code
test eax, 0x800
jnz .Lresident_nested_entry_event_invalid
jmp .Lresident_nested_entry_event_check_instruction_length
.Lresident_nested_entry_event_requires_error_code:
test eax, 0x800
jz .Lresident_nested_entry_event_invalid
.Lresident_nested_entry_event_check_error_code:
test eax, 0x800
jz .Lresident_nested_entry_event_check_instruction_length
cmp edx, 3
jne .Lresident_nested_entry_event_invalid
cmp dword ptr [r12 + {b_nested_vmcs12_vm_entry_exception_error}], 0xffff
ja .Lresident_nested_entry_event_invalid
.Lresident_nested_entry_event_check_instruction_length:
cmp edx, 4
je .Lresident_nested_entry_event_validate_instruction_length
cmp edx, 5
je .Lresident_nested_entry_event_validate_instruction_length
cmp edx, 6
jne .Lresident_nested_entry_event_valid
.Lresident_nested_entry_event_validate_instruction_length:
cmp dword ptr [r12 + {b_nested_vmcs12_vm_entry_instruction_len}], 15
ja .Lresident_nested_entry_event_invalid
.Lresident_nested_entry_event_valid:
mov eax, 1
ret
.Lresident_nested_entry_event_invalid:
xor eax, eax
ret
.Lresident_nested_value_is_canonical:
mov r11, rax
shl r11, 16
sar r11, 16
cmp rax, r11
sete al
movzx eax, al
ret
// Normalize the architectural width, type, and index into a bounded byte table.
.Lresident_vmcs12_field_index:
mov rax, rdx
and rax, -0x6c3f
jnz .Lresident_vmcs12_field_index_missing
mov eax, edx
shr eax, 5
and eax, 0x360
mov ecx, edx
shr ecx, 1
and ecx, 31
or eax, ecx
lea rsi, [rip + .Lresident_vmcs12_field_index_table]
movzx eax, byte ptr [rsi + rax]
ret
.Lresident_vmcs12_field_index_missing:
mov eax, 255
ret
// Cache controls that hardware leaves unchanged. Internal list switches use
// this helper too so their values cannot leave stale cached entry addresses.
.Lresident_nested_write_vmcs02_control:
push rcx
push rdx
push rsi
push rax
mov rdx, rax
call .Lresident_vmcs12_field_index
cmp eax, {vmcs12_extended_field_count}
jae .Lresident_dispatch_halt
mov edx, eax
pop rax
bt qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], rdx
jnc .Lresident_nested_write_vmcs02_control_changed
cmp r11, qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8]
je .Lresident_nested_write_vmcs02_control_done
.Lresident_nested_write_vmcs02_control_changed:
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11
bts qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], rdx
.Lresident_nested_write_vmcs02_control_done:
pop rsi
pop rdx
pop rcx
ret
.Lresident_nested_merge_vmcs02_controls:
call .Lresident_nested_prepare_vpid02
mov rax, {pin_based_vm_exec_control}
mov r11, qword ptr [r12 + {b_nested_vmcs01_pin_based_controls}]
mov edx, dword ptr [r12 + {b_nested_vmcs12_pin_based_control}]
or r11d, edx
// The boot sampling timer belongs to VMCS01 and is not advertised to L1.
btr r11d, 6
call .Lresident_nested_write_vmcs02_control
mov rax, {cpu_based_vm_exec_control}
mov r11, qword ptr [r12 + {b_nested_vmcs01_primary_controls}]
mov edx, dword ptr [r12 + {b_nested_vmcs12_primary_control}]
or r11d, edx
call .Lresident_nested_write_vmcs02_control
bt r11, 21
jnc .Lresident_nested_merge_tpr_shadow_done
mov rax, {virtual_apic_page_addr}
mov r11, qword ptr [r12 + {b_nested_vmcs12_virtual_apic_page}]
call .Lresident_nested_write_vmcs02_control
mov rax, {tpr_threshold}
mov r11, qword ptr [r12 + {b_nested_vmcs12_tpr_threshold}]
call .Lresident_nested_write_vmcs02_control
.Lresident_nested_merge_tpr_shadow_done:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 25
jnc .Lresident_nested_merge_io_bitmaps_done
mov rax, {io_bitmap_a}
mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_a}]
call .Lresident_nested_write_vmcs02_control
mov rax, {io_bitmap_b}
mov r11, qword ptr [r12 + {b_nested_vmcs12_io_bitmap_b}]
call .Lresident_nested_write_vmcs02_control
.Lresident_nested_merge_io_bitmaps_done:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 28
// Clearing "use MSR bitmaps" requests unconditional RDMSR and WRMSR exits.
jnc .Lresident_nested_intercept_unmapped_msr_bitmap
mov r11, qword ptr [r12 + {b_nested_vmcs12_msr_bitmap}]
call .Lresident_ept01_host_page_is_mapped
test eax, eax
jz .Lresident_nested_intercept_unmapped_msr_bitmap
mov rsi, qword ptr [r12 + {b_nested_l0_msr_bitmap}]
mov rdi, qword ptr [r12 + {b_nested_composed_msr_bitmap}]
mov rdx, qword ptr [r12 + {b_nested_vmcs12_msr_bitmap}]
mov ecx, {nested_msr_bitmap_qword_count}
.Lresident_nested_merge_msr_bitmap_loop:
mov r11, qword ptr [rsi]
or r11, qword ptr [rdx]
// An outer hypervisor may write-protect active bitmaps; unchanged stores cause exits.
cmp qword ptr [rdi], r11
je .Lresident_nested_merge_msr_bitmap_next
mov qword ptr [rdi], r11
.Lresident_nested_merge_msr_bitmap_next:
add rsi, 8
add rdi, 8
add rdx, 8
dec ecx
jnz .Lresident_nested_merge_msr_bitmap_loop
jmp .Lresident_nested_use_composed_msr_bitmap
.Lresident_nested_intercept_unmapped_msr_bitmap:
mov rdi, qword ptr [r12 + {b_nested_composed_msr_bitmap}]
mov ecx, {nested_msr_bitmap_qword_count}
.Lresident_nested_intercept_all_msrs_loop:
cmp qword ptr [rdi], -1
je .Lresident_nested_intercept_all_msrs_next
mov qword ptr [rdi], -1
.Lresident_nested_intercept_all_msrs_next:
add rdi, 8
dec ecx
jnz .Lresident_nested_intercept_all_msrs_loop
.Lresident_nested_use_composed_msr_bitmap:
mov r11, qword ptr [r12 + {b_nested_composed_msr_bitmap}]
mov rax, {msr_bitmap}
call .Lresident_nested_write_vmcs02_control
.Lresident_nested_merge_msr_bitmap_done:
mov rax, {secondary_vm_exec_control}
mov r11, qword ptr [r12 + {b_nested_vmcs01_secondary_controls}]
// L0's acceleration VMCS belongs only to VMCS01; L1 supplies its own for L2.
btr r11d, 14
cmp qword ptr [r12 + {b_nested_vmcs02_last_vpid}], 0
jne .Lresident_nested_merge_vpid_ready
and r11d, -33
.Lresident_nested_merge_vpid_ready:
mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]
// L1 secondary controls have no effect unless its primary activation bit is set.
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jc .Lresident_nested_merge_secondary_ready
xor edx, edx
.Lresident_nested_merge_secondary_ready:
// L1 selects guest features; L0 retains its interception and EPT requirements.
and r11d, ~0x503088
and edx, 0x5078ce
or r11d, edx
call .Lresident_nested_write_vmcs02_control
mov qword ptr [r12 + {b_nested_last_merged_secondary_controls}], r11
bt r11d, 14
jnc .Lresident_nested_merge_shadow_done
call .Lresident_nested_eptp_before_root_write
mov rax, 0x2026
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 120 * 8]
call .Lresident_nested_write_vmcs02_control
mov rax, 0x2028
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 121 * 8]
call .Lresident_nested_write_vmcs02_control
.Lresident_nested_merge_shadow_done:
xor r11d, r11d
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_merge_xss_bitmap_ready
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 20
jnc .Lresident_nested_merge_xss_bitmap_ready
mov r11, qword ptr [r12 + {b_nested_vmcs12_xss_exiting_bitmap}]
.Lresident_nested_merge_xss_bitmap_ready:
mov rax, {xss_exiting_bitmap}
call .Lresident_nested_write_vmcs02_control
mov rax, {vm_exit_controls}
mov r11, qword ptr [r12 + {b_nested_vmcs01_exit_controls}]
mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}]
or r11d, edx
call .Lresident_nested_write_vmcs02_control
mov rax, {vm_entry_controls}
mov r11, qword ptr [r12 + {b_nested_vmcs01_entry_controls}]
btr r11, 9
mov edx, dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}]
or r11d, edx
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {exception_bitmap}
mov r11d, dword ptr [r12 + {b_nested_vmcs12_exception_bitmap}]
call .Lresident_nested_write_vmcs02_control
mov rax, {page_fault_error_code_mask}
mov r11d, dword ptr [r12 + {b_nested_vmcs12_pf_error_mask}]
call .Lresident_nested_write_vmcs02_control
mov rax, {page_fault_error_code_match}
mov r11d, dword ptr [r12 + {b_nested_vmcs12_pf_error_match}]
call .Lresident_nested_write_vmcs02_control
mov rax, {cr0_guest_host_mask}
mov r11, qword ptr [r12 + {b_nested_vmcs12_cr0_mask}]
call .Lresident_nested_write_vmcs02_control
mov rax, {cr0_read_shadow}
mov r11, qword ptr [r12 + {b_nested_vmcs12_cr0_shadow}]
call .Lresident_nested_write_vmcs02_control
mov r10, qword ptr [r12 + {b_nested_vmcs12_cr4_mask}]
mov r11, r10
or r11, {cr4_vmxe}
mov rax, {cr4_guest_host_mask}
call .Lresident_nested_write_vmcs02_control
mov r11, qword ptr [r12 + {b_nested_vmcs12_cr4_shadow}]
and r11, r10
test r10, {cr4_vmxe}
jnz .Lresident_nested_vmcs02_cr4_shadow_ready
mov rdx, qword ptr [r12 + {b_nested_vmcs12_guest_cr4}]
and rdx, {cr4_vmxe}
or r11, rdx
.Lresident_nested_vmcs02_cr4_shadow_ready:
mov rax, {cr4_read_shadow}
call .Lresident_nested_write_vmcs02_control
call .Lresident_nested_compose_vmcs02_msr_lists
resident_telemetry_counter inc, {b_nested_control_merge_count}, {b_telemetry_active}
ret
.Lresident_nested_prepare_vpid02:
xor r10d, r10d
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_vpid02_selected
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 5
jnc .Lresident_nested_vpid02_selected
movzx r10d, word ptr [r12 + {b_nested_vmcs12_vpid}]
.Lresident_nested_vpid02_selected:
bt dword ptr [r12 + {b_nested_vmcs01_secondary_controls}], 5
jnc .Lresident_nested_vpid02_ready
test r10d, r10d
jz .Lresident_nested_vpid02_disabled
// Hardware tag 1 belongs to L1. Tags 2 and 3 retain two virtual L2 contexts,
// avoiding a full TLB invalidation on every VTL0/VTL1 transition.
cmp r10w, word ptr [r12 + {b_nested_vmcs02_vpid_cache}]
je .Lresident_nested_vpid02_select_first
cmp r10w, word ptr [r12 + {b_nested_vmcs02_vpid_cache} + 2]
je .Lresident_nested_vpid02_select_second
mov r11, qword ptr [r12 + {b_nested_vmcs02_last_vpid}]
test r11d, r11d
jz .Lresident_nested_vpid02_replace_first
cmp r11w, word ptr [r12 + {b_nested_vmcs02_vpid_cache}]
je .Lresident_nested_vpid02_replace_second
.Lresident_nested_vpid02_replace_first:
mov word ptr [r12 + {b_nested_vmcs02_vpid_cache}], r10w
mov r11d, 2
call .Lresident_nested_flush_vpid02_tag
jmp .Lresident_nested_vpid02_write_tag
.Lresident_nested_vpid02_replace_second:
mov word ptr [r12 + {b_nested_vmcs02_vpid_cache} + 2], r10w
mov r11d, 3
call .Lresident_nested_flush_vpid02_tag
jmp .Lresident_nested_vpid02_write_tag
.Lresident_nested_vpid02_select_first:
mov r11d, 2
jmp .Lresident_nested_vpid02_write_tag
.Lresident_nested_vpid02_select_second:
mov r11d, 3
.Lresident_nested_vpid02_write_tag:
mov rax, {virtual_processor_id}
call .Lresident_nested_write_vmcs02_control
jmp .Lresident_nested_vpid02_ready
.Lresident_nested_vpid02_disabled:
cmp dword ptr [r12 + {b_nested_vmcs02_vpid_cache}], 0
je .Lresident_nested_vpid02_ready
mov r11d, 2
call .Lresident_nested_flush_vpid02_tag
mov r11d, 3
call .Lresident_nested_flush_vpid02_tag
mov dword ptr [r12 + {b_nested_vmcs02_vpid_cache}], 0
.Lresident_nested_vpid02_ready:
mov qword ptr [r12 + {b_nested_vmcs02_last_vpid}], r10
ret
// Invalidate a resident virtual tag even when another VMCS12 is current.
.Lresident_nested_flush_vpid02:
cmp r11w, word ptr [r12 + {b_nested_vmcs02_vpid_cache}]
je .Lresident_nested_flush_vpid02_first
cmp r11w, word ptr [r12 + {b_nested_vmcs02_vpid_cache} + 2]
jne .Lresident_nested_flush_vpid02_done
mov r11d, 3
jmp .Lresident_nested_flush_vpid02_tag
.Lresident_nested_flush_vpid02_first:
mov r11d, 2
.Lresident_nested_flush_vpid02_tag:
bt dword ptr [r12 + {b_nested_vmcs01_secondary_controls}], 5
jnc .Lresident_nested_flush_vpid02_done
sub rsp, 16
mov qword ptr [rsp], r11
mov qword ptr [rsp + 8], 0
mov eax, 1
invvpid rax, xmmword ptr [rsp]
lea rsp, [rsp + 16]
jna .Lresident_dispatch_halt
.Lresident_nested_flush_vpid02_done:
ret
.Lresident_nested_select_msr_entry_list:
add r10d, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
cmp r10d, {nested_guest_msr_list_capacity}
jbe .Lresident_nested_select_msr_entry_done
mov eax, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
sub r10d, eax
shl eax, 4
add r11, rax
.Lresident_nested_select_msr_entry_done:
ret
// A full L1 list leaves no hardware slot for SPEC_CTRL. Load only that root
// switch in software immediately before entry; L1's list still runs afterward.
.Lresident_nested_prepare_full_msr_entry:
cmp dword ptr [rip + matrixhv_resident_island_msr_switch_count], 0
je .Lresident_nested_prepare_full_msr_done
mov eax, {vm_entry_msr_load_count}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
cmp r11d, {nested_guest_msr_list_capacity}
jne .Lresident_nested_prepare_full_msr_done
mov r11, qword ptr [r12 + {b_nested_l0_msr_guest_list}]
jmp .Lresident_nested_switch_spec_ctrl
.Lresident_nested_restore_root_spec_ctrl:
cmp dword ptr [rip + matrixhv_resident_island_msr_switch_count], 0
je .Lresident_nested_prepare_full_msr_done
mov r11, qword ptr [r12 + {b_nested_l0_msr_host_list}]
.Lresident_nested_switch_spec_ctrl:
mov eax, dword ptr [r11 + 8]
mov edx, dword ptr [r11 + 12]
mov ecx, {spec_ctrl_msr}
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_halt
.Lresident_nested_prepare_full_msr_done:
ret
.Lresident_nested_compose_vmcs02_msr_lists:
cld
mov rsi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]
mov rdi, qword ptr [r12 + {b_nested_vmcs02_entry_msr_list}]
mov ecx, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
shl ecx, 1
rep movsq
mov rsi, qword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_msr_load_count}]
mov r11, rsi
call .Lresident_nested_host_msr_list_is_mapped
test eax, eax
jnz .Lresident_nested_copy_vmcs12_entry_msr_list
xor r10d, r10d
jmp .Lresident_nested_copy_vmcs12_entry_msr_list_done
.Lresident_nested_copy_vmcs12_entry_msr_list:
mov ecx, r10d
shl ecx, 1
rep movsq
.Lresident_nested_copy_vmcs12_entry_msr_list_done:
mov rax, {vm_entry_msr_load_addr}
mov r11, qword ptr [r12 + {b_nested_vmcs02_entry_msr_list}]
mov edx, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
mov qword ptr [r12 + {b_nested_entry_msr_prefix_count}], rdx
add edx, r10d
cmp edx, {nested_guest_msr_list_capacity}
jbe .Lresident_nested_entry_msr_prefix_ready
mov qword ptr [r12 + {b_nested_entry_msr_prefix_count}], 0
.Lresident_nested_entry_msr_prefix_ready:
push rax
call .Lresident_nested_select_msr_entry_list
pop rax
call .Lresident_nested_write_vmcs02_control
mov rax, {vm_entry_msr_load_count}
mov r11d, r10d
call .Lresident_nested_write_vmcs02_control
mov rsi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]
mov rdi, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]
mov ecx, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
shl ecx, 1
rep movsq
mov rsi, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_count}]
mov r11, rsi
call .Lresident_nested_host_msr_list_is_mapped
mov ebx, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
test eax, eax
jz .Lresident_nested_copy_vmcs12_exit_store_msr_list_done
.Lresident_nested_copy_vmcs12_exit_store_msr_list:
test r10d, r10d
jz .Lresident_nested_copy_vmcs12_exit_store_msr_list_done
cmp dword ptr [rsi + 4], 0
jne .Lresident_nested_copy_vmcs12_exit_store_next
call .Lresident_nested_msr_requires_hardware_store
test eax, eax
jz .Lresident_nested_copy_vmcs12_exit_store_next
mov r8, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]
mov ecx, ebx
mov eax, dword ptr [rsi]
.Lresident_nested_find_captured_msr:
test ecx, ecx
jz .Lresident_nested_append_captured_msr
cmp eax, dword ptr [r8]
je .Lresident_nested_copy_vmcs12_exit_store_next
add r8, 16
dec ecx
jmp .Lresident_nested_find_captured_msr
.Lresident_nested_append_captured_msr:
mov rax, qword ptr [rsi]
mov qword ptr [rdi], rax
mov qword ptr [rdi + 8], 0
add rdi, 16
inc ebx
.Lresident_nested_copy_vmcs12_exit_store_next:
add rsi, 16
dec r10d
jmp .Lresident_nested_copy_vmcs12_exit_store_msr_list
.Lresident_nested_copy_vmcs12_exit_store_msr_list_done:
mov qword ptr [r12 + {b_nested_captured_msr_store_count}], rbx
mov rax, {vm_exit_msr_store_addr}
mov r11, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]
call .Lresident_nested_write_vmcs02_control
mov rax, {vm_exit_msr_store_count}
mov r11d, ebx
call .Lresident_nested_write_vmcs02_control
mov rax, {vm_exit_msr_load_addr}
mov r11, qword ptr [r12 + {b_nested_l0_msr_host_list}]
call .Lresident_nested_write_vmcs02_control
mov rax, {vm_exit_msr_load_count}
mov r11d, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
call .Lresident_nested_write_vmcs02_control
ret
.Lresident_nested_snapshot_vmcs01_effective_state:
mov rax, {guest_pat}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_inherited_l1_pat}], r11
mov rax, {guest_efer}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_inherited_l1_efer}], r11
mov rax, {tsc_offset}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_inherited_l1_tsc_offset}], r11
mov rax, {vm_entry_controls}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs01_entry_controls}], r11
// Cache VMCS01 execution/exit controls and its EPT root on the first snapshot.
// Boot timer retirement also clears the cached pin-based timer bit.
// Refresh entry controls each time because unrestricted L1 can change EFER.LMA.
cmp qword ptr [r12 + {b_nested_ept01_pointer}], 0
jne .Lresident_nested_snapshot_vmcs01_ready
mov rax, {pin_based_vm_exec_control}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs01_pin_based_controls}], r11
mov rax, {cpu_based_vm_exec_control}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs01_primary_controls}], r11
mov rax, {secondary_vm_exec_control}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs01_secondary_controls}], r11
mov rax, {vm_exit_controls}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs01_exit_controls}], r11
mov rax, {ept_pointer}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_ept01_pointer}], r11
.Lresident_nested_snapshot_vmcs01_ready:
ret
.Lresident_nested_sync_vmcs02_guest_state:
mov rax, {vmcs_link_pointer}
mov r11, -1
bt dword ptr [r12 + {b_nested_last_merged_secondary_controls}], 14
jnc .Lresident_nested_vmcs02_link_ready
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 23 * 8]
.Lresident_nested_vmcs02_link_ready:
call .Lresident_nested_write_vmcs02_control
mov rax, {guest_pat}
mov r11, qword ptr [r12 + {b_nested_inherited_l1_pat}]
bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 14
jnc .Lresident_nested_vmcs02_guest_pat_ready
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 25 * 8]
.Lresident_nested_vmcs02_guest_pat_ready:
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_efer}
mov r11, qword ptr [r12 + {b_nested_inherited_l1_efer}]
bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 15
jnc .Lresident_nested_vmcs02_guest_efer_ready
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 26 * 8]
.Lresident_nested_vmcs02_guest_efer_ready:
btr r11, 10
bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 9
jnc .Lresident_nested_vmcs02_guest_lma_ready
bts r11, 10
.Lresident_nested_vmcs02_guest_lma_ready:
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {tsc_offset}
mov r11, qword ptr [r12 + {b_nested_inherited_l1_tsc_offset}]
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 3
jnc .Lresident_nested_vmcs02_tsc_offset_ready
add r11, qword ptr [r12 + {b_nested_vmcs12_tsc_offset}]
.Lresident_nested_vmcs02_tsc_offset_ready:
call .Lresident_nested_write_vmcs02_control
call .Lresident_nested_sync_vmcs02_guest_fields
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_synthesize_vmcs02_pdptrs
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jc .Lresident_nested_vmcs02_pdptrs_ready
.Lresident_nested_synthesize_vmcs02_pdptrs:
bt qword ptr [r12 + {b_nested_vmcs12_guest_cr0}], 31
jnc .Lresident_nested_vmcs02_pdptrs_ready
bt qword ptr [r12 + {b_nested_vmcs12_guest_cr4}], 5
jnc .Lresident_nested_vmcs02_pdptrs_ready
bt dword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 9
jc .Lresident_nested_vmcs02_pdptrs_ready
mov r10, qword ptr [r12 + {b_nested_vmcs12_guest_cr3}]
and r10, -32
mov r11, r10
call .Lresident_ept01_host_page_is_mapped
test eax, eax
jz .Lresident_nested_vmcs02_pdptrs_ready
mov r11, qword ptr [r10]
mov rax, {guest_pdptr0}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov r11, qword ptr [r10 + 8]
mov rax, {guest_pdptr1}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov r11, qword ptr [r10 + 16]
mov rax, {guest_pdptr2}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov r11, qword ptr [r10 + 24]
mov rax, {guest_pdptr3}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_vmcs02_pdptrs_ready:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_guest_state_recorded
mov rax, {guest_gs_base}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_last_synced_guest_gs_base}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_cr0}]
mov qword ptr [r12 + {b_nested_last_synced_guest_cr0}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_cr3}]
mov qword ptr [r12 + {b_nested_last_synced_guest_cr3}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_cr4}]
mov qword ptr [r12 + {b_nested_last_synced_guest_cr4}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_sysenter_eip}]
mov qword ptr [r12 + {b_nested_last_synced_guest_sysenter_eip}], r11
.Lresident_nested_guest_state_recorded:
mov rax, {vm_entry_intr_info_field}
mov r11d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_intr_info}]
bt qword ptr [r12 + {b_nested_vmcs12_guest_rflags}], 1
jc .Lresident_nested_vmcs02_entry_event_ready
xor r11d, r11d
.Lresident_nested_vmcs02_entry_event_ready:
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {vm_entry_exception_error_code}
mov r11d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_exception_error}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {vm_entry_instruction_len}
mov r11d, dword ptr [r12 + {b_nested_vmcs12_vm_entry_instruction_len}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
resident_telemetry_counter inc, {b_nested_guest_state_sync_count}, {b_telemetry_active}
ret
.Lresident_nested_sync_vmcs02_guest_fields:
lea rsi, [rip + .Lresident_nested_guest_state_table]
mov ecx, {nested_guest_state_table_count}
.Lresident_nested_sync_vmcs02_guest_state_loop:
mov edx, dword ptr [rsi]
// Deferred fields remain authoritative in VMCS02 until L1 accesses them.
bt qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rdx
jc .Lresident_nested_sync_vmcs02_guest_field_done
.Lresident_nested_sync_vmcs02_guest_field_ready:
mov rax, qword ptr [rsi + 8]
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8]
cmp qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 0
je .Lresident_nested_sync_vmcs02_guest_field_write
// PDPTR synthesis below can modify these fields after the cache is populated.
cmp edx, 111
jae .Lresident_nested_sync_vmcs02_guest_field_write
cmp r11, qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8]
je .Lresident_nested_sync_vmcs02_guest_field_done
.Lresident_nested_sync_vmcs02_guest_field_write:
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11
.Lresident_nested_sync_vmcs02_guest_field_done:
add rsi, 16
dec ecx
jnz .Lresident_nested_sync_vmcs02_guest_state_loop
mov qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 1
ret
.Lresident_nested_capture_vmcs02_guest_state:
mov rax, {guest_pat}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_l2_saved_pat}], r11
mov rax, {guest_efer}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_l2_saved_efer}], r11
// Successful VM exits save requested EFER and update the entry mode after EFER.LMA changes.
test dword ptr [r12 + {b_nested_vmcs12_exit_reason}], 0x80000000
jnz .Lresident_nested_capture_vmcs02_entry_mode_done
bt dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}], 20
jnc .Lresident_nested_capture_vmcs02_efer_saved
mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 26 * 8], r11
.Lresident_nested_capture_vmcs02_efer_saved:
bt qword ptr [r12 + {b_nested_vmx_misc}], 5
jnc .Lresident_nested_capture_vmcs02_entry_mode_done
shr r11, 1
and r11d, 0x200
btr qword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], 9
or qword ptr [r12 + {b_nested_vmcs12_vm_entry_controls}], r11
.Lresident_nested_capture_vmcs02_entry_mode_done:
lea rsi, [rip + .Lresident_nested_guest_state_table]
mov ecx, {nested_guest_state_table_count}
.Lresident_nested_capture_vmcs02_guest_state_loop:
mov edx, dword ptr [rsi]
bt qword ptr [rip + .Lresident_nested_rare_guest_fields], rdx
jc .Lresident_nested_capture_vmcs02_guest_field_done
mov rax, qword ptr [rsi + 8]
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11
mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8], r11
.Lresident_nested_capture_vmcs02_guest_field_done:
add rsi, 16
dec ecx
jnz .Lresident_nested_capture_vmcs02_guest_state_loop
mov rax, {guest_gs_base}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_last_captured_guest_gs_base}], r11
mov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields]
mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rax
mov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields + 8]
mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending} + 8], rax
ret
.Lresident_nested_materialize_guest_field:
bt qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rax
jnc .Lresident_nested_materialize_guest_field_done
// A single VMREAD or VMWRITE needs only its own deferred hardware field.
push rax
push rdx
push r11
vmptrld [r12 + {b_nested_vmcs02_region}]
jna .Lresident_dispatch_halt
mov rax, rdx
mov rdx, qword ptr [rsp + 16]
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11
mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8], r11
btr qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rdx
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
pop r11
pop rdx
pop rax
.Lresident_nested_materialize_guest_field_done:
ret
.Lresident_nested_materialize_vmcs02_rare_state:
cmp qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], 0
jne .Lresident_nested_materialize_vmcs02_rare_begin
cmp qword ptr [r12 + {b_nested_vmcs02_rare_state_pending} + 8], 0
je .Lresident_nested_materialize_vmcs02_rare_done
.Lresident_nested_materialize_vmcs02_rare_begin:
// Preserve the VMREAD/VMWRITE operands and VMPTRLD/VMCLEAR target pointer.
push rax
push rcx
push rdx
push rsi
push r11
vmptrld [r12 + {b_nested_vmcs02_region}]
jna .Lresident_dispatch_halt
lea rsi, [rip + .Lresident_nested_guest_state_table]
mov ecx, {nested_guest_state_table_count}
.Lresident_nested_materialize_vmcs02_rare_loop:
mov edx, dword ptr [rsi]
bt qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rdx
jnc .Lresident_nested_materialize_vmcs02_rare_next
mov rax, qword ptr [rsi + 8]
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_vmcs02_field_cache} + rdx * 8], r11
mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8], r11
.Lresident_nested_materialize_vmcs02_rare_next:
add rsi, 16
dec ecx
jnz .Lresident_nested_materialize_vmcs02_rare_loop
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], 0
mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending} + 8], 0
pop r11
pop rsi
pop rdx
pop rcx
pop rax
.Lresident_nested_materialize_vmcs02_rare_done:
ret
.Lresident_nested_complete_vmcs02_msr_exit:
test r10d, 0x80000000
jnz .Lresident_nested_compose_vmcs01_msr_entry
mov rsi, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]
mov rdi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]
mov ecx, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
test ecx, ecx
jz .Lresident_nested_copy_l0_msr_store_done
.Lresident_nested_copy_l0_msr_store_loop:
mov rax, qword ptr [rsi + 8]
mov qword ptr [rdi + 8], rax
add rsi, 16
add rdi, 16
dec ecx
jnz .Lresident_nested_copy_l0_msr_store_loop
.Lresident_nested_copy_l0_msr_store_done:
mov rdi, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_store_count}]
test r10d, r10d
jz .Lresident_nested_compose_vmcs01_msr_entry
mov r11, rdi
call .Lresident_nested_host_msr_list_is_mapped
test eax, eax
jz .Lresident_nested_compose_vmcs01_msr_entry
mov ebx, r10d
call .Lresident_nested_eptp_before_root_write
.Lresident_nested_copy_l1_msr_store_loop:
mov ecx, dword ptr [rdi]
cmp dword ptr [rdi + 4], 0
jne .Lresident_nested_abort_msr_store
mov r8, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]
mov r9d, dword ptr [r12 + {b_nested_captured_msr_store_count}]
.Lresident_nested_find_l0_msr_store_loop:
test r9d, r9d
jz .Lresident_nested_use_software_msr_store
cmp ecx, dword ptr [r8]
je .Lresident_nested_use_l0_msr_store
add r8, 16
dec r9d
jmp .Lresident_nested_find_l0_msr_store_loop
.Lresident_nested_use_software_msr_store:
push rdi
call .Lresident_nested_read_saved_msr
pop rdi
jc .Lresident_nested_abort_msr_store
jmp .Lresident_nested_write_l1_msr_store
.Lresident_nested_use_l0_msr_store:
mov rax, qword ptr [r8 + 8]
.Lresident_nested_write_l1_msr_store:
mov qword ptr [rdi + 8], rax
add rdi, 16
dec ebx
jnz .Lresident_nested_copy_l1_msr_store_loop
jmp .Lresident_nested_compose_vmcs01_msr_entry
.Lresident_nested_abort_msr_store:
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_dispatch_halt
mov dword ptr [r11 + 4], 1
jmp .Lresident_dispatch_halt
.Lresident_nested_compose_vmcs01_msr_entry:
cmp dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}], 0
je .Lresident_nested_compose_vmcs01_msr_entry_done
cld
mov rsi, qword ptr [r12 + {b_nested_l0_msr_guest_list}]
mov rdi, qword ptr [r12 + {b_nested_vmcs01_entry_msr_list}]
mov ecx, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
shl ecx, 1
rep movsq
mov rsi, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}]
mov r11, rsi
call .Lresident_nested_host_msr_list_is_mapped
test eax, eax
jz .Lresident_nested_compose_vmcs01_msr_entry_done
mov ecx, r10d
shl ecx, 1
rep movsq
.Lresident_nested_compose_vmcs01_msr_entry_done:
ret
.Lresident_nested_activate_vmcs01_msr_entry:
cmp dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}], 0
je .Lresident_nested_activate_vmcs01_msr_entry_done
mov r11, qword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_addr}]
mov r10d, dword ptr [r12 + {b_nested_vmcs12_vm_exit_msr_load_count}]
call .Lresident_nested_host_msr_list_is_mapped
test eax, eax
jnz .Lresident_nested_activate_vmcs01_guest_msr_entry
xor r10d, r10d
.Lresident_nested_activate_vmcs01_guest_msr_entry:
mov r11, qword ptr [r12 + {b_nested_vmcs01_entry_msr_list}]
call .Lresident_nested_select_msr_entry_list
mov rax, {vm_entry_msr_load_addr}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov r11d, r10d
mov rax, {vm_entry_msr_load_count}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [r12 + {b_nested_vmcs01_msr_entry_composed}], 1
.Lresident_nested_activate_vmcs01_msr_entry_done:
ret
.Lresident_nested_restore_l1_host_state:
mov rax, {guest_pat}
mov r11, qword ptr [r12 + {b_nested_l2_saved_pat}]
bt dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}], 19
jnc .Lresident_nested_l1_host_pat_ready
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 27 * 8]
.Lresident_nested_l1_host_pat_ready:
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_efer}
mov r11, qword ptr [r12 + {b_nested_l2_saved_efer}]
bt dword ptr [r12 + {b_nested_vmcs12_vm_exit_controls}], 21
jnc .Lresident_nested_l1_host_efer_ready
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + 28 * 8]
.Lresident_nested_l1_host_efer_ready:
or r11, 0x500
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
lea rsi, [rip + .Lresident_nested_host_state_table]
mov ecx, {nested_host_state_table_count}
.Lresident_nested_restore_l1_host_state_loop:
mov edx, dword ptr [rsi]
mov rax, qword ptr [rsi + 8]
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + rdx * 8]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
add rsi, 16
dec ecx
jnz .Lresident_nested_restore_l1_host_state_loop
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_host_state_recorded
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr0}]
mov qword ptr [r12 + {b_nested_last_restored_host_cr0}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr3}]
mov qword ptr [r12 + {b_nested_last_restored_host_cr3}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_cr4}]
mov qword ptr [r12 + {b_nested_last_restored_host_cr4}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_host_sysenter_eip}]
mov qword ptr [r12 + {b_nested_last_restored_host_sysenter_eip}], r11
.Lresident_nested_host_state_recorded:
mov rax, {guest_cs_base}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_cs_limit}
mov r11d, -1
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_cs_ar_bytes}
mov r11d, 0xa09b
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_es_base}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 43 * 8], 0
je .Lresident_nested_restore_es_unusable
mov rax, {guest_es_limit}
mov r11d, -1
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_es_ar_bytes}
mov r11d, 0xc093
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_restore_es_done
.Lresident_nested_restore_es_unusable:
mov rax, {guest_es_limit}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_es_ar_bytes}
mov r11d, 0x10000
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_restore_es_done:
mov rax, {guest_ss_base}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 45 * 8], 0
je .Lresident_nested_restore_ss_unusable
mov rax, {guest_ss_limit}
mov r11d, -1
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ss_ar_bytes}
mov r11d, 0xc093
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_restore_ss_done
.Lresident_nested_restore_ss_unusable:
mov rax, {guest_ss_limit}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ss_ar_bytes}
mov r11d, 0x10000
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_restore_ss_done:
mov rax, {guest_ds_base}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 46 * 8], 0
je .Lresident_nested_restore_ds_unusable
mov rax, {guest_ds_limit}
mov r11d, -1
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ds_ar_bytes}
mov r11d, 0xc093
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_restore_ds_done
.Lresident_nested_restore_ds_unusable:
mov rax, {guest_ds_limit}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ds_ar_bytes}
mov r11d, 0x10000
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_restore_ds_done:
cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 47 * 8], 0
je .Lresident_nested_restore_fs_unusable
mov rax, {guest_fs_limit}
mov r11d, -1
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_fs_ar_bytes}
mov r11d, 0xc093
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_restore_fs_done
.Lresident_nested_restore_fs_unusable:
mov rax, {guest_fs_limit}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_fs_ar_bytes}
mov r11d, 0x10000
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_restore_fs_done:
cmp word ptr [r12 + {b_nested_vmcs12_extended_fields} + 48 * 8], 0
je .Lresident_nested_restore_gs_unusable
mov rax, {guest_gs_limit}
mov r11d, -1
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_gs_ar_bytes}
mov r11d, 0xc093
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_restore_gs_done
.Lresident_nested_restore_gs_unusable:
mov rax, {guest_gs_limit}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_gs_ar_bytes}
mov r11d, 0x10000
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_restore_gs_done:
mov rax, {guest_tr_limit}
mov r11d, 0x67
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_tr_ar_bytes}
mov r11d, 0x8b
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ldtr_selector}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ldtr_base}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ldtr_limit}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ldtr_ar_bytes}
mov r11d, 0x10000
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_gdtr_limit}
mov r11d, 0xffff
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_idtr_limit}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_activity_state}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_pending_dbg_exceptions}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_dr7}
mov r11d, 0x400
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_ia32_debugctl}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_nested_host_registers_recorded
mov rax, {guest_gs_base}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_last_restored_host_gs_base}], r11
mov rax, {guest_cs_ar_bytes}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov qword ptr [r12 + {b_nested_last_restored_host_cs_ar}], r11
resident_telemetry_counter inc, {b_nested_l1_host_restore_count}, {b_telemetry_active}
.Lresident_nested_host_registers_recorded:
ret
.Lresident_nested_l2_enter:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 21
jnc .Lresident_nested_l2_admit_eptp
call .Lresident_nested_eptp_before_root_write
.Lresident_nested_l2_admit_eptp:
mov qword ptr [r12 + {b_nested_eptp_admission}], 1
// VMCS02 is shared by all VMCS12 contexts on this CPU.
cmp qword ptr [r12 + {b_nested_vmcs02_launched}], 0
jne .Lresident_nested_l2_resume_registers
.Lresident_nested_l2_launch_registers:
call .Lresident_watchdog_handler_returned
call .Lresident_sync_ept_cache
call .Lresident_nested_refresh_eptp_list
call .Lresident_deliver_pending_nmi
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
vmlaunch
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
pushfq
mov r12, qword ptr [rsp + 128]
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
call .Lresident_nested_restore_root_spec_ctrl
mov r10, qword ptr [rsp]
add rsp, 8
resident_telemetry_counter inc, {b_watchdog_sequence}, {b_telemetry_active}
resident_telemetry_counter inc, {b_watchdog_resume_failures}, {b_telemetry_active}
cmp qword ptr [r12 + {b_telemetry_active}], 0
je 991f
mov qword ptr [r12 + {b_watchdog_phase}], 2
991:
mov qword ptr [r12 + {b_nested_l2_active}], 0
resident_telemetry_counter dec, {b_nested_l2_entry_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_l2_entry_was_resume}], 0
je .Lresident_nested_l2_launch_failure_counted
resident_telemetry_counter dec, {b_nested_l2_resume_count}, {b_telemetry_active}
.Lresident_nested_l2_launch_failure_counted:
resident_telemetry_counter inc, {b_nested_entry_rejection_count}, {b_telemetry_active}
test r10b, 1
jnz .Lresident_nested_l2_launch_fail_invalid
test r10b, 0x40
jz .Lresident_dispatch_halt
mov rax, {vm_instruction_error}
vmread r10, rax
jna .Lresident_dispatch_halt
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_l2_launch_fail_invalid:
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
jmp .Lresident_nested_vmfail_invalid_hardware
.Lresident_nested_restore_internal_msr_entry:
// Restore the root-switched MSRs captured at this internal exit.
// Replaying L1's entry list would overwrite state that L2 has already changed.
mov rax, {vm_entry_msr_load_addr}
mov r11, qword ptr [r12 + {b_nested_vmcs02_exit_store_msr_list}]
call .Lresident_nested_write_vmcs02_control
mov rax, {vm_entry_msr_load_count}
mov r11d, dword ptr [rip + matrixhv_resident_island_msr_switch_count]
call .Lresident_nested_write_vmcs02_control
ret
.Lresident_nested_l2_resume_ept:
call .Lresident_nested_restore_internal_msr_entry
// Internal EPT exits retry interrupted delivery, not an already delivered entry event.
mov rax, {idt_vectoring_info_field}
vmread r10, rax
jna .Lresident_dispatch_vmread_failed
bt r10d, 31
jc .Lresident_nested_l2_retry_event
xor r10d, r10d
jmp .Lresident_nested_l2_retry_event_ready
.Lresident_nested_l2_retry_event:
and r10d, 0x80000fff
bt r10d, 11
jnc .Lresident_nested_l2_retry_event_type
mov rax, {idt_vectoring_error_code}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov rax, {vm_entry_exception_error_code}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_l2_retry_event_type:
mov edx, r10d
and edx, 0x700
cmp edx, 0x200
jne .Lresident_nested_l2_retry_software_event
mov rax, {guest_interruptibility_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
btr r11, 3
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_l2_retry_event_ready
.Lresident_nested_l2_retry_software_event:
cmp edx, 0x400
jb .Lresident_nested_l2_retry_event_ready
cmp edx, 0x600
ja .Lresident_nested_l2_retry_event_ready
mov rax, {exit_instruction_len}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
mov rax, {vm_entry_instruction_len}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_l2_retry_event_ready:
mov rax, {vm_entry_intr_info_field}
vmwrite rax, r10
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_l2_resume:
cmp qword ptr [r12 + {b_nested_vmcs02_launched}], 0
je .Lresident_nested_l2_launch_registers
.Lresident_nested_l2_resume_registers:
call .Lresident_watchdog_handler_returned
call .Lresident_sync_ept_cache
call .Lresident_nested_refresh_eptp_list
call .Lresident_deliver_pending_nmi
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
pushfq
mov r12, qword ptr [rsp + 128]
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
call .Lresident_nested_restore_root_spec_ctrl
mov r10, qword ptr [rsp]
add rsp, 8
resident_telemetry_counter inc, {b_watchdog_sequence}, {b_telemetry_active}
resident_telemetry_counter inc, {b_watchdog_resume_failures}, {b_telemetry_active}
cmp qword ptr [r12 + {b_telemetry_active}], 0
je 991f
mov qword ptr [r12 + {b_watchdog_phase}], 2
991:
mov qword ptr [r12 + {b_nested_l2_active}], 0
resident_telemetry_counter dec, {b_nested_l2_entry_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_l2_entry_was_resume}], 0
je .Lresident_nested_l2_resume_failure_counted
resident_telemetry_counter dec, {b_nested_l2_resume_count}, {b_telemetry_active}
.Lresident_nested_l2_resume_failure_counted:
resident_telemetry_counter inc, {b_nested_entry_rejection_count}, {b_telemetry_active}
test r10b, 1
jnz .Lresident_nested_l2_resume_fail_invalid
test r10b, 0x40
jz .Lresident_dispatch_halt
mov rax, {vm_instruction_error}
vmread r10, rax
jna .Lresident_dispatch_halt
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_l2_resume_fail_invalid:
vmptrld [r12 + {b_nested_vmcs01_region}]
jna .Lresident_dispatch_halt
jmp .Lresident_nested_vmfail_invalid_hardware
.Lresident_dispatch_vmresume:
resident_telemetry_counter inc, {b_nested_vmresume_count}, {b_telemetry_active}
resident_telemetry_counter inc, {b_nested_entry_rejection_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
matrixhv_hyperv_evmcs_resume_selection
.Lresident_nested_vmresume_vmcs_ready:
cmp qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jne .Lresident_nested_vmfail_invalid_no_current_vmcs
cmp qword ptr [r12 + {b_nested_current_vmcs}], -1
je .Lresident_nested_vmfail_invalid_no_current_vmcs
mov rax, {guest_interruptibility_info}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 2
jnz .Lresident_nested_entry_mov_ss
cmp qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_launched}
jne .Lresident_nested_vmresume_non_launched
call .Lresident_nested_validate_entry
test r10d, r10d
jnz .Lresident_nested_vmfail_with_error
call .Lresident_nested_snapshot_vmcs01_effective_state
resident_telemetry_counter dec, {b_nested_entry_rejection_count}, {b_telemetry_active}
mov qword ptr [r12 + {b_nested_l2_entry_was_resume}], 1
mov qword ptr [r12 + {b_nested_l2_active}], 1
resident_telemetry_counter inc, {b_nested_l2_entry_count}, {b_telemetry_active}
resident_telemetry_counter inc, {b_nested_l2_resume_count}, {b_telemetry_active}
vmptrld [r12 + {b_nested_vmcs02_region}]
jna .Lresident_dispatch_halt
call .Lresident_nested_prepare_ept02
call .Lresident_nested_merge_vmcs02_controls
call .Lresident_nested_sync_vmcs02_guest_state
call .Lresident_nested_activate_vmcs02_ept
mov rax, {guest_rip}
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_rsp}
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {guest_rflags}
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
jmp .Lresident_nested_l2_resume
.Lresident_nested_entry_mov_ss:
mov r10d, {vm_entry_blocked_by_mov_ss_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_nested_vmresume_non_launched:
mov r10d, {vmresume_non_launched_vmcs_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_dispatch_exception:
mov rax, {exit_intr_info}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov r13, r11
test r11d, 0x80000000
jz .Lresident_dispatch_unsupported
and r11d, 0x7ff
cmp r11d, 0x202
je .Lresident_dispatch_nmi
cmp r11d, 0x306
jne .Lresident_dispatch_reinject_exception
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_dispatch_reinject_exception
mov r10, qword ptr [r12 + {b_nested_vmxon_region}]
mov rax, qword ptr [r12 + {b_last_guest_rip}]
cmp rax, qword ptr [r10 + {nested_invept_rip_offset}]
je .Lresident_dispatch_invept_software_prepare
cmp rax, qword ptr [r10 + {nested_invvpid_rip_offset}]
je .Lresident_dispatch_invvpid_software_prepare
.Lresident_dispatch_reinject_exception:
mov rax, {vm_entry_intr_info_field}
vmwrite rax, r13
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_dispatch_nmi:
mov qword ptr [r12 + {b_nmi_pending}], 1
resident_telemetry_counter inc, {b_nmi_count}, {b_telemetry_active}
.Lresident_dispatch_nmi_window:
mov eax, {cpu_based_vm_exec_control}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
btr r11, 22
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
cmp qword ptr [r12 + {b_nested_l2_active}], 0
je .Lresident_boot_timer_retry_event
mov qword ptr [r12 + {b_nested_vmcs02_launched}], 1
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid} + 8], 0
jmp .Lresident_nested_l2_resume_ept
.Lresident_dispatch_invept_software_prepare:
mov r11, qword ptr [r10 + {nested_invept_after_rip_offset}]
sub r11, qword ptr [r12 + {b_last_guest_rip}]
test r11, r11
jz .Lresident_dispatch_reinject_exception
cmp r11, 15
ja .Lresident_dispatch_reinject_exception
mov qword ptr [r12 + {b_last_instruction_len}], r11
jmp .Lresident_dispatch_invept
.Lresident_dispatch_invvpid_software_prepare:
mov r11, qword ptr [r10 + {nested_invvpid_after_rip_offset}]
sub r11, qword ptr [r12 + {b_last_guest_rip}]
test r11, r11
jz .Lresident_dispatch_reinject_exception
cmp r11, 15
ja .Lresident_dispatch_reinject_exception
mov qword ptr [r12 + {b_last_instruction_len}], r11
jmp .Lresident_dispatch_invvpid
.Lresident_dispatch_invept:
resident_telemetry_counter inc, {b_nested_invept_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
mov r10, qword ptr [r12 + {b_nested_vmxon_region}]
mov rax, qword ptr [r12 + {b_last_guest_rip}]
cmp rax, qword ptr [r10 + {nested_invept_rip_offset}]
je .Lresident_dispatch_invept_probe
mov eax, dword ptr [r12 + {b_last_reason}]
and eax, 0xffff
cmp eax, {invept_reason}
je .Lresident_dispatch_invept_hardware
jmp .Lresident_nested_inject_ud
.Lresident_dispatch_invept_probe:
resident_telemetry_counter inc, {b_nested_invept_software_count}, {b_telemetry_active}
mov r11, qword ptr [r12 + {b_nested_vmxon_operand}]
cmp qword ptr [rsp + 24], r11
jne .Lresident_nested_invalid_invalidation_operand
cmp qword ptr [rsp + 8], 1
jne .Lresident_nested_invalid_invalidation_operand
mov r10, qword ptr [r12 + {b_nested_vmxon_region}]
mov r11, qword ptr [r10 + {nested_invept_descriptor_offset}]
cmp r11, qword ptr [r12 + {b_nested_ept12_pointer}]
jne .Lresident_nested_invalid_invalidation_operand
cmp qword ptr [r10 + {nested_invept_descriptor_offset} + 8], 0
jne .Lresident_nested_invalid_invalidation_operand
mov r10, qword ptr [r12 + {b_nested_ept12_source_leaf}]
test r10, r10
jz .Lresident_nested_invalid_invalidation_operand
mov r11, qword ptr [r10]
mov rax, r11
and eax, 0xfff
cmp rax, qword ptr [r12 + {b_nested_ept12_source_leaf_attributes}]
jne .Lresident_nested_invalid_invalidation_operand
and r11, -4096
cmp r11, qword ptr [r12 + {b_nested_ept_target_gpa}]
je .Lresident_nested_invept_select_initial
cmp r11, qword ptr [r12 + {b_nested_ept_second_target_gpa}]
jne .Lresident_nested_invalid_invalidation_operand
mov r11, qword ptr [r12 + {b_nested_ept02_alternate_pointer}]
mov qword ptr [r12 + {b_nested_ept02_pointer}], r11
jmp .Lresident_nested_succeed
.Lresident_nested_invept_select_initial:
mov r11, qword ptr [r12 + {b_nested_ept02_initial_pointer}]
mov qword ptr [r12 + {b_nested_ept02_pointer}], r11
jmp .Lresident_nested_succeed
.Lresident_dispatch_invept_hardware:
mov rax, {exit_instruction_info}
vmread r13, rax
jna .Lresident_dispatch_vmread_failed
mov eax, r13d
shr eax, 28
and eax, 15
mov r15, rsp
call .Lresident_nested_read_gpr
mov r9, r11
mov qword ptr [r12 + {b_nested_last_vmcs_field}], r9
mov qword ptr [r12 + {b_nested_last_operand}], 0
cmp r9, 1
je .Lresident_dispatch_invept_hardware_decode
cmp r9, 2
jne .Lresident_nested_invalid_invalidation_operand
.Lresident_dispatch_invept_hardware_decode:
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_read
push r9
mov ecx, 16
call .Lresident_nested_read_operand_range
pop r9
jc .Lresident_nested_inject_pf_read
mov r11, qword ptr [r10]
mov qword ptr [r12 + {b_nested_last_operand}], r11
cmp r9, 2
je .Lresident_dispatch_invept_all_contexts
cmp qword ptr [r10 + 8], 0
jne .Lresident_nested_invalid_invalidation_operand
mov r14, qword ptr [r10]
mov r11, r14
and r11d, 0x3f
cmp r11d, 0x1e
jne .Lresident_nested_invalid_invalidation_operand
test r14, 0xf80
jnz .Lresident_nested_invalid_invalidation_operand
test r14b, 0x40
jz .Lresident_nested_invept_ad_ready
bt qword ptr [r12 + {b_nested_vmx_ept_vpid_cap}], 21
jnc .Lresident_nested_invalid_invalidation_operand
.Lresident_nested_invept_ad_ready:
mov r11, r14
and r11, -4096
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_invalid_invalidation_operand
// INVEPT identifies a context by EPTP[51:12], independent of A/D and MBEC.
// The operand names an L1 GPA; invalidation does not read that root page.
.Lresident_nested_invalidate_ept12_context:
mov rax, {host_page_address_mask}
and r14, rax
mov r11, qword ptr [r12 + {b_nested_ept12_pointer}]
and r11, rax
cmp r14, r11
jne .Lresident_dispatch_invept_cached_context
push r14
call .Lresident_nested_revalidate_ept02
pop r14
.Lresident_dispatch_invept_cached_context:
cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0
je .Lresident_nested_succeed
mov rax, {host_page_address_mask}
and rax, qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}]
cmp r14, rax
jne .Lresident_nested_succeed
call .Lresident_nested_swap_ept02_cache
call .Lresident_nested_revalidate_ept02
call .Lresident_nested_swap_ept02_cache
jmp .Lresident_nested_succeed
.Lresident_dispatch_invept_all_contexts:
// The EPTP in the descriptor does not select a context for global INVEPT.
cmp qword ptr [r10 + 8], 0
jne .Lresident_nested_invalid_invalidation_operand
call .Lresident_nested_revalidate_ept02
cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0
je .Lresident_nested_succeed
call .Lresident_nested_swap_ept02_cache
call .Lresident_nested_revalidate_ept02
call .Lresident_nested_swap_ept02_cache
jmp .Lresident_nested_succeed
.Lresident_dispatch_invvpid:
resident_telemetry_counter inc, {b_nested_invvpid_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
mov r10, qword ptr [r12 + {b_nested_vmxon_region}]
mov rax, qword ptr [r12 + {b_last_guest_rip}]
cmp rax, qword ptr [r10 + {nested_invvpid_rip_offset}]
je .Lresident_dispatch_invvpid_probe
mov eax, dword ptr [r12 + {b_last_reason}]
and eax, 0xffff
cmp eax, {invvpid_reason}
je .Lresident_dispatch_invvpid_hardware
jmp .Lresident_nested_inject_ud
.Lresident_dispatch_invvpid_probe:
resident_telemetry_counter inc, {b_nested_invvpid_software_count}, {b_telemetry_active}
mov r11, qword ptr [r12 + {b_nested_vmxon_operand}]
cmp qword ptr [rsp + 24], r11
jne .Lresident_nested_invalid_invalidation_operand
cmp qword ptr [rsp + 8], 1
jne .Lresident_nested_invalid_invalidation_operand
mov r10, qword ptr [r12 + {b_nested_vmxon_region}]
mov r11, qword ptr [r10 + {nested_invvpid_descriptor_offset}]
mov rax, r11
shr rax, 16
test rax, rax
jnz .Lresident_nested_invalid_invalidation_operand
test r11w, r11w
jz .Lresident_nested_invalid_invalidation_operand
cmp r11w, word ptr [r12 + {b_nested_vmcs12_vpid}]
jne .Lresident_nested_invalid_invalidation_operand
call .Lresident_nested_flush_vpid02
jmp .Lresident_nested_succeed
// A matching virtual tag invalidates only VMCS02's hardware translations.
.Lresident_dispatch_invvpid_hardware:
mov rax, {exit_instruction_info}
vmread r13, rax
jna .Lresident_dispatch_vmread_failed
mov eax, r13d
shr eax, 28
and eax, 15
mov r15, rsp
call .Lresident_nested_read_gpr
mov r9, r11
cmp r9, 3
ja .Lresident_nested_invalid_invalidation_operand
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_read
push r9
mov ecx, 16
call .Lresident_nested_read_operand_range
pop r9
jc .Lresident_nested_inject_pf_read
.Lresident_nested_invvpid_validate:
mov r11, qword ptr [r10]
mov rax, r11
shr rax, 16
test rax, rax
jnz .Lresident_nested_invalid_invalidation_operand
cmp r9, 2
je .Lresident_dispatch_invvpid_all_contexts
test r11w, r11w
jz .Lresident_nested_invalid_invalidation_operand
cmp r9, 0
je .Lresident_dispatch_invvpid_individual_address
jmp .Lresident_dispatch_invvpid_flush_context
.Lresident_dispatch_invvpid_individual_address:
mov rax, qword ptr [r10 + 8]
mov r11, rax
shl r11, 16
sar r11, 16
cmp rax, r11
jne .Lresident_nested_invalid_invalidation_operand
.Lresident_dispatch_invvpid_flush_context:
movzx r11d, word ptr [r10]
call .Lresident_nested_flush_vpid02
jmp .Lresident_nested_succeed
.Lresident_dispatch_invvpid_all_contexts:
mov r11d, 2
call .Lresident_nested_flush_vpid02_tag
mov r11d, 3
call .Lresident_nested_flush_vpid02_tag
jmp .Lresident_nested_succeed
.Lresident_nested_invalid_invalidation_operand:
mov r10d, {invalid_invalidation_operand_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_dispatch_vmxon:
resident_telemetry_counter inc, {b_nested_vmxon_count}, {b_telemetry_active}
mov r11, qword ptr [r12 + {b_nested_l1_cr4}]
test r11, 0x2000
jz .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
mov r11, qword ptr [r12 + {b_nested_feature_control}]
and r11d, 5
cmp r11d, 5
jne .Lresident_nested_inject_gp
cmp qword ptr [r12 + {b_nested_active}], 0
jne .Lresident_nested_vmxon_active
call .Lresident_nested_decode_memory_operand
jc .Lresident_nested_inject_pf_read
mov ecx, 8
call .Lresident_nested_read_operand_range
jc .Lresident_nested_inject_pf_read
mov r14, qword ptr [r12 + {b_nested_operand_linear_address}]
mov r11, qword ptr [r10]
mov qword ptr [r12 + {b_nested_last_operand}], r11
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_nested_vmfail_invalid_vmxon_address
call .Lresident_ept01_page_is_readable
test eax, eax
jz .Lresident_nested_vmfail_invalid_vmxon_address
mov edx, dword ptr [r11]
mov eax, dword ptr [r12 + {b_nested_vmx_basic}]
and eax, 0x7fffffff
cmp edx, eax
jne .Lresident_nested_vmfail_invalid_vmxon_revision
mov qword ptr [r12 + {b_nested_vmxon_operand}], r14
mov r11, qword ptr [r12 + {b_nested_last_operand}]
mov qword ptr [r12 + {b_nested_vmxon_region}], r11
mov qword ptr [r12 + {b_nested_active}], 1
mov dword ptr [r12 + {b_nested_vmcs02_vpid_cache}], 0
mov qword ptr [r12 + {b_nested_vmcs02_last_vpid}], 0
mov qword ptr [r12 + {b_nested_current_vmcs}], -1
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
call .Lresident_nested_shadow_intercept_reads
resident_hyperv_evmcs_reset
mov qword ptr [r12 + {b_nested_instruction_error}], 0
matrixhv_diagnostic_nested_vmxon
.Lresident_nested_vmxon_active:
mov r10d, {vmxon_in_vmx_root_error}
jmp .Lresident_nested_vmfail_with_error
.Lresident_dispatch_vmxoff:
resident_telemetry_counter inc, {b_nested_vmxoff_count}, {b_telemetry_active}
cmp qword ptr [r12 + {b_nested_active}], 1
jne .Lresident_nested_inject_ud
mov rax, {guest_cs_selector}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
test r11b, 3
jnz .Lresident_nested_inject_gp
mov rax, {exception_bitmap}
xor r11d, r11d
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
call .Lresident_nested_store_current_vmcs12
mov qword ptr [r12 + {b_nested_active}], 0
mov qword ptr [r12 + {b_nested_current_vmcs}], -1
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
resident_hyperv_evmcs_reset
mov qword ptr [r12 + {b_nested_instruction_error}], 0
mov qword ptr [r12 + {b_nested_probe_complete}], 1
call .Lresident_nested_shadow_intercept_reads
matrixhv_diagnostic_nested_vmxoff
.Lresident_nested_vmfail_with_error:
resident_telemetry_counter inc, {b_nested_failure_count}, {b_telemetry_active}
mov r8d, 1
call .Lresident_diagnostic_nested_record_failure
cmp qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jne .Lresident_nested_vmfail_invalid_flags
cmp qword ptr [r12 + {b_nested_current_vmcs}], -1
je .Lresident_nested_vmfail_invalid_flags
mov qword ptr [r12 + {b_nested_instruction_error}], r10
matrixhv_hyperv_evmcs_instruction_error
.Lresident_nested_vmfail_error_recorded:
mov rax, {guest_rflags}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
and r11, {vmx_status_flags_clear_mask}
or r11, {vmfail_valid_status}
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_nested_vmfail_invalid_no_current_vmcs:
mov r10d, 1
jmp .Lresident_nested_vmfail_invalid
.Lresident_nested_vmfail_invalid_vmxon_address:
mov r10d, 2
jmp .Lresident_nested_vmfail_invalid
.Lresident_nested_vmfail_invalid_vmxon_revision:
mov r10d, 3
jmp .Lresident_nested_vmfail_invalid
.Lresident_nested_vmfail_invalid_hardware:
mov r10d, 4
.Lresident_nested_vmfail_invalid:
resident_telemetry_counter inc, {b_nested_failure_count}, {b_telemetry_active}
mov r8d, 2
call .Lresident_diagnostic_nested_record_failure
.Lresident_nested_vmfail_invalid_flags:
mov rax, {guest_rflags}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
and r11, {vmx_status_flags_clear_mask}
or r11, {vmfail_invalid_status}
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_nested_succeed:
mov rax, {guest_rflags}
vmread r11, rax
jc .Lresident_dispatch_vmread_failed
jz .Lresident_dispatch_vmread_failed
mov r10, r11
and r11, {vmx_status_flags_clear_mask}
cmp r11, r10
je .Lresident_nested_success_flags_ready
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
.Lresident_nested_success_flags_ready:
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_nested_inject_pf_write:
mov r11d, 2
jmp .Lresident_nested_inject_pf
.Lresident_nested_inject_pf_read:
xor r11d, r11d
.Lresident_nested_inject_pf:
resident_telemetry_counter inc, {b_nested_failure_count}, {b_telemetry_active}
mov qword ptr [r12 + {b_nested_last_operand}], r10
mov r10, r11
mov r8d, 3
call .Lresident_diagnostic_nested_record_failure
mov r10, qword ptr [r12 + {b_nested_last_operand}]
mov cr2, r10
mov rax, {vm_entry_exception_error_code}
vmwrite rax, r11
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
mov rax, {vm_entry_intr_info_field}
mov r10d, 0x80000b0e
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_nested_inject_ud:
resident_telemetry_counter inc, {b_nested_failure_count}, {b_telemetry_active}
xor r10d, r10d
mov r8d, 4
call .Lresident_diagnostic_nested_record_failure
.Lresident_dispatch_inject_ud:
mov rax, {vm_entry_intr_info_field}
mov r10d, 0x80000306
vmwrite rax, r10
jc .Lresident_dispatch_vmwrite_failed
jz .Lresident_dispatch_vmwrite_failed
jmp .Lresident_dispatch_resume
.Lresident_nested_inject_gp:
resident_telemetry_counter inc, {b_nested_failure_count}, {b_telemetry_active}
xor r10d, r10d
mov r8d, 5
call .Lresident_diagnostic_nested_record_failure
jmp .Lresident_dispatch_inject_gp
matrixhv_diagnostic_nested_failure_trace
.endm

.macro matrixhv_resident_nested_tables
.balign 8
matrixhv_diagnostic_nested_failure_fields
matrixhv_hyperv_evmcs_field_map
.balign 8
.Lresident_vmcs12_field_index_table:
.byte 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 35, 36, 37, 38, 39, 40, 41, 42, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 43, 44, 45, 46, 47, 48, 49, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 93, 94, 18, 103, 104, 105, 117, 255, 17, 101, 102, 255, 118, 16, 255, 255
.byte 255, 255, 119, 120, 121, 255, 95, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 110, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 23, 24, 25, 26, 255, 111, 112, 113, 114, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 27, 28, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 100, 3
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 106, 107, 108, 109, 255, 115, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80
.byte 81, 82, 83, 84, 255, 85, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 88, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 19, 20, 21, 22, 96, 97, 98, 99, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 116, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 29, 30, 31, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 91, 255, 255
.byte 255, 92, 86, 87, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 32, 33, 34, 60, 61, 62, 63, 64, 89, 90, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.byte 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
.balign 8
.Lresident_guest_gpr_offsets:
.byte 0, 8, 16, 24, 0, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112
.balign 8
.Lresident_nested_guest_state_table:
.long 29, 0; .quad 0x6800
.long 30, 0; .quad 0x6802
.long 31, 0; .quad 0x6804
.long 35, 0; .quad 0x0800
.long 36, 0; .quad 0x0802
.long 37, 0; .quad 0x0804
.long 38, 0; .quad 0x0806
.long 39, 0; .quad 0x0808
.long 40, 0; .quad 0x080a
.long 41, 0; .quad 0x080c
.long 42, 0; .quad 0x080e
.long 50, 0; .quad 0x6806
.long 51, 0; .quad 0x6808
.long 52, 0; .quad 0x680a
.long 53, 0; .quad 0x680c
.long 54, 0; .quad 0x680e
.long 55, 0; .quad 0x6810
.long 56, 0; .quad 0x6812
.long 57, 0; .quad 0x6814
.long 58, 0; .quad 0x6816
.long 59, 0; .quad 0x6818
.long 65, 0; .quad 0x4800
.long 66, 0; .quad 0x4802
.long 67, 0; .quad 0x4804
.long 68, 0; .quad 0x4806
.long 69, 0; .quad 0x4808
.long 70, 0; .quad 0x480a
.long 71, 0; .quad 0x480c
.long 72, 0; .quad 0x480e
.long 73, 0; .quad 0x4810
.long 74, 0; .quad 0x4812
.long 75, 0; .quad 0x4814
.long 76, 0; .quad 0x4816
.long 77, 0; .quad 0x4818
.long 78, 0; .quad 0x481a
.long 79, 0; .quad 0x481c
.long 80, 0; .quad 0x481e
.long 81, 0; .quad 0x4820
.long 82, 0; .quad 0x4822
.long 83, 0; .quad 0x4824
.long 84, 0; .quad 0x4826
.long 85, 0; .quad 0x482a
.long 86, 0; .quad 0x6824
.long 87, 0; .quad 0x6826
.long 91, 0; .quad 0x681a
.long 92, 0; .quad 0x6822
.long 111, 0; .quad 0x280a
.long 112, 0; .quad 0x280c
.long 113, 0; .quad 0x280e
.long 114, 0; .quad 0x2810
.balign 8
.Lresident_nested_rare_guest_fields:
// Segment selectors, bases, limits, access rights, and pending debug state.
.quad {nested_rare_guest_fields_low}, {nested_rare_guest_fields_high}
.Lresident_nested_host_state_table:
.long 32, 0; .quad 0x6800
.long 33, 0; .quad 0x6802
.long 34, 0; .quad 0x6804
.long 43, 0; .quad 0x0800
.long 44, 0; .quad 0x0802
.long 45, 0; .quad 0x0804
.long 46, 0; .quad 0x0806
.long 47, 0; .quad 0x0808
.long 48, 0; .quad 0x080a
.long 49, 0; .quad 0x080e
.long 60, 0; .quad 0x680e
.long 61, 0; .quad 0x6810
.long 62, 0; .quad 0x6814
.long 63, 0; .quad 0x6816
.long 64, 0; .quad 0x6818
.long 88, 0; .quad 0x482a
.long 89, 0; .quad 0x6824
.long 90, 0; .quad 0x6826
.endm



// Inline L1 dispatch contract: r12 is the boot context and VMCS01 is current. Restores the L0 entry list after an L2 exit. Clobbers rax, r11 and flags; falls through or jumps to the VMCS write failure path.
.macro matrixhv_resident_nested_l1_msr_rearm
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
.endm

// Inline RDMSR routing contract: ecx is the guest MSR, r12 is the boot context, rsp is the saved guest frame. Compares only; branches to virtual VMX capability handlers or falls through. Preserves GPRs and changes flags.
.macro matrixhv_resident_nested_rdmsr_route
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
.endm

// VMX capability read contract: r12 identifies the cached virtual capabilities. Produces r11 for the MSR result packer, changing flags; denial injects GP without advancing RIP. The packer advances RIP only after a successful read.
.macro matrixhv_resident_nested_msr_values
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
.endm

// CPUID leaf-one base: load saved native ECX into R10D and hide VMX until nested exposure is applied. Changes R10/flags only; R12, guest frame, stack and SIMD stay intact.
.macro matrixhv_nested_cpuid_feature_base
mov r10d, dword ptr [rsp + 8]
and r10d, {cpuid_vmx_clear_mask}
.endm

// Nested CPUID exposure: R12=context, R10D=leaf-one features. Apply configured virtual VMX support, changing R10/flags only; preserve frame/stack/SIMD and fall through to Hyper-V presence policy.
.macro matrixhv_nested_cpuid_vmx_exposure
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_cpuid_vmx_ready
or r10d, {cpuid_vmx_set_mask}
.Lresident_dispatch_cpuid_vmx_ready:
.endm
