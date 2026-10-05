// Dispatch control requests use R12=context and RSP=saved guest GPR frame.
// Helpers may clobber scratch GPRs/flags, preserve the frame except explicit
// guest results, and branch to resume or common VMCS failure paths. VMREAD
// helper output is committed only after CF/ZF checks; offsets derive from Rust.
// The EFI variable bridge has its own native/runtime stack, 32-byte shadow
// space and FX save area. Activation/deactivation restores the recorded native
// GPR/flags/FPU state before crossing CR3/VMX boundaries. Patch slots and all
// return/checkpoint targets remain in the copied image; no allocator is used.
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
.macro matrixhv_island_requests
.Lresident_dispatch_memory:
// Packet address and byte count are carried in guest RDX and R8.
cmp qword ptr [r12 + {b_nested_l2_active}], 0
jne .Lresident_memory_unsupported
mov eax, {vm_entry_controls}
vmread rax, rax
jna .Lresident_dispatch_vmread_failed
test eax, 512
jz .Lresident_memory_unsupported
mov rax, qword ptr [r12 + {b_event_context}]
mov rax, qword ptr [rax + {event_memory_entry}]
test rax, rax
jz .Lresident_memory_unsupported
mov r13, rax
mov rdx, qword ptr [rsp + 16]
mov r8, qword ptr [rsp + 56]
lea rcx, [r12 + {b_memory_scratch}]
sub rsp, 648
fxsave64 [rsp + 128]
mov eax, {guest_cr3}
vmread rax, rax
jna .Lresident_memory_vmread_failed
mov qword ptr [rsp + 32], rax
mov eax, {guest_cr4}
vmread rax, rax
jna .Lresident_memory_vmread_failed
mov qword ptr [rsp + 40], rax
mov rax, qword ptr [r12 + {b_cache_ept_pointer}]
mov qword ptr [rsp + 48], rax
mov rax, cr3
mov qword ptr [rsp + 56], rax
push rcx
push rdx
mov ecx, {ia32_lstar}
rdmsr
shl rdx, 32
or rax, rdx
pop rdx
pop rcx
mov qword ptr [rsp + 64], rax
mov rax, qword ptr [r12 + {b_event_context}]
mov rax, qword ptr [rax + {event_memory_kernel_cr3}]
mov qword ptr [rsp + 72], rax
mov rax, qword ptr [r12 + {b_event_context}]
lea rax, [rax + {event_memory_root_history}]
mov qword ptr [rsp + 88], rax
push rcx
push rdx
mov eax, 0x80000008
cpuid
and eax, 255
pop rdx
pop rcx
mov qword ptr [rsp + 80], rax
mov rax, qword ptr [r12 + {b_event_context}]
mov rax, qword ptr [rax + {event_tracking_context}]
mov qword ptr [rsp + 96], rax
mov qword ptr [rsp + 104], r12
lea rax, [rip + .Lresident_memory_synchronize]
mov qword ptr [rsp + 112], rax
mov rax, qword ptr [r12 + {b_event_context}]
mov rax, qword ptr [rax + {event_interception_context}]
mov qword ptr [rsp + 120], rax
lea r9, [rsp + 32]
call r13
fxrstor64 [rsp + 128]
add rsp, 648
mov qword ptr [rsp + 16], rax
mov eax, {memory_signature}
mov qword ptr [rsp], rax
mov qword ptr [rsp + 8], 0
mov qword ptr [rsp + 24], 0
jmp .Lresident_dispatch_cpuid_advance
.Lresident_memory_vmread_failed:
fxrstor64 [rsp + 128]
add rsp, 648
jmp .Lresident_dispatch_vmread_failed
.Lresident_memory_unsupported:
mov qword ptr [rsp], 0
mov qword ptr [rsp + 16], 5
jmp .Lresident_dispatch_cpuid_advance
.Lresident_memory_synchronize:
// EFI-ABI callback into the shared EPT barrier; Rust may temporarily use R12.
push rbx
push rbp
push rsi
push rdi
push r12
push r13
push r14
push r15
sub rsp, 8
mov r12, rcx
cmp edx, 0
je .Lresident_memory_synchronize_acquire
cmp edx, 1
je .Lresident_memory_synchronize_flush
call .Lresident_nested_eptp_sync_end
mov eax, 1
jmp .Lresident_memory_synchronize_return
.Lresident_memory_synchronize_acquire:
call .Lresident_nested_eptp_sync_acquire
jmp .Lresident_memory_synchronize_return
.Lresident_memory_synchronize_flush:
call .Lresident_nested_eptp_sync_flush_local
mov eax, 1
.Lresident_memory_synchronize_return:
add rsp, 8
pop r15
pop r14
pop r13
pop r12
pop rdi
pop rsi
pop rbp
pop rbx
ret
.Lresident_interception_callback:
mov rax, qword ptr [r12 + {b_event_context}]
mov rax, qword ptr [rax + {event_interception_context}]
test rax, rax
jz .Lresident_interception_callback_idle
cmp edx, 3
je .Lresident_interception_callback_active
cmp qword ptr [rax], 1
je .Lresident_interception_callback_active
cmp qword ptr [r12 + {b_interception_controls}], 0
jne .Lresident_interception_callback_active
cmp qword ptr [r12 + {b_interception_debug_armed}], 0
jne .Lresident_interception_callback_active
cmp qword ptr [r12 + {b_interception_ept}], 0
jne .Lresident_interception_callback_active
cmp edx, 0
jne .Lresident_interception_callback_idle
cmp qword ptr [r12 + {b_interception_exit_ept}], 0
jne .Lresident_interception_callback_active
cmp qword ptr [r12 + {b_interception_exit_step}], 0
jne .Lresident_interception_callback_active
cmp qword ptr [r12 + {b_interception_exit_vmfunc}], 0
jne .Lresident_interception_callback_active
cmp qword ptr [r12 + {b_last_reason}], 48
jne .Lresident_interception_callback_idle
cmp qword ptr [r12 + {b_interception_hook_count}], 0
jne .Lresident_interception_callback_active
.Lresident_interception_callback_idle:
xor eax, eax
ret
.Lresident_interception_callback_active:
// Preserve EFI nonvolatile registers and guest SIMD state across the relocated
// Rust callback. R8 is the guest frame for dispatch; other phases ignore it.
push rbx
push rbp
push rsi
push rdi
push r12
push r13
push r14
push r15
mov rbp, rsp
and rsp, -16
sub rsp, 544
fxsave64 [rsp + 32]
mov rcx, r12
lea r9, [rip + .Lresident_memory_synchronize]
mov rax, qword ptr [r12 + {b_event_context}]
mov rax, qword ptr [rax + {event_interception_entry}]
test rax, rax
jz .Lresident_interception_callback_absent
call rax
jmp .Lresident_interception_callback_return
.Lresident_interception_callback_absent:
xor eax, eax
.Lresident_interception_callback_return:
fxrstor64 [rsp + 32]
mov rsp, rbp
pop r15
pop r14
pop r13
pop r12
pop rdi
pop rsi
pop rbp
pop rbx
cmp rax, -1
je .Lresident_dispatch_halt
ret
.Lresident_dispatch_update_l2_reject:
mov rax, 14
mov rdi, qword ptr [r12 + {b_event_context}]
mov dword ptr [rdi + {event_update_status} + {update_status_error}], eax
jmp .Lresident_update_return
.Lresident_dispatch_update:
call .Lresident_pt_leave
mov qword ptr [r12 + {b_pt_armed}], 0
mov r13, qword ptr [rip + matrixhv_resident_update_context]
test r13, r13
jz .Lresident_update_invalid
mov r8, qword ptr [r12 + {b_processor_number}]
cmp r8, 64
jae .Lresident_update_invalid
mov r15, qword ptr [rsp + 16]
cmp r15, {update_request_size}
jb .Lresident_update_invalid
cmp r15, {update_buffer_size}
ja .Lresident_update_invalid
mov r14, qword ptr [rsp + 8]
mov rax, r14
add rax, r15
jc .Lresident_update_invalid
imul r8, {update_buffer_size}
lea rbp, [r13 + r8 + {update_context_scratch}]
.Lresident_update_copy_page:
mov r10, r14
mov edx, 1
call .Lresident_nested_translate_linear_address
jc .Lresident_update_invalid
mov r11, r10
mov edx, 1
call .Lresident_ept01_page_translate
test eax, eax
jz .Lresident_update_invalid
mov ebx, r14d
and ebx, 4095
neg ebx
add ebx, 4096
cmp rbx, r15
cmova rbx, r15
mov rcx, rbx
mov rsi, r11
mov rdi, rbp
cld
rep movsb
add rbp, rbx
add r14, rbx
sub r15, rbx
jnz .Lresident_update_copy_page
mov r9, qword ptr [r12 + {b_processor_number}]
mov rdx, r9
imul rdx, {update_buffer_size}
lea rdx, [r13 + rdx + {update_context_scratch}]
mov rdi, qword ptr [r12 + {b_event_context}]
mov eax, dword ptr [rdi + {event_control_apic_ids} + r9 * 4]
cmp eax, dword ptr [rdx + 24]
jne .Lresident_update_invalid
mov r8, qword ptr [rsp + 16]
mov rcx, r13
sub rsp, 584
fxsave64 [rsp + 64]
lea rax, [rip + matrixhv_resident_core_identity]
mov qword ptr [rsp + 32], rax
mov dword ptr [rsp + 40], 0
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
jne .Lresident_update_hyperv_blocker
cmp qword ptr [r12 + {b_nested_active}], 0
je .Lresident_update_call
cmp qword ptr [rdi + {event_hyperv_guest_os_id}], 0
je .Lresident_update_call
.Lresident_update_hyperv_blocker:
mov dword ptr [rsp + 40], 15
.Lresident_update_call:
call qword ptr [rip + matrixhv_resident_update_loader]
fxrstor64 [rsp + 64]
add rsp, 584
test eax, eax
jnz .Lresident_update_return
call .Lresident_update_apply_msr_policy
jmp .Lresident_update_return
.Lresident_update_invalid:
mov eax, 1
.Lresident_update_return:
mov qword ptr [rsp], rax
mov rax, {update_result}
mov qword ptr [rsp + 16], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_update_apply_msr_policy:
// Update banks retain the boot bitmap. Change its policy only after all CPUs
// have verified the new core, so incomplete activation preserves the old policy.
cmp dword ptr [r13 + {update_context_phase}], 5
jne .Lresident_update_msr_policy_done
mov r11, qword ptr [r12 + {b_nested_l0_msr_bitmap}]
test r11, r11
jz .Lresident_update_msr_policy_done
// VMCS02 still ORs L1 intercepts into its separate composed bitmap.
lock and byte ptr [r11 + {hwp_request_write_byte}], {hwp_request_write_mask}
.Lresident_update_msr_policy_done:
ret
.Lresident_update_retire_nested:
push rbx
push rbp
push rsi
push rdi
push r13
push r14
push r15
cmp qword ptr [r12 + {b_nested_l2_active}], 0
jne .Lresident_update_retire_failed
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
jne .Lresident_update_retire_failed
cmp qword ptr [r12 + {b_nested_active}], 0
je .Lresident_update_retire_clear
cmp qword ptr [rdi + {event_hyperv_guest_os_id}], 0
jne .Lresident_update_retire_failed
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
cmp r11, -1
je .Lresident_update_retire_store
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_update_retire_failed
.Lresident_update_retire_store:
call .Lresident_nested_store_current_vmcs12
mov eax, {cr4_read_shadow}
vmread r11, rax
jna .Lresident_update_retire_failed
and r11, ~{cr4_vmxe}
vmwrite rax, r11
jna .Lresident_update_retire_failed
and qword ptr [r12 + {b_nested_l1_cr4}], ~{cr4_vmxe}
.Lresident_update_retire_clear:
vmclear qword ptr [r12 + {b_nested_vmcs02_region}]
jna .Lresident_update_retire_failed
cmp qword ptr [r12 + {b_nested_shadow_vmcs_region}], 0
je .Lresident_update_retire_reset
vmclear qword ptr [r12 + {b_nested_shadow_vmcs_region}]
jna .Lresident_update_retire_failed
.Lresident_update_retire_reset:
mov qword ptr [r12 + {b_nested_active}], 0
mov qword ptr [r12 + {b_nested_current_vmcs}], -1
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
mov qword ptr [r12 + {b_nested_vmxon_region}], 0
mov qword ptr [r12 + {b_nested_vmcs02_launched}], 0
mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], 0
mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending} + 8], 0
mov qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid} + 8], 0
mov dword ptr [r12 + {b_nested_vmcs02_vpid_cache}], 0
mov qword ptr [r12 + {b_nested_vmcs02_last_vpid}], 0
mov eax, {exception_bitmap}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_update_retire_failed
resident_hyperv_evmcs_reset
call .Lresident_nested_shadow_intercept_reads
pop r15
pop r14
pop r13
pop rdi
pop rsi
pop rbp
pop rbx
clc
ret
.Lresident_update_retire_failed:
pop r15
pop r14
pop r13
pop rdi
pop rsi
pop rbp
pop rbx
stc
ret
.Lresident_nested_update_gate:
mov rax, qword ptr [rip + matrixhv_resident_update_context]
test rax, rax
jz .Lresident_nested_update_allowed
mov eax, dword ptr [rax + {update_context_phase}]
cmp eax, 2
jb .Lresident_nested_update_allowed
cmp eax, 4
jbe .Lresident_nested_update_frozen
cmp eax, 6
je .Lresident_nested_update_frozen
.Lresident_nested_update_allowed:
clc
ret
.Lresident_nested_update_frozen:
stc
ret
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
mov edx, 2
call .Lresident_interception_callback
mov edx, 1
call .Lresident_interception_callback
call .Lresident_interception_safe_point_timer
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
mov r13, qword ptr [rip + matrixhv_resident_update_context]
test r13, r13
jz .Lresident_control_off_nested_guard
cmp dword ptr [r13 + {update_context_phase}], 3
jne .Lresident_control_off_nested_guard
mov rax, qword ptr [rsp + 8]
cmp rax, qword ptr [r13 + {update_context_transaction}]
jne .Lresident_control_off_failed
call .Lresident_update_retire_nested
jc .Lresident_control_off_failed
.Lresident_control_off_nested_guard:
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
mov rax, qword ptr [r12 + {b_nested_vmcs02_region}]
mov qword ptr [rsi + {control_cpu_vmcs02_region}], rax
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
mov r11, qword ptr [rdi + {event_control_off_native_rip}]
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
.endm

.macro matrixhv_island_bridge
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
sub rsp, 80
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
lea rdx, [rbx + {event_control_off_native_rip}]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rbx + {event_control_recovery_runtime}]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rbx + {event_update_loader_runtime}]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rbx + {event_update_context_runtime}]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
lea rdx, [rbx + {event_update_image_runtime}]
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
mov rax, qword ptr [rbx + {event_update_relocations_start}]
add rax, qword ptr [rbx + {event_update_image_physical}]
mov qword ptr [rsp + 48], rax
mov rax, qword ptr [rbx + {event_update_relocations_end}]
add rax, qword ptr [rbx + {event_update_image_physical}]
mov qword ptr [rsp + 64], rax
.Lresident_va_image_block:
mov rdx, qword ptr [rsp + 48]
cmp rdx, qword ptr [rsp + 64]
jae .Lresident_va_image_done
mov eax, dword ptr [rdx]
mov qword ptr [rsp + 72], rax
mov eax, dword ptr [rdx + 4]
cmp eax, 8
jb .Lresident_va_image_invalid
test al, 1
jnz .Lresident_va_image_invalid
add rax, rdx
cmp rax, qword ptr [rsp + 64]
ja .Lresident_va_image_invalid
mov qword ptr [rsp + 56], rax
add qword ptr [rsp + 48], 8
.Lresident_va_image_pointer:
mov rdx, qword ptr [rsp + 48]
cmp rdx, qword ptr [rsp + 56]
jae .Lresident_va_image_block
movzx eax, word ptr [rdx]
add qword ptr [rsp + 48], 2
mov edx, eax
shr edx, 12
test edx, edx
jz .Lresident_va_image_pointer
cmp edx, 10
jne .Lresident_va_image_invalid
and eax, 4095
add rax, qword ptr [rsp + 72]
lea rdx, [rax + 8]
cmp rdx, qword ptr [rbx + {event_update_image_bytes}]
ja .Lresident_va_image_invalid
add rax, qword ptr [rbx + {event_update_image_physical}]
mov rdx, rax
xor ecx, ecx
call qword ptr [rip + matrixhv_resident_convert_pointer]
test rax, rax
jnz .Lresident_va_failed
jmp .Lresident_va_image_pointer
.Lresident_va_image_invalid:
movabs rax, 0x8000000000000003
jmp .Lresident_va_failed
.Lresident_va_image_done:
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
add rsp, 80
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
mov dword ptr [r10 + {bridge_status_capabilities}], 7
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
push rsi
push rdi
lea rsi, [r11 + {event_update_status}]
lea rdi, [r10 + {bridge_status_update}]
mov ecx, {update_status_qwords}
cld
rep movsq
lea rsi, [r11 + {event_update_public_key}]
lea rdi, [r10 + {bridge_status_public_key}]
mov ecx, 4
rep movsq
lea rsi, [r11 + {event_update_abi}]
lea rdi, [r10 + {bridge_status_update_abi}]
mov ecx, 3
rep movsq
pop rdi
pop rsi
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
cmp r9, {update_request_size}
jae .Lresident_set_variable_update
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
.Lresident_set_variable_update:
cmp r9, {update_buffer_size}
ja .Lresident_bridge_invalid_parameter
mov r10, qword ptr [rsp + 40]
test r10, r10
jz .Lresident_bridge_invalid_parameter
mov r11, qword ptr [rip + matrixhv_resident_bridge_context]
test r11, r11
jz .Lresident_bridge_unsupported
cmp qword ptr [r11 + {event_ebs_seen}], 1
jne .Lresident_bridge_unsupported
cmp qword ptr [r11 + {event_va_seen}], 1
jne .Lresident_bridge_unsupported
cmp qword ptr [r11 + {event_control_va_error}], 0
jne .Lresident_bridge_unsupported
push rbx
call .Lresident_bridge_apic_id
pop rbx
cmp eax, dword ptr [r10 + 24]
jne .Lresident_bridge_unsupported
xor r8d, r8d
.Lresident_update_bridge_find:
cmp eax, dword ptr [r11 + {event_control_apic_ids} + r8 * 4]
je .Lresident_update_bridge_ready
inc r8d
cmp r8d, 64
jb .Lresident_update_bridge_find
jmp .Lresident_bridge_unsupported
.Lresident_update_bridge_ready:
bt qword ptr [r11 + {event_control_failed_mask}], r8
jc .Lresident_bridge_unsupported
bt qword ptr [r11 + {event_control_active_mask}], r8
jnc .Lresident_update_bridge_native
mov rcx, r10
mov rdx, r9
mov rax, {update_vmcall}
vmcall
mov r11, {update_result}
cmp rdx, r11
jne .Lresident_bridge_unsupported
test rax, rax
jnz .Lresident_bridge_unsupported
ret
.Lresident_update_bridge_native:
bt qword ptr [r11 + {event_control_stopped_mask}], r8
jnc .Lresident_bridge_unsupported
mov rax, r8
imul rax, {control_cpu_state_size}
lea rax, [r11 + rax + {event_control_cpu_states}]
cmp qword ptr [rax + {control_cpu_phase}], 2
jne .Lresident_bridge_unsupported
push r12
mov r12, rsp
mov rsp, qword ptr [rax + {control_cpu_native_storage_runtime}]
add rsp, {native_stack_bytes} - 576
fxsave64 [rsp + 64]
mov qword ptr [rsp + 32], r11
mov qword ptr [rsp + 40], 0
mov rcx, qword ptr [r11 + {event_update_context_runtime}]
mov rdx, r10
mov rax, r9
mov r9, r8
bts r9, 63
mov r8, rax
call qword ptr [r11 + {event_update_loader_runtime}]
fxrstor64 [rsp + 64]
mov rsp, r12
pop r12
test rax, rax
jnz .Lresident_bridge_unsupported
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
.globl matrixhv_resident_control_off_native
matrixhv_resident_control_off_native:
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
mov rax, qword ptr [r10 + {event_control_recovery_physical}]
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
cmp qword ptr [r9 + {control_cpu_vmcs02_region}], 0
je .Lresident_control_on_primary_vmcs
vmclear qword ptr [r9 + {control_cpu_vmcs02_region}]
jna .Lresident_control_on_root_failed
vmptrld qword ptr [r9 + {control_cpu_vmcs02_region}]
jna .Lresident_control_on_root_failed
resident_control_on_restore_host {host_rip}, 21
resident_control_on_restore_host {host_idtr_base}, 16
.Lresident_control_on_primary_vmcs:
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
mov rax, qword ptr [r15 + {event_control_recovery_runtime}]
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
mov qword ptr [r12 + {b_root_vmx_active}], 0
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
.globl matrixhv_resident_control_recovery_switch
matrixhv_resident_control_recovery_switch:
mov cr3, r11
jmp rax
.Lresident_control_on_native_restore:
.globl matrixhv_resident_control_native_restore
matrixhv_resident_control_native_restore:
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
.endm

.macro matrixhv_island_slots
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
.endm

// Inline dispatch contract: r12 is the boot context, r11 is the exit reason. Clobbers rax, rcx, rdi, r11 and flags; preserves the saved guest frame. Entry failure transfers to control recovery; success falls through.
.macro matrixhv_island_control_rearm
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
.endm

// Inline failed-resume contract: all guest GPRs are saved at rsp, r12 is the boot context. Restores the control-off host VMCS and retries only an armed phase-one transition. Clobbers scratch GPRs and flags; jumps to resume or falls through to normal failure reporting.
.macro matrixhv_island_control_resume_recovery
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
.endm
