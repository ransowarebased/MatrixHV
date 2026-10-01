// Dispatch observations use R12=context and retain the guest frame at RSP.
// Internal painters/serial helpers may clobber scratch GPRs/flags; local
// push/pop pairs balance the stack and use neither firmware nor SIMD.
// Serial write consumes RSI=message, R9=length; hex output consumes RAX=value.
// Shared event fields use event_* ABI offsets and bounded resident buffers.
// The visual callback alone enters EFI code before EBS: it aligns RSP to 16,
// reserves shadow space and saves/restores FX state. Fatal entries never return.
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
.macro matrixhv_island_observation
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
.endm

.macro matrixhv_island_sampling
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
.Lresident_sample_framebuffer_on_exit:
// Nested hosts may omit the VMX timer. Sample ordinary L1 exits without telemetry.
cmp qword ptr [r12 + {b_diagnostic_interval}], 0
jne .Lresident_sample_framebuffer_done
cmp qword ptr [r12 + {b_diagnostic_expired}], 0
jne .Lresident_sample_framebuffer_done
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_framebuffer_sink}
jz .Lresident_sample_framebuffer_done
cmp qword ptr [r12 + {b_processor_number}], 0
jne .Lresident_sample_framebuffer_done
cmp qword ptr [r12 + {b_nested_l2_active}], 0
jne .Lresident_sample_framebuffer_done
mov r8, qword ptr [r12 + {b_event_context}]
test r8, r8
jz .Lresident_sample_framebuffer_done
cmp qword ptr [r8 + {event_ebs_seen}], 0
je .Lresident_sample_framebuffer_done
call .Lresident_framebuffer_active
jnc .Lresident_sample_framebuffer_expired
cmp qword ptr [r8 + {event_visual_base}], 0
je .Lresident_sample_framebuffer_expired
cmp qword ptr [r8 + {event_diagnostic_halted}], 0
jne .Lresident_sample_framebuffer_done
rdtsc
shl rdx, 32
or rax, rdx
cmp rax, qword ptr [r12 + {b_diagnostic_deadline}]
jb .Lresident_sample_framebuffer_done
add rax, qword ptr [r8 + {event_tsc_hz}]
mov qword ptr [r12 + {b_diagnostic_deadline}], rax
inc qword ptr [r12 + {b_diagnostic_samples}]
jmp .Lresident_diagnostic_snapshot
.Lresident_sample_framebuffer_expired:
mov qword ptr [r12 + {b_diagnostic_expired}], 1
.Lresident_sample_framebuffer_done:
ret
.endm

.macro matrixhv_island_profile
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
.endm

.macro matrixhv_island_visual_callback
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
.endm

.macro matrixhv_island_output
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
.endm

.macro matrixhv_island_log_slot
.globl matrixhv_resident_island_log_backend
matrixhv_resident_island_log_backend:
.byte 0
.balign 8
.endm

.macro matrixhv_island_visual_slot
.globl matrixhv_resident_island_visual_callback
matrixhv_resident_island_visual_callback:
.quad 0
.endm

// Inline dispatch contract: r12 owns the boot context; rsp addresses the saved guest frame. Records only pre-EBS BSP diagnostics. Clobbers volatile scratch registers and flags; falls through without changing guest registers.
.macro matrixhv_island_first_exit_visual
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
.endm

// Inline dispatch contract: r12 is the boot context and the guest GPR frame remains at rsp. Validates shared event canaries and emits bounded lifecycle observations. Clobbers scratch GPRs and flags; falls through or jumps to fatal event diagnostics.
.macro matrixhv_island_event_observation
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
.endm

// Terminal dispatch contract: r12 is the failed boot context. Atomically publishes the first CPU failure and emits diagnostics without firmware after EBS. Clobbers scratch registers and flags; always reaches the halt loop.
.macro matrixhv_island_halt_observation
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
.endm

// Unhandled GP contract: rsp contains saved rdx, saved rax, error code and hardware RIP. r8 receives the retained event context. Atomically claims the diagnostic and transfers to terminal host-fault output; clobbers scratch GPRs and flags and never returns.
.macro matrixhv_island_gp_diagnostic
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
.endm

// Terminal host-fault contract: direct entry disables interrupts and claims shared output; the owned entry accepts r8 as the event context. Uses retained framebuffer/serial state only, clobbers scratch GPRs and flags, and halts permanently.
.macro matrixhv_island_host_fatal
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
.endm

// Boot sampling contract: r12 is the boot context, rsp retains the guest frame. Updates deadlines and retires the instrumentation timer when the framebuffer window expires. Clobbers scratch GPRs/flags and branches to the dispatcher event-retry path; it never advances guest RIP.
.macro matrixhv_island_boot_timer
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
.endm

// Nested failed-entry dump: R12=context, intact dispatcher frame at RSP. Reads VMCS02 and owner-provided eVMCS status for serial output. Scratch GPRs/flags change, stack and SIMD remain intact; disabled serial skips to the nested reflection continuation.
.macro matrixhv_diagnostic_nested_entry_failure
.Lresident_nested_l2_failure_dump:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz .Lresident_nested_l2_reflect_after_failure_dump
lea rsi, [rip + .Lnested_entry_failure_dump_message]
mov r9d, {nested_entry_failure_dump_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]
call .Lresident_serial_hex64
mov al, 0x20
call .Lresident_serial_char
mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]
call .Lresident_serial_hex64
mov al, 0x20
call .Lresident_serial_char
mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]
call .Lresident_serial_hex64
mov al, 0x20
call .Lresident_serial_char
mov rax, qword ptr [r12 + {b_last_qualification}]
call .Lresident_serial_hex64
mov r14d, 0
lea r15, [r12 + {b_nested_vmcs12_extended_fields}]
.Lresident_nested_l2_failure_dump_field:
mov al, 0x20
call .Lresident_serial_char
mov rax, qword ptr [r15 + r14 * 8]
call .Lresident_serial_hex64
inc r14d
cmp r14d, {nested_extended_field_count}
jne .Lresident_nested_l2_failure_dump_field
mov al, 0x0a
call .Lresident_serial_char
lea rsi, [rip + .Lnested_vmcs02_failure_dump_message]
mov r9d, {nested_vmcs02_failure_dump_message_len}
call .Lresident_serial_write
matrixhv_hyperv_evmcs_diagnostic_value
call .Lresident_serial_hex64
lea r15, [rip + .Lresident_nested_failure_vmcs_fields]
.Lresident_nested_l2_failure_dump_hardware_field:
mov al, 0x20
call .Lresident_serial_char
mov rax, qword ptr [r15]
vmread r14, rax
mov rax, r14
call .Lresident_serial_hex64
add r15, 8
lea rax, [rip + .Lresident_nested_failure_vmcs_fields_end]
cmp r15, rax
jne .Lresident_nested_l2_failure_dump_hardware_field
mov al, 0x0a
call .Lresident_serial_char
.endm

// Nested reflected-exit observation: R12=context, complete guest frame at RSP. Rate-limit presentation using existing counters, emit CPU/reason/RIP and jump to dispatch resume. Scratch GPRs/flags change; no VMCS or virtualization policy changes.
.macro matrixhv_diagnostic_nested_exit
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_resume
mov rax, qword ptr [r12 + {b_nested_l2_exit_count}]
cmp rax, 32
jbe .Lresident_nested_l2_log_exit
lea rdx, [rax - 1]
test rax, rdx
jnz .Lresident_dispatch_resume
.Lresident_nested_l2_log_exit:
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz .Lresident_dispatch_resume
lea rsi, [rip + .Lnested_l2_exit_message]
mov r9d, {nested_l2_exit_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_processor_number}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_reason]
mov r9d, {state_reason_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_nested_l2_last_exit_reason}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_rip]
mov r9d, {state_rip_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_nested_l2_last_exit_rip}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_newline]
mov r9d, {state_newline_len}
call .Lresident_serial_write
jmp .Lresident_dispatch_resume
.endm

// VMCS12 probe observation: R12=context, R11=guest RIP, R13=instruction operands. Preserve R13 with one balanced push/pop and reload R11 after serial output; other scratch GPRs/flags change. Disabled output jumps directly to the nested result packer.
.macro matrixhv_diagnostic_vmcs12_probe
test byte ptr [rip + matrixhv_resident_island_log_backend], {log_serial_sink}
jz .Lresident_nested_vmread_value
push r13
lea rsi, [rip + .Lnested_vmcs12_message]
mov r9d, {nested_vmcs12_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_processor_number}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lnested_region_message]
mov r9d, {nested_region_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_nested_vmcs12_region}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lnested_value_message]
mov r9d, {nested_value_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_newline]
mov r9d, {state_newline_len}
call .Lresident_serial_write
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]
pop r13
.endm

// VMXON probe observation: R12=context and dispatcher frame intact. Emit only when the guest proof requests collection, then jump to nested success. Scratch GPRs/flags change; ordinary runtime VMXON avoids synchronous UART stalls.
.macro matrixhv_diagnostic_nested_vmxon
// Synchronous UART output here stalls L1's preemption-disabled VMX entry path.
cmp qword ptr [r12 + {b_telemetry_probe_active}], 0
je .Lresident_nested_succeed
lea rsi, [rip + .Lnested_vmxon_message]
mov r9d, {nested_vmxon_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_processor_number}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lnested_pointer_message]
mov r9d, {nested_pointer_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_nested_last_operand}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_rip]
mov r9d, {state_rip_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_last_guest_rip}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_newline]
mov r9d, {state_newline_len}
call .Lresident_serial_write
jmp .Lresident_nested_succeed
.endm

// VMXOFF probe observation: same state/frame/clobber contract as VMXON; emit the completed transition without changing virtualization state, then jump to nested success.
.macro matrixhv_diagnostic_nested_vmxoff
cmp qword ptr [r12 + {b_telemetry_probe_active}], 0
je .Lresident_nested_succeed
lea rsi, [rip + .Lnested_vmxoff_message]
mov r9d, {nested_vmxoff_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_processor_number}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lnested_pointer_message]
mov r9d, {nested_pointer_message_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_nested_last_operand}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_rip]
mov r9d, {state_rip_len}
call .Lresident_serial_write
mov rax, qword ptr [r12 + {b_last_guest_rip}]
call .Lresident_serial_hex64
lea rsi, [rip + .Lstate_newline]
mov r9d, {state_newline_len}
call .Lresident_serial_write
jmp .Lresident_nested_succeed
.endm

// Bounded failure capture: R12=context, R8=kind, R10=detail. Preserve RAX/RCX/RDX/R9 with four balanced push/pop pairs; preserve other GPRs/SIMD, change flags, and RET. Records guest operands and classifies only diagnostic metadata; no architectural VMfail or injection decisions occur here.
.macro matrixhv_diagnostic_nested_failure_trace
.Lresident_diagnostic_nested_record_failure:
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_diagnostic_nested_record_failure_done
push rax
push rcx
push rdx
push r9
mov rax, qword ptr [r12 + {b_nested_failure_count}]
dec rax
cmp rax, {nested_failure_trace_capacity}
jae .Lresident_diagnostic_nested_record_failure_saved
imul rax, 48
lea r9, [r12 + {b_nested_failure_trace}]
add r9, rax
mov rax, qword ptr [r12 + {b_last_guest_rip}]
mov qword ptr [r9], rax
mov rax, qword ptr [r12 + {b_last_reason}]
mov qword ptr [r9 + 8], rax
mov rcx, r8
cmp ecx, 1
jne .Lresident_diagnostic_nested_record_failure_kind_ready
cmp qword ptr [r12 + {b_nested_current_vmcs}], -1
jne .Lresident_diagnostic_nested_record_failure_kind_ready
mov ecx, 6
.Lresident_diagnostic_nested_record_failure_kind_ready:
mov qword ptr [r9 + 16], rcx
mov qword ptr [r9 + 24], r10
mov rax, qword ptr [r12 + {b_nested_last_vmcs_field}]
mov qword ptr [r9 + 32], rax
mov rax, qword ptr [r12 + {b_nested_last_operand}]
mov qword ptr [r9 + 40], rax
.Lresident_diagnostic_nested_record_failure_saved:
pop r9
pop rdx
pop rcx
pop rax
.Lresident_diagnostic_nested_record_failure_done:
ret
.endm

// RIP-relative VMCS02 diagnostic field list, bounded by its end label. Data only, expanded at the original aligned table position.
.macro matrixhv_diagnostic_nested_failure_fields
.Lresident_nested_failure_vmcs_fields:
// Actual VMCS02 state distinguishes translation errors from invalid L1 input.
.quad 0x4402, 0x4012, 0x4016, 0x6820, 0x4824, 0x4826
.quad 0x2806, 0x6800, 0x6802, 0x6804, 0x681e, 0x2800
.quad 0x4814, 0x4816, 0x4818, 0x481a, 0x481c, 0x481e, 0x4820, 0x4822
.Lresident_nested_failure_vmcs_fields_end:
.endm

// Resident nested diagnostic messages; no executable state or stack effects.
.macro matrixhv_resident_nested_entry_failure_message
.Lnested_entry_failure_dump_message:
.ascii "[MATRIXHV][NESTED] VM_ENTRY_FAILURE_VMCS12 "
.Lnested_entry_failure_dump_message_end:
.Lnested_vmcs02_failure_dump_message:
.ascii "[MATRIXHV][NESTED] VM_ENTRY_FAILURE_VMCS02 "
.Lnested_vmcs02_failure_dump_message_end:
.endm

// Resident nested diagnostic messages; no executable state or stack effects.
.macro matrixhv_resident_nested_messages
.Lnested_vmxon_message:
.ascii "[MATRIXHV][NESTED] VMXON cpu=0x"
.Lnested_vmxon_message_end:
.Lnested_vmxoff_message:
.ascii "[MATRIXHV][NESTED] VMXOFF cpu=0x"
.Lnested_vmxoff_message_end:
.Lnested_pointer_message:
.ascii " pointer=0x"
.Lnested_pointer_message_end:
.Lnested_failure_message:
.ascii "[MATRIXHV][NESTED] PROBE_FAILED"
.Lnested_failure_message_end:
.Lnested_vmcs12_message:
.ascii "[MATRIXHV][NESTED] VMCS12 cpu=0x"
.Lnested_vmcs12_message_end:
.Lnested_region_message:
.ascii " region=0x"
.Lnested_region_message_end:
.Lnested_value_message:
.ascii " value=0x"
.Lnested_value_message_end:
.Lnested_l2_exit_message:
.ascii "[MATRIXHV][NESTED] L2_EXIT cpu=0x"
.Lnested_l2_exit_message_end:
.endm

// Inline serial primitives: R12=context, RSI=message and R9=length are scratch.
// State output also clobbers RAX and helper scratch GPRs/flags. Each call balances
// its return stack, preserves R12/guest frame/SIMD, and returns to its caller.
.macro resident_diagnostic_message message, length
lea rsi, [rip + \message]
mov r9d, \length
call .Lresident_serial_write
.endm
.macro resident_diagnostic_state message, length
resident_diagnostic_message \message, \length
call .Lresident_serial_state
.endm

// Expected EPT probe observation: R12=context, guest frame intact. Emit GPA/RIP/qualification; scratch GPRs/flags change, root stack/SIMD unchanged. Fall through so exits.S alone chooses the new RIP and resumption.
.macro matrixhv_diagnostic_ept_probe
resident_diagnostic_message .Lept_test_violation_message, {ept_test_violation_message_len}
mov rax, qword ptr [r12 + {b_last_guest_physical_address}]
call .Lresident_serial_hex64
resident_diagnostic_message .Lept_violation_rip, {ept_violation_rip_len}
mov rax, qword ptr [r12 + {b_last_guest_rip}]
call .Lresident_serial_hex64
resident_diagnostic_message .Lept_violation_read, {ept_violation_read_len}
mov rax, qword ptr [r12 + {b_last_qualification}]
call .Lresident_serial_hex64
resident_diagnostic_message .Lstate_newline, {state_newline_len}
.endm

// Unexpected EPT observation: R12=context, guest frame intact. Emit GPA and saved state; scratch GPRs/flags change, stack/SIMD unchanged. Fall through to the dispatcher-owned terminal decision.
.macro matrixhv_diagnostic_ept_unexpected
resident_diagnostic_message .Lept_unexpected_violation_message, {ept_unexpected_violation_message_len}
mov rax, qword ptr [r12 + {b_last_guest_physical_address}]
call .Lresident_serial_hex64
call .Lresident_serial_state
.endm

// Failed VMRESUME observation: R12=context, saved guest frame at RSP. Read instruction-error detail, retain it in stop_result and render bounded post-EBS output. Scratch GPRs/flags change; VMCS failure remains terminal, caller owns the halt branch.
.macro matrixhv_diagnostic_vmresume_failure
resident_diagnostic_message .Lvmresume_failed_message, {vmresume_failed_message_len}
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
.endm

// CPUID observation: R12=context, R10D=published guest features. Retain ECX only when collection is active; changes flags and context diagnostic state, preserves GPRs/frame/stack/SIMD, and continues to architectural RIP advancement.
.macro matrixhv_diagnostic_cpuid_leaf1
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_dispatch_cpuid_advance
mov qword ptr [r12 + {b_cpuid_leaf1_ecx}], r10
.endm
