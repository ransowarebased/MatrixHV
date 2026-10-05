// R12 owns the CPU context. Entry/leave preserve GPRs and flags, including
// VMX status flags. Every interval borrows disabled PT state and restores it
// before guest entry or native deactivation. No firmware or allocation occurs.
.macro resident_pt_save
push rax
push rcx
push rdx
push r10
push r11
.endm
.macro resident_pt_restore
pop r11
pop r10
pop rdx
pop rcx
pop rax
popfq
ret
.endm
.macro resident_pt_read msr_index, destination, failure
mov ecx, \msr_index
call .Lresident_rdmsr_instruction
jc \failure
shl rdx, 32
or rax, rdx
mov qword ptr [r12 + \destination], rax
.endm
.macro resident_pt_write msr_index, source, failure
mov rax, \source
mov rdx, rax
shr rdx, 32
mov ecx, \msr_index
call .Lresident_wrmsr_instruction
jc \failure
.endm
.macro resident_pt_write_saved msr_index, source_offset, failure
mov rax, qword ptr [r12 + \source_offset]
resident_pt_write \msr_index, rax, \failure
.endm
.macro matrixhv_island_pt
.Lresident_pt_enter:
pushfq
cmp qword ptr [r12 + {b_pt_armed}], 0
je .Lresident_pt_enter_done
resident_pt_save
// Avoid recording diagnostic reads or controls into the buffer being exported.
cmp qword ptr [r12 + {b_last_reason}], {cpuid_reason}
jne .Lresident_pt_enter_begin
cmp dword ptr [rsp + 56], {matrixhv_status_leaf}
je .Lresident_pt_enter_restore
.Lresident_pt_enter_begin:
lea rax, [rip + matrixhv_resident_island_start]
cmp rax, qword ptr [r12 + {b_pt_code_base}]
jne .Lresident_pt_fault_disarm
resident_pt_read 0x570, {b_pt_saved_control}, .Lresident_pt_fault
test al, 1
jnz .Lresident_pt_busy
resident_pt_read 0x571, {b_pt_saved_status}, .Lresident_pt_fault
resident_pt_read 0x560, {b_pt_saved_base}, .Lresident_pt_fault
resident_pt_read 0x561, {b_pt_saved_pointer}, .Lresident_pt_fault
mov qword ptr [r12 + {b_pt_owned}], 1
resident_pt_write 0x570, 0, .Lresident_pt_setup_fault
resident_pt_write_saved 0x560, {b_pt_table}, .Lresident_pt_setup_fault
resident_pt_write_saved 0x561, {b_pt_output_pointer}, .Lresident_pt_setup_fault
resident_pt_write 0x571, 0, .Lresident_pt_setup_fault
resident_pt_write 0x570, {pt_control}, .Lresident_pt_setup_fault
.Lresident_pt_enter_restore:
resident_pt_restore
.Lresident_pt_enter_done:
popfq
ret
.Lresident_pt_busy:
mov qword ptr [r12 + {b_pt_support}], 3
jmp .Lresident_pt_fault_disarm
.Lresident_pt_setup_fault:
call .Lresident_pt_leave
.Lresident_pt_fault:
mov qword ptr [r12 + {b_pt_support}], 4
.Lresident_pt_fault_disarm:
mov qword ptr [r12 + {b_pt_armed}], 0
jmp .Lresident_pt_enter_restore

.Lresident_pt_leave:
pushfq
cmp qword ptr [r12 + {b_pt_owned}], 0
je .Lresident_pt_leave_done
resident_pt_save
// Clearing TraceEn drains buffered packets before reading the output pointer.
resident_pt_write 0x570, 0, .Lresident_pt_restore_failed
mov qword ptr [r12 + {b_pt_owned}], 0
resident_pt_read 0x571, {b_pt_status}, .Lresident_pt_snapshot_failed
resident_pt_read 0x561, {b_pt_output_pointer}, .Lresident_pt_snapshot_failed
mov rax, qword ptr [r12 + {b_pt_output_pointer}]
shr rax, 32
cmp rax, {pt_buffer_bytes}
ja .Lresident_pt_snapshot_failed
mov qword ptr [r12 + {b_pt_bytes}], rax
test qword ptr [r12 + {b_pt_status}], 0x30
jz .Lresident_pt_restore_state
mov qword ptr [r12 + {b_pt_armed}], 0
jmp .Lresident_pt_restore_state
.Lresident_pt_snapshot_failed:
mov qword ptr [r12 + {b_pt_support}], 4
mov qword ptr [r12 + {b_pt_armed}], 0
.Lresident_pt_restore_state:
resident_pt_write_saved 0x560, {b_pt_saved_base}, .Lresident_pt_restore_failed
resident_pt_write_saved 0x561, {b_pt_saved_pointer}, .Lresident_pt_restore_failed
resident_pt_write_saved 0x571, {b_pt_saved_status}, .Lresident_pt_restore_failed
resident_pt_write_saved 0x570, {b_pt_saved_control}, .Lresident_pt_restore_failed
resident_pt_restore
.Lresident_pt_leave_done:
popfq
ret
.Lresident_pt_restore_failed:
mov qword ptr [r12 + {b_pt_support}], 4
mov qword ptr [r12 + {b_pt_armed}], 0
// A failed restore cannot safely return to a guest with diagnostic MSRs loaded.
cli
.Lresident_pt_restore_halt:
hlt
jmp .Lresident_pt_restore_halt

.Lresident_pt_freeze:
push r12
push rax
mov r12, qword ptr gs:[112]
test r12, r12
jz .Lresident_pt_freeze_done
mov rax, {boot_canary_start}
cmp qword ptr [r12 + {b_canary_start}], rax
jne .Lresident_pt_freeze_done
mov rax, {boot_canary_end}
cmp qword ptr [r12 + {b_canary_end}], rax
jne .Lresident_pt_freeze_done
call .Lresident_pt_leave
mov qword ptr [r12 + {b_pt_armed}], 0
.Lresident_pt_freeze_done:
pop rax
pop r12
ret

.Lresident_pt_guest_msr:
pushfq
cmp ecx, 0x560
jb .Lresident_pt_guest_msr_done
cmp ecx, 0x58f
ja .Lresident_pt_guest_msr_done
call .Lresident_pt_leave
.Lresident_pt_guest_msr_done:
popfq
ret

.Lresident_pt_start:
cmp r8, r12
jne .Lresident_dispatch_cpuid_diagnostic_zero
cmp qword ptr [r9 + {event_ebs_seen}], 0
je .Lresident_dispatch_cpuid_diagnostic_zero
cmp qword ptr [r8 + {b_pt_support}], 1
je .Lresident_pt_start_ready
cmp qword ptr [r8 + {b_pt_support}], 3
jne .Lresident_pt_query
.Lresident_pt_start_ready:
// A repeated start preserves the current capture; a stopped capture resets.
cmp qword ptr [r8 + {b_pt_armed}], 0
jne .Lresident_pt_query
push rdi
mov rdi, qword ptr [r8 + {b_pt_buffer}]
mov ecx, {pt_buffer_bytes} / 8
xor eax, eax
rep stosq
pop rdi
lea rax, [rip + matrixhv_resident_island_start]
mov qword ptr [r8 + {b_pt_code_base}], rax
lea rdx, [rip + matrixhv_resident_island_end]
sub rdx, rax
mov qword ptr [r8 + {b_pt_code_bytes}], rdx
inc qword ptr [r8 + {b_pt_generation}]
mov qword ptr [r8 + {b_pt_support}], 1
mov qword ptr [r8 + {b_pt_bytes}], 0
mov qword ptr [r8 + {b_pt_status}], 0
mov qword ptr [r8 + {b_pt_output_pointer}], 0x7f
mov qword ptr [r8 + {b_pt_armed}], 1
jmp .Lresident_pt_query
.Lresident_pt_stop:
cmp r8, r12
jne .Lresident_dispatch_cpuid_diagnostic_zero
mov qword ptr [r8 + {b_pt_armed}], 0
.Lresident_pt_query:
// Recheck a cached unsupported state on its owning CPU after a runtime update.
cmp r8, r12
jne .Lresident_pt_query_snapshot
cmp qword ptr [r8 + {b_pt_support}], 2
jne .Lresident_pt_query_snapshot
test qword ptr [r8 + {b_nested_host_misc}], 1 << 14
jz .Lresident_pt_query_snapshot
xor eax, eax
cpuid
cmp eax, 0x14
jb .Lresident_pt_query_snapshot
mov eax, 7
xor ecx, ecx
cpuid
bt ebx, 25
jnc .Lresident_pt_query_snapshot
mov eax, 0x14
xor ecx, ecx
cpuid
test ecx, 1
jz .Lresident_pt_query_snapshot
mov qword ptr [r8 + {b_pt_support}], 1
.Lresident_pt_query_snapshot:
mov eax, dword ptr [r8 + {b_pt_support}]
mov ebx, dword ptr [r8 + {b_pt_armed}]
mov ecx, dword ptr [r8 + {b_pt_bytes}]
mov edx, dword ptr [r8 + {b_pt_status}]
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_pt_generation:
mov rax, qword ptr [r8 + {b_pt_generation}]
mov rdx, {pt_control}
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_pt_layout:
mov rax, qword ptr [r8 + {b_pt_code_base}]
mov rdx, qword ptr [r8 + {b_pt_code_bytes}]
jmp .Lresident_dispatch_cpuid_vmx_pair
.Lresident_pt_data:
cmp qword ptr [r8 + {b_pt_armed}], 0
jne .Lresident_dispatch_cpuid_diagnostic_zero
cmp qword ptr [r8 + {b_pt_owned}], 0
jne .Lresident_dispatch_cpuid_diagnostic_zero
sub ecx, {pt_data_subleaf}
shl ecx, 4
cmp rcx, qword ptr [r8 + {b_pt_bytes}]
jae .Lresident_dispatch_cpuid_diagnostic_zero
mov r10, qword ptr [r8 + {b_pt_buffer}]
mov rax, qword ptr [r10 + rcx]
mov rdx, qword ptr [r10 + rcx + 8]
jmp .Lresident_dispatch_cpuid_vmx_pair
.endm
