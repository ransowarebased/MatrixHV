// Expanded inside the copied resident island; all branches remain island-relative.
// Dispatch ABI: R12=context, RSP=saved guest GPRs, ECX=CPUID subleaf/MSR index.
// CPUID commits EAX..EDX to the frame; reads produce R11 for the MSR packer.
// Writes consume saved EDX:EAX. Scratch GPRs/flags may change; R12, balanced
// root stack and SIMD state remain intact. Handlers jump to normal advance,
// passthrough or GP injection; shared EPT01 translation reports status in EAX.
// Guest page accesses use EPT01 translation and retained event_* / b_* state.

.macro matrixhv_resident_hyperv_cpuid
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
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_cpuid_evmcs
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
jne .Lresident_dispatch_cpuid_evmcs
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
.Lresident_dispatch_cpuid_evmcs:
mov qword ptr [rsp + 0], 0
mov qword ptr [rsp + 24], 0
mov qword ptr [rsp + 8], 0
mov qword ptr [rsp + 16], 0
cmp r8d, 0x40000000
je .Lresident_dispatch_cpuid_evmcs_vendor
cmp r8d, 0x40000001
je .Lresident_dispatch_cpuid_evmcs_interface
cmp r8d, 0x40000003
je .Lresident_dispatch_cpuid_evmcs_features
cmp r8d, 0x40000004
je .Lresident_dispatch_cpuid_evmcs_recommendation
cmp r8d, 0x4000000a
je .Lresident_dispatch_cpuid_evmcs_version
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_vendor:
mov qword ptr [rsp + 0], 0x4000000a
mov qword ptr [rsp + 24], 0x7263694d
mov qword ptr [rsp + 8], 0x666f736f
mov qword ptr [rsp + 16], 0x76482074
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_interface:
mov qword ptr [rsp + 0], 0x31237648
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_features:
mov qword ptr [rsp + 0], 0x60
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_cpuid_time_features
// VP Assist Page access is required before L1 can enable enlightened VM entries.
or qword ptr [rsp + 0], 0x10
.Lresident_dispatch_cpuid_time_features:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
je .Lresident_dispatch_cpuid_advance
or qword ptr [rsp + 0], 0x202
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_recommendation:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_cpuid_evmcs_spinlocks
mov qword ptr [rsp + 0], 0x4000
.Lresident_dispatch_cpuid_evmcs_spinlocks:
mov r10d, -1
mov qword ptr [rsp + 24], r10
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_version:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_cpuid_advance
mov qword ptr [rsp + 0], 0x101
jmp .Lresident_dispatch_cpuid_advance
.endm

.macro matrixhv_resident_hyperv_rdmsr
.Lresident_dispatch_rdmsr_vp_assist:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_rdmsr_passthrough
mov r11, qword ptr [r12 + {b_nested_vp_assist_msr}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_hyperv_apic:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, 0x40000070
je .Lresident_dispatch_inject_gp
call .Lresident_hyperv_apic_address
jc .Lresident_dispatch_inject_gp
test r8, r8
jnz .Lresident_dispatch_rdmsr_hyperv_apic_mmio
cmp r9d, 0x300
jne .Lresident_dispatch_rdmsr_passthrough
call .Lresident_guarded_rdmsr
jc .Lresident_dispatch_inject_gp
mov r11d, eax
shl edx, 24
shl rdx, 32
or r11, rdx
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_hyperv_apic_mmio:
mov r11d, dword ptr [r8 + r9]
cmp r9d, 0x300
jne .Lresident_dispatch_rdmsr_nested_value
mov eax, dword ptr [r8 + 0x310]
and eax, 0xff000000
shl rax, 32
or r11, rax
jmp .Lresident_dispatch_rdmsr_nested_value
// L1 owns the local APIC. Translate the synthetic registers to its native
// x2APIC MSRs or xAPIC MMIO registers without depending on an outer Hyper-V.
.Lresident_hyperv_apic_address:
mov r9d, 0xb0
cmp ecx, 0x40000070
je .Lresident_hyperv_apic_register_ready
mov r9d, 0x300
cmp ecx, 0x40000071
je .Lresident_hyperv_apic_register_ready
mov r9d, 0x80
.Lresident_hyperv_apic_register_ready:
mov ecx, {apic_base_msr}
rdmsr
test eax, 0x800
jz .Lresident_hyperv_apic_disabled
test eax, 0x400
jz .Lresident_hyperv_apic_mmio
xor r8d, r8d
mov ecx, r9d
shr ecx, 4
add ecx, 0x800
clc
ret
.Lresident_hyperv_apic_mmio:
shl rdx, 32
or rax, rdx
and rax, -4096
mov r8, rax
clc
ret
.Lresident_hyperv_apic_disabled:
stc
ret
.Lresident_dispatch_rdmsr_guest_os_id:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_rdmsr_guest_os_id_value
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_guest_os_id_value:
mov r9, qword ptr [r12 + {b_event_context}]
mov r11, qword ptr [r9 + {event_hyperv_guest_os_id}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_hypercall:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_rdmsr_hypercall_value
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_hypercall_value:
mov r9, qword ptr [r12 + {b_event_context}]
mov r11, qword ptr [r9 + {event_hyperv_hypercall_msr}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_vp_index:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_rdmsr_vp_index_value
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_vp_index_value:
mov r11, qword ptr [r12 + {b_processor_number}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_reference_count:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
je .Lresident_dispatch_rdmsr_passthrough
mov r9, qword ptr [r12 + {b_event_context}]
lfence
rdtsc
shl rdx, 32
or rax, rdx
mul qword ptr [r9 + {event_hyperv_tsc_scale}]
mov r11, rdx
add r11, qword ptr [r9 + {event_hyperv_tsc_offset}]
jmp .Lresident_dispatch_rdmsr_nested_value
.Lresident_dispatch_rdmsr_reference_tsc:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
je .Lresident_dispatch_rdmsr_passthrough
mov r9, qword ptr [r12 + {b_event_context}]
mov r11, qword ptr [r9 + {event_hyperv_reference_tsc_msr}]
jmp .Lresident_dispatch_rdmsr_nested_value
.endm

.macro matrixhv_resident_hyperv_wrmsr
.Lresident_dispatch_wrmsr_vp_assist:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_wrmsr_passthrough
mov r11d, dword ptr [rsp + 0]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
test r11, 0xffe
jnz .Lresident_dispatch_inject_gp
test r11b, 1
jz .Lresident_dispatch_wrmsr_vp_assist_store
and r11, -4096
test r11, r11
jz .Lresident_dispatch_inject_gp
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_dispatch_inject_gp
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_dispatch_inject_gp
// Never offer lazy EOI before root maintains the assist-page handshake.
// Preserve the nested fields on repeated writes to the same VP Assist page.
mov dword ptr [r11], 0
.Lresident_dispatch_wrmsr_vp_assist_store:
mov r11d, dword ptr [rsp + 0]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
mov qword ptr [r12 + {b_nested_vp_assist_msr}], r11
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_hyperv_apic:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_wrmsr_passthrough
cmp ecx, 0x40000071
je .Lresident_dispatch_wrmsr_hyperv_apic_valid
cmp dword ptr [rsp + 16], 0
jne .Lresident_dispatch_inject_gp
cmp ecx, 0x40000070
jne .Lresident_dispatch_wrmsr_hyperv_tpr
cmp dword ptr [rsp], 0
jne .Lresident_dispatch_inject_gp
jmp .Lresident_dispatch_wrmsr_hyperv_apic_valid
.Lresident_dispatch_wrmsr_hyperv_tpr:
test dword ptr [rsp], -256
jnz .Lresident_dispatch_inject_gp
.Lresident_dispatch_wrmsr_hyperv_apic_valid:
call .Lresident_hyperv_apic_address
jc .Lresident_dispatch_inject_gp
test r8, r8
jnz .Lresident_dispatch_wrmsr_hyperv_apic_mmio
cmp r9d, 0x300
jne .Lresident_dispatch_wrmsr_passthrough
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
shr edx, 24
cmp edx, 0xff
jne .Lresident_dispatch_wrmsr_hyperv_icr_native
mov edx, -1
.Lresident_dispatch_wrmsr_hyperv_icr_native:
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_inject_gp
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_hyperv_apic_mmio:
mov eax, dword ptr [rsp + 0]
cmp r9d, 0x300
jne .Lresident_dispatch_wrmsr_hyperv_apic_low
mov edx, dword ptr [rsp + 16]
mov dword ptr [r8 + 0x310], edx
.Lresident_dispatch_wrmsr_hyperv_apic_low:
mov dword ptr [r8 + r9], eax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_guest_os_id:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_wrmsr_guest_os_id_value
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_wrmsr_passthrough
.Lresident_dispatch_wrmsr_guest_os_id_value:
mov r11d, dword ptr [rsp + 0]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
// OS identity and hypercall configuration belong to the partition, not the VP.
call .Lresident_hypercall_state_lock
mov qword ptr [r9 + {event_hyperv_guest_os_id}], r11
test r11, r11
jnz .Lresident_dispatch_wrmsr_guest_os_id_done
and qword ptr [r9 + {event_hyperv_hypercall_msr}], -2
.Lresident_dispatch_wrmsr_guest_os_id_done:
mov qword ptr [r9 + {event_hyperv_hypercall_lock}], 0
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_hypercall:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_wrmsr_hypercall_value
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_wrmsr_passthrough
.Lresident_dispatch_wrmsr_hypercall_value:
call .Lresident_hypercall_state_lock
test byte ptr [r9 + {event_hyperv_hypercall_msr}], 2
jnz .Lresident_dispatch_wrmsr_hypercall_done
mov r11d, dword ptr [rsp + 0]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
test r11, 0xffc
jnz .Lresident_dispatch_wrmsr_hypercall_invalid
cmp qword ptr [r9 + {event_hyperv_guest_os_id}], 0
je .Lresident_dispatch_wrmsr_hypercall_unidentified
test r11b, 1
jz .Lresident_dispatch_wrmsr_hypercall_store
// Release the partition lock before synchronizing EPT pages, then recheck it
// before publishing because another VP can lock the MSR during validation.
mov qword ptr [r9 + {event_hyperv_hypercall_lock}], 0
and r11, -4096
test r11, r11
jz .Lresident_dispatch_inject_gp
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_dispatch_inject_gp
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_dispatch_inject_gp
call .Lresident_hypercall_state_lock
test byte ptr [r9 + {event_hyperv_hypercall_msr}], 2
jnz .Lresident_dispatch_wrmsr_hypercall_done
cmp qword ptr [r9 + {event_hyperv_guest_os_id}], 0
je .Lresident_dispatch_wrmsr_hypercall_unidentified
mov rdi, r11
mov eax, 0xcc
mov ecx, 4096
cld
rep stosb
mov byte ptr [r11], 0xb8
mov dword ptr [r11 + 1], 2
mov byte ptr [r11 + 5], 0xc3
.Lresident_dispatch_wrmsr_hypercall_store:
mov r11d, dword ptr [rsp + 0]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
mov qword ptr [r9 + {event_hyperv_hypercall_msr}], r11
.Lresident_dispatch_wrmsr_hypercall_done:
mov qword ptr [r9 + {event_hyperv_hypercall_lock}], 0
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_hypercall_unidentified:
mov r11d, dword ptr [rsp]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
btr r11, 0
mov qword ptr [r9 + {event_hyperv_hypercall_msr}], r11
jmp .Lresident_dispatch_wrmsr_hypercall_done
.Lresident_dispatch_wrmsr_hypercall_invalid:
mov qword ptr [r9 + {event_hyperv_hypercall_lock}], 0
jmp .Lresident_dispatch_inject_gp
.Lresident_hypercall_state_lock:
mov r9, qword ptr [r12 + {b_event_context}]
.Lresident_hypercall_state_lock_retry:
lock bts qword ptr [r9 + {event_hyperv_hypercall_lock}], 0
jnc .Lresident_hypercall_state_locked
pause
jmp .Lresident_hypercall_state_lock_retry
.Lresident_hypercall_state_locked:
ret
.Lresident_dispatch_wrmsr_reference_count:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
je .Lresident_dispatch_wrmsr_passthrough
jmp .Lresident_dispatch_inject_gp
.Lresident_dispatch_wrmsr_reference_tsc:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
je .Lresident_dispatch_wrmsr_passthrough
mov r11d, dword ptr [rsp]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
test r11b, 1
jz .Lresident_hyperv_reference_tsc_validated
and r11, -4096
test r11, r11
jz .Lresident_dispatch_inject_gp
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_dispatch_inject_gp
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_dispatch_inject_gp
.Lresident_hyperv_reference_tsc_validated:
mov rdi, r11
call .Lresident_nested_eptp_before_root_write
mov r9, qword ptr [r12 + {b_event_context}]
.Lresident_hyperv_reference_tsc_lock:
lock bts qword ptr [r9 + {event_hyperv_reference_tsc_lock}], 0
jnc .Lresident_hyperv_reference_tsc_locked
pause
jmp .Lresident_hyperv_reference_tsc_lock
.Lresident_hyperv_reference_tsc_locked:
mov r10, qword ptr [r9 + {event_hyperv_reference_tsc_msr}]
test r10b, 1
jz .Lresident_hyperv_reference_tsc_publish
and r10, -4096
mov r11, r10
push r9
call .Lresident_ept01_page_write_translation
pop r9
test eax, eax
jz .Lresident_hyperv_reference_tsc_publish
mov dword ptr [r11], 0
.Lresident_hyperv_reference_tsc_publish:
test byte ptr [rsp], 1
jz .Lresident_hyperv_reference_tsc_store
mov r11, rdi
mov dword ptr [r11], 0
mfence
xor eax, eax
mov ecx, 512
cld
rep stosq
mov rax, qword ptr [r9 + {event_hyperv_tsc_scale}]
mov qword ptr [r11 + 8], rax
mov rax, qword ptr [r9 + {event_hyperv_tsc_offset}]
mov qword ptr [r11 + 16], rax
// Keep the generation across disable/re-enable and page relocation. A reader
// spanning publication must never accept fields from an older generation.
mov eax, dword ptr [r9 + {event_hyperv_reference_tsc_sequence}]
inc eax
jnz .Lresident_hyperv_reference_tsc_sequence_ready
inc eax
.Lresident_hyperv_reference_tsc_sequence_ready:
mov qword ptr [r9 + {event_hyperv_reference_tsc_sequence}], rax
mfence
mov dword ptr [r11], eax
.Lresident_hyperv_reference_tsc_store:
mov r11d, dword ptr [rsp]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
mov qword ptr [r9 + {event_hyperv_reference_tsc_msr}], r11
mov qword ptr [r9 + {event_hyperv_reference_tsc_lock}], 0
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
matrixhv_ept01_page_translation
.endm

.macro matrixhv_resident_hyperv_rdmsr_route
cmp ecx, {hyperv_reference_count_msr}
je .Lresident_dispatch_rdmsr_reference_count
cmp ecx, {hyperv_reference_tsc_msr}
je .Lresident_dispatch_rdmsr_reference_tsc
cmp ecx, {hyperv_guest_os_id_msr}
je .Lresident_dispatch_rdmsr_guest_os_id
cmp ecx, {hyperv_hypercall_msr}
je .Lresident_dispatch_rdmsr_hypercall
cmp ecx, {hyperv_vp_index_msr}
je .Lresident_dispatch_rdmsr_vp_index
cmp ecx, {hyperv_vp_assist_msr}
je .Lresident_dispatch_rdmsr_vp_assist
cmp ecx, 0x40000070
jb .Lresident_dispatch_rdmsr_apic_checked
cmp ecx, 0x40000072
jbe .Lresident_dispatch_rdmsr_hyperv_apic
.endm

.macro matrixhv_resident_hyperv_wrmsr_route
cmp ecx, {hyperv_reference_count_msr}
je .Lresident_dispatch_wrmsr_reference_count
cmp ecx, {hyperv_reference_tsc_msr}
je .Lresident_dispatch_wrmsr_reference_tsc
cmp ecx, {hyperv_guest_os_id_msr}
je .Lresident_dispatch_wrmsr_guest_os_id
cmp ecx, {hyperv_hypercall_msr}
je .Lresident_dispatch_wrmsr_hypercall
cmp ecx, {hyperv_vp_assist_msr}
je .Lresident_dispatch_wrmsr_vp_assist
cmp ecx, 0x40000070
jb .Lresident_dispatch_wrmsr_apic_checked
cmp ecx, 0x40000072
jbe .Lresident_dispatch_wrmsr_hyperv_apic
.endm

// Inline fallback read contract: ecx is the guest MSR after synthetic-MSR routing. Clobbers eax and flags; recognized parent-owned MSRs jump to guarded passthrough, otherwise falls through.
.macro matrixhv_resident_hyperv_read_passthrough
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
.endm

// Inline fallback write contract: ecx is the guest MSR after synthetic-MSR routing. Comparisons preserve GPRs and change flags; recognized parent-owned MSRs jump to guarded passthrough, otherwise falls through.
.macro matrixhv_resident_hyperv_write_passthrough
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
.endm

// eVMCS selection/store: R12=context, RSP=internal return stack. Select returns EAX=1/0/-1 (selected/ordinary/invalid); store publishes mutable fields. Scratch GPRs/flags change, R12 and SIMD survive, pushes balance on every returning path. EPT01 helpers validate shared pages; VMCS12/shadow materialization remains nested-owned.
.macro matrixhv_hyperv_evmcs_handlers
.Lresident_hyperv_evmcs_select:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_hyperv_evmcs_select_none
mov r11, qword ptr [r12 + {b_nested_vp_assist_msr}]
test r11b, 1
jz .Lresident_hyperv_evmcs_select_none
and r11, -4096
call .Lresident_ept01_page_is_readable
test eax, eax
jz .Lresident_hyperv_evmcs_select_invalid
mov eax, dword ptr [r11 + {vp_assist_enlighten_vm_entry}]
test eax, 1
jz .Lresident_hyperv_evmcs_select_none
mov r11, qword ptr [r11 + {vp_assist_current_nested_vmcs}]
test r11, r11
jz .Lresident_hyperv_evmcs_select_invalid
cmp r11, -1
je .Lresident_hyperv_evmcs_select_invalid
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_hyperv_evmcs_select_invalid
push r11
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_hyperv_evmcs_select_page_invalid
mov eax, dword ptr [r11]
cmp eax, {evmcs_version}
je .Lresident_hyperv_evmcs_select_version_ready
cmp eax, dword ptr [r12 + {b_nested_vmcs12_revision_id}]
jne .Lresident_hyperv_evmcs_select_page_invalid
.Lresident_hyperv_evmcs_select_version_ready:
push r13
mov r13, r11
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
jne .Lresident_hyperv_evmcs_select_current_saved
call .Lresident_nested_store_current_vmcs12
.Lresident_hyperv_evmcs_select_current_saved:
call .Lresident_nested_shadow_intercept_reads
mov rax, qword ptr [rsp + 8]
mov qword ptr [r12 + {b_nested_current_vmcs}], rax
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
mov qword ptr [r12 + {b_nested_evmcs_active}], 1
mov qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid} + 8], 0
lea rdi, [r12 + {b_nested_vmcs12_extended_fields}]
xor eax, eax
mov ecx, {nested_extended_field_count}
cld
rep stosq
lea rsi, [rip + .Lresident_evmcs_field_map]
xor r9d, r9d
.Lresident_hyperv_evmcs_select_field:
movzx r10d, word ptr [rsi + r9 * 4 + 2]
test r10d, 0x40
jnz .Lresident_hyperv_evmcs_select_next_field
and r10d, 15
jz .Lresident_hyperv_evmcs_select_next_field
movzx edx, word ptr [rsi + r9 * 4]
cmp r10d, 2
je .Lresident_hyperv_evmcs_select_word
cmp r10d, 4
je .Lresident_hyperv_evmcs_select_dword
mov r11, qword ptr [r13 + rdx]
jmp .Lresident_hyperv_evmcs_select_copy_field
.Lresident_hyperv_evmcs_select_word:
movzx r11d, word ptr [r13 + rdx]
jmp .Lresident_hyperv_evmcs_select_copy_field
.Lresident_hyperv_evmcs_select_dword:
mov r11d, dword ptr [r13 + rdx]
.Lresident_hyperv_evmcs_select_copy_field:
mov qword ptr [r12 + {b_nested_vmcs12_extended_fields} + r9 * 8], r11
.Lresident_hyperv_evmcs_select_next_field:
inc r9d
cmp r9d, {nested_extended_field_count}
jne .Lresident_hyperv_evmcs_select_field
mov r11, qword ptr [r13 + {evmcs_guest_rip}]
mov qword ptr [r12 + {b_nested_vmcs12_guest_rip}], r11
mov r11, qword ptr [r13 + {evmcs_guest_rsp}]
mov qword ptr [r12 + {b_nested_vmcs12_guest_rsp}], r11
mov r11, qword ptr [r13 + {evmcs_guest_rflags}]
mov qword ptr [r12 + {b_nested_vmcs12_guest_rflags}], r11
mov r11, qword ptr [r13 + {evmcs_host_rsp}]
mov qword ptr [r12 + {b_nested_vmcs12_host_rsp}], r11
mov r11, qword ptr [r13 + {evmcs_host_rip}]
mov qword ptr [r12 + {b_nested_vmcs12_host_rip}], r11
pop r13
add rsp, 8
mov eax, 1
ret
.Lresident_hyperv_evmcs_select_page_invalid:
add rsp, 8
jmp .Lresident_hyperv_evmcs_select_invalid
.Lresident_hyperv_evmcs_select_none:
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
je .Lresident_hyperv_evmcs_select_none_ready
mov qword ptr [r12 + {b_nested_evmcs_active}], 0
mov qword ptr [r12 + {b_nested_current_vmcs}], -1
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
.Lresident_hyperv_evmcs_select_none_ready:
xor eax, eax
ret
.Lresident_hyperv_evmcs_select_invalid:
mov eax, -1
ret
.Lresident_hyperv_evmcs_store:
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
je .Lresident_hyperv_evmcs_store_done
call .Lresident_nested_materialize_vmcs02_rare_state
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_hyperv_evmcs_store_done
mov rdi, r11
lea rsi, [rip + .Lresident_evmcs_field_map]
xor r9d, r9d
.Lresident_hyperv_evmcs_store_field:
movzx r10d, word ptr [rsi + r9 * 4 + 2]
test r10d, 0xc0
jz .Lresident_hyperv_evmcs_store_next_field
movzx edx, word ptr [rsi + r9 * 4]
mov r11, qword ptr [r12 + {b_nested_vmcs12_extended_fields} + r9 * 8]
and r10d, 15
cmp r10d, 2
je .Lresident_hyperv_evmcs_store_word
cmp r10d, 4
je .Lresident_hyperv_evmcs_store_dword
mov qword ptr [rdi + rdx], r11
jmp .Lresident_hyperv_evmcs_store_next_field
.Lresident_hyperv_evmcs_store_word:
mov word ptr [rdi + rdx], r11w
jmp .Lresident_hyperv_evmcs_store_next_field
.Lresident_hyperv_evmcs_store_dword:
mov dword ptr [rdi + rdx], r11d
.Lresident_hyperv_evmcs_store_next_field:
inc r9d
cmp r9d, {nested_extended_field_count}
jne .Lresident_hyperv_evmcs_store_field
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rip}]
mov qword ptr [rdi + {evmcs_guest_rip}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rsp}]
mov qword ptr [rdi + {evmcs_guest_rsp}], r11
mov r11, qword ptr [r12 + {b_nested_vmcs12_guest_rflags}]
mov qword ptr [rdi + {evmcs_guest_rflags}], r11
mov r11d, dword ptr [r12 + {b_nested_vmcs12_exit_reason}]
mov dword ptr [rdi + {evmcs_exit_reason}], r11d
mov r11d, dword ptr [r12 + {b_nested_vmcs12_exit_instruction_len}]
mov dword ptr [rdi + {evmcs_exit_instruction_length}], r11d
mov r11, qword ptr [r12 + {b_nested_vmcs12_exit_qualification}]
mov qword ptr [rdi + {evmcs_exit_qualification}], r11
mov dword ptr [rdi + {evmcs_clean_fields}], 0
.Lresident_hyperv_evmcs_store_done:
ret
.endm

// VMCLEAR routing: R11=validated L1 VMCS GPA, R12=context, saved guest frame at RSP. Validate the enlightened header and VP Assist handshake before choosing ordinary VMCLEAR, active eVMCS clearing, VMfail or success. Scratch GPRs/flags change; no stack or SIMD state is retained.
.macro matrixhv_hyperv_evmcs_vmclear_route
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_nested_vmclear_ordinary
mov r14, r11
call .Lresident_ept01_page_is_writable
test eax, eax
jz .Lresident_nested_vmclear_invalid_address
mov edx, dword ptr [r11]
cmp edx, {evmcs_version}
je .Lresident_hyperv_evmcs_vmclear_version_ready
cmp edx, dword ptr [r12 + {b_nested_vmcs12_revision_id}]
jne .Lresident_nested_vmclear_ordinary
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
je .Lresident_hyperv_evmcs_vmclear_check_assist
cmp r14, qword ptr [r12 + {b_nested_current_vmcs}]
je .Lresident_hyperv_evmcs_vmclear
.Lresident_hyperv_evmcs_vmclear_check_assist:
mov r11, qword ptr [r12 + {b_nested_vp_assist_msr}]
test r11b, 1
jz .Lresident_nested_vmclear_ordinary
and r11, -4096
call .Lresident_ept01_page_is_readable
test eax, eax
jz .Lresident_nested_vmclear_invalid_address
test dword ptr [r11 + {vp_assist_enlighten_vm_entry}], 1
jz .Lresident_nested_vmclear_ordinary
// Enlightened mode applies to non-current pages as well. Their header identifies
// the shared layout; ordinary VMCS12 backing offsets would overwrite its fields.
.Lresident_hyperv_evmcs_vmclear_version_ready:
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
je .Lresident_nested_succeed
cmp r14, qword ptr [r12 + {b_nested_current_vmcs}]
je .Lresident_hyperv_evmcs_vmclear
jmp .Lresident_nested_succeed
.endm

// Active eVMCS clear: R12=context, dispatcher frame intact. Clear VMCS02 and enlightened selection/cache state, then jump to nested success; VMX failure halts. Scratch flags change, GPR/frame/SIMD ownership stays with dispatch.
.macro matrixhv_hyperv_evmcs_vmclear
.Lresident_hyperv_evmcs_vmclear:
vmclear [r12 + {b_nested_vmcs02_region}]
jna .Lresident_dispatch_halt
mov qword ptr [r12 + {b_nested_vmcs02_launched}], 0
mov qword ptr [r12 + {b_nested_vmcs02_guest_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid}], 0
mov qword ptr [r12 + {b_nested_vmcs02_control_cache_valid} + 8], 0
mov qword ptr [r12 + {b_nested_evmcs_active}], 0
mov qword ptr [r12 + {b_nested_current_vmcs}], -1
mov qword ptr [r12 + {b_nested_current_vmcs_is_shadow}], 0
jmp .Lresident_nested_succeed
.endm

// VMfail publication: R10=instruction error, R12=context. Publish to the selected writable eVMCS page, preserving R10 with one balanced push/pop. Other scratch GPRs/flags change; unavailable pages skip publication and fall through to nested architectural flags.
.macro matrixhv_hyperv_evmcs_instruction_error
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
je .Lresident_nested_vmfail_error_recorded
push r10
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
call .Lresident_ept01_page_is_writable
pop r10
test eax, eax
jz .Lresident_nested_vmfail_error_recorded
mov dword ptr [r11 + {evmcs_exit_instruction_error}], r10d
.endm

// RIP-relative eVMCS layout table. Indexed by the canonical VMCS12 extended-field index; entries carry byte offsets, widths and copy direction. Expanded at the original data position, with no executable side effects.
.macro matrixhv_hyperv_evmcs_field_map
.Lresident_evmcs_field_map:
// Each entry is an eVMCS byte offset and width; 0x80 copies mutable state back,
// and 0x40 writes a read-only exit field.
.short 632, 2
.short 92, 4
.short 788, 4
.short 100, 4
.short 792, 4
.short 376, 4
.short 380, 4
.short 384, 4
.short 96, 4
.short 388, 4
.short 392, 4
.short 796, 132
.short 396, 4
.short 800, 132
.short 804, 4
.short 808, 4
.short 624, 8
.short 400, 8
.short 120, 8
.short 512, 8
.short 520, 8
.short 528, 8
.short 536, 8
.short 416, 8
.short 424, 136
.short 432, 136
.short 440, 136
.short 24, 8
.short 32, 8
.short 544, 136
.short 552, 136
.short 560, 136
.short 40, 8
.short 48, 8
.short 56, 8
.short 128, 130
.short 130, 130
.short 132, 130
.short 134, 130
.short 136, 130
.short 138, 130
.short 140, 130
.short 142, 130
.short 8, 2
.short 10, 2
.short 12, 2
.short 14, 2
.short 16, 2
.short 18, 2
.short 20, 2
.short 216, 136
.short 224, 136
.short 232, 136
.short 240, 136
.short 248, 136
.short 256, 136
.short 264, 136
.short 272, 136
.short 280, 136
.short 288, 136
.short 576, 8
.short 584, 8
.short 592, 8
.short 600, 8
.short 608, 8
.short 144, 132
.short 148, 132
.short 152, 132
.short 156, 132
.short 160, 132
.short 164, 132
.short 168, 132
.short 172, 132
.short 176, 132
.short 180, 132
.short 184, 132
.short 188, 132
.short 192, 132
.short 196, 132
.short 200, 132
.short 204, 132
.short 208, 132
.short 212, 132
.short 784, 132
.short 504, 132
.short 508, 132
.short 488, 136
.short 496, 136
.short 88, 4
.short 64, 8
.short 72, 8
.short 568, 136
.short 480, 136
.short 104, 8
.short 112, 8
.short 960, 8
.short 344, 8
.short 352, 8
.short 360, 8
.short 368, 8
.short 812, 4
.short 408, 8
.short 0, 0
.short 320, 8
.short 328, 8
.short 336, 8
.short 696, 68
.short 700, 68
.short 704, 68
.short 708, 68
.short 680, 72
.short 448, 136
.short 456, 136
.short 464, 136
.short 472, 136
.short 716, 68
.short 760, 72
.short 0, 0
.short 0, 0
.short 0, 0
.short 0, 0
.short 0, 0
.endm

// VMLAUNCH adapter: select the VP Assist eVMCS and project its initial launch state. R12/frame preserved, scratch GPRs/flags changed; invalid selection jumps to nested VMfail, otherwise falls through with ordinary VMCS12 semantics.
.macro matrixhv_hyperv_evmcs_launch_selection
call .Lresident_hyperv_evmcs_select
cmp eax, -1
je .Lresident_nested_vmfail_invalid_no_current_vmcs
cmp eax, 1
jne .Lresident_nested_vmlaunch_vmcs_ready
mov qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_clear}
.endm

// VMRESUME adapter: select the VP Assist eVMCS and project its launched state. Same frame/clobber contract as the launch adapter; invalid selection jumps to nested VMfail, otherwise falls through.
.macro matrixhv_hyperv_evmcs_resume_selection
call .Lresident_hyperv_evmcs_select
cmp eax, -1
je .Lresident_nested_vmfail_invalid_no_current_vmcs
cmp eax, 1
jne .Lresident_nested_vmresume_vmcs_ready
mov qword ptr [r12 + {b_nested_vmcs12_launch_state}], {vmcs12_launch_state_launched}
.endm

// Ordinary backing-store gate: R12=context. Active enlightened pages bypass the ordinary VMCS12 backing format. GPRs/stack/SIMD unchanged; comparison changes flags and either returns through the nested done label or falls through.
.macro matrixhv_hyperv_evmcs_skip_backing_store
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
jne .Lresident_nested_store_current_vmcs12_done
.endm

// Current VMCLEAR adapter: R12=context. Active enlightened selection jumps to its owner; ordinary backing storage falls through. Changes flags only; frame and stack remain intact.
.macro matrixhv_hyperv_evmcs_clear_current
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
jne .Lresident_hyperv_evmcs_vmclear
.endm

// VMREAD/VMWRITE compatibility gate: R12=context. Hyper-V eVMCS rejects architectural field access; changes flags only, preserves stack/GPRs/SIMD, and falls through or jumps to nested VMfail.
.macro resident_hyperv_evmcs_require_ordinary
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
jne .Lresident_nested_vmfail_invalid_no_current_vmcs
.endm

// VMX lifecycle reset: R12=context. Clear only the owner's active selection; no GPR, flag, stack or SIMD changes. Ordinary VMCS and VMX lifecycle state remain caller-owned.
.macro resident_hyperv_evmcs_reset
mov qword ptr [r12 + {b_nested_evmcs_active}], 0
.endm

// Diagnostic accessor: R12=context, RAX receives active selection. All other GPRs, flags, stack and SIMD remain unchanged.
.macro matrixhv_hyperv_evmcs_diagnostic_value
mov rax, qword ptr [r12 + {b_nested_evmcs_active}]
.endm

// Hypervisor presence policy: R12=context, R10D=leaf-one features. Set or clear the architectural hypervisor bit according to the immutable guest option. Changes R10/flags only, preserves frame/stack/SIMD and falls through to the dispatcher result store.
.macro matrixhv_hyperv_cpuid_presence_policy
cmp qword ptr [r12 + {b_cpuid_presence}], 0
je .Lresident_dispatch_cpuid_presence_hidden
or r10d, {cpuid_hypervisor_set_mask}
jmp .Lresident_dispatch_cpuid_presence_ready
.Lresident_dispatch_cpuid_presence_hidden:
and r10d, {cpuid_hypervisor_clear_mask}
.Lresident_dispatch_cpuid_presence_ready:
.endm
