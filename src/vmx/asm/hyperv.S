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
cmp qword ptr [r12 + {b_nested_expose_vmx}], 0
je .Lresident_dispatch_cpuid_outer_features
// L0 owns L1's VMX instructions; outer nested enlightenments cannot be used.
cmp r8d, {hv_nested_features_leaf}
je .Lresident_dispatch_cpuid_evmcs
cmp r8d, {hv_recommendations_leaf}
jne .Lresident_dispatch_cpuid_outer_features
and dword ptr [rsp], ~{hv_evmcs_recommendation}
.Lresident_dispatch_cpuid_outer_features:
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
cmp r8d, {hv_vendor_leaf}
je .Lresident_dispatch_cpuid_evmcs_vendor
cmp r8d, {hv_interface_leaf}
je .Lresident_dispatch_cpuid_evmcs_interface
cmp r8d, {hv_identity_leaf}
je .Lresident_dispatch_cpuid_identity
cmp r8d, {hv_limits_leaf}
je .Lresident_dispatch_cpuid_limits
cmp r8d, {hv_hardware_leaf}
je .Lresident_dispatch_cpuid_hardware
cmp r8d, {hyperv_features_leaf}
je .Lresident_dispatch_cpuid_evmcs_features
cmp r8d, {hv_recommendations_leaf}
je .Lresident_dispatch_cpuid_evmcs_recommendation
cmp r8d, {hv_nested_features_leaf}
je .Lresident_dispatch_cpuid_evmcs_version
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_vendor:
mov qword ptr [rsp + 0], {hv_nested_features_leaf}
mov qword ptr [rsp + 24], {hv_vendor_ebx}
mov qword ptr [rsp + 8], {hv_vendor_ecx}
mov qword ptr [rsp + 16], {hv_vendor_edx}
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_interface:
mov qword ptr [rsp + 0], {hv_interface_signature}
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_identity:
// Report MatrixHV 0.1, never a fabricated Windows host release.
mov qword ptr [rsp], {hv_build_number}
mov qword ptr [rsp + 24], {hv_product_version}
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_limits:
mov qword ptr [rsp], {hv_processor_limit}
mov qword ptr [rsp + 24], {hv_processor_limit}
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_hardware:
// MSR bitmaps and EPT are always in use. Reserved 7/8 and optional nested
// delivery leaf 9 remain zero; no direct L2 hypercalls are advertised.
mov qword ptr [rsp], {hv_hardware_in_use}
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_features:
mov qword ptr [rsp + 0], {hv_base_access}
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_cpuid_time_features
// VP Assist Page access is required before L1 can enable enlightened VM entries.
or qword ptr [rsp + 0], {hv_apic_access}
.Lresident_dispatch_cpuid_time_features:
mov r9, qword ptr [r12 + {b_event_context}]
cmp qword ptr [r9 + {event_hyperv_tsc_invariant_supported}], 0
je .Lresident_dispatch_cpuid_time_features_ready
or qword ptr [rsp], {hv_invariant_tsc_access}
.Lresident_dispatch_cpuid_time_features_ready:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
je .Lresident_dispatch_cpuid_advance
or qword ptr [rsp + 0], {hv_time_access}
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_recommendation:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_cpuid_evmcs_spinlocks
mov qword ptr [rsp + 0], {hv_evmcs_recommendation}
.Lresident_dispatch_cpuid_evmcs_spinlocks:
mov r10d, -1
mov qword ptr [rsp + 24], r10
jmp .Lresident_dispatch_cpuid_advance
.Lresident_dispatch_cpuid_evmcs_version:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_cpuid_advance
mov qword ptr [rsp + 0], {hv_evmcs_versions}
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
cmp ecx, {hv_eoi_msr}
je .Lresident_dispatch_inject_gp
call .Lresident_hyperv_apic_address
jc .Lresident_dispatch_inject_gp
test ecx, ecx
jz .Lresident_dispatch_rdmsr_hyperv_apic_mmio
cmp r9d, 0x300
jne .Lresident_dispatch_rdmsr_passthrough
call .Lresident_guarded_rdmsr
jc .Lresident_dispatch_inject_gp
mov r11d, eax
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
cmp ecx, {hv_eoi_msr}
je .Lresident_hyperv_apic_register_ready
mov r9d, 0x300
cmp ecx, {hv_icr_msr}
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
mov r11, rax
push r9
call .Lresident_ept01_host_page_is_mapped
pop r9
test eax, eax
jz .Lresident_hyperv_apic_disabled
xor ecx, ecx
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
.Lresident_dispatch_rdmsr_tsc_invariant:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_rdmsr_tsc_invariant_value
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_rdmsr_passthrough
.Lresident_dispatch_rdmsr_tsc_invariant_value:
mov r9, qword ptr [r12 + {b_event_context}]
cmp qword ptr [r9 + {event_hyperv_tsc_invariant_supported}], 0
je .Lresident_dispatch_inject_gp
mov r11, qword ptr [r9 + {event_hyperv_tsc_invariant_control}]
jmp .Lresident_dispatch_rdmsr_nested_value
// A synthetic CPUID interface has one owner. Unsupported synthetic MSRs must
// not change an outer hypervisor's state or return its unrelated partition view.
.Lresident_hyperv_require_parent_msr:
mov eax, ecx
sub eax, {hv_msr_base}
cmp eax, {hv_msr_range_span}
ja .Lresident_hyperv_parent_msr_allowed
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_hyperv_parent_msr_denied
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
jne .Lresident_hyperv_parent_msr_denied
.Lresident_hyperv_parent_msr_allowed:
clc
ret
.Lresident_hyperv_parent_msr_denied:
stc
ret
.endm

.macro matrixhv_resident_hyperv_wrmsr
.Lresident_dispatch_wrmsr_vp_assist:
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_wrmsr_passthrough
mov r11d, dword ptr [rsp + 0]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
test r11b, 1
jz .Lresident_dispatch_wrmsr_vp_assist_store
and r11, -4096
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
cmp ecx, {hv_icr_msr}
je .Lresident_dispatch_wrmsr_hyperv_apic_valid
cmp dword ptr [rsp + 16], 0
jne .Lresident_dispatch_inject_gp
cmp ecx, {hv_eoi_msr}
jne .Lresident_dispatch_wrmsr_hyperv_tpr
jmp .Lresident_dispatch_wrmsr_hyperv_apic_valid
.Lresident_dispatch_wrmsr_hyperv_tpr:
test dword ptr [rsp], -256
jnz .Lresident_dispatch_inject_gp
.Lresident_dispatch_wrmsr_hyperv_apic_valid:
call .Lresident_hyperv_apic_address
jc .Lresident_dispatch_inject_gp
test ecx, ecx
jz .Lresident_dispatch_wrmsr_hyperv_apic_mmio
cmp r9d, 0xb0
je .Lresident_dispatch_wrmsr_hyperv_eoi_native
cmp r9d, 0x300
jne .Lresident_dispatch_wrmsr_passthrough
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
// The synthetic ICR follows the active APIC mode. In x2APIC the complete
// high dword is the destination (cluster and mask in logical mode).
.Lresident_dispatch_wrmsr_hyperv_icr_native:
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_inject_gp
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_hyperv_eoi_native:
// TLFS ignores the low EOI value; native x2APIC requires all bits to be zero.
xor eax, eax
xor edx, edx
jmp .Lresident_dispatch_wrmsr_hyperv_icr_native
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
cmp qword ptr [r9 + {event_hyperv_guest_os_id}], 0
je .Lresident_dispatch_wrmsr_hypercall_unidentified
test r11b, 1
jz .Lresident_dispatch_wrmsr_hypercall_store
// Release the partition lock before synchronizing EPT pages, then recheck it
// before publishing because another VP can lock the MSR during validation.
mov qword ptr [r9 + {event_hyperv_hypercall_lock}], 0
and r11, -4096
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
// VMCALL; RET works in both the TLFS 32-bit and 64-bit calling conventions.
mov dword ptr [r11], 0xc3c1010f
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
.Lresident_hypercall_state_lock:
mov r9, qword ptr [r12 + {b_event_context}]
.Lresident_hypercall_state_lock_retry:
lock bts qword ptr [r9 + {event_hyperv_hypercall_lock}], 0
jnc .Lresident_hypercall_state_locked
pause
jmp .Lresident_hypercall_state_lock_retry
.Lresident_hypercall_state_locked:
ret
.Lresident_dispatch_wrmsr_tsc_invariant:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_dispatch_wrmsr_tsc_invariant_value
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_wrmsr_passthrough
.Lresident_dispatch_wrmsr_tsc_invariant_value:
mov r9, qword ptr [r12 + {b_event_context}]
cmp qword ptr [r9 + {event_hyperv_tsc_invariant_supported}], 0
je .Lresident_dispatch_inject_gp
cmp dword ptr [rsp + 16], 0
jne .Lresident_dispatch_inject_gp
test dword ptr [rsp], -2
jnz .Lresident_dispatch_inject_gp
test byte ptr [rsp], 1
jz .Lresident_dispatch_wrmsr_tsc_invariant_zero
// The native invariant-TSC CPUID bit is already visible to L1. Latch this
// partition-wide acknowledgement without issuing a synthetic MSR on hardware.
lock or qword ptr [r9 + {event_hyperv_tsc_invariant_control}], 1
jmp .Lresident_dispatch_wrmsr_tsc_invariant_done
.Lresident_dispatch_wrmsr_tsc_invariant_zero:
// Once enabled, the guest cannot revoke the invariant-TSC guarantee.
cmp qword ptr [r9 + {event_hyperv_tsc_invariant_control}], 0
jne .Lresident_dispatch_inject_gp
.Lresident_dispatch_wrmsr_tsc_invariant_done:
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
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
jz .Lresident_hyperv_reference_tsc_invalidation_failed
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
.Lresident_hyperv_reference_tsc_invalidation_failed:
// Ownership cannot transfer while the old page still advertises valid time.
// Leave both pages and the MSR unchanged; L1 must restore write access first.
mov qword ptr [r9 + {event_hyperv_reference_tsc_lock}], 0
jmp .Lresident_dispatch_inject_gp
matrixhv_ept01_page_translation
.endm

.macro matrixhv_resident_hyperv_hypercall
.Lresident_dispatch_hyperv_hypercall:
cmp qword ptr [r12 + {b_hyperv_timing_supported}], 0
jne .Lresident_hyperv_hypercall_owned
cmp qword ptr [r12 + {b_nested_evmcs_enabled}], 0
je .Lresident_dispatch_unsupported
.Lresident_hyperv_hypercall_owned:
call .Lresident_guest_privilege
jc .Lresident_dispatch_inject_ud
mov eax, {guest_cr0}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11b, 1
jz .Lresident_dispatch_inject_ud
mov r9, qword ptr [r12 + {b_event_context}]
test byte ptr [r9 + {event_hyperv_hypercall_msr}], 1
jz .Lresident_dispatch_inject_ud
cmp qword ptr [r9 + {event_hyperv_guest_os_id}], 0
je .Lresident_dispatch_inject_ud
mov eax, {guest_cs_ar_bytes}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
xor r13d, r13d
test r11d, 0x2000
jz .Lresident_hyperv_hypercall_32
mov eax, {guest_efer}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 0x400
jz .Lresident_hyperv_hypercall_32
inc r13d
mov r10, qword ptr [rsp + 8]
jmp .Lresident_hyperv_hypercall_control
.Lresident_hyperv_hypercall_32:
mov r10d, dword ptr [rsp + 16]
shl r10, 32
mov eax, dword ptr [rsp]
or r10, rax
.Lresident_hyperv_hypercall_control:
mov eax, {hv_invalid_hypercall_code}
cmp r10w, {hv_notify_long_spin_wait}
jne .Lresident_hyperv_hypercall_result
mov r11, r10
and r11, -65537
cmp r11, {hv_notify_long_spin_wait}
jne .Lresident_hyperv_hypercall_invalid_control
test r13d, r13d
jz .Lresident_hyperv_hypercall_input32
mov r11, qword ptr [rsp + 16]
jmp .Lresident_hyperv_hypercall_input
.Lresident_hyperv_hypercall_input32:
mov r11d, dword ptr [rsp + 24]
shl r11, 32
mov eax, dword ptr [rsp + 8]
or r11, rax
.Lresident_hyperv_hypercall_input:
bt r10, 16
jc .Lresident_hyperv_hypercall_spin
test r11b, 7
jnz .Lresident_hyperv_hypercall_invalid_alignment
call .Lresident_ept01_page_is_readable
test eax, eax
jz .Lresident_hyperv_hypercall_invalid
mov r11, qword ptr [r11]
.Lresident_hyperv_hypercall_spin:
shr r11, 32
jnz .Lresident_hyperv_hypercall_invalid
// Dedicated VPs need no scheduler handoff. Honor the advisory notification
// with a bounded pause while other processors continue running.
mov ecx, 64
.Lresident_hyperv_hypercall_pause:
pause
loop .Lresident_hyperv_hypercall_pause
xor eax, eax
jmp .Lresident_hyperv_hypercall_result
.Lresident_hyperv_hypercall_invalid_control:
mov eax, {hv_invalid_hypercall_input}
jmp .Lresident_hyperv_hypercall_result
.Lresident_hyperv_hypercall_invalid_alignment:
mov eax, {hv_invalid_alignment}
jmp .Lresident_hyperv_hypercall_result
.Lresident_hyperv_hypercall_invalid:
mov eax, {hv_invalid_parameter}
.Lresident_hyperv_hypercall_result:
mov qword ptr [rsp], rax
test r13d, r13d
jnz .Lresident_hyperv_hypercall_done
mov qword ptr [rsp + 16], 0
.Lresident_hyperv_hypercall_done:
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.endm

.macro matrixhv_resident_hyperv_rdmsr_route
cmp ecx, {hyperv_tsc_invariant_control_msr}
je .Lresident_dispatch_rdmsr_tsc_invariant
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
cmp ecx, {hv_eoi_msr}
jb .Lresident_dispatch_rdmsr_apic_checked
cmp ecx, {hv_tpr_msr}
jbe .Lresident_dispatch_rdmsr_hyperv_apic
.endm

.macro matrixhv_resident_hyperv_wrmsr_route
cmp ecx, {hyperv_tsc_invariant_control_msr}
je .Lresident_dispatch_wrmsr_tsc_invariant
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
cmp ecx, {hv_eoi_msr}
jb .Lresident_dispatch_wrmsr_apic_checked
cmp ecx, {hv_tpr_msr}
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
call .Lresident_hyperv_assist_page
test eax, eax
jz .Lresident_hyperv_evmcs_select_invalid
mov eax, dword ptr [r11 + {vp_assist_enlighten_vm_entry}]
test eax, 1
jz .Lresident_hyperv_evmcs_select_none
mov r11, qword ptr [r11 + {vp_assist_current_nested_vmcs}]
cmp r11, qword ptr [r12 + {b_nested_vmxon_region}]
je .Lresident_hyperv_evmcs_select_invalid
mov rax, qword ptr [r12 + {b_nested_vp_assist_msr}]
and rax, -4096
cmp r11, rax
je .Lresident_hyperv_evmcs_select_invalid
cmp r11, -1
je .Lresident_hyperv_evmcs_select_invalid
call .Lresident_nested_physical_address_is_valid
test eax, eax
jz .Lresident_hyperv_evmcs_select_invalid
push r11
call .Lresident_hyperv_evmcs_page
test eax, eax
jz .Lresident_hyperv_evmcs_select_page_invalid
mov eax, dword ptr [r11]
cmp eax, {evmcs_version}
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
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
je .Lresident_hyperv_evmcs_select_changed
cmp rax, qword ptr [r12 + {b_nested_current_vmcs}]
jne .Lresident_hyperv_evmcs_select_changed
cmp r13, qword ptr [r12 + {b_nested_current_vmcs_hpa}]
jne .Lresident_hyperv_evmcs_select_changed
mov r8d, dword ptr [r13 + {evmcs_clean_fields}]
jmp .Lresident_hyperv_evmcs_select_fields_ready
.Lresident_hyperv_evmcs_select_changed:
mov qword ptr [r12 + {b_nested_current_vmcs}], rax
mov qword ptr [r12 + {b_nested_current_vmcs_hpa}], r13
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
xor r8d, r8d
.Lresident_hyperv_evmcs_select_fields_ready:
lea rsi, [rip + .Lresident_evmcs_field_map]
xor r9d, r9d
.Lresident_hyperv_evmcs_select_field:
test dword ptr [rsi + r9 * 8 + 4], r8d
jnz .Lresident_hyperv_evmcs_select_next_field
movzx r10d, word ptr [rsi + r9 * 8 + 2]
test r10d, 0x40
jnz .Lresident_hyperv_evmcs_select_next_field
and r10d, 15
jz .Lresident_hyperv_evmcs_select_next_field
movzx edx, word ptr [rsi + r9 * 8]
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
call .Lresident_hyperv_evmcs_page
test eax, eax
jz .Lresident_dispatch_halt
mov rdi, r11
lea rsi, [rip + .Lresident_evmcs_field_map]
xor r9d, r9d
.Lresident_hyperv_evmcs_store_field:
movzx r10d, word ptr [rsi + r9 * 8 + 2]
test r10d, 0xc0
jz .Lresident_hyperv_evmcs_store_next_field
movzx edx, word ptr [rsi + r9 * 8]
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
// All supported groups now match the per-VP materialized state. L1 clears a
// group's bit on modification; a new GPA/HPA always forces a complete import.
mov dword ptr [rdi + {evmcs_clean_fields}], 0x7fff
.Lresident_hyperv_evmcs_store_done:
ret
// Cache the two shared-page translations, including their full EPT01 paths.
// Validate ancestors before descendants so replaced tables are never followed
// through stale pointers. Permission or mapping changes force a fresh walk;
// no global invalidation assumption is needed, including across root writers.
.Lresident_hyperv_assist_page:
xor r8d, r8d
mov edx, 1
jmp .Lresident_hyperv_cached_page
.Lresident_hyperv_evmcs_page:
call .Lresident_nested_eptp_before_root_write
mov r8d, 96
mov edx, 3
.Lresident_hyperv_cached_page:
push r13
push r14
push r15
lea r13, [r12 + {b_nested_evmcs_page_cache} + r8]
mov r14, r11
mov r15d, edx
mov r8, {host_page_address_mask}
mov r9, qword ptr [r12 + {b_cache_ept_pointer}]
cmp qword ptr [r13 + 24], 0
je .Lresident_hyperv_page_cache_miss
cmp r14, qword ptr [r13]
jne .Lresident_hyperv_page_cache_miss
cmp r9, qword ptr [r13 + 8]
jne .Lresident_hyperv_page_cache_miss
xor ecx, ecx
.Lresident_hyperv_page_cache_check:
mov rax, qword ptr [r13 + 32 + rcx * 8]
mov rax, qword ptr [rax]
cmp rax, qword ptr [r13 + 64 + rcx * 8]
jne .Lresident_hyperv_page_cache_miss
inc ecx
cmp rcx, qword ptr [r13 + 24]
jb .Lresident_hyperv_page_cache_check
mov r11, qword ptr [r13 + 16]
jmp .Lresident_hyperv_page_cache_host
.Lresident_hyperv_page_cache_miss:
mov qword ptr [r13 + 24], 0
mov qword ptr [r13], r14
mov qword ptr [r13 + 8], r9
mov rax, r14
shr rax, 48
jnz .Lresident_hyperv_page_cache_denied
and r9, r8
jz .Lresident_hyperv_page_cache_denied
mov ecx, 39
xor edx, edx
.Lresident_hyperv_page_cache_walk:
mov rax, r14
shr rax, cl
and eax, 511
lea r9, [r9 + rax * 8]
mov qword ptr [r13 + 32 + rdx * 8], r9
mov rax, qword ptr [r9]
mov qword ptr [r13 + 64 + rdx * 8], rax
inc edx
mov r10d, eax
and r10d, r15d
cmp r10d, r15d
jne .Lresident_hyperv_page_cache_denied
cmp ecx, 12
je .Lresident_hyperv_page_cache_leaf
cmp ecx, 39
je .Lresident_hyperv_page_cache_next
test al, 0x80
jnz .Lresident_hyperv_page_cache_leaf
.Lresident_hyperv_page_cache_next:
and rax, r8
mov r9, rax
sub ecx, 9
jmp .Lresident_hyperv_page_cache_walk
.Lresident_hyperv_page_cache_leaf:
mov r10, 1
shl r10, cl
dec r10
mov r11, r14
and r11, r10
not r10
and rax, r10
and rax, r8
or r11, rax
mov qword ptr [r13 + 16], r11
mov qword ptr [r13 + 24], rdx
.Lresident_hyperv_page_cache_host:
call .Lresident_ept01_host_page_is_mapped
test eax, eax
jnz .Lresident_hyperv_page_cache_done
.Lresident_hyperv_page_cache_denied:
mov qword ptr [r13 + 24], 0
xor eax, eax
.Lresident_hyperv_page_cache_done:
pop r15
pop r14
pop r13
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
jne .Lresident_hyperv_evmcs_vmclear_revision_check
// A native revision of one shares the eVMCS header. Require an established
// enlightened selection or the VP Assist handshake before treating it as eVMCS.
cmp edx, dword ptr [r12 + {b_nested_vmcs12_revision_id}]
jne .Lresident_hyperv_evmcs_vmclear_version_ready
// Previously initialized ordinary backing remains identifiable across selections.
mov rax, {vmcs12_backing_magic}
cmp qword ptr [r11 + {vmcs12_backing_magic_offset}], rax
je .Lresident_nested_vmclear_ordinary
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
jne .Lresident_hyperv_evmcs_vmclear_version_ready
jmp .Lresident_hyperv_evmcs_vmclear_check_assist
.Lresident_hyperv_evmcs_vmclear_revision_check:
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

// VMfail publication: R10=instruction error, R12=context. Publish to the selected writable eVMCS page, preserving R10 with one balanced push/pop. Other scratch GPRs/flags change; a lost mapping is fatal just as on the ordinary backing path.
.macro matrixhv_hyperv_evmcs_instruction_error
cmp qword ptr [r12 + {b_nested_evmcs_active}], 0
je .Lresident_nested_vmfail_error_recorded
push r10
mov r11, qword ptr [r12 + {b_nested_current_vmcs}]
call .Lresident_ept01_page_is_writable
pop r10
test eax, eax
jz .Lresident_dispatch_halt
mov dword ptr [r11 + {evmcs_exit_instruction_error}], r10d
.endm

// RIP-relative eVMCS layout table. Indexed by the canonical VMCS12 extended-field index; entries carry byte offsets, widths and copy direction. Expanded at the original data position, with no executable side effects.
.macro matrixhv_hyperv_evmcs_field_map
.Lresident_evmcs_field_map:
// Each entry is an eVMCS byte offset and width; 0x80 copies mutable state back,
// and 0x40 writes a read-only exit field. The trailing dword is the TLFS clean
// group mask; zero means the input is always read.
.short 632, 2
.long 512
.short 92, 4
.long 8
.short 788, 4
.long 16
.short 100, 4
.long 8
.short 792, 4
.long 128
.short 376, 4
.long 0
.short 380, 4
.long 0
.short 384, 4
.long 0
.short 96, 4
.long 8
.short 388, 4
.long 0
.short 392, 4
.long 0
.short 796, 132
.long 64
.short 396, 4
.long 0
.short 800, 132
.long 32
.short 804, 4
.long 32
.short 808, 4
.long 32
.short 624, 8
.long 512
.short 400, 8
.long 4
.short 120, 8
.long 2
.short 512, 8
.long 256
.short 520, 8
.long 256
.short 528, 8
.long 256
.short 536, 8
.long 256
.short 416, 8
.long 2048
.short 424, 136
.long 2048
.short 432, 136
.long 2048
.short 440, 136
.long 2048
.short 24, 8
.long 16384
.short 32, 8
.long 16384
.short 544, 136
.long 256
.short 552, 136
.long 256
.short 560, 136
.long 256
.short 40, 8
.long 16384
.short 48, 8
.long 16384
.short 56, 8
.long 16384
.short 128, 130
.long 4096
.short 130, 130
.long 4096
.short 132, 130
.long 4096
.short 134, 130
.long 4096
.short 136, 130
.long 4096
.short 138, 130
.long 4096
.short 140, 130
.long 4096
.short 142, 130
.long 4096
.short 8, 2
.long 16384
.short 10, 2
.long 16384
.short 12, 2
.long 16384
.short 14, 2
.long 16384
.short 16, 2
.long 16384
.short 18, 2
.long 16384
.short 20, 2
.long 16384
.short 216, 136
.long 4096
.short 224, 136
.long 4096
.short 232, 136
.long 4096
.short 240, 136
.long 4096
.short 248, 136
.long 4096
.short 256, 136
.long 4096
.short 264, 136
.long 4096
.short 272, 136
.long 4096
.short 280, 136
.long 4096
.short 288, 136
.long 4096
.short 576, 8
.long 8192
.short 584, 8
.long 8192
.short 592, 8
.long 8192
.short 600, 8
.long 8192
.short 608, 8
.long 8192
.short 144, 132
.long 4096
.short 148, 132
.long 4096
.short 152, 132
.long 4096
.short 156, 132
.long 4096
.short 160, 132
.long 4096
.short 164, 132
.long 4096
.short 168, 132
.long 4096
.short 172, 132
.long 4096
.short 176, 132
.long 4096
.short 180, 132
.long 4096
.short 184, 132
.long 4096
.short 188, 132
.long 4096
.short 192, 132
.long 4096
.short 196, 132
.long 4096
.short 200, 132
.long 4096
.short 204, 132
.long 4096
.short 208, 132
.long 4096
.short 212, 132
.long 4096
.short 784, 132
.long 1024
.short 504, 132
.long 2048
.short 508, 132
.long 2048
.short 488, 136
.long 2048
.short 496, 136
.long 2048
.short 88, 4
.long 16384
.short 64, 8
.long 16384
.short 72, 8
.long 16384
.short 568, 136
.long 256
.short 480, 136
.long 2048
.short 104, 8
.long 1
.short 112, 8
.long 1
.short 960, 8
.long 4
.short 344, 8
.long 0
.short 352, 8
.long 0
.short 360, 8
.long 0
.short 368, 8
.long 0
.short 812, 4
.long 0
.short 408, 8
.long 4
.short 0, 0
.long 0
.short 320, 8
.long 0
.short 328, 8
.long 0
.short 336, 8
.long 0
.short 696, 68
.long 0
.short 700, 68
.long 0
.short 704, 68
.long 0
.short 708, 68
.long 0
.short 680, 72
.long 0
.short 448, 136
.long 2048
.short 456, 136
.long 2048
.short 464, 136
.long 2048
.short 472, 136
.long 2048
.short 716, 68
.long 0
.short 760, 72
.long 0
.short 0, 0
.long 0
.short 0, 0
.long 0
.short 0, 0
.long 0
.short 0, 0
.long 0
.short 0, 0
.long 0
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
