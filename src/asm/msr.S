// RDMSR/WRMSR enter with R12=context and RSP=dispatcher GPR frame. ECX comes
// from the saved guest register; EDX:EAX results are committed to that frame.
// Handlers clobber scratch GPRs/flags, preserve R12/frame ownership and never
// use SIMD or firmware. Nested/Hyper-V routes share these dispatch contracts.
// Guarded host accesses return CF=fault; privilege checks return CF=denied.
// exits.S supplies shared privilege and fault recovery; only this owner
// exports guarded RDMSR/WRMSR instruction addresses for that recovery contract.
.macro matrixhv_resident_msr_access
.Lresident_dispatch_rdmsr:
resident_telemetry_counter inc, {b_rdmsr_count}, {b_telemetry_active}
call .Lresident_guest_privilege
jc .Lresident_dispatch_inject_gp
mov ecx, dword ptr [rsp + 8]
mov eax, ecx
sub eax, {hv_msr_base}
cmp eax, {hv_msr_range_span}
ja .Lresident_dispatch_rdmsr_apic_checked
matrixhv_resident_hyperv_rdmsr_route
.Lresident_dispatch_rdmsr_apic_checked:
cmp ecx, {platform_id_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {apic_base_msr}
je .Lresident_dispatch_rdmsr_passthrough
cmp ecx, {xss_msr}
je .Lresident_dispatch_rdmsr_passthrough
matrixhv_resident_nested_rdmsr_route
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
matrixhv_resident_hyperv_read_passthrough
cmp ecx, {sysenter_cs_msr}
je .Lresident_dispatch_rdmsr_sysenter_cs
cmp ecx, {sysenter_esp_msr}
je .Lresident_dispatch_rdmsr_sysenter_esp
cmp ecx, {sysenter_eip_msr}
je .Lresident_dispatch_rdmsr_sysenter_eip
cmp ecx, 0x1d9
je .Lresident_dispatch_rdmsr_debugctl
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
matrixhv_resident_nested_msr_values
.Lresident_dispatch_rdmsr_nested_value:
mov eax, r11d
mov qword ptr [rsp + 0], rax
shr r11, 32
mov eax, r11d
mov qword ptr [rsp + 16], rax
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
matrixhv_resident_hyperv_rdmsr
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
call .Lresident_hyperv_require_parent_msr
jc .Lresident_dispatch_inject_gp
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
.Lresident_dispatch_rdmsr_debugctl:
mov eax, {guest_ia32_debugctl}
jmp .Lresident_dispatch_rdmsr_vmcs_value
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
call .Lresident_guest_privilege
jc .Lresident_dispatch_inject_gp
mov ecx, dword ptr [rsp + 8]
mov eax, ecx
sub eax, {hv_msr_base}
cmp eax, {hv_msr_range_span}
ja .Lresident_dispatch_wrmsr_apic_checked
matrixhv_resident_hyperv_wrmsr_route
.Lresident_dispatch_wrmsr_apic_checked:
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
matrixhv_resident_hyperv_write_passthrough
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
cmp ecx, 0x1d9
je .Lresident_dispatch_wrmsr_debugctl
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
.Lresident_dispatch_wrmsr_debugctl:
// Validate model-specific DEBUGCTL bits without retaining the guest value in root.
call .Lresident_guarded_rdmsr
jc .Lresident_dispatch_inject_gp
push rdx
push rax
mov eax, dword ptr [rsp + 16]
mov edx, dword ptr [rsp + 32]
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_wrmsr_debugctl_invalid
pop rax
pop rdx
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_halt
mov r11d, dword ptr [rsp]
mov r10d, dword ptr [rsp + 16]
shl r10, 32
or r11, r10
mov eax, {guest_ia32_debugctl}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.Lresident_dispatch_wrmsr_debugctl_invalid:
add rsp, 16
jmp .Lresident_dispatch_inject_gp
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
call .Lresident_hyperv_require_parent_msr
jc .Lresident_dispatch_inject_gp
mov eax, dword ptr [rsp + 0]
mov edx, dword ptr [rsp + 16]
call .Lresident_guarded_wrmsr
jc .Lresident_dispatch_inject_gp
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
matrixhv_resident_hyperv_wrmsr
matrixhv_resident_xsetbv
.endm


.macro matrixhv_resident_msr_validation
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
matrixhv_resident_guarded_xsetbv
matrixhv_resident_access_faults
.endm

.macro matrixhv_island_switch_slot
.globl matrixhv_resident_island_msr_switch_count
matrixhv_resident_island_msr_switch_count:
.quad 0
.endm
