.text
.globl matrixhv_boot_loader_start_checkpoint_asm
matrixhv_boot_loader_start_checkpoint_asm:
    mov rax, {checkpoint_magic}
    vmcall
    ret
.globl matrixhv_boot_loader_start_guest_asm
matrixhv_boot_loader_start_guest_asm:
    mov rbx, rax
    sub rsp, 32
    call matrixhv_vmx_test_enabled
    add rsp, 32
    test rax, rax
    jz .Lwindows_cpuid_done
    mov rax, rbx
    mov r8, qword ptr [rax + 8]
    mov r9, qword ptr [rax + 16]
    mov rbx, rax
    mov r10, cr4
    mov r12, r10
    or r10, 0x2000
    mov cr4, r10
    vmxon [rax]
    jna .Lwindows_nested_probe_failed
    vmclear [r8]
    jna .Lwindows_nested_probe_failed
    vmptrld [r8]
    jna .Lwindows_nested_probe_failed
    vmxon [rax]
    pushfq
    pop r10
    and r10d, 0x8d5
    cmp r10d, 0x40
    jne .Lwindows_nested_probe_failed
    mov rcx, {instruction_error_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {vmxon_active_error}
    jne .Lwindows_nested_probe_failed
    vmptrst [r9]
    jna .Lwindows_nested_probe_failed
    mov r10, qword ptr [r8]
    cmp qword ptr [r9], r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    mov rdx, {vmcs12_test_value}
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    mov r10, {vmcs12_test_value}
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {exception_bitmap_field}
    mov edx, 0x40
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, 0x40
    jne .Lwindows_nested_probe_failed
    mov rcx, {cr3_target_count_field}
    mov edx, 5
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, 5
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_cr3_field}
    mov rdx, cr3
    mov r10, rdx
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {host_cr3_field}
    mov rdx, cr3
    mov r10, rdx
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_cr0_field}
    mov rdx, cr0
    mov r10, rdx
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {host_cr0_field}
    mov rdx, r10
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_cr4_field}
    mov rdx, cr4
    mov r10, rdx
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {host_cr4_field}
    mov rdx, r10
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov ecx, {sysenter_cs_msr}
    rdmsr
    shl rdx, 32
    or rdx, rax
    mov r10, rdx
    mov rcx, {guest_sysenter_cs_field}
    vmwrite rcx, r10
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {host_sysenter_cs_field}
    vmwrite rcx, r10
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov ecx, {sysenter_esp_msr}
    rdmsr
    shl rdx, 32
    or rdx, rax
    mov r10, rdx
    mov rcx, {guest_sysenter_esp_field}
    vmwrite rcx, r10
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {host_sysenter_esp_field}
    vmwrite rcx, r10
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov ecx, {sysenter_eip_msr}
    rdmsr
    shl rdx, 32
    or rdx, rax
    mov r10, rdx
    mov rcx, {guest_sysenter_eip_field}
    vmwrite rcx, r10
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {host_sysenter_eip_field}
    vmwrite rcx, r10
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    vmlaunch
    pushfq
    pop r10
    and r10d, 0x8d5
    cmp r10d, 64
    jne .Lwindows_nested_probe_failed
    mov rcx, {instruction_error_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {invalid_control_error}
    jne .Lwindows_nested_probe_failed
    vmresume
    pushfq
    pop r10
    and r10d, 0x8d5
    cmp r10d, 64
    jne .Lwindows_nested_probe_failed
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {non_launched_error}
    jne .Lwindows_nested_probe_failed
    vmclear [r8]
    jna .Lwindows_nested_probe_failed
    vmlaunch
    pushfq
    pop r10
    and r10d, 0x8d5
    cmp r10d, 1
    jne .Lwindows_nested_probe_failed
    vmresume
    pushfq
    pop r10
    and r10d, 0x8d5
    cmp r10d, 1
    jne .Lwindows_nested_probe_failed
    vmptrld [r8]
    jna .Lwindows_nested_probe_failed
    mov rcx, {exception_bitmap_field}
    xor edx, edx
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {cr3_target_count_field}
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {pin_based_control_field}
    xor edx, edx
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    test edx, edx
    jnz .Lwindows_nested_probe_failed
    mov rcx, {primary_control_field}
    mov edx, {primary_activate_secondary_controls}
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {primary_activate_secondary_controls}
    jne .Lwindows_nested_probe_failed
    mov rcx, {secondary_control_field}
    mov edx, {secondary_enable_ept}
    or edx, {secondary_enable_vpid}
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    mov r10d, {secondary_enable_ept}
    or r10d, {secondary_enable_vpid}
    cmp edx, r10d
    jne .Lwindows_nested_probe_failed
    mov rcx, {vpid_field}
    mov edx, 1
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, 1
    jne .Lwindows_nested_probe_failed
    mov rcx, {ept_pointer_field}
    mov rdx, qword ptr [rbx + 24]
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, qword ptr [rbx + 24]
    jne .Lwindows_nested_probe_failed
    mov rcx, {vm_exit_controls_field}
    mov edx, {vm_exit_host_address_space_size}
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {vm_exit_host_address_space_size}
    jne .Lwindows_nested_probe_failed
    mov rcx, {vm_entry_controls_field}
    mov edx, {vm_entry_ia32e_mode_guest}
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    xor edx, edx
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {vm_entry_ia32e_mode_guest}
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    lea rdx, [rip + .Lwindows_nested_l2_entry]
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {guest_rsp_field}
    mov rdx, rsp
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {guest_rflags_field}
    mov rdx, 2
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {host_rip_field}
    lea rdx, [rip + .Lwindows_nested_l1_exit]
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {host_rsp_field}
    mov rdx, rsp
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov r14, qword ptr [rbx + 32]
    mov r15, qword ptr [rbx + 40]
    mov r10, qword ptr [r14]
    mov r11, {ept_source_marker}
    cmp r10, r11
    jne .Lwindows_nested_probe_failed
    mov r10, qword ptr [r15]
    mov r11, {ept_target_marker}
    cmp r10, r11
    jne .Lwindows_nested_probe_failed
    vmlaunch
    jmp .Lwindows_nested_probe_failed
.Lwindows_nested_l2_entry:
    mov r13, qword ptr [r14]
    mov r11, {ept_target_marker}
    cmp r13, r11
    jne .Lwindows_nested_l2_bad_resume
    mov rax, {l2_vmcall_magic}
.Lwindows_nested_l2_vmcall:
    vmcall
.Lwindows_nested_l2_after_first:
    mov r13, qword ptr [r14]
    mov r11, {ept_target_marker}
    cmp r13, r11
    jne .Lwindows_nested_l2_bad_resume
    mov r10, {l2_vmresume_magic}
    cmp rax, r10
    jne .Lwindows_nested_l2_bad_resume
.Lwindows_nested_l2_before_invept_vmcall:
    vmcall
.Lwindows_nested_l2_after_invept:
    mov r13, qword ptr [r14]
    mov r11, {ept_second_target_marker}
    cmp r13, r11
    jne .Lwindows_nested_l2_bad_resume
    mov r10, {l2_post_invept_magic}
    cmp rax, r10
    jne .Lwindows_nested_l2_bad_resume
.Lwindows_nested_l2_after_invept_vmcall:
    vmcall
.Lwindows_nested_l2_bad_resume:
    ud2
.Lwindows_nested_l1_exit:
    mov r10, {l2_vmcall_magic}
    cmp rax, r10
    je .Lwindows_nested_l1_first_exit
    mov r10, {l2_vmresume_magic}
    cmp rax, r10
    je .Lwindows_nested_l1_resume_exit
    mov r10, {l2_post_invept_magic}
    cmp rax, r10
    je .Lwindows_nested_l1_after_invept_exit
    jmp .Lwindows_nested_probe_failed
.Lwindows_nested_l1_first_exit:
    mov rcx, {exit_reason_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    and edx, 0xffff
    cmp edx, 18
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    lea r10, [rip + .Lwindows_nested_l2_vmcall]
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {exit_instruction_len_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, 3
    jne .Lwindows_nested_probe_failed
    mov r11, {ept_target_marker}
    cmp r13, r11
    jne .Lwindows_nested_probe_failed
    mov r10, qword ptr [r14]
    mov r11, {ept_source_marker}
    cmp r10, r11
    jne .Lwindows_nested_probe_failed
    mov r10, qword ptr [rbx + 56]
    mov r11, qword ptr [r10]
    and r11, 0xfff
    mov rdx, qword ptr [rbx + 48]
    or r11, rdx
    mov qword ptr [r10], r11
    mov rcx, {guest_rip_field}
    lea rdx, [rip + .Lwindows_nested_l2_after_first]
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rax, {l2_vmresume_magic}
    vmresume
    jmp .Lwindows_nested_probe_failed
.Lwindows_nested_l1_resume_exit:
    mov rcx, {exit_reason_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    and edx, 0xffff
    cmp edx, 18
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    lea r10, [rip + .Lwindows_nested_l2_before_invept_vmcall]
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {exit_instruction_len_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, 3
    jne .Lwindows_nested_probe_failed
    mov r11, {ept_target_marker}
    cmp r13, r11
    jne .Lwindows_nested_probe_failed
    lea r10, [rip + .Lwindows_nested_invept_invalid]
    mov qword ptr [rbx + 80], r10
    lea r10, [rip + .Lwindows_nested_invept_invalid_after]
    mov qword ptr [rbx + 88], r10
    mov rcx, 2
.Lwindows_nested_invept_invalid:
    invept rcx, xmmword ptr [rbx + 64]
.Lwindows_nested_invept_invalid_after:
    pushfq
    pop r10
    and r10d, 0x8d5
    cmp r10d, 0x40
    jne .Lwindows_nested_probe_failed
    mov rcx, {instruction_error_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {invalid_invalidation_operand_error}
    jne .Lwindows_nested_probe_failed
    lea r10, [rip + .Lwindows_nested_invept_valid]
    mov qword ptr [rbx + 80], r10
    lea r10, [rip + .Lwindows_nested_invept_valid_after]
    mov qword ptr [rbx + 88], r10
    mov rcx, 1
.Lwindows_nested_invept_valid:
    invept rcx, xmmword ptr [rbx + 64]
.Lwindows_nested_invept_valid_after:
    pushfq
    pop r10
    and r10d, 0x8d5
    test r10d, r10d
    jnz .Lwindows_nested_probe_failed
    mov qword ptr [rbx + 96], 0
    lea r10, [rip + .Lwindows_nested_invvpid_invalid]
    mov qword ptr [rbx + 112], r10
    lea r10, [rip + .Lwindows_nested_invvpid_invalid_after]
    mov qword ptr [rbx + 120], r10
    mov rcx, 1
.Lwindows_nested_invvpid_invalid:
    invvpid rcx, xmmword ptr [rbx + 96]
.Lwindows_nested_invvpid_invalid_after:
    pushfq
    pop r10
    and r10d, 0x8d5
    cmp r10d, 0x40
    jne .Lwindows_nested_probe_failed
    mov rcx, {instruction_error_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, {invalid_invalidation_operand_error}
    jne .Lwindows_nested_probe_failed
    mov qword ptr [rbx + 96], 1
    lea r10, [rip + .Lwindows_nested_invvpid_valid]
    mov qword ptr [rbx + 112], r10
    lea r10, [rip + .Lwindows_nested_invvpid_valid_after]
    mov qword ptr [rbx + 120], r10
    mov rcx, 1
.Lwindows_nested_invvpid_valid:
    invvpid rcx, xmmword ptr [rbx + 96]
.Lwindows_nested_invvpid_valid_after:
    pushfq
    pop r10
    and r10d, 0x8d5
    test r10d, r10d
    jnz .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    lea rdx, [rip + .Lwindows_nested_l2_after_invept]
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rax, {l2_post_invept_magic}
    vmresume
    jmp .Lwindows_nested_probe_failed
.Lwindows_nested_l1_after_invept_exit:
    mov rcx, {exit_reason_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    and edx, 0xffff
    cmp edx, 18
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    lea r10, [rip + .Lwindows_nested_l2_after_invept_vmcall]
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {exit_instruction_len_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, 3
    jne .Lwindows_nested_probe_failed
    mov r11, {ept_second_target_marker}
    cmp r13, r11
    jne .Lwindows_nested_probe_failed
    vmxoff
    jna .Lwindows_nested_probe_failed
    mov cr4, r12
    sub rsp, 32
    call matrixhv_vt_nested_enabled
    add rsp, 32
    test rax, rax
    jnz .Lwindows_cpuid_done
    mov eax, 1
    xor ecx, ecx
    cpuid
    test ecx, 0x20
    jnz .Lwindows_nested_probe_failed
    test ecx, 0x80000000
    jnz .Lwindows_cpuid_done
    mov eax, 0x40000000
    xor ecx, ecx
    cpuid
    or eax, ebx
    or eax, ecx
    or eax, edx
    jnz .Lwindows_nested_probe_failed
    mov eax, 0x40000003
    xor ecx, ecx
    cpuid
    or eax, ebx
    or eax, ecx
    or eax, edx
    jnz .Lwindows_nested_probe_failed
    mov eax, 0x40000010
    xor ecx, ecx
    cpuid
    or eax, ebx
    or eax, ecx
    or eax, edx
    jnz .Lwindows_nested_probe_failed
    mov eax, 0x40000100
    xor ecx, ecx
    cpuid
    or eax, ebx
    or eax, ecx
    or eax, edx
    jnz .Lwindows_nested_probe_failed
.Lwindows_cpuid_done:
    sub rsp, 32
    call matrixhv_boot_loader_start_guest_stage
    add rsp, 32
    mov rdx, rax
    mov rax, {stop_magic}
    vmcall
    ud2
.Lwindows_nested_probe_failed:
    mov rax, {nested_probe_failed}
    vmcall
    ud2
