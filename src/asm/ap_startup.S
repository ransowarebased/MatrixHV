// AP architectural exits enter with R12=context and the dispatcher GPR frame.
// INIT clears that frame and programs reset VMCS state; SIPI consumes the
// recorded vector and resumes without advancing RIP. Scratch GPRs/flags may
// change, R12/root stack/SIMD stay intact, and VMCS failures use common errors.
// Reset tables are island-relative. CR writes and VPID retirement belong to
// exits.S; this component calls its .Lap_flush_guest_tlb helper after reset.
.macro matrixhv_resident_ap_startup
.Lresident_ap_ready:
    mov qword ptr [r12 + {b_telemetry_probe_active}], 0
    mov qword ptr [r12 + {b_ap_started}], 1
    call .Lresident_advance_guest_rip
    jmp .Lresident_dispatch_resume

// INIT resets the AP guest into wait-for-SIPI while its VMCS and root resources stay live.
.Lresident_ap_init:
    cmp qword ptr [r12 + {b_ap_started}], 1
    jne .Lresident_dispatch_unsupported
    resident_telemetry_counter inc, {b_init_count}, {b_telemetry_active}
    mov r8, qword ptr [r12 + {b_event_context}]
    mov rcx, qword ptr [r12 + {b_processor_number}]
    test r8, r8
    jz .Lap_init_recorded
    cmp rcx, 64
    jae .Lap_init_recorded
    lock bts qword ptr [r8 + {event_init_cpu_mask}], rcx
.Lap_init_recorded:
    lea rsi, [rip + .Lap_reset_fields]
    lea rdi, [rip + .Lap_reset_fields_end]
.Lap_reset_loop:
    mov rax, [rsi]
    mov r10, [rsi + 8]
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    add rsi, 16
    cmp rsi, rdi
    jb .Lap_reset_loop
    mov rax, {vm_entry_controls}
    vmread r10, rax
    jc .Lresident_dispatch_vmread_failed
    jz .Lresident_dispatch_vmread_failed
    and r10, -513
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    mov qword ptr [r12 + {b_nested_l1_cr4}], 0
    mov qword ptr [r12 + {b_nmi_pending}], 0
    call .Lap_flush_guest_tlb
    mov rdi, rsp
    xor eax, eax
    mov ecx, 15
    rep stosq
    mov eax, 1
    cpuid
    mov [rsp + 16], rax
    jmp .Lresident_dispatch_resume

.Lresident_ap_sipi:
    cmp qword ptr [r12 + {b_ap_started}], 1
    jne .Lresident_dispatch_unsupported
    resident_telemetry_counter inc, {b_sipi_count}, {b_telemetry_active}
    mov r8, qword ptr [r12 + {b_event_context}]
    mov rcx, qword ptr [r12 + {b_processor_number}]
    test r8, r8
    jz .Lap_sipi_recorded
    cmp rcx, 64
    jae .Lap_sipi_recorded
    lock bts qword ptr [r8 + {event_sipi_cpu_mask}], rcx
.Lap_sipi_recorded:
    mov r10, [r12 + {b_last_qualification}]
    and r10, 255
    shl r10, 8
    mov rax, {guest_cs_selector}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    shl r10, 4
    mov rax, {guest_cs_base}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    xor r10d, r10d
    mov rax, {guest_rip}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    mov rax, {guest_activity_state}
    vmwrite rax, r10
    jc .Lresident_dispatch_vmwrite_failed
    jz .Lresident_dispatch_vmwrite_failed
    jmp .Lresident_dispatch_resume

matrixhv_island_cr_access
.Lap_reset_fields:
    .quad {guest_cr0}, 0x60000030
    .quad {cr0_read_shadow}, 0x60000010
    .quad {cr0_guest_host_mask}, 0xe0000021
    .quad {guest_cr3}, 0
    .quad {guest_cr4}, 0x2000
    .quad {cr4_read_shadow}, 0
    .quad {cr4_guest_host_mask}, 0x2000
    .quad {guest_efer}, 0
    .quad {guest_rip}, 0xfff0
    .quad {guest_rsp}, 0
    .quad {guest_rflags}, 2
    .quad {guest_dr7}, 0x400
    .quad {guest_ia32_debugctl}, 0
    .quad {guest_pending_dbg_exceptions}, 0
    .quad {guest_interruptibility_info}, 0
    .quad {guest_activity_state}, 3
    .quad {vm_entry_intr_info_field}, 0
    .quad {guest_sysenter_cs}, 0
    .quad {guest_sysenter_esp}, 0
    .quad {guest_sysenter_eip}, 0
    .quad {guest_gdtr_base}, 0
    .quad {guest_gdtr_limit}, 0xffff
    .quad {guest_idtr_base}, 0
    .quad {guest_idtr_limit}, 0xffff
    .quad {guest_es_selector}, 0
    .quad {guest_es_base}, 0
    .quad {guest_es_limit}, 0xffff
    .quad {guest_es_ar_bytes}, 0x93
    .quad {guest_cs_selector}, 0xf000
    .quad {guest_cs_base}, 0xffff0000
    .quad {guest_cs_limit}, 0xffff
    .quad {guest_cs_ar_bytes}, 0x9b
    .quad {guest_ss_selector}, 0
    .quad {guest_ss_base}, 0
    .quad {guest_ss_limit}, 0xffff
    .quad {guest_ss_ar_bytes}, 0x93
    .quad {guest_ds_selector}, 0
    .quad {guest_ds_base}, 0
    .quad {guest_ds_limit}, 0xffff
    .quad {guest_ds_ar_bytes}, 0x93
    .quad {guest_fs_selector}, 0
    .quad {guest_fs_base}, 0
    .quad {guest_fs_limit}, 0xffff
    .quad {guest_fs_ar_bytes}, 0x93
    .quad {guest_gs_selector}, 0
    .quad {guest_gs_base}, 0
    .quad {guest_gs_limit}, 0xffff
    .quad {guest_gs_ar_bytes}, 0x93
    .quad {guest_ldtr_selector}, 0
    .quad {guest_ldtr_base}, 0
    .quad {guest_ldtr_limit}, 0xffff
    .quad {guest_ldtr_ar_bytes}, 0x82
    .quad {guest_tr_selector}, 0
    .quad {guest_tr_base}, 0
    .quad {guest_tr_limit}, 0xffff
    .quad {guest_tr_ar_bytes}, 0x8b
.Lap_reset_fields_end:
.endm
