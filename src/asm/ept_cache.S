// Called inside root with R12=context and an intact dispatcher guest frame.
// Cache helpers use b_* offsets and clobber scratch GPRs/flags, retain R12,
// balance their local stack and leave SIMD untouched. Range/table arguments
// are documented below; helpers RET or take common VMCS/invalidation errors.
// Cache updates use a resident lock and generation counter; every CPU invalidates
// locally before reentry. No page allocation or mapping lifetime changes occur here.
.macro matrixhv_resident_ept_cache
// MTRR snapshots match ept::MtrrState. No firmware, allocator, or guest pointer
// is used here; the shared EPT keeps its original mappings and access rights.
.Lresident_update_dirty_mtrrs:
    cmp qword ptr [r12 + {b_mtrr_dirty}], 0
    je .Lresident_update_dirty_mtrrs_done
    // VM exit saves the physical CD bit, which stays clear while CD is masked.
    // The read shadow retains the guest's cache-disable transaction boundary.
    mov eax, {cr0_read_shadow}
    vmread r11, rax
    jna .Lresident_dispatch_vmread_failed
    bt r11, 30
    jc .Lresident_update_dirty_mtrrs_done
    call .Lresident_rebuild_ept_cache
    mov qword ptr [r12 + {b_mtrr_dirty}], 0
.Lresident_update_dirty_mtrrs_done:
    ret

.Lresident_rebuild_ept_cache:
    push rbx
    push rbp
    push rsi
    push rdi
    push r13
    push r14
    push r15
    sub rsp, 4192
    mov r15, rsp
    mov rdi, rsp
    xor eax, eax
    mov ecx, 524
    rep stosq
    mov ecx, 0xfe
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [r15], rax
    mov ecx, 0x2ff
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [r15 + 8], rax
    mov eax, 0x80000008
    xor ecx, ecx
    cpuid
    movzx ecx, al
    mov rax, 1
    shl rax, cl
    dec rax
    and rax, -4096
    mov [r15 + 16], rax
    test qword ptr [r15], 0x100
    jz .Lresident_cache_capture_variable
    lea rsi, [rip + .Lresident_fixed_mtrr_registers]
    xor ebx, ebx
.Lresident_cache_capture_fixed:
    movzx ecx, word ptr [rsi + rbx * 2]
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [r15 + rbx * 8 + 24], rax
    inc ebx
    cmp ebx, 11
    jb .Lresident_cache_capture_fixed
.Lresident_cache_capture_variable:
    movzx ebx, byte ptr [r15]
    shl ebx, 1
    lea rdi, [r15 + 112]
    mov ecx, 0x200
    test ebx, ebx
    jz .Lresident_cache_lock
.Lresident_cache_capture_pair:
    rdmsr
    shl rdx, 32
    or rax, rdx
    stosq
    inc ecx
    dec ebx
    jnz .Lresident_cache_capture_pair
.Lresident_cache_lock:
    xor eax, eax
    mov edx, 1
    lock cmpxchg qword ptr [rip + .Lresident_cache_lock_word], rdx
    je .Lresident_cache_locked
    pause
    jmp .Lresident_cache_lock
.Lresident_cache_locked:
    movzx ecx, byte ptr [r15]
    lea ecx, [rcx * 2 + 14]
    mov rsi, r15
    lea rdi, [rip + .Lresident_cache_last_snapshot]
    repe cmpsq
    je .Lresident_cache_unlock
    movzx ecx, byte ptr [r15]
    lea ecx, [rcx * 2 + 14]
    mov rsi, r15
    lea rdi, [rip + .Lresident_cache_last_snapshot]
    rep movsq
    wbinvd
    mov rdi, qword ptr [r12 + {b_cache_ept_pointer}]
    mov rax, {host_page_address_mask}
    and rdi, rax
    mov edx, 4
    call .Lresident_cache_update_table
    wbinvd
    lock inc qword ptr [rip + .Lresident_cache_generation]
    resident_telemetry_counter inc, {b_mtrr_updates}, {b_telemetry_active}
.Lresident_cache_unlock:
    mov qword ptr [rip + .Lresident_cache_lock_word], 0
    add rsp, 4192
    pop r15
    pop r14
    pop r13
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

// Input RDI = EPT table, EDX = level, R15 = snapshot. All tree nodes already exist.
.Lresident_cache_update_table:
    push rbx
    push rbp
    push rsi
    push r13
    mov rsi, rdi
    mov ebp, edx
    mov ebx, 512
.Lresident_cache_update_entry:
    mov r13, [rsi]
    test r13b, 7
    jz .Lresident_cache_next_entry
    mov rdi, {host_page_address_mask}
    and rdi, r13
    cmp ebp, 1
    je .Lresident_cache_update_leaf
    test r13b, 0x80
    jnz .Lresident_cache_update_leaf
    lea edx, [rbp - 1]
    call .Lresident_cache_update_table
    jmp .Lresident_cache_next_entry
.Lresident_cache_update_leaf:
    mov ecx, ebp
    dec ecx
    imul ecx, 9
    add ecx, 12
    mov r10, 1
    shl r10, cl
    add r10, rdi
    call .Lresident_cache_range_type
    mov rdx, r13
    shr rdx, 52
    and edx, 7
    cmp eax, edx
    je .Lresident_cache_leaf_type_ready
    cmp edx, 6
    je .Lresident_cache_leaf_type_ready
    cmp eax, 6
    je .Lresident_cache_leaf_firmware_type
    xor edx, edx
.Lresident_cache_leaf_firmware_type:
    mov eax, edx
.Lresident_cache_leaf_type_ready:
    shl eax, 3
    and r13, -57
    or r13, rax
    mov [rsi], r13
.Lresident_cache_next_entry:
    add rsi, 8
    dec ebx
    jnz .Lresident_cache_update_entry
    pop r13
    pop rsi
    pop rbp
    pop rbx
    ret

// Input RDI = range start, R10 = exclusive end, R15 = snapshot; EAX = safe type.
.Lresident_cache_range_type:
    test qword ptr [r15 + 8], 0x800
    jz .Lresident_cache_type_uc
    cmp rdi, 0x100000
    jae .Lresident_cache_variable_type
    test qword ptr [r15 + 8], 0x400
    jz .Lresident_cache_variable_type
    test qword ptr [r15], 0x100
    jz .Lresident_cache_variable_type
    mov rcx, rdi
    xor eax, eax
    cmp rdi, 0x80000
    jae .Lresident_cache_fixed_16k
    shr rcx, 16
    jmp .Lresident_cache_fixed_value
.Lresident_cache_fixed_16k:
    cmp rdi, 0xc0000
    jae .Lresident_cache_fixed_4k
    lea rax, [rdi - 0x80000]
    shr rax, 17
    inc eax
    shr rcx, 14
    jmp .Lresident_cache_fixed_value
.Lresident_cache_fixed_4k:
    lea rax, [rdi - 0xc0000]
    shr rax, 15
    add eax, 3
    shr rcx, 12
.Lresident_cache_fixed_value:
    and ecx, 7
    shl ecx, 3
    mov rax, [r15 + rax * 8 + 24]
    shr rax, cl
    movzx eax, al
    jmp .Lresident_cache_validate_type
.Lresident_cache_variable_type:
    mov r8d, -1
    movzx ecx, byte ptr [r15]
    lea rdx, [r15 + 112]
    test ecx, ecx
    jz .Lresident_cache_variable_done
.Lresident_cache_variable_loop:
    mov rax, [rdx + 8]
    test eax, 0x800
    jz .Lresident_cache_variable_next
    and rax, [r15 + 16]
    mov r9, [rdx]
    and r9, rax
    mov r11, rax
    not r11
    and r11, [r15 + 16]
    or r11, 0xfff
    lea r11, [r11 + r9 + 1]
    cmp r9, r10
    jae .Lresident_cache_variable_next
    cmp r11, rdi
    jbe .Lresident_cache_variable_next
    cmp r9, rdi
    ja .Lresident_cache_type_uc
    cmp r11, r10
    jb .Lresident_cache_type_uc
    movzx eax, byte ptr [rdx]
    call .Lresident_cache_validate_type
    test eax, eax
    jz .Lresident_cache_type_uc
    cmp r8d, -1
    je .Lresident_cache_variable_select
    cmp r8d, eax
    je .Lresident_cache_variable_next
    mov r11d, r8d
    or r11d, eax
    cmp r11d, 6
    jne .Lresident_cache_type_uc
    and r8d, eax
    cmp r8d, 4
    jne .Lresident_cache_type_uc
    jmp .Lresident_cache_variable_next
.Lresident_cache_variable_select:
    mov r8d, eax
.Lresident_cache_variable_next:
    add rdx, 16
    dec ecx
    jnz .Lresident_cache_variable_loop
.Lresident_cache_variable_done:
    mov eax, r8d
    cmp eax, -1
    jne .Lresident_cache_type_return
    movzx eax, byte ptr [r15 + 8]
.Lresident_cache_validate_type:
    cmp eax, 1
    je .Lresident_cache_type_return
    cmp eax, 4
    jb .Lresident_cache_type_uc
    cmp eax, 6
    jbe .Lresident_cache_type_return
.Lresident_cache_type_uc:
    xor eax, eax
.Lresident_cache_type_return:
    ret

// Each CPU retires its own cached EPT translations before its next VM entry.
.Lresident_sync_ept_cache:
    mov rax, qword ptr [rip + .Lresident_cache_generation]
    cmp rax, qword ptr [r12 + {b_cache_generation}]
    je .Lresident_sync_ept_cache_done
    push rax
    sub rsp, 16
    mov r11, qword ptr [r12 + {b_cache_ept_pointer}]
    mov [rsp], r11
    mov qword ptr [rsp + 8], 0
    mov eax, 1
    invept rax, xmmword ptr [rsp]
    lea rsp, [rsp + 16]
    jna .Lresident_dispatch_halt
    resident_telemetry_counter inc, {b_invept_exits}, {b_telemetry_active}
    cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0
    je .Lresident_cache_synced
    call .Lresident_nested_invalidate_ept02
    call .Lresident_nested_swap_ept02_cache
    call .Lresident_nested_invalidate_ept02
    call .Lresident_nested_swap_ept02_cache
.Lresident_cache_synced:
    pop rax
    mov qword ptr [r12 + {b_cache_generation}], rax
.Lresident_sync_ept_cache_done:
    ret
.balign 8
.Lresident_fixed_mtrr_registers:
    .word 0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f
.endm

.macro matrixhv_resident_ept_cache_state
.balign 8
.Lresident_cache_lock_word:
    .quad 0
.Lresident_cache_generation:
    .quad 0
.Lresident_cache_last_snapshot:
    .zero 4192
.endm

.macro matrixhv_island_cache_flush
.Lresident_dispatch_cache_flush:
call .Lresident_guest_privilege
jc .Lresident_dispatch_inject_gp
// INVD must not discard dirty host state on a CPU shared with the guest.
wbinvd
call .Lresident_advance_guest_rip
jmp .Lresident_dispatch_resume
.endm
