// Bounded observational boot capture. R12=context and RSI=the exact saved
// 15-GPR dispatcher frame. Preserve nonvolatile GPRs and R8; change only the
// diagnostic buffer and the existing root mapping cache. Never alter guest
// paging, VMCS state, pending events, or guest memory.
.macro matrixhv_boot_diagnostics
.Lresident_boot_diagnostic_capture:
push rbx
push rbp
push rdi
push rsi
push r13
push r14
push r15
push r8
lea r14, [r12 + {b_boot_diagnostic}]
mov r15, 0x424f4f5400020000
mov qword ptr [r14], 0
mov rax, cr0
mov qword ptr [r14 + 8], rax
mov ecx, 0x277
rdmsr
shl rdx, 32
or rax, rdx
mov qword ptr [r14 + 16], rax
// Word three retains the previous snapshot's measured rendering duration.
lea rdi, [r14 + 32]
mov ecx, 11
cld
rep movsq
lea rdi, [r14 + 120]
mov rax, -1
mov ecx, 17
rep stosq
cmp qword ptr [r12 + {b_nested_l2_active}], 0
je .Lresident_boot_diagnostic_mode
bts r15, 10
jmp .Lresident_boot_diagnostic_peers
.Lresident_boot_diagnostic_mode:
mov eax, {guest_cr0}
vmread r11, rax
jna .Lresident_boot_diagnostic_unsupported_mode
bt r11, 31
jnc .Lresident_boot_diagnostic_unsupported_mode
mov eax, {vm_entry_controls}
vmread r11, rax
jna .Lresident_boot_diagnostic_unsupported_mode
bt r11, 9
jnc .Lresident_boot_diagnostic_unsupported_mode
mov eax, {guest_rip}
vmread rbx, rax
jna .Lresident_boot_diagnostic_stack
xor ebp, ebp
.Lresident_boot_diagnostic_code_loop:
mov r10, rbp
shl r10, 3
add r10, rbx
jc .Lresident_boot_diagnostic_code_next
call .Lresident_boot_diagnostic_read_qword
jc .Lresident_boot_diagnostic_code_next
mov qword ptr [r14 + rbp * 8 + 120], rax
bts r15, rbp
.Lresident_boot_diagnostic_code_next:
inc ebp
cmp ebp, 2
jb .Lresident_boot_diagnostic_code_loop
.Lresident_boot_diagnostic_stack:
mov eax, {guest_rsp}
vmread rbx, rax
jna .Lresident_boot_diagnostic_peers
xor ebp, ebp
.Lresident_boot_diagnostic_stack_loop:
mov r10, rbp
shl r10, 3
add r10, rbx
jc .Lresident_boot_diagnostic_stack_next
call .Lresident_boot_diagnostic_read_qword
jc .Lresident_boot_diagnostic_stack_next
mov qword ptr [r14 + rbp * 8 + 136], rax
lea ecx, [rbp + 2]
bts r15, rcx
.Lresident_boot_diagnostic_stack_next:
inc ebp
cmp ebp, 8
jb .Lresident_boot_diagnostic_stack_loop
jmp .Lresident_boot_diagnostic_peers
.Lresident_boot_diagnostic_unsupported_mode:
bts r15, 11
.Lresident_boot_diagnostic_peers:
mov rdi, qword ptr [r12 + {b_event_context}]
test rdi, rdi
jz .Lresident_boot_diagnostic_commit
mov rbp, qword ptr [r12 + {b_diagnostic_samples}]
and ebp, 63
mov ecx, 64
.Lresident_boot_diagnostic_peer_loop:
mov rax, qword ptr [rdi + rbp * 8 + {event_cpu_contexts}]
test rax, rax
jnz .Lresident_boot_diagnostic_peer_found
inc ebp
and ebp, 63
dec ecx
jnz .Lresident_boot_diagnostic_peer_loop
jmp .Lresident_boot_diagnostic_masks
.Lresident_boot_diagnostic_peer_found:
mov qword ptr [r14 + 200], rbp
mov rcx, qword ptr [rax + {b_flight_sequence}]
mov qword ptr [r14 + 208], rcx
mov rcx, qword ptr [rax + {b_last_guest_rip}]
mov qword ptr [r14 + 216], rcx
mov rcx, qword ptr [rax + {b_last_reason}]
mov qword ptr [r14 + 224], rcx
.Lresident_boot_diagnostic_masks:
mov rax, qword ptr [rdi + {event_init_cpu_mask}]
mov qword ptr [r14 + 232], rax
mov rax, qword ptr [rdi + {event_sipi_cpu_mask}]
mov qword ptr [r14 + 240], rax
mov rax, qword ptr [rdi + {event_halted_cpu_mask}]
mov qword ptr [r14 + 248], rax
.Lresident_boot_diagnostic_commit:
mov qword ptr [r14], r15
pop r8
pop r15
pop r14
pop r13
pop rsi
pop rdi
pop rbp
pop rbx
ret

// R10=guest linear address. Return RAX=value, CF=0, or RAX=-1, CF=1.
// Only L1 long-mode paging is supported. Each page-table and payload access
// must resolve to readable EPT01 WB memory mapped in the root address space.
.Lresident_boot_diagnostic_read_qword:
push rbx
push rbp
push rdi
push r13
push r8
mov rbx, r10
cmp qword ptr [r12 + {b_nested_l2_active}], 0
jne .Lresident_boot_diagnostic_read_failed
mov eax, r10d
and eax, 4095
cmp eax, 4088
ja .Lresident_boot_diagnostic_read_failed
mov eax, {guest_cr0}
vmread r11, rax
jna .Lresident_boot_diagnostic_read_failed
bt r11, 31
jnc .Lresident_boot_diagnostic_read_failed
mov eax, {vm_entry_controls}
vmread r11, rax
jna .Lresident_boot_diagnostic_read_failed
bt r11, 9
jnc .Lresident_boot_diagnostic_read_failed
mov eax, {guest_cr4}
vmread r11, rax
jna .Lresident_boot_diagnostic_read_failed
mov ebp, 39
mov ecx, 16
bt r11, 12
jnc .Lresident_boot_diagnostic_canonical
mov ebp, 48
mov ecx, 7
.Lresident_boot_diagnostic_canonical:
mov rax, rbx
shl rax, cl
sar rax, cl
cmp rax, rbx
jne .Lresident_boot_diagnostic_read_failed
mov eax, {guest_cr3}
vmread r11, rax
jna .Lresident_boot_diagnostic_read_failed
mov r13, {host_page_address_mask}
and r11, r13
.Lresident_boot_diagnostic_linear_walk:
mov ecx, ebp
mov rax, rbx
shr rax, cl
and eax, 511
lea r11, [r11 + rax * 8]
call .Lresident_boot_diagnostic_map_wb
test eax, eax
jz .Lresident_boot_diagnostic_read_failed
mov rdi, qword ptr [r11]
test dil, 1
jz .Lresident_boot_diagnostic_read_failed
cmp ebp, 12
je .Lresident_boot_diagnostic_linear_leaf
test dil, 0x80
jz .Lresident_boot_diagnostic_linear_next
cmp ebp, 30
je .Lresident_boot_diagnostic_large_1g
cmp ebp, 21
jne .Lresident_boot_diagnostic_read_failed
test edi, 0x1fe000
jnz .Lresident_boot_diagnostic_read_failed
jmp .Lresident_boot_diagnostic_linear_leaf
.Lresident_boot_diagnostic_large_1g:
test edi, 0x3fffe000
jnz .Lresident_boot_diagnostic_read_failed
jmp .Lresident_boot_diagnostic_linear_leaf
.Lresident_boot_diagnostic_linear_next:
mov r11, rdi
and r11, r13
sub ebp, 9
jmp .Lresident_boot_diagnostic_linear_walk
.Lresident_boot_diagnostic_linear_leaf:
mov ecx, ebp
mov rax, 1
shl rax, cl
dec rax
mov r11, rbx
and r11, rax
not rax
and rdi, rax
and rdi, r13
or r11, rdi
call .Lresident_boot_diagnostic_map_wb
test eax, eax
jz .Lresident_boot_diagnostic_read_failed
mov rax, qword ptr [r11]
clc
jmp .Lresident_boot_diagnostic_read_return
.Lresident_boot_diagnostic_read_failed:
mov rax, -1
stc
.Lresident_boot_diagnostic_read_return:
pop r8
pop r13
pop rdi
pop rbp
pop rbx
ret

// R11=L1 GPA; return EAX=1 and R11=host identity address, or EAX=0.
// EPT tables are trusted resident allocations. Guest-supplied addresses are
// never dereferenced before leaf permission, WB type, and root mapping checks.
.Lresident_boot_diagnostic_map_wb:
mov rax, r11
shr rax, 48
jnz .Lresident_boot_diagnostic_map_failed
mov r9, qword ptr [r12 + {b_cache_ept_pointer}]
mov r8, {host_page_address_mask}
and r9, r8
jz .Lresident_boot_diagnostic_map_failed
mov ecx, 39
.Lresident_boot_diagnostic_ept_walk:
mov rax, r11
shr rax, cl
and eax, 511
mov rax, qword ptr [r9 + rax * 8]
test al, 1
jz .Lresident_boot_diagnostic_map_failed
cmp ecx, 12
je .Lresident_boot_diagnostic_ept_leaf
test al, 0x80
jz .Lresident_boot_diagnostic_ept_next
cmp ecx, 30
je .Lresident_boot_diagnostic_ept_leaf
cmp ecx, 21
jne .Lresident_boot_diagnostic_map_failed
.Lresident_boot_diagnostic_ept_leaf:
mov rdx, rax
and edx, 0x38
cmp edx, 0x30
jne .Lresident_boot_diagnostic_map_failed
mov r10, 1
shl r10, cl
dec r10
and r11, r10
not r10
and rax, r10
and rax, r8
or r11, rax
mov rax, r11
shr rax, 47
jnz .Lresident_boot_diagnostic_map_failed
jmp .Lresident_ept01_host_page_is_mapped
.Lresident_boot_diagnostic_ept_next:
and rax, r8
mov r9, rax
test r9, r9
jz .Lresident_boot_diagnostic_map_failed
sub ecx, 9
jmp .Lresident_boot_diagnostic_ept_walk
.Lresident_boot_diagnostic_map_failed:
xor eax, eax
ret
.endm
