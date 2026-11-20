// L2 memory request ingress. R12 and RSP retain the dispatcher contract.
// Translation and packet execution live in memory/nested.rs. Architectural
// CPUIDs and all other intercepts remain owned by the nested router and L1.
.macro matrixhv_nested_memory_requests
.Lresident_nested_observe_kernel_root:
// Observe only long-mode CPL0 exits. VMFUNC may have selected another EPT12.
mov eax, {guest_cs_ar_bytes}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11b, 0x60
jnz .Lresident_nested_kernel_root_done
mov eax, {vm_entry_controls}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
test r11d, 512
jz .Lresident_nested_kernel_root_done
call .Lresident_nested_capture_native_eptp
mov r8, qword ptr [r12 + {b_nested_ept12_pointer}]
mov rax, {host_page_address_mask}
and r8, rax
jz .Lresident_nested_kernel_root_done
mov eax, {guest_cr3}
vmread r9, rax
jna .Lresident_dispatch_vmread_failed
mov rax, {host_page_address_mask}
and r9, rax
jz .Lresident_nested_kernel_root_done
mov eax, {guest_cr4}
vmread r10, rax
jna .Lresident_dispatch_vmread_failed
mov ecx, {ia32_lstar}
rdmsr
shl rdx, 32
or rdx, rax
// LSTAR must identify a canonical high-half kernel entry, not L1 metadata.
mov rax, rdx
sar rax, 47
cmp rax, -1
jne .Lresident_nested_kernel_root_done
lea r11, [r12 + {b_nested_kernel_roots}]
xor ecx, ecx
.Lresident_nested_kernel_root_find:
cmp qword ptr [r11], r8
jne .Lresident_nested_kernel_root_next
cmp qword ptr [r11 + 8], r9
jne .Lresident_nested_kernel_root_next
cmp qword ptr [r11 + 16], rdx
jne .Lresident_nested_kernel_root_next
cmp qword ptr [r11 + 24], r10
je .Lresident_nested_kernel_root_done
.Lresident_nested_kernel_root_next:
add r11, 32
inc ecx
cmp ecx, 8
jb .Lresident_nested_kernel_root_find
mov rcx, qword ptr [r12 + {b_nested_kernel_root_cursor}]
and ecx, 7
shl ecx, 5
lea r11, [r12 + rcx + {b_nested_kernel_roots}]
mov qword ptr [r11], 0
mov qword ptr [r11 + 8], r9
mov qword ptr [r11 + 16], rdx
mov qword ptr [r11 + 24], r10
mov qword ptr [r11], r8
inc qword ptr [r12 + {b_nested_kernel_root_cursor}]
.Lresident_nested_kernel_root_done:
ret
.Lresident_nested_memory_request:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_memory_unsupported
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jnc .Lresident_memory_unsupported
// VMFUNC can select the other composed root without an intervening exit.
call .Lresident_nested_capture_native_eptp
jmp .Lresident_memory_context_ready
.endm
