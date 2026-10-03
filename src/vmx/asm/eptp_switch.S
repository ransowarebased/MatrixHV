// Root entry contract: R12=context, saved guest frame at RSP, b_*/event_*
// offsets supplied by Rust. Internal helpers clobber scratch GPRs/flags and
// balance their stack; store guards explicitly preserve the complete caller
// state. SIMD is untouched. Helpers RET with validity/acquisition in EAX or
// jump to resume, L1 reflection, software VMFUNC or common VMCS error paths.
// Shared EPT stores occur only after peer acquisition; peers invalidate locally
// after the owner releases the barrier and before reentry. Root pointers must
// already be mapped.
.macro matrixhv_resident_eptp_switch
// Only publish stable, resident EPT02 roots. Zero slots take the VMFUNC exit
// path, where a cold EPT12 is composed before the next publication.
.Lresident_nested_refresh_eptp_list:
cmp qword ptr [r12 + {b_nested_eptp_native_supported}], 0
je .Lresident_nested_refresh_eptp_done
mov rax, {vm_function_control}
xor r11d, r11d
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [r12 + {b_nested_eptp_native_enabled}], 0
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_refresh_eptp_done
mov eax, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]
and eax, 0x2002
cmp eax, 0x2002
jne .Lresident_nested_refresh_eptp_done
test byte ptr [r12 + {b_nested_vmcs12_vm_function_control}], 1
jz .Lresident_nested_refresh_eptp_done
cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0
je .Lresident_nested_refresh_eptp_done
mov rdi, qword ptr [r12 + {b_nested_eptp_shadow_list}]
test rdi, rdi
jz .Lresident_nested_refresh_eptp_done
mov r8, qword ptr [r12 + {b_nested_vmcs12_eptp_list_address}]
call .Lresident_nested_translate_eptp_list_address
test eax, eax
jz .Lresident_nested_refresh_eptp_done
mov r13, r11
cmp qword ptr [r12 + {b_nested_eptp_admission}], 0
je .Lresident_nested_refresh_eptp_check_readonly
mov qword ptr [r12 + {b_nested_eptp_admission}], 0
call .Lresident_nested_eptp_protect_source
test eax, eax
jz .Lresident_nested_refresh_eptp_done
jmp .Lresident_nested_refresh_eptp_stable
.Lresident_nested_refresh_eptp_check_readonly:
// Once admitted, guest stores are trapped and root stores retire all lists.
call .Lresident_nested_eptp_source_is_readonly
test eax, eax
jz .Lresident_nested_refresh_eptp_done
cmp qword ptr [rip + .Lresident_eptp_lists_live], 0
jne .Lresident_nested_refresh_eptp_stable
call .Lresident_nested_eptp_protect_source
test eax, eax
jz .Lresident_nested_refresh_eptp_done
.Lresident_nested_refresh_eptp_stable:
call .Lresident_nested_eptp_hardware_writers_idle
test eax, eax
jz .Lresident_nested_refresh_eptp_done
mov r14d, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]
shr r14d, 22
and r14d, 1
xor ebx, ebx
.Lresident_nested_publish_eptp_slot:
mov rsi, qword ptr [r13 + rbx * 8]
mov r11, rsi
call .Lresident_nested_eptp_is_valid
test eax, eax
jz .Lresident_nested_publish_eptp_empty
cmp rsi, qword ptr [r12 + {b_nested_ept12_pointer}]
jne .Lresident_nested_publish_eptp_cached
cmp r14, qword ptr [r12 + {b_nested_ept02_mbec}]
jne .Lresident_nested_publish_eptp_cached
mov r11, qword ptr [r12 + {b_nested_ept02_pointer}]
jmp .Lresident_nested_publish_eptp_attributes
.Lresident_nested_publish_eptp_cached:
cmp rsi, qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}]
jne .Lresident_nested_publish_eptp_empty
cmp r14, qword ptr [r12 + {b_nested_ept02_cached_mbec}]
jne .Lresident_nested_publish_eptp_empty
mov r11, qword ptr [r12 + {b_nested_ept02_cached_pointer}]
.Lresident_nested_publish_eptp_attributes:
and esi, 0x40
or r11, rsi
jmp .Lresident_nested_publish_eptp_write
.Lresident_nested_publish_eptp_empty:
xor r11d, r11d
.Lresident_nested_publish_eptp_write:
mov qword ptr [rdi + rbx * 8], r11
inc ebx
cmp ebx, 512
jb .Lresident_nested_publish_eptp_slot
mov rax, {eptp_list_address}
mov r11, rdi
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov rax, {vm_function_control}
mov r11d, 1
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
mov qword ptr [r12 + {b_nested_eptp_native_enabled}], 1
.Lresident_nested_refresh_eptp_done:
ret

// Reconcile before any L2 exit handler reads EPT12, including NMI and faults.
// The source list may have aliases; root ownership is independent of its index.
.Lresident_nested_capture_native_eptp:
cmp qword ptr [r12 + {b_nested_eptp_native_enabled}], 0
je .Lresident_nested_capture_eptp_done
mov rax, {ept_pointer}
vmread r10, rax
jna .Lresident_dispatch_vmread_failed
mov r11, qword ptr [r12 + {b_nested_ept12_pointer}]
and r11d, 0x40
or r11, qword ptr [r12 + {b_nested_ept02_pointer}]
cmp r10, r11
je .Lresident_nested_capture_eptp_selected
mov r11, qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}]
and r11d, 0x40
or r11, qword ptr [r12 + {b_nested_ept02_cached_pointer}]
cmp r10, r11
jne .Lresident_dispatch_halt
call .Lresident_nested_swap_ept02_cache
.Lresident_nested_capture_eptp_selected:
mov r11, qword ptr [r12 + {b_nested_ept12_pointer}]
mov qword ptr [r12 + {b_nested_vmcs12_ept_pointer}], r11
.Lresident_nested_capture_eptp_done:
ret

// R11 is the translated source HPA. EPT01 is shared by all resident CPUs;
// checking only the list GPA would miss writable aliases of the same page.
// Traverse only writable subtrees. Cache-type updates preserve these rights.
.Lresident_nested_eptp_source_is_readonly:
push rbx
push rsi
push rdi
mov rsi, r11
and rsi, -4096
mov rdx, {host_page_address_mask}
mov r9, qword ptr [r12 + {b_nested_ept01_pointer}]
and r9, rdx
mov ecx, 39
call .Lresident_nested_eptp_alias_table
pop rdi
pop rsi
pop rbx
ret
.Lresident_nested_eptp_alias_table:
push rdi
push rcx
push rbx
mov rdi, r9
xor ebx, ebx
.Lresident_nested_eptp_alias_entry:
mov rax, qword ptr [rdi + rbx * 8]
mov r9d, eax
and r9d, 3
cmp r9d, 3
jne .Lresident_nested_eptp_alias_next
cmp ecx, 12
je .Lresident_nested_eptp_alias_leaf
test al, 0x80
jnz .Lresident_nested_eptp_alias_large
mov r9, rax
and r9, rdx
sub ecx, 9
call .Lresident_nested_eptp_alias_table
add ecx, 9
test eax, eax
jz .Lresident_nested_eptp_alias_return
jmp .Lresident_nested_eptp_alias_next
.Lresident_nested_eptp_alias_large:
cmp ecx, 39
je .Lresident_nested_eptp_alias_found
.Lresident_nested_eptp_alias_leaf:
and rax, rdx
xor rax, rsi
shr rax, cl
jz .Lresident_nested_eptp_alias_found
.Lresident_nested_eptp_alias_next:
inc ebx
cmp ebx, 512
jb .Lresident_nested_eptp_alias_entry
mov eax, 1
jmp .Lresident_nested_eptp_alias_return
.Lresident_nested_eptp_alias_found:
xor eax, eax
.Lresident_nested_eptp_alias_return:
pop rbx
pop rcx
pop rdi
ret

// All peers are parked before changing shared EPT01 permissions. Bit 55 is
// ignored by EPT hardware and records only permissions revoked by this path.
// Split large aliases to 4 KiB using resident, concealed table pages. The
// resulting EPT01 tables persist across deoptimization and are never recycled
// while a hardware walk could still reference them.
.Lresident_nested_eptp_protect_source:
push rdi
push r13
call .Lresident_nested_eptp_sync_acquire
test eax, eax
jz .Lresident_nested_eptp_protect_return
mov rsi, r13
mov ebp, 1
call .Lresident_nested_eptp_update_protection
test eax, eax
jnz .Lresident_nested_eptp_protection_ready
// Exhaustion may follow successful splits or permission changes on earlier
// aliases. Restore every tracked leaf and retire all native lists atomically.
xor ebp, ebp
call .Lresident_nested_eptp_update_protection
call .Lresident_nested_eptp_sync_flush_local
mov qword ptr [rip + .Lresident_eptp_lists_live], 0
call .Lresident_nested_eptp_sync_end
xor eax, eax
jmp .Lresident_nested_eptp_protect_return
.Lresident_nested_eptp_protection_ready:
call .Lresident_nested_eptp_sync_flush_local
mov qword ptr [rip + .Lresident_eptp_lists_live], 1
call .Lresident_nested_eptp_sync_end
mov eax, 1
.Lresident_nested_eptp_protect_return:
pop r13
pop rdi
ret

.Lresident_nested_eptp_release_sources:
call .Lresident_nested_eptp_sync_acquire
test eax, eax
jz .Lresident_nested_eptp_release_return
xor ebp, ebp
call .Lresident_nested_eptp_update_protection
call .Lresident_nested_eptp_sync_flush_local
mov qword ptr [rip + .Lresident_eptp_lists_live], 0
call .Lresident_nested_eptp_sync_end
mov eax, 1
.Lresident_nested_eptp_release_return:
ret

// EBP=1 protects every writable alias of RSI; EBP=0 restores tagged leaves.
.Lresident_nested_eptp_update_protection:
mov rdx, {host_page_address_mask}
mov r9, qword ptr [r12 + {b_nested_ept01_pointer}]
and r9, rdx
mov ecx, 39
.Lresident_nested_eptp_protect_table:
push rdi
push rcx
push rbx
mov rdi, r9
xor ebx, ebx
.Lresident_nested_eptp_protect_entry:
mov rax, qword ptr [rdi + rbx * 8]
test al, 1
jz .Lresident_nested_eptp_protect_next
cmp ecx, 12
je .Lresident_nested_eptp_protect_leaf
test al, 0x80
jnz .Lresident_nested_eptp_protect_leaf
test ebp, ebp
jz .Lresident_nested_eptp_protect_descend
test al, 2
jz .Lresident_nested_eptp_protect_next
.Lresident_nested_eptp_protect_descend:
mov r9, rax
and r9, rdx
sub ecx, 9
call .Lresident_nested_eptp_protect_table
add ecx, 9
test eax, eax
jz .Lresident_nested_eptp_protect_table_return
jmp .Lresident_nested_eptp_protect_next
.Lresident_nested_eptp_protect_leaf:
test ebp, ebp
jz .Lresident_nested_eptp_restore_leaf
test al, 2
jz .Lresident_nested_eptp_protect_next
mov r9, rax
and r9, rdx
xor r9, rsi
shr r9, cl
jnz .Lresident_nested_eptp_protect_next
cmp ecx, 12
je .Lresident_nested_eptp_protect_small
call .Lresident_nested_eptp_split_leaf
test eax, eax
jz .Lresident_nested_eptp_protect_table_return
jmp .Lresident_nested_eptp_protect_entry
.Lresident_nested_eptp_protect_small:
btr rax, 1
bts rax, 55
jmp .Lresident_nested_eptp_protect_store
.Lresident_nested_eptp_restore_leaf:
bt rax, 55
jnc .Lresident_nested_eptp_protect_next
btr rax, 55
bts rax, 1
.Lresident_nested_eptp_protect_store:
mov qword ptr [rdi + rbx * 8], rax
.Lresident_nested_eptp_protect_next:
inc ebx
cmp ebx, 512
jb .Lresident_nested_eptp_protect_entry
mov eax, 1
.Lresident_nested_eptp_protect_table_return:
pop rbx
pop rcx
pop rdi
ret

// Input RAX=large leaf, ECX=shift, RDI/RBX=parent table/index. Publish a fully
// initialized child before replacing the parent. Preserve leaf permissions,
// cache type, A/D flags, suppress-VE and firmware cache-ceiling metadata.
.Lresident_nested_eptp_split_leaf:
cmp ecx, 30
je .Lresident_nested_eptp_split_size_valid
cmp ecx, 21
jne .Lresident_nested_eptp_split_failed
.Lresident_nested_eptp_split_size_valid:
mov r8, qword ptr [r12 + {b_nested_eptp_table_used}]
cmp r8, qword ptr [r12 + {b_nested_eptp_table_pages}]
jae .Lresident_nested_eptp_split_failed
mov r9, qword ptr [r12 + {b_nested_eptp_table_pool}]
test r9, r9
jz .Lresident_nested_eptp_split_failed
shl r8, 12
add r9, r8
inc qword ptr [r12 + {b_nested_eptp_table_used}]
push rcx
mov r10, rax
cmp ecx, 21
jne .Lresident_nested_eptp_split_attributes_ready
and r10, -129
.Lresident_nested_eptp_split_attributes_ready:
sub ecx, 9
mov r11d, 1
shl r11, cl
xor r8d, r8d
.Lresident_nested_eptp_split_child:
mov qword ptr [r9 + r8 * 8], r10
add r10, r11
inc r8d
cmp r8d, 512
jb .Lresident_nested_eptp_split_child
pop rcx
and eax, 0x100
or rax, r9
or rax, 7
mov qword ptr [rdi + rbx * 8], rax
mov eax, 1
ret
.Lresident_nested_eptp_split_failed:
xor eax, eax
ret

// TPR shadow writes bypass EPT01. Until its writable page is shadowed too,
// conservatively keep VMFUNC on the exit path while any CPU configures it.
.Lresident_nested_eptp_hardware_writers_idle:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 21
jc .Lresident_nested_eptp_hardware_writer_active
mov r9, qword ptr [r12 + {b_event_context}]
test r9, r9
jz .Lresident_nested_eptp_hardware_writers_ready
xor ecx, ecx
.Lresident_nested_eptp_check_hardware_writer:
mov r10, qword ptr [r9 + {event_cpu_contexts} + rcx * 8]
test r10, r10
jz .Lresident_nested_eptp_next_hardware_writer
bt dword ptr [r10 + {b_nested_vmcs12_primary_control}], 21
jc .Lresident_nested_eptp_hardware_writer_active
.Lresident_nested_eptp_next_hardware_writer:
inc ecx
cmp ecx, 64
jb .Lresident_nested_eptp_check_hardware_writer
.Lresident_nested_eptp_hardware_writers_ready:
mov eax, 1
ret
.Lresident_nested_eptp_hardware_writer_active:
xor eax, eax
ret

// Root stores bypass EPT01 permissions. Retire native lists before writing
// guest memory, including an originally read-only list. Preserve the complete
// caller state; the caller remains in a root handler until its next entry gate,
// so a competing publisher cannot acquire fresh acknowledgements mid-store.
.Lresident_nested_eptp_before_root_write:
pushfq
cmp qword ptr [rip + .Lresident_eptp_lists_live], 0
je .Lresident_nested_eptp_root_write_done
push rax
push rcx
push rdx
push rbx
push rbp
push rsi
push rdi
push r8
push r9
push r10
push r11
push r13
push r14
push r15
.Lresident_nested_eptp_root_write_retry:
call .Lresident_nested_eptp_sync_poll
cmp qword ptr [rip + .Lresident_eptp_lists_live], 0
je .Lresident_nested_eptp_root_write_restored
call .Lresident_nested_eptp_release_sources
test eax, eax
jz .Lresident_nested_eptp_root_write_retry
.Lresident_nested_eptp_root_write_restored:
pop r15
pop r14
pop r13
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rbp
pop rbx
pop rdx
pop rcx
pop rax
.Lresident_nested_eptp_root_write_done:
popfq
ret

.Lresident_nested_vmfunc:
// Unsupported hardware and cold shadow-list slots take the software path.
mov eax, dword ptr [rsp]
mov ecx, dword ptr [rsp + 8]
call .Lresident_nested_switch_eptp
test eax, eax
jz .Lresident_nested_vmfunc_reflect
call .Lresident_nested_activate_vmcs02_ept
call .Lresident_advance_guest_rip
jmp .Lresident_nested_l2_resume_ept
.Lresident_nested_vmfunc_reflect:
mov r10d, {vmfunc_reason}
jmp .Lresident_nested_l2_reflect_generic

// EAX and ECX are the architectural 32-bit function and list selectors.
// Return zero without changing VMCS12 or its EPT cache on an invalid request.
.Lresident_nested_switch_eptp:
test eax, eax
jnz .Lresident_nested_vmfunc_failed
cmp ecx, 512
jae .Lresident_nested_vmfunc_failed
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_vmfunc_failed
mov eax, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]
and eax, 0x2002
cmp eax, 0x2002
jne .Lresident_nested_vmfunc_failed
test byte ptr [r12 + {b_nested_vmcs12_vm_function_control}], 1
jz .Lresident_nested_vmfunc_failed
mov r8, qword ptr [r12 + {b_nested_vmcs12_eptp_list_address}]
lea r8, [r8 + rcx * 8]
call .Lresident_nested_read_eptp_list_entry
test eax, eax
jz .Lresident_nested_vmfunc_failed
mov rbx, r11
call .Lresident_nested_eptp_is_valid
test eax, eax
jz .Lresident_nested_vmfunc_failed
mov qword ptr [r12 + {b_nested_vmcs12_ept_pointer}], rbx
call .Lresident_nested_prepare_ept02
mov eax, 1
ret
.Lresident_nested_vmfunc_failed:
xor eax, eax
ret

// The list contains L1 physical addresses. Walk EPT01 rather than treating
// its GPA as a root pointer, preserving concealment and non-identity mappings.
.Lresident_nested_read_eptp_list_entry:
call .Lresident_nested_translate_eptp_list_address
test eax, eax
jz .Lresident_nested_vmfunc_failed
mov r11, qword ptr [r11]
ret
.Lresident_nested_translate_eptp_list_address:
mov rax, r8
shr rax, 48
jnz .Lresident_nested_vmfunc_failed
mov r9, qword ptr [r12 + {b_nested_ept01_pointer}]
mov rdx, {host_page_address_mask}
and r9, rdx
mov ecx, 39
mov r10d, 7
.Lresident_nested_eptp_list_walk:
mov rax, r8
shr rax, cl
and eax, 511
lea rax, [r9 + rax * 8]
mov r9, qword ptr [rax]
and r10d, r9d
test r9b, 1
jz .Lresident_nested_vmfunc_failed
cmp ecx, 12
je .Lresident_nested_eptp_list_leaf
test r9b, 0x80
jnz .Lresident_nested_eptp_list_leaf
and r9, rdx
sub ecx, 9
jmp .Lresident_nested_eptp_list_walk
.Lresident_nested_eptp_list_leaf:
push rax
mov rax, 1
shl rax, cl
dec rax
mov r11, r8
and r11, rax
not rax
and r9, rax
and r9, rdx
or r11, r9
call .Lresident_ept01_host_page_is_mapped
pop rdx
test eax, eax
jz .Lresident_nested_vmfunc_failed
mov eax, 1
ret

.Lresident_nested_validate_vm_functions:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_vm_functions_valid
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 13
jnc .Lresident_nested_vm_functions_valid
mov rax, qword ptr [r12 + {b_nested_vmcs12_vm_function_control}]
test rax, -2
jnz .Lresident_nested_vmfunc_failed
test al, 1
jz .Lresident_nested_vm_functions_valid
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jnc .Lresident_nested_vmfunc_failed
mov r11, qword ptr [r12 + {b_nested_vmcs12_eptp_list_address}]
jmp .Lresident_nested_physical_address_is_valid
.Lresident_nested_vm_functions_valid:
mov eax, 1
ret

// The virtual EPT capabilities advertise WB, four-level walks, and optional A/D.
.Lresident_nested_eptp_is_valid:
mov eax, r11d
and eax, 0x3f
cmp eax, 0x1e
jne .Lresident_nested_vmfunc_failed
test r11, 0xf80
jnz .Lresident_nested_vmfunc_failed
test r11b, 0x40
jz .Lresident_nested_eptp_address
bt qword ptr [r12 + {b_nested_vmx_ept_vpid_cap}], 21
jnc .Lresident_nested_vmfunc_failed
.Lresident_nested_eptp_address:
and r11, -4096
jmp .Lresident_nested_physical_address_is_valid

.Lresident_nested_prepare_ept02:
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_prepare_ept02_done
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jnc .Lresident_nested_prepare_ept02_done
mov edx, dword ptr [r12 + {b_nested_vmcs12_secondary_control}]
shr edx, 22
and edx, 1
mov rax, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]
cmp rax, qword ptr [r12 + {b_nested_ept12_pointer}]
jne .Lresident_nested_prepare_ept02_other_context
cmp rdx, qword ptr [r12 + {b_nested_ept02_mbec}]
je .Lresident_nested_prepare_ept02_done
.Lresident_nested_prepare_ept02_other_context:
cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0
jne .Lresident_nested_select_ept02_cache
// The boot probe selects a precomposed root; runtime caches own separate table pools.
mov qword ptr [r12 + {b_nested_ept02_cache_initialized}], 1
mov r11, qword ptr [r12 + {b_nested_ept02_initial_pointer}]
mov qword ptr [r12 + {b_nested_ept02_pointer}], r11
jmp .Lresident_nested_replace_ept02_cache
.Lresident_nested_select_ept02_cache:
call .Lresident_nested_swap_ept02_cache
mov rax, qword ptr [r12 + {b_nested_vmcs12_ept_pointer}]
cmp rax, qword ptr [r12 + {b_nested_ept12_pointer}]
jne .Lresident_nested_replace_ept02_cache
cmp rdx, qword ptr [r12 + {b_nested_ept02_mbec}]
je .Lresident_nested_prepare_ept02_done
.Lresident_nested_replace_ept02_cache:
mov qword ptr [r12 + {b_nested_ept12_pointer}], rax
mov qword ptr [r12 + {b_nested_ept02_mbec}], rdx
call .Lresident_nested_invalidate_ept02
.Lresident_nested_prepare_ept02_done:
ret
.Lresident_nested_swap_ept02_cache:
mov rax, qword ptr [r12 + {b_nested_ept12_pointer}]
mov r11, qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}]
mov qword ptr [r12 + {b_nested_ept02_cached_ept12_pointer}], rax
mov qword ptr [r12 + {b_nested_ept12_pointer}], r11
mov rax, qword ptr [r12 + {b_nested_ept02_pointer}]
mov r11, qword ptr [r12 + {b_nested_ept02_cached_pointer}]
mov qword ptr [r12 + {b_nested_ept02_cached_pointer}], rax
mov qword ptr [r12 + {b_nested_ept02_pointer}], r11
mov rax, qword ptr [r12 + {b_nested_ept02_table_pool}]
mov r11, qword ptr [r12 + {b_nested_ept02_cached_table_pool}]
mov qword ptr [r12 + {b_nested_ept02_cached_table_pool}], rax
mov qword ptr [r12 + {b_nested_ept02_table_pool}], r11
mov rax, qword ptr [r12 + {b_nested_ept02_table_pool_pages}]
mov r11, qword ptr [r12 + {b_nested_ept02_cached_table_pool_pages}]
mov qword ptr [r12 + {b_nested_ept02_cached_table_pool_pages}], rax
mov qword ptr [r12 + {b_nested_ept02_table_pool_pages}], r11
mov rax, qword ptr [r12 + {b_nested_ept02_table_pool_used}]
mov r11, qword ptr [r12 + {b_nested_ept02_cached_table_pool_used}]
mov qword ptr [r12 + {b_nested_ept02_cached_table_pool_used}], rax
mov qword ptr [r12 + {b_nested_ept02_table_pool_used}], r11
mov rax, qword ptr [r12 + {b_nested_ept02_mbec}]
mov r11, qword ptr [r12 + {b_nested_ept02_cached_mbec}]
mov qword ptr [r12 + {b_nested_ept02_cached_mbec}], rax
mov qword ptr [r12 + {b_nested_ept02_mbec}], r11
ret
.Lresident_nested_activate_vmcs02_ept:
mov r11, qword ptr [r12 + {b_nested_ept01_pointer}]
bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 31
jnc .Lresident_nested_activate_vmcs02_ept_write
bt dword ptr [r12 + {b_nested_vmcs12_secondary_control}], 1
jnc .Lresident_nested_activate_vmcs02_ept_write
mov r11, qword ptr [r12 + {b_nested_ept02_pointer}]
bt qword ptr [r12 + {b_nested_vmcs12_ept_pointer}], 6
jnc .Lresident_nested_activate_vmcs02_ept_write
or r11, 0x40
.Lresident_nested_activate_vmcs02_ept_write:
mov rax, {ept_pointer}
vmread r10, rax
jna .Lresident_dispatch_vmread_failed
cmp r10, r11
je .Lresident_nested_activate_vmcs02_ept_unchanged
resident_telemetry_counter inc, {b_eptp_switches}, {b_telemetry_active}
vmwrite rax, r11
jna .Lresident_dispatch_vmwrite_failed
.Lresident_nested_activate_vmcs02_ept_unchanged:
ret

// Each synchronization uses a new epoch: an acknowledgement from an earlier
// owner, including the same CPU, cannot satisfy a later request. These helpers
// never wait while holding a handler lock. Peers acknowledge at resident entry
// or immediately before returning to the guest, with all guest GPRs saved.
.Lresident_nested_eptp_sync_acquire:
push rbx
push rbp
push rsi
push rdi
push r13
push r14
push r15
call .Lresident_nested_eptp_sync_begin
test eax, eax
jz .Lresident_nested_eptp_sync_acquire_return
// Single-CPU operation does not require an enabled local APIC transport.
call .Lresident_nested_eptp_sync_ready
test eax, eax
jnz .Lresident_nested_eptp_sync_acquire_return
call .Lresident_nested_eptp_sync_kick
test eax, eax
jz .Lresident_nested_eptp_sync_acquire_abort
mov esi, 1000000
.Lresident_nested_eptp_sync_acquire_wait:
call .Lresident_nested_eptp_sync_ready
test eax, eax
jnz .Lresident_nested_eptp_sync_acquire_return
pause
dec esi
jnz .Lresident_nested_eptp_sync_acquire_wait
.Lresident_nested_eptp_sync_acquire_abort:
// No EPT changes are permitted before acquisition succeeds. A CPU in INIT,
// wait-for-SIPI or an unresponsive outer hypervisor cannot strand its peers.
call .Lresident_nested_eptp_sync_end
xor eax, eax
.Lresident_nested_eptp_sync_acquire_return:
pop r15
pop r14
pop r13
pop rdi
pop rsi
pop rbp
pop rbx
ret

.Lresident_nested_eptp_sync_begin:
xor eax, eax
lock cmpxchg qword ptr [rip + .Lresident_eptp_sync_owner], r12
jne .Lresident_nested_eptp_sync_busy
inc qword ptr [rip + .Lresident_eptp_sync_epoch]
jnz .Lresident_nested_eptp_sync_started
inc qword ptr [rip + .Lresident_eptp_sync_epoch]
.Lresident_nested_eptp_sync_started:
mov eax, 1
ret
.Lresident_nested_eptp_sync_busy:
xor eax, eax
ret

.Lresident_nested_eptp_sync_ready:
cmp qword ptr [rip + .Lresident_eptp_sync_owner], r12
jne .Lresident_nested_eptp_sync_busy
mov r9, qword ptr [r12 + {b_event_context}]
test r9, r9
jz .Lresident_nested_eptp_sync_busy
mov r10, qword ptr [rip + .Lresident_eptp_sync_epoch]
xor ecx, ecx
.Lresident_nested_eptp_sync_check_peer:
mov r11, qword ptr [r9 + {event_cpu_contexts} + rcx * 8]
test r11, r11
jz .Lresident_nested_eptp_sync_next_peer
cmp r11, r12
je .Lresident_nested_eptp_sync_next_peer
cmp qword ptr [r11 + {b_nested_eptp_sync_ack}], r10
jne .Lresident_nested_eptp_sync_busy
.Lresident_nested_eptp_sync_next_peer:
inc ecx
cmp ecx, 64
jb .Lresident_nested_eptp_sync_check_peer
mov eax, 1
ret

.Lresident_nested_eptp_sync_end:
cmp qword ptr [rip + .Lresident_eptp_sync_owner], r12
jne .Lresident_dispatch_halt
mov qword ptr [rip + .Lresident_eptp_sync_owner], 0
ret

// The owner requests directed NMIs only for registered peers that have not
// acknowledged this epoch. A retained token represents an already queued IPI.
// Return zero on transport failure; the caller must release the barrier before
// falling back, without changing EPT permissions or publishing new entries.
.Lresident_nested_eptp_sync_kick:
cmp qword ptr [rip + .Lresident_eptp_sync_owner], r12
jne .Lresident_nested_eptp_sync_busy
mov r15, qword ptr [r12 + {b_event_context}]
test r15, r15
jz .Lresident_nested_eptp_sync_busy
mov ecx, {apic_base_msr}
call .Lresident_guarded_rdmsr
jc .Lresident_nested_eptp_sync_busy
test eax, 0x800
jz .Lresident_nested_eptp_sync_busy
mov ebp, eax
and ebp, 0x400
shl rdx, 32
or rax, rdx
mov r13, {host_page_address_mask}
and r13, rax
test ebp, ebp
jnz .Lresident_nested_eptp_sync_kick_scan
mov r11, r13
call .Lresident_ept01_host_page_is_mapped
test eax, eax
jz .Lresident_nested_eptp_sync_busy
.Lresident_nested_eptp_sync_kick_scan:
xor ebx, ebx
.Lresident_nested_eptp_sync_kick_peer:
mov r14, qword ptr [r15 + {event_cpu_contexts} + rbx * 8]
test r14, r14
jz .Lresident_nested_eptp_sync_kick_next
cmp r14, r12
je .Lresident_nested_eptp_sync_kick_next
mov rax, qword ptr [rip + .Lresident_eptp_sync_epoch]
cmp qword ptr [r14 + {b_nested_eptp_sync_ack}], rax
je .Lresident_nested_eptp_sync_kick_next
test ebp, ebp
jnz .Lresident_nested_eptp_sync_queue_nmi
cmp qword ptr [r14 + {b_nested_eptp_sync_apic_id}], 255
ja .Lresident_nested_eptp_sync_busy
mov ecx, 100000
.Lresident_nested_eptp_sync_icr_wait:
test dword ptr [r13 + 0x300], 0x1000
jz .Lresident_nested_eptp_sync_queue_nmi
pause
dec ecx
jnz .Lresident_nested_eptp_sync_icr_wait
jmp .Lresident_nested_eptp_sync_busy
.Lresident_nested_eptp_sync_queue_nmi:
mov eax, 1
xchg qword ptr [r14 + {b_nested_eptp_sync_nmi}], rax
test rax, rax
jnz .Lresident_nested_eptp_sync_kick_next
mov edx, dword ptr [r14 + {b_nested_eptp_sync_apic_id}]
test ebp, ebp
jz .Lresident_nested_eptp_sync_send_xapic
mov ecx, 0x830
mov eax, 0x4400
call .Lresident_guarded_wrmsr
jnc .Lresident_nested_eptp_sync_kick_next
// A faulting WRMSR sends no IPI. If another NMI consumed its token meanwhile,
// preserve that external event as pending instead of silently swallowing it.
xor eax, eax
xchg qword ptr [r14 + {b_nested_eptp_sync_nmi}], rax
test rax, rax
jnz .Lresident_nested_eptp_sync_busy
mov qword ptr [r14 + {b_nmi_pending}], 1
jmp .Lresident_nested_eptp_sync_busy
.Lresident_nested_eptp_sync_send_xapic:
shl edx, 24
mov dword ptr [r13 + 0x310], edx
mov dword ptr [r13 + 0x300], 0x4400
.Lresident_nested_eptp_sync_kick_next:
inc ebx
cmp ebx, 64
jb .Lresident_nested_eptp_sync_kick_peer
mov eax, 1
ret

.Lresident_nested_eptp_sync_poll:
mov rax, qword ptr [rip + .Lresident_eptp_sync_owner]
test rax, rax
jz .Lresident_nested_eptp_sync_return
cmp rax, r12
je .Lresident_nested_eptp_sync_return
// Capture hardware's selected root before the owner can revoke list entries.
cmp qword ptr [r12 + {b_nested_l2_active}], 0
je .Lresident_nested_eptp_sync_acknowledge
call .Lresident_nested_capture_native_eptp
.Lresident_nested_eptp_sync_acknowledge:
mov r10, qword ptr [rip + .Lresident_eptp_sync_epoch]
mov qword ptr [r12 + {b_nested_eptp_sync_ack}], r10
.Lresident_nested_eptp_sync_wait:
pause
cmp qword ptr [rip + .Lresident_eptp_sync_owner], 0
je .Lresident_nested_eptp_sync_released
cmp qword ptr [rip + .Lresident_eptp_sync_epoch], r10
je .Lresident_nested_eptp_sync_wait
.Lresident_nested_eptp_sync_released:
call .Lresident_nested_eptp_sync_flush_local
jmp .Lresident_nested_eptp_sync_poll
.Lresident_nested_eptp_sync_flush_local:
// Retire local translations after the owner's stores and before VM entry.
// Other CPUs cannot invalidate this logical processor's EPT caches for it.
mov qword ptr [r12 + {b_nested_eptp_native_enabled}], 0
mov qword ptr [r12 + {b_nested_eptp_admission}], 0
mov rdi, qword ptr [r12 + {b_nested_eptp_shadow_list}]
test rdi, rdi
jz .Lresident_nested_eptp_sync_flush_roots
xor eax, eax
mov ecx, 512
rep stosq
.Lresident_nested_eptp_sync_flush_roots:
cmp qword ptr [r12 + {b_nested_ept02_cache_initialized}], 0
je .Lresident_nested_eptp_sync_flush_ept01
call .Lresident_nested_invalidate_ept02
call .Lresident_nested_swap_ept02_cache
call .Lresident_nested_invalidate_ept02
call .Lresident_nested_swap_ept02_cache
.Lresident_nested_eptp_sync_flush_ept01:
sub rsp, 16
// The BSP can use EPT01 before initializing its nested-VMX state.
mov r11, qword ptr [r12 + {b_cache_ept_pointer}]
mov qword ptr [rsp], r11
mov qword ptr [rsp + 8], 0
mov eax, 1
invept rax, xmmword ptr [rsp]
lea rsp, [rsp + 16]
jna .Lresident_dispatch_halt
.Lresident_nested_eptp_sync_return:
ret

// Mark only the final register-restore/VM-entry window as safe for parking
// directly in the host NMI handler. Root handlers may hold unrelated locks.
// Recheck after publishing the marker so an NMI received just before it cannot
// consume the request and let this CPU enter a guest without acknowledging it.
.Lresident_nested_eptp_sync_enter:
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
call .Lresident_nested_eptp_sync_poll
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 1
mfence
mov rax, qword ptr [rip + .Lresident_eptp_sync_owner]
test rax, rax
jz .Lresident_nested_eptp_sync_return
cmp rax, r12
jne .Lresident_nested_eptp_sync_enter
ret

// Return one only for a queued synchronization NMI. An NMI that arrives in a
// root handler is consumed here and serviced at its next guest-entry gate.
.Lresident_nested_eptp_sync_host_nmi:
xor eax, eax
xchg qword ptr [r12 + {b_nested_eptp_sync_nmi}], rax
test rax, rax
jz .Lresident_nested_eptp_sync_return
cmp qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
je .Lresident_nested_eptp_sync_nmi_handled
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 0
call .Lresident_nested_eptp_sync_poll
mov qword ptr [r12 + {b_nested_eptp_sync_safe}], 1
.Lresident_nested_eptp_sync_nmi_handled:
mov eax, 1
ret

// Check the interruption type before consuming a token: #PF, #UD and other
// exceptions also use basic exit reason zero and still belong to the guest.
.Lresident_nested_eptp_sync_exit_nmi:
cmp qword ptr [r12 + {b_nested_eptp_sync_nmi}], 0
je .Lresident_nested_eptp_sync_busy
cmp qword ptr [r12 + {b_last_reason}], 0
jne .Lresident_nested_eptp_sync_busy
mov eax, {exit_intr_info}
vmread r11, rax
jna .Lresident_dispatch_vmread_failed
and r11d, 0x800007ff
cmp r11d, 0x80000202
jne .Lresident_nested_eptp_sync_busy
xor eax, eax
xchg qword ptr [r12 + {b_nested_eptp_sync_nmi}], rax
ret
.endm

.macro matrixhv_resident_eptp_switch_state
.balign 8
.Lresident_eptp_sync_owner:
.quad 0
.Lresident_eptp_sync_epoch:
.quad 0
.Lresident_eptp_lists_live:
.quad 0
.endm

// Shared EPT01 page access: R11=L1 GPA, R12=context; translate returns EAX=1/0 and R11=HPA on success. EDX supplies required permissions; readable/writable entries set it. RAX/RCX/RDX/R8/R9/R10/flags are scratch. Balanced internal stack, unchanged R12/SIMD. Writable access retires protected source lists before stores; final root mapping validation is nested-owned.
.macro matrixhv_ept01_page_translation
.Lresident_ept01_page_is_readable:
mov edx, 1
jmp .Lresident_ept01_page_translate
.Lresident_ept01_page_is_writable:
call .Lresident_nested_eptp_before_root_write
.Lresident_ept01_page_write_translation:
mov edx, 3
.Lresident_ept01_page_translate:
// R11 is an L1 GPA on entry and the mapped HPA on success. Require the requested
// permissions at every EPT01 level before accessing a shared page from root.
mov rax, r11
shr rax, 48
jnz .Lresident_ept01_page_denied
mov r9, qword ptr [r12 + {b_cache_ept_pointer}]
mov r8, {host_page_address_mask}
and r9, r8
test r9, r9
jz .Lresident_ept01_page_denied
mov ecx, 39
.Lresident_ept01_page_walk:
mov rax, r11
shr rax, cl
and eax, 511
mov rax, qword ptr [r9 + rax * 8]
mov r10d, eax
and r10d, edx
cmp r10d, edx
jne .Lresident_ept01_page_denied
cmp ecx, 12
je .Lresident_ept01_page_allowed
cmp ecx, 39
je .Lresident_ept01_page_next
test al, 0x80
jnz .Lresident_ept01_page_allowed
.Lresident_ept01_page_next:
and rax, r8
mov r9, rax
sub ecx, 9
jmp .Lresident_ept01_page_walk
.Lresident_ept01_page_allowed:
mov r10, 1
shl r10, cl
dec r10
and r11, r10
not r10
and rax, r10
and rax, r8
or r11, rax
jmp .Lresident_ept01_host_page_is_mapped
.Lresident_ept01_page_denied:
xor eax, eax
ret
.endm

// Root mapping validation: R11=HPA, R12=context; EAX=1/0 reports accessibility. RAX/RCX/RDX/flags are scratch, other GPRs/RSP/SIMD preserved. Cache only complete immutable 2 MiB host mappings, using existing per-CPU ABI offsets. Return without touching guest translation permissions.
.macro matrixhv_ept01_host_mapping_validation
.Lresident_ept01_host_page_is_mapped:
// Root page tables never change after setup. Cache only fully mapped 2 MiB
// ranges; a 4 KiB mapping cannot certify its neighbors across a hole.
mov rdx, {host_page_address_mask}
mov rcx, r11
shr rcx, 21
and ecx, 3
mov rax, r11
and rax, -2097152
or rax, 1
cmp rax, qword ptr [r12 + {b_nested_host_mapping_cache} + rcx * 8]
je .Lresident_ept01_host_page_is_mapped_success
mov rax, qword ptr [r12 + {b_expected_host_cr3}]
and rax, rdx
mov rcx, r11
shr rcx, 39
and ecx, 0x1ff
mov rax, qword ptr [rax + rcx * 8]
test al, 1
jz .Lresident_ept01_host_page_is_unmapped
and rax, rdx
mov rcx, r11
shr rcx, 30
and ecx, 0x1ff
mov rax, qword ptr [rax + rcx * 8]
test al, 1
jz .Lresident_ept01_host_page_is_unmapped
test al, 0x80
jnz .Lresident_ept01_host_mapping_cache_fill
and rax, rdx
mov rcx, r11
shr rcx, 21
and ecx, 0x1ff
mov rax, qword ptr [rax + rcx * 8]
test al, 1
jz .Lresident_ept01_host_page_is_unmapped
test al, 0x80
jnz .Lresident_ept01_host_mapping_cache_fill
and rax, rdx
mov rcx, r11
shr rcx, 12
and ecx, 0x1ff
mov rax, qword ptr [rax + rcx * 8]
test al, 1
jz .Lresident_ept01_host_page_is_unmapped
jmp .Lresident_ept01_host_page_is_mapped_success
.Lresident_ept01_host_mapping_cache_fill:
mov rcx, r11
shr rcx, 21
and ecx, 3
mov rax, r11
and rax, -2097152
or rax, 1
mov qword ptr [r12 + {b_nested_host_mapping_cache} + rcx * 8], rax
.Lresident_ept01_host_page_is_mapped_success:
mov eax, 1
ret
.Lresident_ept01_host_page_is_unmapped:
xor eax, eax
ret
.endm
