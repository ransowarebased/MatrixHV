// The EFI entry routines accept RCX=context, RDX=HOST_RSP, R8=HOST_RIP and
// return EAX=launch status. They preserve ABI nonvolatile GPRs; the boot entry
// also saves/restores FPU/SIMD state in the 16-byte-aligned context FX area.
// Root entry uses the context pointer at HOST_RSP, without a C return address.
// Only the section delimited by island_start/end is copied. Component macros
// expand in place so relative branches, tables and patch slots move together.
.text
.globl matrixhv_resident_guest_probe_asm
matrixhv_resident_guest_probe_asm:
vmcall
ud2
.globl matrixhv_resident_probe_run_asm
matrixhv_resident_probe_run_asm:
push rbx
push rbp
push rdi
push rsi
push r12
push r13
push r14
push r15
mov qword ptr [rcx + {p_root_rsp}], rsp
lea rax, [rip + 9f]
mov qword ptr [rcx + {p_return_rip}], rax
sgdt [rcx + {p_original_gdtr}]
sidt [rcx + {p_original_idtr}]
mov rax, {host_rsp}
vmwrite rax, rdx
jc 6f
jz 3f
mov rax, {host_rip}
vmwrite rax, r8
jc 7f
jz 4f
vmlaunch
jc 1f
jz 2f
mov eax, 5
jmp 8f
1:
mov eax, 1
jmp 8f
2:
mov eax, 2
jmp 8f
3:
mov eax, 3
jmp 8f
4:
mov eax, 4
jmp 8f
6:
mov eax, 7
jmp 8f
7:
mov eax, 8
jmp 8f
9:
lgdt [r10 + {p_original_gdtr}]
lidt [r10 + {p_original_idtr}]
xor eax, eax
8:
pop r15
pop r14
pop r13
pop r12
pop rsi
pop rdi
pop rbp
pop rbx
ret
.globl matrixhv_resident_boot_run_asm
matrixhv_resident_boot_run_asm:
push rbx
push rbp
push rdi
push rsi
push r12
push r13
push r14
push r15
mov qword ptr [rcx + {b_root_rsp}], rsp
lea rax, [rip + .Lresident_boot_return]
mov qword ptr [rcx + {b_return_rip}], rax
sgdt [rcx + {b_gdtr}]
sidt [rcx + {b_idtr}]
fxsave64 [rcx + {b_fx}]
mov rax, {host_rsp}
vmwrite rax, rdx
jc .Lresident_boot_rsp_fail_invalid
jz .Lresident_boot_rsp_fail
mov rax, {host_rip}
vmwrite rax, r8
jc .Lresident_boot_rip_fail_invalid
jz .Lresident_boot_rip_fail
mov rax, qword ptr [rcx + {b_nested_vmxon_operand}]
vmlaunch
jc .Lresident_boot_fail_invalid
jz .Lresident_boot_fail_valid
mov eax, 5
jmp .Lresident_boot_failure_restore
.Lresident_boot_fail_invalid:
mov eax, 1
jmp .Lresident_boot_failure_restore
.Lresident_boot_fail_valid:
mov eax, 2
jmp .Lresident_boot_failure_restore
.Lresident_boot_rsp_fail:
mov eax, 3
jmp .Lresident_boot_failure_restore
.Lresident_boot_rip_fail:
mov eax, 4
jmp .Lresident_boot_failure_restore
.Lresident_boot_rsp_fail_invalid:
mov eax, 7
jmp .Lresident_boot_failure_restore
.Lresident_boot_rip_fail_invalid:
mov eax, 8
.Lresident_boot_failure_restore:
fxrstor64 [rcx + {b_fx}]
jmp .Lresident_boot_pop
.Lresident_boot_return:
lgdt [r12 + {b_gdtr}]
lidt [r12 + {b_idtr}]
fxrstor64 [r12 + {b_fx}]
xor eax, eax
.Lresident_boot_pop:
pop r15
pop r14
pop r13
pop r12
pop rsi
pop rdi
pop rbp
pop rbx
ret

.globl matrixhv_resident_startup_halt_asm
matrixhv_resident_startup_halt_asm:
.Lresident_startup_halt:
cli
hlt
jmp .Lresident_startup_halt

.section .text.matrixhv_resident_island,"ax"
.p2align 4
.globl matrixhv_resident_island_start
.globl matrixhv_resident_island_entry
matrixhv_resident_island_start:
matrixhv_resident_island_entry:
cld
mov r10, qword ptr [rsp]
mov rax, cr3
mov qword ptr [r10 + {p_observed_host_cr3}], rax
mov rax, {guest_cr3}
vmread r11, rax
jc matrixhv_resident_island_fatal
jz matrixhv_resident_island_fatal
mov qword ptr [r10 + {p_observed_guest_cr3}], r11
mov rax, {exit_reason}
vmread r11, rax
jc matrixhv_resident_island_fatal
jz matrixhv_resident_island_fatal
mov qword ptr [r10 + {p_exit_reason}], r11
mov rax, {guest_rip}
vmread r11, rax
jc matrixhv_resident_island_fatal
jz matrixhv_resident_island_fatal
mov qword ptr [r10 + {p_guest_rip}], r11
mov rax, {complete}
mov qword ptr [r10 + {p_completed}], rax
mov rax, qword ptr [r10 + {p_source_cr3}]
mov cr3, rax
mov rsp, qword ptr [r10 + {p_root_rsp}]
jmp qword ptr [r10 + {p_return_rip}]
matrixhv_island_dispatch
matrixhv_island_visual_callback
matrixhv_resident_guest_privilege
matrixhv_island_nmi_delivery
matrixhv_resident_msr_validation
matrixhv_island_host_exceptions
matrixhv_island_bridge
matrixhv_island_output
matrixhv_island_log_slot
matrixhv_island_switch_slot
matrixhv_island_visual_slot
matrixhv_island_slots
.globl matrixhv_resident_island_end
matrixhv_resident_ept_cache
matrixhv_resident_eptp_switch
matrixhv_island_flight_recorder
matrixhv_resident_island_end:
.text
