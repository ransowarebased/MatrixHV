// EFI AP callback: RCX=launch context. Save flags, all nonvolatile GPRs and FX
// state; 544 stack bytes provide 32-byte shadow space and an aligned FX area.
// matrixhv_ap_prepare receives RDX=saved stack, R8=guest continuation and
// returns RAX=nested operand page or zero. VMLAUNCH reaches guest_boot.S;
// RAX returns one after the guest probe or zero on preparation failure.
// Both returns restore the complete firmware state via .Lap_restore_state.
// Failure calls the vcpu owner while resources remain retained. Root preparation
// runs before EBS; the guest continuation uses the saved firmware stack.
.text
.globl matrixhv_ap_launch_asm
matrixhv_ap_launch_asm:
    pushfq
    cli
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 544
    fxsave64 [rsp + 32]
    mov rdx, rsp
    lea r8, [rip + .Lap_guest_return]
    call matrixhv_ap_prepare
    test rax, rax
    jz .Lap_restore_state
    vmlaunch
    // A failed launch cannot release resources while another CPU may be resident.
    pushfq
    pop rcx
    call matrixhv_ap_launch_failed
matrixhv_ap_guest_probe
.Lap_restore:
    mov eax, 1
.Lap_restore_state:
    fxrstor64 [rsp + 32]
    add rsp, 544
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    popfq
    ret
