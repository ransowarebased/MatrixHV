"""Build an isolated firmware probe for VMFUNC on the encrypted VMware fixture."""

from pathlib import Path
import argparse
import shutil
import subprocess


project = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=project / "builds/vmfunc-runtime")
arguments = parser.parse_args()
output = arguments.output.resolve()
output.relative_to(project / "builds")
probe = output / "probe-source"
probe.mkdir(parents=True, exist_ok=True)
for name in ("Cargo.toml", "Cargo.lock", "build.rs"):
    shutil.copy2(project / name, probe / name)
shutil.copytree(project / "src", probe / "src", dirs_exist_ok=True)
(probe / "builds").mkdir(exist_ok=True)
configuration = (project / "builds/MatrixConfig.bin").read_text()
assert "VmxTest=false" in configuration and "VtNested=true" in configuration
(probe / "builds/MatrixConfig.bin").write_text(configuration)
guest_rust = probe / "src/boot/guest.rs"
source = guest_rust.read_text()
old = "u64::from(VMX_TEST_ENABLED.load(Ordering::Acquire))"
assert source.count(old) == 1
guest_rust.write_text(source.replace(old, "1"))

resources = probe / "src/vmx/vcpu.rs"
source = resources.read_text()
old = "let nested_vmcs12_pages = ResidentPages::allocate(2, AddressConstraint::Any)"
assert source.count(old) == 1
resources.write_text(source.replace(old, old.replace("allocate(2,", "allocate(3,")))

guest = probe / "src/asm/guest_boot.S"
source = guest.read_text()
dispatch = ".Lwindows_nested_l1_exit:\n"
assert source.count(dispatch) == 1
source = source.replace(dispatch, dispatch + "    test eax, eax\n    jz .Lwindows_nested_vmfunc_exit\n")
finish = "    vmxoff\n    jna .Lwindows_nested_probe_failed\n"
assert source.count(finish) == 1
source = source.replace(finish, """    mov ecx, 0x48b
    rdmsr
    test edx, 0x2000
    jz .Lwindows_nested_probe_failed
    lea rdi, [r8 + 4096]
    mov rdx, qword ptr [rbx + 24]
    mov qword ptr [rdi], rdx
    mov qword ptr [rdi + 4088], rdx
    mov ecx, 0x48c
    rdmsr
    test eax, 0x200000
    jz .Lwindows_nested_vmfunc_list_ready
    xor qword ptr [rdi + 4088], 0x40
.Lwindows_nested_vmfunc_list_ready:
    mov rcx, 0x2024
    mov rdx, rdi
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, 0x2018
    mov edx, 1
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {secondary_control_field}
    mov edx, 0x2022
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    lea rdx, [rip + .Lwindows_nested_vmfunc_loop_start]
    vmwrite rcx, rdx
    jna .Lwindows_nested_probe_failed
    push rbx
    mov eax, 0x4d485652
    mov ecx, 0x202
    cpuid
    pop rbx
    push rbx
    mov eax, 0x4d485652
    mov ecx, 5
    cpuid
    pop rbx
    mov dword ptr [rbx + 136], eax
    vmresume
    jmp .Lwindows_nested_probe_failed
.Lwindows_nested_vmfunc_loop_start:
    mov ebp, 1024
.Lwindows_nested_vmfunc_loop:
    xor eax, eax
    mov ecx, 511
    vmfunc
    xor ecx, ecx
    vmfunc
    dec ebp
    jnz .Lwindows_nested_vmfunc_loop
    mov r13, qword ptr [r14]
    mov r11, {ept_second_target_marker}
    cmp r13, r11
    jne .Lwindows_nested_l2_bad_resume
    mov r10, qword ptr [rbx + 24]
    mov qword ptr [rdi + 16], r10
    xor eax, eax
    mov ecx, 2
    vmfunc
    mov qword ptr [rdi + 16], 0
    xor eax, eax
    mov ecx, 2
.Lwindows_nested_vmfunc_invalid:
    vmfunc
    jmp .Lwindows_nested_l2_bad_resume
.Lwindows_nested_vmfunc_exit:
    cmp ecx, 2
    jne .Lwindows_nested_probe_failed
    mov rcx, {exit_reason_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp edx, 59
    jne .Lwindows_nested_probe_failed
    mov rcx, {guest_rip_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    lea r10, [rip + .Lwindows_nested_vmfunc_invalid]
    cmp rdx, r10
    jne .Lwindows_nested_probe_failed
    mov rcx, {ept_pointer_field}
    vmread rdx, rcx
    jna .Lwindows_nested_probe_failed
    cmp rdx, qword ptr [rbx + 24]
    jne .Lwindows_nested_probe_failed
    push rbx
    mov eax, 0x4d485652
    mov ecx, 5
    cpuid
    pop rbx
    sub eax, dword ptr [rbx + 136]
    mov dword ptr [rbx + 144], eax
    cmp eax, 128
    jae .Lwindows_nested_probe_failed
    mov qword ptr [rbx + 152], 1
""" + finish)
guest.write_text(source)

subprocess.run([
    "cargo", "build", "--release", "--target", "x86_64-unknown-uefi",
    "--manifest-path", str(probe / "Cargo.toml"),
    "--target-dir", str(project / "builds/.cargo-target-vmfunc-probe"),
], cwd=project, check=True)
print("Probe completion and exit delta are at BSP nested.vmxon_operand + 152 and + 144.")
