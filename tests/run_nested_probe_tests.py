"""Execute nested invalidation routing with translated VMXON probe metadata."""

from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds/nested-probe-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/asm/nested.S").read_text(encoding="utf-8")
assembly = ".text\n"
for operation, reason, offset in (("invept", 50, 88), ("invvpid", 53, 120)):
    start = source.index(f".Lresident_dispatch_{operation}:\n")
    start = source.index("jnz .Lresident_nested_inject_gp\n", start) + len("jnz .Lresident_nested_inject_gp\n")
    end = source.index(f".Lresident_dispatch_{operation}_probe:\n", start)
    route = source[start:end]
    for name, value in {
        "b_nested_vmxon_region": 0,
        "b_last_guest_rip": 8,
        "b_last_reason": 16,
        f"nested_{operation}_rip_offset": offset,
        f"{operation}_reason": reason,
    }.items():
        route = route.replace("{" + name + "}", str(value))
    assembly += f"""
.globl test_probe_{operation}
test_probe_{operation}:
push r12
mov r12, rcx
call .Ltest_probe_{operation}_route
pop r12
ret
.Ltest_probe_{operation}_route:
{route}
.Lresident_dispatch_{operation}_probe:
mov eax, 1
ret
.Lresident_dispatch_{operation}_hardware:
mov eax, 2
ret
"""
assembly += """
.Lresident_nested_inject_ud:
mov eax, 3
ret
.Lresident_ept01_page_is_readable:
inc qword ptr [r12 + 32]
cmp r11, qword ptr [r12]
jne .Ltest_probe_invalid_translation
mov r11, qword ptr [r12 + 24]
xor eax, eax
test r11, r11
setnz al
ret
.Ltest_probe_invalid_translation:
ud2
"""
(output / "probe.S").write_text(assembly, encoding="utf-8")
binary = output / "nested_probe_tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test",
                str(project / "tests/nested_probe_tests.rs"), "-o", str(binary)],
               cwd=project, check=True)
subprocess.run([str(binary)], cwd=project, check=True)
