"""Execute production L2 kernel observation assembly with simulated VMCS/MSRs."""
from pathlib import Path
import re
import subprocess

project = Path(__file__).resolve().parents[1]
output = project / "builds/l2-kernel-root-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/asm/nested_intercept.S").read_text(encoding="utf-8")
source = source.split(".Lresident_nested_observe_kernel_root:", 1)[1].split(".Lresident_nested_memory_request:", 1)[0]
constants = {"guest_cs_ar_bytes": 0, "vm_entry_controls": 1, "b_nested_ept12_pointer": 16,
             "guest_cr3": 3, "guest_cr4": 4, "ia32_lstar": 0xc0000082,
             "host_page_address_mask": 0x000f_ffff_ffff_f000,
             "b_nested_kernel_root_cursor": 48, "b_nested_kernel_roots": 56}
source = re.sub(r"\{(\w+)\}", lambda match: str(constants[match[1]]), source)
source = re.sub(r"vmread (\w+), rax", r"mov \1, qword ptr [r12 + rax * 8]\nmov eax, 1\ntest eax, eax", source)
source = source.replace("rdmsr", "mov rax, qword ptr [r12 + 40]\nmov rdx, rax\nshr rdx, 32\nmov eax, eax")
source = source.replace("call .Lresident_nested_capture_native_eptp", "inc qword ptr [r12 + 312]")
assembly = ".text\n.global test_l2_observe\ntest_l2_observe:\npush r12\nmov r12, rcx\ncall .Ltest_observe\npop r12\nret\n.Ltest_observe:\n" + source + "\n.Lresident_dispatch_vmread_failed:\nud2\n"
(output / "observe.S").write_text(assembly, encoding="utf-8")
binary = output / "tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test", str(project / "tests/l2_kernel_root_tests.rs"), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
