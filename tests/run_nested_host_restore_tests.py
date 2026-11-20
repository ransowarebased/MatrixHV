"""Compare production L1 host restoration with unconditional VMCS writes."""

from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds/nested-host-restore-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/asm/nested.S").read_text(encoding="utf-8")
start = source.index(".Lresident_nested_restore_l1_host_state:")
assembly = source[start:source.index(".Lresident_nested_l2_enter:", start)]
start = source.index(".Lresident_nested_host_state_table:")
assembly += source[start:source.index(".endm", start)]
assembly = re.sub(r"^resident_telemetry_counter .*\n", "", assembly, flags=re.MULTILINE)
fields = {"b_nested_vmcs12_extended_fields": 0}
for index, name in enumerate(sorted(set(re.findall(r"\{(b_\w+)\}", assembly)) - fields.keys()), 128):
    fields[name] = index * 8
values = {name: int(value, 16) for name, value in re.findall(
    r"pub const (\w+): u64 = (0x[0-9a-fA-F]+);",
    (project / "src/vmx/vmcs.rs").read_text(encoding="utf-8"))}
aliases = dict(re.findall(r"(\w+) = const (\w+),",
                         (project / "src/vmx/resident/mod.rs").read_text(encoding="utf-8")))
constants = {**fields, "nested_host_state_table_count": 18}
for name in set(re.findall(r"\{(guest_\w+)\}", assembly)):
    constants[name] = values[aliases[name]]
assembly = re.sub(r"\{(\w+)\}", lambda match: str(constants[match[1]]), assembly)
assembly = assembly.replace("vmwrite rax, r11", "mov [r12 + 2048 + rax * 8], r11\n"
                            "inc qword ptr [r12 + 1536]\ncmp r12, 0")
assembly = assembly.replace("vmread r11, rax", "mov r11, [r12 + 2048 + rax * 8]\ncmp r12, 0")
assembly += "\n.Lresident_dispatch_vmwrite_failed:\n.Lresident_dispatch_vmread_failed:\nud2\n"
reference, count = re.subn(
    r"cmp r11, qword ptr \[r12 \+ \d+\]\nje \.Lresident_nested_l1_host_\w+_unchanged\n",
    "", assembly)
assert count == 4, count
reference = reference.replace(".Lresident_", ".Lreference_")
wrapper = ".text\n"
for name, label in (("restore_host", ".Lresident_"), ("restore_host_reference", ".Lreference_")):
    wrapper += (f".globl {name}\n{name}:\npush r12\npush rsi\nmov r12, rcx\n"
                f"call {label}nested_restore_l1_host_state\npop rsi\npop r12\nret\n")
(output / "handlers.S").write_text(wrapper + assembly + reference, encoding="utf-8")
(output / "offsets.rs").write_text(
    "fn offset(name: &str) -> usize { match name {\n" +
    "".join(f'"{name}" => {value // 8},\n' for name, value in fields.items()) +
    '_ => panic!("unknown context field: {name}"),\n} }\n', encoding="utf-8")
binary = output / "tests.exe"
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "--test",
                str(project / "tests/nested_host_restore_tests.rs"), "-o", str(binary)],
               cwd=project, check=True)
subprocess.run([str(binary)], cwd=project, check=True)
