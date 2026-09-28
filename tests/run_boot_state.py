"""Verify the debugger collector's offsets against the Rust compiler layout."""

import ast
from pathlib import Path
import re
import struct
import subprocess


project = Path(__file__).resolve().parents[1]
resident = (project / "src/core/vt_resident.rs").read_text()
nested = (project / "src/nested.rs").read_text()
collector = ast.parse((project / "tests/collect_boot_state.py").read_text())
functions = [node for node in collector.body if isinstance(node, ast.FunctionDef)
             and node.name in ("structure", "append_u64_fields")]
namespace = {"resident": resident, "nested": nested, "re": re,
             "fields": {}, "formats": {}, "offset": 0}
exec(compile(ast.Module(body=functions, type_ignores=[]), "collect_boot_state.py", "exec"), namespace)
namespace["append_u64_fields"](namespace["structure"](resident, "ResidentBootContext"), "")

output = project / "builds/boot-state-tests"
output.mkdir(parents=True, exist_ok=True)
harness = "use std::mem::{offset_of, size_of};\n"
for name in ("VMCS12_EXTENDED_FIELD_COUNT", "NESTED_FAILURE_TRACE_WORD_COUNT"):
    count = re.search(r"const " + name + r": usize = (\d+)", nested)[1]
    harness += f"const {name}: usize = {count};\n"
harness += "#[repr(C, align(16))]\npub struct RootFxState(pub [u8; 512]);\n"
for source, name, alignment in (
    (resident, "WatchdogGuestState", ""),
    (nested, "NestedVmcs12State", ""),
    (nested, "NestedVmxState", ""),
    (resident, "ResidentBootContext", ", align(16)"),
):
    harness += f"#[repr(C{alignment})]\npub struct {name} {{"
    harness += namespace["structure"](source, name) + "\n}\n"
harness += "fn main() {\n"
for name, format_code in namespace["formats"].items():
    path = name
    displacement = ""
    if name.rsplit(".", 1)[-1].isdecimal():
        path, index = name.rsplit(".", 1)
        element = "u64" if format_code == "<Q" else "u32"
        displacement = f" + {index} * size_of::<{element}>()"
    harness += f'println!("{name}={{}}", offset_of!(ResidentBootContext, {path}){displacement});\n'
harness += "}\n"
source_path = output / "layout.rs"
executable = output / "layout.exe"
source_path.write_text(harness)
subprocess.run(["rustc", "--edition=2024", "-Dwarnings", str(source_path),
                "-o", str(executable)], check=True, cwd=project)
result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
actual = dict(line.split("=", 1) for line in result.stdout.splitlines())
expected = namespace["fields"]
assert set(actual) == set(expected)
for name, offset in expected.items():
    assert int(actual[name]) == offset, (name, offset, actual[name])
    assert struct.calcsize(namespace["formats"][name]) in (4, 8)
print(f"Verified {len(expected)} resident fields, including nested structs and mixed-width arrays.")
