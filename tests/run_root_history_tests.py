"""Exercise the actual resident root-history assembly on the host."""

from pathlib import Path
import re
import subprocess
import sys

project = Path(__file__).resolve().parents[1]
output = project / "builds" / "root-history-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/vmx/asm/exits.S").read_text(encoding="utf-8")
match = re.search(r"(?ms)^\.macro resident_memory_record_root\n.*?^\.endm$", source)
if match is None:
    raise ValueError("Resident root-history macro was not found")
protocol = (project / "sdk/src/protocol.rs").read_text(encoding="utf-8")
count_match = re.search(r"ROOT_HISTORY_COUNT: usize = (\d+);", protocol)
if count_match is None:
    raise ValueError("Root-history size was not found")
count = int(count_match.group(1))
if count != 16:
    raise ValueError("Update the root-history fixture for the new history size")
macro = match.group(0)
for name, value in {
    "event_memory_kernel_cr3": 0,
    "event_memory_root_sequence": 8,
    "event_memory_root_history": 16,
    "memory_root_history_mask": count - 1,
}.items():
    macro = macro.replace("{" + name + "}", str(value))
args = "mov rax, rcx\nmov r11, rdx" if sys.platform == "win32" else "mov rax, rdi\nmov r11, rsi"
assembly = f"""
.text
{macro}
.globl test_record_root
test_record_root:
{args}
resident_memory_record_root
.Lresident_memory_root_observed:
ret
"""
(output / "record.S").write_text(assembly, encoding="utf-8")
binary = output / ("root_history_tests.exe" if sys.platform == "win32" else "root_history_tests")
subprocess.run(
    ["rustc", "--edition=2024", "-Dwarnings", "--test", str(project / "tests/root_history_tests.rs"), "-o", str(binary)],
    cwd=project,
    check=True,
)
subprocess.run([str(binary)], cwd=project, check=True)
