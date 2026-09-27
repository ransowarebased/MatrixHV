from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "eptp-sync-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/asm/eptp_switch.S").read_text()
start = source.index(".Lresident_nested_eptp_sync_acquire:")
end = source.index(".endm", start)
assembly = source[start:end]
assert assembly.count("invept rax, xmmword ptr [rsp]") == 1
assembly = assembly.replace(
    "invept rax, xmmword ptr [rsp]",
    "inc qword ptr [r12 + {test_flushes}]\nmov eax, 1\ntest eax, eax",
)
assert assembly.count("vmread r11, rax") == 1
assembly = assembly.replace(
    "vmread r11, rax",
    "mov r11, qword ptr [r12 + {test_exit_info}]\n"
    "push rax\nmov eax, 1\ntest eax, eax\npop rax",
)
# The production data lives in the writable resident copy of the island.
assembly = assembly.replace(".balign 8\n.Lresident_eptp_sync_owner:",
                            ".data\n.balign 8\n.Lresident_eptp_sync_owner:")
(output / "eptp-sync.S").write_text(assembly + "\n.text\n")
executable = output / "eptp-sync-tests.exe"
subprocess.run(
    ["rustc", "--edition=2024", "--test", str(project / "tests/eptp_sync.rs"),
     "-o", str(executable)], check=True, cwd=project,
)
subprocess.run([str(executable)], check=True, cwd=project)
