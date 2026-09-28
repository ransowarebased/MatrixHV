"""Run the Neo interactive console integration tests on the host target."""

from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
version = subprocess.run(["rustc", "-vV"], check=True, capture_output=True, text=True)
host_target = next(
    line.removeprefix("host: ")
    for line in version.stdout.splitlines()
    if line.startswith("host: ")
)
subprocess.run(
    [
        "cargo", "test",
        "--manifest-path", str(project / "src/road/Cargo.toml"),
        "--target", host_target,
        "--target-dir", str(project / "builds/neo-control-trace-target"),
        "--test", "neo_repl",
    ],
    check=True,
    cwd=project,
)
