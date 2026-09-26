from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "logger-tests"
output.mkdir(parents=True, exist_ok=True)
logger = (project / "src/runtime/logger.rs").read_text(encoding="utf-8")
serial = (project / "src/runtime/serial.rs").read_text(encoding="utf-8")
screen = (project / "src/boot/mod.rs").read_text(encoding="utf-8")


def item(source, declaration):
    start = source.index(declaration)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


backend = "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n" + item(logger, "pub(crate) enum LogBackend")
selector = item(logger, "fn select_backend(")
probe = item(serial, "fn probe_com1(")
firmware_guard = item(screen, "fn firmware_calls_allowed(")
constants = "\n".join(
    re.findall(r"(?:pub\(crate\) )?const (?:COM1|TRANSMIT_EMPTY|TX_WAIT_LIMIT):[^;]+;", serial)
    + re.findall(r"pub\(crate\) const (?:SERIAL_SINK|FRAMEBUFFER_SINK):[^;]+;", logger)
)
harness = output / "harness.rs"
cases = (project / "tests/logger.rs").read_text(encoding="utf-8")
harness.write_text("\n".join([backend, selector, probe, firmware_guard, constants, cases]), encoding="utf-8")
binary = output / "logger-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
