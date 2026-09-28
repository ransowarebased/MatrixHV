from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "config-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/boot.rs").read_text(encoding="utf-8")
start = source.index("pub const CONFIG_HEADER:")
end = source.index("\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum ConfigLoadError", start)
parser = source[start:source.index("const CONFIG_FILE_PATH", start)]
parser += source[source.index("static CPUID_PRESENCE", start):end]
cases = (project / "tests/config.rs").read_text(encoding="utf-8")
harness = output / "harness.rs"
harness.write_text(
    "mod boot {\nuse core::str;\n"
    "use core::sync::atomic::{AtomicBool, Ordering};\n"
    + parser + "\n}\n" + cases,
    encoding="utf-8",
)
binary = output / "config-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
