from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src" / "boot.rs").read_text(encoding="utf-8")
start = source.index("mod boot_order {")
end = source.index("\nmod memory_map {", start)
parser = source[start:end]
cases = (ROOT / "tests" / "boot_order.rs").read_text(encoding="utf-8")
builds = ROOT / "builds"
builds.mkdir(exist_ok=True)
harness = builds / "boot-order-harness.rs"
binary = builds / "boot-order-tests.exe"
harness.write_text(parser + "\n" + cases, encoding="utf-8")
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
