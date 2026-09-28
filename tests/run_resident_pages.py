from pathlib import Path
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "resident-pages-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/memory.rs").read_text(encoding="utf-8")


def item(declaration):
    start = source.index(declaration)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


definitions = "\n".join(item(declaration) for declaration in [
    "pub enum AddressConstraint",
    "pub struct ResidentPages",
    "impl ResidentPages",
    "impl Drop for ResidentPages",
])
harness = output / "harness.rs"
harness.write_text(
    definitions + "\n" + (project / "tests/resident_pages.rs").read_text(encoding="utf-8"),
    encoding="utf-8",
)
binary = output / "resident-pages-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
