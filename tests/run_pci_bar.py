from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src" / "core" / "vt_ept.rs").read_text(encoding="utf-8")
start = source.index("fn read_pci_bar_range(")
opening = source.index("{", start)
depth, end = 1, opening + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
parser = source[start:end]
cases = (ROOT / "tests" / "pci_bar.rs").read_text(encoding="utf-8")
builds = ROOT / "builds"
builds.mkdir(exist_ok=True)
harness = builds / "pci-bar-harness.rs"
binary = builds / "pci-bar-tests.exe"
stubs = """
const PCI_BAR_DESCRIPTOR_SIZE: usize = 46;
const EPT_GUEST_PHYSICAL_LIMIT: u64 = 1 << 48;
#[derive(Debug, PartialEq)]
enum EptError {
    AddressOverflow,
    GuestPhysicalAddressTooWide(u64),
}
"""
harness.write_text(stubs + parser + "\n" + cases, encoding="utf-8")
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
