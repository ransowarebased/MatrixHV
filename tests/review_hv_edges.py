"""Run isolated architectural contract probes without changing the runtime."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from harness import prepare_nested_ept


PROJECT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT / "builds" / "hv-review-20261001"


def run(command, log_name):
    result = subprocess.run(command, cwd=PROJECT, capture_output=True, text=True)
    (OUTPUT / log_name).write_text(result.stdout + result.stderr, encoding="utf-8")
    return result


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    source_path = PROJECT / "tests" / "nested_tests.rs"
    prepare_nested_ept(PROJECT)
    baseline = OUTPUT / "baseline-ept.exe"
    compile_result = run(
        ["rustc", "--edition=2024", "--test", "--cfg", 'test_harness="ept"',
         str(source_path), "-o", str(baseline)], "baseline-compile.log"
    )
    compile_result.check_returncode()
    baseline_result = run([str(baseline)], "baseline-ept.log")
    baseline_result.check_returncode()
    binary = baseline
    probes = [
        "ept_nonleaf_reserved_bits_require_misconfiguration",
        "ept_large_leaf_alignment_requires_misconfiguration",
        "ept_address_width_requires_misconfiguration",
        "ept_execute_only_requires_advertised_support",
        "ept_invalid_entries_must_not_survive_revalidation",
        "observe_valid_memory_type_composition",
        "io_bitmaps_require_ept01_translation",
    ]
    results = []
    for probe in probes:
        result = run([str(binary), "review_edge_" + probe, "--nocapture", "--test-threads=1"], probe + ".log")
        executed = "running 1 test" in result.stdout
        assertion_failed = "assertion" in result.stderr and "FAILED" in result.stdout
        classification = "contract_violated" if assertion_failed else "passed" if result.returncode == 0 and executed else "harness_error"
        results.append({"probe": probe, "classification": classification, "exit_code": result.returncode, "log": str(OUTPUT / (probe + ".log"))})
        print(f"{probe}: {classification}")
    snapshot = {
        str(path.relative_to(PROJECT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [PROJECT / "src/asm/nested.S", PROJECT / "src/asm/hyperv.S", PROJECT / "src/nested.rs"]
    }
    (OUTPUT / "edge-results.json").write_text(json.dumps({
        "method": "Actual resident assembly; VMREAD and hardware invalidation mocked by the existing host harness",
        "physical_execution": False,
        "baseline_passed": True, "source_hashes": snapshot, "probes": results,
    }, indent=2) + "\n", encoding="utf-8")
    if any(result["classification"] != "passed" for result in results):
        raise SystemExit("An architectural contract probe failed; inspect its log")


if __name__ == "__main__":
    main()
