"""Run all local Python test runners and standalone Rust tests in tests/."""

from pathlib import Path
import re
import subprocess
import sys
from time import perf_counter


def run_commands(commands, project):
    for command in commands:
        try:
            result = subprocess.run(command, cwd=project)
        except OSError as error:
            print(f"Unable to execute {command[0]}: {error}", flush=True)
            return False
        if result.returncode != 0:
            print(f"Command failed with exit code {result.returncode}", flush=True)
            return False
    return True


def main():
    project = Path(__file__).resolve().parent
    tests = project / "tests"
    runners = sorted(tests.rglob("run_*.py"))
    covered = {path.with_name(path.stem.removeprefix("run_") + ".rs") for path in runners}
    # The EPT cache runner also builds the high-address mapping harness.
    if tests / "run_ept_cache.py" in runners:
        covered.add(tests / "ept_high.rs")

    suites = [
        (str(path.relative_to(tests)), [[sys.executable, "-u", str(path)]])
        for path in runners
    ]
    for source in sorted(tests.rglob("*.rs")):
        if source in covered:
            continue
        relative = source.relative_to(tests)
        output = project / "builds" / "run-all" / relative.parent
        output.mkdir(parents=True, exist_ok=True)
        binary = output / (source.stem + (".exe" if sys.platform == "win32" else ""))
        command = ["rustc", "--edition=2024"]
        if not re.search(r"\bfn\s+main\s*\(", source.read_text(encoding="utf-8")):
            command.append("--test")
        command.extend([str(source), "-o", str(binary)])
        suites.append((str(relative), [command, [str(binary)]]))

    if not suites:
        print("No local test suites found.", flush=True)
        return 1

    print(f"Running {len(suites)} local test suites.", flush=True)
    results = []
    started = perf_counter()
    for index, (name, commands) in enumerate(suites, start=1):
        print(f"\n[{index}/{len(suites)}] {name}", flush=True)
        suite_started = perf_counter()
        passed = run_commands(commands, project)
        elapsed = perf_counter() - suite_started
        results.append((name, passed, elapsed))
        print(f"{'PASS' if passed else 'FAIL'} {name} ({elapsed:.2f}s)", flush=True)

    print("\nTest summary:", flush=True)
    for name, passed, elapsed in results:
        print(f"  {'PASS' if passed else 'FAIL'} {name} ({elapsed:.2f}s)", flush=True)
    failures = sum(not passed for _, passed, _ in results)
    print(
        f"{len(results) - failures} passed, {failures} failed "
        f"in {perf_counter() - started:.2f}s.",
        flush=True,
    )
    print(
        "External utilities require separate execution: collect_boot_state.py "
        "(IDA/VMware), nested_runtime.py (guest snapshots), "
        "kvm_unit_nested.py (external VMX suite).",
        flush=True,
    )
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nTest run interrupted.", flush=True)
        sys.exit(130)
