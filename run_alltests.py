"""Build and run the local test suites grouped by component."""

import argparse
from pathlib import Path
import subprocess
import sys
from time import perf_counter

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))
from harness import COMPONENTS, prepare_boot_state


def execute(command, project, env=None):
    subprocess.run(command, cwd=project, env=env, check=True)


def run_component(project, component, release=False):
    prepared = set()
    for name, prepare in COMPONENTS[component].items():
        print(f"\n  {component}::{name}", flush=True)
        if prepare is not None and prepare not in prepared:
            prepare(project)
            prepared.add(prepare)
        output = project / "builds" / "tests" / component
        output.mkdir(parents=True, exist_ok=True)
        binary = output / (name + (".exe" if sys.platform == "win32" else ""))
        execute(
            [
                "rustc", "--edition=2024", "--test",
                "--cfg", f'test_harness="{name}"',
                *(["-C", "opt-level=3"] if release else []),
                str(project / "tests" / f"{component}_tests.rs"),
                "-o", str(binary),
            ],
            project,
        )
        execute([str(binary)], project)
    if component == "resident":
        execute([sys.executable, str(project / "tests/run_interception_runtime_tests.py")], project)
        print("\n  resident::boot_state_layout", flush=True)
        prepare_boot_state(project)
        execute([sys.executable, str(project / "tests/run_flight_recorder_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_intel_pt_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_exit_guard_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_vmcall_snapshot_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_host_state_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_debugctl_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_cet_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_exit_event_tests.py")], project)
        execute([sys.executable, str(project / "tests/run_watchdog_recovery_tests.py")], project)
        proof_binary = project / "builds/tests/resident/proof_exit_regressions.exe"
        execute(["rustc", "--edition=2024", "-Dwarnings", "--test",
                 str(project / "tests/proof_exit_regressions.rs"), "-o", str(proof_binary)], project)
        execute([str(proof_binary)], project)
    if component == "nested":
        execute([sys.executable, str(project / "tests/run_nested_probe_tests.py")], project)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="Build optimized host tests in Release mode")
    parser.add_argument(
        "components", nargs="*", metavar="COMPONENT",
        help=f"Optional component filter: {', '.join(COMPONENTS)}",
    )
    arguments = parser.parse_args()
    components = arguments.components or list(COMPONENTS)
    unknown = set(components) - set(COMPONENTS)
    if unknown:
        parser.error(f"Unknown components: {', '.join(sorted(unknown))}")
    project = Path(__file__).resolve().parent
    print(f"Running {len(components)} component test suites.", flush=True)
    results = []
    started = perf_counter()
    for index, component in enumerate(components, start=1):
        print(f"\n[{index}/{len(components)}] {component}_tests.rs", flush=True)
        suite_started = perf_counter()
        passed = True
        try:
            run_component(project, component, arguments.release)
            if component == "boot" and sys.platform == "win32":
                print("\n  boot::build_scripts", flush=True)
                execute(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", str(project / "tests/build_scripts_tests.ps1")], project)
        except (OSError, subprocess.CalledProcessError, ValueError, AssertionError) as error:
            print(f"Suite failed: {error}", flush=True)
            passed = False
        elapsed = perf_counter() - suite_started
        results.append((component, passed, elapsed))
        print(f"{'PASS' if passed else 'FAIL'} {component} ({elapsed:.2f}s)", flush=True)

    print("\nTest summary:", flush=True)
    for component, passed, elapsed in results:
        print(f"  {'PASS' if passed else 'FAIL'} {component} ({elapsed:.2f}s)", flush=True)
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
