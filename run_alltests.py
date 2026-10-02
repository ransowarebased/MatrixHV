"""Build and run the local test suites grouped by component."""

import argparse
import os
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
        print("\n  resident::boot_state_layout", flush=True)
        prepare_boot_state(project)


def run_neo(project, release=False):
    version = subprocess.run(
        ["rustc", "-vV"], cwd=project, check=True, capture_output=True, text=True
    )
    host_target = next(
        line.removeprefix("host: ")
        for line in version.stdout.splitlines()
        if line.startswith("host: ")
    )
    output = project / "builds" / "neo-tests-target"
    options = [
        "--manifest-path", str(project / "src/road/Cargo.toml"),
        "--target", host_target, "--target-dir", str(output), "--bin", "neo",
    ]
    if release:
        options.append("--release")
    execute(["cargo", "build", *options], project)
    env = os.environ.copy()
    env["NEO_TEST_BINARY"] = str(
        output / host_target / ("release" if release else "debug") / ("neo.exe" if sys.platform == "win32" else "neo")
    )
    execute(["cargo", "test", *options], project, env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="Build optimized host tests and the ROAD agent in Release mode")
    parser.add_argument(
        "components", nargs="*", metavar="COMPONENT",
        help=f"Optional component filter: {', '.join([*COMPONENTS, 'neo'])}",
    )
    arguments = parser.parse_args()
    components = arguments.components or [*COMPONENTS, "neo"]
    unknown = set(components) - {*COMPONENTS, "neo"}
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
            if component == "neo":
                run_neo(project, arguments.release)
            else:
                run_component(project, component, arguments.release)
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
