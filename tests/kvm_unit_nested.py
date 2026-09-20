"""Build and validate the upstream kvm-unit-tests VMX compatibility suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


UPSTREAM_URL = "https://gitlab.com/kvm-unit-tests/kvm-unit-tests.git"
UPSTREAM_REVISION = "5a221342a025948fa7d84f0c404748f6ba57f3ad"
DEFAULT_CASES = (
    "test_vmx_feature_control",
    "test_vmxon",
    "test_vmptrld",
    "test_vmclear",
    "test_vmptrst",
    "test_vmwrite_vmread",
    "test_vmx_caps",
)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SUMMARY_PATTERN = re.compile(
    r"SUMMARY:\s*(?P<tests>\d+)\s+tests"
    r"(?:,\s*(?P<failures>\d+)\s+unexpected failures)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TestSummary:
    tests: int
    unexpected_failures: int


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_external_root() -> Path:
    return project_root() / "builds" / "kvm-unit-tests"


def run_checked(arguments: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def command_output(arguments: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout.strip()


def ensure_source(source_dir: Path) -> None:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git was not found in PATH")

    if not source_dir.exists():
        source_dir.parent.mkdir(parents=True, exist_ok=True)
        run_checked([git, "clone", "--no-checkout", UPSTREAM_URL, str(source_dir)])
    if not (source_dir / ".git").is_dir():
        raise RuntimeError(f"managed source path is not a Git checkout: {source_dir}")

    status = command_output([git, "status", "--porcelain"], cwd=source_dir)
    if status:
        raise RuntimeError(f"managed kvm-unit-tests checkout has local changes: {source_dir}")

    try:
        command_output([git, "cat-file", "-e", f"{UPSTREAM_REVISION}^{{commit}}"], cwd=source_dir)
    except subprocess.CalledProcessError:
        run_checked([git, "fetch", "--depth=1", "origin", UPSTREAM_REVISION], cwd=source_dir)

    run_checked([git, "checkout", "--detach", UPSTREAM_REVISION], cwd=source_dir)
    actual_revision = command_output([git, "rev-parse", "HEAD"], cwd=source_dir)
    if actual_revision != UPSTREAM_REVISION:
        raise RuntimeError(
            f"unexpected kvm-unit-tests revision: {actual_revision}; expected {UPSTREAM_REVISION}"
        )


def msys_path(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    if not drive:
        raise RuntimeError(f"Windows path does not have a drive letter: {resolved}")
    suffix = resolved.as_posix()[2:].lstrip("/")
    return f"/{drive}/{suffix}"


def windows_build_tools() -> tuple[Path, Path]:
    bash = Path(r"C:\msys64\usr\bin\bash.exe")
    toolchain = Path(r"D:\Programacao\x86_64-elf-tools-windows\bin")
    if not bash.is_file():
        raise RuntimeError(f"MSYS2 bash was not found: {bash}")
    if not (toolchain / "x86_64-elf-gcc.exe").is_file():
        raise RuntimeError(f"x86_64 cross compiler was not found: {toolchain}")
    return bash, toolchain


def build_payload(source_dir: Path, build_dir: Path, jobs: int) -> Path:
    build_dir.mkdir(parents=True, exist_ok=True)
    build_script = (
        'set -eu; source_dir="$1"; build_dir="$2"; jobs="$3"; '
        'cross_prefix="$4"; command -v make >/dev/null; '
        'command -v "${cross_prefix}gcc" >/dev/null; '
        'command -v "${cross_prefix}objcopy" >/dev/null; cd "$build_dir"; '
        'sh "$source_dir/configure" --arch=x86_64 --cross-prefix="$cross_prefix"; '
        'make -j "$jobs" x86/vmx.flat'
    )

    if os.name == "nt":
        bash, toolchain = windows_build_tools()
        source_argument = msys_path(source_dir)
        build_argument = msys_path(build_dir)
        toolchain_argument = msys_path(toolchain)
        run_checked(
            [
                str(bash),
                "-lc",
                build_script,
                "matrixhv-kvm-unit-tests",
                source_argument,
                build_argument,
                str(jobs),
                f"{toolchain_argument}/x86_64-elf-",
            ]
        )
    else:
        run_checked(
            [
                "sh",
                "-lc",
                build_script,
                "matrixhv-kvm-unit-tests",
                str(source_dir.resolve()),
                str(build_dir.resolve()),
                str(jobs),
                "",
            ]
        )

    payload = build_dir / "x86" / "vmx.flat"
    if not payload.is_file() or payload.stat().st_size == 0:
        raise RuntimeError(f"kvm-unit-tests did not produce a VMX payload: {payload}")
    return payload


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(path: Path, payload: Path, cases: tuple[str, ...]) -> None:
    manifest = {
        "upstream": UPSTREAM_URL,
        "revision": UPSTREAM_REVISION,
        "payload": str(payload.resolve()),
        "payload_sha256": file_sha256(payload),
        "cases": list(cases),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def parse_summary(output: str) -> TestSummary:
    clean_output = ANSI_ESCAPE.sub("", output)
    lowered = clean_output.lower()
    if "vmx not supported" in lowered:
        raise ValueError("kvm-unit-tests reported that VMX is not exposed to the L1 guest")
    if re.search(r"(^|\n)\s*(fail:|abort:)", clean_output, re.IGNORECASE):
        raise ValueError("kvm-unit-tests output contains a failure or abort record")

    matches = list(SUMMARY_PATTERN.finditer(clean_output))
    if not matches:
        raise ValueError("kvm-unit-tests did not emit a SUMMARY record")
    match = matches[-1]
    summary = TestSummary(
        tests=int(match.group("tests")),
        unexpected_failures=int(match.group("failures") or 0),
    )
    if summary.tests == 0:
        raise ValueError("kvm-unit-tests reported zero executed tests")
    if summary.unexpected_failures != 0:
        raise ValueError(
            f"kvm-unit-tests reported {summary.unexpected_failures} unexpected failures"
        )
    return summary


def validate_log(log_path: Path) -> TestSummary:
    if not log_path.is_file():
        raise RuntimeError(f"runner did not produce the requested serial log: {log_path}")
    return parse_summary(log_path.read_text(encoding="utf-8", errors="replace"))


def selected_cases(arguments: argparse.Namespace) -> tuple[str, ...]:
    return tuple(arguments.cases) if arguments.cases else DEFAULT_CASES


def prepare(arguments: argparse.Namespace) -> tuple[Path, tuple[str, ...]]:
    external_root = arguments.external_root.resolve()
    source_dir = external_root / "src"
    build_dir = external_root / "build-flat-x86_64-elf"
    cases = selected_cases(arguments)
    ensure_source(source_dir)
    payload = build_payload(source_dir, build_dir, arguments.jobs)
    write_manifest(external_root / "manifest.json", payload, cases)
    return payload, cases


def build_command(arguments: argparse.Namespace) -> int:
    payload, cases = prepare(arguments)
    print(json.dumps({"payload": str(payload.resolve()), "cases": cases}, indent=2))
    return 0


def run_command(arguments: argparse.Namespace) -> int:
    payload, cases = prepare(arguments)
    log_path = arguments.log.resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    runner_arguments = [
        str(arguments.runner.resolve()),
        *arguments.runner_argument,
        "--payload",
        str(payload.resolve()),
        "--log",
        str(log_path),
        "--",
        *cases,
    ]
    run_checked(runner_arguments, cwd=project_root())
    summary = validate_log(log_path)
    print(json.dumps(asdict(summary)))
    return 0


def verify_log_command(arguments: argparse.Namespace) -> int:
    summary = validate_log(arguments.log.resolve())
    print(json.dumps(asdict(summary)))
    return 0


def add_build_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--external-root",
        type=Path,
        default=default_external_root(),
        help="checkout and build root; must remain below builds/",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, os.cpu_count() or 1),
        help="parallel make job count",
    )
    parser.add_argument(
        "--case",
        dest="cases",
        action="append",
        help="VMX test filter passed to vmx.flat; repeat to select multiple cases",
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="fetch and build x86/vmx.flat")
    add_build_arguments(build_parser)
    build_parser.set_defaults(handler=build_command)

    run_parser = subparsers.add_parser(
        "run",
        help="build and pass vmx.flat to a MatrixHV multiboot runner",
    )
    add_build_arguments(run_parser)
    run_parser.add_argument(
        "--runner",
        type=Path,
        required=True,
        help="adapter invoked with --payload, --log, --, and the VMX case filters",
    )
    run_parser.add_argument(
        "--runner-argument",
        action="append",
        default=[],
        help="argument inserted before the runner protocol arguments; may be repeated",
    )
    run_parser.add_argument(
        "--log",
        type=Path,
        default=default_external_root() / "serial.log",
        help="serial log produced by the runner",
    )
    run_parser.set_defaults(handler=run_command)

    verify_parser = subparsers.add_parser(
        "verify-log",
        help="validate a serial log captured from vmx.flat running over MatrixHV",
    )
    verify_parser.add_argument("log", type=Path)
    verify_parser.set_defaults(handler=verify_log_command)
    return parser


def main() -> int:
    parser = create_parser()
    arguments = parser.parse_args()
    if hasattr(arguments, "jobs") and arguments.jobs < 1:
        parser.error("--jobs must be greater than zero")
    if hasattr(arguments, "external_root"):
        build_root = (project_root() / "builds").resolve()
        external_root = arguments.external_root.resolve()
        if build_root not in external_root.parents:
            parser.error("--external-root must be a child of the repository builds directory")

    try:
        return arguments.handler(arguments)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
