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
    "test_vmcs_high",
    "test_vmcs_lifecycle",
    "test_vmx_caps",
    "vmenter",
    "vmx_controls_test",
    "vmx_host_state_area_test",
    "vmx_guest_state_area_test",
    "CR_shadowing",
    "I/O_bitmap",
    "MSR_switch",
    "interrupt",
    "nmi_hlt",
    "ept_access_test_read_write_execute",
)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SUMMARY_PATTERN = re.compile(
    r"SUMMARY:\s*(?P<tests>\d+)\s+tests"
    r"(?:,\s*(?P<skipped>\d+)\s+skipped)?"
    r"(?:,\s*(?P<failures>\d+)\s+unexpected failures)?",
    re.IGNORECASE,
)
SKIP_PATTERN = re.compile(r"^\s*SKIP:\s*(?P<reason>.+?)\s*$", re.MULTILINE)
EXPECTED_SKIP_MARKERS = {
    "pml": "test_pml",
    "mbec": "MBEC not supported",
    "preemption_timer": "test_vmx_preemption_timer",
    "host_efer": "test_efer",
    "host_pat": "test_load_host_pat",
    "host_perf_global_ctrl": "test_load_host_perf_global_ctrl",
    "guest_pat": "test_load_guest_pat",
    "guest_efer": "test_guest_efer",
    "guest_perf_global_ctrl": "test_load_guest_perf_global_ctrl",
    "guest_bndcfgs": "test_load_guest_bndcfgs",
}
REQUIRED_NMI_HLT_PASSES = (
    "PASS: direct NMI + hlt",
    "PASS: NMI intercept while running guest",
    "PASS: intercepted NMI + hlt",
)
REQUIRED_EPT_PASSES = ("Test suite: ept_access_test_read_write_execute",)


@dataclass(frozen=True)
class TestSummary:
    tests: int
    skipped: int
    unexpected_failures: int


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_external_root() -> Path:
    return project_root() / "builds" / "kvm-unit-tests"


def efi_patch_path() -> Path:
    return project_root() / "tests" / "kvm_unit_efi.patch"


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


def windows_build_tools() -> tuple[Path, Path, Path]:
    bash = Path(r"C:\msys64\usr\bin\bash.exe")
    toolchain = Path(r"D:\Programacao\x86_64-elf-tools-windows\bin")
    objcopy = Path(r"C:\msys64\usr\bin\objcopy.exe")
    if not bash.is_file():
        raise RuntimeError(f"MSYS2 bash was not found: {bash}")
    if not (toolchain / "x86_64-elf-gcc.exe").is_file():
        raise RuntimeError(f"x86_64 cross compiler was not found: {toolchain}")
    if not objcopy.is_file():
        raise RuntimeError(f"MSYS2 objcopy was not found: {objcopy}")
    return bash, toolchain, objcopy


def remove_managed_directory(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        path.unlink()
    else:
        shutil.rmtree(path)


def prepare_efi_source(source_dir: Path, efi_source_dir: Path) -> None:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git was not found in PATH")
    patch_path = efi_patch_path()
    if not patch_path.is_file():
        raise RuntimeError(f"kvm-unit-tests EFI patch was not found: {patch_path}")

    remove_managed_directory(efi_source_dir)
    run_checked(
        [
            git,
            "-c",
            "core.autocrlf=false",
            "clone",
            "--quiet",
            "--shared",
            "--no-checkout",
            str(source_dir),
            str(efi_source_dir),
        ]
    )
    run_checked(
        [git, "-c", "core.autocrlf=false", "checkout", "--quiet", "--detach", UPSTREAM_REVISION],
        cwd=efi_source_dir,
    )
    run_checked(
        [git, "-c", "core.autocrlf=false", "apply", "--whitespace=error-all", str(patch_path)],
        cwd=efi_source_dir,
    )


def package_windows_efi(build_dir: Path, toolchain: Path, objcopy: Path) -> Path:
    binary_dir = build_dir / "x86"
    shared_object = binary_dir / "vmx.so"
    payload = binary_dir / "vmx.efi"
    cross_objcopy = toolchain / "x86_64-elf-objcopy.exe"
    if not shared_object.is_file():
        raise RuntimeError(f"kvm-unit-tests did not produce a VMX shared object: {shared_object}")

    run_checked([str(cross_objcopy), "--only-keep-debug", "vmx.so", "vmx.efi.debug"], cwd=binary_dir)
    run_checked([str(cross_objcopy), "--strip-debug", "vmx.so"], cwd=binary_dir)
    run_checked(
        [str(cross_objcopy), "--add-gnu-debuglink=vmx.efi.debug", "vmx.so"], cwd=binary_dir
    )
    sections = (
        ".text",
        ".sdata",
        ".data",
        ".dynamic",
        ".dynsym",
        ".dynstr",
        ".rel",
        ".rela",
        ".reloc",
    )
    arguments = [str(objcopy), "-I", "elf64-x86-64", "-O", "efi-app-x86_64"]
    for section in sections:
        arguments.extend(("-j", section))
    arguments.extend(("-S", str(shared_object), str(payload)))
    run_checked(arguments)
    return payload


def build_payload(source_dir: Path, build_dir: Path, jobs: int) -> Path:
    remove_managed_directory(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    build_script = (
        'set -eu; source_dir="$1"; build_dir="$2"; jobs="$3"; '
        'cross_prefix="$4"; command -v make >/dev/null; '
        'command -v "${cross_prefix}gcc" >/dev/null; '
        'cd "$build_dir"; '
        'sh "$source_dir/configure" --arch=x86_64 --enable-efi '
        '--cross-prefix="$cross_prefix"; make -j "$jobs" x86/vmx.so'
    )

    if os.name == "nt":
        bash, toolchain, objcopy = windows_build_tools()
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
        payload = package_windows_efi(build_dir, toolchain, objcopy)
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
        run_checked(["make", "-j", str(jobs), "x86/vmx.efi"], cwd=build_dir)
        payload = build_dir / "x86" / "vmx.efi"

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
        "efi_patch": str(efi_patch_path().resolve()),
        "efi_patch_sha256": file_sha256(efi_patch_path()),
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
        skipped=int(match.group("skipped") or 0),
        unexpected_failures=int(match.group("failures") or 0),
    )
    if summary.tests == 0:
        raise ValueError("kvm-unit-tests reported zero executed tests")
    if summary.unexpected_failures != 0:
        raise ValueError(
            f"kvm-unit-tests reported {summary.unexpected_failures} unexpected failures"
        )

    missing_nmi_passes = [record for record in REQUIRED_NMI_HLT_PASSES if record not in clean_output]
    if missing_nmi_passes:
        raise ValueError(f"nmi_hlt did not complete required checks: {missing_nmi_passes}")

    missing_ept_passes = [record for record in REQUIRED_EPT_PASSES if record not in clean_output]
    if missing_ept_passes:
        raise ValueError(f"EPT tests did not complete required checks: {missing_ept_passes}")

    skip_records = [match.group("reason") for match in SKIP_PATTERN.finditer(clean_output)]
    if summary.skipped != len(skip_records):
        raise ValueError(
            f"summary reports {summary.skipped} skips but {len(skip_records)} SKIP records were found"
        )
    matched_skips = {
        name
        for name, marker in EXPECTED_SKIP_MARKERS.items()
        if any(marker in record for record in skip_records)
    }
    unexpected_skips = [
        record
        for record in skip_records
        if not any(marker in record for marker in EXPECTED_SKIP_MARKERS.values())
    ]
    if unexpected_skips:
        raise ValueError(f"kvm-unit-tests reported unexpected skips: {unexpected_skips}")
    missing_skips = sorted(set(EXPECTED_SKIP_MARKERS) - matched_skips)
    if missing_skips:
        raise ValueError(f"kvm-unit-tests did not report the expected out-of-scope skips: {missing_skips}")
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
    efi_source_dir = external_root / "src-efi"
    build_dir = external_root / "build-efi-x86_64-elf"
    cases = selected_cases(arguments)
    ensure_source(source_dir)
    prepare_efi_source(source_dir, efi_source_dir)
    payload = build_payload(efi_source_dir, build_dir, arguments.jobs)
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

    build_parser = subparsers.add_parser("build", help="fetch and build x86/vmx.efi")
    add_build_arguments(build_parser)
    build_parser.set_defaults(handler=build_command)

    run_parser = subparsers.add_parser(
        "run",
        help="build and pass vmx.efi to a MatrixHV UEFI runner",
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
        help="validate a serial log captured from vmx.efi running over MatrixHV",
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
