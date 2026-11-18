"""Check optimized resident stack budgets without executing VMX or CPUID transport."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def compiled_functions(text):
    """Read LLVM's x86-64 AT&T assembly, including probed Windows frames."""
    chunks = re.split(r"(?m)^([A-Za-z_][A-Za-z0-9_.$]*):\s*$", text)
    bodies = {chunks[index]: chunks[index + 1] for index in range(1, len(chunks) - 1, 2)}
    frames = {}
    edges = {}
    for name, body in bodies.items():
        sizes = re.findall(r"subq\s+\$(\d+), %rsp", body)
        sizes += re.findall(r"movl\s+\$(\d+), %eax\s*\n\s*callq\s+[^\n]*probestack", body)
        prefix = body.split("subq", 1)[0]
        pushes = len(re.findall(r"(?m)^\s*pushq\s+", prefix))
        if re.search(r"subq\s+%\w+, %rsp", body) and "probestack" not in body:
            raise ValueError(f"Unmodeled dynamic stack allocation: {name}")
        frames[name] = max(map(int, sizes), default=0) + pushes * 8 + 8
        # Counting tail calls as nested calls is conservative for this check.
        edges[name] = [callee for callee in re.findall(
            r"(?m)^\s*(?:callq|jmp)\s+([A-Za-z_][A-Za-z0-9_.$]*)\s*$", body
        ) if callee in bodies and "probestack" not in callee]
    return frames, edges


def longest_path(root, frames, edges, targets=None):
    paths = []

    def visit(name, path):
        if name in path:
            return
        path = path + [name]
        if targets is None or name in targets:
            paths.append(path)
        for callee in edges[name]:
            visit(callee, path)

    visit(root, [])
    if not paths:
        raise ValueError("No compiled call path from memory entry to CPU-view builder")
    return max(paths, key=lambda items: sum(frames[name] for name in items))


def check(assembly, source):
    text = assembly.read_text(encoding="utf-8")
    frames, edges = compiled_functions(text)
    roots = [name for name in frames if "access8resident12memory_entry" in name]
    runtime = [name for name in frames if "runtime18interception_entry" in name and name.startswith("_RNv")]
    targets = {name for name in frames if "interception9cpu_views" in name}
    refresh = {name for name in frames if "interception12refresh_page" in name}
    if len(roots) != 1 or len(runtime) != 1 or not targets or not refresh:
        raise ValueError("Compiled memory/runtime entries, CPU-view builder and page refresh must be present")
    paths = {
        "hook_installation": longest_path(roots[0], frames, edges, targets),
        "memory_service": longest_path(roots[0], frames, edges),
        "interception_runtime": longest_path(runtime[0], frames, edges),
    }
    path = max(paths.values(), key=lambda items: sum(frames[name] for name in items))
    vcpu = source.read_text(encoding="utf-8")
    pages = int(re.search(r"const HOST_STACK_PAGES: usize = (\d+);", vcpu)[1])
    if "const HOST_EXIT_STACK_PAGES: usize = HOST_STACK_PAGES;" not in vcpu:
        raise ValueError("Host exit and resident stack capacities must share the checked budget")
    # The assembly dispatcher, EFI bridge, NMI entry and leaf helpers also use
    # this stack. Direct Rust frames alone are a lower bound, not a full proof.
    reserve = 8192
    used = sum(frames[name] for name in path)
    return {"status": "PASS" if used + reserve <= pages * 4096 else "FAIL",
            "assembly": str(assembly.resolve()), "assembly_sha256": hashlib.sha256(assembly.read_bytes()).hexdigest(),
            "stack_bytes": pages * 4096, "direct_path_bytes": used,
            "entry_and_interrupt_reserve": reserve,
            "path": [{"symbol": name, "frame_bytes": frames[name]} for name in path],
            "paths": {kind: {"bytes": sum(frames[name] for name in items),
                             "frames": [{"symbol": name, "frame_bytes": frames[name]} for name in items]}
                      for kind, items in paths.items()},
            "scope": "Compiled direct-call frame estimate for memory and interception entries; indirect calls, recursion, dynamic control flow and assembly entry/NMI liveness require separate review"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    project = Path(__file__).resolve().parents[1]
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--assembly", type=Path)
    mode.add_argument("--build", action="store_true", help="Compile release assembly only; never load the EFI")
    parser.add_argument("--output", type=Path, default=project / "builds/resident-stack/report.json")
    args = parser.parse_args()
    if args.build:
        target = project / "builds/resident-stack/target"
        target.parent.mkdir(parents=True, exist_ok=True)
        args.assembly = target.parent / "MatrixHV.s"
        subprocess.run(["cargo", "rustc", "--locked", "--release", "--target", "x86_64-unknown-uefi",
                        "--target-dir", str(target), "--bin", "MatrixHV", "--", "-Dwarnings",
                        f"--emit=asm={args.assembly},link"],
                       cwd=project, check=True)
    result = check(args.assembly, project / "src/vmx/vcpu.rs")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"{result['status']}: direct_path={result['direct_path_bytes']} reserve={result['entry_and_interrupt_reserve']} capacity={result['stack_bytes']}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
