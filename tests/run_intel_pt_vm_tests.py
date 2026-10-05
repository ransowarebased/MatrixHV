"""Exercise runtime Intel PT commands through a Windows Neo server."""

import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--neo", type=Path, required=True)
    parser.add_argument("--remote", required=True)
    parser.add_argument("--guest-neo", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    output = arguments.output.resolve()
    output.relative_to(Path(__file__).resolve().parents[1] / "builds")
    output.mkdir(parents=True, exist_ok=True)
    records = []

    def remote(*operands, expected=0):
        command = [str(arguments.neo.resolve()), "--remote", arguments.remote,
                   "--timeout", "45", "exec", *operands]
        result = subprocess.run(command, capture_output=True, timeout=55)
        record = {"arguments": list(operands), "exit": result.returncode,
                  "stdout": result.stdout.decode("utf-8", errors="replace"),
                  "stderr": result.stderr.decode("utf-8", errors="replace")}
        records.append(record)
        (output / "commands.json").write_text(json.dumps(records, indent=2))
        if result.returncode != expected:
            raise AssertionError(record)
        return record["stdout"]

    def powershell(script):
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        return remote("powershell.exe", "-NoProfile", "-EncodedCommand", encoded)

    def pt(*operands, expected=0):
        return remote(arguments.guest_neo, "pt", *operands, expected=expected)

    def values(text):
        return dict(re.findall(r"^(cpu\.\d+\.\w+)=(\S+)$", text, re.MULTILINE))

    def inactive(text):
        snapshot = values(text)
        cpus = sorted(key.removesuffix(".state") for key in snapshot if key.endswith(".state"))
        assert cpus, text
        assert all(snapshot[cpu + ".armed"] == "0" for cpu in cpus), text
        return cpus, snapshot

    cpus, initial = inactive(pt("status"))
    assert all(initial[cpu + ".bytes"] == "0" for cpu in cpus), initial
    supported = all(initial[cpu + ".state"] in ("1", "3") for cpu in cpus)
    if supported:
        first = values(pt("start"))
        assert all(first[cpu + ".armed"] == "1" for cpu in cpus), first
        inactive(pt("stop"))
    else:
        pt("start", expected=1)
        after = values(pt("status"))
        assert initial == after, (initial, after)
        inactive(pt("stop"))

    guest_output = rf"C:\MatrixHVIntelPtTests\capture-{time.time_ns()}"
    snapshot = values(pt("dump", "--output", guest_output))
    inactive(pt("status"))
    files = json.loads(powershell(
        "$ErrorActionPreference='Stop'; Get-ChildItem -LiteralPath '" + guest_output +
        "' | Select-Object Name,Length | ConvertTo-Json -Compress"))
    assert {entry["Name"] for entry in files} == {"metadata.txt", *(
        "cpu-" + cpu.split(".")[1] + ".pt" for cpu in cpus)}, files
    for cpu in cpus:
        name = "cpu-" + cpu.split(".")[1] + ".pt"
        length = next(entry["Length"] for entry in files if entry["Name"] == name)
        assert length == int(snapshot[cpu + ".bytes"]), (name, length, snapshot)
    if supported:
        assert any(int(snapshot[cpu + ".bytes"]) > 0 for cpu in cpus), snapshot
    metadata = powershell("Get-Content -Raw -LiteralPath '" + guest_output + "\\metadata.txt'")
    assert "scope=vmx_root_handlers" in metadata and "cpuid_14_0=" in metadata, metadata
    (output / "metadata.txt").write_text(metadata)
    pt("dump", "--output", guest_output, expected=1)
    pt("start", "--output", guest_output, expected=1)
    pt("dump", expected=1)
    pt("start", "--seconds", "1", expected=1)
    for _ in range(10):
        inactive(pt("stop"))
        inactive(pt("status"))
        if not supported:
            pt("start", expected=1)
    matrix = remote(arguments.guest_neo, "matrix", "status")
    assert "failed=0x0" in matrix and "stopped=0x0" in matrix, matrix
    result = {"runtime_commands": "PASS", "cpu_count": len(cpus),
              "capture_hardware_available": supported, "guest_export": guest_output,
              "initial_states": initial, "export_files": files}
    (output / "results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
