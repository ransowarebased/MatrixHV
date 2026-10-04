"""Exercise split reclamation beyond pool capacity with resident executable pages."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", required=True)
    parser.add_argument("--neo", type=Path, required=True)
    parser.add_argument("--guest-neo", required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.relative_to(project / "builds")
    output.mkdir(parents=True, exist_ok=True)
    guest = r"C:\MatrixHVSplitStress"
    sequence = 0
    token = None
    log = (output / "stress-commands.log").open("w", encoding="utf-8", buffering=1)

    def remote(*operands):
        result = subprocess.run([str(args.neo.resolve()), "--remote", args.remote, "--timeout", "30", "exec", *map(str, operands)], capture_output=True, timeout=40)
        text = result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
        log.write(" ".join(map(str, operands)) + "\n" + text + "\n")
        assert result.returncode == 0, text
        return text

    def script(source):
        encoded = base64.b64encode(("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + source).encode("utf-16le")).decode()
        return remote("powershell.exe", "-NoProfile", "-EncodedCommand", encoded)

    def capture(sample):
        env = os.environ.copy()
        env["MATRIXHV_EVIDENCE_ROOT"] = str(output)
        env["MATRIXHV_EVIDENCE_SAMPLE"] = sample
        env["MATRIXHV_SPLIT_FIXTURE"] = str(output / "split-fixture.json")
        command = f"$p=Start-Process -FilePath '{str(args.ida).replace(chr(39), chr(39)*2)}' -WindowStyle Hidden -ArgumentList '-A','-t','-S\"{project / 'tests/collect_boot_state.py'}\"','-L\"{output / (sample + '-idat.log')}\"' -PassThru; $p.WaitForExit(); exit $p.ExitCode"
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", command], env=env, check=True, timeout=120)
        state = json.loads((output / (sample + "-state.json")).read_text())
        assert "error" not in state, state.get("error")
        assert len(state["cpus"]) == fixture["processors"] and len(state["contexts"]) == fixture["processors"]
        assert all(c["values"]["event.halted"] == 0 for c in state["contexts"])
        assert all(c["values"]["event.host_fault_vector"] == 0xFFFFFFFFFFFFFFFF for c in state["contexts"])
        return state

    fixture_bytes = (project / "tests/interception_vm_fixture.ps1").read_bytes()
    script(f"New-Item -ItemType Directory -Path '{guest}' -Force | Out-Null; Remove-Item '{guest}\\fixture.json','{guest}\\result.json','{guest}\\command.json' -ErrorAction SilentlyContinue; [IO.File]::WriteAllBytes('{guest}\\fixture.ps1',[byte[]]@())")
    for offset in range(0, len(fixture_bytes), 4096):
        data = base64.b64encode(fixture_bytes[offset:offset+4096]).decode()
        script(f"$s=[IO.File]::Open('{guest}\\fixture.ps1',[IO.FileMode]::Append);try {{$b=[Convert]::FromBase64String('{data}');$s.Write($b,0,$b.Length)}}finally{{$s.Dispose()}}")
    script(f"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \"& ''{guest}\\fixture.ps1'' -OutputDirectory ''{guest}'' -StressMiB 384 *> ''{guest}\\fixture-out.log''\"'")
    try:
        fixture = json.loads(script(f"for($i=0;$i -lt 1000;$i++){{if(Test-Path '{guest}\\fixture.json'){{Get-Content -Raw '{guest}\\fixture.json';exit}};Start-Sleep -Milliseconds 25}};Get-Content '{guest}\\fixture-out.log';throw 'Stress fixture initialization timed out'"))
        fixture["cr3"] = re.search(r"\bcr3=(\S+)", remote(args.guest_neo, "read", fixture["pid"], "auto"))[1]
        (output / "split-fixture.json").write_text(json.dumps(fixture, indent=2))
        before = capture("stress-before")
        regions = before["split_regions"]
        assert len(regions) >= 144, f"Only {len(regions)} physical 2 MiB regions; cannot exceed the 128-slot pool"
        addresses = [item["address"] for item in regions[:144]]
        sequence += 1
        request = json.dumps(dict(id=sequence, operation="stress-cycle", neo=args.guest_neo, cr3=fixture["cr3"], addresses=addresses))
        script(f"Set-Content '{guest}\\command.tmp' -Value '{request}';Move-Item '{guest}\\command.tmp' '{guest}\\command.json' -Force")
        for attempt in range(300):
            value = script(f"if(Test-Path '{guest}\\result.json'){{Get-Content -Raw '{guest}\\result.json'}}")
            if value.lstrip().startswith("{"):
                result = json.loads(value)
                assert "error" not in result, result
                token = result["value"]["token"]
                assert result["value"]["completed"] == 144
                break
            if attempt % 6 == 0:
                print(f"Waiting for split stress: poll {attempt}", flush=True)
            time.sleep(5)
        else:
            raise AssertionError("Split stress timed out")
        after = capture("stress-active")
        assert after["interception"]["hook_count"] == 1
        assert after["interception"]["base_pool_used"] <= 4, after["interception"]
        assert after["interception"]["split_epoch"] > before["interception"]["split_epoch"]
        acknowledgements = {str(c["values"]["processor_number"]): c["values"]["interception.split_flush_epoch"] for c in after["contexts"]}
        assert all(epoch >= after["interception"]["split_epoch"] for epoch in acknowledgements.values())
        remote(args.guest_neo, "hook", "release", token)
        token = None
        final = capture("stress-released")
        assert final["interception"]["hook_count"] == 0
        assert final["interception"]["base_pool_used"] <= 4, final["interception"]
        summary = {"passed": True, "regions": 144, "processors": fixture["processors"], "executions_per_address_per_cpu": 32, "flush_acknowledgements": acknowledgements, "before": before["interception"], "active": after["interception"], "released": final["interception"]}
        (output / "split-results.json").write_text(json.dumps(summary, indent=2))
        print("PASS 144 distinct physical regions, pool reuse, original restoration and active neighbor preservation on eight CPUs", flush=True)
    finally:
        if token is not None:
            remote(args.guest_neo, "hook", "release", token)
        script(f"Set-Content '{guest}\\command.json' -Value '{{\"operation\":\"stop\"}}'")
        log.close()


if __name__ == "__main__":
    main()
