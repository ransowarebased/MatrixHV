"""Validate exported hardware PT packets with Intel's libipt packet decoder."""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decoder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("captures", type=Path, nargs="+")
    arguments = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = arguments.output.resolve()
    output.relative_to(project / "builds")
    output.mkdir(parents=True, exist_ok=True)
    records = []
    generations = {}
    for directory in arguments.captures:
        directory = directory.resolve()
        directory.relative_to(project / "builds")
        metadata = dict(line.split("=", 1) for line in
                        (directory / "metadata.txt").read_text().splitlines() if "=" in line)
        assert metadata["scope"] == "vmx_root_handlers", metadata
        cpus = sorted(int(match[1]) for key in metadata
                      if (match := re.fullmatch(r"cpu\.(\d+)\.state", key)))
        assert cpus, directory
        assert {path.name for path in directory.glob("*.pt")} == {
            f"cpu-{cpu}.pt" for cpu in cpus}, directory
        for cpu in cpus:
            prefix = f"cpu.{cpu}."
            assert metadata[prefix + "state"] == "1", (directory, cpu, metadata)
            assert metadata[prefix + "armed"] == "0", (directory, cpu, metadata)
            status = int(metadata[prefix + "rtit_status"], 0)
            assert status & (1 << 4) == 0, (directory, cpu, status)
            generation = int(metadata[prefix + "generation"])
            if cpu in generations:
                assert generation == generations[cpu] + 1, (directory, cpu, generation)
            generations[cpu] = generation
            trace = directory / f"cpu-{cpu}.pt"
            data = trace.read_bytes()
            assert len(data) == int(metadata[prefix + "bytes"]) and 0 < len(data) <= 65536
            assert data.startswith(bytes([0x02, 0x82]) * 8), (directory, cpu)
            signature = int(metadata[prefix + "cpuid_1_eax"], 0)
            family = (signature >> 8) & 15
            if family == 15:
                family += (signature >> 20) & 255
            model = (signature >> 4) & 15
            if family in (6, 15):
                model |= (signature >> 12) & 0xf0
            stepping = signature & 15
            decoded = subprocess.run([str(arguments.decoder.resolve()), "--lastip",
                "--cpu", f"{family}/{model}/{stepping}", str(trace)],
                capture_output=True, text=True, timeout=30)
            listing = output / f"{directory.name}-cpu-{cpu}.txt"
            listing.write_text(decoded.stdout + decoded.stderr)
            assert decoded.returncode == 0, (listing, decoded.stderr)
            assert "error" not in (decoded.stdout + decoded.stderr).lower(), listing
            packets = collections.Counter(re.findall(
                r"^[0-9a-f]{16}\s+([a-z0-9.]+)", decoded.stdout, re.MULTILINE))
            assert packets["psb"] and packets["tip.pge"] and packets["tnt.8"], (listing, packets)
            addresses = [int(address, 16) for address in re.findall(
                r"\bip\s+([0-9a-f]{16})", decoded.stdout)]
            base = int(metadata[prefix + "code_base"], 0)
            length = int(metadata[prefix + "code_bytes"])
            assert addresses and all(base <= address < base + length for address in addresses), listing
            records.append({"capture": directory.name, "cpu": cpu, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "generation": generation,
                "status": status, "stopped_at_capacity": bool(status & (1 << 5)),
                "packet_counts": dict(packets), "instruction_pointer_packets": len(addresses),
                "root_code_base": base, "root_code_bytes": length, "decoder_exit": 0})
    result = {"result": "PASS", "captures": len(arguments.captures),
              "files": len(records), "total_bytes": sum(record["bytes"] for record in records),
              "records": records}
    (output / "results.json").write_text(json.dumps(result, indent=2))
    print(f"PASS {len(records)} hardware captures, {result['total_bytes']} bytes; "
          "all decoded IPs stay inside the resident VMX root image")


if __name__ == "__main__":
    main()
