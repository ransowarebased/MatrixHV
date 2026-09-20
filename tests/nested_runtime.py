"""Validate resident nested observations collected from the running guest."""

import argparse
import hashlib
import json
from pathlib import Path


def records(path):
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        item = {key: int(value, 16) for key, value in json.loads(line).items()}
        cpu = item["cpu"]
        if cpu in result:
            raise ValueError(f"Duplicate resident context for CPU {cpu}")
        result[cpu] = item
    return result


def validate(start, end, cpu_count):
    checks = {"cpu_set": set(start) == set(end) == set(range(cpu_count))}
    for cpu in sorted(end):
        current = end[cpu]
        previous = start.get(cpu, {})
        prefix = f"cpu{cpu}_"
        for field in ("exits", "post_ebs", "post_va"):
            checks[prefix + field + "_advances"] = current[field] > previous.get(field, current[field])
        expected = {
            "stop": 0,
            "canary_start": 0x4856424F4F544331,
            "canary_end": 0x4856424F4F544332,
            "cpuid_presence": 0,
            "cpuid_hypervisor_eax": 0,
            "nested_expose_vmx": 0,
            "nested_active": 0,
            "nested_vmxon_count": 2,
            "nested_vmxoff_count": 1,
            "nested_failure_count": 5,
            "nested_probe_complete": 1,
            "nested_current_vmcs": (1 << 64) - 1,
            "nested_vmcs12_launch_state": 0,
            "nested_vmcs12_guest_rip": 0x1122334455667788,
            "nested_vmclear_count": 2,
            "nested_vmptrld_count": 1,
            "nested_vmptrst_count": 1,
            "nested_vmwrite_count": 1,
            "nested_vmread_count": 4,
            "nested_vmcs12_probe_complete": 1,
            "nested_vmlaunch_count": 2,
            "nested_vmresume_count": 2,
            "nested_entry_rejection_count": 4,
        }
        if cpu == 0:
            expected.update(ept_test_seen=1, checkpoint=1)
        else:
            expected.update(started=1, init=1, sipi=1)
        for field, value in expected.items():
            checks[prefix + field] = current[field] == value
        checks[prefix + "host_cr3"] = current["host_cr3"] == current["last_host_cr3"] != current["guest_cr3"]
        checks[prefix + "cpuid_bits"] = current["cpuid_leaf1_count"] > 0 and current["cpuid_leaf1_ecx"] & ((1 << 31) | (1 << 5)) == 0
        checks[prefix + "hypervisor_queries"] = current["cpuid_hypervisor_count"] >= 4
        checks[prefix + "vmcs_pointer"] = current["nested_last_stored_pointer"] == current["nested_vmcs12_region"]
    for field in ("address", "nested_vmxon_region", "nested_vmcs12_region", "nested_vmcs12_operand"):
        checks[field + "_distinct"] = len({item[field] for item in end.values()}) == cpu_count
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("start", type=Path)
    parser.add_argument("end", type=Path)
    parser.add_argument("--cpus", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checks = validate(records(args.start), records(args.end), args.cpus)
    checks["sampling_interval"] = args.end.stat().st_mtime - args.start.stat().st_mtime >= 30
    failed = [name for name, passed in checks.items() if not passed]
    report = {
        "scope": "Controlled pre-EBS VMXON/VMXOFF, VMCS12 access and rejected entries; post-EBS residency. No L2 execution.",
        "inputs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (args.start, args.end)},
        "checks": checks,
        "failed_checks": failed,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"checks": len(checks), "failed_checks": failed}))
    raise SystemExit(bool(failed))


if __name__ == "__main__":
    main()
