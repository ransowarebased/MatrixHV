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
            "nested_vmcs12_launch_state": 1,
            "nested_vmclear_count": 2,
            "nested_vmptrld_count": 2,
            "nested_vmptrst_count": 1,
            "nested_vmwrite_count": 16,
            "nested_vmread_count": 19,
            "nested_vmcs12_probe_complete": 1,
            "nested_vmlaunch_count": 3,
            "nested_vmresume_count": 3,
            "nested_entry_rejection_count": 4,
            "nested_vmcs12_control_validation_count": 2,
            "nested_l2_active": 0,
            "nested_l2_entry_count": 2,
            "nested_l2_exit_count": 2,
            "nested_l1_reflection_count": 2,
            "nested_l2_resume_count": 1,
            "nested_l2_resume_exit_count": 1,
            "nested_ept_composition_count": 1,
            "nested_ept_probe_count": 1,
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
        checks[prefix + "control_pinbased"] = current["nested_vmcs12_pin_based_control"] == 0
        checks[prefix + "control_primary"] = current["nested_vmcs12_primary_control"] == 1 << 31
        checks[prefix + "control_secondary"] = current["nested_vmcs12_secondary_control"] == 1 << 1
        checks[prefix + "control_exit"] = current["nested_vmcs12_vm_exit_controls"] == 1 << 9
        checks[prefix + "control_entry"] = current["nested_vmcs12_vm_entry_controls"] == 1 << 9
        control_capability = (1 << 9) | ((1 << 9) << 32)
        checks[prefix + "vmx_pinbased_cap"] = current["nested_vmx_pinbased_ctls"] == 0
        primary_capability = (1 << 31) << 32
        secondary_capability = (1 << 1) << 32
        checks[prefix + "vmx_procbased_cap"] = current["nested_vmx_procbased_ctls"] == primary_capability
        checks[prefix + "vmx_secondary_cap"] = current["nested_vmx_procbased_ctls2"] == secondary_capability
        checks[prefix + "vmx_exit_cap"] = current["nested_vmx_exit_ctls"] == control_capability
        checks[prefix + "vmx_entry_cap"] = current["nested_vmx_entry_ctls"] == control_capability
        checks[prefix + "vmx_misc_cap"] = current["nested_vmx_misc"] == 0
        checks[prefix + "vmx_ept_cap"] = current["nested_vmx_ept_vpid_cap"] & 0x4040 == 0x4040 and current["nested_vmx_ept_vpid_cap"] & ~0x14040 == 0
        checks[prefix + "vmx_vmcs_enum"] = 0 < (current["nested_vmx_vmcs_enum"] >> 1) <= 22
        has_true_controls = bool(current["nested_vmx_basic"] & (1 << 55))
        checks[prefix + "vmx_true_pinbased_cap"] = current["nested_vmx_true_pinbased_ctls"] == 0
        checks[prefix + "vmx_true_procbased_cap"] = current["nested_vmx_true_procbased_ctls"] == (primary_capability if has_true_controls else 0)
        checks[prefix + "vmx_true_exit_cap"] = current["nested_vmx_true_exit_ctls"] == (control_capability if has_true_controls else 0)
        checks[prefix + "vmx_true_entry_cap"] = current["nested_vmx_true_entry_ctls"] == (control_capability if has_true_controls else 0)
        checks[prefix + "extended_exception_bitmap"] = current["nested_vmcs12_exception_bitmap"] == 0x40
        checks[prefix + "extended_guest_cr3"] = current["nested_vmcs12_guest_cr3_field"] == current["initial_cr3"]
        checks[prefix + "extended_host_cr3"] = current["nested_vmcs12_host_cr3_field"] == current["initial_cr3"]
        checks[prefix + "ept_pointer"] = current["nested_vmcs12_ept_pointer"] == current["nested_ept12_pointer"] != 0
        checks[prefix + "ept02_private"] = current["nested_ept02_pointer"] != 0 and current["nested_ept02_pointer"] != current["nested_ept12_pointer"]
        checks[prefix + "ept_non_identity"] = current["nested_ept_source_gpa"] != current["nested_ept_target_gpa"] and current["nested_ept_composed_hpa"] == current["nested_ept_target_gpa"]
        checks[prefix + "ept_permissions"] = current["nested_ept_permissions"] == 0x7
        checks[prefix + "ept_observed_value"] = current["nested_ept_observed_value"] == 0x4E45505454475431
        checks[prefix + "l2_exit_reason"] = current["nested_l2_last_exit_reason"] & 0xffff == 18
        checks[prefix + "vmcs12_exit_reason"] = current["nested_vmcs12_exit_reason"] & 0xffff == 18
        checks[prefix + "l2_exit_length"] = current["nested_vmcs12_exit_instruction_len"] == 3
        checks[prefix + "l2_exit_rip"] = current["nested_l2_last_exit_rip"] != 0 and current["nested_l2_last_exit_rip"] == current["nested_vmcs12_guest_rip"]
        checks[prefix + "l2_exit_rsp"] = current["nested_l2_last_exit_rsp"] != 0 and current["nested_l2_last_exit_rsp"] == current["nested_vmcs12_guest_rsp"]
        checks[prefix + "l1_host_state"] = current["nested_vmcs12_host_rip"] != 0 and current["nested_vmcs12_host_rsp"] != 0
        checks[prefix + "vmcs02_private"] = current["nested_vmcs01_region"] != current["nested_vmcs02_region"]
    for field in (
        "address",
        "nested_vmxon_region",
        "nested_vmcs12_region",
        "nested_vmcs12_operand",
        "nested_vmcs01_region",
        "nested_vmcs02_region",
        "nested_ept12_pointer",
        "nested_ept02_pointer",
        "nested_ept_source_gpa",
        "nested_ept_target_gpa",
    ):
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
        "scope": "Controlled pre-EBS VMXON/VMXOFF, expanded VMCS12 state, host-derived VMX controls, immutable non-identity EPT12+EPT01 to EPT02 composition, real L2 VMLAUNCH plus VMRESUME, and two reflected VMCALL exits per CPU; post-EBS residency. Virtual INVEPT/INVVPID remain unadvertised.",
        "inputs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (args.start, args.end)},
        "checks": checks,
        "failed_checks": failed,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"checks": len(checks), "failed_checks": failed}))
    raise SystemExit(bool(failed))


if __name__ == "__main__":
    main()
