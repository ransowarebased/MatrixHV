"""Measure the MSR mix of observed L2 WRMSR exits using capability-gated telemetry."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import time


def invoke(neo, *arguments):
    result = subprocess.run([str(neo), *arguments], check=True, capture_output=True,
                            text=True, encoding="utf-8", timeout=60)
    return result.stdout


def fields(text):
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def measure(neo, seconds, output):
    output.mkdir(parents=True, exist_ok=True)
    initial_text = invoke(neo, "telemetry")
    (output / "initial.txt").write_text(initial_text, encoding="utf-8")
    initial = fields(initial_text)
    cpus = sorted({match[1] for key in initial if
                   (match := re.fullmatch(r"cpu\.(\d+)\.telemetry_enabled", key))}, key=int)
    if not cpus or any(int(initial[f"cpu.{cpu}.capabilities"], 0) & (1 << 23) == 0
                       for cpu in cpus):
        raise ValueError("L2 WRMSR profiling is unavailable; boot the updated MatrixHV EFI first")
    states = {initial[f"cpu.{cpu}.telemetry_enabled"] for cpu in cpus}
    if len(states) != 1:
        raise ValueError("Mixed per-CPU collection settings; refusing to change them")
    was_enabled = states == {"1"}
    changed = False
    try:
        if not was_enabled:
            changed = True
            invoke(neo, "telemetry", "enable")
        before_text = invoke(neo, "telemetry")
        (output / "before.txt").write_text(before_text, encoding="utf-8")
        started = time.monotonic()
        time.sleep(seconds)
        after_text = invoke(neo, "telemetry")
        elapsed = time.monotonic() - started
        (output / "after.txt").write_text(after_text, encoding="utf-8")
    finally:
        if changed:
            invoke(neo, "telemetry", "disable")
    before, after = fields(before_text), fields(after_text)
    count_names = ["total", "x2apic", "hyperv_apic", "hyperv_other", "spec_ctrl", "other",
                   "x2apic_tpr", "x2apic_eoi", "x2apic_icr", "x2apic_self_ipi",
                   "hyperv_eoi", "hyperv_icr", "hyperv_tpr"]
    deltas = {name: 0 for name in count_names}
    per_cpu = {}
    for cpu in cpus:
        prefix = f"cpu.{cpu}.nested_l2_wrmsr."
        counts = {name: int(after[prefix + name]) - int(before[prefix + name])
                  for name in count_names}
        if any(value < 0 for value in counts.values()):
            raise ValueError("Profiling counters reset during collection")
        for name, value in counts.items():
            deltas[name] += value
        per_cpu[cpu] = {
            "deltas": counts,
            "last_ecx": hex(int(after[prefix + "last_ecx"])),
            "x2apic_requested": after[f"cpu.{cpu}.nested_x2apic_requested"] == "true",
            "x2apic_active": after[f"cpu.{cpu}.nested_x2apic_active"] == "true",
        }
    percentages = {name: value * 100 / deltas["total"] if deltas["total"] else None
                   for name, value in deltas.items() if name != "total"}
    result = {
        "scope": "observed_l2_reason_32_exits",
        "elapsed_seconds": elapsed,
        "deltas": deltas,
        "percentages": percentages,
        "exclusive_class_sum": sum(deltas[name] for name in count_names[1:6]),
        "telemetry_restored_enabled": was_enabled,
        "per_cpu": per_cpu,
        "limitations": [
            "Sequential CPU and counter snapshots can be incoherent; interval deltas are approximate.",
            "Counts cover observed VM exits, not native or hardware-virtualized WRMSR instructions.",
            "Detail-register percentages are subsets of the exclusive classes.",
            "Historical captures without ECX cannot be reclassified retrospectively.",
        ],
    }
    metric_names = ["exits", "nested_l2_entries", "nested_l2_exits", "nested_ept_compositions",
                    "nested_ept02_invalidations", "exit_reason.48", "exit_reason.50",
                    "resume_failures", "nested_vmx_failures", "nested_entry_rejections"]
    if all(int(after[f"cpu.{cpu}.capabilities"], 0) & (1 << 26) for cpu in cpus):
        metric_names += ["ept_revalidation." + name for name in
                         ["calls", "budget_exhaustions", "leaves_checked", "leaves_dropped_at_budget"]]
    result["interval_metrics"] = {
        name: sum(int(after[f"cpu.{cpu}.{name}"]) - int(before[f"cpu.{cpu}.{name}"])
                  for cpu in cpus) for name in metric_names
    }
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--neo", required=True, type=Path)
    parser.add_argument("--seconds", type=int, default=30, choices=range(1, 3601), metavar="1..3600")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(measure(args.neo.resolve(), args.seconds, args.output.resolve()), indent=2))


if __name__ == "__main__":
    main()
