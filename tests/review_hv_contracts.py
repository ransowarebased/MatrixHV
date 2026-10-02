"""Extract the reviewed loader contract without inferring physical boot state."""

import hashlib
import json
from pathlib import Path
import struct

import capstone
import pefile


PROJECT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT / "tools" / "hv-review"
LOADER_SHA256 = "09c9676c944f5db21619a6aa2611271dc8a91f624c4c7ed5f65b2e2c50d2d811"
CONTROLS = [
    ("pinbased_ctls", 0x481, 0x1E, 0x3F),
    ("procbased_ctls", 0x482, 0xA42065FA, 0xE7F9FFFE),
    ("exit_ctls", 0x483, 0x36FFF, 0x2BEFFF),
    ("entry_ctls", 0x484, 0x11FF, 0xD3FF),
    ("procbased_ctls2", 0x48B, 0, 0x26),
    ("procbased_ctls3", 0x492, 0, 0),
]
FIXED = [
    ("cr0_fixed0", 0x486, "subset", 0x80000031),
    ("cr0_fixed1", 0x487, "superset", 0x8005003F),
    ("cr4_fixed0", 0x488, "subset", 0x2040),
    ("cr4_fixed1", 0x489, "superset", 0x27FF),
    ("ept_vpid_cap", 0x48C, "superset", 0xF0106104040),
]


def write_json(name, value):
    (OUTPUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def export_pe_ranges():
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.skipdata = True
    for identity_path in OUTPUT.glob("*/identity.json"):
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        source = Path(identity["binary"])
        binary = source.read_bytes()
        if hashlib.sha256(binary).hexdigest() != identity["sha256"]:
            raise ValueError(f"Binary changed since IDA export: {source}")
        pe = pefile.PE(data=binary)
        image = pe.get_memory_mapped_image()
        index = json.loads((identity_path.parent / "index.json").read_text(encoding="utf-8"))
        names = {int(function["rva"], 16): function["name"] for function in index["functions"]}
        with (identity_path.parent / "unwind-disassembly.txt").open("w", encoding="utf-8") as output:
            output.write("Linear decode of PE exception-directory ranges, independent of IDA no-return inference. Data embedded in a range must be interpreted with control flow.\n")
            for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
                start, end = entry.struct.BeginAddress, entry.struct.EndAddress
                output.write(f"\nFUNCTION RVA={start:#x} END={end:#x} {names.get(start, 'unnamed')}\n")
                for instruction in decoder.disasm(image[start:end], pe.OPTIONAL_HEADER.ImageBase + start):
                    output.write(f"{instruction.address:#x} {instruction.mnemonic} {instruction.op_str}\n")


def extract_cpuid_table(image):
    records = []
    grouped = {}
    address = 0x25160
    while True:
        fields = struct.unpack_from("<7I", image, address)
        if fields[0] == 0xFFFFFFFF:
            break
        leaf, subleaf, mask, register, operation, vendor_filter, error = fields
        if register >= 4:
            raise ValueError(f"Unexpected register index at {address:#x}")
        records.append({"rva": hex(address), "leaf": hex(leaf), "subleaf": hex(subleaf), "register": ["eax", "ebx", "ecx", "edx"][register], "mask": hex(mask), "operation": operation, "vendor_filter": vendor_filter, "error_argument": hex(error)})
        if operation in (2, 3) and vendor_filter != 1:
            key = leaf, subleaf, register, operation
            grouped[key] = grouped.get(key, 0) | mask
        address += 28
    if len(records) != 741 or address != 0x2A26C:
        raise ValueError("The CPUID table does not match the reviewed image")
    checks = [{"leaf": hex(leaf), "subleaf": hex(subleaf), "register": ["eax", "ebx", "ecx", "edx"][register], "predicate": "all_mask_bits_one" if operation == 2 else "all_mask_bits_zero", "mask": hex(mask)} for (leaf, subleaf, register, operation), mask in grouped.items()]
    write_json("loader-cpuid-table.json", {"binary_sha256": LOADER_SHA256, "reader_rva": "0x1cd88", "table_rva": "0x25160", "sentinel_rva": hex(address), "entry_size": 28, "record_count": len(records), "vendor_filters": {"0": "Intel", "1": "AMD or Hygon", "other": "all vendors"}, "operations_in_admission_reader": {"2": "all mask bits must be one; missing leaf fails", "3": "mask bits must be zero; missing leaf is skipped", "other": "no rejection in this reader"}, "records": records})
    return checks


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    export_pe_ranges()
    path = PROJECT / "tools" / "Reverse Engeneering" / "hvloader.dll"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != LOADER_SHA256:
        raise ValueError("Loader SHA-256 differs from the reviewed build; RVAs and masks must be reviewed again")
    checks = extract_cpuid_table(pefile.PE(data=data).get_memory_mapped_image())
    mapping = {
        "binary": str(path), "sha256": LOADER_SHA256, "file_version": "10.0.26100.9444", "image_base": "0x180000000",
        "symbol_limit": "Matching public PDB unavailable (HTTP 404). The Intel detector role is inferred; HvlpDetectVirtualizationHardware is not a recovered symbol.",
        "call_chain": ["HvlLoadHypervisor RVA 0x1104", "load worker RVA 0xd900", "vendor dispatch RVA 0x1ccac", "Intel hardware detector RVA 0x1d898", "capability reader RVA 0x1ea20", "VMX capability validator RVA 0x1e788"],
        "hardware_detector": [
            {"predicate": "CPUID.1:ECX[5] == 1", "failure_internal_code": 19},
            {"predicate": "IA32_FEATURE_CONTROL[0] == 1 and [2] == 1 for ordinary launch; execution-environment flags 1 or 2 select [1] instead", "failure_internal_code": 19, "source_exposure": "MatrixHV returns 0x5, permitting ordinary VMX outside SMX only"},
            {"predicate": "CR4.SMXE[14] == 0", "failure_internal_code": 18},
            {"predicate": "IA32_VMX_PROCBASED_CTLS2.allowed_one[1] == 1", "failure_internal_code": 26},
            {"predicate": "VMX capability validator succeeds", "failure_internal_code": 24}
        ],
        "control_semantics": "Reject if (actual_low & ~accepted_mandatory_one) != 0 or (required_allowed_one & ~actual_high) != 0. The lower half is not an allowed-zero bitmask.",
        "control_msr_selection": "IA32_VMX_BASIC[55] selects 0x48d..0x490 instead of 0x481..0x484. Secondary is read if primary allowed-one[31]; EPT/VPID if secondary allowed-one[1 or 5]; VMFUNC if [13]. Tertiary 0x492 is read if primary allowed-one[17], with its low 32 bits placed in the high half of the validation table.",
        "basic": {"msr": "0x480", "region_size": "((value >> 32) & 0x1fff) <= 0x1000", "memory_type": "((value >> 50) & 0xf) == 6"},
        "controls": [{"name": name, "legacy_msr": hex(msr), "true_msr": hex(msr + 12) if index < 4 else None, "accepted_mandatory_one": hex(low), "required_allowed_one": hex(high)} for index, (name, msr, low, high) in enumerate(CONTROLS)],
        "fixed_and_ept_masks": [{"name": name, "msr": hex(msr), "predicate": operation, "mask": hex(mask)} for name, msr, operation, mask in FIXED],
        "ept_required_bits": {"6": "four-level EPT walk", "14": "WB EPTP", "20": "INVEPT", "25": "single-context INVEPT", "26": "all-context INVEPT", "32": "INVVPID", "40": "individual-address INVVPID", "41": "single-context INVVPID", "42": "all-context INVVPID", "43": "single-context retaining globals INVVPID"},
        "mbec": {"required_by_this_base_gate": False, "matrixhv_secondary_bit": 22, "matrixhv_exposure_condition": "Native secondary allowed-one[22] plus EPT/VPID execute-only[0] and advanced EPT-violation information[22]", "source": "src/nested.rs:266", "caveat": "Later VSM policy and nested execution are separate stages; passing this gate does not establish successful HVCI initialization."},
        "other_optional_features": "This validator does not require EPT A/D, 1-GiB EPT pages or VMFUNC. Its expected MISC[30] and VMFUNC masks are zero.",
        "failure_path": {"validator_return": "0x1029", "msr_error_recorder_rva": "0x1e9cc", "diagnostic_writer_rva": "0x1d9f0", "detector_return": 24, "status_mapping_rva": "0xb8fc", "mapped_ntstatus_for_24_and_26": "0xc0000010", "direct_reset_in_validator": False},
        "cpuid": {"reader_rva": "0x1cd88", "intel_leaf_bound_checks": "Cached maximum basic leaf >= 4; cached maximum extended leaf must differ from 0x80000000", "intel_admission_checks": checks, "full_table": "loader-cpuid-table.json"},
        "matrixhv_source_contract": {"vmx_policy": "src/nested.rs:175", "cpuid": "src/asm/exits.S:52", "tlfs_and_evmcs": "src/asm/hyperv.S:9", "nested_state_validation": "src/asm/nested.S:2154", "ept12_composition": "src/asm/nested.S:860"},
    }
    write_json("prerequisites.json", mapping)
    print(json.dumps({"cpuid_checks": len(checks), "physical_boot_state_evaluated": False, "vm_captures_used": False}))


if __name__ == "__main__":
    main()
