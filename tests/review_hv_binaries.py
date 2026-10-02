"""Export reproducible, read-only IDA evidence for Windows virtualization review."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import traceback
import urllib.error
import urllib.request
import uuid


def export_ida():
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_nalt
    import ida_pro
    import ida_segment
    import idautils
    import idc

    output = Path(os.environ["MATRIXHV_REVIEW_OUTPUT"])
    output.mkdir(parents=True, exist_ok=True)
    sys.stdout = (output / "export.log").open("w", encoding="utf-8", buffering=1)
    sys.stderr = sys.stdout
    try:
        ida_auto.auto_wait()
        base = ida_nalt.get_imagebase()
        functions = []
        interesting = re.compile(
            r"Hvl|Hyper|Virtual|Vmx|Vbs|Vsm|Hvci|Firmware|Reboot|Reset|Secure|SkInit|Ium|Cpu|Processor|Ept|Launch|Failure|Fatal|BugCheck",
            re.IGNORECASE,
        )
        privileged = {"cpuid", "rdmsr", "wrmsr", "vmxon", "vmxoff", "vmlaunch", "vmresume", "vmread", "vmwrite", "vmcall", "invept", "invvpid", "vmfunc"}
        with (output / "disassembly.txt").open("w", encoding="utf-8") as listing:
            for start in idautils.Functions():
                function = ida_funcs.get_func(start)
                name = idc.get_func_name(start)
                record = {"va": hex(start), "rva": hex(start - base), "end": hex(function.end_ea), "name": name, "privileged": [], "calls": [], "callers": []}
                listing.write(f"\nFUNCTION {start:#x} RVA={start - base:#x} {name}\n")
                for address in idautils.FuncItems(start):
                    if not ida_bytes.is_code(ida_bytes.get_full_flags(address)):
                        continue
                    mnemonic = idc.print_insn_mnem(address)
                    line = idc.generate_disasm_line(address, 0) or ""
                    listing.write(f"{address:#x} {line}\n")
                    if mnemonic in privileged:
                        record["privileged"].append({"va": hex(address), "instruction": line})
                    if mnemonic == "call":
                        record["calls"].append({"va": hex(address), "instruction": line, "targets": [hex(target) for target in idautils.CodeRefsFrom(address, False)]})
                for reference in idautils.CodeRefsTo(start, False):
                    owner = ida_funcs.get_func(reference)
                    record["callers"].append({"va": hex(reference), "function": idc.get_func_name(reference), "start": hex(owner.start_ea) if owner else None})
                functions.append(record)
        segments = []
        for address in idautils.Segments():
            segment = ida_segment.getseg(address)
            segments.append({"start": hex(segment.start_ea), "end": hex(segment.end_ea), "name": ida_segment.get_segm_name(segment)})
        metadata = {"input": ida_nalt.get_input_file_path(), "image_base": hex(base), "segments": segments, "functions": functions}
        (output / "index.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        with (output / "strings.txt").open("w", encoding="utf-8") as listing:
            for value in idautils.Strings():
                listing.write(f"{value.ea:#x} {value}\n")
        focus = os.environ.get("MATRIXHV_REVIEW_FOCUS")
        focus_pattern = re.compile(focus, re.IGNORECASE) if focus else None
        selected = [function for function in functions if (
            focus_pattern.search(function["name"]) if focus_pattern else
            len(functions) < 500 or interesting.search(function["name"]) or function["privileged"]
        )]
        print("Functions", len(functions), "Selected", len(selected), flush=True)
        if ida_hexrays.init_hexrays_plugin():
            label = hashlib.sha256(focus.encode()).hexdigest()[:12] if focus_pattern else None
            filename = f"focused-{label}.txt" if label else "decompiled.txt"
            with (output / filename).open("w", encoding="utf-8") as listing:
                for function in selected:
                    listing.write(f"\nFUNCTION {function['va']} RVA={function['rva']} {function['name']}\n")
                    try:
                        listing.write(str(ida_hexrays.decompile(int(function["va"], 16))) + "\n")
                    except Exception as error:
                        listing.write(f"DECOMPILATION FAILED: {error}\n")
        print("Export complete", flush=True)
        ida_pro.qexit(0)
    except Exception:
        traceback.print_exc()
        ida_pro.qexit(1)


def inspect_binary(source, output):
    import pefile

    data = source.read_bytes()
    image = pefile.PE(data=data)
    identity = {"binary": str(source), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "image_base": hex(image.OPTIONAL_HEADER.ImageBase), "timestamp": image.FILE_HEADER.TimeDateStamp, "symbols": []}
    versions = getattr(image, "VS_FIXEDFILEINFO", [])
    if versions:
        version = versions[0]
        identity["file_version"] = ".".join(str(part) for part in (version.FileVersionMS >> 16, version.FileVersionMS & 65535, version.FileVersionLS >> 16, version.FileVersionLS & 65535))
    for entry in getattr(image, "DIRECTORY_ENTRY_DEBUG", []):
        if entry.struct.Type != 2:
            continue
        record = image.get_data(entry.struct.AddressOfRawData, entry.struct.SizeOfData)
        if record[:4] != b"RSDS":
            continue
        guid = uuid.UUID(bytes_le=record[4:20]).hex.upper()
        age = struct.unpack_from("<I", record, 20)[0]
        name = record[24:].split(b"\0", 1)[0].decode().replace("\\", "/").split("/")[-1]
        url = f"https://msdl.microsoft.com/download/symbols/{name}/{guid}{age:X}/{name}"
        symbol = {"name": name, "guid": guid, "age": age, "url": url}
        symbol_path = output / name
        if symbol_path.exists():
            symbol["download"] = "cached"
        else:
            try:
                with urllib.request.urlopen(url, timeout=25) as response:
                    symbol_path.write_bytes(response.read())
                symbol["download"] = "available"
            except (urllib.error.URLError, TimeoutError) as error:
                symbol["download"] = str(error)
        identity["symbols"].append(symbol)
    (output / "identity.json").write_text(json.dumps(identity, indent=2), encoding="utf-8")
    return identity


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="*", default=["hvloader.dll", "winload.efi", "hvix64.exe", "securekernel.exe", "skci.dll", "ci.dll", "bootmgfw.efi", "hvax64.exe"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--idat", type=Path, required=True)
    arguments = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    root = arguments.output.resolve()
    if not root.is_relative_to(project / "builds") and root != project / "tools" / "hv-review":
        raise ValueError("Review output must be under builds or tools/hv-review")
    root.mkdir(parents=True, exist_ok=True)
    for name in arguments.binaries:
        source = project / "tools" / "Reverse Engeneering" / name
        output = root / source.stem
        output.mkdir(exist_ok=True)
        identity = inspect_binary(source, output)
        print(json.dumps(identity), flush=True)
        binary = output / source.name
        shutil.copy2(source, binary)
        if (output / "index.json").exists() and (output / "decompiled.txt").exists():
            print("Reusing completed export", name, flush=True)
            continue
        env = os.environ.copy()
        env["MATRIXHV_REVIEW_OUTPUT"] = str(output)
        env["_NT_SYMBOL_PATH"] = str(output)
        command = [str(arguments.idat), "-A", "-c", "-P+", "-Opdb:pdbida", f"-o{output / 'analysis.i64'}", f"-L{output / 'idat.log'}", f"-S{Path(__file__).resolve()}", str(binary)]
        with (output / "console.log").open("w", encoding="utf-8") as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=900)
        print("IDA result", name, result.returncode, flush=True)
        if result.returncode != 0:
            raise RuntimeError(f"IDA failed for {name}; inspect {output}")


if __name__ == "__main__":
    if os.environ.get("MATRIXHV_REVIEW_OUTPUT"):
        export_ida()
    else:
        main()
