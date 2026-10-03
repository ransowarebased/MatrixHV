"""Generate a signed, bounded MatrixHV resident runtime package."""

import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tests"))
from resident_image import validate_image


def signing_key(path):
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def bootstrap(key_path, public_path):
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        key = Ed25519PrivateKey.generate()
        data = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
        if os.name == "nt":
            identity = subprocess.check_output(["whoami"], text=True).strip()
            subprocess.run(["icacls", str(key_path), "/inheritance:r", "/grant:r", f"{identity}:(F)"],
                           check=True, capture_output=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(signing_key(key_path).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def build_package(object_path, key_path, output_path, version=None, efi_path=None):
    output_path.resolve().relative_to((PROJECT / "builds").resolve())
    image, symbols = validate_image(object_path)
    if efi_path is not None and efi_path.read_bytes().count(image) != 1:
        raise ValueError("The packaged resident image does not match the embedded EFI core")
    code_end = symbols["matrixhv_resident_code_end"]
    metadata = symbols["matrixhv_resident_package_abi"]
    abi = struct.unpack_from("<5I4xQ", image, metadata)
    release = version if version is not None else abi[5]
    if not 0 < release < 1 << 64 or len(image) > 256 * 1024 or code_end % 4096:
        raise ValueError("Invalid resident package capacity, version, or code alignment")
    header = bytearray(256)
    header[:8] = b"MATRIXUP"
    regions = struct.pack("<8I", 0, code_end, 5, 0, code_end, len(image) - code_end, 3, 0)
    relocations = []
    for name, kind in [("matrixhv_resident_island_event_context", 1),
                       ("matrixhv_resident_island_msr_switch_count", 2),
                       ("matrixhv_resident_island_log_backend", 3),
                       ("matrixhv_resident_update_loader", 4),
                       ("matrixhv_resident_update_context", 5),
                       ("matrixhv_resident_core_version", 6),
                       ("matrixhv_resident_core_identity", 7)]:
        target = symbols[name]
        width = 32 if kind == 7 else 8
        if target < code_end or target % 8 or any(image[target:target + width]):
            raise ValueError(f"Invalid resident relocation slot: {name}")
        relocations.append((target, kind, 0))
    relocations.sort()
    relocations = b"".join(struct.pack("<IIQ", *item) for item in relocations)
    body = regions + relocations + image
    image_offset = 256 + len(regions) + len(relocations)
    for offset, value in [(8, 1), (12, 256), (16, 256 + len(body)), (20, image_offset),
                          (24, len(image)), (28, 1), (40, abi[0]), (44, 2), (48, 7), (52, 5),
                          (80, abi[1]), (84, abi[2]), (88, abi[3]), (92, abi[4]), (96, 256), (100, 288)]:
        struct.pack_into("<I", header, offset, value)
    struct.pack_into("<Q", header, 32, release)
    for offset, name in [(56, "matrixhv_resident_dispatch_entry"), (60, "matrixhv_resident_island_fatal"),
                         (64, "matrixhv_resident_island_gp"), (68, "matrixhv_resident_exception_stubs"),
                         (72, "matrixhv_resident_island_entry")]:
        struct.pack_into("<I", header, offset, symbols[name])
    key = signing_key(key_path)
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    header[104:136] = hashlib.sha256(public_key).digest()
    header[136:168] = hashlib.sha256(image).digest()
    identity = hashlib.sha256(b"MatrixHV runtime core package v1\0" + header[:192] + body).digest()
    header[192:256] = key.sign(identity)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(header + body)
    print(f"Runtime package: {output_path} version={release} identity={identity.hex()} bytes={256 + len(body)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["bootstrap", "package"])
    parser.add_argument("--key", type=Path, default=Path(os.environ.get("MATRIXHV_UPDATE_SIGNING_KEY", str(Path(os.environ.get("LOCALAPPDATA", Path.home())) / "MatrixHV/update-signing.key"))))
    parser.add_argument("--public", type=Path)
    parser.add_argument("--object", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--version", type=int)
    parser.add_argument("--efi", type=Path)
    args = parser.parse_args()
    if args.action == "bootstrap":
        if args.public is None:
            parser.error("bootstrap requires --public")
        bootstrap(args.key, args.public)
    else:
        if args.object is None or args.output is None:
            parser.error("package requires --object and --output")
        build_package(args.object, args.key, args.output, args.version, args.efi)


if __name__ == "__main__":
    main()
