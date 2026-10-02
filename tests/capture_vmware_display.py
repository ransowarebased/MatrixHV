import argparse
import socket
import struct
from pathlib import Path

from PIL import Image

MAX_MESSAGE_BYTES = 64 * 1024 * 1024


def receive_exact(connection: socket.socket, size: int) -> bytes:
    if not 0 <= size <= MAX_MESSAGE_BYTES:
        raise RuntimeError("VNC message exceeds the capture limit")
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("VNC connection closed during capture")
        chunks.extend(chunk)
    return bytes(chunks)


def capture(host: str, port: int, output_path: Path) -> None:
    with socket.create_connection((host, port), timeout=10) as connection:
        version = receive_exact(connection, 12)
        if version not in (b"RFB 003.007\n", b"RFB 003.008\n"):
            raise RuntimeError(f"Unsupported VNC protocol: {version!r}")
        connection.sendall(version)
        security_count = receive_exact(connection, 1)[0]
        if security_count == 0:
            reason_length = struct.unpack("!I", receive_exact(connection, 4))[0]
            reason = receive_exact(connection, reason_length).decode(errors="replace")
            raise RuntimeError(f"VNC rejected the connection: {reason}")
        security_types = receive_exact(connection, security_count)
        if 1 not in security_types:
            raise RuntimeError(f"VNC security type None is unavailable: {list(security_types)}")
        connection.sendall(b"\x01")
        if struct.unpack("!I", receive_exact(connection, 4))[0] != 0:
            raise RuntimeError("VNC security negotiation failed")
        connection.sendall(b"\x01")

        width, height = struct.unpack("!HH", receive_exact(connection, 4))
        if width == 0 or height == 0 or width * height * 4 > MAX_MESSAGE_BYTES:
            raise RuntimeError("Invalid VNC framebuffer dimensions")
        receive_exact(connection, 16)
        name_length = struct.unpack("!I", receive_exact(connection, 4))[0]
        receive_exact(connection, name_length)

        pixel_format = struct.pack(
            "!BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0
        )
        connection.sendall(b"\x00\x00\x00\x00" + pixel_format)
        connection.sendall(struct.pack("!BBH", 2, 0, 1) + struct.pack("!i", 0))
        connection.sendall(struct.pack("!BBHHHH", 3, 0, 0, 0, width, height))

        image = Image.new("RGB", (width, height))
        while True:
            message_type = receive_exact(connection, 1)[0]
            if message_type == 0:
                receive_exact(connection, 1)
                rectangle_count = struct.unpack("!H", receive_exact(connection, 2))[0]
                if rectangle_count == 0:
                    continue
                for _ in range(rectangle_count):
                    x, y, rect_width, rect_height, encoding = struct.unpack(
                        "!HHHHi", receive_exact(connection, 12)
                    )
                    if encoding != 0:
                        raise RuntimeError(f"Unexpected VNC encoding {encoding}")
                    if rect_width == 0 or rect_height == 0 or x + rect_width > width or y + rect_height > height:
                        raise RuntimeError("VNC rectangle lies outside the framebuffer")
                    pixels = receive_exact(connection, rect_width * rect_height * 4)
                    rectangle = Image.frombytes(
                        "RGB", (rect_width, rect_height), pixels, "raw", "BGRX"
                    )
                    image.paste(rectangle, (x, y))
                break
            if message_type == 2:
                continue
            if message_type == 3:
                length = struct.unpack("!I", receive_exact(connection, 4))[0]
                receive_exact(connection, length)
                continue
            raise RuntimeError(f"Unexpected VNC server message {message_type}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)
    print(output_path.resolve())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5905)
    arguments = parser.parse_args()
    capture(arguments.host, arguments.port, arguments.output)


if __name__ == "__main__":
    main()
