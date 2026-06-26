from __future__ import annotations

import base64
import struct
from dataclasses import dataclass


class SSHDecodeError(ValueError):
    pass


def byte(value: int) -> bytes:
    return struct.pack(">B", value)


def boolean(value: bool) -> bytes:
    return b"\x01" if value else b"\x00"


def uint32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"uint32 out of range: {value!r}")
    return struct.pack(">I", value)


def uint64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"uint64 out of range: {value!r}")
    return struct.pack(">Q", value)


def string(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    return uint32(len(value)) + value


def name_list(names: list[str] | tuple[str, ...]) -> bytes:
    return string(",".join(names).encode())


def mpint(value: int) -> bytes:
    if value == 0:
        return uint32(0)
    if value < 0:
        raise ValueError("negative mpint is not supported")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return string(raw)


def parse_authorized_key(line: str) -> tuple[str, bytes]:
    parts = line.strip().split()
    if len(parts) < 2:
        raise ValueError("authorized-key line must contain algorithm and key blob")
    alg = parts[0]
    blob = base64.b64decode(parts[1].encode(), validate=True)
    return alg, blob


def public_key_fingerprint(key_blob: bytes) -> str:
    import hashlib

    digest = hashlib.sha256(key_blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


@dataclass
class Reader:
    data: bytes
    offset: int = 0

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise SSHDecodeError("truncated SSH payload")
        out = self.data[self.offset : self.offset + size]
        self.offset += size
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def boolean(self) -> bool:
        value = self.byte()
        if value not in (0, 1):
            raise SSHDecodeError(f"invalid SSH boolean: {value}")
        return bool(value)

    def uint32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def uint64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def string(self) -> bytes:
        return self.take(self.uint32())

    def text(self) -> str:
        return self.string().decode()

    def name_list(self) -> list[str]:
        raw = self.string()
        if not raw:
            return []
        return raw.decode().split(",")

    def mpint(self) -> int:
        raw = self.string()
        if not raw:
            return 0
        if raw[0] & 0x80:
            raise SSHDecodeError("negative mpint is not supported")
        return int.from_bytes(raw, "big")

    def eof(self) -> None:
        if self.remaining():
            raise SSHDecodeError(f"{self.remaining()} trailing bytes")
