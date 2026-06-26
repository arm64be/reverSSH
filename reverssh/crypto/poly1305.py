from __future__ import annotations

P = (1 << 130) - 5


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for pos in range(0, len(message), 16):
        chunk = message[pos : pos + 16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + n) * r) % P
    tag = (acc + s) % (1 << 128)
    return tag.to_bytes(16, "little")
