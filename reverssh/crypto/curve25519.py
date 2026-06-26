from __future__ import annotations

P = 2**255 - 19
A24 = 121665


def _clamp_scalar(scalar: bytes) -> bytes:
    if len(scalar) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def x25519(scalar: bytes, u: bytes) -> bytes:
    if len(u) != 32:
        raise ValueError("X25519 peer point must be 32 bytes")
    k = int.from_bytes(_clamp_scalar(scalar), "little")
    x1 = int.from_bytes(u, "little") % P
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt

        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) ** 2) % P
        z3 = (x1 * ((da - cb) ** 2)) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + A24 * e)) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    out = (x2 * pow(z2, P - 2, P)) % P
    return out.to_bytes(32, "little")


def public_from_private(private: bytes) -> bytes:
    return x25519(private, b"\x09" + b"\x00" * 31)
