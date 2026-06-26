from __future__ import annotations

import hashlib
import os

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
IDENTITY = (0, 1)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _point_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    den = (D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + x2 * y1) * _inv(1 + den)) % P
    y3 = ((y1 * y2 + x1 * x2) * _inv(1 - den)) % P
    return x3, y3


def _scalar_mult(s: int, p: tuple[int, int] = B) -> tuple[int, int]:
    q = IDENTITY
    while s:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _encode_point(p: tuple[int, int]) -> bytes:
    x, y = p
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def _decode_point(raw: bytes) -> tuple[int, int]:
    if len(raw) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    xx = ((y * y - 1) * _inv(D * y * y + 1)) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = (x * I) % P
    if (x * x - xx) % P:
        raise ValueError("invalid Ed25519 point")
    if (x & 1) != sign:
        x = P - x
    return x, y


def _secret_scalar(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a = bytearray(digest[:32])
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    return int.from_bytes(a, "little"), digest[32:]


def create_seed() -> bytes:
    return os.urandom(32)


def public_from_seed(seed: bytes) -> bytes:
    a, _ = _secret_scalar(seed)
    return _encode_point(_scalar_mult(a))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _secret_scalar(seed)
    public = public_from_seed(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_point = _encode_point(_scalar_mult(r))
    k = int.from_bytes(hashlib.sha512(r_point + public + message).digest(), "little") % L
    s = (r + k * a) % L
    return r_point + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        a = _decode_point(public)
        r = _decode_point(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    left = _scalar_mult(s)
    right = _point_add(r, _scalar_mult(k, a))
    return left == right
