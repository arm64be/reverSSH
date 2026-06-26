from __future__ import annotations

import base64
import os
from pathlib import Path

from .crypto import ed25519
from .ssh_encoding import Reader, string


def ed25519_key_blob(public: bytes) -> bytes:
    return string("ssh-ed25519") + string(public)


def parse_ed25519_key_blob(blob: bytes) -> bytes:
    reader = Reader(blob)
    alg = reader.text()
    if alg != "ssh-ed25519":
        raise ValueError(f"unsupported SSH public key algorithm: {alg}")
    public = reader.string()
    reader.eof()
    if len(public) != 32:
        raise ValueError("invalid ssh-ed25519 key length")
    return public


def load_or_create_host_seed(state_dir: Path) -> bytes:
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / "ssh_host_ed25519_seed"
    if path.exists():
        return base64.b64decode(path.read_text().strip().encode(), validate=True)
    seed = ed25519.create_seed()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(base64.b64encode(seed).decode() + "\n")
    return seed
