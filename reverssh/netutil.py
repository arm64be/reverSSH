from __future__ import annotations

import socket
from contextlib import closing


def parse_host_port(value: str, default_host: str = "") -> tuple[str, int]:
    if value.startswith("["):
        end = value.index("]")
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest.startswith(":"):
            raise ValueError(f"missing port in address: {value}")
        port = int(rest[1:])
    else:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    if not host:
        host = default_host
    return host, port


def listen_socket(address: str, backlog: int = 100) -> socket.socket:
    host, port = parse_host_port(address, default_host="0.0.0.0")
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(backlog)
    return sock


def port_is_available(host: str, port: int) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True
