from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import struct
from urllib.parse import urlparse

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocketError(Exception):
    pass


class WebSocketStream:
    def __init__(self, sock: socket.socket, *, mask_outgoing: bool):
        self.sock = sock
        self.mask_outgoing = mask_outgoing
        self.buffer = bytearray()
        self.closed = False

    def recv(self, size: int) -> bytes:
        while not self.buffer and not self.closed:
            self._read_next_message()
        if self.closed and not self.buffer:
            return b""
        out = bytes(self.buffer[:size])
        del self.buffer[:size]
        return out

    def sendall(self, data: bytes) -> None:
        if self.closed:
            raise OSError("websocket is closed")
        self.sock.sendall(self._frame(0x2, data))

    def shutdown(self, how: int) -> None:
        self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.sendall(self._frame(0x8, b""))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _read_next_message(self) -> None:
        parts: list[bytes] = []
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == 0x8:
                self.closed = True
                return
            if opcode == 0x9:
                self.sock.sendall(self._frame(0xA, payload))
                continue
            if opcode == 0xA:
                continue
            if opcode not in (0x0, 0x1, 0x2):
                raise WebSocketError(f"unsupported websocket opcode {opcode}")
            parts.append(payload)
            if fin:
                self.buffer.extend(b"".join(parts))
                return

    def _read_frame(self) -> tuple[bool, int, bytes]:
        header = _recv_exact(self.sock, 2)
        first, second = header
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", _recv_exact(self.sock, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _recv_exact(self.sock, 8))[0]
        mask = _recv_exact(self.sock, 4) if masked else b""
        payload = _recv_exact(self.sock, length) if length else b""
        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return fin, opcode, payload

    def _frame(self, opcode: int, payload: bytes) -> bytes:
        first = 0x80 | opcode
        length = len(payload)
        mask_bit = 0x80 if self.mask_outgoing else 0
        if length < 126:
            header = bytes([first, mask_bit | length])
        elif length <= 0xFFFF:
            header = bytes([first, mask_bit | 126]) + struct.pack(">H", length)
        else:
            header = bytes([first, mask_bit | 127]) + struct.pack(">Q", length)
        if not self.mask_outgoing:
            return header + payload
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return header + mask + masked


def connect_websocket(url: str, timeout: float = 30.0) -> WebSocketStream:
    parsed = urlparse(_normalize_ws_url(url))
    if parsed.scheme not in ("ws", "wss"):
        raise ValueError(f"unsupported WebSocket relay scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("WebSocket relay URL must include a host")
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
    if parsed.scheme == "wss":
        raw = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    key = base64.b64encode(os.urandom(16)).decode()
    host = parsed.hostname
    if parsed.port and parsed.port not in (80, 443):
        host = f"{host}:{parsed.port}"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode()
    raw.sendall(request)
    response = _read_http_header(raw).decode("iso-8859-1")
    lines = response.split("\r\n")
    if not lines or " 101 " not in lines[0]:
        raise WebSocketError(f"websocket upgrade failed: {lines[0] if lines else response!r}")
    headers = _parse_headers(lines[1:])
    expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    if headers.get("sec-websocket-accept", "") != expected:
        raise WebSocketError("websocket upgrade returned invalid accept key")
    return WebSocketStream(raw, mask_outgoing=True)


def accept_websocket(sock: socket.socket, path_prefix: str) -> WebSocketStream:
    request = _read_http_header(sock).decode("iso-8859-1")
    lines = request.split("\r\n")
    if not lines:
        raise WebSocketError("empty websocket request")
    try:
        method, path, _version = lines[0].split(" ", 2)
    except ValueError as exc:
        raise WebSocketError("invalid websocket request line") from exc
    if method != "GET":
        raise WebSocketError("websocket request must use GET")
    if not path.startswith(path_prefix):
        _send_http_error(sock, 404, "not found")
        raise WebSocketError(f"unexpected websocket path: {path}")
    headers = _parse_headers(lines[1:])
    if headers.get("upgrade", "").lower() != "websocket":
        _send_http_error(sock, 426, "upgrade required")
        raise WebSocketError("request did not ask for websocket upgrade")
    key = headers.get("sec-websocket-key")
    if not key:
        _send_http_error(sock, 400, "missing sec-websocket-key")
        raise WebSocketError("missing sec-websocket-key")
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    ).encode()
    sock.sendall(response)
    return WebSocketStream(sock, mask_outgoing=False)


def _normalize_ws_url(url: str) -> str:
    if url.startswith("https://"):
        return "wss://" + url[len("https://") :]
    if url.startswith("http://"):
        return "ws://" + url[len("http://") :]
    return url


def _read_http_header(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed during HTTP header")
        data.extend(chunk)
        if len(data) > 64 * 1024:
            raise WebSocketError("HTTP header too large")
    return bytes(data.split(b"\r\n\r\n", 1)[0])


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def _send_http_error(sock: socket.socket, status: int, message: str) -> None:
    body = (message + "\n").encode()
    response = (
        f"HTTP/1.1 {status} {message}\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body
    sock.sendall(response)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("websocket connection closed")
        data.extend(chunk)
    return bytes(data)
