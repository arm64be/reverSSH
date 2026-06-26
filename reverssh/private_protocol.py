from __future__ import annotations

import json
import socket
import struct
import threading
from enum import IntEnum
from typing import Any

from .ssh_encoding import Reader, boolean, string, uint32
from .ssh_packet import recv_exact


MAX_FRAME = 16 * 1024 * 1024


class FrameType(IntEnum):
    REGISTER = 1
    REGISTER_RESULT = 2
    AUTH_REQUEST = 3
    AUTH_RESPONSE = 4
    OPEN_CHANNEL = 10
    OPEN_CONFIRM = 11
    CHANNEL_DATA = 12
    CHANNEL_EOF = 13
    CHANNEL_CLOSE = 14
    CHANNEL_REQUEST = 15
    CHANNEL_EXTENDED_DATA = 16
    HEARTBEAT = 30


class FrameSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._send_lock = threading.Lock()

    def send_frame(self, frame_type: FrameType, payload: bytes = b"") -> None:
        body = bytes([int(frame_type)]) + payload
        if len(body) > MAX_FRAME:
            raise ValueError("private protocol frame too large")
        with self._send_lock:
            self.sock.sendall(struct.pack(">I", len(body)) + body)

    def read_frame(self) -> tuple[FrameType, bytes]:
        header = recv_exact(self.sock, 4)
        length = struct.unpack(">I", header)[0]
        if length < 1 or length > MAX_FRAME:
            raise ValueError(f"invalid private protocol frame length: {length}")
        body = recv_exact(self.sock, length)
        return FrameType(body[0]), body[1:]


def pack_register(identifier: str) -> bytes:
    return string(identifier)


def unpack_register(payload: bytes) -> str:
    reader = Reader(payload)
    identifier = reader.text()
    reader.eof()
    return identifier


def pack_register_result(ok: bool, message: str) -> bytes:
    return boolean(ok) + string(message)


def unpack_register_result(payload: bytes) -> tuple[bool, str]:
    reader = Reader(payload)
    ok = reader.boolean()
    message = reader.text()
    reader.eof()
    return ok, message


def pack_auth_request(auth_id: int, username: str, fingerprint: str, key_blob: bytes) -> bytes:
    return uint32(auth_id) + string(username) + string(fingerprint) + string(key_blob)


def unpack_auth_request(payload: bytes) -> tuple[int, str, str, bytes]:
    reader = Reader(payload)
    auth_id = reader.uint32()
    username = reader.text()
    fingerprint = reader.text()
    key_blob = reader.string()
    reader.eof()
    return auth_id, username, fingerprint, key_blob


def pack_auth_response(auth_id: int, ok: bool, persist: bool) -> bytes:
    return uint32(auth_id) + boolean(ok) + boolean(persist)


def unpack_auth_response(payload: bytes) -> tuple[int, bool, bool]:
    reader = Reader(payload)
    auth_id = reader.uint32()
    ok = reader.boolean()
    persist = reader.boolean()
    reader.eof()
    return auth_id, ok, persist


def pack_open_channel(channel_id: int, kind: str, extra: dict[str, Any]) -> bytes:
    return uint32(channel_id) + string(kind) + string(json.dumps(extra, separators=(",", ":")))


def unpack_open_channel(payload: bytes) -> tuple[int, str, dict[str, Any]]:
    reader = Reader(payload)
    channel_id = reader.uint32()
    kind = reader.text()
    extra = json.loads(reader.text())
    reader.eof()
    return channel_id, kind, extra


def pack_open_confirm(channel_id: int, ok: bool, message: str = "") -> bytes:
    return uint32(channel_id) + boolean(ok) + string(message)


def unpack_open_confirm(payload: bytes) -> tuple[int, bool, str]:
    reader = Reader(payload)
    channel_id = reader.uint32()
    ok = reader.boolean()
    message = reader.text()
    reader.eof()
    return channel_id, ok, message


def pack_channel_data(channel_id: int, data: bytes) -> bytes:
    return uint32(channel_id) + string(data)


def unpack_channel_data(payload: bytes) -> tuple[int, bytes]:
    reader = Reader(payload)
    channel_id = reader.uint32()
    data = reader.string()
    reader.eof()
    return channel_id, data


def pack_channel_id(channel_id: int) -> bytes:
    return uint32(channel_id)


def unpack_channel_id(payload: bytes) -> int:
    reader = Reader(payload)
    channel_id = reader.uint32()
    reader.eof()
    return channel_id


def pack_channel_request(channel_id: int, request: str, want_reply: bool, payload: bytes) -> bytes:
    return uint32(channel_id) + string(request) + boolean(want_reply) + string(payload)


def unpack_channel_request(payload: bytes) -> tuple[int, str, bool, bytes]:
    reader = Reader(payload)
    channel_id = reader.uint32()
    request = reader.text()
    want_reply = reader.boolean()
    request_payload = reader.string()
    reader.eof()
    return channel_id, request, want_reply, request_payload


def pack_extended_data(channel_id: int, data_type: int, data: bytes) -> bytes:
    return uint32(channel_id) + uint32(data_type) + string(data)


def unpack_extended_data(payload: bytes) -> tuple[int, int, bytes]:
    reader = Reader(payload)
    channel_id = reader.uint32()
    data_type = reader.uint32()
    data = reader.string()
    reader.eof()
    return channel_id, data_type, data
