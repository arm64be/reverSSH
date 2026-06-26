from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

from .crypto.chacha import chacha20_block, chacha20_xor
from .crypto.poly1305 import poly1305_mac


class SSHProtocolError(Exception):
    pass


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise EOFError("connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


@dataclass
class OpenSSHChaCha20Poly1305:
    key_material: bytes

    def __post_init__(self) -> None:
        if len(self.key_material) != 64:
            raise ValueError("chacha20-poly1305@openssh.com requires 64 key bytes")
        # OpenSSH names these K_2 then K_1 in the exported SSH key material.
        self.payload_key = self.key_material[:32]
        self.length_key = self.key_material[32:]

    def encrypt_packet(self, sequence: int, plain_packet: bytes) -> bytes:
        nonce = struct.pack(">Q", sequence)
        encrypted_length = chacha20_xor(self.length_key, nonce, 0, plain_packet[:4])
        poly_key = chacha20_block(self.payload_key, nonce, 0)[:32]
        encrypted_payload = chacha20_xor(self.payload_key, nonce, 1, plain_packet[4:])
        tag = poly1305_mac(encrypted_length + encrypted_payload, poly_key)
        return encrypted_length + encrypted_payload + tag

    def decrypt_packet(self, sequence: int, encrypted: bytes) -> bytes:
        if len(encrypted) < 20:
            raise SSHProtocolError("encrypted packet too short")
        nonce = struct.pack(">Q", sequence)
        encrypted_length = encrypted[:4]
        encrypted_payload = encrypted[4:-16]
        received_tag = encrypted[-16:]
        poly_key = chacha20_block(self.payload_key, nonce, 0)[:32]
        expected_tag = poly1305_mac(encrypted_length + encrypted_payload, poly_key)
        if not _constant_time_equal(received_tag, expected_tag):
            raise SSHProtocolError("invalid packet authentication tag")
        packet_length = chacha20_xor(self.length_key, nonce, 0, encrypted_length)
        payload = chacha20_xor(self.payload_key, nonce, 1, encrypted_payload)
        return packet_length + payload

    def decrypt_length(self, sequence: int, encrypted_length: bytes) -> int:
        if len(encrypted_length) != 4:
            raise ValueError("encrypted packet length must be 4 bytes")
        nonce = struct.pack(">Q", sequence)
        packet_length = chacha20_xor(self.length_key, nonce, 0, encrypted_length)
        return struct.unpack(">I", packet_length)[0]


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


class PacketStream:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.send_sequence = 0
        self.recv_sequence = 0
        self.send_cipher: OpenSSHChaCha20Poly1305 | None = None
        self.recv_cipher: OpenSSHChaCha20Poly1305 | None = None

    def set_send_cipher(self, cipher: OpenSSHChaCha20Poly1305) -> None:
        self.send_cipher = cipher

    def set_recv_cipher(self, cipher: OpenSSHChaCha20Poly1305) -> None:
        self.recv_cipher = cipher

    def send_packet(self, payload: bytes) -> None:
        packet = self._build_plain_packet(payload, aead=bool(self.send_cipher))
        if self.send_cipher:
            wire = self.send_cipher.encrypt_packet(self.send_sequence, packet)
        else:
            wire = packet
        self.sock.sendall(wire)
        self.send_sequence = (self.send_sequence + 1) & 0xFFFFFFFF

    def read_packet(self) -> bytes:
        if self.recv_cipher:
            first = recv_exact(self.sock, 4)
            packet_length = self.recv_cipher.decrypt_length(self.recv_sequence, first)
            if packet_length < 5 or packet_length > 256 * 1024:
                raise SSHProtocolError(f"invalid encrypted packet length: {packet_length}")
            rest = recv_exact(self.sock, packet_length + 16)
            plain = self.recv_cipher.decrypt_packet(self.recv_sequence, first + rest)
        else:
            first = recv_exact(self.sock, 4)
            packet_length = struct.unpack(">I", first)[0]
            if packet_length < 5 or packet_length > 256 * 1024:
                raise SSHProtocolError(f"invalid packet length: {packet_length}")
            plain = first + recv_exact(self.sock, packet_length)
        self.recv_sequence = (self.recv_sequence + 1) & 0xFFFFFFFF
        packet_length = struct.unpack(">I", plain[:4])[0]
        body = plain[4 : 4 + packet_length]
        padding_length = body[0]
        if padding_length < 4 or padding_length >= packet_length:
            raise SSHProtocolError("invalid SSH packet padding")
        return body[1 : packet_length - padding_length]

    @staticmethod
    def _build_plain_packet(payload: bytes, aead: bool = False) -> bytes:
        block_size = 8
        padding_length = 4
        alignment_extra = 0 if aead else 4
        while (len(payload) + 1 + padding_length + alignment_extra) % block_size:
            padding_length += 1
        packet_length = len(payload) + 1 + padding_length
        return struct.pack(">I", packet_length) + bytes([padding_length]) + payload + os.urandom(
            padding_length
        )
