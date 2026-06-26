from __future__ import annotations

import argparse
import hashlib
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import curve25519, ed25519
from .keys import ed25519_key_blob, load_or_create_host_seed, parse_ed25519_key_blob
from .netutil import listen_socket
from .private_protocol import (
    FrameSocket,
    FrameType,
    pack_auth_request,
    pack_channel_data,
    pack_channel_id,
    pack_channel_request,
    pack_extended_data,
    pack_open_channel,
    pack_register_result,
    unpack_auth_response,
    unpack_channel_data,
    unpack_channel_id,
    unpack_channel_request,
    unpack_extended_data,
    unpack_open_confirm,
    unpack_register,
)
from .ssh_encoding import Reader, boolean, byte, mpint, name_list, public_key_fingerprint, string, uint32
from .ssh_messages import *
from .ssh_packet import OpenSSHChaCha20Poly1305, PacketStream, SSHProtocolError

LOG = logging.getLogger("reverssh.relay")

KEX_ALGORITHMS = ["curve25519-sha256", "curve25519-sha256@libssh.org"]
HOST_KEY_ALGORITHMS = ["ssh-ed25519"]
CIPHERS = ["chacha20-poly1305@openssh.com"]
MACS = ["hmac-sha2-256", "none"]
COMPRESSIONS = ["none"]
SERVER_VERSION = b"SSH-2.0-reverSSH_0.1"
CHANNEL_WINDOW = 2**31 - 1
CHANNEL_MAX_PACKET = 32768


def _first_common(client: list[str], server: list[str], what: str) -> str:
    for alg in client:
        if alg in server:
            return alg
    raise SSHProtocolError(f"no compatible {what}; client offered {client!r}")


def _read_version(sock: socket.socket) -> bytes:
    line = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise EOFError("connection closed before SSH version")
        if ch == b"\n":
            raw = bytes(line).rstrip(b"\r")
            if raw.startswith(b"SSH-"):
                return raw
            line.clear()
            continue
        line.extend(ch)
        if len(line) > 255:
            raise SSHProtocolError("SSH version line too long")


def _derive_key(k_int: int, exchange_hash: bytes, session_id: bytes, letter: bytes, length: int) -> bytes:
    k_bytes = mpint(k_int)
    out = hashlib.sha256(k_bytes + exchange_hash + letter + session_id).digest()
    while len(out) < length:
        out += hashlib.sha256(k_bytes + exchange_hash + out).digest()
    return out[:length]


@dataclass
class PendingValue:
    event: threading.Event = field(default_factory=threading.Event)
    value: Any = None


class ClientRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients: dict[str, RegisteredClient] = {}

    def add(self, identifier: str, client: "RegisteredClient") -> bool:
        with self._lock:
            existing = self._clients.get(identifier)
            if existing and existing.alive:
                return False
            self._clients[identifier] = client
            return True

    def remove(self, identifier: str, client: "RegisteredClient") -> None:
        with self._lock:
            if self._clients.get(identifier) is client:
                del self._clients[identifier]

    def get(self, identifier: str) -> "RegisteredClient | None":
        with self._lock:
            client = self._clients.get(identifier)
            if client and client.alive:
                return client
            return None


class RegisteredClient:
    def __init__(self, registry: ClientRegistry, sock: socket.socket, addr: tuple, identifier: str):
        self.registry = registry
        self.sock = sock
        self.addr = addr
        self.identifier = identifier
        self.frames = FrameSocket(sock)
        self.alive = True
        self._lock = threading.Lock()
        self._auth_counter = 1
        self._channel_counter = 1
        self._pending_auth: dict[int, PendingValue] = {}
        self._pending_open: dict[int, PendingValue] = {}
        self.channels: dict[int, RemoteRelayChannel] = {}

    def start(self) -> None:
        thread = threading.Thread(target=self._reader_loop, name=f"client:{self.identifier}", daemon=True)
        thread.start()

    def close(self) -> None:
        if not self.alive:
            return
        self.alive = False
        self.registry.remove(self.identifier, self)
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        for channel in list(self.channels.values()):
            channel.client_closed()

    def request_auth(self, username: str, fingerprint: str, key_blob: bytes, timeout: float = 300.0) -> bool:
        with self._lock:
            auth_id = self._auth_counter
            self._auth_counter += 1
            pending = PendingValue()
            self._pending_auth[auth_id] = pending
        self.frames.send_frame(FrameType.AUTH_REQUEST, pack_auth_request(auth_id, username, fingerprint, key_blob))
        if not pending.event.wait(timeout):
            LOG.warning("operator approval timed out for %s via %s", username, self.identifier)
            with self._lock:
                self._pending_auth.pop(auth_id, None)
            return False
        return bool(pending.value)

    def open_channel(self, channel: "RemoteRelayChannel", kind: str, extra: dict[str, Any], timeout: float = 30.0) -> tuple[bool, str]:
        with self._lock:
            channel_id = self._channel_counter
            self._channel_counter += 1
            channel.remote_channel_id = channel_id
            self.channels[channel_id] = channel
            pending = PendingValue()
            self._pending_open[channel_id] = pending
        self.frames.send_frame(FrameType.OPEN_CHANNEL, pack_open_channel(channel_id, kind, extra))
        if not pending.event.wait(timeout):
            with self._lock:
                self.channels.pop(channel_id, None)
                self._pending_open.pop(channel_id, None)
            return False, "remote channel open timed out"
        ok, message = pending.value
        if not ok:
            with self._lock:
                self.channels.pop(channel_id, None)
            return False, message
        return True, message

    def send_channel_data(self, channel_id: int, data: bytes) -> None:
        self.frames.send_frame(FrameType.CHANNEL_DATA, pack_channel_data(channel_id, data))

    def send_extended_data(self, channel_id: int, data_type: int, data: bytes) -> None:
        self.frames.send_frame(FrameType.CHANNEL_EXTENDED_DATA, pack_extended_data(channel_id, data_type, data))

    def send_channel_request(self, channel_id: int, request: str, want_reply: bool, payload: bytes) -> None:
        self.frames.send_frame(FrameType.CHANNEL_REQUEST, pack_channel_request(channel_id, request, want_reply, payload))

    def send_channel_eof(self, channel_id: int) -> None:
        self.frames.send_frame(FrameType.CHANNEL_EOF, pack_channel_id(channel_id))

    def send_channel_close(self, channel_id: int) -> None:
        self.frames.send_frame(FrameType.CHANNEL_CLOSE, pack_channel_id(channel_id))

    def forget_channel(self, channel_id: int) -> None:
        with self._lock:
            self.channels.pop(channel_id, None)

    def _reader_loop(self) -> None:
        try:
            while self.alive:
                frame_type, payload = self.frames.read_frame()
                if frame_type == FrameType.AUTH_RESPONSE:
                    auth_id, ok, _persist = unpack_auth_response(payload)
                    pending = self._pending_auth.pop(auth_id, None)
                    if pending:
                        pending.value = ok
                        pending.event.set()
                elif frame_type == FrameType.OPEN_CONFIRM:
                    channel_id, ok, message = unpack_open_confirm(payload)
                    pending = self._pending_open.pop(channel_id, None)
                    if pending:
                        pending.value = (ok, message)
                        pending.event.set()
                elif frame_type == FrameType.CHANNEL_DATA:
                    channel_id, data = unpack_channel_data(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.remote_data(data)
                elif frame_type == FrameType.CHANNEL_EXTENDED_DATA:
                    channel_id, data_type, data = unpack_extended_data(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.remote_extended_data(data_type, data)
                elif frame_type == FrameType.CHANNEL_REQUEST:
                    channel_id, request, want_reply, request_payload = unpack_channel_request(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.remote_request(request, want_reply, request_payload)
                elif frame_type == FrameType.CHANNEL_EOF:
                    channel_id = unpack_channel_id(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.remote_eof()
                elif frame_type == FrameType.CHANNEL_CLOSE:
                    channel_id = unpack_channel_id(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.remote_close()
                elif frame_type == FrameType.HEARTBEAT:
                    continue
        except Exception as exc:
            if self.alive:
                LOG.info("client %s disconnected: %s", self.identifier, exc)
        finally:
            self.close()


class SSHChannelBase:
    def __init__(self, ssh: "SSHConnection", local_id: int):
        self.ssh = ssh
        self.local_id = local_id
        self.recipient: int | None = None
        self.remote_window = 0
        self.remote_max_packet = CHANNEL_MAX_PACKET
        self._window_cond = threading.Condition()
        self._closed = False

    def set_recipient(self, recipient: int, remote_window: int, remote_max_packet: int) -> None:
        with self._window_cond:
            self.recipient = recipient
            self.remote_window = remote_window
            self.remote_max_packet = max(1024, min(remote_max_packet, CHANNEL_MAX_PACKET))
            self._window_cond.notify_all()

    def add_window(self, amount: int) -> None:
        with self._window_cond:
            self.remote_window = min(0xFFFFFFFF, self.remote_window + amount)
            self._window_cond.notify_all()

    def reserve_window(self, size: int) -> int:
        with self._window_cond:
            deadline = time.monotonic() + 60
            while self.remote_window <= 0 and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("SSH channel window wait timed out")
                self._window_cond.wait(remaining)
            if self._closed:
                raise EOFError("channel closed")
            chunk = min(size, self.remote_window, self.remote_max_packet)
            self.remote_window -= chunk
            return chunk

    def mark_closed(self) -> None:
        with self._window_cond:
            self._closed = True
            self._window_cond.notify_all()

    def on_ssh_data(self, data: bytes) -> None:
        raise NotImplementedError

    def on_ssh_extended_data(self, data_type: int, data: bytes) -> None:
        self.on_ssh_data(data)

    def on_ssh_eof(self) -> None:
        pass

    def on_ssh_close(self) -> None:
        self.mark_closed()


class RemoteRelayChannel(SSHChannelBase):
    def __init__(self, ssh: "SSHConnection", local_id: int, client: RegisteredClient):
        super().__init__(ssh, local_id)
        self.client = client
        self.remote_channel_id: int | None = None

    def on_ssh_data(self, data: bytes) -> None:
        if self.remote_channel_id is not None:
            self.client.send_channel_data(self.remote_channel_id, data)

    def on_ssh_extended_data(self, data_type: int, data: bytes) -> None:
        if self.remote_channel_id is not None:
            self.client.send_extended_data(self.remote_channel_id, data_type, data)

    def on_ssh_eof(self) -> None:
        if self.remote_channel_id is not None:
            self.client.send_channel_eof(self.remote_channel_id)

    def on_ssh_close(self) -> None:
        super().on_ssh_close()
        if self.remote_channel_id is not None:
            self.client.send_channel_close(self.remote_channel_id)
            self.client.forget_channel(self.remote_channel_id)

    def remote_data(self, data: bytes) -> None:
        self.ssh.send_channel_data(self, data)

    def remote_extended_data(self, data_type: int, data: bytes) -> None:
        self.ssh.send_channel_extended_data(self, data_type, data)

    def remote_request(self, request: str, want_reply: bool, payload: bytes) -> None:
        self.ssh.send_channel_request(self, request, want_reply, payload)

    def remote_eof(self) -> None:
        self.ssh.send_channel_eof(self)

    def remote_close(self) -> None:
        self.mark_closed()
        self.ssh.send_channel_close(self)
        if self.remote_channel_id is not None:
            self.client.forget_channel(self.remote_channel_id)

    def client_closed(self) -> None:
        self.remote_close()


class TCPForwardedChannel(SSHChannelBase):
    def __init__(self, ssh: "SSHConnection", local_id: int, tcp_sock: socket.socket):
        super().__init__(ssh, local_id)
        self.tcp_sock = tcp_sock
        self.open_event = threading.Event()
        self.open_ok = False
        self.open_message = ""

    def set_open_result(self, ok: bool, message: str = "") -> None:
        self.open_ok = ok
        self.open_message = message
        self.open_event.set()

    def start_reader(self) -> None:
        thread = threading.Thread(target=self._reader_loop, name=f"forward:{self.local_id}", daemon=True)
        thread.start()

    def _reader_loop(self) -> None:
        try:
            while True:
                data = self.tcp_sock.recv(CHANNEL_MAX_PACKET)
                if not data:
                    break
                self.ssh.send_channel_data(self, data)
        except OSError:
            pass
        finally:
            self.ssh.send_channel_eof(self)
            self.ssh.send_channel_close(self)

    def on_ssh_data(self, data: bytes) -> None:
        self.tcp_sock.sendall(data)

    def on_ssh_close(self) -> None:
        super().on_ssh_close()
        try:
            self.tcp_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.tcp_sock.close()
        except OSError:
            pass


class ForwardListener:
    def __init__(self, ssh: "SSHConnection", bind_address: str, bind_port: int):
        self.ssh = ssh
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.sock: socket.socket | None = None
        self.alive = False

    def start(self) -> int:
        host = self._map_bind_address(self.bind_address)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, self.bind_port))
        sock.listen(100)
        self.sock = sock
        self.alive = True
        thread = threading.Thread(target=self._accept_loop, name=f"tcpip-forward:{sock.getsockname()}", daemon=True)
        thread.start()
        return sock.getsockname()[1]

    def close(self) -> None:
        self.alive = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self.sock is not None
        while self.alive:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn: socket.socket, addr: tuple) -> None:
        channel = self.ssh.create_forwarded_channel(conn)
        connected_address = self.bind_address or "0.0.0.0"
        connected_port = self.sock.getsockname()[1] if self.sock else self.bind_port
        origin_host = addr[0]
        origin_port = addr[1]
        payload = (
            byte(SSH_MSG_CHANNEL_OPEN)
            + string("forwarded-tcpip")
            + uint32(channel.local_id)
            + uint32(CHANNEL_WINDOW)
            + uint32(CHANNEL_MAX_PACKET)
            + string(connected_address)
            + uint32(connected_port)
            + string(origin_host)
            + uint32(origin_port)
        )
        self.ssh.send_payload(payload)
        if not channel.open_event.wait(30) or not channel.open_ok:
            channel.on_ssh_close()
            return
        channel.start_reader()

    @staticmethod
    def _map_bind_address(bind_address: str) -> str:
        if bind_address in ("", "*"):
            return "0.0.0.0"
        if bind_address == "localhost":
            return "127.0.0.1"
        return bind_address


class SSHConnection:
    def __init__(self, sock: socket.socket, addr: tuple, registry: ClientRegistry, host_seed: bytes):
        self.sock = sock
        self.addr = addr
        self.registry = registry
        self.host_seed = host_seed
        self.host_public = ed25519.public_from_seed(host_seed)
        self.host_key_blob = ed25519_key_blob(self.host_public)
        self.stream = PacketStream(sock)
        self.send_lock = threading.Lock()
        self.next_channel_id = 0
        self.channels: dict[int, SSHChannelBase] = {}
        self.forwards: dict[tuple[str, int], ForwardListener] = {}
        self.session_id: bytes | None = None
        self.identifier = ""
        self.client: RegisteredClient | None = None
        self.client_version = b""
        self.server_kexinit = b""
        self.client_kexinit = b""

    def run(self) -> None:
        try:
            self._version_exchange()
            self._key_exchange()
            self._authenticate()
            self._connection_loop()
        except EOFError:
            LOG.info("SSH client %s disconnected", self.addr)
        except Exception as exc:
            LOG.info("SSH connection %s ended: %s", self.addr, exc)
            try:
                self._disconnect(str(exc))
            except Exception:
                pass
        finally:
            for listener in list(self.forwards.values()):
                listener.close()
            try:
                self.sock.close()
            except OSError:
                pass

    def send_payload(self, payload: bytes) -> None:
        with self.send_lock:
            self.stream.send_packet(payload)

    def _version_exchange(self) -> None:
        self.sock.sendall(SERVER_VERSION + b"\r\n")
        self.client_version = _read_version(self.sock)
        LOG.debug("SSH version from %s: %s", self.addr, self.client_version.decode(errors="replace"))

    def _make_kexinit(self) -> bytes:
        return (
            byte(SSH_MSG_KEXINIT)
            + os.urandom(16)
            + name_list(KEX_ALGORITHMS)
            + name_list(HOST_KEY_ALGORITHMS)
            + name_list(CIPHERS)
            + name_list(CIPHERS)
            + name_list(MACS)
            + name_list(MACS)
            + name_list(COMPRESSIONS)
            + name_list(COMPRESSIONS)
            + name_list([])
            + name_list([])
            + boolean(False)
            + uint32(0)
        )

    def _parse_kexinit(self, payload: bytes) -> dict[str, list[str]]:
        reader = Reader(payload)
        msg = reader.byte()
        if msg != SSH_MSG_KEXINIT:
            raise SSHProtocolError("expected KEXINIT")
        reader.take(16)
        result = {
            "kex": reader.name_list(),
            "hostkey": reader.name_list(),
            "c2s_cipher": reader.name_list(),
            "s2c_cipher": reader.name_list(),
            "c2s_mac": reader.name_list(),
            "s2c_mac": reader.name_list(),
            "c2s_compression": reader.name_list(),
            "s2c_compression": reader.name_list(),
        }
        reader.name_list()
        reader.name_list()
        reader.boolean()
        reader.uint32()
        reader.eof()
        return result

    def _key_exchange(self) -> None:
        self.server_kexinit = self._make_kexinit()
        self.send_payload(self.server_kexinit)
        while True:
            payload = self.stream.read_packet()
            if payload[0] == SSH_MSG_KEXINIT:
                self.client_kexinit = payload
                break
            if payload[0] not in (SSH_MSG_IGNORE, SSH_MSG_DEBUG):
                raise SSHProtocolError(f"expected KEXINIT, got {payload[0]}")
        offered = self._parse_kexinit(self.client_kexinit)
        _first_common(offered["kex"], KEX_ALGORITHMS, "key exchange")
        _first_common(offered["hostkey"], HOST_KEY_ALGORITHMS, "host key")
        _first_common(offered["c2s_cipher"], CIPHERS, "client-to-server cipher")
        _first_common(offered["s2c_cipher"], CIPHERS, "server-to-client cipher")
        _first_common(offered["c2s_compression"], COMPRESSIONS, "client-to-server compression")
        _first_common(offered["s2c_compression"], COMPRESSIONS, "server-to-client compression")

        payload = self.stream.read_packet()
        reader = Reader(payload)
        if reader.byte() != SSH_MSG_KEX_ECDH_INIT:
            raise SSHProtocolError("expected ECDH init")
        client_public = reader.string()
        reader.eof()
        if len(client_public) != 32:
            raise SSHProtocolError("invalid Curve25519 client public key length")

        server_private = os.urandom(32)
        server_public = curve25519.public_from_private(server_private)
        secret_bytes = curve25519.x25519(server_private, client_public)
        if secret_bytes == b"\x00" * 32:
            raise SSHProtocolError("invalid all-zero Curve25519 shared secret")
        k_int = int.from_bytes(secret_bytes, "big")
        exchange_hash = hashlib.sha256(
            string(self.client_version)
            + string(SERVER_VERSION)
            + string(self.client_kexinit)
            + string(self.server_kexinit)
            + string(self.host_key_blob)
            + string(client_public)
            + string(server_public)
            + mpint(k_int)
        ).digest()
        if self.session_id is None:
            self.session_id = exchange_hash
        signature = string("ssh-ed25519") + string(ed25519.sign(self.host_seed, exchange_hash))
        self.send_payload(
            byte(SSH_MSG_KEX_ECDH_REPLY)
            + string(self.host_key_blob)
            + string(server_public)
            + string(signature)
        )
        c2s_key = _derive_key(k_int, exchange_hash, self.session_id, b"C", 64)
        s2c_key = _derive_key(k_int, exchange_hash, self.session_id, b"D", 64)
        self.send_payload(byte(SSH_MSG_NEWKEYS))
        self.stream.set_send_cipher(OpenSSHChaCha20Poly1305(s2c_key))
        newkeys = self.stream.read_packet()
        if newkeys != byte(SSH_MSG_NEWKEYS):
            raise SSHProtocolError("expected NEWKEYS")
        self.stream.set_recv_cipher(OpenSSHChaCha20Poly1305(c2s_key))

    def _authenticate(self) -> None:
        while True:
            payload = self.stream.read_packet()
            reader = Reader(payload)
            msg = reader.byte()
            if msg == SSH_MSG_SERVICE_REQUEST:
                service = reader.text()
                if service != "ssh-userauth":
                    raise SSHProtocolError(f"unsupported service: {service}")
                self.send_payload(byte(SSH_MSG_SERVICE_ACCEPT) + string(service))
                break
            if msg not in (SSH_MSG_IGNORE, SSH_MSG_DEBUG):
                raise SSHProtocolError(f"expected service request, got {msg}")

        while True:
            payload = self.stream.read_packet()
            reader = Reader(payload)
            msg = reader.byte()
            if msg != SSH_MSG_USERAUTH_REQUEST:
                raise SSHProtocolError(f"expected userauth request, got {msg}")
            username = reader.text()
            service = reader.text()
            method = reader.text()
            if service != "ssh-connection":
                self._auth_failure()
                continue
            if method != "publickey":
                self._auth_failure()
                continue
            has_signature = reader.boolean()
            key_alg = reader.text()
            key_blob = reader.string()
            if key_alg != "ssh-ed25519":
                self._auth_failure()
                continue
            if not has_signature:
                self.send_payload(byte(SSH_MSG_USERAUTH_PK_OK) + string(key_alg) + string(key_blob))
                continue
            sig_blob = reader.string()
            reader.eof()
            if self._verify_user_signature(username, service, key_alg, key_blob, sig_blob):
                client = self.registry.get(username)
                if not client:
                    LOG.info("no reverse client registered for identifier %s", username)
                    self._auth_failure()
                    continue
                fingerprint = public_key_fingerprint(key_blob)
                LOG.info("operator %s asks for %s with %s", self.addr, username, fingerprint)
                if client.request_auth(username, fingerprint, key_blob):
                    self.identifier = username
                    self.client = client
                    self.send_payload(byte(SSH_MSG_USERAUTH_SUCCESS))
                    return
                LOG.info("remote client rejected operator %s for %s", fingerprint, username)
            self._auth_failure()

    def _verify_user_signature(self, username: str, service: str, key_alg: str, key_blob: bytes, sig_blob: bytes) -> bool:
        if self.session_id is None:
            raise SSHProtocolError("missing SSH session id")
        try:
            public = parse_ed25519_key_blob(key_blob)
            sig_reader = Reader(sig_blob)
            sig_alg = sig_reader.text()
            signature = sig_reader.string()
            sig_reader.eof()
            if sig_alg != "ssh-ed25519":
                return False
        except Exception:
            return False
        signed = (
            string(self.session_id)
            + byte(SSH_MSG_USERAUTH_REQUEST)
            + string(username)
            + string(service)
            + string("publickey")
            + boolean(True)
            + string(key_alg)
            + string(key_blob)
        )
        return ed25519.verify(public, signed, signature)

    def _auth_failure(self) -> None:
        self.send_payload(byte(SSH_MSG_USERAUTH_FAILURE) + name_list(["publickey"]) + boolean(False))

    def _connection_loop(self) -> None:
        while True:
            payload = self.stream.read_packet()
            reader = Reader(payload)
            msg = reader.byte()
            if msg == SSH_MSG_GLOBAL_REQUEST:
                self._handle_global_request(reader)
            elif msg == SSH_MSG_CHANNEL_OPEN:
                self._handle_channel_open(reader)
            elif msg == SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                self._handle_open_confirmation(reader)
            elif msg == SSH_MSG_CHANNEL_OPEN_FAILURE:
                self._handle_open_failure(reader)
            elif msg == SSH_MSG_CHANNEL_WINDOW_ADJUST:
                local_id = reader.uint32()
                amount = reader.uint32()
                channel = self.channels.get(local_id)
                if channel:
                    channel.add_window(amount)
            elif msg == SSH_MSG_CHANNEL_DATA:
                local_id = reader.uint32()
                data = reader.string()
                channel = self.channels.get(local_id)
                if channel:
                    channel.on_ssh_data(data)
                    self._adjust_local_window(channel, len(data))
            elif msg == SSH_MSG_CHANNEL_EXTENDED_DATA:
                local_id = reader.uint32()
                data_type = reader.uint32()
                data = reader.string()
                channel = self.channels.get(local_id)
                if channel:
                    channel.on_ssh_extended_data(data_type, data)
                    self._adjust_local_window(channel, len(data))
            elif msg == SSH_MSG_CHANNEL_EOF:
                local_id = reader.uint32()
                channel = self.channels.get(local_id)
                if channel:
                    channel.on_ssh_eof()
            elif msg == SSH_MSG_CHANNEL_CLOSE:
                local_id = reader.uint32()
                channel = self.channels.pop(local_id, None)
                if channel:
                    channel.on_ssh_close()
                    if channel.recipient is not None:
                        self.send_payload(byte(SSH_MSG_CHANNEL_CLOSE) + uint32(channel.recipient))
            elif msg == SSH_MSG_CHANNEL_REQUEST:
                self._handle_channel_request(reader)
            elif msg in (SSH_MSG_IGNORE, SSH_MSG_DEBUG):
                continue
            else:
                self.send_payload(byte(SSH_MSG_UNIMPLEMENTED) + uint32((self.stream.recv_sequence - 1) & 0xFFFFFFFF))

    def _handle_global_request(self, reader: Reader) -> None:
        request = reader.text()
        want_reply = reader.boolean()
        rest = reader.take(reader.remaining())
        if request == "tcpip-forward":
            r = Reader(rest)
            bind_address = r.text()
            bind_port = r.uint32()
            try:
                listener = ForwardListener(self, bind_address, bind_port)
                actual_port = listener.start()
                self.forwards[(bind_address, bind_port)] = listener
                if want_reply:
                    payload = byte(SSH_MSG_REQUEST_SUCCESS)
                    if bind_port == 0:
                        payload += uint32(actual_port)
                    self.send_payload(payload)
                LOG.info("enabled tcpip-forward %s:%s for %s", bind_address, actual_port, self.addr)
            except OSError as exc:
                LOG.info("tcpip-forward failed for %s:%s: %s", bind_address, bind_port, exc)
                if want_reply:
                    self.send_payload(byte(SSH_MSG_REQUEST_FAILURE))
        elif request == "cancel-tcpip-forward":
            r = Reader(rest)
            bind_address = r.text()
            bind_port = r.uint32()
            listener = self.forwards.pop((bind_address, bind_port), None)
            if listener:
                listener.close()
            if want_reply:
                self.send_payload(byte(SSH_MSG_REQUEST_SUCCESS))
        elif request in ("keepalive@openssh.com", "no-more-sessions@openssh.com"):
            if want_reply:
                self.send_payload(byte(SSH_MSG_REQUEST_SUCCESS))
        else:
            if want_reply:
                self.send_payload(byte(SSH_MSG_REQUEST_FAILURE))

    def _handle_channel_open(self, reader: Reader) -> None:
        channel_type = reader.text()
        sender_channel = reader.uint32()
        sender_window = reader.uint32()
        sender_max_packet = reader.uint32()
        if not self.client:
            self._channel_open_failure(sender_channel, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "not authenticated")
            return
        if channel_type == "session":
            kind = "session"
            extra: dict[str, Any] = {}
        elif channel_type == "direct-tcpip":
            target_host = reader.text()
            target_port = reader.uint32()
            origin_host = reader.text()
            origin_port = reader.uint32()
            kind = "direct-tcpip"
            extra = {
                "target_host": target_host,
                "target_port": target_port,
                "origin_host": origin_host,
                "origin_port": origin_port,
            }
        else:
            self._channel_open_failure(sender_channel, SSH_OPEN_UNKNOWN_CHANNEL_TYPE, f"unsupported channel type: {channel_type}")
            return
        local_id = self._next_channel_id()
        channel = RemoteRelayChannel(self, local_id, self.client)
        ok, message = self.client.open_channel(channel, kind, extra)
        if not ok:
            self._channel_open_failure(sender_channel, SSH_OPEN_CONNECT_FAILED, message)
            return
        channel.set_recipient(sender_channel, sender_window, sender_max_packet)
        self.channels[local_id] = channel
        self.send_payload(
            byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
            + uint32(sender_channel)
            + uint32(local_id)
            + uint32(CHANNEL_WINDOW)
            + uint32(CHANNEL_MAX_PACKET)
        )

    def _handle_channel_request(self, reader: Reader) -> None:
        local_id = reader.uint32()
        request = reader.text()
        want_reply = reader.boolean()
        rest = reader.take(reader.remaining())
        channel = self.channels.get(local_id)
        if not channel:
            if want_reply:
                self.send_payload(byte(SSH_MSG_CHANNEL_FAILURE) + uint32(local_id))
            return
        if isinstance(channel, RemoteRelayChannel) and channel.remote_channel_id is not None:
            channel.client.send_channel_request(channel.remote_channel_id, request, want_reply, rest)
            if want_reply and request in {
                "pty-req",
                "env",
                "shell",
                "exec",
                "subsystem",
                "window-change",
                "signal",
            }:
                self.send_payload(byte(SSH_MSG_CHANNEL_SUCCESS) + uint32(channel.recipient))
            elif want_reply:
                self.send_payload(byte(SSH_MSG_CHANNEL_FAILURE) + uint32(channel.recipient))
        else:
            if want_reply and channel.recipient is not None:
                self.send_payload(byte(SSH_MSG_CHANNEL_FAILURE) + uint32(channel.recipient))

    def _handle_open_confirmation(self, reader: Reader) -> None:
        local_id = reader.uint32()
        sender_channel = reader.uint32()
        sender_window = reader.uint32()
        sender_max_packet = reader.uint32()
        channel = self.channels.get(local_id)
        if channel:
            channel.set_recipient(sender_channel, sender_window, sender_max_packet)
            if isinstance(channel, TCPForwardedChannel):
                channel.set_open_result(True)

    def _handle_open_failure(self, reader: Reader) -> None:
        local_id = reader.uint32()
        reason = reader.uint32()
        message = reader.text()
        _language = reader.text()
        channel = self.channels.pop(local_id, None)
        if isinstance(channel, TCPForwardedChannel):
            channel.set_open_result(False, f"{reason}: {message}")

    def _adjust_local_window(self, channel: SSHChannelBase, amount: int) -> None:
        if channel.recipient is not None and amount:
            self.send_payload(byte(SSH_MSG_CHANNEL_WINDOW_ADJUST) + uint32(channel.recipient) + uint32(amount))

    def send_channel_data(self, channel: SSHChannelBase, data: bytes) -> None:
        if channel.recipient is None:
            return
        pos = 0
        while pos < len(data):
            size = channel.reserve_window(len(data) - pos)
            chunk = data[pos : pos + size]
            self.send_payload(byte(SSH_MSG_CHANNEL_DATA) + uint32(channel.recipient) + string(chunk))
            pos += size

    def send_channel_extended_data(self, channel: SSHChannelBase, data_type: int, data: bytes) -> None:
        if channel.recipient is None:
            return
        pos = 0
        while pos < len(data):
            size = channel.reserve_window(len(data) - pos)
            chunk = data[pos : pos + size]
            self.send_payload(
                byte(SSH_MSG_CHANNEL_EXTENDED_DATA) + uint32(channel.recipient) + uint32(data_type) + string(chunk)
            )
            pos += size

    def send_channel_request(self, channel: SSHChannelBase, request: str, want_reply: bool, payload: bytes) -> None:
        if channel.recipient is not None:
            self.send_payload(
                byte(SSH_MSG_CHANNEL_REQUEST) + uint32(channel.recipient) + string(request) + boolean(want_reply) + payload
            )

    def send_channel_eof(self, channel: SSHChannelBase) -> None:
        if channel.recipient is not None:
            self.send_payload(byte(SSH_MSG_CHANNEL_EOF) + uint32(channel.recipient))

    def send_channel_close(self, channel: SSHChannelBase) -> None:
        if channel.recipient is not None:
            channel.mark_closed()
            self.channels.pop(channel.local_id, None)
            self.send_payload(byte(SSH_MSG_CHANNEL_CLOSE) + uint32(channel.recipient))

    def create_forwarded_channel(self, tcp_sock: socket.socket) -> TCPForwardedChannel:
        local_id = self._next_channel_id()
        channel = TCPForwardedChannel(self, local_id, tcp_sock)
        self.channels[local_id] = channel
        return channel

    def _channel_open_failure(self, recipient: int, reason: int, message: str) -> None:
        self.send_payload(
            byte(SSH_MSG_CHANNEL_OPEN_FAILURE) + uint32(recipient) + uint32(reason) + string(message) + string("")
        )

    def _next_channel_id(self) -> int:
        channel_id = self.next_channel_id
        self.next_channel_id += 1
        return channel_id

    def _disconnect(self, message: str) -> None:
        self.send_payload(byte(SSH_MSG_DISCONNECT) + uint32(11) + string(message) + string(""))


class RelayServer:
    def __init__(self, ssh_listen: str, client_listen: str, state_dir: Path):
        self.ssh_listen = ssh_listen
        self.client_listen = client_listen
        self.state_dir = state_dir
        self.registry = ClientRegistry()
        self.host_seed = load_or_create_host_seed(state_dir)

    def serve_forever(self) -> None:
        ssh_sock = listen_socket(self.ssh_listen)
        client_sock = listen_socket(self.client_listen)
        LOG.info("relay SSH listening on %s", ssh_sock.getsockname())
        LOG.info("relay client protocol listening on %s", client_sock.getsockname())
        threading.Thread(target=self._accept_reverse_clients, args=(client_sock,), daemon=True).start()
        while True:
            conn, addr = ssh_sock.accept()
            thread = threading.Thread(target=self._handle_ssh, args=(conn, addr), daemon=True)
            thread.start()

    def _accept_reverse_clients(self, listen_sock: socket.socket) -> None:
        while True:
            conn, addr = listen_sock.accept()
            threading.Thread(target=self._handle_reverse_client, args=(conn, addr), daemon=True).start()

    def _handle_reverse_client(self, conn: socket.socket, addr: tuple) -> None:
        frames = FrameSocket(conn)
        try:
            frame_type, payload = frames.read_frame()
            if frame_type != FrameType.REGISTER:
                frames.send_frame(FrameType.REGISTER_RESULT, pack_register_result(False, "first frame must register identifier"))
                conn.close()
                return
            identifier = unpack_register(payload)
            if not identifier or any(ch.isspace() for ch in identifier):
                frames.send_frame(FrameType.REGISTER_RESULT, pack_register_result(False, "invalid identifier"))
                conn.close()
                return
            client = RegisteredClient(self.registry, conn, addr, identifier)
            if not self.registry.add(identifier, client):
                LOG.warning("duplicate reverse client identifier %s from %s rejected", identifier, addr)
                frames.send_frame(FrameType.REGISTER_RESULT, pack_register_result(False, "identifier already registered"))
                conn.close()
                return
            frames.send_frame(FrameType.REGISTER_RESULT, pack_register_result(True, "registered"))
            LOG.info("reverse client %s registered from %s", identifier, addr)
            client.start()
        except Exception as exc:
            LOG.info("reverse client handshake failed from %s: %s", addr, exc)
            try:
                conn.close()
            except OSError:
                pass

    def _handle_ssh(self, conn: socket.socket, addr: tuple) -> None:
        SSHConnection(conn, addr, self.registry, self.host_seed).run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a reverSSH relay")
    parser.add_argument("--ssh-listen", default="0.0.0.0:2222", help="OpenSSH listen address")
    parser.add_argument("--client-listen", default="0.0.0.0:8022", help="reverse client listen address")
    parser.add_argument("--state-dir", default="./state", help="relay state directory")
    parser.add_argument("--log-level", default="INFO", help="Python logging level")
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    RelayServer(args.ssh_listen, args.client_listen, Path(args.state_dir)).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
