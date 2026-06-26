from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux target, kept for import clarity.
    fcntl = None  # type: ignore[assignment]

from .netutil import parse_host_port
from .private_protocol import (
    FrameSocket,
    FrameType,
    pack_auth_response,
    pack_channel_data,
    pack_channel_id,
    pack_channel_request,
    pack_extended_data,
    pack_open_confirm,
    pack_register,
    unpack_auth_request,
    unpack_channel_data,
    unpack_channel_id,
    unpack_channel_request,
    unpack_extended_data,
    unpack_open_channel,
    unpack_register_result,
)
from .sftp import SFTPServer
from .ssh_encoding import Reader, uint32
from .ssh_messages import EXTENDED_DATA_STDERR

LOG = logging.getLogger("reverssh.client")
CHANNEL_MAX_PACKET = 32768


class KnownOperators:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def contains(self, fingerprint: str) -> bool:
        with self._lock:
            if not self.path.exists():
                return False
            for line in self.path.read_text().splitlines():
                value = line.strip()
                if value and not value.startswith("#") and value == fingerprint:
                    return True
            return False

    def add(self, fingerprint: str) -> None:
        with self._lock:
            existing = set()
            if self.path.exists():
                existing = {line.strip() for line in self.path.read_text().splitlines() if line.strip()}
            if fingerprint in existing:
                return
            with self.path.open("a") as handle:
                handle.write(fingerprint + "\n")
            self.path.chmod(0o600)


class ReverseClientConnection:
    def __init__(self, sock: socket.socket, identifier: str, shell: str, known: KnownOperators):
        self.sock = sock
        self.identifier = identifier
        self.shell = shell
        self.known = known
        self.frames = FrameSocket(sock)
        self.channels: dict[int, ClientChannelBase] = {}
        self.alive = True

    def register(self) -> bool:
        self.frames.send_frame(FrameType.REGISTER, pack_register(self.identifier))
        frame_type, payload = self.frames.read_frame()
        if frame_type != FrameType.REGISTER_RESULT:
            raise RuntimeError("relay did not send registration result")
        ok, message = unpack_register_result(payload)
        if ok:
            LOG.info("registered identifier %s", self.identifier)
            return True
        LOG.error("registration rejected: %s", message)
        return False

    def run(self) -> None:
        try:
            while self.alive:
                frame_type, payload = self.frames.read_frame()
                if frame_type == FrameType.AUTH_REQUEST:
                    auth_id, username, fingerprint, _key_blob = unpack_auth_request(payload)
                    ok, persist = self._approve_operator(username, fingerprint)
                    if ok and persist:
                        self.known.add(fingerprint)
                    self.frames.send_frame(FrameType.AUTH_RESPONSE, pack_auth_response(auth_id, ok, persist))
                elif frame_type == FrameType.OPEN_CHANNEL:
                    self._handle_open_channel(payload)
                elif frame_type == FrameType.CHANNEL_DATA:
                    channel_id, data = unpack_channel_data(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.on_data(data)
                elif frame_type == FrameType.CHANNEL_EXTENDED_DATA:
                    channel_id, data_type, data = unpack_extended_data(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.on_extended_data(data_type, data)
                elif frame_type == FrameType.CHANNEL_REQUEST:
                    channel_id, request, want_reply, request_payload = unpack_channel_request(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.on_request(request, want_reply, request_payload)
                elif frame_type == FrameType.CHANNEL_EOF:
                    channel_id = unpack_channel_id(payload)
                    channel = self.channels.get(channel_id)
                    if channel:
                        channel.on_eof()
                elif frame_type == FrameType.CHANNEL_CLOSE:
                    channel_id = unpack_channel_id(payload)
                    channel = self.channels.pop(channel_id, None)
                    if channel:
                        channel.on_close(send_close=False)
                elif frame_type == FrameType.HEARTBEAT:
                    continue
        finally:
            self.alive = False
            for channel in list(self.channels.values()):
                channel.on_close(send_close=False)

    def send_channel_data(self, channel_id: int, data: bytes) -> None:
        for pos in range(0, len(data), CHANNEL_MAX_PACKET):
            self.frames.send_frame(FrameType.CHANNEL_DATA, pack_channel_data(channel_id, data[pos : pos + CHANNEL_MAX_PACKET]))

    def send_extended_data(self, channel_id: int, data_type: int, data: bytes) -> None:
        for pos in range(0, len(data), CHANNEL_MAX_PACKET):
            self.frames.send_frame(
                FrameType.CHANNEL_EXTENDED_DATA,
                pack_extended_data(channel_id, data_type, data[pos : pos + CHANNEL_MAX_PACKET]),
            )

    def send_channel_request(self, channel_id: int, request: str, payload: bytes = b"") -> None:
        self.frames.send_frame(FrameType.CHANNEL_REQUEST, pack_channel_request(channel_id, request, False, payload))

    def send_channel_eof(self, channel_id: int) -> None:
        self.frames.send_frame(FrameType.CHANNEL_EOF, pack_channel_id(channel_id))

    def send_channel_close(self, channel_id: int) -> None:
        self.frames.send_frame(FrameType.CHANNEL_CLOSE, pack_channel_id(channel_id))
        self.channels.pop(channel_id, None)

    def _handle_open_channel(self, payload: bytes) -> None:
        channel_id, kind, extra = unpack_open_channel(payload)
        if kind == "session":
            channel = SessionChannel(self, channel_id, self.shell)
            self.channels[channel_id] = channel
            self.frames.send_frame(FrameType.OPEN_CONFIRM, pack_open_confirm(channel_id, True, "session opened"))
        elif kind == "direct-tcpip":
            channel = DirectTCPChannel(self, channel_id, extra)
            ok, message = channel.open()
            if ok:
                self.channels[channel_id] = channel
            self.frames.send_frame(FrameType.OPEN_CONFIRM, pack_open_confirm(channel_id, ok, message))
            if ok:
                channel.start_reader()
        else:
            self.frames.send_frame(FrameType.OPEN_CONFIRM, pack_open_confirm(channel_id, False, f"unsupported channel type {kind}"))

    def _approve_operator(self, username: str, fingerprint: str) -> tuple[bool, bool]:
        if self.known.contains(fingerprint):
            LOG.info("trusted operator %s approved for %s", fingerprint, username)
            return True, False
        if not sys.stdin.isatty():
            LOG.warning("rejecting unknown operator %s for %s; stdin is not interactive", fingerprint, username)
            return False, False
        print("", file=sys.stderr)
        print(f"reverSSH operator request for identifier '{username}'", file=sys.stderr)
        print(f"Operator key fingerprint: {fingerprint}", file=sys.stderr)
        while True:
            answer = input("Approve? [o]nce, [t]rust, [r]eject: ").strip().lower()
            if answer in ("o", "once", "y", "yes"):
                return True, False
            if answer in ("t", "trust"):
                return True, True
            if answer in ("r", "reject", "n", "no", ""):
                return False, False


class ClientChannelBase:
    def __init__(self, conn: ReverseClientConnection, channel_id: int):
        self.conn = conn
        self.channel_id = channel_id
        self.closed = False

    def on_data(self, data: bytes) -> None:
        pass

    def on_extended_data(self, data_type: int, data: bytes) -> None:
        self.on_data(data)

    def on_request(self, request: str, want_reply: bool, payload: bytes) -> None:
        pass

    def on_eof(self) -> None:
        pass

    def on_close(self, send_close: bool = True) -> None:
        self.closed = True
        if send_close:
            self.conn.send_channel_close(self.channel_id)


class SessionChannel(ClientChannelBase):
    def __init__(self, conn: ReverseClientConnection, channel_id: int, shell: str):
        super().__init__(conn, channel_id)
        self.shell = shell
        self.env: dict[str, str] = {}
        self.pty_requested = False
        self.term = "xterm"
        self.cols = 80
        self.rows = 24
        self.width_pixels = 0
        self.height_pixels = 0
        self.master_fd: int | None = None
        self.stdin = None
        self.process: subprocess.Popen | None = None
        self.sftp: SFTPServer | None = None
        self.reader_threads: list[threading.Thread] = []

    def on_data(self, data: bytes) -> None:
        if self.sftp:
            self.sftp.feed(data)
        elif self.master_fd is not None:
            try:
                os.write(self.master_fd, data)
            except OSError:
                self.on_close()
        elif self.stdin:
            try:
                self.stdin.write(data)
                self.stdin.flush()
            except BrokenPipeError:
                pass

    def on_extended_data(self, data_type: int, data: bytes) -> None:
        self.on_data(data)

    def on_request(self, request: str, want_reply: bool, payload: bytes) -> None:
        try:
            if request == "pty-req":
                self._handle_pty_req(payload)
            elif request == "env":
                reader = Reader(payload)
                name = reader.text()
                value = reader.text()
                self.env[name] = value
            elif request == "window-change":
                self._handle_window_change(payload)
            elif request == "shell":
                self._start_process(command=None)
            elif request == "exec":
                command = Reader(payload).text()
                self._start_process(command=command)
            elif request == "subsystem":
                subsystem = Reader(payload).text()
                if subsystem == "sftp":
                    self.sftp = SFTPServer(lambda data: self.conn.send_channel_data(self.channel_id, data))
                else:
                    self._finish_with_status(1)
            elif request == "signal":
                self._handle_signal(payload)
        except Exception as exc:
            LOG.info("session request %s failed on channel %s: %s", request, self.channel_id, exc)
            self._finish_with_status(1)

    def on_eof(self) -> None:
        if self.sftp:
            self.sftp.close()
            self.sftp = None
            self._finish_with_status(0)
        elif self.stdin:
            try:
                self.stdin.close()
            except OSError:
                pass

    def on_close(self, send_close: bool = True) -> None:
        if self.closed:
            return
        self.closed = True
        if self.sftp:
            self.sftp.close()
        if self.process and self.process.poll() is None:
            try:
                if self.master_fd is not None:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGHUP)
                else:
                    self.process.terminate()
            except OSError:
                pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None
        if send_close:
            self.conn.send_channel_close(self.channel_id)

    def _handle_pty_req(self, payload: bytes) -> None:
        reader = Reader(payload)
        self.term = reader.text()
        self.cols = reader.uint32()
        self.rows = reader.uint32()
        self.width_pixels = reader.uint32()
        self.height_pixels = reader.uint32()
        _modes = reader.string()
        self.pty_requested = True
        if self.master_fd is not None:
            self._set_pty_size(self.master_fd)

    def _handle_window_change(self, payload: bytes) -> None:
        reader = Reader(payload)
        self.cols = reader.uint32()
        self.rows = reader.uint32()
        self.width_pixels = reader.uint32()
        self.height_pixels = reader.uint32()
        if self.master_fd is not None:
            self._set_pty_size(self.master_fd)

    def _handle_signal(self, payload: bytes) -> None:
        signal_name = Reader(payload).text()
        if not self.process or self.process.poll() is not None:
            return
        mapping = {
            "HUP": signal.SIGHUP,
            "INT": signal.SIGINT,
            "TERM": signal.SIGTERM,
            "KILL": signal.SIGKILL,
        }
        sig = mapping.get(signal_name)
        if sig:
            try:
                if self.master_fd is not None:
                    os.killpg(os.getpgid(self.process.pid), sig)
                else:
                    self.process.send_signal(sig)
            except OSError:
                pass

    def _start_process(self, command: str | None) -> None:
        if self.process is not None:
            return
        env = os.environ.copy()
        env.update(self.env)
        argv = [self.shell] if command is None else [self.shell, "-lc", command]
        if self.pty_requested:
            master_fd, slave_fd = os.openpty()
            self.master_fd = master_fd
            self._set_pty_size(master_fd)
            self.process = subprocess.Popen(
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                close_fds=True,
                preexec_fn=os.setsid,
            )
            os.close(slave_fd)
            thread = threading.Thread(target=self._pty_reader, daemon=True)
            self.reader_threads.append(thread)
            thread.start()
        else:
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                close_fds=True,
            )
            self.stdin = self.process.stdin
            stdout_thread = threading.Thread(target=self._pipe_reader, args=(self.process.stdout, False), daemon=True)
            stderr_thread = threading.Thread(target=self._pipe_reader, args=(self.process.stderr, True), daemon=True)
            self.reader_threads.extend([stdout_thread, stderr_thread])
            stdout_thread.start()
            stderr_thread.start()
        threading.Thread(target=self._waiter, daemon=True).start()

    def _set_pty_size(self, fd: int) -> None:
        if fcntl is None:
            return
        winsize = struct.pack("HHHH", self.rows, self.cols, self.height_pixels, self.width_pixels)
        try:
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
        except OSError:
            pass

    def _pty_reader(self) -> None:
        assert self.master_fd is not None
        while not self.closed:
            try:
                data = os.read(self.master_fd, CHANNEL_MAX_PACKET)
            except OSError:
                break
            if not data:
                break
            self.conn.send_channel_data(self.channel_id, data)

    def _pipe_reader(self, pipe, stderr: bool) -> None:
        while pipe and not self.closed:
            data = pipe.read(CHANNEL_MAX_PACKET)
            if not data:
                break
            if stderr:
                self.conn.send_extended_data(self.channel_id, EXTENDED_DATA_STDERR, data)
            else:
                self.conn.send_channel_data(self.channel_id, data)

    def _waiter(self) -> None:
        assert self.process is not None
        status = self.process.wait()
        current = threading.current_thread()
        for thread in self.reader_threads:
            if thread is not current:
                thread.join(timeout=2)
        self._finish_with_status(status)

    def _finish_with_status(self, status: int) -> None:
        if self.closed:
            return
        self.conn.send_channel_request(self.channel_id, "exit-status", uint32(status & 0xFFFFFFFF))
        self.conn.send_channel_eof(self.channel_id)
        self.on_close(send_close=True)


class DirectTCPChannel(ClientChannelBase):
    def __init__(self, conn: ReverseClientConnection, channel_id: int, extra: dict[str, Any]):
        super().__init__(conn, channel_id)
        self.extra = extra
        self.sock: socket.socket | None = None

    def open(self) -> tuple[bool, str]:
        host = str(self.extra["target_host"])
        port = int(self.extra["target_port"])
        try:
            self.sock = socket.create_connection((host, port), timeout=30)
            return True, "connected"
        except OSError as exc:
            return False, str(exc)

    def start_reader(self) -> None:
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def on_data(self, data: bytes) -> None:
        if self.sock:
            self.sock.sendall(data)

    def on_eof(self) -> None:
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def on_close(self, send_close: bool = True) -> None:
        if self.closed:
            return
        self.closed = True
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if send_close:
            self.conn.send_channel_close(self.channel_id)

    def _reader_loop(self) -> None:
        assert self.sock is not None
        try:
            while not self.closed:
                data = self.sock.recv(CHANNEL_MAX_PACKET)
                if not data:
                    break
                self.conn.send_channel_data(self.channel_id, data)
        except OSError:
            pass
        finally:
            self.conn.send_channel_eof(self.channel_id)
            self.on_close(send_close=True)


class ReverseClient:
    def __init__(self, relay: str, identifier: str, state_dir: Path, shell: str, known_operators: Path):
        self.relay = relay
        self.identifier = identifier
        self.state_dir = state_dir
        self.shell = shell
        self.known = KnownOperators(known_operators)

    def run_forever(self) -> None:
        backoff = 1.0
        while True:
            try:
                host, port = parse_host_port(self.relay)
                LOG.info("connecting to relay %s:%s", host, port)
                sock = socket.create_connection((host, port), timeout=30)
                conn = ReverseClientConnection(sock, self.identifier, self.shell, self.known)
                if not conn.register():
                    return
                backoff = 1.0
                conn.run()
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                LOG.info("relay connection failed: %s", exc)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a reverSSH reverse client")
    parser.add_argument("--relay", required=True, help="relay client-protocol address, for example host:8022")
    parser.add_argument("--identifier", required=True, help="identifier operators use as ssh username")
    parser.add_argument("--state-dir", default=str(Path.home() / ".reverssh"), help="client state directory")
    parser.add_argument("--shell", default=os.environ.get("SHELL", "/bin/sh"), help="shell for session and exec channels")
    parser.add_argument("--known-operators", default=None, help="trusted operator fingerprint file")
    parser.add_argument("--log-level", default="INFO", help="Python logging level")
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    state_dir = Path(args.state_dir)
    known = Path(args.known_operators) if args.known_operators else state_dir / "known_operators"
    ReverseClient(args.relay, args.identifier, state_dir, args.shell, known).run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
