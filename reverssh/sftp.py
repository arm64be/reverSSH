from __future__ import annotations

import errno
import os
import stat
import struct
import time
from pathlib import Path
from typing import Callable

from .ssh_encoding import Reader, string, uint32, uint64

SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_SETSTAT = 9
SSH_FXP_FSETSTAT = 10
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_REMOVE = 13
SSH_FXP_MKDIR = 14
SSH_FXP_RMDIR = 15
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17
SSH_FXP_RENAME = 18

SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

SSH_FX_OK = 0
SSH_FX_EOF = 1
SSH_FX_NO_SUCH_FILE = 2
SSH_FX_PERMISSION_DENIED = 3
SSH_FX_FAILURE = 4
SSH_FX_OP_UNSUPPORTED = 8

SSH_FILEXFER_ATTR_SIZE = 0x00000001
SSH_FILEXFER_ATTR_UIDGID = 0x00000002
SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008

SSH_FXF_READ = 0x00000001
SSH_FXF_WRITE = 0x00000002
SSH_FXF_APPEND = 0x00000004
SSH_FXF_CREAT = 0x00000008
SSH_FXF_TRUNC = 0x00000010
SSH_FXF_EXCL = 0x00000020


def normalize_sftp_path(cwd: Path, path: str) -> Path:
    if "\x00" in path:
        raise ValueError("SFTP path contains NUL")
    if not path:
        path = "."
    expanded = os.path.expanduser(path)
    if os.path.isabs(expanded):
        return Path(os.path.abspath(expanded))
    return Path(os.path.abspath(cwd / expanded))


def _status_from_oserror(exc: OSError) -> int:
    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
        return SSH_FX_NO_SUCH_FILE
    if exc.errno in (errno.EACCES, errno.EPERM):
        return SSH_FX_PERMISSION_DENIED
    return SSH_FX_FAILURE


def _attrs_from_stat(st: os.stat_result) -> bytes:
    return (
        uint32(
            SSH_FILEXFER_ATTR_SIZE
            | SSH_FILEXFER_ATTR_UIDGID
            | SSH_FILEXFER_ATTR_PERMISSIONS
            | SSH_FILEXFER_ATTR_ACMODTIME
        )
        + uint64(st.st_size)
        + uint32(getattr(st, "st_uid", 0))
        + uint32(getattr(st, "st_gid", 0))
        + uint32(st.st_mode)
        + uint32(int(st.st_atime))
        + uint32(int(st.st_mtime))
    )


def _longname(path: Path, st: os.stat_result) -> str:
    mode = stat.filemode(st.st_mode)
    size = st.st_size
    mtime = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
    return f"{mode} 1 {getattr(st, 'st_uid', 0)} {getattr(st, 'st_gid', 0)} {size:8d} {mtime} {path.name}"


class SFTPServer:
    def __init__(self, send_data: Callable[[bytes], None], cwd: Path | None = None):
        self.send_data = send_data
        self.cwd = cwd or Path.cwd()
        self.buffer = bytearray()
        self.next_handle = 1
        self.handles: dict[bytes, object] = {}

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        while len(self.buffer) >= 4:
            length = struct.unpack(">I", self.buffer[:4])[0]
            if len(self.buffer) < 4 + length:
                return
            packet = bytes(self.buffer[4 : 4 + length])
            del self.buffer[: 4 + length]
            self._handle_packet(packet)

    def close(self) -> None:
        for handle in list(self.handles):
            self._close_handle(handle)

    def _send_packet(self, packet_type: int, payload: bytes) -> None:
        packet = bytes([packet_type]) + payload
        self.send_data(uint32(len(packet)) + packet)

    def _handle_packet(self, packet: bytes) -> None:
        packet_type = packet[0]
        reader = Reader(packet[1:])
        if packet_type == SSH_FXP_INIT:
            version = reader.uint32()
            self._send_packet(SSH_FXP_VERSION, uint32(min(version, 3)))
            return
        request_id = reader.uint32()
        try:
            if packet_type == SSH_FXP_REALPATH:
                self._realpath(request_id, reader.text())
            elif packet_type in (SSH_FXP_STAT, SSH_FXP_LSTAT):
                path = normalize_sftp_path(self.cwd, reader.text())
                st = os.lstat(path) if packet_type == SSH_FXP_LSTAT else os.stat(path)
                self._send_packet(SSH_FXP_ATTRS, uint32(request_id) + _attrs_from_stat(st))
            elif packet_type == SSH_FXP_FSTAT:
                handle = reader.string()
                obj = self.handles[handle]
                st = os.fstat(obj.fileno())  # type: ignore[attr-defined]
                self._send_packet(SSH_FXP_ATTRS, uint32(request_id) + _attrs_from_stat(st))
            elif packet_type == SSH_FXP_OPENDIR:
                self._opendir(request_id, reader.text())
            elif packet_type == SSH_FXP_READDIR:
                self._readdir(request_id, reader.string())
            elif packet_type == SSH_FXP_OPEN:
                self._open(request_id, reader.text(), reader.uint32())
            elif packet_type == SSH_FXP_READ:
                self._read(request_id, reader.string(), reader.uint64(), reader.uint32())
            elif packet_type == SSH_FXP_WRITE:
                self._write(request_id, reader.string(), reader.uint64(), reader.string())
            elif packet_type == SSH_FXP_CLOSE:
                self._close(request_id, reader.string())
            elif packet_type == SSH_FXP_REMOVE:
                os.remove(normalize_sftp_path(self.cwd, reader.text()))
                self._status(request_id, SSH_FX_OK, "ok")
            elif packet_type == SSH_FXP_MKDIR:
                os.mkdir(normalize_sftp_path(self.cwd, reader.text()))
                self._status(request_id, SSH_FX_OK, "ok")
            elif packet_type == SSH_FXP_RMDIR:
                os.rmdir(normalize_sftp_path(self.cwd, reader.text()))
                self._status(request_id, SSH_FX_OK, "ok")
            elif packet_type == SSH_FXP_RENAME:
                os.rename(
                    normalize_sftp_path(self.cwd, reader.text()),
                    normalize_sftp_path(self.cwd, reader.text()),
                )
                self._status(request_id, SSH_FX_OK, "ok")
            else:
                self._status(request_id, SSH_FX_OP_UNSUPPORTED, "unsupported")
        except KeyError:
            self._status(request_id, SSH_FX_FAILURE, "invalid handle")
        except PermissionError as exc:
            self._status(request_id, SSH_FX_PERMISSION_DENIED, str(exc))
        except OSError as exc:
            self._status(request_id, _status_from_oserror(exc), str(exc))
        except Exception as exc:
            self._status(request_id, SSH_FX_FAILURE, str(exc))

    def _status(self, request_id: int, code: int, message: str) -> None:
        self._send_packet(SSH_FXP_STATUS, uint32(request_id) + uint32(code) + string(message) + string(""))

    def _new_handle(self, obj: object) -> bytes:
        handle = f"h{self.next_handle}".encode()
        self.next_handle += 1
        self.handles[handle] = obj
        return handle

    def _close_handle(self, handle: bytes) -> None:
        obj = self.handles.pop(handle, None)
        if hasattr(obj, "close"):
            obj.close()  # type: ignore[call-arg]

    def _realpath(self, request_id: int, path_text: str) -> None:
        path = normalize_sftp_path(self.cwd, path_text)
        try:
            resolved = path.resolve(strict=False)
            st = os.stat(resolved)
        except OSError:
            resolved = path
            st = os.stat(path.parent if path.parent.exists() else self.cwd)
        name = str(resolved)
        payload = uint32(request_id) + uint32(1) + string(name) + string(name) + _attrs_from_stat(st)
        self._send_packet(SSH_FXP_NAME, payload)

    def _opendir(self, request_id: int, path_text: str) -> None:
        path = normalize_sftp_path(self.cwd, path_text)
        entries = ["."]
        if path.parent != path:
            entries.append("..")
        entries.extend(entry.name for entry in os.scandir(path))
        handle = self._new_handle({"path": path, "entries": entries, "offset": 0})
        self._send_packet(SSH_FXP_HANDLE, uint32(request_id) + string(handle))

    def _readdir(self, request_id: int, handle: bytes) -> None:
        state = self.handles[handle]
        if not isinstance(state, dict):
            self._status(request_id, SSH_FX_FAILURE, "not a directory")
            return
        entries: list[str] = state["entries"]
        offset = state["offset"]
        batch = entries[offset : offset + 64]
        state["offset"] = offset + len(batch)
        if not batch:
            self._status(request_id, SSH_FX_EOF, "end of directory")
            return
        base: Path = state["path"]
        payload = uint32(request_id) + uint32(len(batch))
        for name_text in batch:
            full = base / name_text
            try:
                st = os.lstat(full)
            except OSError:
                continue
            payload += string(name_text) + string(_longname(Path(name_text), st)) + _attrs_from_stat(st)
        self._send_packet(SSH_FXP_NAME, payload)

    def _open(self, request_id: int, path_text: str, flags: int) -> None:
        path = normalize_sftp_path(self.cwd, path_text)
        if flags & SSH_FXF_READ and flags & SSH_FXF_WRITE:
            mode = "r+b"
        elif flags & SSH_FXF_WRITE:
            mode = "ab" if flags & SSH_FXF_APPEND else "wb" if flags & SSH_FXF_TRUNC else "r+b"
        else:
            mode = "rb"
        if flags & SSH_FXF_CREAT and "r+" in mode and not path.exists():
            mode = "w+b"
        if flags & SSH_FXF_EXCL and path.exists():
            raise FileExistsError(path)
        file_obj = open(path, mode)
        handle = self._new_handle(file_obj)
        self._send_packet(SSH_FXP_HANDLE, uint32(request_id) + string(handle))

    def _read(self, request_id: int, handle: bytes, offset: int, size: int) -> None:
        file_obj = self.handles[handle]
        file_obj.seek(offset)  # type: ignore[attr-defined]
        data = file_obj.read(size)  # type: ignore[attr-defined]
        if data:
            self._send_packet(SSH_FXP_DATA, uint32(request_id) + string(data))
        else:
            self._status(request_id, SSH_FX_EOF, "end of file")

    def _write(self, request_id: int, handle: bytes, offset: int, data: bytes) -> None:
        file_obj = self.handles[handle]
        file_obj.seek(offset)  # type: ignore[attr-defined]
        file_obj.write(data)  # type: ignore[attr-defined]
        file_obj.flush()  # type: ignore[attr-defined]
        self._status(request_id, SSH_FX_OK, "ok")

    def _close(self, request_id: int, handle: bytes) -> None:
        self._close_handle(handle)
        self._status(request_id, SSH_FX_OK, "ok")
