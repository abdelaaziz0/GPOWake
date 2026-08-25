from __future__ import annotations

import os
import csv
import io
import re
import stat
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path


MAX_CREDENTIAL_BYTES = 64 * 1024


def _read_descriptor_bytes(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(8192, MAX_CREDENTIAL_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_CREDENTIAL_BYTES:
            raise ValueError(
                f"credential input exceeds the {MAX_CREDENTIAL_BYTES}-byte limit"
            )
    return b"".join(chunks)


def _restrict_windows_acl(path: Path) -> None:
    import ctypes

    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise OSError("Windows GetSystemDirectoryW failed")
    system_directory = Path(buffer.value)
    identity = subprocess.run(
        [str(system_directory / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    rows = list(csv.reader(io.StringIO(identity)))
    if len(rows) != 1 or len(rows[0]) < 2:
        raise OSError("could not determine the current Windows user SID")
    sid = rows[0][1].strip()
    if re.fullmatch(r"S-1-(?:\d+-)+\d+", sid, re.IGNORECASE) is None:
        raise OSError("whoami returned an invalid Windows user SID")
    subprocess.run(
        [
            str(system_directory / "icacls.exe"),
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:(R,W)",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def secure_write_text(path: str | Path, text: str) -> None:
    """Atomically replace a text artifact with owner-only permissions."""

    secure_write_lines(path, (text,))


def secure_write_lines(path: str | Path, lines: Iterable[str]) -> None:
    """Atomically stream text lines to an owner-only artifact."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        else:
            _restrict_windows_acl(temporary)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            descriptor = -1
            stream.writelines(lines)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        if os.name == "posix":
            os.chmod(destination, 0o600)
        else:
            _restrict_windows_acl(destination)
        if os.name == "posix":
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def read_secure_file(path: str | Path) -> str:
    """Read a small owner-only, regular credential file without following links."""

    source = Path(path)
    if os.name == "nt":
        raise ValueError(
            "credential files are disabled on native Windows; use an inherited "
            "descriptor or interactive prompt"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(source, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("credential file must be a regular file, not a link")
        if metadata.st_size > MAX_CREDENTIAL_BYTES:
            raise ValueError(
                f"credential file exceeds the {MAX_CREDENTIAL_BYTES}-byte limit"
            )
        if metadata.st_uid != os.geteuid():
            raise ValueError("credential file must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("credential file permissions must be 0600 or stricter")
        data = _read_descriptor_bytes(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > MAX_CREDENTIAL_BYTES:
        raise ValueError("credential file grew beyond its size limit while reading")
    return data.decode("utf-8", errors="strict")


def read_bounded_fd(descriptor: int) -> str:
    if descriptor < 0:
        raise ValueError("credential file descriptor cannot be negative")
    return _read_descriptor_bytes(descriptor).decode("utf-8", errors="strict")
