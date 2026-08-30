from __future__ import annotations

import os
import csv
import io
import ipaddress
import re
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from collections.abc import Iterable
from pathlib import Path
from typing import Iterator


MAX_CREDENTIAL_BYTES = 64 * 1024
MAX_CCACHE_BYTES = 16 * 1024 * 1024
MAX_PFX_BYTES = 16 * 1024 * 1024


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


@contextmanager
def _scoped_secret_copy(
    path: str | Path,
    *,
    label: str,
    max_bytes: int,
    prefix: str,
    suffix: str,
) -> Iterator[str]:
    if os.name != "posix":
        raise ValueError(
            f"explicit {label} files require POSIX owner/mode validation; "
            "run collection from Linux or WSL"
        )
    value = os.fspath(path)
    if not value:
        raise ValueError(f"{label} requires a non-empty file path")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    source_descriptor = os.open(value, flags)
    temporary_descriptor = -1
    temporary_name: str | None = None
    try:
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular file, not a link")
        if metadata.st_uid != os.geteuid():
            raise ValueError(f"{label} must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"{label} permissions must be 0600 or stricter")
        if metadata.st_size > max_bytes:
            raise ValueError(f"{label} exceeds the {max_bytes}-byte limit")

        temporary_descriptor, temporary_name = tempfile.mkstemp(
            prefix=prefix, suffix=suffix
        )
        os.fchmod(temporary_descriptor, 0o600)
        total = 0
        while True:
            chunk = os.read(
                source_descriptor, min(64 * 1024, max_bytes + 1 - total)
            )
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} grew beyond the {max_bytes}-byte limit")
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(temporary_descriptor, remaining)
                if written <= 0:
                    raise OSError(f"failed to copy {label}")
                remaining = remaining[written:]
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        yield temporary_name
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


@contextmanager
def scoped_private_key_file(path: str | Path) -> Iterator[str]:
    """Yield a stable owner-only temporary copy of a PFX/P12 credential."""

    with _scoped_secret_copy(
        path,
        label="PFX credential",
        max_bytes=MAX_PFX_BYTES,
        prefix="gpowake-pfx-",
        suffix=".pfx",
    ) as copied:
        yield copied


@contextmanager
def scoped_credential_cache(path: str | Path) -> Iterator[str]:
    """Expose a stable owner-only ccache copy only for one collection call.

    GSSAPI and Impacket both consume ``KRB5CCNAME``. Copying from an already
    opened, no-follow descriptor removes the validation/use race, while the
    scoped environment restoration prevents credential state leaking into a
    later in-process command.
    """

    value = os.fspath(path)
    if value.startswith("FILE:"):
        value = value[len("FILE:") :]
    elif re.match(r"^[A-Za-z]+:", value):
        raise ValueError("--ccache currently supports only FILE credential caches")
    previous = os.environ.get("KRB5CCNAME")
    with _scoped_secret_copy(
        value,
        label="ccache",
        max_bytes=MAX_CCACHE_BYTES,
        prefix="gpowake-ccache-",
        suffix=".bin",
    ) as copied:
        # A bare path is the common denominator: MIT Kerberos interprets it as
        # a FILE cache, while Impacket incorrectly treats a ``FILE:`` prefix as
        # part of the filename when loading KRB5CCNAME.
        cache_name = copied
        os.environ["KRB5CCNAME"] = cache_name
        try:
            yield cache_name
        finally:
            if previous is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = previous


@contextmanager
def scoped_kerberos_config(domain: str, dc_ip: str) -> Iterator[str]:
    """Pin one Kerberos realm to an explicit KDC for a collection call.

    MIT Kerberos otherwise performs DNS SRV discovery even when GPOWake was
    given ``--dc-ip``. A private, short-lived configuration makes ccache and
    PKINIT authentication deterministic in segmented networks without
    modifying the operator's global Kerberos configuration.
    """

    if os.name != "posix":
        raise ValueError("Kerberos KDC pinning requires Linux or WSL")
    normalized_domain = domain.rstrip(".").casefold()
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", normalized_domain) is None:
        raise ValueError("--domain is not a valid DNS domain for Kerberos")
    try:
        address = ipaddress.ip_address(dc_ip)
    except ValueError as exc:
        raise ValueError("--dc-ip must be a literal IPv4 or IPv6 address") from exc
    kdc = f"[{address}]" if address.version == 6 else str(address)
    realm = normalized_domain.upper()
    document = (
        "[libdefaults]\n"
        f" default_realm = {realm}\n"
        " dns_lookup_kdc = false\n"
        " dns_lookup_realm = false\n"
        " rdns = false\n"
        " dns_canonicalize_hostname = false\n\n"
        "[realms]\n"
        f" {realm} = {{\n"
        f"  kdc = {kdc}\n"
        " }\n\n"
        "[domain_realm]\n"
        f" .{normalized_domain} = {realm}\n"
        f" {normalized_domain} = {realm}\n"
    ).encode("ascii")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix="gpowake-krb5-", suffix=".conf"
    )
    previous = os.environ.get("KRB5_CONFIG")
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(document)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("failed to write temporary Kerberos configuration")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.environ["KRB5_CONFIG"] = temporary_name
        yield temporary_name
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if previous is None:
            os.environ.pop("KRB5_CONFIG", None)
        else:
            os.environ["KRB5_CONFIG"] = previous
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
