from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


FORBIDDEN_PARTS = {
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".venv",
    ".vscode",
    ".idea",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "venv",
}


def _relative_parts(name: str, *, strip_root: bool) -> tuple[str, ...]:
    if "\\" in name:
        raise ValueError(f"backslash is not allowed in archive path: {name}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive path: {name}")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    return parts[1:] if strip_root and parts else parts


def _check_name(name: str, *, strip_root: bool, source: bool) -> None:
    parts = _relative_parts(name, strip_root=strip_root)
    if any(part in FORBIDDEN_PARTS for part in parts):
        raise ValueError(f"generated/cache/VCS path in archive: {name}")
    if any(part.startswith(".coverage") for part in parts):
        raise ValueError(f"coverage data in archive: {name}")
    if parts and parts[-1].endswith((".pyc", ".pyo")):
        raise ValueError(f"bytecode in archive: {name}")
    for index, part in enumerate(parts):
        if not part.endswith(".egg-info"):
            continue
        expected = source and index > 0 and parts[index - 1] == "src"
        expected = expected and part == "gpowake.egg-info"
        if not expected:
            raise ValueError(f"unexpected generated egg-info in archive: {name}")


def inspect_archive(path: Path) -> int:
    count = 0
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            roots = {PurePosixPath(member.name).parts[0] for member in members}
            if len(roots) != 1:
                raise ValueError("sdist must have exactly one top-level directory")
            for member in members:
                if not (member.isfile() or member.isdir()):
                    raise ValueError(
                        f"special entries are not allowed in the sdist: {member.name}"
                    )
                _check_name(member.name, strip_root=True, source=True)
                count += 1
    elif path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    raise ValueError(
                        f"links are not allowed in the wheel: {info.filename}"
                    )
                _check_name(info.filename, strip_root=False, source=False)
                count += 1
    else:
        raise ValueError(f"unsupported release archive type: {path}")
    if count == 0:
        raise ValueError(f"release archive is empty: {path}")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reject generated, cached, VCS, or unsafe paths in release archives"
    )
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()
    for archive in args.archives:
        count = inspect_archive(archive)
        print(f"{archive}: checked {count} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
