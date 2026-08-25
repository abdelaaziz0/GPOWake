from __future__ import annotations

import argparse
import gzip
import io
import os
import tarfile
import tempfile
from pathlib import Path


MAX_SDIST_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


def normalize_sdist(path: Path, epoch: int) -> None:
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    names: set[str] = set()
    total = 0
    with tarfile.open(path, "r:gz") as source:
        for original in source.getmembers():
            if original.name in names:
                raise ValueError(f"duplicate sdist member: {original.name}")
            names.add(original.name)
            if not (original.isfile() or original.isdir()):
                raise ValueError(f"special sdist member is not allowed: {original.name}")
            data = None
            if original.isfile():
                handle = source.extractfile(original)
                if handle is None:
                    raise ValueError(f"could not read sdist member: {original.name}")
                remaining = MAX_SDIST_UNCOMPRESSED_BYTES - total
                data = handle.read(remaining + 1)
                total += len(data)
                if total > MAX_SDIST_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        "sdist exceeds normalization size limit of "
                        f"{MAX_SDIST_UNCOMPRESSED_BYTES} bytes"
                    )
            member = tarfile.TarInfo(original.name)
            member.type = tarfile.DIRTYPE if original.isdir() else tarfile.REGTYPE
            member.size = len(data) if data is not None else 0
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mode = 0o755 if original.isdir() or original.mode & 0o111 else 0o644
            entries.append((member, data))

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as target:
        for member, data in sorted(entries, key=lambda item: item[0].name):
            target.addfile(member, io.BytesIO(data) if data is not None else None)

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=path.name + ".",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=temporary,
                mtime=epoch,
            ) as compressed:
                compressed.write(tar_buffer.getvalue())
        os.replace(temporary_path, path)
        path.chmod(0o644)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize sdist ownership, ordering, modes, and timestamps"
    )
    parser.add_argument("archives", nargs="+", type=Path)
    parser.add_argument("--epoch", required=True, type=int)
    args = parser.parse_args()
    if not 0 <= args.epoch <= 0xFFFFFFFF:
        parser.error("--epoch must fit the gzip uint32 timestamp field")
    for archive in args.archives:
        if archive.name.endswith(".tar.gz"):
            normalize_sdist(archive, args.epoch)
            print(f"normalized {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
