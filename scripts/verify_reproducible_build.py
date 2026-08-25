from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from normalize_release_archives import normalize_sdist


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild a release and require byte-identical artifacts"
    )
    parser.add_argument("--reference", required=True, type=Path)
    args = parser.parse_args()
    reference = args.reference.resolve()
    expected = {path.name: _digest(path) for path in reference.iterdir() if path.is_file()}
    if not expected:
        raise ValueError(f"no reference artifacts found in {reference}")
    if "SOURCE_DATE_EPOCH" not in os.environ:
        raise ValueError("SOURCE_DATE_EPOCH must be set for reproducibility checks")
    with tempfile.TemporaryDirectory(prefix="gpowake-rebuild-") as temporary:
        rebuilt = Path(temporary)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(rebuilt),
            ],
            check=True,
        )
        epoch = int(os.environ["SOURCE_DATE_EPOCH"])
        for artifact in rebuilt.iterdir():
            if artifact.name.endswith(".tar.gz"):
                normalize_sdist(artifact, epoch)
        actual = {path.name: _digest(path) for path in rebuilt.iterdir() if path.is_file()}
    if actual != expected:
        differing = sorted(set(expected).union(actual))
        details = [
            f"{name}: reference={expected.get(name)} rebuilt={actual.get(name)}"
            for name in differing
            if expected.get(name) != actual.get(name)
        ]
        raise RuntimeError("release is not reproducible\n" + "\n".join(details))
    for name, digest in sorted(expected.items()):
        print(f"reproducible {name} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
