from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _sha1(path: Path) -> str:
    # SPDX 2.3 requires SHA-1 for File elements. SHA-256 remains the security
    # digest used by the provenance subject and release output.
    hasher = hashlib.sha1(usedforsecurity=False)
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _timestamp() -> str:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None or not raw.isdigit():
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer")
    return datetime.fromtimestamp(int(raw), timezone.utc).isoformat().replace("+00:00", "Z")


def _project_name_version() -> tuple[str, str]:
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"(?ms)^\[project\]\s*(.*?)(?=^\[|\Z)", text)
    if match is None:
        raise ValueError("pyproject.toml lacks a [project] table")
    values: dict[str, str] = {}
    for key in ("name", "version"):
        value = re.search(rf'(?m)^{key}\s*=\s*"([^"]+)"\s*$', match.group(1))
        if value is None:
            raise ValueError(f"pyproject.toml [project] lacks {key}")
        values[key] = value.group(1)
    return values["name"], values["version"]


def _optional_runtime_dependencies() -> tuple[str, ...]:
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^\[project\.optional-dependencies\]\s*(.*?)(?=^\[|\Z)", text
    )
    if match is None:
        return ()
    collect = re.search(r"(?ms)^collect\s*=\s*\[(.*?)\]", match.group(1))
    if collect is None:
        return ()
    names: list[str] = []
    for requirement in re.findall(r'"([^"]+)"', collect.group(1)):
        name = re.match(r"[A-Za-z0-9_.-]+", requirement)
        if name is not None:
            names.append(name.group(0))
    return tuple(dict.fromkeys(names))


def generate(dist: Path, commit: str) -> tuple[Path, Path]:
    name, version = _project_name_version()
    artifacts = sorted(
        path
        for path in dist.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    )
    if len(artifacts) != 2:
        raise ValueError("release metadata requires exactly one wheel and one sdist")
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ValueError("commit must be a lowercase 40-character Git object ID")
    created = _timestamp()
    subjects = [
        {
            "name": path.name,
            "digest": {"sha1": _sha1(path), "sha256": _sha256(path)},
        }
        for path in artifacts
    ]
    artifact_files = [
        {
            "fileName": f"./{item['name']}",
            "SPDXID": f"SPDXRef-Artifact-{index}",
            "checksums": [
                {
                    "algorithm": "SHA1",
                    "checksumValue": item["digest"]["sha1"],
                },
                {
                    "algorithm": "SHA256",
                    "checksumValue": item["digest"]["sha256"],
                }
            ],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        for index, item in enumerate(subjects, 1)
    ]
    dependency_packages = [
        {
            "name": dependency,
            "SPDXID": f"SPDXRef-Optional-{index}",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{dependency}",
                }
            ],
        }
        for index, dependency in enumerate(_optional_runtime_dependencies(), 1)
    ]

    sbom_path = dist / f"{name}-{version}.spdx.json"
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}",
        "documentNamespace": (
            f"https://spdx.org/spdxdocs/{name}-{version}-{commit}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: GPOWake reproducible release guard"],
        },
        "documentDescribes": [
            "SPDXRef-Package-GPOWake",
            *(item["SPDXID"] for item in artifact_files),
        ],
        "packages": [
            {
                "name": name,
                "SPDXID": "SPDXRef-Package-GPOWake",
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name}@{version}",
                    }
                ],
            },
            *dependency_packages,
        ],
        "files": artifact_files,
        "relationships": [
            *(
                {
                    "spdxElementId": item["SPDXID"],
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": "SPDXRef-Package-GPOWake",
                }
                for item in artifact_files
            ),
            *(
                {
                    "spdxElementId": item["SPDXID"],
                    "relationshipType": "OPTIONAL_DEPENDENCY_OF",
                    "relatedSpdxElement": "SPDXRef-Package-GPOWake",
                }
                for item in dependency_packages
            ),
        ],
        "annotations": [
            {
                "annotationDate": created,
                "annotationType": "OTHER",
                "annotator": "Tool: GPOWake reproducible release guard",
                "comment": "Release artifact SHA-256: "
                + ", ".join(
                    f"{item['name']}={item['digest']['sha256']}" for item in subjects
                ),
            }
        ],
    }
    sbom_path.write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    provenance_path = dist / f"{name}-{version}.intoto.jsonl"
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://gpowake.dev/build-release/v1",
                "externalParameters": {"version": version},
                "internalParameters": {
                    "sourceDateEpoch": int(os.environ["SOURCE_DATE_EPOCH"])
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/abdelaaziz0/GPOWake",
                        "digest": {"gitCommit": commit},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": "https://gpowake.dev/reproducible-release-guard"},
            },
        },
    }
    provenance_path.write_text(
        json.dumps(provenance, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return sbom_path, provenance_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic SPDX and SLSA/in-toto release metadata"
    )
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    for path in generate(args.dist, args.commit):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
