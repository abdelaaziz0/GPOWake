#!/usr/bin/env bash
set -euo pipefail

project_root=$(git rev-parse --show-toplevel)
cd "$project_root"

if [[ -n $(git status --porcelain --untracked-files=all) ]]; then
    echo "release refused: the Git worktree or index is dirty" >&2
    exit 2
fi

project_version=$(python3 -c 'from scripts.generate_release_metadata import _project_name_version; print(_project_name_version()[1])')
release_tag=$(git describe --exact-match --tags HEAD 2>/dev/null || true)
if [[ "$release_tag" != "v$project_version" ]]; then
    echo "release refused: HEAD must have exact tag v$project_version" >&2
    exit 2
fi
if ! git \
    -c gpg.format=ssh \
    -c gpg.ssh.allowedSignersFile=maintainers/allowed_signers \
    verify-tag "$release_tag" >/dev/null 2>&1; then
    echo "release refused: tag $release_tag must have a valid cryptographic signature" >&2
    exit 2
fi

PYTHONPATH=src python3 -m pytest
PYTHONPATH=src python3 -m pytest tests/test_security_hardening.py
python3 -m ruff check src tests benchmarks scripts
python3 -m mypy src
python3 -m bandit -r src scripts -ll
PYTHONPATH=src python3 benchmarks/benchmark_solver.py \
    --profile all \
    --iterations 1 \
    --max-seconds 20 \
    --max-peak-mib 256

output_dir=${1:-dist}
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
if [[ -n $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "release refused: output directory is not empty: $output_dir" >&2
    exit 2
fi

release_temp=$(mktemp -d)
cleanup() {
    if [[ -n ${release_temp:-} && -d $release_temp ]]; then
        rm -rf -- "$release_temp"
    fi
}
trap cleanup EXIT

git archive --format=tar HEAD | tar -xf - -C "$release_temp"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
(
    cd "$release_temp"
    python3 -m build --no-isolation --outdir "$output_dir"
)
python3 scripts/normalize_release_archives.py \
    --epoch "$SOURCE_DATE_EPOCH" "$output_dir"/*
python3 scripts/check_release_archive.py "$output_dir"/*
(
    cd "$release_temp"
    python3 scripts/verify_reproducible_build.py --reference "$output_dir"
)
python3 scripts/generate_release_metadata.py \
    --dist "$output_dir" \
    --commit "$(git rev-parse HEAD)"
sha256sum "$output_dir"/*
