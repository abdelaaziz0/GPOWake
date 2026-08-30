from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .secure_io import scoped_credential_cache, scoped_private_key_file


@contextmanager
def pkinit_credential_cache(
    *,
    pfx_path: str,
    pfx_password: str,
    username: str,
    domain: str,
    dc_ip: str,
    dc_host: str,
    timeout: float,
) -> Iterator[str]:
    """Acquire a temporary PKINIT TGT and expose it only inside this scope."""

    try:
        from .pkinit_backend import request_pkinit_tgt
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError(
            "PFX/PKINIT authentication requires the 'pkinit' extra"
        ) from exc

    with scoped_private_key_file(pfx_path) as stable_pfx:
        with tempfile.TemporaryDirectory(prefix="gpowake-pkinit-") as workdir:
            cache_path = Path(workdir, "pkinit.ccache")
            previous_umask = os.umask(0o077)
            try:
                request_pkinit_tgt(
                    pfx_path=stable_pfx,
                    pfx_password=pfx_password,
                    username=username,
                    domain=domain,
                    dc_ip=dc_ip,
                    output_path=str(cache_path),
                    timeout=timeout,
                )
            finally:
                os.umask(previous_umask)
            if not cache_path.is_file():
                raise RuntimeError("PFX PKINIT authentication did not produce a TGT")
            os.chmod(cache_path, 0o600)
            with scoped_credential_cache(cache_path) as cache_name:
                yield cache_name
