#!/usr/bin/env python3
"""Root-level launcher for GPOWake, equivalent to `python -m gpowake`."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

BANNER = r"""
 ██████╗ ██████╗  ██████╗ ██╗    ██╗ █████╗ ██╗  ██╗███████╗
██╔════╝ ██╔══██╗██╔═══██╗██║    ██║██╔══██╗██║ ██╔╝██╔════╝
██║  ███╗██████╔╝██║   ██║██║ █╗ ██║███████║█████╔╝ █████╗
██║   ██║██╔═══╝ ██║   ██║██║███╗██║██╔══██║██╔═██╗ ██╔══╝
╚██████╔╝██║     ╚██████╔╝╚███╔███╔╝██║  ██║██║  ██╗███████╗
 ╚═════╝ ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
             dormant GPO activation finder
"""

if __name__ == "__main__":
    # Banner goes to stderr so it never corrupts -o file output or a piped
    # JSON/JSONL stream on stdout.
    print(BANNER, file=sys.stderr)
    from gpowake.cli import main

    raise SystemExit(main())
