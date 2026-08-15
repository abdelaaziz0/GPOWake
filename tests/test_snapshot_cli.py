from __future__ import annotations

import json

from gpowake.cli import main
from gpowake.models import Link
from gpowake.snapshot import load_snapshot, save_snapshot

from conftest import DANGEROUS_DN, SAFE_DN, environment, som_sd
from gpowake.acl import GPLINK_GUID


def test_snapshot_round_trip_and_cli_json(tmp_path) -> None:
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    snapshot = tmp_path / "snapshot.json"
    report = tmp_path / "report.json"
    save_snapshot(env, snapshot)
    loaded = load_snapshot(snapshot)
    assert len(loaded.gpos) == 2
    assert loaded.som(env.targets[0].som_dn).links[0].order == 1
    assert main(["scan", "--snapshot", str(snapshot), "--output", str(report)]) == 0
    document = json.loads(report.read_text())
    assert document["finding_count"] >= 1
    assert any(item["reason"] == "SAME_SCOPE_MASKED" for item in document["findings"])
