from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .models import Finding


def _convert(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_convert(item) for item in value]
    if isinstance(value, list):
        return [_convert(item) for item in value]
    if isinstance(value, dict):
        return {key: _convert(item) for key, item in value.items()}
    return value


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return _convert(asdict(finding))


def report_document(
    findings: list[Finding],
    source_dc: str | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_dc": source_dc,
        "finding_count": len(findings),
        "warnings": warnings or [],
        "findings": [finding_to_dict(finding) for finding in findings],
    }


def write_json_report(document: dict[str, Any], path: str | Path | None = None) -> str:
    rendered = json.dumps(document, indent=2, sort_keys=False) + "\n"
    if path:
        Path(path).write_text(rendered, encoding="utf-8")
    return rendered


def render_finding(finding: Finding) -> str:
    winner = finding.current_winner or "None"
    action_lines = "\n".join(
        f"  {index}. {action.description}"
        for index, action in enumerate(finding.actions, 1)
    )
    targets = ", ".join(finding.targets)
    return (
        f"[{finding.finding_id}] Existing dangerous setting can be activated\n"
        f"Principal:       {finding.principal} ({finding.principal_sid})\n"
        f"Capabilities:    {', '.join(item.value for item in finding.capabilities)}\n"
        f"Dormant GPO:     {finding.gpo_name}\n"
        f"Setting:         {finding.setting_name}\n"
        f"Dormant value:   {finding.dormant_value}\n"
        f"Current reason:  {finding.reason.value}\n"
        f"Current winner:  {winner}\n"
        f"Minimal action:\n{action_lines}\n"
        f"Actions needed:  {len(finding.actions)}\n"
        f"Requires GPO edit: {'Yes' if finding.requires_gpo_edit else 'No'}\n"
        f"Result:          {finding.setting_name} = {finding.result_value}\n"
        f"Confidence:      {finding.confidence}\n"
        f"Severity:        {finding.severity.value} ({finding.score}/10)\n"
        f"Blast radius:    {targets}"
    )


def render_text(findings: list[Finding], warnings: list[str] | None = None) -> str:
    sections: list[str] = []
    if warnings:
        sections.append(
            "Collection warnings:\n" + "\n".join(f"- {warning}" for warning in warnings)
        )
    if not findings:
        sections.append("No activatable dormant dangerous settings were found.")
    else:
        sections.extend(render_finding(finding) for finding in findings)
    return "\n\n".join(sections) + "\n"
