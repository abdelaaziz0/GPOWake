from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from .models import CoverageGap, Finding
from .redaction import display_value, redact_sensitive, redact_value
from .secure_io import secure_write_text


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
    document = _convert(asdict(finding))
    document["dormant_value"] = redact_value(
        finding.dormant_value, finding.value_sensitivity
    )
    document["result_value"] = redact_value(
        finding.result_value, finding.value_sensitivity
    )
    document["current_value"] = redact_value(
        finding.current_value, finding.current_value_sensitivity
    )
    document["impact"] = {
        "rating": finding.severity.value,
        "score": finding.score,
    }
    return redact_sensitive(document)


def coverage_gap_to_dict(gap: CoverageGap) -> dict[str, Any]:
    return _convert(asdict(gap))


def report_document(
    findings: list[Finding],
    source_dc: str | None = None,
    warnings: list[str] | None = None,
    *,
    coverage_gaps: list[CoverageGap] | None = None,
    ldap_endpoint: str | None = None,
    smb_endpoint: str | None = None,
    tls_verified: bool | None = None,
    collected_at: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 5,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_dc": source_dc,
        "ldap_endpoint": ldap_endpoint,
        "smb_endpoint": smb_endpoint,
        "tls_verified": tls_verified,
        "collected_at": collected_at,
        "finding_count": len(findings),
        "coverage_gap_count": len(coverage_gaps or []),
        "warnings": warnings or [],
        "findings": [finding_to_dict(finding) for finding in findings],
        "coverage_gaps": [
            coverage_gap_to_dict(gap) for gap in (coverage_gaps or [])
        ],
    }


def write_json_report(document: dict[str, Any], path: str | Path | None = None) -> str:
    rendered = json.dumps(redact_sensitive(document), indent=2, sort_keys=False) + "\n"
    if path:
        secure_write_text(path, rendered)
    return rendered


def iter_jsonl(
    findings: list[Finding],
    warnings: list[str] | None = None,
    coverage_gaps: list[CoverageGap] | None = None,
) -> Iterator[str]:
    """Render independently parseable records without one giant JSON document."""

    def line(record: dict[str, Any]) -> str:
        return json.dumps(record, separators=(",", ":")) + "\n"

    yield line(
        {
            "record_type": "summary",
            "schema_version": 1,
            "finding_count": len(findings),
            "coverage_gap_count": len(coverage_gaps or []),
            "warning_count": len(warnings or []),
        }
    )
    for warning in warnings or []:
        yield line({"record_type": "warning", "message": warning})
    for gap in coverage_gaps or []:
        yield line({"record_type": "coverage_gap", **coverage_gap_to_dict(gap)})
    for finding in findings:
        yield line({"record_type": "finding", **finding_to_dict(finding)})


def render_jsonl(
    findings: list[Finding],
    warnings: list[str] | None = None,
    coverage_gaps: list[CoverageGap] | None = None,
) -> str:
    return "".join(iter_jsonl(findings, warnings, coverage_gaps))


def _render_path(actions) -> str:
    return "\n".join(
        f"  {index}. {action.description}" for index, action in enumerate(actions, 1)
    )


def render_finding(finding: Finding) -> str:
    winner = finding.current_winner or "None"
    action_lines = _render_path(finding.actions)
    alternatives = ""
    if finding.alternative_paths:
        blocks = []
        for letter, path in zip("BCDEFGHIJ", finding.alternative_paths):
            blocks.append(f"  Alternative {letter}:\n" + _render_path(path))
        alternatives = "Other minimal paths:\n" + "\n".join(blocks) + "\n"
    targets = ", ".join(finding.targets)
    gpt_evidence = "; ".join(
        f"{item.target}:{item.source.value}:{item.oracle}/{item.oracle_version}"
        for item in finding.gpt_access_provenance
    ) or "offline fixture/no structured observation"
    return (
        f"[{finding.finding_id}] Candidate activation path ({finding.outcome.value})\n"
        f"Principal:       {finding.principal} ({finding.principal_sid})\n"
        f"Capabilities:    {', '.join(item.value for item in finding.capabilities)}\n"
        f"Dormant GPO:     {finding.gpo_name}\n"
        f"Setting:         {finding.setting_name}\n"
        f"Dormant value:   {display_value(finding.dormant_value, finding.value_sensitivity)}\n"
        f"Current value:   {display_value(finding.current_value, finding.current_value_sensitivity)}\n"
        f"New trustees:    {', '.join(finding.newly_privileged_trustees) or 'N/A'}\n"
        f"Risk rule:       {finding.rule_id or 'explicit snapshot rule'}\n"
        f"Current reason:  {finding.reason.value}\n"
        f"Current winner:  {winner}\n"
        f"Minimal action:\n{action_lines}\n"
        f"{alternatives}"
        f"Actions needed:  {len(finding.actions)}\n"
        f"Requires GPO edit: {'Yes' if finding.requires_gpo_edit else 'No'}\n"
        f"Result:          {finding.setting_name} = "
        f"{display_value(finding.result_value, finding.value_sensitivity)}\n"
        f"Outcome:         {finding.outcome.value}\n"
        f"Impact:          {finding.severity.value} ({finding.score}/10)\n"
        f"Confidence:      {finding.confidence.value}\n"
        f"Confidence why:  {'; '.join(finding.confidence_reasons) or 'N/A'}\n"
        f"GPT evidence:    {gpt_evidence}\n"
        f"Blast radius:    {targets}"
    )


def render_text(
    findings: list[Finding],
    warnings: list[str] | None = None,
    coverage_gaps: list[CoverageGap] | None = None,
) -> str:
    sections: list[str] = []
    if warnings:
        sections.append(
            "Collection warnings:\n" + "\n".join(f"- {warning}" for warning in warnings)
        )
    if not findings:
        sections.append("No candidate activation paths were found.")
    else:
        sections.extend(render_finding(finding) for finding in findings)
    if coverage_gaps:
        sections.append(
            "Coverage gaps:\n"
            + "\n".join(
                f"- [{gap.gap_id}] {gap.gate}: {gap.reason} "
                f"({gap.principal} -> {gap.target}, {gap.gpo_name})"
                for gap in coverage_gaps
            )
        )
    return "\n\n".join(sections) + "\n"



_PROTO = "GPOWAKE"
_SEVERITY_MARKER = {"CRITICAL": "+", "HIGH": "+", "MEDIUM": "*", "LOW": "-"}
_MARKER_COLOR = {
    "+": "\033[92m",
    "*": "\033[94m",
    "-": "\033[93m",
    "!": "\033[95m",
    "?": "\033[93m",
}
_RESET = "\033[0m"


def _tag(marker: str, color: bool) -> str:
    if color and marker in _MARKER_COLOR:
        return f"{_MARKER_COLOR[marker]}[{marker}]{_RESET}"
    return f"[{marker}]"


def _fit(value: str, width: int) -> str:
    value = value or ""
    if len(value) > width:
        return value[: width - 2] + ".."
    return f"{value:<{width}}"


def _nxc_line(col: str, severity: str, marker: str, message: str, color: bool) -> str:
    return (
        f"{_PROTO:<8} {_fit(col, 28)} {severity:<8} "
        f"{_tag(marker, color)} {message}"
    )


def _path_label(actions) -> str:
    return " + ".join(action.type.value for action in actions)


def _format_value(value) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    if isinstance(value, dict):
        return ";".join(f"{key}={item}" for key, item in value.items())
    return str(value)


def render_netexec(
    findings: list[Finding],
    warnings: list[str] | None = None,
    color: bool = False,
    coverage_gaps: list[CoverageGap] | None = None,
) -> str:
    lines: list[str] = []
    for warning in warnings or []:
        lines.append(_nxc_line("", "", "!", warning, color))
    for gap in coverage_gaps or []:
        lines.append(
            _nxc_line(
                gap.gpo_name,
                "",
                "?",
                f"coverage gap {gap.gate}: {gap.reason} "
                f"({gap.principal} -> {gap.target})  {gap.gap_id}",
                color,
            )
        )
    if not findings:
        lines.append(
            _nxc_line(
                "", "", "*", "no candidate activation paths found", color
            )
        )
        return "\n".join(lines) + "\n"
    for finding in findings:
        severity = finding.severity.value
        marker = (
            _SEVERITY_MARKER.get(severity, "*")
            if finding.outcome.value == "PROVEN"
            else "?"
        )
        message = (
            f"{finding.principal} -> {finding.setting_name}="
            f"{_format_value(redact_value(finding.result_value, finding.value_sensitivity))} "
            f"via {_path_label(finding.actions)}  "
            f"(outcome={finding.outcome.value}; impact={severity}/{finding.score}; "
            f"confidence={finding.confidence.value}; {finding.reason.value})  "
            f"{finding.finding_id}"
        )
        lines.append(_nxc_line(finding.gpo_name, severity, marker, message, color))
        lines.append(
            _nxc_line(
                finding.gpo_name,
                severity,
                "*",
                f"    hosts ({len(finding.targets)}): " + ", ".join(finding.targets),
                color,
            )
        )
        for alternative in finding.alternative_paths:
            lines.append(
                _nxc_line(
                    finding.gpo_name,
                    severity,
                    "*",
                    "    alt: " + _path_label(alternative),
                    color,
                )
            )
    return "\n".join(lines) + "\n"


def render_explanation(finding: dict[str, Any]) -> str:
    """Render the authorization and policy decision tree from report evidence."""

    finding = redact_sensitive(finding)

    lines = [
        f"[{finding.get('finding_id')}] {finding.get('outcome', 'POSSIBLE')} candidate",
        f"Actor: {finding.get('principal')} ({finding.get('principal_sid')})",
        f"Rule: {finding.get('rule_id') or 'explicit snapshot rule'}",
        (
            f"Policy delta: {finding.get('setting_name')} "
            f"{finding.get('current_value')!r} -> {finding.get('result_value')!r}"
        ),
        "Newly privileged trustees: "
        + ", ".join(finding.get("newly_privileged_trustees") or ["none recorded"]),
        "",
        "Current LSDOU trace:",
    ]
    lines.extend(f"  {item}" for item in finding.get("current_processing_trace", []))
    lines.extend(("", "Counterfactual actions:"))
    for index, action in enumerate(finding.get("actions", []), 1):
        lines.append(f"  {index}. {action.get('description')}")
        if action.get("dacl_rewrite_mode"):
            lines.append(f"     DACL mode: {action['dacl_rewrite_mode']}")
        for evidence in action.get("authorization", []):
            lines.append(
                "     auth: "
                + evidence.get("detail", evidence.get("source", "authorization evidence"))
            )
        newly_exposed = action.get("newly_exposed_rights", [])
        if newly_exposed:
            lines.append(
                "     newly exposed rights: " + ", ".join(newly_exposed)
            )
        for ace in action.get("dacl_removed", []):
            lines.append(
                "     DACL remove: "
                f"{ace.get('ace_type')} {ace.get('trustee_sid')} "
                f"mask={ace.get('access_mask')} object={ace.get('object_type')}"
            )
        for ace in action.get("dacl_added", []):
            lines.append(
                "     DACL add: "
                f"{ace.get('ace_type')} {ace.get('trustee_sid')} "
                f"mask={ace.get('access_mask')} object={ace.get('object_type')}"
            )
        collateral_trustees = action.get("collateral_trustees", [])
        if collateral_trustees:
            lines.append(
                "     collateral trustees: " + ", ".join(collateral_trustees)
            )
        for effect in action.get("collateral_effects", []):
            lines.append(f"     collateral effect: {effect}")
    lines.extend(("", "Counterfactual LSDOU trace:"))
    lines.extend(
        f"  {item}" for item in finding.get("counterfactual_trace", [])
    )
    reasons = finding.get("uncertainty_reasons", [])
    if reasons:
        lines.extend(("", "Uncertainty:"))
        lines.extend(f"  - {reason}" for reason in reasons)
    confidence_reasons = finding.get("confidence_reasons", [])
    lines.extend(
        (
            "",
            f"Impact: {finding.get('severity')} ({finding.get('score')}/10)",
            f"Confidence: {finding.get('confidence', 'LOW')}",
        )
    )
    lines.extend(f"  - {reason}" for reason in confidence_reasons)
    provenance = finding.get("gpt_access_provenance", [])
    if provenance:
        lines.extend(("", "Target GPT access provenance:"))
        for item in provenance:
            lines.append(
                f"  {item.get('target')}: {item.get('decision')} via "
                f"{item.get('source')} {item.get('oracle')}/"
                f"{item.get('oracle_version')} on {item.get('dc')} at "
                f"{item.get('observed_at')} snapshot={item.get('snapshot_sha256')}"
            )
            lines.append(
                f"    identity: {item.get('credential_principal')} SID="
                f"{item.get('authenticated_sid')} "
                f"attestation={item.get('identity_attestation')}"
            )
    return "\n".join(lines) + "\n"
