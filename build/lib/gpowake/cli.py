from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .parsers.gpttmpl import parse_gpttmpl_file
from .report import render_text, report_document, write_json_report
from .snapshot import load_snapshot, save_snapshot
from .solver import CounterfactualSolver


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gpowake",
        description="Find minimal changes that activate dormant dangerous GPO settings",
    )
    parser.add_argument("--version", action="version", version="GPOWake 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="analyze a collected JSON snapshot")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--snapshot", help="GPOWake snapshot JSON")
    source.add_argument("--domain", help="collect live from this DNS domain")
    scan.add_argument(
        "--principal", action="append", help="limit actor by name or SID (repeatable)"
    )
    scan.add_argument(
        "--target",
        action="append",
        help="limit target by name, DN, or SID (repeatable)",
    )
    scan.add_argument("--max-actions", type=int, choices=(1, 2), default=1)
    scan.add_argument("--format", choices=("text", "json"), default=None)
    scan.add_argument("--output", "-o", help="write report to this path")
    scan.add_argument("--save-snapshot", help="save live collection before analysis")
    _add_collection_arguments(scan)

    collect = commands.add_parser(
        "collect", help="collect LDAP and SYSVOL into an offline snapshot"
    )
    collect.add_argument("--domain", required=True, help="DNS domain name")
    collect.add_argument(
        "--principal",
        action="append",
        required=True,
        help="actor name, DN, or SID (repeatable)",
    )
    collect.add_argument("--output", "-o", required=True, help="snapshot JSON path")
    _add_collection_arguments(collect)

    explain = commands.add_parser(
        "explain", help="render one finding from a JSON report"
    )
    explain.add_argument("--finding", required=True)
    explain.add_argument("--report", required=True)

    parse = commands.add_parser(
        "parse-gpttmpl", help="parse a GptTmpl.inf into normalized JSON"
    )
    parse.add_argument("path")
    return parser


def _add_collection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dc-ip", help="domain controller IP address")
    parser.add_argument("--dc-host", help="domain controller hostname/SPN target")
    parser.add_argument("--ldap-uri", help="explicit ldap:// or ldaps:// URI")
    parser.add_argument("--username", default="")
    parser.add_argument(
        "--password", default="", help="password (prefer --password-env)"
    )
    parser.add_argument(
        "--password-env", help="read password from this environment variable"
    )
    parser.add_argument(
        "--auth-domain", default="", help="NetBIOS authentication domain"
    )
    parser.add_argument("--hashes", help="LMHASH:NTHASH for NTLM authentication")
    parser.add_argument("--kerberos", action="store_true")
    parser.add_argument("--ccache", help="Kerberos credential cache path")
    parser.add_argument(
        "--target-filter",
        default="(objectCategory=computer)",
        help="LDAP filter selecting computer targets",
    )
    parser.add_argument("--scope", choices=("computer",), default="computer")
    parser.add_argument(
        "--no-sysvol", action="store_true", help="collect LDAP metadata only"
    )


def _matches(value_set: list[str] | None, *values: str) -> bool:
    if not value_set:
        return True
    choices = {value.casefold() for value in values}
    return any(item.casefold() in choices for item in value_set)


def _scan(args: argparse.Namespace) -> int:
    if args.snapshot:
        environment = load_snapshot(args.snapshot)
        environment.principals = [
            item
            for item in environment.principals
            if _matches(args.principal, item.name, item.sid)
        ]
        environment.targets = [
            item
            for item in environment.targets
            if _matches(args.target, item.name, item.sid, item.dn)
        ]
        if args.principal and not environment.principals:
            raise ValueError("no requested principal exists in the snapshot")
        if args.target and not environment.targets:
            raise ValueError("no requested target exists in the snapshot")
    else:
        if not args.principal:
            raise ValueError("live scan requires at least one --principal")
        environment = _collect_environment(args)
        if args.target:
            environment.targets = [
                item
                for item in environment.targets
                if _matches(args.target, item.name, item.sid, item.dn)
            ]
        if args.save_snapshot:
            save_snapshot(environment, args.save_snapshot)
    findings = CounterfactualSolver(environment, max_actions=args.max_actions).solve()
    output_format = args.format or (
        "json"
        if args.output and Path(args.output).suffix.casefold() == ".json"
        else "text"
    )
    if output_format == "json":
        rendered = write_json_report(
            report_document(findings, environment.source_dc, environment.warnings),
            args.output,
        )
    else:
        rendered = render_text(findings, environment.warnings)
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
    if not args.output:
        sys.stdout.write(rendered)
    return 0


def _collect_environment(args: argparse.Namespace):
    from .collectors import AuthConfig, CollectionConfig, collect_environment

    if not args.dc_ip:
        raise ValueError("live collection requires --dc-ip")
    password = args.password
    if args.password_env:
        if args.password_env not in os.environ:
            raise ValueError(
                f"password environment variable {args.password_env!r} is not set"
            )
        password = os.environ[args.password_env]
    lmhash = nthash = ""
    if args.hashes:
        try:
            lmhash, nthash = args.hashes.split(":", 1)
        except ValueError as exc:
            raise ValueError("--hashes must be LMHASH:NTHASH") from exc
    if args.ccache:
        os.environ["KRB5CCNAME"] = (
            args.ccache if args.ccache.startswith("FILE:") else f"FILE:{args.ccache}"
        )
    auth = AuthConfig(
        username=args.username,
        password=password,
        auth_domain=args.auth_domain or args.domain.split(".", 1)[0].upper(),
        lmhash=lmhash,
        nthash=nthash,
        kerberos=args.kerberos,
        ccache=args.ccache,
    )
    config = CollectionConfig(
        domain=args.domain,
        dc_ip=args.dc_ip,
        dc_host=args.dc_host,
        ldap_uri=args.ldap_uri,
        principals=tuple(args.principal or ()),
        target_filter=args.target_filter,
        auth=auth,
        collect_sysvol=not args.no_sysvol,
    )
    return collect_environment(config)


def _collect(args: argparse.Namespace) -> int:
    environment = _collect_environment(args)
    save_snapshot(environment, args.output)
    print(
        f"Collected {len(environment.gpos)} GPOs, {len(environment.soms)} scopes, "
        f"and {len(environment.targets)} targets into {args.output}"
    )
    return 0


def _explain(args: argparse.Namespace) -> int:
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    finding = next(
        (
            item
            for item in report.get("findings", [])
            if item.get("finding_id") == args.finding
        ),
        None,
    )
    if finding is None:
        raise ValueError(f"finding {args.finding!r} does not exist in {args.report}")
    sys.stdout.write(json.dumps(finding, indent=2) + "\n")
    return 0


def _parse_template(args: argparse.Namespace) -> int:
    settings = parse_gpttmpl_file(args.path)
    data = [
        {
            "kind": item.kind.value,
            "name": item.name,
            "value": item.value,
            "dangerous": item.dangerous,
            "severity": item.severity.value,
            "rationale": item.rationale,
            "required_extension": item.required_extension,
        }
        for item in settings
    ]
    sys.stdout.write(json.dumps(data, indent=2) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "collect":
            return _collect(args)
        if args.command == "explain":
            return _explain(args)
        if args.command == "parse-gpttmpl":
            return _parse_template(args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"gpowake: error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
