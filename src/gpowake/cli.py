from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .gpt_oracle import SmbOracleConfig, collect_smb_effective_observations
from .observations import MAX_OBSERVATION_FILE_BYTES, import_gpt_access_observations
from .parsers.gpttmpl import parse_gpttmpl_file
from .report import (
    render_explanation,
    iter_jsonl,
    render_netexec,
    render_text,
    report_document,
    write_json_report,
)
from .snapshot import load_snapshot, save_snapshot
from .solver import CounterfactualSolver


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gpowake",
        description="Find candidate paths that may activate dormant dangerous GPO settings",
    )
    parser.add_argument("--version", action="version", version="GPOWake 0.3.0")
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
    scan.add_argument(
        "--explicit-blocker-rewrite",
        "--full-dacl-rewrite",
        dest="explicit_blocker_rewrite",
        action="store_true",
        help=(
            "include high-collateral WRITE_DAC paths that remove applicable "
            "explicit blockers; --full-dacl-rewrite is a deprecated alias"
        ),
    )
    scan.add_argument(
        "--format",
        choices=("nxc", "text", "json", "jsonl"),
        default=None,
        help="output format (default: NetExec-style lines; json when -o ends in .json)",
    )
    scan.add_argument(
        "--output", "-o", help="write the report to this path instead of stdout"
    )
    scan.add_argument("--save-snapshot", help="save live collection before analysis")
    scan.add_argument(
        "--max-candidates",
        type=int,
        default=250_000,
        help="hard candidate-evaluation budget (default: 250000)",
    )
    scan.add_argument(
        "--max-transitions",
        type=int,
        default=2_000_000,
        help="hard transition/replay evaluation budget (default: 2000000)",
    )
    scan.add_argument(
        "--max-findings",
        type=int,
        default=100_000,
        help="hard finding budget; exceeding it fails rather than truncates",
    )
    scan.add_argument(
        "--max-coverage-gaps",
        type=int,
        default=100_000,
        help="hard coverage-gap budget; exceeding it fails rather than truncates",
    )
    scan.add_argument(
        "--estimate-only",
        action="store_true",
        help="print the candidate-search upper bound without solving",
    )
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
    collect.add_argument(
        "--target",
        action="append",
        help="limit target by name, DN, or SID (repeatable)",
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

    import_access = commands.add_parser(
        "import-gpt-access",
        help="merge target-specific Windows/SMB GPT access observations",
    )
    import_access.add_argument("--snapshot", required=True)
    import_access.add_argument("--observations", required=True)
    import_access.add_argument("--output", "-o", required=True)
    import_access.add_argument(
        "--replace-existing",
        action="store_true",
        help="replace existing observations for the same target and GPO",
    )

    oracle = commands.add_parser(
        "oracle-gpt-access",
        help="probe target GPT reads over SMB as the target machine account",
    )
    oracle.add_argument("--snapshot", required=True)
    oracle.add_argument("--target", required=True, help="one target name, DN, or SID")
    selection = oracle.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--gpo", action="append", help="GPO name, DN, or GUID (repeatable)"
    )
    selection.add_argument(
        "--all-gpos",
        action="store_true",
        help="explicitly probe every hashed GPO in the snapshot",
    )
    oracle.add_argument("--output", "-o", required=True, help="observation JSON path")
    oracle.add_argument("--dc-ip", required=True, help="snapshot DC IP address")
    oracle.add_argument("--dc-host", help="DC hostname/SPN target")
    oracle.add_argument("--username", required=True, help="target machine account (HOST$)")
    oracle.add_argument("--password", default="", help="password (prefer --password-env)")
    oracle.add_argument("--password-env", help="read password from this environment variable")
    oracle.add_argument("--auth-domain", default="", help="NetBIOS authentication domain")
    oracle.add_argument("--hashes", help="LMHASH:NTHASH for NTLM authentication")
    oracle.add_argument("--smb-timeout", type=float, default=30.0)
    oracle.add_argument(
        "--max-sysvol-file-bytes", type=int, default=64 * 1024 * 1024
    )
    oracle.add_argument("--max-gpos", type=int, default=5_000)
    return parser


def _add_collection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dc-ip", help="domain controller IP address")
    parser.add_argument("--dc-host", help="domain controller hostname/SPN target")
    parser.add_argument("--ldap-uri", help="explicit ldap:// or ldaps:// URI")
    parser.add_argument(
        "--ca-file", help="PEM CA bundle for LDAPS (default: system trust store)"
    )
    parser.add_argument(
        "--tls-no-verify",
        action="store_true",
        help="disable LDAPS certificate and hostname verification (unsafe)",
    )
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
        "--allow-insecure-simple-bind",
        action="store_true",
        help="permit a SIMPLE bind password over cleartext ldap:// (unsafe)",
    )
    parser.add_argument(
        "--target-filter",
        default="(objectCategory=computer)",
        help="LDAP filter selecting computer targets",
    )
    parser.add_argument(
        "--all-targets",
        action="store_true",
        help="explicitly allow broad target collection (can load a DC heavily)",
    )
    parser.add_argument("--scope", choices=("computer",), default="computer")
    parser.add_argument(
        "--no-sysvol", action="store_true", help="collect LDAP metadata only"
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=10.0,
        help="LDAP connect timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--receive-timeout",
        type=float,
        default=30.0,
        help="LDAP response timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--ldap-page-size", type=int, default=500, help="LDAP page size (default: 500)"
    )
    parser.add_argument(
        "--max-ldap-queries",
        type=int,
        default=5000,
        help="hard LDAP query/attempt budget (default: 5000)",
    )
    parser.add_argument(
        "--max-group-queries",
        type=int,
        default=1000,
        help="recursive group-membership query budget (default: 1000)",
    )
    parser.add_argument(
        "--ldap-retries",
        type=int,
        default=2,
        help="bounded retries per LDAP search (default: 2)",
    )
    parser.add_argument(
        "--smb-timeout",
        type=float,
        default=30.0,
        help="SMB operation timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--max-sysvol-file-bytes",
        type=int,
        default=64 * 1024 * 1024,
        help="maximum bytes read from one SYSVOL file (default: 64 MiB)",
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
    solver = CounterfactualSolver(
        environment,
        max_actions=args.max_actions,
        explicit_blocker_rewrite=args.explicit_blocker_rewrite,
        max_candidate_evaluations=args.max_candidates,
        max_transition_evaluations=args.max_transitions,
        max_findings=args.max_findings,
        max_coverage_gaps=args.max_coverage_gaps,
    )
    if args.estimate_only:
        rendered = json.dumps(asdict(solver.estimate_work()), indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    findings = solver.solve()
    output_format = args.format or (
        (
            "json"
            if args.output and Path(args.output).suffix.casefold() == ".json"
            else "jsonl"
            if args.output and Path(args.output).suffix.casefold() == ".jsonl"
            else "nxc"
        )
    )
    if output_format == "json":
        rendered = write_json_report(
            report_document(
                findings,
                environment.source_dc,
                environment.warnings,
                coverage_gaps=solver.coverage_gaps,
                ldap_endpoint=environment.ldap_endpoint,
                smb_endpoint=environment.smb_endpoint,
                tls_verified=environment.tls_verified,
                collected_at=environment.collected_at,
            ),
            args.output,
        )
    elif output_format == "jsonl":
        if args.output:
            with Path(args.output).open("w", encoding="utf-8") as destination:
                destination.writelines(
                    iter_jsonl(findings, environment.warnings, solver.coverage_gaps)
                )
            rendered = ""
        else:
            for line in iter_jsonl(
                findings, environment.warnings, solver.coverage_gaps
            ):
                sys.stdout.write(line)
            return 0
    else:
        if output_format == "text":
            rendered = render_text(
                findings, environment.warnings, solver.coverage_gaps
            )
        else:
            # Colorize only when streaming to an interactive terminal.
            color = not args.output and sys.stdout.isatty()
            rendered = render_netexec(
                findings,
                environment.warnings,
                color=color,
                coverage_gaps=solver.coverage_gaps,
            )
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
    if not args.output:
        sys.stdout.write(rendered)
    return 0


def _collect_environment(args: argparse.Namespace):
    from .collectors import AuthConfig, CollectionConfig, collect_environment

    if not args.dc_ip:
        raise ValueError("live collection requires --dc-ip")
    if not getattr(args, "target", None) and not args.all_targets:
        raise ValueError(
            "live collection requires at least one --target; use --all-targets "
            "to acknowledge the cost of broad collection"
        )
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
        allow_insecure_simple_bind=getattr(
            args, "allow_insecure_simple_bind", False
        ),
    )
    config = CollectionConfig(
        domain=args.domain,
        dc_ip=args.dc_ip,
        dc_host=args.dc_host,
        ldap_uri=args.ldap_uri,
        principals=tuple(args.principal or ()),
        target_filter=args.target_filter,
        target_names=tuple(getattr(args, "target", None) or ()),
        auth=auth,
        collect_sysvol=not args.no_sysvol,
        ca_file=args.ca_file,
        tls_no_verify=args.tls_no_verify,
        allow_all_targets=args.all_targets,
        connect_timeout=args.connect_timeout,
        receive_timeout=args.receive_timeout,
        ldap_page_size=args.ldap_page_size,
        max_ldap_queries=args.max_ldap_queries,
        max_group_queries=args.max_group_queries,
        retry_limit=args.ldap_retries,
        smb_timeout=args.smb_timeout,
        max_sysvol_file_bytes=args.max_sysvol_file_bytes,
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
    sys.stdout.write(render_explanation(finding))
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


def _import_gpt_access(args: argparse.Namespace) -> int:
    snapshot_path = Path(args.snapshot)
    environment = load_snapshot(snapshot_path)
    hasher = hashlib.sha256()
    with snapshot_path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    count = import_gpt_access_observations(
        environment,
        args.observations,
        snapshot_sha256=hasher.hexdigest(),
        replace_existing=args.replace_existing,
    )
    save_snapshot(environment, args.output)
    print(f"Imported {count} GPT access observation(s) into {args.output}")
    return 0


def _sha256_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _smb_auth(args: argparse.Namespace):
    from .collectors import AuthConfig

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
    return AuthConfig(
        username=args.username,
        password=password,
        auth_domain=args.auth_domain,
        lmhash=lmhash,
        nthash=nthash,
        kerberos=False,
        ccache=None,
    )


def _oracle_gpt_access(args: argparse.Namespace) -> int:
    snapshot_path = Path(args.snapshot)
    environment = load_snapshot(snapshot_path)
    digest = _sha256_path(snapshot_path)
    selectors = tuple(args.gpo or ())
    if args.all_gpos:
        selectors = tuple(gpo.dn for gpo in environment.gpos.values() if gpo.gpt_hashes)
    document = collect_smb_effective_observations(
        environment,
        snapshot_sha256=digest,
        config=SmbOracleConfig(
            dc_ip=args.dc_ip,
            dc_host=args.dc_host,
            target_selector=args.target,
            gpo_selectors=selectors,
            auth=_smb_auth(args),
            timeout=args.smb_timeout,
            max_file_bytes=args.max_sysvol_file_bytes,
            max_gpos=args.max_gpos,
        ),
    )
    rendered = json.dumps(document, indent=2) + "\n"
    if len(rendered.encode("utf-8")) > MAX_OBSERVATION_FILE_BYTES:
        raise ValueError(
            f"oracle output exceeds the {MAX_OBSERVATION_FILE_BYTES}-byte import limit; "
            "select fewer GPOs"
        )
    Path(args.output).write_text(rendered, encoding="utf-8")
    observation_rows = document.get("observations")
    observation_count = len(observation_rows) if isinstance(observation_rows, list) else 0
    print(
        f"Wrote {observation_count} authenticated GPT access "
        f"observation(s) to {args.output}"
    )
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
        if args.command == "import-gpt-access":
            return _import_gpt_access(args)
        if args.command == "oracle-gpt-access":
            return _oracle_gpt_access(args)
    except (
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"gpowake: error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
