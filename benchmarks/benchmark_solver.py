from __future__ import annotations

import argparse
import json
import statistics
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

from gpowake.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_WRITE_PROP,
    APPLY_GROUP_POLICY_GUID,
    DIRECTORY_GENERIC_READ,
    GPLINK_GUID,
)
from gpowake.collectors.ldap import _relevant_gpo_trustee_sids
from gpowake.models import (
    Ace,
    AceType,
    Environment,
    GPO,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    Setting,
    SettingKind,
    Severity,
    SomKind,
    Target,
)
from gpowake.solver import CounterfactualSolver


DOMAIN_DN = "DC=benchmark,DC=invalid"
OU_DN = f"OU=Servers,{DOMAIN_DN}"
AUTHENTICATED_USERS = "S-1-5-11"


def synthetic_environment(
    principal_count: int,
    target_count: int,
    gpo_count: int,
    *,
    target_partition_count: int,
) -> Environment:
    principal_sids = [f"S-1-5-21-100-200-300-{1100 + index}" for index in range(principal_count)]
    target_sids = [f"S-1-5-21-100-200-300-{2100 + index}" for index in range(target_count)]
    som_descriptor = SecurityDescriptor(
        aces=tuple(
            Ace(sid, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID)
            for sid in principal_sids
        )
    )
    target_descriptor = SecurityDescriptor(
        aces=(
            Ace(AUTHENTICATED_USERS, AceType.ALLOW, DIRECTORY_GENERIC_READ),
            Ace(
                AUTHENTICATED_USERS,
                AceType.ALLOW,
                ADS_RIGHT_DS_CONTROL_ACCESS,
                APPLY_GROUP_POLICY_GUID,
            ),
            *(
                Ace(sid, AceType.ALLOW, DIRECTORY_GENERIC_READ)
                for sid in target_sids[:target_partition_count]
            ),
        )
    )
    gpos = {}
    for index in range(gpo_count):
        guid = f"{{00000000-0000-0000-0000-{index:012d}}}"
        gpo = GPO(
            dn=f"CN={guid},CN=Policies,CN=System,{DOMAIN_DN}",
            guid=guid,
            name=f"Dormant benchmark GPO {index}",
            settings=(
                Setting(
                    SettingKind.PRIVILEGE_RIGHT,
                    "SeDebugPrivilege",
                    (AUTHENTICATED_USERS,),
                    dangerous=True,
                    severity=Severity.CRITICAL,
                ),
            ),
            security_descriptor=target_descriptor,
        )
        gpos[gpo.dn.casefold()] = gpo
    return Environment(
        soms={
            DOMAIN_DN.casefold(): ScopeOfManagement(DOMAIN_DN, SomKind.DOMAIN),
            OU_DN.casefold(): ScopeOfManagement(
                OU_DN,
                SomKind.OU,
                parent_dn=DOMAIN_DN,
                security_descriptor=som_descriptor,
            ),
        },
        gpos=gpos,
        principals=[
            Principal(sid, f"actor-{index}", ())
            for index, sid in enumerate(principal_sids)
        ],
        targets=[
            Target(
                dn=f"CN=host-{index},{OU_DN}",
                name=f"host-{index}",
                sid=sid,
                som_dn=OU_DN,
                token_sids=(AUTHENTICATED_USERS,),
            )
            for index, sid in enumerate(target_sids)
        ],
    )


def run_once(
    environment: Environment, *, max_candidates: int, max_findings: int
) -> tuple[float, int, float, int]:
    tracemalloc.start()
    started = time.perf_counter()
    solver = CounterfactualSolver(
        environment,
        max_candidate_evaluations=max_candidates,
        max_findings=max_findings,
    )
    findings = solver.solve()
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return (
        elapsed,
        len(findings),
        peak / (1024 * 1024),
        solver.candidate_evaluations,
    )


@dataclass(frozen=True)
class Profile:
    name: str
    principals: int
    targets: int
    gpos: int
    target_partitions: int


PROFILES = {
    "best": Profile("best", 3, 250, 10, 0),
    "typical": Profile("typical", 3, 250, 10, 8),
    "adversarial": Profile("adversarial", 3, 100, 10, 100),
}


def _run_profile(args, base: Profile) -> dict[str, object]:
    principals = args.principals or base.principals
    targets = args.targets or base.targets
    gpos = args.gpos or base.gpos
    partitions = {
        "best": 0,
        "typical": min(8, targets),
        "adversarial": targets,
    }[base.name]
    environment = synthetic_environment(
        principals,
        targets,
        gpos,
        target_partition_count=partitions,
    )
    trustee_count = len(_relevant_gpo_trustee_sids(environment.gpos))
    estimate = CounterfactualSolver(environment).estimate_work()
    samples = [
        run_once(
            environment,
            max_candidates=args.max_candidates,
            max_findings=args.max_findings,
        )
        for _index in range(args.iterations)
    ]
    seconds = [sample[0] for sample in samples]
    finding_counts = {sample[1] for sample in samples}
    candidate_counts = {sample[3] for sample in samples}
    groups = partitions + (1 if partitions < targets else 0)
    expected = principals * groups * gpos
    if finding_counts != {expected}:
        raise RuntimeError(
            f"{base.name} invariant failed: expected {expected} findings, "
            f"got {finding_counts}"
        )
    if candidate_counts != {expected} or (
        estimate.candidate_evaluations_upper_bound != expected
    ):
        raise RuntimeError(
            f"{base.name} candidate invariant failed: expected {expected}, "
            f"got samples={candidate_counts}, estimate="
            f"{estimate.candidate_evaluations_upper_bound}"
        )
    median = statistics.median(seconds)
    peak = max(sample[2] for sample in samples)
    result: dict[str, object] = {
        "profile": base.name,
        "principals": principals,
        "targets": targets,
        "gpos": gpos,
        "target_equivalence_groups": groups,
        "trustees": trustee_count,
        "candidate_evaluations": expected,
        "findings": expected,
        "iterations": args.iterations,
        "median_seconds": round(median, 6),
        "peak_mib": round(peak, 3),
    }
    if args.max_seconds is not None and median > args.max_seconds:
        raise RuntimeError(
            f"{base.name} median {median:.3f}s exceeded threshold "
            f"{args.max_seconds:.3f}s"
        )
    if args.max_peak_mib is not None and peak > args.max_peak_mib:
        raise RuntimeError(
            f"{base.name} peak {peak:.1f}MiB exceeded threshold "
            f"{args.max_peak_mib:.1f}MiB"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthetic GPOWake solver benchmark")
    parser.add_argument(
        "--profile", choices=("best", "typical", "adversarial", "all"), default="all"
    )
    parser.add_argument("--principals", type=int)
    parser.add_argument("--targets", type=int)
    parser.add_argument("--gpos", type=int)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--max-seconds", type=float)
    parser.add_argument("--max-peak-mib", type=float)
    parser.add_argument("--max-candidates", type=int, default=250_000)
    parser.add_argument("--max-findings", type=int, default=100_000)
    parser.add_argument("--jsonl", help="write one machine-readable result per profile")
    args = parser.parse_args()
    counts = [args.iterations, args.max_candidates, args.max_findings]
    counts.extend(
        value for value in (args.principals, args.targets, args.gpos) if value is not None
    )
    if min(counts) < 1:
        parser.error("all counts and budgets must be positive")
    names = tuple(PROFILES) if args.profile == "all" else (args.profile,)
    results = [_run_profile(args, PROFILES[name]) for name in names]
    for result in results:
        print(json.dumps(result, sort_keys=True))
    if args.jsonl:
        Path(args.jsonl).write_text(
            "".join(json.dumps(result, sort_keys=True) + "\n" for result in results),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
