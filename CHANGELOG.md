# Changelog

## 0.3.0 - 2026-08-25

- Enforced a replay invariant for every claimed target and split target-specific
  DACL grants into separate findings instead of reporting a false shared blast radius.
- Replaced globally contagious target-token uncertainty with exact unresolved
  trustee SIDs and target-specific WMI/GPT observations.
- Made `can_*` APIs strict Boolean wrappers, made tri-state decisions non-truthy,
  and classified unverified owner-implicit access as `UNKNOWN`.
- Made DACL grants additive, order-preserving, and refusal-based when an explicit
  deny/unsupported ACE would need weakening; reports include exact exposed rights.
- Added structured coverage-gap records for unresolved policy inputs instead of
  suppressing them invisibly or emitting optimistic findings.
- Scoped policy uncertainty by setting key/family and GPO/link branch, so an
  unreadable unrelated CSE file no longer suppresses every candidate.
- Replaced free-form GPT evidence with a schema-2 machine-readable record and
  shipped a target-machine authenticated, DC-pinned effective SMB read oracle.
  Evidence is bound to the snapshot, target/token, GPO versions, UNC, access
  mask, collection time, and per-file hashes; only actual access denial is DENY.
  The source-snapshot digest and compact oracle provenance survive into findings.
- Separated conservative `ADDITIVE_GRANT` paths from opt-in
  `EXPLICIT_BLOCKER_REWRITE` paths with exact ACE deltas, collateral trustees, and
  observed before/after authorization effects.
- Separated collector SYSVOL readability from target GPT authorization, tracked
  incomplete policy-file collection, and confined bounded SMB reads to the expected
  SYSVOL GPO root.
- Added LDAP/SMB timeouts, retry/page/query budgets, disabled LDAP referrals,
  primary-group ancestry, zero-mask unsupported-ACE trustee resolution, and
  conservative foreign-trustee handling.
- Bumped snapshots and reports to schema 4, with strict Boolean input
  validation and read-compatible schema-1/schema-2/schema-3 loading. Unsafe
  pre-schema-4 free-form GPT observations are discarded during migration.
- Split impact from confidence in JSON, text, NetExec-style, JSONL, and explain
  output; unvalidated model paths remain explicitly POSSIBLE/LOW confidence.
- Added hard candidate/finding budgets, a preflight work estimate, JSONL records,
  and best/typical/adversarial benchmarks with time and memory thresholds.
- Expanded automatic classification beyond 13 privilege rights with narrow rules
  for local Administrators membership and five exact credential/security states.
- Fixed undecodable-trustee explicit-ACE dispatch and the solver gate that
  prematurely suppressed opt-in explicit-blocker rewrite paths.
- Rejected SMB guest sessions and unattestable Kerberos-cache identities, added
  aggregate snapshot/oracle I/O budgets and an independent transition budget,
  and corrected Restricted Groups privilege-delta subtraction.
- Added Ruff F821, mypy, a Python 3.10-3.13 test matrix, replay regressions, and
  adversarial tests for malformed snapshots and incomplete policy evidence. Added
  multi-profile performance benchmarks and clean tagged-archive release checks.

## 0.2.0 - 2026-08-25

- Replaced Boolean authorization with `ALLOW`, `DENY`, and `UNKNOWN` decisions plus ACE/owner evidence.
- Corrected implicit owner rights, unsupported Owner Rights handling, and `BlockOwnerImplicitRights` modeling.
- Replaced append-only `WRITE_DAC` transitions with canonical DACL rewrites and exact ACE-change evidence.
- Made capability caches token-sensitive and cached modified policy evaluations by state fingerprint.
- Added exact-domain privilege trustee validation and delta-aware newly privileged trustees.
- Made LDAPS certificate/hostname validation mandatory by default and verified LDAP/SMB peer consistency.
- Replaced per-computer `tokenGroups` collection with referenced-group resolution and made broad collection opt-in.
- Added endpoint/version/USN/hash provenance, policy traces, outcome classes, and a rendered `explain` decision tree.
- Aggregated findings at target equivalence-class level and documented the 13-rule automatic coverage boundary.

## 0.1.0

- Initial research prototype.
