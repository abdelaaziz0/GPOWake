# GPOWake

GPOWake is a Linux-first detector for dormant Active Directory Group Policy weaponization. It answers a counterfactual question:

> Given a dangerous setting already present in a GPO, is there a modeled one- or two-change candidate path that could make it effective against this computer?

It keeps activation separate from ordinary GPO-content weaponization. A finding must connect existing dangerous content, its current dormancy reason, the actor's effective permission, a minimal successful transition, and the resulting target set. GPOWake is read-only: it models transitions but never writes them to AD or SYSVOL.

## Implemented milestone

- Exact `gPLink` parsing, including stored order, disabled bit `0x1`, and enforced bit `0x2`.
- Separate `gPOptions` Block Inheritance handling.
- Site → domain → parent OU → child OU policy ordering.
- Normal and enforced precedence, including enforced ancestors and Block Inheritance boundaries.
- Computer-section, trustee-scoped security-filter, target-specific WMI, CSE-advertisement, and target GPT-readability gates.
- Tri-state (`ALLOW`/`DENY`/`UNKNOWN`) object-specific AD DACL checks for `WriteGPLink`, `WriteGPOptions`, GPO `flags`, and `WRITE_DAC`. The check walks the DACL in order, skips `INHERIT_ONLY` ACEs, grants owners only implicit `READ_CONTROL`/`WRITE_DAC` unless Owner Rights constrains them, models `BlockOwnerImplicitRights`, and returns `UNKNOWN` for relevant callback/conditional ACEs. `SELF` is not treated as universal token membership.
- `GptTmpl.inf` parsing for privilege rights, restricted groups, and registry-backed security options.
- Machine `Registry.pol` parsing for deterministic single-value policies.
- Bounded one- or two-action transition search, including two-step paths that first use `WRITE_DAC` on a SOM to grant `WriteGPLink`. Every reported path is replayed from the pristine snapshot against every target it claims.
- Live LDAP/SYSVOL collection pinned to one domain controller (owner and DACL) and offline JSON snapshots.
- NetExec-style, JSON, JSONL, and verbose-text findings with stable IDs, separately labeled impact and confidence, outcome class, blast radius, alternative paths, ACE/owner authorization evidence, LSDOU traces, versions, `uSNChanged`, endpoint provenance, and GPT hashes. Unresolved gates are emitted separately as structured coverage gaps.

Live automatic danger detection covers **13 computer-side user-right assignments**, both Restricted Groups forms that place unexpected trustees in builtin Administrators, and five exact security/registry states: remote blank-password use, LM-hash retention, disabled UAC, WDigest plaintext credential caching, and the presence of a stored AutoLogon password. AutoLogon password bytes are destroyed while parsing `Registry.pol`; only a non-reversible `secret_present` marker survives. Other Restricted Groups, security options, and `Registry.pol` values are normalized for evidence/precedence but are not automatically classified. Snapshot settings can explicitly set `dangerous`, `severity`, and `rationale` to extend coverage.

The privilege catalog is per-privilege and delta-aware: reports identify the current value and newly privileged trustees. Domain/Schema/Enterprise Admins are exempted only when their full SID matches the collected domain/forest-root SID; an external group is never trusted merely because its RID ends in `512`, `518`, or `519`.

All findings are currently `POSSIBLE` with `LOW` confidence, not `PROVEN`, because this repository does not yet contain the required Windows AuthZ/RSoP differential corpus. Impact is reported independently as `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` plus a score. Authorization or policy ambiguity is a separate coverage-gap record and is never promoted to an allowed transition.

## Install

Python 3.10 or newer is required.

```bash
python3 -m pip install -e '.[collect,dev]'
pytest
```

The core offline analyzer has no third-party runtime dependency. Live collection uses `ldap3` and `impacket` through the `collect` extra; Kerberos LDAP authentication also installs the platform GSSAPI binding.

## Quick start with the included lab

```bash
# NetExec-style lines straight to stdout
gpowake scan --snapshot examples/same_scope_masked.json --max-actions 1

# ... or save a machine-readable report
gpowake scan \
  --snapshot examples/same_scope_masked.json \
  --max-actions 1 \
  --output report.json

gpowake explain \
  --finding "$(python3 -c 'import json; print(json.load(open("report.json"))["findings"][0]["finding_id"])')" \
  --report report.json
```

By default `scan` prints NetExec-style, one-line-per-finding output to stdout (`GPOWAKE  <gpo>  <impact>  [?] ... impact=... confidence=...`), with indented `hosts:` and `alt:` continuation lines. `?` means a modeled `POSSIBLE` candidate. `-o/--output` writes to a file instead; `.json` and `.jsonl` select those formats automatically. JSONL begins with a summary and then emits independent warning, coverage-gap, and finding records. `gpowake explain` renders the stored authorization and policy decision tree rather than dumping raw JSON.

Snapshots, reports, and oracle evidence are replaced atomically. POSIX outputs are mode `0600`; native Windows outputs receive a current-user-only ACL before any sensitive content is written. Serialization and every renderer also apply a final fail-closed secret redaction boundary.

## Live collection and scan

NTLM password authentication prompts without echo when no credential source is supplied:

```bash
gpowake scan \
  --domain corp.local \
  --dc-ip 10.0.0.10 \
  --dc-host dc01.corp.local \
  --username auditor \
  --principal 'helpdesk-ops' \
  --target dc01.corp.local \
  --scope computer \
  --max-actions 1 \
  --save-snapshot corp-snapshot.json \
  --output report.json
```

Kerberos uses the current cache (a DC hostname is strongly recommended so the LDAP SPN is correct):

```bash
gpowake scan \
  --domain corp.local \
  --dc-ip 10.0.0.10 \
  --dc-host dc01.corp.local \
  --kerberos \
  --ccache /tmp/corp.ccache \
  --principal 'CORP\\helpdesk-ops' \
  --target dc01.corp.local \
  --output report.json
```

To separate evidence collection from analysis:

```bash
gpowake collect \
  --domain corp.local \
  --dc-ip 10.0.0.10 \
  --dc-host dc01.corp.local \
  --username auditor \
  --principal helpdesk-ops \
  --target dc01.corp.local \
  --output corp-snapshot.json

gpowake scan --snapshot corp-snapshot.json --principal helpdesk-ops --output report.json
```

For automation, pass credential JSON through an inherited descriptor (`--credential-fd 3`) or an owner-only regular file (`--credential-file`, mode `0600`). The JSON must contain exactly `{"password":"..."}` or exactly `{"lmhash":"...","nthash":"..."}`. Plaintext command arguments and environment-variable credential sources are not accepted. Native Windows requires a descriptor or interactive prompt because portable strict ACL validation for an input secrets file is unavailable.

Live collection requires at least one exact `--target` (name/DN/SID, repeatable), and applies it in the LDAP filter. Broad collection requires the explicit `--all-targets` acknowledgement. Target security-filter membership is resolved group-first for only the trustees referenced by GPO DACLs; `tokenGroups` is retained only for the small actor set. Unresolved membership is stored by trustee and affects only a DACL that names that trustee. Primary-group SIDs and their recursive parent-group closure are resolved once per distinct primary group under the shared group-query budget; foreign security principals remain unresolved. Unsupported ACE trustees are resolved even when their parsed mask is zero. Use a least-privileged read-only identity.

LDAPS uses `CERT_REQUIRED`, hostname checking, and the system trust store by default. `--ca-file` supplies a private CA bundle; `--tls-no-verify` is an explicit noisy escape hatch. The connected LDAP peer IP must match the IP used for SMB/SYSVOL, otherwise collection is rejected. Cleartext SIMPLE binds are refused unless `--allow-insecure-simple-bind` is supplied. LDAP referrals are disabled, and connection/read timeouts, bounded retries, page size, total LDAP queries, recursive group queries, SMB timeout, per-file SYSVOL size, aggregate SYSVOL bytes/files, and aggregate probe count are configurable from the CLI.

Collector access to a GPT proves only that the audit identity could read it. It does not prove a computer target can. Live-collected snapshots therefore require target-specific authorization evidence before the solver treats that GPT as applicable; otherwise the report contains a `TARGET_GPT_READ` coverage gap.

GPOWake ships a read-only effective-I/O oracle. Run it within 30 minutes of collection using the selected computer's machine account and NTLM authentication. The snapshot contains the LDAP-collected `sAMAccountName`, object SID, DNS domain, and NetBIOS domain. The oracle requires an exact canonical domain/account match, binds the same credential to LDAP on the pinned DC, resolves that exact computer object, and refuses the session unless its SID matches the snapshot target. Kerberos caches are intentionally not accepted. It then reconnects to the exact SMB peer, rejects guest sessions, explicitly opens each file with `GPT_FILE_GENERIC_READ`, performs bounded streaming reads and incremental SHA-256, continues after per-file denials, and refuses drift, missing files, transport errors, a different DC, or a stale snapshot.

Preflight uses snapshot-bound file sizes and rejects selections above the configured total bytes, files, or probes before authentication/network work. Runtime counters enforce the same limits across the entire selection. A denied `gpt.ini` is a global gate; `GptTmpl.inf` controls privilege rights, Restricted Groups, and security options; `Registry.pol` controls registry settings. Mixed results are `UNKNOWN` only at the aggregate row and remain deterministic per setting family:

```bash
gpowake oracle-gpt-access \
  --snapshot corp-snapshot.json \
  --target SRV1.corp.local \
  --gpo '{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}' \
  --dc-ip 10.0.0.10 \
  --dc-host dc01.corp.local \
  --username 'SRV1$' \
  --auth-domain CORP \
  --output gpt-access.json

gpowake import-gpt-access \
  --snapshot corp-snapshot.json \
  --observations gpt-access.json \
  --output corp-observed.json
```

An authenticated successful file open/read is the server-enforced effective result after both SMB share and NTFS authorization. This oracle does not claim it separately recovered either descriptor, so those hash fields are `null`. External `WINDOWS_AUTHZ_ACCESSCHECK` and `SMB_SHARE_NTFS_ACCESSCHECK` records must provide both descriptor hashes.

The machine-readable observation schema is strict. An effective-I/O row looks like:

```json
{
  "schema_version": 3,
  "snapshot_sha256": "<SHA-256 of corp-snapshot.json>",
  "preflight": {
    "selected_gpos": 1,
    "total_files": 2,
    "total_probes": 2,
    "total_bytes": 1200,
    "max_total_files": 10000,
    "max_total_probes": 10000,
    "max_total_bytes": 536870912
  },
  "observations": [
    {
      "target": "S-1-5-21-111-222-333-2100",
      "gpo": "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
      "decision": "UNKNOWN",
      "source": "SMB_EFFECTIVE_IO",
      "oracle": "gpowake-smb-effective-io",
      "oracle_version": "0.4.0",
      "observed_at": "2026-08-25T00:05:00+00:00",
      "desired_access": 1179785,
      "gpt_unc_path": "\\\\dc01.corp.local\\SYSVOL\\corp.local\\Policies\\{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
      "dc": "dc01.corp.local",
      "target_sid": "S-1-5-21-111-222-333-2100",
      "token_sids_sha256": "<SHA-256 of the canonical snapshot target token>",
      "credential_principal": "CORP\\SRV1$",
      "authenticated_sid": "S-1-5-21-111-222-333-2100",
      "identity_attestation": "PINNED_LDAP_BIND_OBJECT_SID",
      "gpo_ad_version": 7,
      "gpt_version": 7,
      "share_sd_sha256": null,
      "ntfs_sd_sha256": null,
      "probes": [
        {"relative_path": "gpt.ini", "status": "READ_OK", "sha256": "<SHA-256>", "size": 24},
        {"relative_path": "Machine\\Registry.pol", "status": "ACCESS_DENIED", "sha256": null, "size": null}
      ]
    }
  ]
}
```

Import revalidates every selector, duplicate, field set, timestamp, snapshot digest, aggregate preflight counter, DC, UNC root, expected and authenticated target SID, canonical token hash, exact domain/account, attestation method, AD/GPT version, desired-access mask, and every per-file hash and size. The original source-snapshot digest is retained in each merged observation and surfaced with target/DC/oracle/version/time/identity provenance in findings. Every snapshot-hashed file must have one probe. Existing target/GPO evidence is not overwritten unless `--replace-existing` is explicit. Local snapshot and evidence files remain inside the operator trust boundary; an operator able to edit both can alter the analysis input.

## Workload controls

The default hard limits are 250,000 principal/target-group/dangerous-setting candidate evaluations, 2,000,000 transition/replay evaluations, 100,000 findings, and 100,000 coverage gaps. Exceeding any limit aborts the scan instead of returning a partial result. Narrow `--principal`/`--target`, or explicitly raise `--max-candidates`, `--max-transitions`, `--max-findings`, and `--max-coverage-gaps`. Preflight a snapshot without transition search using:

```bash
gpowake scan --snapshot corp-observed.json --estimate-only
```

The estimate reports principals, targets, target equivalence groups, dangerous settings, and the candidate-evaluation upper bound. Use `.jsonl` output for line-oriented downstream processing.

## Transition model

The solver currently tests these state changes when the actor has the exact required right:

| Transition | Required capability |
| --- | --- |
| Add a link at any applicable scope (site, domain, or any OU in the chain), enable, reorder, or enforce a link | `WriteGPLink` on that SOM |
| Clear Block Inheritance | `WriteGPOptions` on that SOM |
| Add an explicit, narrow SOM ACE granting the actor `WriteGPLink` (first half of a two-step path) | `WRITE_DAC` on that SOM (explicit or verified owner-implicit) |
| Grant target Read + Apply Group Policy | `WriteGPOSecurity` (`WRITE_DAC`) on the GPO |
| Enable the computer half | `WriteGPOContainer` (`flags` write) on the GPO |

The engine recalculates the full effective setting after every proposed transition. `WRITE_DAC` transitions are explicitly `ADDITIVE_GRANT`: they preserve every existing ACE and its relative order, add only narrow explicit allows, and refuse a path if an explicit deny or unsupported ACE would have to be weakened. GPOWake does not silently reinterpret that refusal as a full DACL replacement. The report retains exact ACE additions and the rights actually exposed. Targets may be aggregated only when every advertised path replays successfully for every target; a target-SID grant is always reported separately.

`scan --explicit-blocker-rewrite` explicitly adds separate `EXPLICIT_BLOCKER_REWRITE` actions for those refused paths. These actions remove only applicable explicit blocking ACEs, retain inherited and unrelated ACEs, and add narrow grants. They report every removed/added ACE, each collateral trustee, observed before/after Read/Apply or WriteGPLink changes, and a warning that unobserved trustee members may gain unrelated rights. This high-collateral mode is opt-in. The deprecated `--full-dacl-rewrite` spelling remains an alias, but the output never claims that inherited-DACL protection or removal is modeled.

## Snapshot format

Snapshots and JSON reports use schema version `5` (snapshot schemas 1–4 remain readable; schema 1 receives a migration warning). Pre-schema-5 GPT observations are deliberately discarded because they did not bind an explicitly requested SMB mask, attested session SID, file sizes, and per-file-family decisions. Unstructured live GPT decisions are also discarded and must be recollected with the hardened oracle. The included [example](examples/same_scope_masked.json) is a complete reference. Important details:

- `gp_link` is preserved in its native ordered string form.
- `access_mask` accepts a JSON integer or a string such as `"0x00000020"`.
- Object-specific ACEs use the schema/control-access GUID in `object_type`.
- Omitting a security descriptor means “not collected,” not “allow all.”
- `machine_extensions: null` means unknown; an empty list means the GPO explicitly advertises no machine CSE.
- `functionality_version` records `gPCFunctionalityVersion`; live collection rejects values other than the protocol-supported value `2`.
- `gpt_hashes` and `gpt_file_sizes` bind each collected relative GPT path to the exact bytes used by oracle preflight and drift detection.
- Live targets retain LDAP-collected `sam_account_name`, `dns_domain`, and `netbios_domain`; the object SID remains the `sid` field.
- `value_sensitivity: SECRET` values may contain only a destroyed `secret_present` marker; loaders and serializers discard any supplied literal value.
- A setting may be embedded under `settings`, or loaded from paths relative to the snapshot with `gpt_tmpl_files` and `registry_pol_files`.
- Record WMI observations under each target's `wmi_results` as `[filter-id, boolean]`; a legacy GPO-global `true` value is not accepted as proof for every host.
- Imported target GPT authorization is stored under each target's `gpt_read_observations` with structured oracle, expected/attested SID, exact domain/account, version, token, DC, UNC, descriptor-hash, and per-file probe fields. Legacy `gpt_read_decisions` remain usable only for offline fixtures; they are discarded from live snapshots. `collector_gpt_readable` is separate evidence and never substitutes for target authorization in a live snapshot.
- `incomplete_setting_kinds` scopes a failed GPT policy file to the setting families it can contain; an empty value on an incomplete legacy GPO remains conservatively unscoped.
- `unresolved_token_sids` names exact trustees whose membership could not be established. It does not contaminate unrelated DACLs.
- Boolean fields are strict JSON booleans; strings such as `"false"` are rejected.

Parse a template independently with:

```bash
gpowake parse-gpttmpl path/to/GptTmpl.inf
```

## Scope and explicit limitations

This release intentionally supports deterministic computer-side policy only. It does not claim correctness for user policy, loopback, GPP item-level targeting, scripts, software installation, arbitrary WMI evaluation, fake LDAP-hosted GPT paths, or full cross-domain links. Only the explicitly listed Restricted Groups and registry/security states are in the automatic danger catalog; all other normalized values remain evidence/precedence data.

The Linux and native-Windows CI jobs validate the model, parser, secret-sentinel, ACL-output, and fake SMB/LDAP contracts. They are not a substitute for a domain lab. Before promoting findings beyond `POSSIBLE`/`LOW`, the project still requires differential Windows AuthZ/RSoP results across same-name trusted-domain accounts, partial file denial, supported SMB dialects, machine TokenUser identity, and actual Group Policy processing.

If a descriptor, actor token, referenced target group, site, WMI result, target GPT decision, supported policy file, linked GPO, CSE advertisement, or required policy input cannot be resolved, the affected gate is uncertain and no optimistic authorization transition is created. The report emits a structured coverage gap. Collection warnings, AD/GPT version divergence, and unsupported behavior are retained as evidence. LDAP and SMB endpoints, collection time, AD/GPT versions, `uSNChanged`, collector/target SYSVOL readability, and SHA-256 GPT hashes are included in snapshots/reports.

Uncertainty is scoped to the exact setting, setting family, GPO/link branch, or target gate it can affect. Unknown site resolution and a missing linked GPO remain intentionally global because either can introduce an unseen winner for any supported setting.

Callback/conditional ACEs are not interpreted; an access decision that could depend on one is `UNKNOWN` (a coverage gap), including unsupported Owner Rights ACEs. This is conservative and can under-report.

## Development

```bash
PYTHONPATH=src pytest
ruff check src tests
mypy src
python3 -m gpowake --help
PYTHONPATH=src python3 benchmarks/benchmark_solver.py --profile all
python3 scripts/check_release_archive.py dist/*
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD) \
  python3 scripts/verify_reproducible_build.py --reference dist
```

The benchmark has grouped best-case, mixed typical, and per-target adversarial profiles. It checks exact candidate/finding invariants and supports `--max-seconds`, `--max-peak-mib`, solver budgets, dimension overrides, and `--jsonl` results.

`scripts/build_release.sh` refuses a dirty tree, requires `HEAD` to have an exact, valid SSH-signed `v<project-version>` tag from `maintainers/allowed_signers`, runs the full tests/static/secret-sentinel gates and all thresholded benchmark profiles, builds from `git archive` in a temporary directory, normalizes source-archive ordering/ownership/modes/timestamps from the commit, rebuilds from that same canonical archive tree for byte-identical verification, and inspects both archives before generating deterministic SPDX 2.3 and SLSA/in-toto metadata. CI additionally produces GitHub/Sigstore build-provenance and SBOM attestations for push builds.

The code is split by responsibility:

```text
collectors/ldap.py     topology, GPOs, DACLs, referenced-group resolution
collectors/sysvol.py   DC-pinned GPT collection
gpt_oracle.py          SID-attested, explicit-access effective SMB probes
observations.py        strict snapshot-bound GPT evidence import
parsers/               GptTmpl.inf and Registry.pol
acl.py                 effective low-level capabilities
precedence.py          target-specific applicability and winners
solver.py              bounded counterfactual transitions
snapshot.py            stable offline evidence format
report.py              JSON and human-readable findings
```
