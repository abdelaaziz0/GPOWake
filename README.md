# GPOWake

GPOWake finds dangerous GPO settings that already exist in a domain but are not currently applying, works out exactly why, and checks whether a principal you name can activate them with a permission it already holds.

It detects dormant settings caused by: no link, a disabled link, being masked by a higher priority link, Block Inheritance, and security filtering that excludes the target. For each one it checks whether the named principal can activate it by linking the GPO, enabling or reordering an existing link, enforcing a link, clearing Block Inheritance, granting itself Read and Apply on the GPO, or a two-step WriteDacl-then-link path.

Use cases:
- Privesc path discovery: a low-priv account has WriteGPLink or WriteDacl somewhere and you want to know what that actually unlocks.
- Assessing blast radius before you touch anything: which computers would be affected if a specific activation happened.
- Auditing a domain for dangerous GPO settings that are silently disabled but one permission away from live.

## Install

```
pip install -e '.[collect]'
```

## Scan a live domain

```
gpowake scan --domain corp.local --dc-ip 10.0.0.10 --principal someuser --target dc01.corp.local
```

Leave out the password and it prompts without echo. Use `--kerberos --ccache /path/to/ticket` for a ticket instead, or `--pfx cert.pfx` for PKINIT.

## Scan offline

Collect once, scan as many times as you want, no touching the DC again:

```
gpowake collect --domain corp.local --dc-ip 10.0.0.10 --principal someuser --target dc01.corp.local -o snap.json
gpowake scan --snapshot snap.json
```

## Read one finding

```
gpowake explain --finding <id> --report report.json
```

## Output

By default it prints short, one line per finding, straight to your terminal. Pass `-o report.json` for full JSON, or `-o report.jsonl` for one record per line.

Every finding names the GPO, the setting, why it is dead right now, the exact move or two-step chain that wakes it up, who can pull it off, and which computers end up affected.

## Limits

- Confidence is capped low on purpose. A finding is a lead, not proof. Verify it before you touch anything.
- No user-side policy, no GPP item-level targeting, no loopback.
- Restricted Groups only gets a literal, last-writer comparison.
