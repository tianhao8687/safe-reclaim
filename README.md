# SafeReclaim

**A conservative Codex skill for auditing and reclaiming Windows disk space.**

SafeReclaim is designed for developer machines where careless cleanup can destroy source code, repositories, environments, or personal files. It defaults to read-only analysis and requires a tamper-evident plan plus an exact approval phrase before any deletion.

## Safety model

- Read-only by default
- Exact-path allowlist for supported caches and temporary directories
- Project and repository marker detection
- Reparse point and symlink rejection
- Minimum file-age protection
- Tamper-evident, expiring cleanup plans
- Exact approval phrase and explicit execution flag
- Advisory-only handling for `node_modules`, Docker, virtual environments, Downloads, and unknown large files

## Install

Copy the `safe-reclaim` folder to:

```text
$HOME/.agents/skills/safe-reclaim
```

Or run the included PowerShell installer from this repository:

```powershell
./install.ps1
```

## Use with Codex

Invoke the skill explicitly:

```text
$safe-reclaim
```

Typical workflow:

1. Scan the available Windows drives.
2. Review largest directories, coverage errors, and risk-classified candidates.
3. Select LOW-risk candidates.
4. Generate and verify an expiring cleanup plan.
5. Execute only after repeating the exact approval phrase.

## CLI examples

Read-only scan:

```powershell
python scripts/safe_reclaim.py scan C:\ D:\ --probe-tools --output safe-reclaim-report.json
```

Create and verify a cleanup plan:

```powershell
python scripts/safe_reclaim.py plan --report safe-reclaim-report.json --select CANDIDATE_ID --output safe-reclaim-plan.json
python scripts/safe_reclaim.py verify --plan safe-reclaim-plan.json
```

Execute an approved plan:

```powershell
python scripts/safe_reclaim.py execute --plan safe-reclaim-plan.json --approve APPROVE-XXXXXXXX --yes --output safe-reclaim-execution.json
```

## Tests

```powershell
python scripts/test_safe_reclaim.py
```

## Scope

SafeReclaim does **not** format drives, change partitions, edit the registry, uninstall software, clean Windows Update, remove personal files, or automatically delete development projects and environments.

## License

MIT
