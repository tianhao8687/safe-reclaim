# SafeReclaim

**An auditable Codex skill for finding and safely reclaiming Windows disk space.**

SafeReclaim is designed for developer machines where careless cleanup can destroy source code, repositories, environments, Docker data, or personal files. It separates disk analysis from deletion and requires a tamper-evident plan plus an exact approval phrase before any cleanup.

Repository release: **2.1.0** · Cleanup engine: **1.1.0**

## What changed in cleanup engine v1.1.0

The earlier engine could report the total size of a Temp directory while only a tiny fraction was old enough to delete. This release fixes that mismatch.

- Reports exact eligible bytes and file counts for **1-day, 3-day, and 7-day** thresholds.
- Separates total cache size from actually eligible cleanup size.
- Discovers exact Chrome, Edge, Brave, Firefox, VS Code, Cursor, Discord, Slack, DirectX, NVIDIA, and AMD cache locations.
- Probes npm, pip, pnpm, NuGet, Docker, and WSL when requested.
- Keeps Docker and WSL advisory-only.
- Records skipped recent bytes, project directories, links, locked files, and permission errors separately.
- Measures free disk space before and after execution.
- Re-scans each candidate after cleanup and reports remaining eligible bytes.
- Prunes reparse points before drive traversal instead of discovering them after descent.

## Safety model

- Read-only by default.
- Exact-path allowlist for supported caches and temporary directories.
- Project and repository marker detection.
- Link, junction, and Windows reparse-point rejection.
- Only 1-day, 3-day, and 7-day cleanup thresholds.
- Tamper-evident, expiring cleanup plans.
- Exact approval phrase and explicit `--yes`.
- Advisory-only handling for `node_modules`, virtual environments, Docker, WSL, Downloads, and unknown large files.
- The candidate root directory is always retained.

## Install

Copy the repository folder to:

```text
$HOME/.agents/skills/safe-reclaim
```

Or run:

```powershell
./install.ps1
```

## Use with Codex

Invoke:

```text
$safe-reclaim
```

Recommended flow:

1. Scan C: and D: read-only.
2. Compare the 1-day, 3-day, and 7-day eligible totals.
3. Review exact LOW-risk candidates.
4. Generate and verify a cleanup plan.
5. Execute only after repeating the exact approval phrase.
6. Compare logical bytes deleted with the observed free-space change.

## CLI

Read-only scan:

```powershell
python scripts/safe_reclaim.py scan C:\ D:\ --probe-tools --output safe-reclaim-report.json
```

Compact summary:

```powershell
python scripts/safe_reclaim.py summary --report safe-reclaim-report.json
```

Create a plan using candidate defaults:

```powershell
python scripts/safe_reclaim.py plan --report safe-reclaim-report.json --select CANDIDATE_ID --output safe-reclaim-plan.json
```

Override selected file candidates to a specific threshold:

```powershell
python scripts/safe_reclaim.py plan --report safe-reclaim-report.json --select CANDIDATE_ID --age-days 1 --output safe-reclaim-plan.json
```

`--age-days` accepts only `1`, `3`, or `7`.

Verify and execute:

```powershell
python scripts/safe_reclaim.py verify --plan safe-reclaim-plan.json
python scripts/safe_reclaim.py execute --plan safe-reclaim-plan.json --approve APPROVE-XXXXXXXX --yes --output safe-reclaim-execution.json
```

## Understanding the numbers

- `total_bytes`: everything measured inside the exact cache candidate.
- `eligible_by_age`: what would actually qualify at 1, 3, or 7 days.
- `estimated_eligible_bytes`: estimate frozen into the reviewed plan.
- `logical_deleted_bytes`: sum of file lengths successfully deleted.
- `observed_free_space_delta_bytes`: actual change reported by the filesystem.
- `remaining_eligible_bytes`: old-enough data still present after cleanup, usually because it was locked or inaccessible.

The observed disk-space delta can differ from logical file lengths because of hard links, sparse files, filesystem allocation, and concurrent writes.

## Tests

```powershell
python scripts/test_safe_reclaim.py
```

Current local regression suite: **13 tests**.

## Scope

SafeReclaim does **not** format drives, change partitions, edit the registry, uninstall software, clean the Windows component store, delete restore points, remove personal files, or automatically delete development projects, Docker data, WSL distributions, VMs, or game libraries.

## License

MIT
