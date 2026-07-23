---
name: safe-reclaim
description: "Safely audit and reclaim Windows C: and D: drive space using read-only scanning, exact 1/3/7-day reclaim estimates, exact-path cache allowlists, a tamper-evident cleanup plan, and explicit approval. Use only when the user explicitly invokes this skill for Windows disk analysis or cleanup. Do not use it for formatting drives, partition changes, registry cleanup, uninstalling software, deleting personal files, or automatically deleting projects, Docker data, WSL distributions, or development environments."
---

# SafeReclaim

Audit Windows disk usage and reclaim only exact allowlisted cache or temporary data. Treat every request as read-only until the user reviews a generated cleanup plan and repeats its exact approval phrase.

## Non-negotiable safety rules

- Start with `scan`. Never start with `execute`.
- Never run ad hoc deletion commands such as `rm`, `del`, `rmdir`, `Remove-Item`, `shutil.rmtree`, or wildcard deletion.
- Never delete personal folders, unknown large files, projects, repositories, databases, virtual environments, `node_modules`, Docker images or volumes, WSL distributions, game data, restore points, or Windows Update data.
- Never edit a generated plan. Regenerate it from the scan report.
- Never bypass plan hashing, expiration, exact approval, path allowlisting, LOW-risk restriction, reparse-point checks, or file-age protection.
- Treat inaccessible folders as uncertainty. Report them.
- Stop before execution unless the user's latest message explicitly authorizes deletion and includes the exact approval phrase.

Read [references/safety-model.md](references/safety-model.md) before execution. Read [references/windows-catalog.md](references/windows-catalog.md) when interpreting candidates.

## Workflow

### 1. Run a read-only scan

```powershell
python scripts/safe_reclaim.py scan C:\ D:\ --probe-tools --output safe-reclaim-report.json
```

Do not request administrator rights merely to improve scan coverage.

### 2. Produce a truthful summary

Run:

```powershell
python scripts/safe_reclaim.py summary --report safe-reclaim-report.json
```

Read the JSON and report:

- Free and used space for each drive.
- Largest aggregate directories.
- Exact candidate totals.
- Actual eligible bytes and files at **1 day, 3 days, and 7 days**.
- Per-candidate default age and eligible bytes.
- Development directories as advisory-only findings.
- Docker and WSL probes as advisory-only findings.
- Permission errors, skipped links, and incomplete coverage.

Never describe `total_bytes` as reclaimable space. Reclaimable estimates must come from `eligible_by_age`.

### 3. Select candidates and age policy

Recommended defaults:

- Browser and Electron caches: 1 day.
- User/application temporary files: 3 days.
- Windows Temp and crash dumps: 7 days.

Use candidate defaults by omitting `--age-days`:

```powershell
python scripts/safe_reclaim.py plan --report safe-reclaim-report.json --select CANDIDATE_ID --output safe-reclaim-plan.json
```

To intentionally apply one threshold to all selected file candidates:

```powershell
python scripts/safe_reclaim.py plan --report safe-reclaim-report.json --select CANDIDATE_ID --age-days 1 --output safe-reclaim-plan.json
```

Only `1`, `3`, and `7` are supported. Repeat `--select` for multiple candidates. Do not include every candidate unless the user explicitly chose every LOW-risk item.

### 4. Verify and show the plan

```powershell
python scripts/safe_reclaim.py verify --plan safe-reclaim-plan.json
```

Show the user:

- Exact paths and native commands.
- Threshold for every item.
- Estimated eligible bytes and files.
- Plan expiration.
- Exact approval phrase.
- Warning that package-manager caches will be downloaded again when needed.

### 5. Execute only after exact approval

Require the exact `APPROVE-XXXXXXXX` phrase and a clear instruction to proceed:

```powershell
python scripts/safe_reclaim.py execute --plan safe-reclaim-plan.json --approve APPROVE-XXXXXXXX --yes --output safe-reclaim-execution.json
```

Never invent, shorten, normalize, or reuse an approval phrase.

### 6. Verify the result

Read `safe-reclaim-execution.json` and report:

- `logical_deleted_bytes`.
- `observed_free_space_delta_bytes` by drive.
- Deleted files and directories.
- Recent files and bytes skipped.
- Project-like directories and links skipped.
- Permission and other errors.
- `remaining_eligible_bytes`.

If the observed free-space gain is much smaller than the estimate, explain the exact logged causes. Do not claim success based only on candidate directory size.

## Automatic coverage

- Exact user and Windows temporary directories.
- Exact Chrome, Edge, Brave, and Firefox cache leaves.
- Exact VS Code, Cursor, Discord, and Slack cache leaves.
- DirectX, NVIDIA, AMD, and Windows internet caches.
- Fixed native cache commands for npm, pip, pnpm, and NuGet.

Docker, WSL, `node_modules`, virtual environments, Downloads, duplicates, system files, and unknown large folders remain advisory-only.

## Installation

Place the entire folder at:

```text
$HOME/.agents/skills/safe-reclaim
```

The included `install.ps1` backs up an existing installation before copying the upgrade.
