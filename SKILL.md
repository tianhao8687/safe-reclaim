---
name: safe-reclaim
description: "Safely audit and reclaim Windows C: and D: drive space using a read-only scan, risk-classified candidates, a tamper-evident cleanup plan, and explicit approval before any deletion. Use only when the user explicitly invokes this skill for Windows disk analysis or cleanup. Do not use it for formatting drives, partition changes, registry cleanup, uninstalling software, deleting personal files, or automatically deleting projects and development environments."
---

# SafeReclaim

Audit Windows disk usage and reclaim only allowlisted cache or temporary data. Treat every request as read-only until the user has reviewed a generated cleanup plan and repeated its exact approval phrase.

## Non-negotiable safety rules

- Start with `scan`. Never start with `execute`.
- Never run ad hoc deletion commands such as `rm`, `del`, `rmdir`, `Remove-Item`, `shutil.rmtree`, or wildcard deletion.
- Never delete personal folders, unknown large files, project folders, repositories, databases, virtual environments, `node_modules`, Docker images, game data, system restore points, or Windows Update data.
- Never edit a generated plan. Regenerate it from the scan report instead.
- Never bypass the plan hash, approval phrase, expiration, path allowlist, LOW-risk restriction, link/reparse-point checks, or minimum file age.
- Treat scan errors and inaccessible folders as uncertainty. Report them; do not assume they are safe.
- Stop before execution unless the user's latest message explicitly authorizes deletion and includes the exact approval phrase shown in the plan.

Read [references/safety-model.md](references/safety-model.md) before execution. Read [references/windows-catalog.md](references/windows-catalog.md) when interpreting candidates.

## Workflow

### 1. Run a read-only scan

Use the bundled script from this skill directory:

```powershell
python scripts/safe_reclaim.py scan C:\ D:\ --probe-tools --output safe-reclaim-report.json
```

If only one drive exists, scan that drive. Do not request administrator rights merely to improve coverage.

### 2. Review and summarize

Read `safe-reclaim-report.json` and report:

- Free-space problem by drive.
- Largest directories from the aggregate size calculation.
- LOW-risk allowlisted candidates and estimated size.
- Development directories and Docker/WSL probes as advisory-only findings.
- Permission errors, skipped links, and incomplete coverage.

Do not call a directory safe merely because its name contains `cache`, `temp`, `log`, `build`, or `node_modules`.

### 3. Create a plan only after item selection

When the user chooses candidate IDs, create a plan:

```powershell
python scripts/safe_reclaim.py plan --report safe-reclaim-report.json --select CANDIDATE_ID --output safe-reclaim-plan.json
```

Repeat `--select` for multiple candidates. Without `--select`, the script includes all automatic LOW-risk candidates, so use that behavior only when the user explicitly selected all LOW-risk candidates.

Then verify it:

```powershell
python scripts/safe_reclaim.py verify --plan safe-reclaim-plan.json
```

Show the user the exact paths/actions, minimum age, estimated reclaimable bytes, expiration, and approval phrase. State that estimates can differ from actual freed space.

### 4. Execute only after exact approval

Require the user to repeat the plan's exact `APPROVE-XXXXXXXX` phrase and clearly instruct execution. Then run:

```powershell
python scripts/safe_reclaim.py execute --plan safe-reclaim-plan.json --approve APPROVE-XXXXXXXX --yes --output safe-reclaim-execution.json
```

Do not invent, shorten, normalize, or reuse an old approval phrase.

### 5. Report the result

Read `safe-reclaim-execution.json`. Report actual deleted bytes, skipped/locked files, command failures, and any items that were rejected by safety validation. Never claim more space was freed than the execution log records.

## Supported automatic actions

- Delete old contents from exact allowlisted Windows temporary and application/browser cache directories.
- Run fixed, allowlisted native cleanup commands for npm, pip, pnpm, and NuGet when detected.

Everything else is advisory-only. For Docker, `node_modules`, virtual environments, Downloads, duplicate files, and large unknown folders, explain the finding and require the user to handle it separately after understanding the consequences.

## Installation

For personal use, place the entire `safe-reclaim` folder in `$HOME/.agents/skills/`. The included `install.ps1` performs that copy and backs up an existing installation.
