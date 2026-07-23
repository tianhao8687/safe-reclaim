# Safety model

## Threats addressed

1. **Wrong target** — a report or model confuses a project, personal directory, or system path with cache data.
2. **Path substitution** — the plan is edited after review to point at a different directory.
3. **Link traversal** — a symlink, junction, or reparse point redirects cleanup outside the intended cache.
4. **Stale approval** — the filesystem changes after a plan is reviewed.
5. **Overbroad deletion** — wildcard or recursive deletion removes more than the reviewed contents.
6. **False completeness** — inaccessible folders make a partial scan look complete.

## Controls

- The scanner is read-only.
- Candidate IDs are deterministic and derived from action plus path/command.
- A plan contains an expiration time, random approval phrase, and SHA-256 integrity hash.
- The executor independently validates every path instead of trusting the report.
- Filesystem deletion accepts only exact known cache categories.
- Fixed command IDs map to hard-coded argument arrays; arbitrary shell strings are rejected.
- Execution accepts LOW-risk items only.
- Links and Windows reparse points are skipped.
- The root candidate directory is retained; only old contents are removed.
- Files newer than the plan's minimum age are retained.
- Locked and inaccessible files are skipped and logged.

## Explicitly outside the automatic safety boundary

- Desktop, Documents, Downloads, Pictures, Videos, Music, OneDrive.
- Repositories and directories below detected project markers.
- `node_modules`, `.venv`, `venv`, build output, package lockfiles, databases.
- Windows, Program Files, ProgramData, registry, pagefile, hibernation file.
- Windows Update component store, restore points, recovery partitions.
- Docker images/volumes, WSL distributions, VMs, emulators, game libraries.
- Duplicate-file deletion and uninstalling applications.

These may be reported for manual investigation but must never enter an automatic plan.
