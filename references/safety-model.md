# Safety model

## Threats addressed

1. **Wrong target** — a report or model confuses a project, personal directory, or system path with cache data.
2. **False reclaim estimate** — total directory size is presented as deletable even though age, locks, projects, or permissions exclude most files.
3. **Path substitution** — a reviewed plan is edited to point at a different directory.
4. **Link traversal** — a symlink, junction, or reparse point redirects scanning or cleanup.
5. **Stale approval** — the filesystem or plan changes after review.
6. **Overbroad deletion** — wildcard or recursive deletion removes more than reviewed.
7. **False completeness** — inaccessible folders make a partial scan look complete.
8. **False success** — logical file lengths are reported as actual reclaimed disk space.

## Controls

- Scanning is read-only.
- Drive traversal is top-down so links and reparse points are pruned before descent.
- Candidate IDs are deterministic from action plus path or command.
- Candidate measurement separates total bytes from 1-day, 3-day, and 7-day eligibility.
- A plan freezes selected estimates, expiration, random approval phrase, source report hash, and SHA-256 plan hash.
- The executor independently revalidates every path.
- File deletion accepts only exact known cache categories.
- Fixed command IDs map to hard-coded argument arrays; arbitrary shell strings are rejected.
- Execution accepts LOW-risk items and supported age thresholds only.
- Links, junctions, and reparse points are skipped.
- Project-like subdirectories are skipped.
- Candidate root directories are retained.
- Locked and inaccessible files are skipped and logged.
- Free space is measured before and after execution.
- Candidates are re-measured after cleanup to reveal remaining eligible data.

## Explicitly outside the automatic safety boundary

- Desktop, Documents, Downloads, Pictures, Videos, Music, OneDrive.
- Repositories and directories below detected project markers.
- `node_modules`, `.venv`, `venv`, build outputs, databases.
- Windows, Program Files, ProgramData, registry, pagefile, hibernation file.
- Windows component store, update cache, restore points, recovery partitions.
- Docker images and volumes, WSL distributions, VMs, emulators, game libraries.
- Duplicate-file deletion and application uninstalling.

These may be reported for manual investigation but must never enter an automatic cleanup plan.
