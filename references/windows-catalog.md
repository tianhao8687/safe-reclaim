# Windows cleanup catalog

## LOW-risk automatic candidates

### Temporary directories

Supported exact roots include the user's TEMP/TMP path, LocalAppData Temp, Windows Temp, and CrashDumps.

Default thresholds:

- User and LocalAppData Temp: 3 days.
- Windows Temp: 7 days.
- Crash dumps: 7 days.

The plan can intentionally override selected file candidates to 1, 3, or 7 days.

### Browser caches

Supported cache leaves are discovered per profile for:

- Chrome.
- Edge.
- Brave.
- Firefox.

Only cache leaves such as `Cache`, `Code Cache`, `GPUCache`, and `cache2` are eligible. Profiles, cookies, history, extensions, passwords, and settings are never candidates.

Default threshold: 1 day.

### Electron application caches

Supported exact leaves include caches for:

- Visual Studio Code.
- Cursor.
- Discord.
- Slack.

Close the application before cleanup. Account data and configuration roots are not candidates.

Default threshold: 1 day.

### Graphics and Windows caches

Supported exact locations include:

- DirectX shader cache.
- NVIDIA DX, GL, and application caches.
- AMD DX and GL caches.
- Windows internet cache.

These caches may be rebuilt on the next application or game launch.

Default threshold: 3 days.

### Package-manager caches

Use only fixed native commands:

- `npm cache clean --force`
- `python -m pip cache purge`
- `pnpm store prune`
- `dotnet nuget locals all --clear`

Packages may need to be downloaded or rebuilt again.

## Advisory-only findings

### `node_modules` and build outputs

Often reproducible, but deletion can break offline work, scripts, native addons, or projects with incomplete lockfiles. Identify the owning project first.

### Python virtual environments

Only reproducible when dependency metadata and interpreter requirements are complete. Never remove automatically.

### Docker and WSL

Data may contain the only copy of databases, volumes, images, or development state. Use native inspection such as `docker system df -v`. Never delete VHDX files manually.

### Downloads and unknown large files

Large does not mean disposable. Present paths and sizes only.

## Reporting rules

- `total_bytes` is measured content, not a cleanup promise.
- `eligible_by_age` is the cleanup estimate.
- `logical_deleted_bytes` is the sum of file lengths removed.
- `observed_free_space_delta_bytes` is the filesystem's measured change.
- `remaining_eligible_bytes` shows old-enough files still present after cleanup.

## Risk labels

- **LOW:** Regenerable data at an exact allowlisted location or a fixed native cache command.
- **MEDIUM:** Rebuildable-looking data whose ownership and recoverability require project-specific knowledge.
- **HIGH:** Personal, system, application state, unknown data, or anything lacking a deterministic recovery path.
