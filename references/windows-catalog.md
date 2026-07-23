# Windows cleanup catalog

## LOW-risk automatic candidates

### User and system temporary directories

Delete only contents older than the candidate minimum age: 7 days for temporary files, 14 days for crash dumps, and 3 days for browser/application caches. Keep the root directory. Skip locked files, links, reparse points, and nested project directories.

### Browser and Electron application caches

Recognize only exact cache leaves under supported LocalAppData product roots, such as `Cache_Data`, `Code Cache`, `GPUCache`, and `CachedData`. Do not remove profiles, cookies, history, extensions, settings, or user data roots.

### Package-manager caches

Use the package manager's own fixed command rather than raw path deletion:

- `npm cache clean --force`
- `python -m pip cache purge`
- `pnpm store prune`
- `dotnet nuget locals all --clear`

## Advisory-only findings

### node_modules

Usually reproducible, but deletion can break offline work, scripts, native addons, or abandoned projects. Identify the owning project and package manager before any manual action.

### Python virtual environments

Usually reproducible only when dependency metadata is complete. Never remove automatically.

### Docker, WSL, VMs, emulators

Unused-looking data may contain the only copy of databases, volumes, images, or development state. Use product-native inspection and require separate confirmation.

### Downloads and large unknown files

Large does not mean disposable. Present paths, sizes, and modification dates only.

## Risk labels

- **LOW:** Regenerable data at an exact allowlisted location or cleaned by a fixed native cache command.
- **MEDIUM:** Rebuildable-looking data whose ownership and recoverability require project-specific knowledge.
- **HIGH:** Personal, system, application state, unknown data, or anything lacking a deterministic recovery path.
