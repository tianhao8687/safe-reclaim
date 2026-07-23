#!/usr/bin/env python3
"""SafeReclaim: auditable Windows disk analysis and conservative cleanup.

The scan phase is read-only. Cleanup requires a tamper-evident plan, an exact
approval phrase, and --yes. Only exact allowlisted cache paths and fixed native
package-manager cache commands can run automatically.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA_VERSION = 3
APP_VERSION = "1.1.0"
PLAN_TTL_HOURS = 6
DEFAULT_AGE_DAYS = 3
SUPPORTED_AGES = (1, 3, 7)
MAX_ERRORS = 300

PROJECT_MARKERS = {
    ".git", ".hg", ".svn", "package.json", "pyproject.toml",
    "Cargo.toml", "pom.xml", "go.mod", "composer.json",
}
DEV_DIRS = {
    "node_modules", ".venv", "venv", ".gradle", ".m2", ".nuget",
    "target", "dist", "build", ".next", ".cache",
}
CACHE_LEAVES = {
    "cache", "cache2", "cache_data", "code cache", "gpucache",
    "cacheddata", "d3dscache", "dxcache", "glcache", "nv_cache",
}
ALLOWED_COMMANDS: dict[str, list[str]] = {
    "npm-cache-clean": ["npm", "cache", "clean", "--force"],
    "pip-cache-purge": [sys.executable, "-m", "pip", "cache", "purge"],
    "pnpm-store-prune": ["pnpm", "store", "prune"],
    "nuget-cache-clear": ["dotnet", "nuget", "locals", "all", "--clear"],
}


@dataclass(frozen=True)
class Candidate:
    id: str
    label: str
    path: Optional[str]
    total_bytes: int
    total_files: int
    eligible_bytes: int
    eligible_files: int
    eligible_by_age: dict[str, dict[str, int]]
    risk: str
    action: str
    safety_tag: str
    reason: str
    min_age_days: int = DEFAULT_AGE_DAYS
    automatic: bool = True
    command_id: Optional[str] = None
    notes: tuple[str, ...] = ()


class AuditLog:
    def __init__(self) -> None:
        self.errors: list[dict[str, str]] = []
        self.skipped_links = 0
        self.skipped_project_directories = 0
        self.directories_seen = 0
        self.files_seen = 0

    def error(self, path: str, exc: BaseException) -> None:
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(
                {"path": path, "error": f"{type(exc).__name__}: {exc}"}
            )


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def norm(path: str | Path) -> str:
    return os.path.normcase(
        os.path.abspath(os.path.expandvars(os.path.expanduser(str(path))))
    )


def same_path(a: str | Path, b: str | Path) -> bool:
    return norm(a) == norm(b)


def is_within(child: str | Path, parent: str | Path) -> bool:
    try:
        return os.path.commonpath([norm(child), norm(parent)]) == norm(parent)
    except ValueError:
        return False


def is_root(path: str | Path) -> bool:
    p = Path(norm(path))
    return p.parent == p or bool(p.drive and same_path(p, p.drive + os.sep))


def is_link(path: str | Path) -> bool:
    try:
        p = Path(path)
        if p.is_symlink():
            return True
        attrs = getattr(os.lstat(p), "st_file_attributes", 0)
        return bool(
            attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    except FileNotFoundError:
        return False
    except OSError:
        return True


def directory_has_project_marker(path: str | Path) -> bool:
    p = Path(path)
    try:
        if any((p / marker).exists() for marker in PROJECT_MARKERS):
            return True
        return bool(
            next(p.glob("*.sln"), None)
            or next(p.glob("*.csproj"), None)
            or next(p.glob("*.vcxproj"), None)
        )
    except OSError:
        return True


def protected_paths() -> list[Path]:
    result = [
        Path(v)
        for key in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData")
        if (v := os.getenv(key))
    ]
    home = Path.home()
    result += [
        home / name
        for name in (
            "Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music",
            "OneDrive", ".ssh", ".gnupg",
        )
    ]
    return result


def relative_parts(path: str | Path, base: str | Path) -> Optional[list[str]]:
    if not is_within(path, base):
        return None
    rel = os.path.relpath(norm(path), norm(base))
    if rel == ".":
        return []
    return [part.casefold() for part in Path(rel).parts]


def _profile_name(value: str) -> bool:
    v = value.casefold()
    return v == "default" or v.startswith("profile ") or v in {"guest profile", "system profile"}


def classify_safe_cache_path(path: str | Path) -> Optional[str]:
    """Return an allowlist tag only for exact known cache/temp directories."""
    p = Path(norm(path))
    local = os.getenv("LOCALAPPDATA")
    roaming = os.getenv("APPDATA")
    system = os.getenv("SystemRoot")

    temp_targets = [
        Path(value)
        for key in ("TEMP", "TMP")
        if (value := os.getenv(key))
    ]
    if local:
        temp_targets += [Path(local) / "Temp", Path(local) / "CrashDumps"]
    if system:
        temp_targets += [Path(system) / "Temp"]
    if any(same_path(p, target) for target in temp_targets):
        return "known-temp"

    if local and (rel := relative_parts(p, local)):
        browser_prefixes = (
            ["google", "chrome", "user data"],
            ["microsoft", "edge", "user data"],
            ["bravesoftware", "brave-browser", "user data"],
        )
        for prefix in browser_prefixes:
            if len(rel) == 5 and rel[:3] == prefix and _profile_name(rel[3]) and rel[4] in CACHE_LEAVES:
                return "browser-cache"
            if len(rel) == 6 and rel[:3] == prefix and _profile_name(rel[3]) and rel[4] == "cache" and rel[5] == "cache_data":
                return "browser-cache"
        if len(rel) == 5 and rel[:3] == ["mozilla", "firefox", "profiles"] and rel[4] == "cache2":
            return "browser-cache"

        exact_local = {
            ("d3dscache",): "gpu-cache",
            ("microsoft", "windows", "inetcache"): "application-cache",
            ("nvidia", "dxcache"): "gpu-cache",
            ("nvidia", "glcache"): "gpu-cache",
            ("nvidia corporation", "nv_cache"): "gpu-cache",
            ("amd", "dxcache"): "gpu-cache",
            ("amd", "glcache"): "gpu-cache",
        }
        if tuple(rel) in exact_local:
            return exact_local[tuple(rel)]

    if roaming and (rel := relative_parts(p, roaming)):
        if len(rel) == 2 and rel[0] in {"code", "cursor", "discord", "slack"} and rel[1] in CACHE_LEAVES:
            return "application-cache"

    return None


def validate_cleanup_path(path: str | Path, expected_tag: str) -> tuple[bool, str]:
    p = Path(path)
    if not p.is_absolute():
        return False, "path is not absolute"
    if is_root(p):
        return False, "refusing filesystem root"
    if is_link(p):
        return False, "target is a link or reparse point"

    system = os.getenv("SystemRoot")
    system_temp = Path(system) / "Temp" if system else None
    for protected in protected_paths():
        if protected.exists() and (same_path(p, protected) or is_within(p, protected)):
            if system_temp and expected_tag == "known-temp" and same_path(p, system_temp):
                continue
            return False, f"target is protected by {protected}"

    if directory_has_project_marker(p):
        return False, "target directory contains project/repository markers"
    actual = classify_safe_cache_path(p)
    if actual != expected_tag:
        return False, f"path allowlist mismatch: expected {expected_tag}, got {actual}"
    return True, "ok"


def scan_root(
    root: Path, top_n: int, max_depth: int, audit: AuditLog
) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
    """Aggregate directory sizes without ever descending into links/reparse points."""
    root = Path(norm(root))
    if not root.exists() or is_link(root):
        audit.error(str(root), RuntimeError("root missing or unsafe"))
        return 0, [], []

    records: list[tuple[Path, int, list[Path]]] = []
    development_paths: list[tuple[Path, str]] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cp = Path(current)
        allowed_dirs: list[str] = []
        children: list[Path] = []
        for name in dirs:
            child = cp / name
            if is_link(child):
                audit.skipped_links += 1
            else:
                allowed_dirs.append(name)
                children.append(child)
        dirs[:] = allowed_dirs

        direct_bytes = 0
        for name in files:
            fp = cp / name
            try:
                if is_link(fp):
                    audit.skipped_links += 1
                    continue
                st = fp.stat()
                if stat.S_ISREG(st.st_mode):
                    direct_bytes += st.st_size
                    audit.files_seen += 1
            except OSError as exc:
                audit.error(str(fp), exc)

        records.append((cp, direct_bytes, children))
        audit.directories_seen += 1
        if cp.name.casefold() in DEV_DIRS:
            development_paths.append((cp, cp.name))

    sizes: dict[str, int] = {}
    for cp, direct_bytes, children in reversed(records):
        total = direct_bytes + sum(sizes.get(norm(child), 0) for child in children)
        sizes[norm(cp)] = total

    ranked: list[dict[str, Any]] = []
    for path, size in sizes.items():
        try:
            depth = 0 if same_path(path, root) else len(
                Path(os.path.relpath(path, root)).parts
            )
        except ValueError:
            continue
        if depth <= max_depth:
            ranked.append({"path": path, "bytes": size})

    development = [
        {
            "path": str(path),
            "bytes": sizes.get(norm(path), 0),
            "kind": kind,
            "automatic": False,
        }
        for path, kind in development_paths
    ]
    ranked.sort(key=lambda item: item["bytes"], reverse=True)
    development.sort(key=lambda item: item["bytes"], reverse=True)
    return sizes.get(norm(root), 0), ranked[:top_n], development[:top_n]


def candidate_id(action: str, path: Optional[str], command_id: Optional[str]) -> str:
    seed = f"{action}|{norm(path) if path else ''}|{command_id or ''}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def measure_candidate(
    root: Path, ages: Iterable[int] = SUPPORTED_AGES
) -> dict[str, Any]:
    """Measure total and age-eligible bytes in one traversal."""
    age_list = sorted(set(int(x) for x in ages))
    cutoffs = {age: time.time() - age * 86400 for age in age_list}
    buckets = {
        str(age): {"bytes": 0, "files": 0}
        for age in age_list
    }
    result: dict[str, Any] = {
        "total_bytes": 0,
        "total_files": 0,
        "eligible_by_age": buckets,
        "skipped_links": 0,
        "skipped_project_directories": 0,
        "errors": [],
    }
    if not root.exists() or is_link(root):
        return result

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cp = Path(current)
        safe_dirs: list[str] = []
        for name in dirs:
            dp = cp / name
            if is_link(dp):
                result["skipped_links"] += 1
            elif directory_has_project_marker(dp):
                result["skipped_project_directories"] += 1
            else:
                safe_dirs.append(name)
        dirs[:] = safe_dirs

        for name in files:
            fp = cp / name
            try:
                if is_link(fp):
                    result["skipped_links"] += 1
                    continue
                st = fp.stat()
                if not stat.S_ISREG(st.st_mode):
                    continue
                result["total_bytes"] += st.st_size
                result["total_files"] += 1
                for age, cutoff in cutoffs.items():
                    if st.st_mtime <= cutoff:
                        buckets[str(age)]["bytes"] += st.st_size
                        buckets[str(age)]["files"] += 1
            except OSError as exc:
                if len(result["errors"]) < MAX_ERRORS:
                    result["errors"].append(
                        {"path": str(fp), "error": f"{type(exc).__name__}: {exc}"}
                    )
    return result


def _candidate_for_path(
    path: Path, tag: str, label: str, default_age: int, notes: tuple[str, ...] = ()
) -> Candidate:
    measurement = measure_candidate(path, SUPPORTED_AGES)
    eligible = measurement["eligible_by_age"].get(
        str(default_age), {"bytes": 0, "files": 0}
    )
    extra_notes = list(notes)
    if measurement["skipped_project_directories"]:
        extra_notes.append(
            f"Skipped {measurement['skipped_project_directories']} project-like directories."
        )
    if measurement["errors"]:
        extra_notes.append(
            f"Measurement had {len(measurement['errors'])} access/stat errors."
        )
    return Candidate(
        id=candidate_id("delete-contents", str(path), None),
        label=label,
        path=str(path),
        total_bytes=int(measurement["total_bytes"]),
        total_files=int(measurement["total_files"]),
        eligible_bytes=int(eligible["bytes"]),
        eligible_files=int(eligible["files"]),
        eligible_by_age=measurement["eligible_by_age"],
        risk="LOW",
        action="delete-contents",
        safety_tag=tag,
        reason="Exact allowlisted cache or temporary-data location.",
        min_age_days=default_age,
        automatic=True,
        notes=tuple(extra_notes),
    )


def _add_path_candidate(
    result: list[Candidate],
    seen: set[str],
    path: Path,
    tag: str,
    label: str,
    age: int,
    notes: tuple[str, ...] = (),
) -> None:
    key = norm(path)
    if key in seen or not path.exists():
        return
    valid, _ = validate_cleanup_path(path, tag)
    if not valid:
        return
    seen.add(key)
    result.append(_candidate_for_path(path, tag, label, age, notes))


def _browser_candidates(result: list[Candidate], seen: set[str], local: Path) -> None:
    chromium_bases = (
        (local / "Google" / "Chrome" / "User Data", "Chrome"),
        (local / "Microsoft" / "Edge" / "User Data", "Edge"),
        (local / "BraveSoftware" / "Brave-Browser" / "User Data", "Brave"),
    )
    for base, browser in chromium_bases:
        if not base.exists():
            continue
        try:
            profiles = [
                p for p in base.iterdir()
                if p.is_dir() and _profile_name(p.name)
            ]
        except OSError:
            profiles = []
        for profile in profiles:
            for leaf in ("Cache", "Code Cache", "GPUCache"):
                _add_path_candidate(
                    result, seen, profile / leaf, "browser-cache",
                    f"{browser} {profile.name} {leaf}", 1,
                    ("May sign out no accounts; pages and code will be re-downloaded.",),
                )

    firefox = local / "Mozilla" / "Firefox" / "Profiles"
    if firefox.exists():
        try:
            profiles = [p for p in firefox.iterdir() if p.is_dir()]
        except OSError:
            profiles = []
        for profile in profiles:
            _add_path_candidate(
                result, seen, profile / "cache2", "browser-cache",
                f"Firefox {profile.name} cache", 1,
                ("Web content will be re-downloaded.",),
            )


def _application_candidates(
    result: list[Candidate], seen: set[str], local: Optional[Path], roaming: Optional[Path]
) -> None:
    if local:
        exact = (
            (local / "D3DSCache", "gpu-cache", "DirectX shader cache"),
            (local / "Microsoft" / "Windows" / "INetCache", "application-cache", "Windows internet cache"),
            (local / "NVIDIA" / "DXCache", "gpu-cache", "NVIDIA DirectX cache"),
            (local / "NVIDIA" / "GLCache", "gpu-cache", "NVIDIA OpenGL cache"),
            (local / "NVIDIA Corporation" / "NV_Cache", "gpu-cache", "NVIDIA application cache"),
            (local / "AMD" / "DxCache", "gpu-cache", "AMD DirectX cache"),
            (local / "AMD" / "GLCache", "gpu-cache", "AMD OpenGL cache"),
        )
        for path, tag, label in exact:
            _add_path_candidate(
                result, seen, path, tag, label, 3,
                ("The related application or game may rebuild this cache on next launch.",),
            )
    if roaming:
        for app, title in (
            ("Code", "Visual Studio Code"),
            ("Cursor", "Cursor"),
            ("discord", "Discord"),
            ("Slack", "Slack"),
        ):
            for leaf in ("Cache", "Code Cache", "GPUCache", "CachedData"):
                _add_path_candidate(
                    result, seen, roaming / app / leaf, "application-cache",
                    f"{title} {leaf}", 1,
                    ("Close the application before cleanup for best results.",),
                )


def _run_probe(command: list[str], timeout: int = 20) -> Optional[str]:
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip().splitlines()
    return value[-1].strip() if value else None


def _tool_candidate(
    command_id: str,
    label: str,
    cache_path: Optional[Path],
    notes: tuple[str, ...],
) -> Candidate:
    measurement = (
        measure_candidate(cache_path, SUPPORTED_AGES)
        if cache_path and cache_path.exists()
        else {
            "total_bytes": 0,
            "total_files": 0,
            "eligible_by_age": {str(a): {"bytes": 0, "files": 0} for a in SUPPORTED_AGES},
        }
    )
    by_age = {
        str(a): {
            "bytes": int(measurement["total_bytes"]),
            "files": int(measurement["total_files"]),
        }
        for a in SUPPORTED_AGES
    }
    return Candidate(
        id=candidate_id("run-command", str(cache_path) if cache_path else None, command_id),
        label=label,
        path=str(cache_path) if cache_path else None,
        total_bytes=int(measurement["total_bytes"]),
        total_files=int(measurement["total_files"]),
        eligible_bytes=int(measurement["total_bytes"]),
        eligible_files=int(measurement["total_files"]),
        eligible_by_age=by_age,
        risk="LOW",
        action="run-command",
        safety_tag="native-tool-cache",
        reason="Fixed allowlisted package-manager cache command.",
        min_age_days=1,
        automatic=True,
        command_id=command_id,
        notes=notes,
    )


def probe_tool_candidates() -> tuple[list[Candidate], list[dict[str, Any]]]:
    candidates: list[Candidate] = []
    advisories: list[dict[str, Any]] = []

    if shutil.which("npm"):
        value = _run_probe(["npm", "config", "get", "cache"])
        path = Path(value) if value and value.lower() not in {"undefined", "null"} else None
        candidates.append(
            _tool_candidate(
                "npm-cache-clean", "npm download cache", path,
                ("Packages will be downloaded again when needed.",),
            )
        )

    pip_value = _run_probe([sys.executable, "-m", "pip", "cache", "dir"])
    if pip_value:
        candidates.append(
            _tool_candidate(
                "pip-cache-purge", "pip download/build cache", Path(pip_value),
                ("Python packages will be downloaded or rebuilt again when needed.",),
            )
        )

    if shutil.which("pnpm"):
        value = _run_probe(["pnpm", "store", "path"])
        path = Path(value) if value else None
        candidates.append(
            _tool_candidate(
                "pnpm-store-prune", "pnpm unreferenced store data", path,
                ("Only pnpm's own prune command is run.",),
            )
        )

    if shutil.which("dotnet"):
        candidates.append(
            _tool_candidate(
                "nuget-cache-clear", "NuGet local caches", None,
                ("Size is unknown until the native command runs.",),
            )
        )

    if shutil.which("docker"):
        output = _run_probe(["docker", "system", "df"])
        advisories.append(
            {
                "kind": "docker",
                "risk": "MEDIUM",
                "automatic": False,
                "summary": output or "Docker detected; daemon unavailable or size probe failed.",
                "guidance": "Review `docker system df -v` before any prune. SafeReclaim never prunes Docker automatically.",
            }
        )

    if shutil.which("wsl"):
        output = _run_probe(["wsl", "--list", "--verbose"])
        advisories.append(
            {
                "kind": "wsl",
                "risk": "HIGH",
                "automatic": False,
                "summary": output or "WSL detected; distribution probe failed.",
                "guidance": "Do not delete VHDX files manually. Compact or unregister only after verifying the distribution and backups.",
            }
        )

    return candidates, advisories


def discover_candidates(probe_tools: bool = False) -> tuple[list[Candidate], list[dict[str, Any]]]:
    result: list[Candidate] = []
    advisories: list[dict[str, Any]] = []
    seen: set[str] = set()

    for value in (os.getenv("TEMP"), os.getenv("TMP")):
        if value:
            _add_path_candidate(
                result, seen, Path(value), "known-temp",
                "User temporary files", 3,
                ("Open or locked files are skipped.",),
            )

    local_value = os.getenv("LOCALAPPDATA")
    roaming_value = os.getenv("APPDATA")
    system_value = os.getenv("SystemRoot")
    local = Path(local_value) if local_value else None
    roaming = Path(roaming_value) if roaming_value else None

    if local:
        _add_path_candidate(
            result, seen, local / "Temp", "known-temp",
            "Local temporary files", 3,
            ("Open or locked files are skipped.",),
        )
        _add_path_candidate(
            result, seen, local / "CrashDumps", "known-temp",
            "Application crash dumps", 7,
            ("Keep recent crash dumps while diagnosing crashes.",),
        )
        _browser_candidates(result, seen, local)

    if system_value:
        _add_path_candidate(
            result, seen, Path(system_value) / "Temp", "known-temp",
            "Windows temporary files", 7,
            ("Administrator rights may improve coverage; permission failures remain skipped.",),
        )

    _application_candidates(result, seen, local, roaming)

    if probe_tools:
        tool_candidates, tool_advisories = probe_tool_candidates()
        for candidate in tool_candidates:
            if candidate.id not in {item.id for item in result}:
                result.append(candidate)
        advisories.extend(tool_advisories)

    result.sort(key=lambda item: item.eligible_bytes, reverse=True)
    return result, advisories


def default_roots() -> list[Path]:
    if os.name == "nt":
        return [
            Path(f"{letter}:\\")
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if Path(f"{letter}:\\").exists()
        ]
    return [Path(Path.cwd().anchor or "/")]


def _candidate_totals(candidates: list[Candidate]) -> dict[str, Any]:
    return {
        "candidate_total_bytes": sum(c.total_bytes for c in candidates),
        "eligible_by_age": {
            str(age): {
                "bytes": sum(c.eligible_by_age.get(str(age), {}).get("bytes", 0) for c in candidates),
                "files": sum(c.eligible_by_age.get(str(age), {}).get("files", 0) for c in candidates),
            }
            for age in SUPPORTED_AGES
        },
    }


def scan_command(args: argparse.Namespace) -> int:
    roots = [Path(value) for value in args.roots] or default_roots()
    audit = AuditLog()
    drives: list[dict[str, Any]] = []
    for root in roots:
        total, largest, development = scan_root(
            root, args.top, args.max_depth, audit
        )
        try:
            usage = shutil.disk_usage(root)
            disk = {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
            }
        except OSError as exc:
            audit.error(str(root), exc)
            disk = {}
        drives.append(
            {
                "root": str(root),
                "scanned_bytes": total,
                "disk": disk,
                "largest_directories": largest,
                "development_directories": development,
            }
        )

    candidates, advisories = discover_candidates(args.probe_tools)
    report = {
        "schema_version": SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "created_at": iso(utc_now()),
        "platform": sys.platform,
        "drives": drives,
        "candidates": [asdict(item) for item in candidates],
        "cleanup_summary": _candidate_totals(candidates),
        "advisories": advisories,
        "audit": audit.__dict__,
    }
    Path(args.output).write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Wrote read-only report: {args.output}")
    for age in SUPPORTED_AGES:
        eligible = report["cleanup_summary"]["eligible_by_age"][str(age)]
        print(
            f"Estimated eligible at {age} day(s): "
            f"{eligible['bytes']} bytes in {eligible['files']} files"
        )
    return 0


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def plan_payload(plan: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in plan.items() if key != "plan_hash"}


def plan_command(args: argparse.Namespace) -> int:
    report = load_json(args.report)
    if report.get("schema_version") != SCHEMA_VERSION:
        raise SystemExit("scan report schema is not supported; run a new scan")

    all_items = {
        item["id"]: item
        for item in report.get("candidates", [])
        if item.get("risk") == "LOW" and item.get("automatic")
    }
    selected = args.select or list(all_items)
    missing = [candidate_id for candidate_id in selected if candidate_id not in all_items]
    if missing:
        raise SystemExit(
            f"unknown or non-automatic candidate IDs: {', '.join(missing)}"
        )

    items: list[dict[str, Any]] = []
    for candidate_id_value in selected:
        item = dict(all_items[candidate_id_value])
        item["candidate_id"] = item.pop("id")
        age = int(args.age_days) if args.age_days is not None else int(
            item.get("min_age_days", DEFAULT_AGE_DAYS)
        )
        if age not in SUPPORTED_AGES:
            raise SystemExit(
                f"unsupported age threshold {age}; choose one of {SUPPORTED_AGES}"
            )
        item["min_age_days"] = age
        estimate = item.get("eligible_by_age", {}).get(
            str(age), {"bytes": 0, "files": 0}
        )
        item["estimated_eligible_bytes"] = int(estimate.get("bytes", 0))
        item["estimated_eligible_files"] = int(estimate.get("files", 0))
        items.append(item)

    if not items:
        raise SystemExit("refusing to create an empty plan")

    now = utc_now()
    plan = {
        "schema_version": SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "plan_id": secrets.token_hex(8),
        "created_at": iso(now),
        "expires_at": iso(now + dt.timedelta(hours=PLAN_TTL_HOURS)),
        "source_report_hash": sha256_json(report),
        "approval_phrase": f"APPROVE-{secrets.token_hex(4).upper()}",
        "items": items,
        "estimated_eligible_bytes": sum(
            item["estimated_eligible_bytes"] for item in items
        ),
        "estimated_eligible_files": sum(
            item["estimated_eligible_files"] for item in items
        ),
    }
    plan["plan_hash"] = sha256_json(plan_payload(plan))
    Path(args.output).write_text(
        json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Wrote plan: {args.output}")
    print(f"Estimated eligible bytes: {plan['estimated_eligible_bytes']}")
    print(f"Approval phrase: {plan['approval_phrase']}")
    return 0


def delete_eligible_contents(root: Path, min_age_days: int) -> dict[str, Any]:
    """Delete only regular files old enough, never the root, projects, or links."""
    if min_age_days not in SUPPORTED_AGES:
        raise ValueError(f"unsupported age threshold: {min_age_days}")

    cutoff = time.time() - min_age_days * 86400
    result: dict[str, Any] = {
        "deleted_files": 0,
        "deleted_directories": 0,
        "deleted_bytes": 0,
        "skipped_recent_files": 0,
        "skipped_recent_bytes": 0,
        "skipped_links": 0,
        "skipped_project_directories": 0,
        "permission_errors": 0,
        "other_errors": 0,
        "errors": [],
    }
    if is_link(root):
        result["skipped_links"] = 1
        return result

    visited: list[Path] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cp = Path(current)
        visited.append(cp)
        allowed_dirs: list[str] = []
        for name in dirs:
            dp = cp / name
            if is_link(dp):
                result["skipped_links"] += 1
            elif directory_has_project_marker(dp):
                result["skipped_project_directories"] += 1
            else:
                allowed_dirs.append(name)
        dirs[:] = allowed_dirs

        for name in files:
            fp = cp / name
            try:
                if is_link(fp):
                    result["skipped_links"] += 1
                    continue
                st = fp.stat()
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mtime > cutoff:
                    result["skipped_recent_files"] += 1
                    result["skipped_recent_bytes"] += st.st_size
                    continue
                fp.unlink()
                result["deleted_bytes"] += st.st_size
                result["deleted_files"] += 1
            except PermissionError as exc:
                result["permission_errors"] += 1
                if len(result["errors"]) < MAX_ERRORS:
                    result["errors"].append(
                        {"path": str(fp), "error": f"PermissionError: {exc}"}
                    )
            except OSError as exc:
                result["other_errors"] += 1
                if len(result["errors"]) < MAX_ERRORS:
                    result["errors"].append(
                        {"path": str(fp), "error": f"{type(exc).__name__}: {exc}"}
                    )

    for directory in reversed(visited):
        if same_path(directory, root) or is_link(directory):
            continue
        try:
            directory.rmdir()
            result["deleted_directories"] += 1
        except OSError:
            pass
    return result


delete_old_contents = delete_eligible_contents


def verify_plan(plan: dict[str, Any]) -> dict[str, bool]:
    items = plan.get("items", [])
    checks = {
        "schema_supported": plan.get("schema_version") == SCHEMA_VERSION,
        "hash_valid": plan.get("plan_hash") == sha256_json(plan_payload(plan)),
        "not_expired": bool(plan.get("expires_at"))
        and parse_iso(plan["expires_at"]) >= utc_now(),
        "has_items": bool(items),
        "all_low_risk": all(item.get("risk") == "LOW" for item in items),
        "all_actions_known": all(
            item.get("action") in {"delete-contents", "run-command"}
            for item in items
        ),
        "all_ages_supported": all(
            int(item.get("min_age_days", -1)) in SUPPORTED_AGES
            for item in items
        ),
    }
    checks["valid"] = all(checks.values())
    return checks


def verify_command(args: argparse.Namespace) -> int:
    checks = verify_plan(load_json(args.plan))
    print(json.dumps(checks, indent=2))
    return 0 if checks["valid"] else 1


def _drive_key(path: str | Path) -> str:
    p = Path(norm(path))
    return p.anchor or str(p)


def _free_space_for_drives(drives: Iterable[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for drive in sorted(set(drives)):
        try:
            result[drive] = shutil.disk_usage(drive).free
        except OSError:
            continue
    return result


def execute_command(args: argparse.Namespace) -> int:
    if os.name != "nt":
        raise SystemExit("execution is Windows-only")

    plan = load_json(args.plan)
    if not verify_plan(plan)["valid"]:
        raise SystemExit("plan is invalid, expired, modified, or unsupported")
    if args.approve != plan.get("approval_phrase") or not args.yes:
        raise SystemExit("exact approval phrase and --yes are required")

    relevant_drives = [
        _drive_key(item["path"])
        for item in plan["items"]
        if item.get("path")
    ]
    if any(item.get("action") == "run-command" for item in plan["items"]):
        relevant_drives += [str(root) for root in default_roots()]
    free_before = _free_space_for_drives(relevant_drives)

    results: list[dict[str, Any]] = []
    for item in plan["items"]:
        result: dict[str, Any] = {
            "candidate_id": item.get("candidate_id"),
            "label": item.get("label"),
            "status": "FAILED",
            "estimated_eligible_bytes": int(
                item.get("estimated_eligible_bytes", 0)
            ),
        }
        try:
            if item["action"] == "delete-contents":
                valid, reason = validate_cleanup_path(
                    item["path"], item["safety_tag"]
                )
                if not valid:
                    raise RuntimeError(reason)
                details = delete_eligible_contents(
                    Path(item["path"]), int(item["min_age_days"])
                )
                remaining = measure_candidate(
                    Path(item["path"]), [int(item["min_age_days"])]
                )
                details["remaining_eligible_bytes"] = remaining[
                    "eligible_by_age"
                ][str(item["min_age_days"])]["bytes"]
                details["remaining_eligible_files"] = remaining[
                    "eligible_by_age"
                ][str(item["min_age_days"])]["files"]
                result.update(status="DONE", details=details)

            elif item["action"] == "run-command":
                command = ALLOWED_COMMANDS.get(item.get("command_id"))
                if not command:
                    raise RuntimeError("command is not allowlisted")
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                result.update(
                    status="DONE" if completed.returncode == 0 else "FAILED",
                    returncode=completed.returncode,
                    stdout=completed.stdout[-4000:],
                    stderr=completed.stderr[-4000:],
                )
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        results.append(result)

    free_after = _free_space_for_drives(relevant_drives)
    per_drive_delta = {
        drive: free_after.get(drive, before) - before
        for drive, before in free_before.items()
    }
    logical_deleted = sum(
        item.get("details", {}).get("deleted_bytes", 0)
        for item in results
    )
    observed_delta = sum(per_drive_delta.values())
    summary = {
        "done": sum(item["status"] == "DONE" for item in results),
        "failed": sum(item["status"] == "FAILED" for item in results),
        "logical_deleted_bytes": logical_deleted,
        "observed_free_space_delta_bytes": observed_delta,
        "free_space_delta_by_drive": per_drive_delta,
        "estimated_eligible_bytes": int(
            plan.get("estimated_eligible_bytes", 0)
        ),
        "skipped_recent_files": sum(
            item.get("details", {}).get("skipped_recent_files", 0)
            for item in results
        ),
        "skipped_recent_bytes": sum(
            item.get("details", {}).get("skipped_recent_bytes", 0)
            for item in results
        ),
        "permission_errors": sum(
            item.get("details", {}).get("permission_errors", 0)
            for item in results
        ),
        "remaining_eligible_bytes": sum(
            item.get("details", {}).get("remaining_eligible_bytes", 0)
            for item in results
        ),
    }
    log = {
        "schema_version": SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "plan_id": plan["plan_id"],
        "executed_at": iso(utc_now()),
        "free_space_before": free_before,
        "free_space_after": free_after,
        "results": results,
        "summary": summary,
    }
    Path(args.output).write_text(
        json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Wrote execution log: {args.output}")
    print(f"Logical deleted bytes: {logical_deleted}")
    print(f"Observed free-space delta: {observed_delta}")
    return 1 if summary["failed"] else 0


def summary_command(args: argparse.Namespace) -> int:
    report = load_json(args.report)
    print(f"SafeReclaim report {report.get('app_version', 'unknown')}")
    for drive in report.get("drives", []):
        disk = drive.get("disk", {})
        print(
            f"{drive.get('root')}: free={disk.get('free_bytes', 0)} "
            f"used={disk.get('used_bytes', 0)}"
        )
    print("Cleanup estimates:")
    for age, value in report.get("cleanup_summary", {}).get(
        "eligible_by_age", {}
    ).items():
        print(f"  {age} day(s): {value.get('bytes', 0)} bytes / {value.get('files', 0)} files")
    print("Candidates:")
    for item in report.get("candidates", []):
        print(
            f"  {item['id']} | {item['label']} | "
            f"default={item['min_age_days']}d | "
            f"eligible={item['eligible_bytes']} | total={item['total_bytes']}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auditable Windows disk analysis and conservative cleanup"
    )
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Read-only drive and cleanup-candidate scan")
    scan.add_argument("roots", nargs="*")
    scan.add_argument("--output", default="safe-reclaim-report.json")
    scan.add_argument("--top", type=int, default=40)
    scan.add_argument("--max-depth", type=int, default=5)
    scan.add_argument("--probe-tools", action="store_true")
    scan.set_defaults(func=scan_command)

    summary = sub.add_parser("summary", help="Print a compact report summary")
    summary.add_argument("--report", required=True)
    summary.set_defaults(func=summary_command)

    plan = sub.add_parser("plan", help="Create a tamper-evident cleanup plan")
    plan.add_argument("--report", required=True)
    plan.add_argument("--output", default="safe-reclaim-plan.json")
    plan.add_argument("--select", action="append")
    plan.add_argument(
        "--age-days",
        type=int,
        choices=SUPPORTED_AGES,
        help="Override every selected file candidate to 1, 3, or 7 days.",
    )
    plan.set_defaults(func=plan_command)

    verify = sub.add_parser("verify", help="Verify plan integrity and expiry")
    verify.add_argument("--plan", required=True)
    verify.set_defaults(func=verify_command)

    execute = sub.add_parser("execute", help="Execute an approved cleanup plan")
    execute.add_argument("--plan", required=True)
    execute.add_argument("--approve", required=True)
    execute.add_argument("--yes", action="store_true")
    execute.add_argument("--output", default="safe-reclaim-execution.json")
    execute.set_defaults(func=execute_command)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except (
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
