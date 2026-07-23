#!/usr/bin/env python3
"""SafeReclaim: conservative Windows disk audit and cleanup.

Scanning is read-only. Deletion requires an unmodified, unexpired plan, the
exact approval phrase, and --yes. Only exact allowlisted cache paths or fixed
package-manager commands may be executed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import heapq
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
from typing import Any, Optional

SCHEMA_VERSION = 2
PLAN_TTL_HOURS = 6
DEFAULT_MIN_AGE_DAYS = 3
MAX_ERRORS = 300
CACHE_LEAVES = {"cache", "cache2", "cache_data", "code cache", "gpucache", "cacheddata"}
PROJECT_MARKERS = {".git", ".hg", ".svn", "package.json", "pyproject.toml", "Cargo.toml", "pom.xml"}
DEV_DIRS = {"node_modules", ".venv", "venv", ".gradle", ".m2", ".nuget", "target", "dist", "build"}
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
    bytes: int
    risk: str
    action: str
    safety_tag: str
    reason: str
    min_age_days: int = DEFAULT_MIN_AGE_DAYS
    automatic: bool = True
    command_id: Optional[str] = None


class AuditLog:
    def __init__(self) -> None:
        self.errors: list[dict[str, str]] = []
        self.skipped_links = 0
        self.skipped_project_directories = 0
        self.directories_seen = 0
        self.files_seen = 0

    def error(self, path: str, exc: BaseException) -> None:
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"path": path, "error": f"{type(exc).__name__}: {exc}"})


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def norm(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.path.expandvars(os.path.expanduser(str(path)))))


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
        return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except FileNotFoundError:
        return False
    except OSError:
        return True


def contains_project_marker(path: str | Path) -> bool:
    p = Path(path)
    for current in (p, *p.parents):
        try:
            if any((current / marker).exists() for marker in PROJECT_MARKERS):
                return True
            if next(current.glob("*.sln"), None) or next(current.glob("*.csproj"), None):
                return True
        except OSError:
            return True
    return False


def protected_paths() -> list[Path]:
    result = [Path(v) for k in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData") if (v := os.getenv(k))]
    home = Path.home()
    result += [home / n for n in ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music", "OneDrive", ".ssh", ".gnupg")]
    return result


def relative_parts(path: str | Path, base: str | Path) -> Optional[list[str]]:
    if not is_within(path, base):
        return None
    rel = os.path.relpath(norm(path), norm(base))
    return [] if rel == "." else [x.casefold() for x in Path(rel).parts]


def classify_safe_cache_path(path: str | Path) -> Optional[str]:
    p = Path(norm(path))
    local, roaming, system = os.getenv("LOCALAPPDATA"), os.getenv("APPDATA"), os.getenv("SystemRoot")
    temps = [Path(v) for k in ("TEMP", "TMP") if (v := os.getenv(k))]
    if local:
        temps += [Path(local) / "Temp", Path(local) / "CrashDumps"]
    if system:
        temps += [Path(system) / "Temp"]
    if any(same_path(p, target) for target in temps):
        return "known-temp"

    if local and (rel := relative_parts(p, local)):
        leaf = rel[-1]
        browsers = (["google", "chrome", "user data"], ["microsoft", "edge", "user data"], ["bravesoftware", "brave-browser", "user data"])
        if len(rel) in {5, 6} and any(rel[:3] == x for x in browsers) and leaf in CACHE_LEAVES:
            return "browser-cache"
        if len(rel) == 5 and rel[:3] == ["mozilla", "firefox", "profiles"] and leaf == "cache2":
            return "browser-cache"
        for prefix in (["microsoft", "vscode"], ["cursor"], ["discord"], ["slack"]):
            if rel[:-1] == prefix and leaf in CACHE_LEAVES:
                return "application-cache"
    if roaming and (rel := relative_parts(p, roaming)):
        if len(rel) == 2 and rel[0] in {"code", "cursor", "discord", "slack"} and rel[-1] in CACHE_LEAVES:
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
    if contains_project_marker(p):
        return False, "target is inside or below a detected project/repository"
    actual = classify_safe_cache_path(p)
    return (True, "ok") if actual == expected_tag else (False, f"path allowlist mismatch: expected {expected_tag}, got {actual}")


def _push(heap: list[tuple[int, str]], item: tuple[int, str], limit: int) -> None:
    if len(heap) < limit:
        heapq.heappush(heap, item)
    elif item > heap[0]:
        heapq.heapreplace(heap, item)


def scan_root(root: Path, top_n: int, max_depth: int, audit: AuditLog) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
    root = Path(norm(root))
    if not root.exists() or is_link(root):
        audit.error(str(root), RuntimeError("root missing or unsafe"))
        return 0, [], []
    sizes: dict[str, int] = {}
    dev: list[dict[str, Any]] = []
    for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
        cp = Path(current)
        safe_dirs = []
        for name in dirs:
            child = cp / name
            if is_link(child):
                audit.skipped_links += 1
            else:
                safe_dirs.append(name)
        total = 0
        for name in files:
            fp = cp / name
            try:
                if is_link(fp):
                    audit.skipped_links += 1
                    continue
                total += fp.stat().st_size
                audit.files_seen += 1
            except OSError as exc:
                audit.error(str(fp), exc)
        total += sum(sizes.get(norm(cp / name), 0) for name in safe_dirs)
        sizes[norm(cp)] = total
        audit.directories_seen += 1
        if cp.name.casefold() in DEV_DIRS:
            dev.append({"path": str(cp), "bytes": total, "kind": cp.name})
    ranked = []
    for path, size in sizes.items():
        try:
            depth = 0 if same_path(path, root) else len(Path(os.path.relpath(path, root)).parts)
        except ValueError:
            continue
        if depth <= max_depth:
            ranked.append({"path": path, "bytes": size})
    ranked.sort(key=lambda x: x["bytes"], reverse=True)
    dev.sort(key=lambda x: x["bytes"], reverse=True)
    return sizes.get(norm(root), 0), ranked[:top_n], dev[:top_n]


def candidate_id(action: str, path: Optional[str], command_id: Optional[str]) -> str:
    return hashlib.sha256(f"{action}|{norm(path) if path else ''}|{command_id or ''}".encode()).hexdigest()[:16]


def candidate_for_path(path: Path, tag: str, label: str, days: int) -> Candidate:
    size = 0
    try:
        for current, _, files in os.walk(path, followlinks=False):
            for name in files:
                fp = Path(current) / name
                if not is_link(fp):
                    size += fp.stat().st_size
    except OSError:
        pass
    return Candidate(candidate_id("delete-contents", str(path), None), label, str(path), size, "LOW", "delete-contents", tag, "Exact allowlisted cache location", days)


def discover_candidates() -> list[Candidate]:
    paths: list[tuple[Path, str, str, int]] = []
    seen: set[str] = set()
    for value in (os.getenv("TEMP"), os.getenv("TMP")):
        if value:
            paths.append((Path(value), "known-temp", "Temporary files", 7))
    local, system = os.getenv("LOCALAPPDATA"), os.getenv("SystemRoot")
    if local:
        paths += [(Path(local) / "Temp", "known-temp", "Local temporary files", 7), (Path(local) / "CrashDumps", "known-temp", "Crash dumps", 14)]
    if system:
        paths.append((Path(system) / "Temp", "known-temp", "Windows temporary files", 7))
    result: list[Candidate] = []
    for path, tag, label, days in paths:
        key = norm(path)
        if key in seen or not path.exists():
            continue
        seen.add(key)
        valid, _ = validate_cleanup_path(path, tag)
        if valid:
            result.append(candidate_for_path(path, tag, label, days))
    return result


def default_roots() -> list[Path]:
    if os.name == "nt":
        return [Path(f"{letter}:\\") for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{letter}:\\").exists()]
    return [Path.cwd().anchor or "/"]


def scan_command(args: argparse.Namespace) -> int:
    roots = [Path(x) for x in args.roots] or default_roots()
    audit = AuditLog()
    drives = []
    for root in roots:
        total, largest, dev = scan_root(root, args.top, args.max_depth, audit)
        try:
            usage = shutil.disk_usage(root)
            disk = {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}
        except OSError as exc:
            audit.error(str(root), exc)
            disk = {}
        drives.append({"root": str(root), "scanned_bytes": total, "disk": disk, "largest_directories": largest, "development_directories": dev})
    candidates = [asdict(x) for x in discover_candidates()]
    report = {"schema_version": SCHEMA_VERSION, "created_at": iso(utc_now()), "platform": sys.platform, "drives": drives, "candidates": candidates, "audit": audit.__dict__}
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote read-only report: {args.output}")
    return 0


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def plan_payload(plan: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in plan.items() if k != "plan_hash"}


def plan_command(args: argparse.Namespace) -> int:
    report = load_json(args.report)
    all_items = {x["id"]: x for x in report.get("candidates", []) if x.get("risk") == "LOW" and x.get("automatic")}
    selected = args.select or list(all_items)
    missing = [x for x in selected if x not in all_items]
    if missing:
        raise SystemExit(f"unknown or non-automatic candidate IDs: {', '.join(missing)}")
    items = []
    for cid in selected:
        item = dict(all_items[cid])
        item["candidate_id"] = item.pop("id")
        item["min_age_days"] = max(DEFAULT_MIN_AGE_DAYS, int(item.get("min_age_days", args.min_age_days)))
        items.append(item)
    if not items:
        raise SystemExit("refusing to create an empty plan")
    now = utc_now()
    plan = {"schema_version": SCHEMA_VERSION, "plan_id": secrets.token_hex(8), "created_at": iso(now), "expires_at": iso(now + dt.timedelta(hours=PLAN_TTL_HOURS)), "approval_phrase": f"APPROVE-{secrets.token_hex(4).upper()}", "items": items}
    plan["plan_hash"] = sha256_json(plan_payload(plan))
    Path(args.output).write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote plan: {args.output}\nApproval phrase: {plan['approval_phrase']}")
    return 0


def delete_old_contents(root: Path, min_age_days: int) -> dict[str, Any]:
    cutoff = time.time() - max(DEFAULT_MIN_AGE_DAYS, min_age_days) * 86400
    deleted_bytes = deleted_files = deleted_dirs = skipped = 0
    errors: list[dict[str, str]] = []
    if is_link(root):
        return {"deleted_files": 0, "deleted_directories": 0, "deleted_bytes": 0, "skipped": 1, "errors": []}
    visited: list[Path] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cp = Path(current)
        visited.append(cp)
        allowed_dirs: list[str] = []
        for name in dirs:
            dp = cp / name
            if is_link(dp) or contains_project_marker(dp):
                skipped += 1
            else:
                allowed_dirs.append(name)
        dirs[:] = allowed_dirs
        for name in files:
            fp = cp / name
            try:
                st = fp.stat()
                if is_link(fp) or st.st_mtime > cutoff:
                    skipped += 1
                    continue
                fp.unlink()
                deleted_bytes += st.st_size
                deleted_files += 1
            except OSError as exc:
                errors.append({"path": str(fp), "error": f"{type(exc).__name__}: {exc}"})
    for directory in reversed(visited):
        if same_path(directory, root):
            continue
        try:
            directory.rmdir()
            deleted_dirs += 1
        except OSError:
            pass
    return {"deleted_files": deleted_files, "deleted_directories": deleted_dirs, "deleted_bytes": deleted_bytes, "skipped": skipped, "errors": errors[:MAX_ERRORS]}


def verify_plan(plan: dict[str, Any]) -> dict[str, bool]:
    checks = {
        "hash_valid": plan.get("plan_hash") == sha256_json(plan_payload(plan)),
        "not_expired": parse_iso(plan["expires_at"]) >= utc_now(),
        "has_items": bool(plan.get("items")),
        "all_low_risk": all(x.get("risk") == "LOW" for x in plan.get("items", [])),
        "all_actions_known": all(x.get("action") in {"delete-contents", "run-command"} for x in plan.get("items", [])),
    }
    checks["valid"] = all(checks.values())
    return checks


def verify_command(args: argparse.Namespace) -> int:
    checks = verify_plan(load_json(args.plan))
    print(json.dumps(checks, indent=2))
    return 0 if checks["valid"] else 1


def execute_command(args: argparse.Namespace) -> int:
    if os.name != "nt":
        raise SystemExit("execution is Windows-only")
    plan = load_json(args.plan)
    if not verify_plan(plan)["valid"]:
        raise SystemExit("plan is invalid, expired, or modified")
    if args.approve != plan.get("approval_phrase") or not args.yes:
        raise SystemExit("exact approval phrase and --yes are required")
    results = []
    for item in plan["items"]:
        result = {"candidate_id": item.get("candidate_id"), "label": item.get("label"), "status": "FAILED"}
        try:
            if item["action"] == "delete-contents":
                valid, reason = validate_cleanup_path(item["path"], item["safety_tag"])
                if not valid:
                    raise RuntimeError(reason)
                result.update(status="DONE", details=delete_old_contents(Path(item["path"]), int(item["min_age_days"])))
            elif item["action"] == "run-command":
                command = ALLOWED_COMMANDS.get(item.get("command_id"))
                if not command:
                    raise RuntimeError("command is not allowlisted")
                done = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
                result.update(status="DONE" if done.returncode == 0 else "FAILED", returncode=done.returncode, stdout=done.stdout[-4000:], stderr=done.stderr[-4000:])
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        results.append(result)
    log = {"schema_version": SCHEMA_VERSION, "plan_id": plan["plan_id"], "executed_at": iso(utc_now()), "results": results, "summary": {"done": sum(x["status"] == "DONE" for x in results), "failed": sum(x["status"] == "FAILED" for x in results), "deleted_bytes": sum(x.get("details", {}).get("deleted_bytes", 0) for x in results)}}
    Path(args.output).write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote execution log: {args.output}")
    return 1 if log["summary"]["failed"] else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Conservative Windows disk audit and cleanup")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("roots", nargs="*")
    scan.add_argument("--output", default="safe-reclaim-report.json")
    scan.add_argument("--top", type=int, default=40)
    scan.add_argument("--max-depth", type=int, default=5)
    scan.add_argument("--probe-tools", action="store_true")
    scan.set_defaults(func=scan_command)
    plan = sub.add_parser("plan")
    plan.add_argument("--report", required=True)
    plan.add_argument("--output", default="safe-reclaim-plan.json")
    plan.add_argument("--select", action="append")
    plan.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS)
    plan.set_defaults(func=plan_command)
    verify = sub.add_parser("verify")
    verify.add_argument("--plan", required=True)
    verify.set_defaults(func=verify_command)
    execute = sub.add_parser("execute")
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
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
