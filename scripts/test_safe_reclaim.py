#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("safe_reclaim.py")
spec = importlib.util.spec_from_file_location("safe_reclaim", MODULE_PATH)
sr = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = sr
spec.loader.exec_module(sr)


class SafeReclaimTests(unittest.TestCase):
    def old(self, path: Path, days: int) -> None:
        value = time.time() - days * 86400
        os.utime(path, (value, value))

    def test_scan_aggregates_nested_directory_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "parent" / "nested").mkdir(parents=True)
            (root / "parent" / "nested" / "blob.bin").write_bytes(b"x" * 10000)
            audit = sr.AuditLog()
            total, largest, _ = sr.scan_root(root, 20, 10, audit)
            by_path = {item["path"]: item["bytes"] for item in largest}
            self.assertEqual(total, 10000)
            self.assertEqual(by_path[str(root / "parent")], 10000)
            self.assertEqual(by_path[str(root / "parent" / "nested")], 10000)

    def test_measure_candidate_reports_1_3_7_day_eligibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, days, size in (
                ("recent.bin", 0, 11),
                ("two-days.bin", 2, 22),
                ("five-days.bin", 5, 33),
                ("ten-days.bin", 10, 44),
            ):
                path = root / name
                path.write_bytes(b"x" * size)
                self.old(path, days)
            result = sr.measure_candidate(root)
            self.assertEqual(result["total_bytes"], 110)
            self.assertEqual(result["eligible_by_age"]["1"]["bytes"], 99)
            self.assertEqual(result["eligible_by_age"]["3"]["bytes"], 77)
            self.assertEqual(result["eligible_by_age"]["7"]["bytes"], 44)

    def test_delete_reports_recent_bytes_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cache"
            root.mkdir()
            old = root / "old.tmp"
            recent = root / "recent.tmp"
            old.write_bytes(b"old")
            recent.write_bytes(b"recent")
            self.old(old, 10)
            result = sr.delete_eligible_contents(root, 3)
            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())
            self.assertTrue(root.exists())
            self.assertEqual(result["deleted_bytes"], 3)
            self.assertEqual(result["skipped_recent_bytes"], 6)
            self.assertEqual(result["skipped_recent_files"], 1)

    def test_plan_hash_detects_tampering(self):
        plan = {
            "schema_version": sr.SCHEMA_VERSION,
            "plan_id": "abc",
            "created_at": "2030-01-01T00:00:00Z",
            "expires_at": "2030-01-01T06:00:00Z",
            "approval_phrase": "APPROVE-1234",
            "items": [],
        }
        plan["plan_hash"] = sr.sha256_json(sr.plan_payload(plan))
        self.assertEqual(plan["plan_hash"], sr.sha256_json(sr.plan_payload(plan)))
        plan["approval_phrase"] = "APPROVE-9999"
        self.assertNotEqual(plan["plan_hash"], sr.sha256_json(sr.plan_payload(plan)))

    def test_validate_exact_temp_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Temp"
            root.mkdir()
            env = {"TEMP": str(root), "TMP": str(root)}
            with mock.patch.dict(os.environ, env, clear=False):
                valid, _ = sr.validate_cleanup_path(root, "known-temp")
                self.assertTrue(valid)
                other = Path(tmp) / "Documents"
                other.mkdir()
                valid, _ = sr.validate_cleanup_path(other, "known-temp")
                self.assertFalse(valid)

    def test_browser_profile_allowlist_is_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "Local"
            cache = local / "Google" / "Chrome" / "User Data" / "Profile 2" / "Cache"
            cache.mkdir(parents=True)
            bad = local / "Google" / "Chrome" / "User Data" / "Profile 2" / "Cookies"
            bad.mkdir()
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}, clear=False):
                self.assertEqual(sr.classify_safe_cache_path(cache), "browser-cache")
                self.assertIsNone(sr.classify_safe_cache_path(bad))

    def test_delete_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "cache"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            victim = outside / "keep.txt"
            victim.write_text("keep")
            self.old(victim, 10)
            try:
                (root / "link").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            result = sr.delete_eligible_contents(root, 3)
            self.assertTrue(victim.exists())
            self.assertGreaterEqual(result["skipped_links"], 1)

    def test_delete_skips_nested_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cache"
            project = root / "project"
            project.mkdir(parents=True)
            (project / "package.json").write_text("{}")
            victim = project / "important.txt"
            victim.write_text("important")
            normal = root / "old.tmp"
            normal.write_text("old")
            for path in (victim, normal):
                self.old(path, 10)
            result = sr.delete_eligible_contents(root, 3)
            self.assertTrue(victim.exists())
            self.assertFalse(normal.exists())
            self.assertGreaterEqual(result["skipped_project_directories"], 1)

    def test_temp_environment_cannot_bypass_protected_system_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            system_root = Path(tmp) / "Windows"
            system32 = system_root / "System32"
            system_temp = system_root / "Temp"
            system32.mkdir(parents=True)
            system_temp.mkdir()
            env = {
                "SystemRoot": str(system_root),
                "TEMP": str(system32),
                "TMP": str(system32),
            }
            with mock.patch.dict(os.environ, env, clear=False):
                valid, _ = sr.validate_cleanup_path(system32, "known-temp")
                self.assertFalse(valid)
                valid, _ = sr.validate_cleanup_path(system_temp, "known-temp")
                self.assertTrue(valid)

    def test_plan_age_override_uses_matching_estimate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "report.json"
            plan_path = root / "plan.json"
            candidate = {
                "id": "candidate",
                "label": "test",
                "path": str(root / "Temp"),
                "total_bytes": 100,
                "total_files": 3,
                "eligible_bytes": 25,
                "eligible_files": 1,
                "eligible_by_age": {
                    "1": {"bytes": 90, "files": 3},
                    "3": {"bytes": 50, "files": 2},
                    "7": {"bytes": 25, "files": 1},
                },
                "risk": "LOW",
                "action": "delete-contents",
                "safety_tag": "known-temp",
                "reason": "test",
                "min_age_days": 7,
                "automatic": True,
                "command_id": None,
                "notes": [],
            }
            report = {
                "schema_version": sr.SCHEMA_VERSION,
                "candidates": [candidate],
            }
            report_path.write_text(json.dumps(report), encoding="utf-8")
            args = Namespace(
                report=str(report_path),
                output=str(plan_path),
                select=["candidate"],
                age_days=1,
            )
            self.assertEqual(sr.plan_command(args), 0)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["items"][0]["min_age_days"], 1)
            self.assertEqual(plan["estimated_eligible_bytes"], 90)
            self.assertTrue(sr.verify_plan(plan)["valid"])

    def test_plan_rejects_old_schema_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            report.write_text(json.dumps({"schema_version": 2, "candidates": []}))
            args = Namespace(
                report=str(report),
                output=str(Path(tmp) / "plan.json"),
                select=None,
                age_days=None,
            )
            with self.assertRaises(SystemExit):
                sr.plan_command(args)

    def test_command_allowlist_contains_no_shell_operators(self):
        for command in sr.ALLOWED_COMMANDS.values():
            self.assertIsInstance(command, list)
            self.assertGreater(len(command), 1)
            self.assertNotIn("&&", command)
            self.assertNotIn("|", command)
            self.assertNotIn(";", command)

    def test_verify_rejects_unsupported_age(self):
        now = sr.utc_now()
        plan = {
            "schema_version": sr.SCHEMA_VERSION,
            "plan_id": "abc",
            "created_at": sr.iso(now),
            "expires_at": sr.iso(now + sr.dt.timedelta(hours=1)),
            "approval_phrase": "APPROVE-1234",
            "items": [
                {
                    "risk": "LOW",
                    "action": "delete-contents",
                    "min_age_days": 0,
                }
            ],
        }
        plan["plan_hash"] = sr.sha256_json(sr.plan_payload(plan))
        self.assertFalse(sr.verify_plan(plan)["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
