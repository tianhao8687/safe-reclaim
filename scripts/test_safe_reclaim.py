#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("safe_reclaim.py")
spec = importlib.util.spec_from_file_location("safe_reclaim", MODULE_PATH)
ds = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = ds
spec.loader.exec_module(ds)


class SafeReclaimTests(unittest.TestCase):
    def test_scan_aggregates_nested_directory_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "parent" / "nested").mkdir(parents=True)
            (root / "parent" / "nested" / "blob.bin").write_bytes(b"x" * 10000)
            audit = ds.AuditLog()
            total, largest, _ = ds.scan_root(root, 20, 10, audit)
            by_path = {item["path"]: item["bytes"] for item in largest}
            self.assertEqual(total, 10000)
            self.assertEqual(by_path[str(root / "parent")], 10000)
            self.assertEqual(by_path[str(root / "parent" / "nested")], 10000)

    def test_plan_hash_detects_tampering(self):
        plan = {
            "schema_version": 2,
            "plan_id": "abc",
            "created_at": "2030-01-01T00:00:00Z",
            "expires_at": "2030-01-01T06:00:00Z",
            "approval_phrase": "APPROVE-1234",
            "items": [],
        }
        plan["plan_hash"] = ds.sha256_json(ds.plan_payload(plan))
        self.assertEqual(plan["plan_hash"], ds.sha256_json(ds.plan_payload(plan)))
        plan["approval_phrase"] = "APPROVE-9999"
        self.assertNotEqual(plan["plan_hash"], ds.sha256_json(ds.plan_payload(plan)))

    def test_delete_old_contents_keeps_recent_files_and_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cache"
            root.mkdir()
            old = root / "old.tmp"
            new = root / "new.tmp"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            old_time = time.time() - 10 * 86400
            os.utime(old, (old_time, old_time))
            result = ds.delete_old_contents(root, 3)
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())
            self.assertTrue(root.exists())
            self.assertEqual(result["deleted_bytes"], 3)

    def test_validate_exact_temp_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Temp"
            root.mkdir()
            with mock.patch.dict(os.environ, {"TEMP": str(root), "TMP": str(root)}, clear=False):
                valid, _ = ds.validate_cleanup_path(root, "known-temp")
                self.assertTrue(valid)
                other = Path(tmp) / "Documents"
                other.mkdir()
                valid, _ = ds.validate_cleanup_path(other, "known-temp")
                self.assertFalse(valid)

    def test_delete_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "cache"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            victim = outside / "keep.txt"
            victim.write_text("keep")
            old_time = time.time() - 10 * 86400
            os.utime(victim, (old_time, old_time))
            try:
                (root / "link").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            result = ds.delete_old_contents(root, 3)
            self.assertTrue(victim.exists())
            self.assertGreaterEqual(result["skipped"], 1)

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
            old_time = time.time() - 10 * 86400
            for path in (victim, normal):
                os.utime(path, (old_time, old_time))
            result = ds.delete_old_contents(root, 3)
            self.assertTrue(victim.exists())
            self.assertFalse(normal.exists())
            self.assertGreaterEqual(result["skipped"], 1)

    def test_temp_environment_cannot_bypass_protected_system_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            system_root = Path(tmp) / "Windows"
            system32 = system_root / "System32"
            system_temp = system_root / "Temp"
            system32.mkdir(parents=True)
            system_temp.mkdir()
            env = {"SystemRoot": str(system_root), "TEMP": str(system32), "TMP": str(system32)}
            with mock.patch.dict(os.environ, env, clear=False):
                valid, _ = ds.validate_cleanup_path(system32, "known-temp")
                self.assertFalse(valid)
                valid, _ = ds.validate_cleanup_path(system_temp, "known-temp")
                self.assertTrue(valid)

    def test_command_allowlist_contains_no_shell_strings(self):
        for command in ds.ALLOWED_COMMANDS.values():
            self.assertIsInstance(command, list)
            self.assertGreater(len(command), 1)
            self.assertNotIn("&&", command)
            self.assertNotIn("|", command)


if __name__ == "__main__":
    unittest.main(verbosity=2)
