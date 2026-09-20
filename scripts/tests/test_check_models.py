"""Offline tests of formal evidence custody and failure handling, not model proofs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_models


class ModelEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        directory = self.root / "docs/models"
        directory.mkdir(parents=True)
        rows: list[str] = []
        for name in check_models.MODELS:
            for suffix in ("tla", "cfg"):
                (directory / f"{name}.{suffix}").write_text("fixture\n", encoding="utf-8")
            digest = hashlib.sha256(b"fixture\n").hexdigest()
            rows.append(f"| {name} | {digest} | {digest} | N=1 | 128 | BLOCKED | - | - |")
        (self.root / "CONSTRAINTS.md").write_text("\n".join(rows), encoding="utf-8")
        self.home = self.root / "tool"
        (self.home / "bin").mkdir(parents=True)
        (self.home / "lib").mkdir()
        jar = self.home / "lib/apalache.jar"
        jar.write_bytes(b"synthetic tool, not a prover")
        api = self.root / "docs/api"
        api.mkdir()
        (api / "core-compat.toml").write_text(
            '[reference.formal_tool]\nname = "apalache-mc"\nversion = "0.62.2"\n'
            f'jar_sha256 = "{hashlib.sha256(jar.read_bytes()).hexdigest()}"\n',
            encoding="utf-8",
        )
        self.executable = self.home / "bin/apalache-mc"
        self.write_tool('print("The outcome is: NoError\\nEXITCODE: OK")')

    def write_tool(self, body: str, version: str = "0.62.2") -> None:
        self.executable.write_text(
            f"#!{sys.executable}\nimport sys, time\n"
            f"if sys.argv[1] == 'version':\n    print({version!r})\n    sys.exit(0)\n{body}\n",
            encoding="utf-8",
        )
        self.executable.chmod(0o755)

    def run_check(self, timeout: int = 5) -> None:
        model = check_models.models(self.root)[0]
        check_models.run_model(self.root, self.executable, model, check_models.PROPERTIES[0], timeout)

    def test_input_custody_rejects_changed_or_missing_models(self) -> None:
        self.assertEqual(len(check_models.models(self.root)), 3)
        (self.root / "docs/models/ChainAdmission.tla").write_text("changed", encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.models(self.root)
        self.assertEqual(error.exception.code, 15)
        (self.root / "CONSTRAINTS.md").write_text("", encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.models(self.root)
        self.assertEqual(error.exception.code, 15)

    def test_tool_custody_rejects_wrong_version_and_jar(self) -> None:
        with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
            self.assertEqual(check_models.tool(self.root), self.executable)
            self.write_tool("", version="0.62.20")
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
            self.assertEqual(error.exception.code, 11)
            self.write_tool("")
            (self.home / "lib/apalache.jar").write_bytes(b"different")
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
            self.assertEqual(error.exception.code, 11)

    def test_complete_success_retains_identity_and_outcome(self) -> None:
        self.run_check()
        results = list(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(len(results), 1)
        self.assertEqual(json.loads(results[0].read_text()), {"native_rc": 0, "evidence_rc": 0})
        identity = json.loads(results[0].with_name("identity.json").read_text())
        self.assertIn("--length=128", identity["argv"])
        self.assertIn("--inv=TypeOK,Safety,TransitionSafety", identity["argv"])
        self.assertEqual(identity["constants"], "N=1")

    def test_native_failures_keep_their_meaning(self) -> None:
        for native, expected in ((150, 12), (120, 12), (12, 13), (255, 14)):
            with self.subTest(native=native):
                self.write_tool(f"sys.exit({native})")
                with self.assertRaises(check_models.EvidenceError) as error:
                    self.run_check()
                self.assertEqual(error.exception.code, expected)

    def test_zero_exit_without_complete_outcome_is_not_a_proof(self) -> None:
        for text in ("", "The outcome is: NoError", "EXITCODE: OK"):
            with self.subTest(text=text):
                self.write_tool(f"print({text!r})")
                with self.assertRaises(check_models.EvidenceError) as error:
                    self.run_check()
                self.assertEqual(error.exception.code, 14)

    def test_timeout_is_recorded_as_unavailable(self) -> None:
        self.write_tool("time.sleep(60)")
        with self.assertRaises(check_models.EvidenceError) as error:
            self.run_check(timeout=1)
        self.assertEqual(error.exception.code, 14)
        result = next(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(json.loads(result.read_text()), {"native_rc": None, "evidence_rc": 14})


if __name__ == "__main__":
    unittest.main()
