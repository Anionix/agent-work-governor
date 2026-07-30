from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import project_toolchain_digest

# LLM-CONTRACT
# id: agent-work-governor.toolchain-digest-projection-tests
# state: LOCK_OR_PROJECTION_MUTATION -> CHECK_OR_WRITE -> EXACT_UPDATE | STABLE_REJECTION
# preconditions: mutable fixtures are isolated in one temporary repository root
# invariant: current bytes pass, stale or malformed bytes fail, and repeated writes are byte-identical
# failure: unittest reports the projection transition that violated the single-source contract
# source: repo:scripts/project_toolchain_digest.py
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: ToolchainProjectionTests
# test: bundle:tests/test_toolchain_projection.py


class ToolchainProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copyfile(
            PLUGIN_ROOT / "toolchain.lock.json",
            self.root / "toolchain.lock.json",
        )
        for relative in project_toolchain_digest.PROJECTIONS:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PLUGIN_ROOT / relative, target)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _change_catalog_entry(self) -> None:
        catalog = self.root / "toolchain.lock.json"
        document = json.loads(catalog.read_text(encoding="utf-8"))
        document["tools"][0]["source_digest"] = f"sha256:{'0' * 64}"
        catalog.write_text(
            json.dumps(document, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_repository_and_unchanged_copy_are_current(self) -> None:
        for root in (PLUGIN_ROOT, self.root):
            with self.subTest(root=root):
                report = project_toolchain_digest.synchronize(root, write=False)
                self.assertEqual("PASS", report["status"])
                self.assertEqual([], report["updated"])

    def test_stale_projection_fails_with_exact_path(self) -> None:
        relative = project_toolchain_digest.PROJECTIONS[0]
        path = self.root / relative
        current = path.read_text(encoding="utf-8")
        path.write_text(
            project_toolchain_digest.FIELD.sub(
                lambda match: f"{match.group(1)}{'0' * 64}{match.group(2)}",
                current,
            ),
            encoding="utf-8",
        )

        with self.assertRaises(project_toolchain_digest.ProjectionError) as caught:
            project_toolchain_digest.synchronize(self.root, write=False)

        self.assertEqual("TOOLCHAIN_PROJECTION_STALE", caught.exception.code)
        self.assertEqual((str(relative),), caught.exception.paths)

    def test_missing_duplicate_and_malformed_pointer_are_rejected(self) -> None:
        path = self.root / project_toolchain_digest.PROJECTIONS[0]
        original = path.read_text(encoding="utf-8")
        digest_line = next(
            line for line in original.splitlines() if '"toolchain_sha256"' in line
        )
        mutations = {
            "missing": original.replace("toolchain_sha256", "toolchain_digest", 1),
            "duplicate": original.replace(
                digest_line,
                f"{digest_line},\n{digest_line}",
                1,
            ),
            "malformed": "{",
            "non_finite": original.replace(
                '"mutation_count": 0',
                '"mutation_count": NaN',
                1,
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                path.write_text(mutation, encoding="utf-8")
                with self.assertRaises(
                    project_toolchain_digest.ProjectionError
                ) as caught:
                    project_toolchain_digest.synchronize(self.root, write=False)
                self.assertEqual(
                    "TOOLCHAIN_PROJECTION_INVALID",
                    caught.exception.code,
                )
                path.write_text(original, encoding="utf-8")

    def test_write_is_complete_and_idempotent(self) -> None:
        self._change_catalog_entry()

        first = project_toolchain_digest.synchronize(self.root, write=True)
        generated = {
            relative: (self.root / relative).read_bytes()
            for relative in project_toolchain_digest.PROJECTIONS
        }
        second = project_toolchain_digest.synchronize(self.root, write=True)

        self.assertEqual(
            [str(path) for path in project_toolchain_digest.PROJECTIONS],
            first["updated"],
        )
        self.assertEqual([], second["updated"])
        self.assertEqual(
            generated,
            {
                relative: (self.root / relative).read_bytes()
                for relative in project_toolchain_digest.PROJECTIONS
            },
        )

    def test_write_failure_rolls_back_completed_projection(self) -> None:
        self._change_catalog_entry()
        originals = {
            relative: (self.root / relative).read_bytes()
            for relative in project_toolchain_digest.PROJECTIONS
        }
        rejected = self.root / project_toolchain_digest.PROJECTIONS[1]
        write_bytes = Path.write_bytes
        injected = False

        def fail_second(path: Path, payload: bytes) -> int:
            nonlocal injected
            if path.name == rejected.name and not injected:
                injected = True
                raise OSError("injected write failure")
            return write_bytes(path, payload)

        with (
            mock.patch.object(Path, "write_bytes", new=fail_second),
            self.assertRaises(project_toolchain_digest.ProjectionError) as caught,
        ):
            project_toolchain_digest.synchronize(self.root, write=True)

        self.assertEqual(
            "TOOLCHAIN_PROJECTION_WRITE_FAILED",
            caught.exception.code,
        )
        self.assertEqual(
            originals,
            {
                relative: (self.root / relative).read_bytes()
                for relative in project_toolchain_digest.PROJECTIONS
            },
        )


if __name__ == "__main__":
    unittest.main()
