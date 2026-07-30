from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts/validate_flake_lock_pair.py"
HEAD_SHA = "a" * 40
NIX_VERSION = "nix (Nix) 2.34.7"

# LLM-CONTRACT
# id: agent-work-governor.flake-lock-pair-tests
# state: VALIDATOR_FIXTURE -> EXPECTED_TERMINAL_EVIDENCE | TEST_FAILURE
# preconditions: each test owns isolated regular-file inputs
# invariant: PASS, FAIL, and INCONCLUSIVE remain deterministic and fail closed
# failure: any exit or JSON evidence drift fails the unit test
# source: https://github.com/NixOS/nix/blob/2c6d06e9387cf58167cb5a7ab91cee7333d8d17c/src/nix/flake-lock.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: FlakeLockPairTests
# test: bundle:tests/test_flake_lock_pair.py


class FlakeLockPairTests(unittest.TestCase):
    def run_validator(
        self,
        root: Path,
        *,
        head_sha: str = HEAD_SHA,
        nix_version: str = NIX_VERSION,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                "--flake-nix",
                str(root / "flake.nix"),
                "--committed-lock",
                str(root / "flake.lock"),
                "--regenerated-lock",
                str(root / "regenerated.lock"),
                "--head-sha",
                head_sha,
                "--nix-version",
                nix_version,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return process, json.loads(process.stdout)

    def make_pair(self, root: Path, regenerated: bytes = b'{"version":7}\n') -> None:
        (root / "flake.nix").write_text("{ outputs = _: {}; }\n", encoding="utf-8")
        (root / "flake.lock").write_bytes(b'{"version":7}\n')
        (root / "regenerated.lock").write_bytes(regenerated)

    def test_byte_equivalent_pair_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_pair(root)
            process, evidence = self.run_validator(root)
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertEqual("PASS", evidence["status"])
        self.assertEqual("BYTE_EQUIVALENT", evidence["state"])
        self.assertEqual(
            evidence["committed_lock_sha256"],
            evidence["regenerated_lock_sha256"],
        )

    def test_stale_lock_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_pair(root, regenerated=b'{"version":8}\n')
            process, evidence = self.run_validator(root)
        self.assertEqual(1, process.returncode)
        self.assertEqual("FAIL", evidence["status"])
        self.assertEqual("FLAKE_LOCK_PAIR_MISMATCH", evidence["code"])

    def test_missing_regenerated_lock_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_pair(root)
            (root / "regenerated.lock").unlink()
            process, evidence = self.run_validator(root)
        self.assertEqual(2, process.returncode)
        self.assertEqual("INCONCLUSIVE", evidence["status"])
        self.assertEqual("FLAKE_LOCK_PAIR_UNREADABLE", evidence["code"])
        self.assertIsNone(evidence["regenerated_lock_sha256"])

    def test_invalid_execution_identity_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_pair(root)
            process, evidence = self.run_validator(
                root,
                head_sha="HEAD",
                nix_version="nix (Nix) latest",
            )
        self.assertEqual(2, process.returncode)
        self.assertEqual("INCONCLUSIVE", evidence["status"])
        self.assertEqual("FLAKE_LOCK_EXECUTION_IDENTITY_INVALID", evidence["code"])

    def test_non_regular_inputs_are_inconclusive_without_hanging(self) -> None:
        creators = {
            "directory": lambda path: path.mkdir(),
            "fifo": os.mkfifo,
            "symlink": lambda path: path.symlink_to(path.with_name("flake.lock")),
        }
        for kind, create in creators.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_pair(root)
                (root / "regenerated.lock").unlink()
                create(root / "regenerated.lock")
                process, evidence = self.run_validator(root)
                self.assertEqual(2, process.returncode)
                self.assertEqual("FLAKE_LOCK_PAIR_UNREADABLE", evidence["code"])

    def test_oversized_input_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_pair(root, regenerated=b"x" * (4 * 1024 * 1024 + 1))
            process, evidence = self.run_validator(root)
        self.assertEqual(2, process.returncode)
        self.assertEqual("FLAKE_LOCK_PAIR_UNREADABLE", evidence["code"])

    def test_json_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_pair(root)
            first, _ = self.run_validator(root)
            second, _ = self.run_validator(root)
        self.assertEqual(first.stdout, second.stdout)


@unittest.skipUnless(
    os.environ.get("AWG_RUN_NIX_INTEGRATION") == "1"
    and shutil.which("git")
    and shutil.which("nix"),
    "requires explicit git+nix integration",
)
class FlakeLockPairNixIntegrationTests(unittest.TestCase):
    def run_command(self, *command: str, cwd: Path) -> None:
        process = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(0, process.returncode, process.stderr)

    def test_flake_lock_preserves_an_existing_moving_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            upstream = root / "upstream"
            upstream.mkdir()
            self.run_command("git", "init", "-b", "main", cwd=upstream)
            self.run_command("git", "config", "user.name", "Test", cwd=upstream)
            self.run_command("git", "config", "commit.gpgsign", "false", cwd=upstream)
            self.run_command(
                "git", "config", "user.email", "test@example.invalid", cwd=upstream
            )
            (upstream / "flake.nix").write_text(
                "{ outputs = { self }: {}; }\n",
                encoding="utf-8",
            )
            self.run_command("git", "add", "flake.nix", cwd=upstream)
            self.run_command("git", "commit", "-m", "first", cwd=upstream)

            consumer = root / "consumer"
            consumer.mkdir()
            (consumer / "flake.nix").write_text(
                '{ inputs.dep.url = "git+file://'
                f'{upstream}"; outputs = {{ self, dep }}: {{}}; }}\n',
                encoding="utf-8",
            )
            committed = consumer / "flake.lock"
            self.run_command(
                "nix",
                "flake",
                "lock",
                "--no-use-registries",
                "--output-lock-file",
                str(committed),
                f"path:{consumer}",
                cwd=consumer,
            )
            expected = committed.read_bytes()

            (upstream / "README.md").write_text("second\n", encoding="utf-8")
            self.run_command("git", "add", "README.md", cwd=upstream)
            self.run_command("git", "commit", "-m", "second", cwd=upstream)
            regenerated = root / "regenerated.lock"
            self.run_command(
                "nix",
                "flake",
                "lock",
                "--no-use-registries",
                "--output-lock-file",
                str(regenerated),
                f"path:{consumer}",
                cwd=consumer,
            )
            self.assertEqual(expected, regenerated.read_bytes())


if __name__ == "__main__":
    unittest.main()
