#!/usr/bin/env bash
set -euo pipefail

# LLM-CONTRACT
# id: agent-work-governor.buck2-release-digest-regression
# state: REVIEWED_TREE -> CORRUPTED_RELEASE_DIGEST -> HASH_REJECTION | INCONCLUSIVE
# preconditions: Git, Python, and the pinned Nix executable are available
# invariant: only Buck2's top-level digest changes; platform artifacts stay fixed
# failure: acceptance is CODE_FAIL=1; transport or untyped failure is INCONCLUSIVE=2
# source: https://nix.dev/manual/nix/2.34/store/file-system-object/content-address
# knowledge: bundle:knowledge/references/buck2-shadow-pilot.md
# enforced_by: proof-slow-buck2-release
# test: bundle:tests/test_contracts.py

repository="$(git rev-parse --show-toplevel)"
temporary_root="$(python3 -c 'import os,tempfile; print(os.path.realpath(tempfile.gettempdir()))')"
runtime="$(mktemp -d "$temporary_root/awg-buck2-release.XXXXXX")"
trap 'rm -rf "$runtime"' EXIT
git -C "$repository" archive HEAD | tar -x -C "$runtime"

python3 -B - "$runtime/toolchain.lock.json" "$runtime/release" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
matches = [tool for tool in document["tools"] if tool["id"] == "buck2"]
if len(matches) != 1:
    raise SystemExit("BUCK2_PIN_NOT_UNIQUE")
pin = matches[0]
artifacts = json.dumps(pin["artifacts"], sort_keys=True, separators=(",", ":"))
pin["source_digest"] = f"sha256:{'0' * 64}"
if json.dumps(pin["artifacts"], sort_keys=True, separators=(",", ":")) != artifacts:
    raise SystemExit("BUCK2_PLATFORM_ARTIFACT_DRIFT")
path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
Path(sys.argv[2]).write_text(pin["version"].replace(".", "-"), encoding="utf-8")
PY

release="$(cat "$runtime/release")"
corrupted_sri="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
set +e
nix build --no-link --no-update-lock-file --no-write-lock-file \
  "path:$runtime#buck2-release-source" >"$runtime/nix.log" 2>&1
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "BUCK2_RELEASE_DIGEST_CORRUPTION_ACCEPTED" >&2
  exit 1
fi
if grep -Fqi "hash mismatch in fixed-output derivation" "$runtime/nix.log" \
  && grep -Fq "buck2-$release-release-launcher.drv" "$runtime/nix.log" \
  && grep -Fq "specified: $corrupted_sri" "$runtime/nix.log"; then
  echo '{"classification":"CODE_OK","gate":"buck2-release-digest","status":"PASS"}'
  exit 0
fi
cat "$runtime/nix.log" >&2
exit 2
