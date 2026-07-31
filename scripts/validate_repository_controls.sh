#!/usr/bin/env bash
# LLM-CONTRACT
# id: agent-work-governor.required-repository-controls
# state: REVIEWED_COMMIT -> REQUIRED_GIT_BLOBS + REQUIRED_CONTROLS -> PASS | CODE_FAIL
# preconditions: head identifies the reviewed commit and base identifies its comparison point
# invariant: required contracts are unique regular Git blobs; runtime output, mutable Actions, and invalid diffs never pass
# failure: emit a stable CODE_FAIL reason and exit 1
# source: https://git-scm.com/docs/git-ls-tree
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: proof-slow / nix
# test: bundle:tests/test_contracts.py
set -euo pipefail

code_fail() {
  printf '{"classification":"CODE_FAIL","code":"%s","status":"FAIL"}\n' "$1"
  exit 1
}

base_sha="${1:-}"
head_sha="${2:-}"
[[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || code_fail BASE_SHA_INVALID
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || code_fail HEAD_SHA_INVALID
[[ "$(git rev-parse HEAD)" == "$head_sha" ]] || code_fail CHECKOUT_IDENTITY_MISMATCH

required_contracts=(AGENTS.md CONTRIBUTING.md SECURITY.md flake.nix flake.lock)
contract_exclusions=()
for path in "${required_contracts[@]}"; do
  entry="$(git ls-tree "$head_sha" -- "$path")" ||
    code_fail REPOSITORY_CONTRACT_INVALID
  [[ -n "$entry" && "$entry" != *$'\n'* ]] ||
    code_fail REPOSITORY_CONTRACT_INVALID
  read -r mode object_type object_id tracked_path extra <<<"$entry" ||
    code_fail REPOSITORY_CONTRACT_INVALID
  [[ -z "${extra:-}" && "$tracked_path" == "$path" ]] ||
    code_fail REPOSITORY_CONTRACT_INVALID
  [[ "$mode" == 100644 || "$mode" == 100755 ]] ||
    code_fail REPOSITORY_CONTRACT_INVALID
  [[ "$object_type" == blob ]] ||
    code_fail REPOSITORY_CONTRACT_INVALID
  declared_size="$(git cat-file -s "$object_id" 2>/dev/null)" ||
    code_fail REPOSITORY_CONTRACT_INVALID
  readback_size="$(
    git cat-file blob "$object_id" 2>/dev/null | wc -c | tr -d '[:space:]'
  )" ||
    code_fail REPOSITORY_CONTRACT_INVALID
  readback_id="$(
    git cat-file blob "$object_id" 2>/dev/null | git hash-object --stdin
  )" ||
    code_fail REPOSITORY_CONTRACT_INVALID
  [[ "$declared_size" =~ ^[0-9]+$ &&
    "$readback_size" == "$declared_size" &&
    "$readback_id" == "$object_id" ]] ||
    code_fail REPOSITORY_CONTRACT_INVALID
  contract_exclusions+=(":(exclude)$path")
done

forbidden="$(
  git ls-files --cached --ignored --exclude-standard -- . "${contract_exclusions[@]}"
)"
test -z "$forbidden" || {
  echo "$forbidden"
  code_fail TRACKED_RUNTIME_OUTPUT
}
while IFS= read -r -d '' tracked_path; do
  case "/$tracked_path/" in
    */.cache/* | */.devenv/* | */.direnv/* | */.governance/* | \
      */.mypy_cache/* | */.nox/* | */.pytest_cache/* | */.ruff_cache/* | \
      */.tox/* | */.venv/* | */__pycache__/* | */bin/* | */build/* | \
      */dist/* | */dist-packages/* | */node_modules/* | */site-packages/* | \
      */Scripts/activate*/* | */Scripts/python*.exe/* | \
      */rust/target/* | */target/* | */venv/*)
      echo "$tracked_path"
      code_fail TRACKED_RUNTIME_OUTPUT
      ;;
  esac
  case "${tracked_path##*/}" in
    .coverage | .DS_Store | *.pyc | *.pyd | *.pyo | *.receipt.json | \
      pyvenv.cfg | result | result-* | run-receipt*.json)
      echo "$tracked_path"
      code_fail TRACKED_RUNTIME_OUTPUT
      ;;
  esac
done < <(git ls-files -z)

validator_root="${BASH_SOURCE[0]%/*}/.."
if ! PYTHONPATH="$validator_root/vendor/pyyaml-6.0.3.zip" python3 -B - <<'PY'
from pathlib import Path
import re
import subprocess
import yaml

def load(path):
    if path.is_symlink() or path.stat().st_size > 1_000_000:
        raise ValueError(f"unsafe YAML: {path}")
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"YAML root is not a mapping: {path}")
    return document

def step_actions(steps, path):
    if not isinstance(steps, list):
        raise ValueError(f"steps are not a list: {path}")
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError(f"step is not a mapping: {path}")
        if "uses" in step:
            yield step["uses"]

def workflow_actions(path):
    jobs = load(path).get("jobs")
    if not isinstance(jobs, dict):
        raise ValueError(f"jobs are not a mapping: {path}")
    for job in jobs.values():
        if not isinstance(job, dict):
            raise ValueError(f"job is not a mapping: {path}")
        if "uses" in job:
            yield job["uses"]
        if "steps" in job:
            yield from step_actions(job["steps"], path)

def manifest_actions(path):
    runs = load(path).get("runs")
    if not isinstance(runs, dict):
        raise ValueError(f"runs are not a mapping: {path}")
    if runs.get("using") == "composite":
        return step_actions(runs.get("steps"), path)
    if runs.get("using") == "docker":
        image = runs.get("image")
        if image == "Dockerfile" or (
            isinstance(image, str) and image.startswith("./")
        ):
            return []
        return [image]
    return []

def validate_action(action, path):
    if not isinstance(action, str):
        raise ValueError(f"non-text action: {path}")
    if action.startswith("./"):
        return
    pattern = (
        r"docker://[^@\s]+@sha256:[0-9a-f]{64}"
        if action.startswith("docker://")
        else r"[^@\s]+@[0-9a-f]{40}"
    )
    if re.fullmatch(pattern, action) is None:
        raise ValueError(f"mutable action: {path}: {action}")

if getattr(yaml, "__with_libyaml__", None) is not False:
    raise ValueError("locked pure-Python YAML runtime not loaded")
workflow_bytes = subprocess.check_output(
    [
        "git", "ls-files", "-z", "--",
        ":(glob).github/workflows/*.yml",
        ":(glob).github/workflows/*.yaml",
        ":(glob)**/.github/workflows/*.yml",
        ":(glob)**/.github/workflows/*.yaml",
    ]
)
workflows = sorted(
    {Path(raw.decode("utf-8")) for raw in workflow_bytes.split(b"\0") if raw}
)
if not workflows:
    raise ValueError("workflow directory is empty")
manifest_bytes = subprocess.check_output(
    ["git", "ls-files", "-z", "--", "action.yml", "action.yaml",
     ":(glob)**/action.yml", ":(glob)**/action.yaml"]
)
manifests = sorted(Path(raw.decode("utf-8")) for raw in manifest_bytes.split(b"\0") if raw)
for path in workflows:
    for action in workflow_actions(path):
        validate_action(action, path)
for path in manifests:
    for action in manifest_actions(path):
        validate_action(action, path)
PY
then
  code_fail UNPINNED_ACTION
fi

git diff --check "$base_sha...$head_sha" || code_fail DIFF_INVALID
echo '{"classification":"CODE_OK","gate":"repository-controls","status":"PASS"}'
