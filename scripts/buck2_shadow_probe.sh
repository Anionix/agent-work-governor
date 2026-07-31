#!/usr/bin/env bash
set -euo pipefail

# LLM-CONTRACT
# id: agent-work-governor.buck2-shadow-probe
# state: DECLARED_REPOSITORY_INPUTS -> FOCUSED_REGRESSION -> BYTE_STABLE_PASS | TEST_FAILURE
# preconditions: one explicit output path and the declared source tree are available
# invariant: the probe runs no authority or external side effect and writes only its output
# failure: unittest exits non-zero before a PASS artifact can be written
# source: https://docs.python.org/3/library/unittest.html
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: test_required_repository_controls_fail_closed
# test: bundle:tests/test_contracts.py

output="${1:?OUTPUT_REQUIRED}"
python3 -B -m unittest \
  tests.test_contracts.SourceHygieneTests.test_required_repository_controls_fail_closed \
  >/dev/null
printf '%s\n' \
  '{"authority":"none","classification":"CODE_OK","gate":"buck2-shadow-contract","status":"PASS"}' \
  >"$output"
