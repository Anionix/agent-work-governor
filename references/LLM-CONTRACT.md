# LLM-CONTRACT
# id: agent-work-governor.ask-matt-reference-lock
# state: ADVISORY_SOURCE -> IMMUTABLE_REVISION -> VERIFIED_INPUT | STALE_INPUT
# preconditions: the lock names the reviewed ask-matt revision and expected digest
# invariant: mutable or digest-mismatched advisory input never becomes authoritative
# failure: report ask_matt_source_lock as failed
# source: repo:references/ask-matt.lock.json
# knowledge: repo:knowledge/references/ask-matt.md
# enforced_by: audit
# test: repo:tests/test_contracts.py

# LLM-CONTRACT
# id: agent-work-governor.canonical-runtime-reference-lock
# state: PYYAML_SOURCE -> DETERMINISTIC_ARCHIVE -> VERIFIED_RUNTIME | CLOSED_BLOCKER
# preconditions: the lock binds the PyPI source artifact and packaged pure-Python bytes
# invariant: missing, symlinked, or digest-mismatched runtime bytes never enter sys.path
# failure: report a typed canonical validator runtime blocker before validator execution
# source: repo:references/canonical-runtime.lock.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: load_runtime
# test: repo:tests/test_contracts.py

# LLM-CONTRACT
# id: agent-work-governor.canonical-validator-reference-lock
# state: VALIDATOR_SOURCE -> IMMUTABLE_REVISION -> VERIFIED_VALIDATOR | STALE_INPUT
# preconditions: each validator lock names an immutable source URL and SHA-256 digest
# invariant: missing or digest-mismatched validator bytes never execute
# failure: canonical validation returns a non-zero process status
# source: repo:references/canonical-validators.lock.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: load_lock
# test: repo:tests/test_contracts.py

# LLM-CONTRACT
# id: agent-work-governor.code-review-reference-lock
# state: REVIEW_SKILL -> IMMUTABLE_DIGEST -> TRUSTED_ATTESTER | UNTRUSTED_ATTESTER
# preconditions: the lock binds the reviewed code-review Skill digest
# invariant: self-attested or digest-mismatched review evidence never authorizes a PR
# failure: report CODE_REVIEW_ATTESTATION_UNTRUSTED
# source: repo:references/code-review.lock.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: validate_pre_pr_receipt
# test: repo:tests/test_contracts.py

# LLM-CONTRACT
# id: agent-work-governor.okf-reference-lock
# state: OKF_SOURCE -> IMMUTABLE_REVISION -> VERIFIED_POLICY_INPUT | STALE_INPUT
# preconditions: the lock names the reviewed OKF v0.2 revision and expected digest
# invariant: stale or digest-mismatched OKF evidence never becomes policy authority
# failure: OKF validation returns a non-zero process status
# source: repo:references/okf-v0.2.lock.json
# knowledge: repo:knowledge/references/okf-v0.2.md
# enforced_by: validate_okf
# test: repo:tests/test_contracts.py

The verification paths are `audit`, `load_lock`, `load_runtime`,
`validate_pre_pr_receipt`, and `validate_okf`.
