# Bounded harness isolation

`bounded_harness.py` treats every planned check as candidate code. The harness
must run as root and always resolves the operating system's fixed `nobody`
account for those checks. Arbitrary UID/GID input is not accepted. It refuses
execution when that privilege boundary is absent or when `nobody` resolves to
the `sudo` caller. Do not use the GitHub runner account: hosted runner accounts
may have passwordless `sudo`.

The subject snapshot and trusted Governor bundle remain root-owned and
read-only. The harness rejects symlinks, special files, and every source path
writable by `nobody` through either mode bits or effective ACL access; it also
bounds the tree walk. Cargo, uv, pip, Ruff, XDG, home, and temporary state are
redirected into the candidate-owned artifacts directory. Candidate processes
receive an explicit toolchain/locale environment allowlist rather than the root
environment.

The runtime root must be a new direct child of a root-owned sticky directory,
such as `/tmp` on Linux or `/private/tmp` on macOS. The harness owns the root,
receipt, and evidence directories. Only the artifacts directory is transferred
to the candidate identity.

Every check starts in a new session with supplementary groups removed. The
harness kills that process group after success, timeout, cancellation, or
output overflow. A descendant can create a new session, so process-group
termination alone is not the security boundary. Distinct UID ownership ensures
that such a survivor cannot replace receipt or evidence bytes; an ephemeral
runner must still tear down any survivor after the job.

Example, with a trusted harness checkout:

```bash
runtime="/tmp/agent-work-governor-$RANDOM-$RANDOM"
sudo chown -R 0:0 subject
sudo chmod -R a+rX,a-w subject
sudo python scripts/bounded_harness.py \
  --plan-report plan.json \
  --expected-plan-sha256 "$plan_sha256" \
  --repository subject \
  --invocation-sha256 "$invocation_sha256" \
  --runtime-root "$runtime" \
  --receipt "$runtime/run.json"
```

Primary sources:

- [CPython subprocess credential controls](https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/subprocess.rst)
- [POSIX `setuid()` semantics, Issue 8](https://pubs.opengroup.org/onlinepubs/9799919799/functions/setuid.html)
- [GitHub-hosted runner administrative privileges](https://github.com/github/docs/blob/ee27de73e024106c5cf1f3938cf00bb477252862/content/actions/reference/runners/github-hosted-runners.md)
