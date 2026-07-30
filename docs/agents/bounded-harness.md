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

Before any candidate starts, the harness self-tests an inherited OS network
boundary against trusted host-local canaries. Linux uses the catalog-pinned
Bubblewrap to expose only the Nix store and candidate workspaces, create
network/user/PID/IPC/UTS namespaces, disable nested user namespaces, and drop
every capability before becoming `nobody`. The trusted preflight's inherited,
architecture-bound seccomp filter permits Unix, IPv4, and IPv6 sockets.
Candidate filters permit Unix sockets only; VSOCK, packet, IPv4, IPv6,
alternate-ABI, and `io_uring` socket paths fail with `EPERM`. On macOS, the
trusted preflight uses a deny-default Seatbelt profile that permits only pinned
system/toolchain, repository, and runtime paths plus IPv4/IPv6 loopback.
Candidate checks use the same bounded file/process surface with no network
allow rules, so a host-local HTTP, SOCKS, or browser debug broker cannot relay
egress. A readiness pipe proves that Bubblewrap or Seatbelt entered the sandbox
before any check exit code can be evaluated. The trusted self-test requires
loopback success and denies host-interface TCP, IPv4-mapped IPv6, UDP/DNS
transport, and a host Unix socket from both the probe and its descendants.
When the host has routable native IPv6, it adds a reachable native canary;
route absence is never accepted as isolation proof. It also verifies the
platform-specific writable UID mapping; Linux exposes Cargo home read-only
except for its two required lock files. A missing mechanism, unsupported
policy, setup fault, or observed bypass returns a stable network-sandbox fault
with exit 70; the shadow workflow classifies it as inconclusive before
candidate execution.

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
- [Linux `CLONE_NEWNET` ABI](https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/linux/sched.h)
- [Linux seccomp ABI](https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/linux/seccomp.h)
- [Linux VSOCK namespace modes](https://www.kernel.org/doc/html/v7.1/admin-guide/sysctl/net.html#vsock-sockets)
- [Linux `IORING_OP_SOCKET` ABI](https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/linux/io_uring.h)
- [XNU socket-connect MAC hook](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac_socket.c#L147-L164)
- [Bubblewrap sandbox model](https://github.com/containers/bubblewrap/blob/1b80120ef26a28e065e67f89bfef873f13bdd317/README.md#sandboxing)
- Apple-shipped `sandbox-exec(1)` plus
  `/usr/share/sandbox/com.apple.CommCenter.sb` (`remote ip "localhost:*"`) and
  `/usr/share/sandbox/mds_stores.sb` (`file-read* (subpath ...)`)
