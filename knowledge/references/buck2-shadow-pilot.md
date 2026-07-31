---
{
  "type": "Reference",
  "title": "Buck2 shadow fast-lane pilot",
  "description": "Reproducible benchmark for one non-authoritative repository-control probe.",
  "resource": "https://github.com/Anionix/agent-work-governor/issues/127",
  "tags": ["buck2", "benchmark", "shadow-fast"],
  "status": "draft",
  "generated": {"by": "agent-work-governor/0.1.0", "at": "2026-07-31T00:00:00+09:00"},
  "stale_after": "2026-08-31",
  "sources": [
    {
      "id": "buck2-release",
      "resource": "https://github.com/facebook/buck2/releases/tag/2026-07-15",
      "title": "Buck2 2026-07-15 release",
      "author": "facebook/buck2",
      "last_modified": "2026-07-15"
    },
    {
      "id": "buck2-isolation",
      "resource": "https://buck2.build/docs/concepts/isolation_dir/",
      "title": "Buck2 isolation directory",
      "author": "facebook/buck2"
    }
  ]
}
---
# Decision

Promote the pilot only as an opt-in shadow route. It does not replace Gradle,
the direct test, `authority-fast`, or reproducibility gates.

## Method

Runner: Darwin 27.0.0 arm64, macOS 27.0. Source identity: the final commit
containing this artifact; this result file is excluded from action inputs so it
can record those inputs without changing them. Release `2026-07-15` runs in
fixed isolation `awg-final2`. `flake.nix` binds the selected Nixpkgs package
URL and SHA-256 to the platform artifact in `toolchain.lock.json`.

```sh
/usr/bin/time -p bash scripts/buck2_shadow_probe.sh /tmp/awg-bound-direct.json
/usr/bin/time -p nix develop --no-update-lock-file --no-write-lock-file --command buck2 --isolation-dir awg-final2 build //:shadow_contract --show-output
nix develop --command buck2 --isolation-dir awg-final2 log summary --recent 3
nix develop --command buck2 --isolation-dir awg-final2 log critical-path --recent 3
nix develop --command buck2 --isolation-dir awg-final2 log show --recent 3
cmp -s /tmp/awg-bound-direct.json buck-out/awg-final2/art/root/*/__shadow_contract__/out/shadow-contract.json
du -sk buck-out/awg-final2
```

The timed Buck2 command ran once cold and three times warm. The other commands
collected raw event-log evidence and compared direct/Buck2 bytes.

## Result

| observation | value |
|---|---:|
| direct wall | 19.85 s |
| cold wall | 24.59 s |
| daemon startup | 0.180 s |
| warm wall | 2.79, 0.66, 0.68 s |
| warm median improvement | 96.6% |
| output SHA-256 | `b2a052ef8383b1b1fa8e6a542948c374666257ce2be1c21d0387bc5d30d43f9b` |
| cold critical path | 20.404009 s |
| Buck2 peak RSS | 217,907,200 bytes |
| disk growth | 0 to 22,052 KiB |

Cold analysis scheduled one local action with zero cached or remote actions.
Warm summaries reported zero analyzed targets and zero actions; the speedup is
long-lived daemon/DICE graph reuse, not a local or remote action-cache hit.

Cold regressed by 4.74 seconds, below the allowed five-second bound. The warm
median improved by 96.6%, above the required 20%. Output bytes were identical.
The system demo toolchain is intentionally non-hermetic, so this route remains
measurement-only and cannot produce authority evidence.
