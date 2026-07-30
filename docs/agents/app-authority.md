# External App authority

`agent-work-governor / authoritative` reserves the future external authority
identity. Phase A is shadow-only: a validated result concludes `neutral`, while
every other result concludes `failure`. It must not be required by branch
protection. This prevents an ambiguous API write from admitting a merge before
the external reconciler exists.

## Bootstrap

Create a private GitHub App and install it only on this repository. Grant:

- Checks: read and write
- Contents: read
- Issues: read
- Pull requests: read

No candidate webhook handler is required. The protected-base
`pull_request_target` workflow obtains a short-lived installation token and
revokes it at job completion. The existing PR-body/Issue validator continues
to gate `governor / authority` in both modes; App configuration only adds the
reserved shadow check.

Store the numeric App ID as the repository variable
`AWG_AUTHORITY_APP_ID`. Store the private key as the repository secret
`AWG_AUTHORITY_APP_PRIVATE_KEY`. Never commit either the key or an installation
token. An absent pair skips only the shadow publisher; a partial pair fails
closed.

## Canary and cutover

Do not change branch protection until a real PR head has:

1. one completed `agent-work-governor / authoritative` check;
2. `conclusion: success`;
3. the configured App ID in `check_run.app.id`; and
4. an `external_id` bound to repository ID, PR number, and head SHA so workflow
   retries reuse the same check.

The publisher reads back every neutral or failed completion. Phase B must add
the external reconciler and a successful canary before success is enabled.

Update only `main`'s `required_status_checks` endpoint with `strict: true` and
one `checks` entry containing that exact context and App ID. Read the endpoint
back and require byte-for-byte equivalent values before considering cutover
complete.

Keep the current GitHub Actions checks required until that readback succeeds.
After cutover, remove the legacy `governor / validate` proof aggregator from
branch protection and give it a proof-only name. `shadow-fast / validate`
remains advisory evidence and is never consumed by the App validator.

## Closed failures

Missing App configuration, a wrong App ID, an ambiguous create/update, duplicate
external IDs, incomplete pagination, mutable candidate execution, or failed
post-write readback must not produce a successful authoritative check. Restore
the previously read branch-protection check set if cutover readback differs.

Primary sources:

- <https://docs.github.com/en/rest/checks/runs>
- <https://docs.github.com/en/rest/branches/branch-protection>
- <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app>
