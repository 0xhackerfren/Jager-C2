# Management authentication contract

Specification for issue #13. This contract is a release requirement; passing
focused tests does not qualify other runtime components.

## Required behavior

- `/mgmt/ping` remains an unauthenticated reachability check.
- Other management requests fail with 403 if the server, API-key store, or RBAC
  manager is absent. An incomplete auth configuration must not authorize work.
- Missing, incorrect, and expired keys receive 401 and never reach the handler.
- A valid key authenticates through `X-Jager-C2-Api-Key` or `Authorization: Bearer`.
- Identity comes from the key's operator, ignoring caller-supplied operator headers.
- Permission checks require an authenticated operator and initialized manager.
  A viewer may list sessions but cannot perform an admin-only operation.
- Constructor failures in tests are fatal setup errors. Never discard a `New`
  error and then test a nil server as though it were initialized.
- Server fixtures use a separate temporary database/workspace/build directory,
  with cleanup registered after successful construction. Key persistence tests
  restore the environment on exit and never log generated secret values.

## Verification

From `teamserver/`:

```bash
go test ./internal/server -run 'TestAuthMiddleware|TestRequirePerm|TestEnsureMgmtAPIKey|TestAPIKeyStore' -count=1
go test ./... -timeout 120s -count=1
```

Run the complete suite twice from a clean checkout. Include the exact failing
baseline and passing candidate in the PR. Preserve denied-access assertions;
do not change expected 401/403 responses to accommodate setup failures.
