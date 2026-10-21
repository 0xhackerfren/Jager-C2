# Local management lab

These commands describe the current startup interface. Full runtime validation
is pending the blockers in RELEASE_READINESS.md. Use a disposable local lab.

Run from the repository root with Go and a C compiler installed:

```bash
mkdir -p bin data
(cd teamserver && go build -o ../bin/jager-server ./cmd/jager-server)
./bin/jager-server --workspace "$PWD" --db data/jager.db \
  --grpc 127.0.0.1:31337 --mgmt 127.0.0.1:31338 --no-tls
```

`--no-tls` disables gRPC TLS for this loopback lab only. In another terminal,
from the same repository root:

```bash
curl --fail http://127.0.0.1:31338/mgmt/ping
```

Ping is intentionally unauthenticated. Its success shows reachability only.
Other management routes need the key from data/api-key.txt via
`X-Jager-C2-Api-Key` or a Bearer header. Never paste keys into issues or logs.
Stop with Ctrl-C. Preserve data only when needed; test backup/restore before
depending on it. Do not expose this development configuration publicly.

The Docker Compose deployment is experimental: authentication between MCP and
teamserver, TLS, runtime workspace contents, and persistence need a clean-install
validation. It is not currently a qualified one-command deployment.
