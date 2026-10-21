# Test strategy

## Fast foundation checks

From the repository root, Python 3.11+:

```bash
python -m unittest discover -s tests/unit -v
python scripts/check-doc-links.py
python -m compileall -q mcp builder tests scripts
python tests/contract/test_task_dispatch.py
python scripts/validate-c2-capabilities.py
```

Foundation unit tests use only the standard library. They exercise board state
classification, priority order, unsafe title escaping, exclusions, pagination
inputs, malformed input, and conflicting states. Link validation checks local
Markdown document targets; external URLs and anchors require human review.

## Runtime checks

```bash
(cd teamserver && go build ./... && go test ./... -timeout 120s)
(cd client/cli && go mod tidy && go build ./...)
bash scripts/ci-pipeline.sh
```

Use the module's declared Go version and dependencies. The full pipeline also
requires native build tools and Python packages from mcp/requirements.txt,
pytest and pytest-timeout. Run in a disposable lab checkout. Review any module
changes made by `go mod tidy` before committing.

## Known coverage gaps at baseline 54eb735

- CI run 39434214859 fails teamserver auth tests, Windows compilation, Linux
  compilation, and integration tests. See RELEASE_READINESS.md.
- `go build ./...` does not produce the executable expected by the integration
  fixture. Issue #10 tracks lifecycle correction.
- `JagerTestSuite` in tests/integration/test_e2e.py uses a custom runner and is
  not collected as a pytest test class. Its existence is not pytest coverage.
- Tunnel tests contact a fixed listener without consuming the teamserver
  fixture; one imports a Python `pivot` module absent from this repo.
- The fixture may skip a missing binary or startup failure and may reuse an
  existing service. That is unsuitable evidence for release qualification.
- Compileall checks syntax, not successful imports or working tool dispatch.

Do not hide these failures behind skips or advertise the pipeline as passing.
Integration stabilization must use fresh temporary data, isolated ports,
authenticated management requests, startup diagnostics, unconditional cleanup,
and explicit failure when required services cannot start. Verify actual test
collection counts. A successful startup is not an end-to-end test.

## Evidence

Record commit SHA, OS/toolchain, exact command, collected/pass/fail/skip counts,
and relevant logs in each PR. Release validation must run against the exact
candidate commit and be repeated from a clean environment. Include denied auth,
role boundaries, persistence/restart, invalid input and teardown failure cases.
Platform-specific claims require platform-specific evidence.
