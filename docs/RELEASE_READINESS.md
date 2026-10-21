# Public preview release readiness

Status: **not qualified for operational release**. Baseline: `54eb735`.
Audit date: 2026-10-20 (America/New_York).

The repository is already public. This checklist governs promoting a reliable
preview and its marketing claims; it is not a claim of production readiness.

## Launch blockers

Evidence: [CI run 39434214859](https://github.com/0xhackerfren/Jager-C2/actions/runs/39434214859).

| Work | Observed gap | Release acceptance |
| --- | --- | --- |
| Teamserver authentication | Five auth tests fail; nil pointer panic in permission test | Isolated auth fixtures; missing/invalid keys denied, correct role permissions; full Go suite passes |
| Build reproducibility | Windows result-structure compile errors; Linux curl header not found | Clean documented builds pass on supported platforms; dependency provenance recorded |
| Integration harness (#10) | No persisted server binary, uncollected custom suite, unmanaged listener and missing Python import | Required tests collected, isolated authenticated lifecycle, failures block CI |
| CLI truth (#3) | List commands print empty tables; task shell/upload/download only print messages | Stubs explicitly excluded from support; every promoted command has a behavioral test |
| Dependency/tool truth (#1, #2, #4) | Missing shared libraries and placeholder tools | Supported surface explicitly enumerated; no placeholder advertised as complete |
| Deployment | Default Docker guide implies ready deployment; MCP API key not wired in Compose | Clean install, auth, TLS, persistence, backup/restore and teardown demonstrated |
| Evidence guide (#9) | Retrieval and retention not fully documented | Storage, access, export and cleanup verified and documented |
| Board/process (#11) | Existing Projects access unverified | Accessible issue dashboard, issue ownership and docs/tests/code review evidence |

Maintainer owns release sign-off. Each implementation issue must name an owner
before moving to In Progress. Assigning an issue is not acceptance evidence.

## Scope of the first reliable preview

Stabilize existing management, authentication, documentation, CI and development
infrastructure. Separate Windows and Linux support claims. Keep experimental
modules labeled as such. Ship a small verified surface before expanding it.

## Release checklist

- [ ] All launch blockers resolved or explicitly removed from the advertised scope.
- [ ] CI and Foundation checks green on the exact release candidate; required checks configured.
- [ ] No required check skipped; actual integration collection reviewed.
- [ ] Clean-clone setup verified by someone following the docs verbatim.
- [ ] Supported platform matrix includes toolchains and validation evidence.
- [ ] API/CLI/MCP references distinguish tested, experimental and unavailable behavior.
- [ ] Authentication and role-boundary regression suites pass.
- [ ] TLS configuration, access restrictions, backup/restore and teardown tested.
- [ ] Dependency provenance/license inventory and secret scanning reviewed.
- [ ] Changelog, known limitations, install instructions and rollback instructions match the candidate.
- [ ] Candidate tag and release notes identify preview status and exact commit.
- [ ] Website claims match the verified support matrix; maintainer records go/no-go.

## Marketing claims

Safe current description: “An open-source development preview exploring an
MCP interface for authorized red team workflows.” Do not claim complete tool
coverage, production hardening, reliable cross-platform operation, or validated
end-to-end automation before recording corresponding evidence.

Existing 1.0.x changelog headings do not override these acceptance gates.
