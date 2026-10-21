# Development process

## Delivery order

1. **Docs:** open an issue describing the problem, scope, non-goals, affected
   interfaces, failure behavior, measurable acceptance criteria, and test plan.
   Commit a specification or relevant documentation changes first.
2. **Tests:** add the smallest meaningful regression tests. Record the command,
   failing assertion, and why it fails before implementation. For existing
   behavior, reproduce the bug rather than replacing the test with a weaker one.
3. **Code:** implement the specified behavior and refactor while keeping the
   tests green. Record passing results and unresolved limitations in the PR.

Prefer separate commits in that order within one focused PR. Docs-only changes
need link/content validation, not artificial runtime tests. Refactors need
existing regression evidence. Explain exceptions in the PR. Tests must be
deterministic and pass twice from a clean checkout per AGENTS.md.

## Kanban

Use [dashboard issue #12](https://github.com/0xhackerfren/Jager-C2/issues/12).
Issue labels are the source of truth; the dashboard is a generated view.

| Column | Label | Entry requirement |
| --- | --- | --- |
| Backlog | `status/backlog` or no status | Problem accepted; scope may need work |
| Ready | `status/ready` | Spec, acceptance criteria, test plan and dependencies recorded |
| In Progress | `status/in-progress` | One owner; WIP limit one issue per contributor |
| In Review | `status/in-review` | PR linked, red/green evidence recorded; failures disclosed |
| Done | Closed issue | Accepted change merged, required checks passed |

Apply exactly one status label to open work. Moving a card means replacing its
status label. Closed issues appear in Done regardless of old status labels.
Add `blocked` when necessary and name the dependency in the issue; keep the
status showing the actual stage. The dashboard flags conflicting status labels
and multiple In Progress assignments for the same owner. It does not infer that
an open PR has passed CI or that a closed issue was successfully delivered.

Priority uses existing `priority/p1` (release blocker), `priority/p2` (next),
`priority/p3` (later); area labels remain those in AGENTS.md. Keep unrelated
capability expansion out of the stabilization release.

The board workflow bootstraps status labels and refreshes the dashboard on issue
creation, label changes, closure/reopening, and manual dispatch. Editing a title,
body, or assignee alone requires manual dispatch. Until the workflow is merged
to the default branch, the dashboard is a manually refreshed setup snapshot.
No Projects token or new persistent credential is required.

## Review and release

Branch from main; reference the issue; avoid direct pushes to main. Use the PR
template. A reviewer checks documentation truth, failure cases, test evidence,
compatibility, and security impact. Do not merge with failing required checks.
Configure branch rules to require CI and Foundation checks after both are
verified; branch protection is an account setting, not enforced by this doc.

Only move to Done after merge and verification. Close rejected work with an
explicit reason. Use RELEASE_READINESS.md for launch decisions and TESTING.md
for commands. A green Foundation check validates development infrastructure;
it does not qualify the platform runtime for release.
