# Documentation index

Jager-C2 is currently a development preview. Existing version headings in the
changelog are history, not evidence of release qualification.

| Document | Purpose |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Component boundaries and source locations |
| [Operator guide](OPERATOR_GUIDE.md) | Existing interfaces; consult limitations before use |
| [Development process](DEVELOPMENT.md) | Docs → tests → code; issue and review gates |
| [Management authentication](management-authentication.md) | Required authentication and fixture behavior |
| [Testing](TESTING.md) | Test commands, coverage gaps, evidence requirements |
| [Release readiness](RELEASE_READINESS.md) | Launch blockers and release checklist |
| [Local lab](LOCAL_LAB.md) | Loopback-only management startup and health check |
| [Decisions](decisions/0001-docs-tests-code.md) | Why the workflow and board work this way |

The [issue Kanban](https://github.com/0xhackerfren/Jager-C2/issues/12) is the
accessible workflow dashboard. The existing GitHub Projects board remains
linked in the repository; its permissions and automation have not been verified.

Documentation ownership follows the affected component. Every behavior-changing
PR updates the relevant reference and release notes. Specifications must label
proposed behavior explicitly; a specification does not establish support.
