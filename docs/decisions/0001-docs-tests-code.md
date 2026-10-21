# ADR 0001: Docs, then tests, then code

Status: accepted for development infrastructure. Date: 2026-10-20.

## Context

The platform has broad capability claims while current CI fails. Existing
documentation and issues provide a starting point but do not prove reliability.
The Projects board cannot be verified through the current connection.

## Decision

Specify scope and acceptance first, record failing behavioral tests second,
implement third. Keep those stages visible as ordered commits in one focused PR.
Use repository issues as work items with exclusive status labels and a generated
issue dashboard. Retain the existing Projects link without claiming it works.
Keep runtime CI failures visible while adding separate infrastructure checks.

## Consequences

The board can run with repository-scoped Actions permissions and no personal
token. It is an issue dashboard, not a drag-and-drop Projects replacement.
Templates guide review but cannot prove test-first chronology automatically;
reviewers inspect evidence. Documentation and runtime claims remain separate.
Native Projects synchronization can be added once its access is verified.
