# AGENTS.md

This file defines how agents should work in this repository. It is not an
architecture specification or a second source of subsystem truth.

- Before changing a settled area, read `CONCEPTS.md`, the owning crate docs and
  source, relevant policies and tests, and the current issue/PR. Treat the
  closest authoritative owner as the source of truth rather than restating it
  here.
- Keep one clear current authority for each concept, invariant, and state
  transition. Do not duplicate architecture across `AGENTS.md`, `CONCEPTS.md`,
  solution notes, source comments, and tests just to make a local change easier.
- Preserve ownership boundaries. Change state and invariants through their
  existing owner instead of adding parallel state, shadow models, broad
  wrappers, or speculative abstractions. Add a new abstraction only for a
  concrete current consumer or contract.
- Prefer clean cutovers. When replacing an interface, state path, or data
  layout, remove the superseded path in the same change unless an explicit
  compatibility contract requires it.
- Tests should protect authoritative behavior and invariants, not reproduce the
  implementation in another place. Prefer regression cases at the boundary
  that owns the contract.
- Development experiments are disposable by default. Alternative A/B
  implementations, benchmark campaign outputs, profiler captures, temporary
  fixtures, migration/oracle scaffolding, review logs, and agent scratch should
  not become permanent repository state merely because they were useful during
  development.
- Keep only the winning production path after an experiment. Retain a benchmark
  or fixture on `main` only when it is intentionally maintained as a recurring
  performance, correctness, compatibility, or protocol contract.
- Put acceptance criteria in the issue or PR. Put execution proof and raw run
  evidence in CI logs/artifacts or the PR discussion. Keep local plans and
  scratch under ignored `.agent-tasks/`. Git history is the archive for
  superseded repository state.
- When durable knowledge changes, update its authoritative owner and remove or
  reconcile overlapping stale descriptions. Do not copy the new architecture
  into `AGENTS.md`.
