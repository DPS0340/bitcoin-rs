# Documentation

This tree is organised by where documents came from, not by who reads them.
This page maps it to what you might want.

## Start here

- [getting-started.md](getting-started.md) walks from a clone to a syncing
  node.
- [rest-interface.md](rest-interface.md) documents the optional Core-compatible
  REST gateway and enforcer integration.
- [../CONCEPTS.md](../CONCEPTS.md) is the project glossary. Read a term here
  before assuming it means what it means elsewhere in Bitcoin.
- [../README.md](../README.md) covers the defaults and the measured benchmark.

## Reference

- [policies/](policies/) holds the rules a change has to satisfy.
  [source-compatibility.md](policies/source-compatibility.md) covers the
  toolchain and dependency rules;
  [db-migration.md](policies/db-migration.md) covers on-disk schema changes.
- [benchmarks/](benchmarks/) holds the benchmark methodology in
  [end-to-end-sync.md](benchmarks/end-to-end-sync.md) and the raw run data
  under `data/`. Read the methodology before quoting any number: the results
  depend on CPU pinning and on whether the harness competes with the node.

## Explanation

[solutions/](solutions/) is the durable knowledge base: a problem that cost
real time, and what was concluded. Five areas, `architecture-patterns`,
`best-practices`, `logic-errors`, `performance`, and `performance-issues`.

Search it before debugging a recurring problem or designing in an area someone
has already touched. Several entries record approaches that were measured and
rejected, which is the cheapest kind of result to reuse.

## Internal working notes

These two are the project thinking aloud. They are kept because the reasoning
is useful, not because they describe current behaviour. Do not treat either as
a description of how the node works today.

- [plans/](plans/) holds design blueprints for multi-step campaigns, each dated
  and scoped to the work that prompted it.
- [brainstorms/](brainstorms/) holds exploratory requirements from before a
  direction was settled.

## Known gaps

**Do not run this on mainnet as your only node.** Sync now calls
`switch_to_branch` when a higher-work header branch wins. It preloads the
divergent bodies, revalidates the plan under one chain-transition guard, and
retires staged accounting after each committed connect. A fatal partial
transition stops the process.

Reorg handling still does not return disconnected transactions to the mempool.
That requires one production admission pipeline shared by Electrum, P2P relay,
and reorg handling. Production transaction relay is also incomplete. The ZMQ
`pubsequence` stream publishes block connect/disconnect events, but intentionally
does not emit mempool `A`/`R` events until mempool event sequencing is redesigned.

Also incomplete: metrics coverage and parts of the CLI and RPC surface.

On documentation itself: there is no API reference and no tutorial series.
JSON-RPC uses Bitcoin Core's method names, so Core's API documentation applies
to the shared surface; the authoritative list of what this node implements is
the dispatch table in `crates/rpc/src/handlers.rs`.
