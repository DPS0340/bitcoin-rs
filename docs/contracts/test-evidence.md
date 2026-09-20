# Test evidence ownership

Tests protect an observable contract or an independently checked result.
A test that only restates a constructor, field layout, historical task plan,
lookup count, or private call order is not a permanent compatibility rule.
Performance claims require measured evidence, not a source-shape assertion.

## Retained proof owners

These are suite families, not a claim that every individual test has been
reviewed. Changes to a family must retain its independent reference and its
failure-path evidence. Tests may move with their owner without preserving an
old module layout.

| Owner | Contract and failure boundary | Disposition |
| --- | --- | --- |
| Primitives parsing, encoding, layout, arithmetic | Bitcoin wire identities, canonical bytes, malformed and truncated input; `P2P-01`, `VAL-02` | Keep independent golden/rust-bitcoin comparisons and rejection boundaries. Internal layout is not a public contract. |
| Script and consensus | `VAL-02`; Core vectors, signed-spend parity, witness and Merkle commitments, activation, missing coins and duplicate inputs | Keep. Remove lookup-count and parser-shape assertions when the same result has independent evidence. |
| Chain and UTXO | `RCV-01`..`RCV-11`; ancestry, branch selection, coin state, connect/disconnect and crash outcomes | Keep behavioral, differential and property tests. Do not replace corruption refusals with fixture round trips. |
| Storage and index | `IDX-01`..`IDX-08`, `FP-01`..`FP-04`, recovery; backend persistence, capability errors, cursor/reorg recovery | Keep. Backend and restart tests cannot be replaced by in-memory mocks. |
| Mempool | `MPL-01`..`MPL-04`, `POL-01`..`POL-06`; admission, replacement, dependencies, sequence, fencing and bounded orphans | Keep mutation and concurrency scenarios; reorg admission must use the same current-chain evaluator. |
| P2P | `P2P-01`..`P2P-04`; independent wire envelopes, live peer identity, budgets, body attribution, stalled requests and branch recovery | Keep. Assert peer-visible requests and eventual application, not incidental message ordering. |
| Mining | External miner/API clauses, coherent template generations and invalid candidates | Keep independently valid blocks and public submission behavior. |
| RPC | `API-*`, `WF-*`, `MRPC-*`; requests, errors, values, capability refusal and coherent views | Keep public-boundary and pinned Core comparisons. A method inventory is not a successful call. |
| Node and binary | `EMB-*`, `EVT-*`, recovery; public process startup, shutdown, persistence, reorg and observer ordering | Keep process and durability scenarios. A successful `--help` exit does not prove lifecycle behavior. |
| Cargo dependency/feature graph | `ARCH-01`, `DEP-*`, `FEAT-*` | Keep the metadata-based dependency-direction gate, feature builds and cargo-deny. Do not add a second uniqueness checker. |
| Reference custody | `REF-*`, `CORP-*`, `QAC-01`; artifact identity and unavailable inputs | Keep typed refusal cases and real process/corpus custody. Mutate parsed fields rather than matching historical TOML text. |
| Benchmark evidence | `HPA-*`; identities, overlap and repeated samples | Run evidence-tool tests with `--bench evidence`; measured campaigns remain separate. No frozen path/cell inventory in normal Cargo tests. |
| Formal models | `CONSTRAINTS.md` proof inventory | Run `scripts/check_models.py` in the manual lane. Custody checks and runner regressions are not model proofs. |

## Reviewed deletion and replacement

| Former test | Decision and replacement |
| --- | --- |
| `g18_hot_path_ledger` | Delete historical matrix/path/disposition gates. The declared benchmark ledger and actual campaign artifacts remain. |
| `overhaul_evidence` | Move identity, overlap and repetition checks to `crates/node/benches/evidence.rs`. Delete the all-cells-unmeasured assertion. |
| `g19_validation_default` | Delete the hardcoded promotion verdict and ad-hoc Cargo feature parser. `VAL-01` requires measured promotion evidence; feature builds remain. |
| `g20_unique_consensus_crates` | Delete the duplicate graph checker. Both dependency-range endpoints require `cargo deny check bans`. |
| `g20_formal_models` | Remove external Java/solver execution and source-text checks from Rust tests. Keep pinned models, hashes, properties, K=128 and explicit failure outcomes in the dedicated runner. |
| `cli_help` | Delete the exit-status-only smoke. Public process suites and actual CLI/config behavior remain. |
| Reference manifest value enumeration | Delete duplicated pin literals and comment-sensitive text edits. Keep artifact custody and typed malformed/unbound identity matrices. |
| `single_pass_shape_is_observable_and_second_decode_shape_is_not` | Delete. Golden facts, witness binding and independent identity parity remain. |
| Exact input lookup counters | Delete both the integration assertion and duplicate inline counting-view test. Keep multi-input verification, missing-coin and duplicate-input errors. |
| `prepared_facts_survive_source_record_replacement` | Delete: it dropped a view and re-parsed a transaction, never testing record replacement. It supplied no lifetime evidence. |
| `sighash_variants_match_reference_oracle` | Rename to the transaction-identity behavior it actually checks. Signed-spend/Core suites, not this fixture, own sighash evidence. |

## Evidence still required

The retained families above are not an exhaustive test-function audit. In
particular, a full contract-first reset still needs individual review of
node/P2P private-state assertions and a complete clause-to-scenario gap
check. This page does not mark that broader work complete.

A formal runner test uses a synthetic executable and cannot establish a
model property. A successful evidence-parser test cannot establish a
performance improvement. Missing Core binaries, corpora, model completions
or measured comparisons remain unavailable evidence, never implied passes.
