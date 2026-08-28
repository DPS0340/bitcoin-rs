# QA corpus contract (pointer)

Fuzz seed provenance is owned by
[fuzz/CORPUS_PROVENANCE.md](../../fuzz/CORPUS_PROVENANCE.md). That document
is the owner: it records the upstream corpus, the pinned commit, the
license, the per-target mapping, and the refresh rule. This page adds
nothing normative; it places the document under the
[contracts precedence rule](README.md).

- **Owner**: `fuzz/CORPUS_PROVENANCE.md` (seeds imported from
  rust-bitcoin/qa-assets, CC0-1.0, minimized with `cargo fuzz cmin`).
- **Scope**: seeds under `fuzz/corpus/` feeding the targets
  `fuzz/fuzz_targets/p2p_message.rs`, `block_decode.rs`, `tx_decode.rs`, and
  `script_eval.rs`; `script_eval` exercises the production interpreter.
- **Proven by**: the targets themselves — run
  `cargo fuzz run <target> -- -runs=10000` against the imported corpora
  (usage in [fuzz/README.md](../../fuzz/README.md)). The import and refresh
  path is `scripts/import-qa-assets.sh`; provenance rows must change in the
  same commit as any corpus re-import.
