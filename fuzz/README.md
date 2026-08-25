# Fuzz Targets

Five `cargo-fuzz` harnesses covering the untrusted-input surfaces of
bitcoin-rs: P2P wire messages, block/transaction deserialization, script
evaluation, and UTXO snapshot loading.

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running a target

From the repository root:

```sh
cargo +nightly fuzz run p2p_message
```

Replace `p2p_message` with any of:

| Target          | Surface                                              |
|-----------------|------------------------------------------------------|
| `p2p_message`   | P2P wire message decoder (`read_message`)            |
| `block_decode`  | Block consensus deserialization                      |
| `tx_decode`     | Transaction consensus deserialization                |
| `script_eval`   | Portable script interpreter (`Interpreter::execute`) |
| `utxo_snapshot` | UTXO snapshot deserializer (`read_snapshot_strict_v4`)     |

To limit the number of iterations:

```sh
cargo +nightly fuzz run p2p_message -- -max_total_time=60
```

## Adding a corpus

Each target has a seed corpus directory at `fuzz/corpus/<target>/`. Create it
and add seed files (one file per input):

```sh
mkdir -p fuzz/corpus/p2p_message
# Add binary seed files, e.g. a captured wire message:
cp some_block_message.bin fuzz/corpus/p2p_message/
```

To merge new coverage finds into the corpus:

```sh
cargo +nightly fuzz run p2p_message -- -merge=1 fuzz/corpus/p2p_message
```

## Reproducing a crash

When a target finds a crash, `cargo-fuzz` writes the crashing input to
`fuzz/artifacts/<target>/`. Reproduce it with:

```sh
cargo +nightly fuzz run p2p_message -- fuzz/artifacts/p2p_message/crash-<hash>
```

Or reproduce directly without `cargo-fuzz` by building the target and feeding
the crash file on stdin (the `libfuzzer_sys` harness reads one file argument):

```sh
cargo +nightly run --manifest-path fuzz/Cargo.toml --bin p2p_message \
  -- fuzz/artifacts/p2p_message/crash-<hash>
```

`--manifest-path` is required. `fuzz/` declares its own workspace, so run from
the repository root without it Cargo selects the root workspace, whose metadata
exposes only the `bitcoin-rs` binary, and the command fails with `no bin target
named p2p_message` before it reads the artifact.

To get a full backtrace, set `RUST_BACKTRACE=1`:

```sh
RUST_BACKTRACE=1 cargo +nightly fuzz run p2p_message -- fuzz/artifacts/p2p_message/crash-<hash>
```
