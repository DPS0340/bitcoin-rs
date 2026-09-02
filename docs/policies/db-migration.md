# Current Datadir Format Policy

`bitcoin-rs` supports exactly one persistent datadir format. It does not
migrate, translate, or silently recover incompatible state from an older
release. Persistent state can be rebuilt from the Bitcoin network, so a schema
change requires an explicit operator resync.

## Datadir schema marker

Every node datadir contains a small, durable `CURRENT_SCHEMA` file. The current
epoch is `1`, encoded as the exact bytes `1\n`.

Startup follows this contract:

| Datadir state | Startup action |
| --- | --- |
| Empty directory | Create and sync `CURRENT_SCHEMA`, then initialize the current schema |
| `CURRENT_SCHEMA` contains the current epoch | Continue startup |
| Marker is missing from a non-empty directory | Fail before opening persistent state |
| Marker is malformed or has another epoch | Fail before opening persistent state |
| Current marker but no checkpoint root | Start cold; this is normal before the first clean checkpoint |
| Checkpoint root exists but is missing, incompatible, or corrupt | Fail with an explicit remove/recreate/resync instruction |

The node never deletes user data automatically. The failure message tells the
operator to remove or replace the datadir and restart for a full resync. A
future breaking change increments the single epoch and provides no conversion
path.

## Current persisted formats

The marker covers all persistent surfaces in the datadir:

- KV chainstate and optional transaction-index stores use the current backend
  layout and have no historical translation layer.
- Flat block files use the current `BRSB` record format.
- UTXO checkpoints use only `utxo-v4.dat` and the strict v4 reader.
- Chainstate checkpoints use the current `CURRENT`, generation, manifest,
  headers, UTXO, and CoinStats artifacts. Manifest fields and component
  versions are required; absent historical fields are not defaulted.
- Undo records use only the current undo codec.

Current readers still validate magic values, versions, filenames, lengths,
hashes, checksums, ancestry, tips, and semantic invariants. Those checks detect
corruption in the current format; they are not compatibility or migration
machinery.

## Schema changes

A change is breaking when a current binary cannot parse or safely interpret
bytes written by another version. This includes column-family names or
discriminants, key/value layouts, block-file records, UTXO snapshot records,
checkpoint artifacts, and undo records.

For every breaking change:

1. Increment the datadir schema epoch.
2. Keep one current writer and one current reader.
3. Do not add an in-place converter, legacy reader, compatibility adapter, or
   automatic `HeadersOnly`/`Cold` fallback for existing state.
4. Keep current-format integrity and corruption tests.
5. Document that operators must remove or quarantine the datadir and resync.

The `Cold` path is only for a genuinely new datadir with the current marker and
no checkpoint root. It is not a recovery mode for an existing incompatible
datadir.
