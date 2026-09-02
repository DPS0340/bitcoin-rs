# Current Datadir Format Policy

`bitcoin-rs` supports exactly one persistent datadir format. It does not
migrate, translate, or silently recover incompatible state from an older
release. Persistent state can be rebuilt from the Bitcoin network, so a schema
change requires an explicit operator resync.

## Datadir schema marker

Every node datadir contains a small `CURRENT_SCHEMA` identity record. Its
current schema epoch is `1`; the canonical record binds the datadir to the
resolved consensus network, genesis hash, effective P2P magic, and selected
storage backend. The marker is written and synced before any checkpoint or KV
store opens. Its file contents are synced everywhere; the containing directory
is synced on platforms that expose a reliable directory-sync primitive.

Startup follows this contract:

| Datadir state | Startup action |
| --- | --- |
| Empty directory | Create and sync the current `CURRENT_SCHEMA` identity, then initialize the current schema |
| `CURRENT_SCHEMA` matches the current epoch and configured identity | Continue startup |
| `CURRENT_SCHEMA` identity differs from configuration | Fail as a configuration error; use the matching network/backend or another datadir |
| Marker is missing from a non-empty directory | Fail before opening persistent state |
| Marker is malformed or has another epoch | Fail before opening persistent state |
| Current marker but no checkpoint root | Start cold; this is normal before the first clean checkpoint |
| Checkpoint root exists but `CURRENT` is absent | Start cold; unpublished generations and temp files are not committed state |
| `CURRENT` points to an incompatible or corrupt generation | Fail with an explicit remove/recreate/resync instruction |

The node never deletes user data automatically. Schema incompatibility and
unrecoverable current-checkpoint corruption tell the operator to remove or
replace the datadir and restart for a full resync. A configuration identity
mismatch instead tells the operator to use matching settings or another
datadir. A future breaking change increments the single epoch and provides no
conversion path.

`CURRENT` is the only checkpoint commit point. A writer first writes and syncs
all generation artifacts, then atomically publishes `CURRENT`. A crash before
that publication can leave generation or temp residue, but the loader ignores
it: an existing `CURRENT` restores its referenced generation, while no
`CURRENT` means that no checkpoint is committed and startup is `Cold`.

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
   automatic `HeadersOnly` fallback for existing state. `Cold` is only the
   result of no committed checkpoint, including an unpublished first write.
4. Keep current-format integrity and corruption tests.
5. Document that operators must remove or quarantine the datadir and resync.

The `Cold` path is for a datadir with the current marker and no committed
checkpoint. It is also the recovery result for a checkpoint root containing
only unpublished residue. It is not a compatibility mode for an old schema or
for a `CURRENT` that points to invalid state.
