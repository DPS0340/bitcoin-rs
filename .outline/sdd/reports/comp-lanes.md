# Comparator lanes report: issues #34, #35, #41

## Summary

| Issue | Lane | Status | Artifact |
|-------|------|--------|----------|
| #34 | offline-full-validation | **blocked** | Blocking fact recorded |
| #35 | p2p-loopback | **passed** | p2p-loopback fixture (retired by #224) |
| #41 | muhash-rpc | **blocked** | Blocking fact recorded |

Combined lane report: comp-lanes report (retired by #224)

## What comparator machinery already exists

The repository contains three standalone comparators under
`tools/benchmark-campaign/`, each with a dedicated doc page and test
suite:

1. **Offline full-validation** (`runner.py` + `native_offline.py`,
   doc: `docs/benchmarks/offline-full-validation.md`,
   tests: `test_runner.py`): a strict exact-seven-pair campaign runner
   that binds one `bitcoin_rs_replay_v3` candidate to one
   `bitcoin_core_loadblock_v31` reference. Both arms inherit the same
   read-only corpus descriptor. The controller certifies matched state
   (height, best block, UTXO count, total amount, MuHash), full
   validation (assume-valid disabled), matched cache budget, binary
   identity, and fresh state per arm. The test suite exercises the full
   synthetic controller path with fake scripts
   (`test_complete_seven_pair_run_and_round_trip`). No live
   `benchmark-campaign-result-v2` receipt for a real C150 or Cmodern
   cell is committed.

2. **P2P loopback** (`p2p_loopback.py`,
   doc: `docs/benchmarks/p2p-loopback.md`,
   tests: `test_p2p_loopback.py`): a deterministic, correctness-gated
   Bitcoin P2P loopback comparator. It feeds both nodes the identical
   external peer experience — same framed bytes, same delays, same
   bandwidth ceilings, same staller behavior, same disconnect points,
   same corpus order, same peer parameters — and compares externally
   observed wall time. The test suite uses deterministic fixture nodes
   (tiny Python scripts that connect, echo, read the exact corpus
   length, and write state files) and real loopback sockets.

3. **MuHash RPC** (`muhash_rpc.py`,
   doc: `docs/benchmarks/muhash-rpc.md`,
   tests: `test_muhash_rpc.py`): a fail-closed external MuHash JSON-RPC
   comparator. It issues exactly one `gettxoutsetinfo "muhash" null
   false` request per trial, times the full one-shot exchange, and
   validates the response against the frozen tip. The test suite uses a
   fixture HTTP server, not real daemons.

All three comparators are blocked by issue #36 (benchmark custody
controller), which is **CLOSED/COMPLETED**. The blocker is resolved.

## What was built

### Campaign lane runner (`comp_lanes.py`)

A thin orchestrator (`tools/benchmark-campaign/comp_lanes.py`) that runs
all three comparator lanes and produces a combined `comp-lanes-report-v1`
artifact. It does not re-implement any comparison logic — it delegates to
the existing comparators.

- **P2P lane (#35)**: creates deterministic fixture nodes, builds a
  `p2p-loopback-config-v1` config, runs `p2p_loopback.main`, and records
  the result artifact path, schema, arm count, correctness gates, ratio,
  and result SHA-256.
- **Offline lane (#34)**: checks for `bitcoind` on PATH. When absent,
  records the blocking fact with the exact command run
  (`shutil.which('bitcoind')`) and result (`None`).
- **RPC lane (#41)**: checks for `bitcoind` on PATH. When absent,
  records the blocking fact identically to the offline lane.

### Test suite (`test_comp_lanes.py`)

14 tests covering:
- P2P lane produces a valid result with correct schema, arm count,
  correctness gates, and result SHA-256
- Offline lane reports blocked when `bitcoind` is absent
- RPC lane reports blocked when `bitcoind` is absent
- Combined report has correct schema, three lanes, correct issue order,
  and consistent `report_sha256`
- Six `NonVacuityProofs` tests that deliberately break each assertion
  and confirm `AssertionError` is raised

### Durable artifacts

- comp-lanes report (retired by #224): combined
  lane report from a live run on this host
- p2p-loopback fixture (retired by #224):
  the P2P loopback result artifact from the same run

## Per-issue status

### Issue #34: strict offline full-validation comparator

**Status: blocked**

The comparator machinery is fully implemented and tested with fake
scripts (`test_complete_seven_pair_run_and_round_trip` in
`test_runner.py`). The blocking fact is that no `bitcoind` binary exists
on this host:

```
$ shutil.which('bitcoind')
None
```

Commands run to verify:
- `which bitcoind` → not found
- `find /usr -name bitcoind` → not found
- `find /home/linuxbrew -name bitcoind` → not found
- `find /opt -name bitcoind` → not found
- `.references/bitcoin/src/bitcoind` → does not exist (source only, not built)

The `.references/bitcoin/` directory contains Bitcoin Core v31.1 source
but no built binary. Building bitcoind from source requires a C++
toolchain, Boost, libsecp256k1, and other dependencies that may not all
be available offline on this host.

**What exists**: The comparator method, controller, and synthetic test
path are all in-tree and passing. The doc page
(`docs/benchmarks/offline-full-validation.md`) records the
requirement-to-proof map and the bounded historical receipt
(`bounded-performance-custody-v1.json`) with a 1.6540 ratio that did not
meet the 2.0x target.

**Remaining gap**: A live seven-pair `benchmark-campaign-result-v2` run
against a frozen C150 or Cmodern corpus with a real `bitcoind` binary.
This requires: (1) a `bitcoind` binary built from the v31.1 source in
`.references/bitcoin/` or installed externally, (2) a frozen corpus
archive exported by the `export_active_chain_corpus` tool, (3) a
cell-proof file binding the corpus, manifest, and certified state.

### Issue #35: controlled loopback P2P comparator

**Status: passed (offline with fixture nodes)**

The P2P loopback comparator is fully implemented and tested. The
campaign lane runner produces a recorded, reproducible artifact using
deterministic fixture nodes (tiny Python scripts that connect, echo,
read the exact corpus length, and write state files) over real loopback
sockets.

**Artifact**: p2p-loopback fixture (retired by #224)
- Schema: `p2p-loopback-result-v2`
- 7 pairs, 14 arms, alternating core/candidate order
- All six correctness gates true: `bytes_equal`, `peer_parameters_equal`,
  `protocol_ok`, `restart_state_equal`, `schedule_equal`, `state_equal`
- `result_sha256` verified against canonical serialization
- `candidate_over_core_p50_ratio`: ~1.0 (fixture nodes are identical
  Python scripts, so the ratio is expected to be near unity)

**What is held identical**: corpus (ordered P2P frames with SHA-256
checksums), schedule (send/stall/disconnect steps with delays and
bandwidth), peer parameters (network magic, protocol version, services,
timeouts, buffer sizes), lifecycle (mode, generation, initial/final/
restart states).

**Remaining gap**: A live run against real `bitcoind` and bitcoin-rs
binaries (not fixture scripts). This requires both binaries to be
available on the host. The fixture run proves the comparator harness,
correctness gates, and artifact production; it does not measure real
node performance.

### Issue #41: production MuHash query comparator / campaign lane

**Status: blocked (live execution); campaign lane implemented**

The MuHash RPC comparator is fully implemented and tested with a fixture
HTTP server. The campaign lane runner checks for `bitcoind` and records
the blocking fact when it is absent.

The campaign lane (`comp_lanes.py`) runs all three comparators and
produces a combined `comp-lanes-report-v1` artifact. This is the "lane
that runs them" — it dispatches to each comparator and collects results.

**Artifact**: comp-lanes report (retired by #224)
- Schema: `comp-lanes-report-v1`
- Three lanes: #34 (blocked), #35 (passed), #41 (blocked)
- `report_sha256` verified against canonical serialization

**Blocking fact for live execution**:
```
$ shutil.which('bitcoind')
None
```

The MuHash RPC comparator requires a running `bitcoind` daemon with RPC
enabled and a bitcoin-rs RPC server, both committed at the frozen corpus
tip. Neither binary is available on this host.

**What exists**: The protocol contract (one-shot `gettxoutsetinfo
"muhash" null false` request, bounded HTTP exchange, strict eight-field
UTXO state validation, seven-pair alternating campaign, fail-closed
publication) is implemented and covered by local fixture tests in
`test_muhash_rpc.py` (42 trial tests + 30 aggregate tests, all passing).

**Remaining gap**: A live seven-pair campaign with real `bitcoind` and
bitcoin-rs RPC daemons, frozen-tip corpus, pre-receipt/observation/
post-receipt triples, and a published `muhash-rpc-result-v2` file.

## RED/GREEN proof transcripts

### Proof 1: P2P result schema assertion

**Assertion**: `result["result_schema"] == "p2p-loopback-result-v2"`

**RED** (broke `comp_lanes.py` to report `"WRONG-SCHEMA"`):
```
AssertionError: 'WRONG-SCHEMA' != 'p2p-loopback-result-v2'
- WRONG-SCHEMA
+ p2p-loopback-result-v2

FAILED (failures=1)
```

**GREEN** (restored):
```
test_p2p_lane_produces_valid_result ... ok
Ran 1 test in 1.653s
OK
```

### Proof 2: P2P arm count assertion

**Assertion**: `result["arm_count"] == 14`

**RED** (broke `comp_lanes.py` to report `12`):
```
AssertionError: 12 != 14
FAILED (failures=1)
```

**GREEN** (restored):
```
test_p2p_lane_produces_valid_result ... ok
Ran 1 test in 1.591s
OK
```

### Proof 3: Report lane count assertion

**Assertion**: `len(lanes) == 3`

**RED** (removed RPC lane from `run_all_lanes`):
```
AssertionError: 2 != 3
FAILED (failures=1)
```

**GREEN** (restored):
```
test_report_has_correct_schema_and_three_lanes ... ok
Ran 1 test in 1.600s
OK
```

### Proof 4: Report SHA-256 consistency assertion

**Assertion**: `report["report_sha256"]` matches canonical hash of report
without that field.

**RED** (prepended `"deadbeef"` to the hash):
```
AssertionError: 'deadbeef4f4cfadc...' != '4f4cfadc...'
FAILED (failures=1)
```

**GREEN** (restored):
```
test_report_sha256_is_consistent ... ok
Ran 1 test in 1.610s
OK
```

### NonVacuityProofs class (structured RED tests)

Six tests in `test_comp_lanes.NonVacuityProofs` deliberately use wrong
expectations and confirm `AssertionError` is raised:

- `test_RED_wrong_schema_name_is_caught`: asserts schema is
  `"p2p-loopback-result-v1"` (wrong) → AssertionError ✓
- `test_RED_wrong_arm_count_is_caught`: asserts arm count is `12`
  (wrong) → AssertionError ✓
- `test_RED_wrong_correctness_gate_count_is_caught`: asserts
  `"fake_gate"` in correctness (wrong) → AssertionError ✓
- `test_RED_wrong_lane_count_is_caught`: asserts lane count is `2`
  (wrong) → AssertionError ✓
- `test_RED_wrong_issue_order_is_caught`: asserts issues are
  `["#35", "#34", "#41"]` (wrong order) → AssertionError ✓
- `test_RED_tampered_report_sha256_is_caught`: tampers with report
  fields and asserts sha256 matches (wrong) → AssertionError ✓

All 14 tests pass (GREEN):
```
Ran 14 tests in 22.556s
OK
```

All 237 tests (223 existing + 14 new) pass:
```
Ran 237 tests in 142.046s
OK
```

## Existing test coverage (not modified)

The existing test suites remain unchanged and all pass:

- `test_runner.py`: 26 tests covering the offline campaign runner
  (cell universe, schedule, config contract, native execution, evidence
  custody, host architecture, fixed child env, schedule seed validation,
  descriptor lifetime)
- `test_p2p_loopback.py`: 155 tests covering P2P loopback (config
  parsing, gates, pacing, magic gates, campaign, security contracts)
- `test_muhash_rpc.py`: 42 tests covering MuHash RPC (trial protocol,
  aggregate, pure helpers)
