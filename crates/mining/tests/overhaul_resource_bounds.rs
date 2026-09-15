//! CL-14 evidence for the mempool surfaces changed by #639.
//!
//! Raw admitted-graph fixtures isolate graph costs; signed input validity is
//! covered by `overhaul_process_harness`. RSS is process `VmHWM`, and retained
//! bytes are the pool's capacity-based estimate. A vsize limit is not an RSS
//! limit. These samples do not certify unrelated resources or performance.

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_mempool::{
    AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolEntry, MempoolGateway,
    MempoolLimits, ReplacementCandidate,
};
use bitcoin_rs_mining::{CandidateContext, assemble_candidate};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness,
};
use parking_lot::RwLock;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const CLUSTERS: u32 = 100;
const MEMBERS: u32 = 64;

struct Fixture {
    gateway: MempoolGateway,
    roots: Vec<OutPoint>,
    tips: Vec<(OutPoint, u64)>,
}

fn transaction(previous_output: OutPoint, value: u64, script: &[u8]) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(script.to_vec()),
        }],
    }
}

fn fixture(members: u32) -> TestResult<Fixture> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut roots = Vec::new();
    let mut tips = Vec::new();
    for cluster in 0..CLUSTERS {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&(cluster + 1).to_le_bytes());
        let mut input = OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0);
        roots.push(input);
        let mut value = 1_000_000_u64;
        for depth in 0..members {
            let fee = u64::from(depth % 7 + 1) * 1_000;
            value = value.checked_sub(fee).ok_or("fixture funding exhausted")?;
            let tx = Arc::new(transaction(input, value, &[0x51]));
            input = OutPoint::new(tx.txid(), 0);
            let vsize = u32::try_from(tx.vsize())?;
            pool.insert_entry(MempoolEntry::new(tx, vsize, fee, 1, 1))?;
        }
        tips.push((input, value));
    }
    assert_eq!(pool.limits.cluster_count, MEMBERS);
    assert_eq!(pool.limits.max_replacement_clusters, CLUSTERS);
    assert_eq!(pool.tx_count(), usize::try_from(CLUSTERS * members)?);
    Ok(Fixture {
        gateway: MempoolGateway::new(Arc::new(RwLock::new(pool)), None),
        roots,
        tips,
    })
}

fn rss_kib(field: &str) -> TestResult<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let row = status
        .lines()
        .find(|line| line.starts_with(field))
        .ok_or("missing Linux RSS field")?;
    Ok(row
        .split_whitespace()
        .nth(1)
        .ok_or("missing RSS value")?
        .parse()?)
}

fn sample(gateway: &MempoolGateway) -> TestResult<Value> {
    let pool = gateway.read();
    assert!(pool.total_vsize() <= pool.limits.max_total_bytes);
    Ok(json!({
        "entries": pool.tx_count(), "vsize": pool.total_vsize(),
        "vsize_limit": pool.limits.max_total_bytes,
        "retained_estimate_bytes": pool.dynamic_memory_usage(),
        "rss_kib": rss_kib("VmRSS:")?, "process_rss_high_water_kib": rss_kib("VmHWM:")?,
    }))
}

struct Chain;
impl AdmissionChain for Chain {
    fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot {
            height: 200,
            csv_active: true,
            ..ChainAdmissionSnapshot::default()
        })
    }
}

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
        height: 201,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        min_time: 1_700_000_001,
        current_time: 1_700_000_600,
        locktime_cutoff: 1_700_000_000,
        network: Network::Regtest,
        csv_active: true,
        segwit_active: true,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}

fn exercise(stage: &str, fixture: &Fixture) -> TestResult<Value> {
    let gateway = &fixture.gateway;
    match stage {
        "replacement" => {
            let mut tx = transaction(fixture.roots[0], 1_000, &[0x51]);
            tx.inputs = fixture
                .roots
                .iter()
                .map(|&previous_output| TxIn {
                    previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect();
            let vsize = u32::try_from(tx.vsize())?;
            let changes = gateway.replace_transaction(
                AdmissionOrigin::Rpc,
                ReplacementCandidate::new(Arc::new(tx), vsize, 100_000_000, 1_000),
                2,
                1,
                0,
            )?;
            assert_eq!(changes.len(), usize::try_from(CLUSTERS * MEMBERS + 1)?);
            assert_eq!(gateway.read().tx_count(), 1);
            Ok(json!({"mutation_changes": changes.len(), "change_bound": CLUSTERS * MEMBERS + 1}))
        }
        "package-preview" => {
            let script = [vec![0, 20], vec![1; 20]].concat();
            let txs: Vec<_> = fixture
                .tips
                .iter()
                .take(25)
                .map(|&(outpoint, value)| transaction(outpoint, value - 1_000, &script))
                .collect();
            let sequence = gateway.read().sequence_number();
            let facts = gateway.preview_transactions(&txs, None, &Chain)?;
            assert!(facts.package_error.is_none(), "{facts:?}");
            assert_eq!(facts.results.len(), 25);
            assert!(
                facts.results.iter().all(|row| row.allowed == Some(true)),
                "{facts:?}"
            );
            assert_eq!(gateway.read().sequence_number(), sequence);
            Ok(
                json!({"offered": facts.results.len(), "package_bound": 25, "projected_cluster_count": MEMBERS}),
            )
        }
        "mining" => {
            let snapshot = gateway.read().mining_snapshot();
            let context = context();
            let candidate = assemble_candidate(&context, &snapshot, &[0x51])?;
            assert_eq!(candidate.transactions.len(), snapshot.entries.len());
            assert!(
                candidate.weight <= context.max_weight
                    && candidate.sigop_cost <= context.max_sigops
            );
            Ok(
                json!({"selected": candidate.transactions.len(), "weight": candidate.weight,
                "weight_limit": context.max_weight, "sigops": candidate.sigop_cost, "sigop_limit": context.max_sigops}),
            )
        }
        "eviction" => {
            let target = gateway.read().total_vsize() / 2;
            let changes = gateway.enforce_size_limit(AdmissionOrigin::Rpc, target)?;
            assert!(gateway.read().total_vsize() <= target);
            assert!(changes.len() <= usize::try_from(CLUSTERS * MEMBERS)?);
            Ok(json!({"target_vsize": target, "mutation_changes": changes.len()}))
        }
        _ => Err("unknown resource scenario".into()),
    }
}

#[test]
fn mempool_policy_resource_capture_at_resolved_graph_bounds() -> TestResult {
    let mut measurements = Vec::new();
    let mut retained_peak = 0_u64;
    for stage in ["package-preview", "mining", "replacement", "eviction"] {
        let fixture = fixture(if stage == "package-preview" {
            MEMBERS - 1
        } else {
            MEMBERS
        })?;
        let before = sample(&fixture.gateway)?;
        let start = Instant::now();
        let result = exercise(stage, &fixture)?;
        let elapsed = start.elapsed().as_micros();
        let after = sample(&fixture.gateway)?;
        for value in [&before, &after] {
            retained_peak = retained_peak.max(
                value["retained_estimate_bytes"]
                    .as_u64()
                    .ok_or("retained estimate missing")?,
            );
        }
        measurements.push(json!({"stage": stage, "elapsed_us": elapsed, "before": before, "after": after, "result": result}));
    }
    let report = json!({
        "scope": "mempool policy owner only; raw admitted-graph fixtures",
        "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "source_sha256": {
            "fee_diagram": sha256::Hash::hash(include_bytes!("../../../crates/mempool/src/fee_diagram.rs")).to_string(),
            "pool": sha256::Hash::hash(include_bytes!("../../../crates/mempool/src/pool.rs")).to_string(),
            "gateway": sha256::Hash::hash(include_bytes!("../../../crates/mempool/src/gateway.rs")).to_string(),
            "mining_policy": sha256::Hash::hash(include_bytes!("../src/policy.rs")).to_string(),
            "harness": sha256::Hash::hash(include_bytes!("overhaul_resource_bounds.rs")).to_string(),
            "cargo_lock": sha256::Hash::hash(include_bytes!("../../../Cargo.lock")).to_string(),
        },
        "cluster_count_bound": MEMBERS, "conflicting_cluster_bound": CLUSTERS,
        "retained_estimate_high_water_bytes": retained_peak,
        "process_rss_high_water_kib": rss_kib("VmHWM:")?,
        "rss_limit": Value::Null,
        "notes": "RSS has no configured mempool-specific cap. Vsize and structural limits are checked separately. Single-pass time samples are not a regression or throughput claim.",
        "measurements": measurements,
    });
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/process-harness");
    std::fs::create_dir_all(&directory)?;
    let captured_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let path = directory.join(format!(
        "resource-bounds-{}-{captured_at}.json",
        std::process::id()
    ));
    std::fs::write(&path, serde_json::to_vec_pretty(&report)?)?;
    println!("RESOURCE_EVIDENCE {report}");
    println!("resource evidence: {}", path.display());
    Ok(())
}
