//! Transaction validation benchmarks for the portable consensus path.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use hashbrown::HashMap;
use std::hint::black_box;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::verify_transaction;

struct BenchUtxos(HashMap<OutPoint, TxOut>);

impl UtxoView for BenchUtxos {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0.get(outpoint).cloned()
    }
}

use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
use bitcoin_rs_script::push_int;
use bitcoin_rs_script::{Interpreter, VerifyFlags};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const INPUTS: u8 = 128;

fn multi_input_true_scripts(c: &mut Criterion) {
    c.bench_function("verify_tx/multi_input_true_scripts", |b| {
        b.iter_batched(
            fixture,
            |(tx, utxos)| {
                verify_transaction(
                    black_box(&tx),
                    black_box(&utxos),
                    1,
                    0,
                    black_box(VerifyFlags::MANDATORY),
                )
                .unwrap_or_else(|error| panic!("transaction verification failed: {error}"));
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("verify_tx/interpreter_multi_input_true_scripts", |b| {
        b.iter_batched(
            fixture,
            |(tx, utxos)| {
                verify_with_interpreter_loop(black_box(&tx), black_box(&utxos.0));
            },
            BatchSize::SmallInput,
        );
    });
}

fn verify_with_interpreter_loop(tx: &Tx, utxos: &HashMap<OutPoint, TxOut>) {
    let interpreter = Interpreter;
    for (input_index, input) in tx.inputs.iter().enumerate() {
        let prevout = utxos
            .get(&input.previous_output)
            .unwrap_or_else(|| panic!("missing prevout at input {input_index}"));
        let witness = input.witness.clone();
        interpreter
            .execute(
                &prevout.script_pubkey,
                &input.script_sig,
                &witness,
                VerifyFlags::MANDATORY,
                prevout,
                tx,
                input_index,
            )
            .unwrap_or_else(|error| panic!("interpreter verification failed: {error}"));
    }
}

fn fixture() -> (Tx, BenchUtxos) {
    let mut inputs = Vec::with_capacity(usize::from(INPUTS));
    let mut utxos = HashMap::new();
    for index in 0..INPUTS {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[index; 32])), 0);
        inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        });
        utxos.insert(
            outpoint,
            TxOut {
                value: 100,
                script_pubkey: push_int(1),
            },
        );
    }

    (
        Tx {
            version: 1,
            inputs,
            outputs: vec![TxOut {
                value: u64::from(INPUTS) * 50,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        },
        BenchUtxos(utxos),
    )
}

criterion_group!(benches, multi_input_true_scripts);
criterion_main!(benches);
