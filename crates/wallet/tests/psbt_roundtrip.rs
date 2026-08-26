//! PSBT build, external signing, finalization, and consensus roundtrips.
//!
//! **Gated on the `kernel` feature, because it needs the real script backend.**
//! The last step hands the finished transaction to
//! `bitcoin_rs_consensus::verify_transaction`, which without the kernel routes
//! to `verify_non_taproot_portable` -- a stub that accepts only bare `OP_TRUE`
//! and refuses everything else.
//!
//! Before the gate this crate declared no such dependency and the test passed
//! anyway, because `cargo test --workspace` unifies features across members and
//! `bin/bitcoin-rs` turns the kernel on. So it was green through a dependency it
//! did not name, of a crate it did not mention -- and `cargo test -p
//! bitcoin-rs-wallet` failed with "portable script backend cannot verify this
//! non-taproot spend", a message about script backends, in a PSBT test, with
//! nothing connecting the two.
//!
//! Two things follow, and both matter:
//!
//! - `crates/node`'s `kernel` feature now forwards to this crate's, so anything
//!   turning the kernel on turns it on here too. `cargo test --workspace` still
//!   runs this.
//! - A gated-out file is an empty binary, and an empty binary reports success --
//!   which is the failure mode the gate exists to remove. `psbt_roundtrip_gate`
//!   compiles in its place and says what is not being checked.
//!
//! Run it alone with:
//!
//! ```text
//! cargo test -p bitcoin-rs-wallet --features kernel --test psbt_roundtrip
//! ```
#![cfg(feature = "kernel")]

use std::collections::BTreeMap;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, Network, OutPoint, TxOut, Txid};
use bitcoin_rs_consensus::verify_transaction;
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_wallet::{Descriptor, ExternalSigner, PrevUtxo, PsbtBuilder, finalize_signed};

#[path = "fixtures/test_signer.rs"]
mod test_signer;

#[test]
fn descriptor_psbt_signer_finalizer_roundtrips_through_consensus()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let cases = [
        format!("pkh({public_key})"),
        format!("wpkh({public_key})"),
        format!("sh(wpkh({public_key}))"),
        format!("tr({public_key})"),
        format!("wsh(multi(1,{public_key}))"),
    ];

    for (case_index, descriptor_text) in cases.iter().enumerate() {
        let descriptor = Descriptor::parse(descriptor_text)?;
        let script_pubkey = descriptor
            .derive_address(Network::Regtest, 0)?
            .script_pubkey();
        let byte = u8::try_from(case_index + 1)?;
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout: 0,
        };
        let prev_txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
        builder.add_input(PrevUtxo::new(outpoint, prev_txout.clone()), 0)?;
        let destination = descriptor.derive_address(Network::Regtest, 1)?;
        builder.add_output(destination, Amount::from_sat(40_000))?;
        let unsigned = builder.finalize()?;
        assert!(unsigned.inputs[0].partial_sigs.is_empty());
        assert!(unsigned.inputs[0].tap_key_sig.is_none());

        let signed = signer.sign_psbt(&unsigned)?;
        let finalized = finalize_signed(signed)?;
        let mut prevouts = BTreeMap::new();
        prevouts.insert(outpoint, prev_txout);
        verify_transaction(&finalized, &prevouts, 0, 0, VerifyFlags::MANDATORY)?;
    }

    Ok(())
}
