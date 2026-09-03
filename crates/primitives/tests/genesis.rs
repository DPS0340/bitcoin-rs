//! Differential oracle: native genesis blocks byte-match rust-bitcoin's and hash
//! to the compiled-in per-network genesis hashes.

use bitcoin::consensus::Encodable as _;
use bitcoin_rs_primitives::Network;

#[test]
fn native_genesis_matches_bitcoin_crate_and_compiled_hash() -> Result<(), Box<dyn std::error::Error>>
{
    let cases = [
        (Network::Mainnet, bitcoin::Network::Bitcoin),
        (Network::Testnet3, bitcoin::Network::Testnet),
        (Network::Testnet4, bitcoin::Network::Testnet4),
        (Network::Signet, bitcoin::Network::Signet),
        (Network::Regtest, bitcoin::Network::Regtest),
    ];
    for (network, oracle_network) in cases {
        let native = network.genesis_block();
        let oracle = bitcoin::blockdata::constants::genesis_block(oracle_network);
        let mut bytes = Vec::new();
        oracle.consensus_encode(&mut bytes)?;

        assert_eq!(
            bitcoin_rs_primitives::consensus_bytes(&native),
            bytes,
            "{network:?} genesis serialization diverges"
        );
        let hash = format!("{}", network.genesis_block_hash());
        assert_eq!(
            format!("{}", native.block_hash()),
            hash,
            "{network:?} genesis hash diverges"
        );
    }
    Ok(())
}
