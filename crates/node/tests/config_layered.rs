//! Resolver tests for grouped node configuration layers.

use std::collections::BTreeMap;

use anyhow::Result;
use bitcoin_rs_node::zmq_publisher::ZmqTopic;
use bitcoin_rs_node::{
    NetworkSelection, P2pOverrides, ScriptIndexMode, UserConfig, ValidationOverrides, ZmqOverrides,
    resolve,
};
use bitcoin_rs_primitives::Network;

#[test]
fn standard_network_uses_builtin_defaults() -> Result<()> {
    let layer = UserConfig {
        network: Some(NetworkSelection::Testnet4),
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.network, Network::Testnet4);
    assert_eq!(config.p2p.magic, Network::Testnet4.magic());
    assert!(config.p2p.connect.is_empty());
    assert!(config.p2p.dns_seeds_enabled);
    Ok(())
}

#[test]
fn drynet4_network_applies_atomic_p2p_profile() -> Result<()> {
    let layer = UserConfig {
        network: Some(NetworkSelection::Drynet4),
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(config.p2p.magic, [0xec, 0xa5, 0xd4, 0x04]);
    assert_eq!(config.p2p.connect, vec!["drynet4.drivechain.dev:8533"]);
    assert!(!config.p2p.dns_seeds_enabled);
    Ok(())
}

#[test]
fn p2p_magic_override_preserves_consensus_network() -> Result<()> {
    let layer = UserConfig {
        p2p: P2pOverrides {
            magic: Some([0xec, 0xa5, 0xd4, 0x34]),
            dns_seeds: Some(false),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(config.p2p.magic, [0xec, 0xa5, 0xd4, 0x34]);
    assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333"]);
    assert!(!config.p2p.dns_seeds_enabled);
    Ok(())
}

#[test]
fn same_layer_explicit_overrides_follow_network_profile() -> Result<()> {
    let layer = UserConfig {
        network: Some(NetworkSelection::Drynet4),
        p2p: P2pOverrides {
            magic: Some([1, 2, 3, 4]),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            dns_seeds: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.p2p.magic, [1, 2, 3, 4]);
    assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333"]);
    Ok(())
}

#[test]
fn p2p_magic_override_requires_explicit_peer_and_disabled_seeds() {
    let layer = UserConfig {
        p2p: P2pOverrides {
            magic: Some([0xec, 0xa5, 0xd4, 0x34]),
            dns_seeds: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let error = match resolve(&[&layer]) {
        Ok(_) => panic!("magic overrides need a peer"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("at least one --connect peer"));
}

#[test]
fn script_index_is_valid_without_core_txindex() -> Result<()> {
    let layer = UserConfig {
        indexes: bitcoin_rs_node::IndexOverrides {
            script_index: Some(ScriptIndexMode::Full),
            txindex: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert!(!config.indexes.txindex);
    assert!(config.indexes.script_index.is_enabled());
    Ok(())
}

#[test]
fn zmq_endpoints_expand_in_topic_order_with_hwm() -> Result<()> {
    let mut endpoints = BTreeMap::new();
    endpoints.insert(
        ZmqTopic::HashBlock,
        vec![
            "tcp://127.0.0.1:28332".to_owned(),
            "tcp://127.0.0.1:28333".to_owned(),
        ],
    );
    endpoints.insert(ZmqTopic::HashTx, vec!["tcp://127.0.0.1:28334".to_owned()]);
    let mut hwm = BTreeMap::new();
    hwm.insert(ZmqTopic::HashBlock, 9);
    let layer = UserConfig {
        zmq: ZmqOverrides { endpoints, hwm },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(
        config.zmq.iter().map(|item| item.topic).collect::<Vec<_>>(),
        [ZmqTopic::HashBlock, ZmqTopic::HashBlock, ZmqTopic::HashTx]
    );
    assert_eq!(
        config.zmq.iter().map(|item| item.hwm).collect::<Vec<_>>(),
        [9, 9, 1_000]
    );
    Ok(())
}

#[test]
fn connect_hostnames_are_preserved_for_later_resolution() -> Result<()> {
    let layer = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec!["localhost:18444".to_owned()]),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.p2p.connect, vec!["localhost:18444"]);
    Ok(())
}

#[test]
fn assume_valid_height_override_has_precedence() -> Result<()> {
    let low = UserConfig {
        validation: ValidationOverrides {
            assume_valid_height: Some(10_000),
        },
        ..Default::default()
    };
    let high = UserConfig {
        validation: ValidationOverrides {
            assume_valid_height: Some(30_000),
        },
        ..Default::default()
    };
    let config = resolve(&[&low, &high])?;
    assert_eq!(config.validation.assume_valid_height, 30_000);
    Ok(())
}

#[test]
fn assume_valid_height_defaults_to_mainnet_anchor() -> Result<()> {
    let config = resolve(&[])?;
    assert_eq!(
        config.validation.assume_valid_height,
        Network::Mainnet
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height)
    );
    Ok(())
}
