use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use bitcoin_rs_node::zmq_publisher::ZmqTopic;
use bitcoin_rs_node::{NetworkSelection, ScriptIndexMode, UserConfig, ZmqOverrides};
use bitcoin_rs_storage::StorageBackend;

use crate::cli::{
    parse_bool, parse_connect_list, parse_p2p_magic, parse_socket_list, parse_string_list,
};

pub(crate) fn user_config_from_env(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Result<UserConfig> {
    let mut layer = UserConfig::default();
    for (key, value) in vars {
        let Some(key) = key.to_str() else {
            continue;
        };
        if is_zmq_env_key(key) {
            let value = environment_value(&value, key)?;
            apply_zmq_env(&mut layer.zmq, key, value)?;
        } else if is_general_env_key(key) {
            apply_general_env(&mut layer, key, &value)?;
        }
    }
    Ok(layer)
}

fn is_zmq_env_key(key: &str) -> bool {
    matches!(
        key,
        "BITCOIN_RS_ZMQPUBHASHBLOCK"
            | "BITCOIN_RS_ZMQPUBHASHTX"
            | "BITCOIN_RS_ZMQPUBRAWBLOCK"
            | "BITCOIN_RS_ZMQPUBRAWTX"
            | "BITCOIN_RS_ZMQPUBSEQUENCE"
            | "BITCOIN_RS_ZMQPUBHASHBLOCKHWM"
            | "BITCOIN_RS_ZMQPUBHASHTXHWM"
            | "BITCOIN_RS_ZMQPUBRAWBLOCKHWM"
            | "BITCOIN_RS_ZMQPUBRAWTXHWM"
            | "BITCOIN_RS_ZMQPUBSEQUENCEHWM"
    )
}

fn is_general_env_key(key: &str) -> bool {
    matches!(
        key,
        "BITCOIN_RS_NETWORK"
            | "BITCOIN_RS_P2P_MAGIC"
            | "BITCOIN_RS_DATA_DIR"
            | "BITCOIN_RS_STORAGE_BACKEND"
            | "BITCOIN_RS_RPC_BIND"
            | "BITCOIN_RS_REST"
            | "BITCOIN_RS_RPC_USER"
            | "BITCOIN_RS_RPC_PASSWORD"
            | "BITCOIN_RS_RPC_COOKIE"
            | "BITCOIN_RS_SCRIPTINDEX"
            | "BITCOIN_RS_P2P_LISTEN"
            | "BITCOIN_RS_DNS_SEEDS_ENABLED"
            | "BITCOIN_RS_CONNECT"
            | "BITCOIN_RS_PRUNE_TARGET_MB"
            | "BITCOIN_RS_TXINDEX"
            | "BITCOIN_RS_DBCACHE_MB"
            | "BITCOIN_RS_INDEX_ROLLBACK_REBUILD_CUTOVER"
            | "BITCOIN_RS_LOG_LEVEL"
            | "BITCOIN_RS_METRICS_BIND"
            | "BITCOIN_RS_ASSUME_VALID_HEIGHT"
    )
}

fn apply_general_env(layer: &mut UserConfig, key: &str, value: &OsString) -> Result<()> {
    let value = environment_value(value, key)?;
    match key {
        "BITCOIN_RS_NETWORK" => {
            layer.network = Some(
                value
                    .parse::<NetworkSelection>()
                    .map_err(anyhow::Error::msg)?,
            );
        }
        "BITCOIN_RS_P2P_MAGIC" => layer.p2p.magic = Some(parse_p2p_magic(value)?),
        "BITCOIN_RS_DATA_DIR" => layer.data_dir = Some(PathBuf::from(value)),
        "BITCOIN_RS_STORAGE_BACKEND" => {
            layer.storage.backend = Some(
                value
                    .parse::<StorageBackend>()
                    .map_err(anyhow::Error::msg)?,
            );
        }
        "BITCOIN_RS_RPC_BIND" => layer.rpc.bind = Some(value.parse()?),
        "BITCOIN_RS_REST" => layer.rpc.rest = Some(parse_bool(value)?),
        "BITCOIN_RS_RPC_USER" => layer.rpc.user = Some(value.to_owned()),
        "BITCOIN_RS_RPC_PASSWORD" => layer.rpc.password = Some(value.to_owned()),
        "BITCOIN_RS_RPC_COOKIE" => layer.rpc.cookie = Some(PathBuf::from(value)),
        "BITCOIN_RS_SCRIPTINDEX" => {
            layer.indexes.script_index = Some(
                ScriptIndexMode::parse(value)
                    .ok_or_else(|| anyhow::anyhow!("invalid scriptindex value `{value}`"))?,
            );
        }
        "BITCOIN_RS_P2P_LISTEN" => layer.p2p.listen = Some(parse_socket_list(value)?),
        "BITCOIN_RS_DNS_SEEDS_ENABLED" => layer.p2p.dns_seeds = Some(parse_bool(value)?),
        "BITCOIN_RS_CONNECT" => layer.p2p.connect = Some(parse_connect_list(value)?),
        "BITCOIN_RS_PRUNE_TARGET_MB" => layer.storage.prune_target_mb = Some(value.parse()?),
        "BITCOIN_RS_TXINDEX" => layer.indexes.txindex = Some(parse_bool(value)?),
        "BITCOIN_RS_DBCACHE_MB" => layer.storage.dbcache_mb = Some(value.parse()?),
        "BITCOIN_RS_INDEX_ROLLBACK_REBUILD_CUTOVER" => {
            layer.indexes.rollback_rebuild_cutover = Some(value.parse()?);
        }
        "BITCOIN_RS_LOG_LEVEL" => layer.observability.log_level = Some(value.to_owned()),
        "BITCOIN_RS_METRICS_BIND" => layer.observability.metrics_bind = Some(value.parse()?),
        "BITCOIN_RS_ASSUME_VALID_HEIGHT" => {
            layer.validation.assume_valid_height = Some(value.parse()?);
        }
        _ => {}
    }
    Ok(())
}

fn environment_value<'a>(value: &'a OsString, key: &str) -> Result<&'a str> {
    value
        .to_str()
        .with_context(|| format!("environment variable {key} is not valid UTF-8"))
}

fn apply_zmq_env(layer: &mut ZmqOverrides, key: &str, value: &str) -> Result<()> {
    let endpoint_topic = match key {
        "BITCOIN_RS_ZMQPUBHASHBLOCK" => Some(ZmqTopic::HashBlock),
        "BITCOIN_RS_ZMQPUBHASHTX" => Some(ZmqTopic::HashTx),
        "BITCOIN_RS_ZMQPUBRAWBLOCK" => Some(ZmqTopic::RawBlock),
        "BITCOIN_RS_ZMQPUBRAWTX" => Some(ZmqTopic::RawTx),
        "BITCOIN_RS_ZMQPUBSEQUENCE" => Some(ZmqTopic::Sequence),
        _ => None,
    };
    if let Some(topic) = endpoint_topic {
        layer.endpoints.insert(topic, parse_string_list(value));
        return Ok(());
    }

    let hwm_topic = match key {
        "BITCOIN_RS_ZMQPUBHASHBLOCKHWM" => Some(ZmqTopic::HashBlock),
        "BITCOIN_RS_ZMQPUBHASHTXHWM" => Some(ZmqTopic::HashTx),
        "BITCOIN_RS_ZMQPUBRAWBLOCKHWM" => Some(ZmqTopic::RawBlock),
        "BITCOIN_RS_ZMQPUBRAWTXHWM" => Some(ZmqTopic::RawTx),
        "BITCOIN_RS_ZMQPUBSEQUENCEHWM" => Some(ZmqTopic::Sequence),
        _ => None,
    };
    if let Some(topic) = hwm_topic {
        layer.hwm.insert(topic, value.parse()?);
        return Ok(());
    }

    unreachable!("only known ZMQ environment keys are dispatched")
}
