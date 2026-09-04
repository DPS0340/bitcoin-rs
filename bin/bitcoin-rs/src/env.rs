use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{NetworkSelection, ScriptIndexMode, UserConfig};
use bitcoin_rs_storage::StorageBackend;

use crate::cli::{parse_bool, parse_connect_list, parse_p2p_magic, parse_socket_list};

#[derive(Copy, Clone)]
enum EnvSetting {
    Network,
    P2pMagic,
    DataDir,
    StorageBackend,
    RpcBind,
    Rest,
    RpcUser,
    RpcPassword,
    RpcCookie,
    ScriptIndex,
    P2pListen,
    DnsSeedsEnabled,
    Connect,
    PruneTargetMb,
    TxIndex,
    DbcacheMb,
    LogLevel,
    MetricsBind,
    AssumeValidHeight,
}

pub(crate) fn user_config_from_env(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Result<UserConfig> {
    let mut layer = UserConfig::default();
    for (key, value) in vars {
        let Some(key) = key.to_str() else {
            continue;
        };
        let Some(setting) = env_setting(key) else {
            continue;
        };
        let value = environment_value(&value, key)?;
        apply(&mut layer, setting, value)?;
    }
    Ok(layer)
}

fn env_setting(key: &str) -> Option<EnvSetting> {
    Some(match key {
        "BITCOIN_RS_NETWORK" => EnvSetting::Network,
        "BITCOIN_RS_P2P_MAGIC" => EnvSetting::P2pMagic,
        "BITCOIN_RS_DATA_DIR" => EnvSetting::DataDir,
        "BITCOIN_RS_STORAGE_BACKEND" => EnvSetting::StorageBackend,
        "BITCOIN_RS_RPC_BIND" => EnvSetting::RpcBind,
        "BITCOIN_RS_REST" => EnvSetting::Rest,
        "BITCOIN_RS_RPC_USER" => EnvSetting::RpcUser,
        "BITCOIN_RS_RPC_PASSWORD" => EnvSetting::RpcPassword,
        "BITCOIN_RS_RPC_COOKIE" => EnvSetting::RpcCookie,
        "BITCOIN_RS_SCRIPTINDEX" => EnvSetting::ScriptIndex,
        "BITCOIN_RS_P2P_LISTEN" => EnvSetting::P2pListen,
        "BITCOIN_RS_DNS_SEEDS_ENABLED" => EnvSetting::DnsSeedsEnabled,
        "BITCOIN_RS_CONNECT" => EnvSetting::Connect,
        "BITCOIN_RS_PRUNE_TARGET_MB" => EnvSetting::PruneTargetMb,
        "BITCOIN_RS_TXINDEX" => EnvSetting::TxIndex,
        "BITCOIN_RS_DBCACHE_MB" => EnvSetting::DbcacheMb,
        "BITCOIN_RS_LOG_LEVEL" => EnvSetting::LogLevel,
        "BITCOIN_RS_METRICS_BIND" => EnvSetting::MetricsBind,
        "BITCOIN_RS_ASSUME_VALID_HEIGHT" => EnvSetting::AssumeValidHeight,
        _ => return None,
    })
}

fn environment_value<'a>(value: &'a OsString, key: &str) -> Result<&'a str> {
    value
        .to_str()
        .with_context(|| format!("environment variable {key} is not valid UTF-8"))
}

fn apply(layer: &mut UserConfig, setting: EnvSetting, value: &str) -> Result<()> {
    match setting {
        EnvSetting::Network => {
            layer.network = Some(
                value
                    .parse::<NetworkSelection>()
                    .map_err(anyhow::Error::msg)?,
            );
        }
        EnvSetting::P2pMagic => layer.p2p.magic = Some(parse_p2p_magic(value)?),
        EnvSetting::DataDir => layer.data_dir = Some(PathBuf::from(value)),
        EnvSetting::StorageBackend => {
            layer.storage.backend = Some(
                value
                    .parse::<StorageBackend>()
                    .map_err(anyhow::Error::msg)?,
            );
        }
        EnvSetting::RpcBind => layer.rpc.bind = Some(value.parse()?),
        EnvSetting::Rest => layer.rpc.rest = Some(parse_bool(value)?),
        EnvSetting::RpcUser => layer.rpc.user = Some(value.to_owned()),
        EnvSetting::RpcPassword => layer.rpc.password = Some(value.to_owned()),
        EnvSetting::RpcCookie => layer.rpc.cookie = Some(PathBuf::from(value)),
        EnvSetting::ScriptIndex => {
            layer.indexes.script_index = Some(
                ScriptIndexMode::parse(value)
                    .ok_or_else(|| anyhow::anyhow!("invalid scriptindex value `{value}`"))?,
            );
        }
        EnvSetting::P2pListen => layer.p2p.listen = Some(parse_socket_list(value)?),
        EnvSetting::DnsSeedsEnabled => layer.p2p.dns_seeds = Some(parse_bool(value)?),
        EnvSetting::Connect => layer.p2p.connect = Some(parse_connect_list(value)?),
        EnvSetting::PruneTargetMb => layer.storage.prune_target_mb = Some(value.parse()?),
        EnvSetting::TxIndex => layer.indexes.txindex = Some(parse_bool(value)?),
        EnvSetting::DbcacheMb => layer.storage.dbcache_mb = Some(value.parse()?),
        EnvSetting::LogLevel => layer.observability.log_level = Some(value.to_owned()),
        EnvSetting::MetricsBind => layer.observability.metrics_bind = Some(value.parse()?),
        EnvSetting::AssumeValidHeight => {
            layer.validation.assume_valid_height = Some(value.parse()?);
        }
    }
    Ok(())
}
