#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::Config;
use bitcoin_rs_node::state::NodeState;

#[path = "support/corpus.rs"]
mod corpus;

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;
    let network = parse_network(&args.network)?;

    let manifest = if let Some(rest_url) = &args.rest_url {
        corpus::export_corpus_from_rest(
            rest_url,
            network,
            args.stop_height,
            &args.archive,
            &args.manifest,
        )
        .context("export corpus from REST")?
    } else {
        let Some(data_dir) = args.data_dir.as_ref() else {
            bail!("exactly one corpus source must be configured");
        };
        let mut config = Config::default_for_network(network);
        config.data_dir.clone_from(data_dir);
        config.storage_backend.clone_from(&args.storage_backend);
        config.p2p_listen.clear();
        config.dns_seeds_enabled = false;

        let state = NodeState::open(config).context("open node state")?;
        corpus::export_active_chain_corpus(
            &state,
            network,
            args.stop_height,
            &args.archive,
            &args.manifest,
        )
        .context("export active-chain corpus")?
    };

    println!("exported active chain 0..={}", manifest.stop_height);
    println!("archive: {}", args.archive.display());
    println!("manifest: {}", args.manifest.display());
    println!("archive size: {} bytes", manifest.archive.size);
    println!(
        "archive sha256: {}",
        manifest.archive.sha256.as_slice().to_lower_hex_string()
    );
    Ok(())
}

#[derive(Debug)]
struct Args {
    data_dir: Option<PathBuf>,
    rest_url: Option<String>,
    storage_backend: String,
    network: String,
    stop_height: u32,
    archive: PathBuf,
    manifest: PathBuf,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut parsed = Self {
            data_dir: None,
            rest_url: None,
            storage_backend: "fjall".to_owned(),
            network: "mainnet".to_owned(),
            stop_height: 0,
            archive: PathBuf::new(),
            manifest: PathBuf::new(),
        };
        let mut data_dir = None;
        let mut rest_url = None;
        let mut archive = None;
        let mut manifest = None;
        let mut stop_height = None;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg.to_string_lossy();
            match arg.as_ref() {
                "--data-dir" => data_dir = Some(PathBuf::from(next_arg(&mut args, "--data-dir")?)),
                "--rest-url" => rest_url = Some(next_arg(&mut args, "--rest-url")?),
                "--storage-backend" => {
                    parsed.storage_backend = next_arg(&mut args, "--storage-backend")?;
                }
                "--network" => parsed.network = next_arg(&mut args, "--network")?,
                "--stop-height" => {
                    stop_height = Some(parse_height(&next_arg(&mut args, "--stop-height")?)?);
                }
                "--archive" => archive = Some(PathBuf::from(next_arg(&mut args, "--archive")?)),
                "--manifest" => manifest = Some(PathBuf::from(next_arg(&mut args, "--manifest")?)),
                other => bail!("unknown argument: {other}"),
            }
        }

        if data_dir.is_some() == rest_url.is_some() {
            bail!("provide exactly one of --data-dir or --rest-url");
        }
        parsed.data_dir = data_dir;
        parsed.rest_url = rest_url;
        parsed.archive = archive.context("--archive is required")?;
        parsed.manifest = manifest.context("--manifest is required")?;
        parsed.stop_height = stop_height.context("--stop-height is required")?;
        Ok(parsed)
    }
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))
        .map(|s| s.to_string_lossy().into_owned())
}

fn parse_height(s: &str) -> Result<u32> {
    s.parse::<u32>()
        .with_context(|| format!("invalid height: {s}"))
}

fn parse_network(value: &str) -> Result<Network> {
    match value.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(Network::Mainnet),
        "test" | "testnet" | "testnet3" => Ok(Network::Testnet3),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => bail!("unsupported network {other}"),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::Args;

    fn base_args() -> Vec<OsString> {
        vec![
            "--archive".into(),
            "/tmp/archive.dat".into(),
            "--manifest".into(),
            "/tmp/manifest.json".into(),
            "--stop-height".into(),
            "1".into(),
        ]
    }

    #[test]
    fn data_dir_alone_is_accepted() {
        let mut args = base_args();
        args.extend(["--data-dir".into(), "/tmp/data".into()]);
        assert!(Args::parse(args).is_ok());
    }

    #[test]
    fn rest_url_alone_is_accepted() {
        let mut args = base_args();
        args.extend(["--rest-url".into(), "127.0.0.1:18443".into()]);
        assert!(Args::parse(args).is_ok());
    }

    #[test]
    fn neither_source_is_rejected() {
        assert!(Args::parse(base_args()).is_err());
    }

    #[test]
    fn both_sources_are_rejected() {
        let mut args = base_args();
        args.extend([
            "--data-dir".into(),
            "/tmp/data".into(),
            "--rest-url".into(),
            "127.0.0.1:18443".into(),
        ]);
        assert!(Args::parse(args).is_err());
    }
}
