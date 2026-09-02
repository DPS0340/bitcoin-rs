#![allow(missing_docs)]
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::NodeConfig;
use bitcoin_rs_node::corpus::bounded_diagnostic_path;
use bitcoin_rs_node::state::NodeState;

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;
    let network = parse_network(&args.network)?;

    let manifest = if let Some(rest_url) = &args.rest_url {
        bitcoin_rs_node::corpus::export_corpus_from_rest(
            rest_url,
            network,
            args.stop_height,
            args.custody()?,
            &args.archive,
            &args.manifest,
        )
        .context("export corpus from REST")?
    } else {
        let Some(data_dir) = args.data_dir.as_ref() else {
            bail!("exactly one corpus source must be configured");
        };
        let mut config = NodeConfig::default_for_network(network);
        config.data_dir.clone_from(data_dir);
        config.storage_backend.clone_from(&args.storage_backend);
        config.p2p_listen.clear();
        config.dns_seeds_enabled = false;

        let state = NodeState::open(config, None).context("open node state")?;
        bitcoin_rs_node::corpus::export_active_chain_corpus(
            &state,
            network,
            args.stop_height,
            args.custody()?,
            &args.archive,
            &args.manifest,
        )
        .context("export active-chain corpus")?
    };

    write_export_summary(
        &mut std::io::stdout().lock(),
        &manifest,
        &args.archive,
        &args.manifest,
    )?;
    Ok(())
}
/// Prints the operator-facing export summary.
///
/// Operator-supplied paths go through the shared bounded renderer so a
/// hostile name cannot forge terminal structure; the corpus id and core
/// version print only because custody validation already accepted them.
fn write_export_summary(
    writer: &mut impl std::io::Write,
    manifest: &bitcoin_rs_node::corpus::CorpusManifest,
    archive: &Path,
    manifest_path: &Path,
) -> std::io::Result<()> {
    writeln!(writer, "exported active chain 0..={}", manifest.stop_height)?;
    writeln!(writer, "corpus: {}", manifest.corpus_id)?;
    writeln!(writer, "core version: {}", manifest.core_version)?;
    writeln!(
        writer,
        "manifest sha256: {}",
        manifest.manifest_sha256.as_slice().to_lower_hex_string()
    )?;
    writeln!(writer, "archive: {}", bounded_diagnostic_path(archive))?;
    writeln!(
        writer,
        "manifest: {}",
        bounded_diagnostic_path(manifest_path)
    )?;
    writeln!(writer, "archive size: {} bytes", manifest.archive.size)?;
    writeln!(
        writer,
        "archive sha256: {}",
        manifest.archive.sha256.as_slice().to_lower_hex_string()
    )?;
    Ok(())
}

#[derive(Debug)]
struct Args {
    data_dir: Option<PathBuf>,
    rest_url: Option<String>,
    storage_backend: String,
    network: String,
    stop_height: u32,
    corpus_id: Option<String>,
    core_version: Option<String>,
    validation: Option<PathBuf>,
    reopen_proofs: Vec<String>,
    archive: PathBuf,
    manifest: PathBuf,
}

impl Args {
    /// Builds the custody contract from the operator-supplied bindings.
    ///
    /// Fails closed unless the corpus id names C150 or Cmodern, a Core
    /// version is present, exactly one proof per supported backend is
    /// supplied, and one shared validation artifact binds all three proofs.
    fn custody(&self) -> Result<bitcoin_rs_node::corpus::ExportCustody> {
        let corpus_id = self
            .corpus_id
            .as_deref()
            .context("--corpus-id is required (C150 or Cmodern)")?;
        let core_version = self
            .core_version
            .as_deref()
            .context("--core-version is required (exported Bitcoin Core version)")?;
        let validation_path = self
            .validation
            .as_deref()
            .context("--validation is required (shared validation artifact all proofs bind)")?;
        let validation =
            bitcoin_rs_node::corpus::load_validation_artifact(corpus_id, validation_path)
                .with_context(|| {
                    format!(
                        "load validation artifact {}",
                        bounded_diagnostic_path(validation_path)
                    )
                })?;
        let proofs = self
            .reopen_proofs
            .iter()
            .map(|spec| -> Result<_> {
                let (backend, path) = parse_reopen_proof(spec)?;
                let proof = bitcoin_rs_node::corpus::load_reopen_proof(
                    corpus_id,
                    &backend,
                    &path,
                    &validation,
                )?;
                Ok(proof)
            })
            .collect::<Result<Vec<_>>>()
            .context("invalid reopen proofs")?;
        bitcoin_rs_node::corpus::ExportCustody::new(corpus_id, core_version, proofs)
            .context("invalid custody bindings")
    }

    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut parsed = Self {
            data_dir: None,
            rest_url: None,
            storage_backend: "fjall".to_owned(),
            network: "mainnet".to_owned(),
            corpus_id: None,
            core_version: None,
            validation: None,
            reopen_proofs: Vec::new(),
            archive: PathBuf::new(),
            manifest: PathBuf::new(),
            stop_height: 0,
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
                "--corpus-id" => parsed.corpus_id = Some(next_arg(&mut args, "--corpus-id")?),
                "--core-version" => {
                    parsed.core_version = Some(next_arg(&mut args, "--core-version")?);
                }
                "--validation" => {
                    parsed.validation = Some(PathBuf::from(next_arg(&mut args, "--validation")?));
                }
                "--reopen-proof" => {
                    parsed
                        .reopen_proofs
                        .push(next_arg(&mut args, "--reopen-proof")?);
                }
                "--archive" => archive = Some(PathBuf::from(next_arg(&mut args, "--archive")?)),
                "--manifest" => manifest = Some(PathBuf::from(next_arg(&mut args, "--manifest")?)),
                other => bail!("unknown argument: {other}"),
            }
        }

        if data_dir.is_some() == rest_url.is_some() {
            bail!("provide exactly one of --data-dir or --rest-url");
        }
        if parsed.corpus_id.is_none() {
            bail!("--corpus-id is required (C150 or Cmodern)");
        }
        if parsed.core_version.is_none() {
            bail!("--core-version is required");
        }
        if parsed.validation.is_none() {
            bail!(
                "--validation is required (one shared validation artifact for every backend proof)"
            );
        }
        parsed.data_dir = data_dir;
        parsed.rest_url = rest_url;
        parsed.archive = archive.context("--archive is required")?;
        parsed.manifest = manifest.context("--manifest is required")?;
        parsed.stop_height = stop_height.context("--stop-height is required")?;
        Ok(parsed)
    }
}

/// Parses one `backend,path` reopen-proof specification. The referenced
/// artifact is verified when custody is built, not here.
fn parse_reopen_proof(spec: &str) -> Result<(String, PathBuf)> {
    let parts: Vec<&str> = spec.split(',').collect();
    if parts.len() != 2 {
        bail!(
            "--reopen-proof must be backend,path: {}",
            bounded_diagnostic_path(Path::new(spec))
        );
    }
    Ok((parts[0].to_owned(), PathBuf::from(parts[1])))
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
// Test fixtures fail at the assertion site.
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use std::path::Path;

    use bitcoin_rs_node::Network;
    use bitcoin_rs_node::corpus::{
        ArchiveInfo, CHECKSIG_CENSUS_SCHEMA, CHECKSIG_CENSUS_VERSION, CorpusManifest,
        EXPORTER_SCHEMA, EXPORTER_VERSION, VersionedSchema,
    };
    use bitcoin_rs_primitives::Hash256;

    use super::{Args, write_export_summary};

    fn base_args() -> Vec<OsString> {
        vec![
            "--archive".into(),
            "/tmp/archive.dat".into(),
            "--manifest".into(),
            "/tmp/manifest.json".into(),
            "--stop-height".into(),
            "1".into(),
            "--corpus-id".into(),
            "C150".into(),
            "--core-version".into(),
            "31.1.0".into(),
            "--validation".into(),
            "/tmp/synthetic/validation.json".into(),
            "--reopen-proof".into(),
            "fjall,/tmp/synthetic/fjall-reopen-proof.json".into(),
            "--reopen-proof".into(),
            "rocksdb,/tmp/synthetic/rocksdb-reopen-proof.json".into(),
            "--reopen-proof".into(),
            "redb,/tmp/synthetic/redb-reopen-proof.json".into(),
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

    #[test]
    fn missing_validation_is_rejected() {
        let mut args = base_args();
        let position = args.iter().position(|arg| arg == "--validation").unwrap();
        args.drain(position..position + 2);
        assert!(Args::parse(args).is_err());
    }

    #[test]
    fn missing_corpus_id_is_rejected() {
        let args: Vec<OsString> = base_args()
            .into_iter()
            .skip(6) // drop --corpus-id and its value
            .collect();
        assert!(Args::parse(args).is_err());
    }

    #[test]
    fn missing_core_version_is_rejected() {
        let mut args = base_args();
        let position = args.iter().position(|arg| arg == "--core-version").unwrap();
        args.drain(position..position + 2);
        assert!(Args::parse(args).is_err());
    }

    #[test]
    fn incomplete_reopen_proofs_fail_custody() {
        let mut args = base_args();
        args.pop(); // drop the redb proof value
        args.pop(); // drop the redb flag
        args.extend(["--data-dir".into(), "/tmp/data".into()]);
        let parsed = Args::parse(args).unwrap();
        assert!(parsed.custody().is_err());
    }

    #[test]
    fn malformed_reopen_proof_is_rejected() {
        let mut args = base_args();
        args.extend(["--data-dir".into(), "/tmp/data".into()]);
        let position = args.iter().position(|arg| arg == "--reopen-proof").unwrap();
        args[position + 1] = "fjall-only".into();
        let parsed = Args::parse(args).unwrap();
        assert!(parsed.custody().is_err());
    }

    #[test]
    fn unknown_corpus_id_fails_custody() {
        let mut args = base_args();
        args.extend(["--data-dir".into(), "/tmp/data".into()]);
        let position = args.iter().position(|arg| arg == "--corpus-id").unwrap();
        args[position + 1] = "C999".into();
        let parsed = Args::parse(args).unwrap();
        assert!(parsed.custody().is_err());
    }

    fn summary_manifest() -> CorpusManifest {
        CorpusManifest {
            network: Network::Mainnet,
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            genesis_hash: Hash256::from_le_bytes(&[0x11; 32]),
            start_height: 0,
            stop_height: 150_000,
            corpus_id: "C150".to_owned(),
            core_version: "31.1.0".to_owned(),
            exporter: VersionedSchema {
                schema: EXPORTER_SCHEMA.to_owned(),
                version: EXPORTER_VERSION,
            },
            checksig_census: VersionedSchema {
                schema: CHECKSIG_CENSUS_SCHEMA.to_owned(),
                version: CHECKSIG_CENSUS_VERSION,
            },
            reopen_proofs: Vec::new(),
            source_tip_hash: Hash256::from_le_bytes(&[0x22; 32]),
            manifest_sha256: [0x33; 32],
            archive: ArchiveInfo {
                size: 176,
                sha256: [0x44; 32],
            },
            entries: Vec::new(),
        }
    }

    #[test]
    fn export_summary_writes_success_lines() {
        let manifest = summary_manifest();
        let mut out: Vec<u8> = Vec::new();
        write_export_summary(
            &mut out,
            &manifest,
            Path::new("/tmp/archive.dat"),
            Path::new("/tmp/manifest.json"),
        )
        .unwrap();
        let lines: Vec<String> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(lines.len(), 8, "{lines:?}");
        assert_eq!(lines[0], "exported active chain 0..=150000");
        assert_eq!(lines[1], "corpus: C150");
        assert_eq!(lines[2], "core version: 31.1.0");
        assert_eq!(lines[3], format!("manifest sha256: {}", "33".repeat(32)));
        assert_eq!(lines[4], "archive: /tmp/archive.dat");
        assert_eq!(lines[5], "manifest: /tmp/manifest.json");
        assert_eq!(lines[6], "archive size: 176 bytes");
        assert_eq!(lines[7], format!("archive sha256: {}", "44".repeat(32)));
    }

    #[test]
    fn export_summary_bounds_hostile_paths() {
        let manifest = summary_manifest();
        let hostile = format!("a\n\u{1b}[31m\u{202e}{}", "x".repeat(180));
        let mut out: Vec<u8> = Vec::new();
        write_export_summary(
            &mut out,
            &manifest,
            Path::new(&hostile),
            Path::new("/tmp/manifest.json"),
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 8, "line count: {text:?}");
        let archive_line = text
            .lines()
            .find(|line| line.starts_with("archive: "))
            .expect("archive line");
        assert!(
            !archive_line.contains('\u{1b}'),
            "raw escape: {archive_line:?}"
        );
        assert!(
            !archive_line.contains('\u{202e}'),
            "raw bidi: {archive_line:?}"
        );
        assert!(
            !archive_line.contains(&"x".repeat(40)),
            "raw run: {archive_line:?}"
        );
        assert!(archive_line.contains("path:"), "bounded: {archive_line:?}");
        assert!(
            archive_line.contains("sha256="),
            "no fingerprint: {archive_line:?}"
        );
    }

    #[test]
    fn custody_validation_error_bounds_path() {
        let dir = tempfile::tempdir().unwrap();
        let hostile = format!("missing\n\u{1b}[31m.json");
        let validation = dir.path().join(&hostile);
        let mut args = base_args();
        let position = args.iter().position(|arg| arg == "--validation").unwrap();
        args[position + 1] = validation.into_os_string();
        args.extend(["--data-dir".into(), "/tmp/data".into()]);
        let parsed = Args::parse(args).unwrap();
        let rendered = parsed.custody().unwrap_err().to_string();
        assert!(rendered.contains("load validation artifact"), "{rendered}");
        assert!(!rendered.contains('\u{1b}'), "raw escape: {rendered:?}");
        assert!(rendered.contains("path:"), "bounded: {rendered:?}");
    }

    #[test]
    fn custody_reopenspec_error_bounds_spec() {
        let rendered = super::parse_reopen_proof("fjall,/tmp/p\n\u{1b}[31m,extra")
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("must be backend,path"), "{rendered}");
        assert!(!rendered.contains('\u{1b}'), "raw escape: {rendered:?}");
        assert!(rendered.contains("path:"), "bounded: {rendered:?}");
    }
}
