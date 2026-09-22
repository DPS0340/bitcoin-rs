//! Process custody for `bitcoin-rs` and pinned Bitcoin Core nodes.

use std::fs::{self, File};
use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash as _, sha256};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::error::{Error, Result};

/// Cold storage initialization needs more time than a single loopback request.
pub const START_TIMEOUT: Duration = Duration::from_mins(1);
/// Graceful shutdown budget before the harness reaps the child.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// Single request deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on an HTTP body the harness reads or writes.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Bound on retained child output.
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
/// Fixed test credentials; both node kinds share them.
const AUTH_USER: &str = "parity";
const AUTH_PASSWORD: &str = "parity";
/// Mock clock pinned on the Core side so generated blocks are always valid.
const MOCK_TIME: u64 = 1_780_000_000;

/// Which binary a [`ProcessNode`] wraps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// The `bitcoin-rs` daemon under test.
    BitcoinRs,
    /// The pinned Bitcoin Core reference node.
    Core,
}

/// Options applied on top of the default launch profile.
#[derive(Clone, Debug, Default)]
pub struct SpawnOptions<'a> {
    /// Extra command-line arguments appended after the harness defaults.
    pub extra_args: &'a [&'a str],
    /// Extra TOML lines appended to `node.toml` (bitcoin-rs only).
    pub toml_extra: &'a str,
    /// Full replacement for `node.toml` contents (bitcoin-rs only).
    /// When set, the default regtest profile is not written.
    pub toml_override: Option<&'a str>,
    /// Readiness deadline; defaults to [`START_TIMEOUT`].
    pub timeout: Option<Duration>,
}

/// A decoded HTTP response from the node's RPC/REST/Esplora listener.
#[derive(Debug)]
pub struct HttpResponse {
    /// Numeric status code.
    pub status: u16,
    /// Response headers (lower-cased names).
    pub headers: Vec<(String, String)>,
    /// Raw body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Parse the body as JSON.
    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).map_err(Error::Json)
    }

    /// Interpret the body as UTF-8 text.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| Error::Assertion(format!("response is not utf-8: {e}")))
    }

    /// Look up a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A spawned node process with its RPC endpoint and evidence files.
#[derive(Debug)]
pub struct ProcessNode {
    kind: Kind,
    child: Child,
    datadir: Option<TempDir>,
    /// RPC/HTTP loopback address the child is bound to.
    pub rpc_addr: SocketAddr,
    /// P2P loopback address the child is bound to.
    pub p2p_addr: SocketAddr,
    /// Directory that receives launch.json, stdout.log, stderr.log, transcript.
    pub evidence: PathBuf,
    journal: File,
    started: Instant,
    output: Vec<JoinHandle<()>>,
}

/// Workspace root, derived from this crate's manifest location.
#[must_use]
pub fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Resolve the `bitcoin-rs` binary: `BITCOIN_RS_NODE` env, then the
/// workspace `target/debug` and `target/release` profiles.
pub fn bitcoin_rs_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("BITCOIN_RS_NODE") {
        return Ok(PathBuf::from(path));
    }
    for profile in ["debug", "release"] {
        let path = workspace().join(format!("target/{profile}/bitcoin-rs"));
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(Error::Assertion(
        "bitcoin-rs binary not found; run `cargo build --bin bitcoin-rs` first".into(),
    ))
}

fn core_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("BITCOIN_RS_REFERENCE_BITCOIND") {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let path = Path::new(&home).join("bitcoin-core-31.1/bin/bitcoind");
        if path.is_file() {
            return path;
        }
    }
    workspace().join("target/reference-core-31.1/bitcoin-31.1/bin/bitcoind")
}

/// Verify the resolved bitcoind matches the pinned digest in
/// `docs/api/core-compat.toml`. Returns the binary path on success.
pub fn verified_core_binary() -> Result<PathBuf> {
    let path = core_binary();
    let compat = fs::read_to_string(workspace().join("docs/api/core-compat.toml"))
        .map_err(|e| Error::Assertion(format!("cannot read core-compat.toml: {e}")))?;
    let table: toml::Table = compat
        .parse()
        .map_err(|e| Error::Assertion(format!("cannot parse core-compat.toml: {e}")))?;
    let expected = table
        .get("reference")
        .and_then(|r| r.get("release"))
        .and_then(|r| r.get("bitcoind_sha256"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Assertion("bitcoind_sha256 missing in core-compat.toml".into()))?
        .to_owned();
    let mut file = File::open(&path).map_err(|e| {
        Error::Assertion(format!(
            "pinned bitcoind {} not readable (install via scripts/install-bitcoind.sh): {e}",
            path.display()
        ))
    })?;
    let mut engine = sha256::Hash::engine();
    std::io::copy(&mut file, &mut engine)?;
    let actual = sha256::Hash::from_engine(engine).to_string();
    if actual != expected {
        return Err(Error::Assertion(format!(
            "bitcoind sha256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(path)
}

/// Reserve two loopback ports; callers drop the listeners right before spawn.
fn loopback_addresses() -> Result<(SocketAddr, SocketAddr, TcpListener, TcpListener)> {
    let rpc = TcpListener::bind("127.0.0.1:0")?;
    let p2p = TcpListener::bind("127.0.0.1:0")?;
    Ok((rpc.local_addr()?, p2p.local_addr()?, rpc, p2p))
}

fn launch_command(
    kind: Kind,
    datadir: &Path,
    rpc_addr: SocketAddr,
    p2p_addr: SocketAddr,
    options: &SpawnOptions<'_>,
) -> Result<Command> {
    let mut command = match kind {
        Kind::BitcoinRs => Command::new(bitcoin_rs_binary()?),
        Kind::Core => Command::new(verified_core_binary()?),
    };
    // Host configuration must not leak into the isolated regtest profile.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BITCOIN_RS_") {
            command.env_remove(key);
        }
    }
    match kind {
        Kind::Core => {
            command
                .args([
                    "-regtest",
                    "-server",
                    "-listen=1",
                    "-listenonion=0",
                    "-connect=0",
                    "-dnsseed=0",
                    "-disablewallet",
                    "-rpcuser=parity",
                    "-rpcpassword=parity",
                ])
                .arg(format!("-datadir={}", datadir.display()))
                .arg(format!("-bind={p2p_addr}"))
                .arg(format!("-rpcport={}", rpc_addr.port()))
                .arg(format!("-mocktime={MOCK_TIME}"));
        }
        Kind::BitcoinRs => {
            let config_path = datadir.join("node.toml");
            let base = options.toml_override.map_or_else(
                || {
                    format!(
                        "network = \"regtest\"\np2p_listen = [\"{p2p_addr}\"]\ndns_seeds_enabled = false\n"
                    )
                },
                |text| format!("{text}\n"),
            );
            fs::write(&config_path, format!("{base}{}", options.toml_extra))?;
            command
                .arg("--config")
                .arg(config_path)
                .args([
                    "--storage-backend",
                    "fjall",
                    "--rpc-user",
                    AUTH_USER,
                    "--rpc-password",
                    AUTH_PASSWORD,
                    "--dbcache-mb",
                    "64",
                ])
                .arg("--data-dir")
                .arg(datadir.join("node"))
                .arg("--rpc-bind")
                .arg(rpc_addr.to_string());
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command)
}

impl ProcessNode {
    /// Spawn a node with the default launch profile.
    pub fn spawn(kind: Kind) -> Result<Self> {
        Self::spawn_with(kind, &SpawnOptions::default())
    }

    /// Spawn a node with extra arguments / config lines.
    pub fn spawn_with(kind: Kind, options: &SpawnOptions<'_>) -> Result<Self> {
        let datadir = tempfile::tempdir()?;
        Self::spawn_in_datadir(kind, options, datadir)
    }

    /// Spawn over an existing datadir (restart scenarios).
    pub fn spawn_in_datadir(
        kind: Kind,
        options: &SpawnOptions<'_>,
        datadir: TempDir,
    ) -> Result<Self> {
        let evidence_root = workspace().join("target/e2e");
        fs::create_dir_all(&evidence_root)?;
        let evidence = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(evidence_root)?
            .keep();
        let (rpc_addr, p2p_addr, rpc_listener, p2p_listener) = loopback_addresses()?;
        let journal = File::create(evidence.join("transcript.jsonl"))?;
        let mut command = launch_command(kind, datadir.path(), rpc_addr, p2p_addr, options)?;
        command.args(options.extra_args);
        fs::write(
            evidence.join("launch.json"),
            serde_json::to_vec_pretty(&json!({
                "kind": format!("{kind:?}"),
                "program": command.get_program(),
                "argv": command.get_args().map(|a| a.to_string_lossy()).collect::<Vec<_>>(),
                "datadir": datadir.path(),
                "rpc_address": rpc_addr.to_string(),
                "p2p_address": p2p_addr.to_string(),
            }))?,
        )?;
        drop((rpc_listener, p2p_listener));
        let child = command.spawn()?;
        let mut node = Self {
            kind,
            child,
            datadir: Some(datadir),
            rpc_addr,
            p2p_addr,
            evidence,
            journal,
            started: Instant::now(),
            output: Vec::new(),
        };
        let stdout = node
            .child
            .stdout
            .take()
            .ok_or_else(|| Error::Assertion("piped stdout missing".into()))?;
        let stderr = node
            .child
            .stderr
            .take()
            .ok_or_else(|| Error::Assertion("piped stderr missing".into()))?;
        node.output
            .push(capture_output(stdout, node.evidence.join("stdout.log")));
        node.output
            .push(capture_output(stderr, node.evidence.join("stderr.log")));
        node.wait_ready(options.timeout.unwrap_or(START_TIMEOUT))?;
        Ok(node)
    }

    /// Child process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Which binary this process wraps.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Move datadir custody out for a restart.
    pub fn take_datadir(&mut self) -> Result<TempDir> {
        self.datadir
            .take()
            .ok_or_else(|| Error::Assertion("datadir custody already moved".into()))
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(Error::ChildExit {
                    pid: self.pid(),
                    status,
                    evidence: self.evidence.clone(),
                });
            }
            match self.rpc("getblockchaininfo", &json!([])) {
                Ok(_) => return Ok(()),
                Err(error) if Instant::now() >= deadline => {
                    return Err(Error::Timeout {
                        operation: "readiness",
                        detail: error.to_string(),
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    /// JSON-RPC call; the reply's `result` is returned, an `error` becomes
    /// [`Error::Rpc`].
    pub fn rpc(&mut self, method: &str, params: &Value) -> Result<Value> {
        let request = json!({"jsonrpc": "1.0", "id": "e2e", "method": method, "params": params});
        self.record(&request)?;
        let reply = rpc_call(self.rpc_addr, &request, REQUEST_TIMEOUT);
        self.record(&match &reply {
            Ok(value) => value.clone(),
            Err(error) => json!({"transport_error": error.to_string()}),
        })?;
        reply
    }

    /// Low-level JSON-RPC call returning the full parsed envelope (or the
    /// parsed error reply); never converts a structured error into
    /// [`Error::Rpc`].
    pub fn rpc_raw(&mut self, request: &Value) -> Result<Value> {
        let response = self.http("POST", "/", serde_json::to_vec(request)?.as_slice(), true)?;
        response.json()
    }

    /// HTTP request against the node's listener; `auth` toggles the
    /// parity:parity Basic header.
    pub fn http(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: bool,
    ) -> Result<HttpResponse> {
        http_exchange(
            self.rpc_addr,
            method,
            path,
            body,
            if auth {
                Some((AUTH_USER, AUTH_PASSWORD))
            } else {
                None
            },
            REQUEST_TIMEOUT,
        )
    }

    /// GET helper for REST/Esplora surfaces.
    pub fn http_get(&mut self, path: &str) -> Result<HttpResponse> {
        self.http("GET", path, &[], false)
    }

    fn record(&mut self, entry: &Value) -> Result<()> {
        let line = serde_json::to_vec(&json!({
            "at_micros": self.started.elapsed().as_micros(),
            "entry": entry,
        }))?;
        self.journal.write_all(&line)?;
        self.journal.write_all(b"\n")?;
        self.journal.flush()?;
        Ok(())
    }

    /// Poll `condition` until it returns `Some` or the deadline passes.
    pub fn wait_for<T>(
        &mut self,
        operation: &'static str,
        timeout: Duration,
        mut condition: impl FnMut(&mut Self) -> Result<Option<T>>,
    ) -> Result<T> {
        let deadline = Instant::now() + timeout;
        let mut detail = String::new();
        loop {
            match condition(self) {
                Ok(Some(value)) => return Ok(value),
                Ok(None) => {}
                Err(error) => detail = error.to_string(),
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout { operation, detail });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait until `getblockcount` reports at least `height`.
    pub fn wait_block_count(&mut self, height: u64, timeout: Duration) -> Result<u64> {
        self.wait_for("block count", timeout, move |node| {
            let count = node
                .rpc("getblockcount", &json!([]))?
                .as_u64()
                .ok_or_else(|| Error::Assertion("getblockcount is not a number".into()))?;
            Ok((count >= height).then_some(count))
        })
    }

    /// Graceful stop: `stop` RPC for Core, SIGTERM for bitcoin-rs.
    pub fn stop(mut self) -> Result<()> {
        self.stop_process()?;
        self.finish_output();
        Ok(())
    }

    /// Graceful stop that keeps the datadir alive for a restart: the node
    /// exits first (no shared storage), then custody of the `TempDir` moves
    /// to the caller.
    pub fn stop_keep_datadir(mut self) -> Result<TempDir> {
        self.stop_process()?;
        self.finish_output();
        self.take_datadir()
    }

    fn stop_process(&mut self) -> Result<()> {
        match self.kind {
            Kind::Core => {
                if let Err(error) = self.rpc("stop", &json!([])) {
                    eprintln!("core stop rpc: {error}");
                }
            }
            Kind::BitcoinRs => self.send_sigterm(),
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }

    /// Ask the process for its current exit status.
    pub fn exited(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child.try_wait().map_err(Error::Io)
    }

    /// Send SIGTERM to the child.
    pub fn send_sigterm(&self) {
        let pid = self.pid().to_string();
        let _ = Command::new("kill").args(["-TERM", pid.as_str()]).status();
    }

    /// Send SIGKILL to the child.
    pub fn send_sigkill(&self) {
        let pid = self.pid().to_string();
        let _ = Command::new("kill").args(["-KILL", pid.as_str()]).status();
    }

    fn finish_output(&mut self) {
        for reader in self.output.drain(..) {
            let _ = reader.join();
        }
    }
}

impl Drop for ProcessNode {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.finish_output();
    }
}

fn capture_output(mut reader: impl Read + Send + 'static, file: PathBuf) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let Ok(mut file) = File::create(&file) else {
            return;
        };
        let mut retained = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let keep = usize::try_from(
                        u64::try_from(count)
                            .unwrap_or(0)
                            .min(MAX_OUTPUT.saturating_sub(retained)),
                    )
                    .unwrap_or(0);
                    let _ = file.write_all(buffer.get(..keep).unwrap_or(&[]));
                    retained = retained.saturating_add(u64::try_from(keep).unwrap_or(0));
                }
            }
        }
        let _ = file.flush();
    })
}

fn rpc_call(addr: SocketAddr, request: &Value, timeout: Duration) -> Result<Value> {
    let body = serde_json::to_vec(request)?;
    let response = http_exchange(
        addr,
        "POST",
        "/",
        &body,
        Some((AUTH_USER, AUTH_PASSWORD)),
        timeout,
    )?;
    let reply = response.json()?;
    if let Some(error) = reply.get("error").filter(|e| !e.is_null()) {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::Assertion("rpc error lacks numeric code".into()))?;
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_owned();
        return Err(Error::Rpc {
            method,
            code,
            message,
        });
    }
    reply
        .get("result")
        .cloned()
        .ok_or_else(|| Error::Assertion(format!("missing rpc result in {reply}")))
}

fn http_exchange(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    auth: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<HttpResponse> {
    let mut wire = Vec::new();
    write!(wire, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n")?;
    if let Some((user, password)) = auth {
        let token = base64(&format!("{user}:{password}").into_bytes());
        write!(wire, "Authorization: Basic {token}\r\n")?;
    }
    if !body.is_empty() {
        write!(wire, "Content-Type: application/json\r\n")?;
    }
    write!(
        wire,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    wire.extend_from_slice(body);
    if wire.len() > MAX_BODY {
        return Err(Error::Assertion("request exceeds body bound".into()));
    }
    let mut stream = TcpStream::connect_timeout(&addr, timeout.min(Duration::from_secs(2)))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&wire)?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_BODY {
            return Err(Error::Assertion("response exceeds body bound".into()));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    parse_http_reply(&bytes)
}

fn parse_http_reply(bytes: &[u8]) -> Result<HttpResponse> {
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Assertion("missing HTTP header terminator".into()))?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|e| Error::Assertion(format!("invalid HTTP head: {e}")))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| Error::Assertion(format!("invalid status line: {status_line}")))?;
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_lowercase();
        let value = value.trim().to_owned();
        if name == "content-length" {
            content_length = value.parse::<usize>().ok();
        }
        headers.push((name, value));
    }
    let body = bytes[split + 4..].to_vec();
    if let Some(length) = content_length {
        if length != body.len() {
            return Err(Error::Assertion(format!(
                "content-length {length} != body {}",
                body.len()
            )));
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        let pick = |bits: u32| char::from(TABLE[usize::try_from(bits & 63).unwrap_or(0)]);
        out.push(pick(n >> 18));
        out.push(pick(n >> 12));
        out.push(if chunk.len() > 1 { pick(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { pick(n) } else { '=' });
    }
    out
}
