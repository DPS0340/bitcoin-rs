//! Behavioral tests for the G14 systemd resource guard.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, MutexGuard};
use serde_json::Value;

const BREACH_EXIT: i32 = 75;

#[test]
fn setsid_descendant_rss_breach_kills_tree_and_deletes_fixture()
-> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let pid_path = temp.path().join("descendant.pid");
    let allocator = temp.path().join("allocate.py");
    fs::write(
        &allocator,
        r#"import os
import pathlib
import sys
import time

pid_path = pathlib.Path(sys.argv[1])
fixture = pathlib.Path(sys.argv[2])
pid_path.write_text(str(os.getpid()), encoding="ascii")
fixture.mkdir()
memory = bytearray(32 * 1024 * 1024)
for offset in range(0, len(memory), 4096):
    memory[offset] = 1
time.sleep(30)
"#,
    )?;
    let launcher = temp.path().join("launch.sh");
    fs::write(
        &launcher,
        r#"#!/bin/sh
/usr/bin/setsid /usr/bin/python3 "$1" "$2" "$3" &
child=$!
wait "$child"
"#,
    )?;

    let run = GuardRun::new(temp.path(), fixture.clone(), unique_unit("rss"));
    let output = run.execute(
        1 << 30,
        24 << 20,
        &[
            "/bin/sh".as_ref(),
            launcher.as_os_str(),
            allocator.as_os_str(),
            pid_path.as_os_str(),
            fixture.as_os_str(),
        ],
    )?;

    assert_eq!(
        output.status.code(),
        Some(BREACH_EXIT),
        "{}",
        diagnostics(&output)
    );
    assert!(!fixture.exists());
    let descendant_pid: u32 = fs::read_to_string(pid_path)?.parse()?;
    assert!(!Path::new(&format!("/proc/{descendant_pid}")).exists());
    let verdict = run.verdict()?;
    assert_eq!(verdict["breach_reason"], "aggregate-rss");
    assert_eq!(verdict["exit_code"], BREACH_EXIT);
    let aggregate_rss = verdict["aggregate_max_rss_bytes"]
        .as_u64()
        .ok_or("aggregate_max_rss_bytes must be an unsigned integer")?;
    assert!(aggregate_rss >= 24 << 20);
    Ok(())
}

#[test]
fn sighup_stops_unit_kills_descendant_and_writes_failure_verdict()
-> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let pid_path = temp.path().join("descendant.pid");
    let sleeper = temp.path().join("sleep.py");
    fs::write(
        &sleeper,
        r#"import os
import pathlib
import sys
import time
pid_path = pathlib.Path(sys.argv[1])
pending_pid_path = pid_path.with_suffix(".tmp")
pending_pid_path.write_text(str(os.getpid()), encoding="ascii")
pending_pid_path.replace(pid_path)
pathlib.Path(sys.argv[2]).mkdir()
time.sleep(30)
"#,
    )?;
    let launcher = temp.path().join("launch.sh");
    fs::write(
        &launcher,
        r#"#!/bin/sh
/usr/bin/setsid /usr/bin/python3 "$1" "$2" "$3" &
child=$!
wait "$child"
"#,
    )?;

    let run = GuardRun::new(temp.path(), fixture.clone(), unique_unit("sighup"));
    let guard = run.spawn(
        1 << 30,
        1 << 40,
        &[
            "/bin/sh".as_ref(),
            launcher.as_os_str(),
            sleeper.as_os_str(),
            pid_path.as_os_str(),
            fixture.as_os_str(),
        ],
    )?;
    assert!(wait_for_path(&pid_path, Duration::from_secs(5)));
    let descendant_pid: u32 = fs::read_to_string(&pid_path)?.parse()?;
    let kill = Command::new("/bin/kill")
        .args(["-HUP", &guard.id().to_string()])
        .status()?;
    assert!(kill.success());
    let output = guard.wait_with_output()?;

    let fixture_removed = !fixture.exists();
    let descendant_dead = !Path::new(&format!("/proc/{descendant_pid}")).exists();
    let load_state = unit_load_state(&run.unit)?;
    if load_state != "not-found" {
        Command::new("systemctl")
            .args([
                "--user",
                "--no-pager",
                "stop",
                &format!("{}.service", run.unit),
            ])
            .status()?;
        Command::new("systemctl")
            .args([
                "--user",
                "--no-pager",
                "reset-failed",
                &format!("{}.service", run.unit),
            ])
            .status()?;
    }

    assert_eq!(output.status.code(), Some(129), "{}", diagnostics(&output));
    assert!(fixture_removed);
    assert!(descendant_dead);
    assert_eq!(load_state, "not-found");
    let verdict = run.verdict()?;
    assert_eq!(verdict["exit_code"], 129);
    assert_eq!(verdict["breach_reason"], "signal");
    Ok(())
}

#[test]
fn fixture_size_breach_deletes_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let writer = temp.path().join("write_fixture.py");
    fs::write(
        &writer,
        r#"import pathlib
import sys
import time
pathlib.Path(sys.argv[1]).write_bytes(b"x" * 4096)
time.sleep(30)
"#,
    )?;
    let run = GuardRun::new(temp.path(), fixture.clone(), unique_unit("size"));
    let output = run.execute(
        1024,
        1 << 40,
        &[
            "/usr/bin/python3".as_ref(),
            writer.as_os_str(),
            fixture.as_os_str(),
        ],
    )?;

    assert_eq!(
        output.status.code(),
        Some(BREACH_EXIT),
        "{}",
        diagnostics(&output)
    );
    assert!(!fixture.exists());
    let verdict = run.verdict()?;
    assert_eq!(verdict["breach_reason"], "fixture-size");
    let peak_fixture_bytes = verdict["peak_fixture_bytes"]
        .as_u64()
        .ok_or("peak_fixture_bytes must be an unsigned integer")?;
    assert!(peak_fixture_bytes > 1024);
    Ok(())
}

#[test]
fn insufficient_space_preflight_never_starts_command() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let marker = temp.path().join("started");
    let run = GuardRun::new(temp.path(), fixture, unique_unit("space"));
    let command = format!("printf started > '{}'", marker.display());
    let output = run.execute_with_reserve(
        u64::MAX,
        1,
        1 << 40,
        &["/bin/sh".as_ref(), "-c".as_ref(), command.as_ref()],
    )?;

    assert_eq!(output.status.code(), Some(2), "{}", diagnostics(&output));
    assert!(!marker.exists());
    assert!(!run.verdict_path().exists());
    Ok(())
}

#[test]
fn existing_output_preflight_never_starts_command() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let marker = temp.path().join("started");
    let run = GuardRun::new(temp.path(), fixture.clone(), unique_unit("output"));
    fs::write(&run.stdout, "existing custody\n")?;
    let command = format!("printf started > '{}'", marker.display());

    let output = run.execute(
        1024,
        1 << 40,
        &["/bin/sh".as_ref(), "-c".as_ref(), command.as_ref()],
    )?;

    assert_eq!(output.status.code(), Some(2), "{}", diagnostics(&output));
    assert!(!marker.exists());
    assert!(!fixture.exists());
    assert_eq!(fs::read_to_string(&run.stdout)?, "existing custody\n");
    assert!(!run.verdict_path().exists());
    Ok(())
}

#[test]
fn aliased_custody_paths_never_start_command() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let marker = temp.path().join("started");
    let mut run = GuardRun::new(temp.path(), fixture.clone(), unique_unit("alias"));
    run.stderr = run.verdict_path();
    let command = format!("printf started > '{}'", marker.display());

    let output = run.execute(
        1024,
        1 << 40,
        &["/bin/sh".as_ref(), "-c".as_ref(), command.as_ref()],
    )?;

    assert_eq!(output.status.code(), Some(2), "{}", diagnostics(&output));
    assert!(!marker.exists());
    assert!(!fixture.exists());
    assert!(!run.stdout.exists());
    assert!(!run.stderr.exists());
    Ok(())
}

#[test]
fn success_leaves_fixture_and_writes_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let writer = temp.path().join("succeed.py");
    fs::write(
        &writer,
        r#"import pathlib
import sys
pathlib.Path(sys.argv[1]).write_bytes(b"kept")
print("guarded stdout")
print("guarded stderr", file=sys.stderr)
"#,
    )?;
    let run = GuardRun::new(temp.path(), fixture.clone(), unique_unit("success"));
    let output = run.execute(
        1024,
        1 << 40,
        &[
            "/usr/bin/python3".as_ref(),
            writer.as_os_str(),
            fixture.as_os_str(),
            "--rpc-password=bench-secret".as_ref(),
        ],
    )?;

    assert!(output.status.success(), "{}", diagnostics(&output));
    assert_eq!(fs::read(&fixture)?, b"kept");
    assert_eq!(fs::read_to_string(&run.stdout)?, "guarded stdout\n");
    assert_eq!(fs::read_to_string(&run.stderr)?, "guarded stderr\n");
    assert_eq!(
        fs::metadata(&run.stdout)?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&run.stderr)?.permissions().mode() & 0o777,
        0o600
    );
    let verdict = run.verdict()?;
    assert_eq!(verdict["schema"], "bitcoin-rs-disk-guard-v2");
    assert_eq!(verdict["exit_code"], 0);
    assert!(verdict["breach_reason"].is_null());
    assert_eq!(verdict["peak_fixture_bytes"], 4);
    assert_eq!(verdict["unit_name"], run.unit);
    let verdict_raw = fs::read_to_string(run.verdict_path())?;
    assert!(!verdict_raw.contains("bench-secret"));
    let command_sha256 = verdict["command_sha256"]
        .as_str()
        .ok_or("command_sha256 must be a string")?
        .to_owned();
    assert_eq!(command_sha256.len(), 64);
    assert_eq!(
        fs::metadata(run.verdict_path())?.permissions().mode() & 0o777,
        0o600
    );
    Ok(())
}

#[test]
fn command_digest_redacts_secrets_but_binds_other_arguments()
-> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let writer = temp.path().join("digest.py");
    fs::write(
        &writer,
        r#"import pathlib
import sys
pathlib.Path(sys.argv[1]).write_bytes(b"digest")
"#,
    )?;

    let first = guarded_command_digest(
        temp.path(),
        &fixture,
        &writer,
        "digest-first",
        "first-secret",
        None,
    )?;
    let second = guarded_command_digest(
        temp.path(),
        &fixture,
        &writer,
        "digest-second",
        "second-secret",
        None,
    )?;
    let variant = guarded_command_digest(
        temp.path(),
        &fixture,
        &writer,
        "digest-variant",
        "second-secret",
        Some("--non-secret-variant"),
    )?;

    assert_eq!(first, second);
    assert_ne!(first, variant);
    Ok(())
}

#[test]
fn repeated_unit_teardown_never_becomes_guard_error() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    for iteration in 0..64 {
        let root = temp.path().join(iteration.to_string());
        fs::create_dir(&root)?;
        let run = GuardRun::new(&root, root.join("fixture"), unique_unit("rapid-exit"));
        let output = run.execute(1024, 1 << 40, &["/bin/sleep".as_ref(), "0.05".as_ref()])?;
        assert!(output.status.success(), "{}", diagnostics(&output));
        let verdict = run.verdict()?;
        assert_eq!(verdict["exit_code"], 0);
        assert!(verdict["breach_reason"].is_null());
    }
    Ok(())
}

#[test]
fn disappearing_cgroup_member_is_not_a_guard_error() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    fs::write(
        temp.path().join("sitecustomize.py"),
        r#"import errno
from pathlib import Path

original_open = Path.open
injected = False

def open_with_enodev(path, *args, **kwargs):
    global injected
    if not injected and path.name == "cgroup.procs":
        injected = True
        raise OSError(errno.ENODEV, "injected cgroup teardown")
    return original_open(path, *args, **kwargs)

Path.open = open_with_enodev
"#,
    )?;
    let run = GuardRun::new(
        temp.path(),
        temp.path().join("fixture"),
        unique_unit("enodev"),
    );
    let output = run
        .command(1024, 0, 1 << 40, &["/bin/sleep".as_ref(), "0.05".as_ref()])
        .env("PYTHONPATH", temp.path())
        .output()?;

    assert!(output.status.success(), "{}", diagnostics(&output));
    let verdict = run.verdict()?;
    assert_eq!(verdict["exit_code"], 0);
    assert!(verdict["breach_reason"].is_null());
    Ok(())
}

#[test]
fn child_failure_removes_fixture_and_propagates_status() -> Result<(), Box<dyn std::error::Error>> {
    let _systemd_user_units = lock_systemd_user_units()?;

    let temp = tempfile::tempdir()?;
    let fixture = temp.path().join("fixture");
    let writer = temp.path().join("fail.py");
    fs::write(
        &writer,
        r#"import pathlib
import sys
pathlib.Path(sys.argv[1]).write_bytes(b"discard")
raise SystemExit(23)
"#,
    )?;
    let run = GuardRun::new(temp.path(), fixture.clone(), unique_unit("failure"));
    let output = run.execute(
        1024,
        1 << 40,
        &[
            "/usr/bin/python3".as_ref(),
            writer.as_os_str(),
            fixture.as_os_str(),
        ],
    )?;

    assert_eq!(output.status.code(), Some(23), "{}", diagnostics(&output));
    assert!(!fixture.exists());
    let verdict = run.verdict()?;
    assert_eq!(verdict["exit_code"], 23);
    assert!(verdict["breach_reason"].is_null());
    Ok(())
}

struct GuardRun {
    fixture: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
    unit: String,
}

impl GuardRun {
    fn new(root: &Path, fixture: PathBuf, unit: String) -> Self {
        Self {
            fixture,
            stdout: root.join("command.stdout"),
            stderr: root.join("command.stderr"),
            unit,
        }
    }

    fn execute(
        &self,
        max_fixture_bytes: u64,
        max_rss_bytes: u64,
        command: &[&std::ffi::OsStr],
    ) -> std::io::Result<Output> {
        self.execute_with_reserve(max_fixture_bytes, 0, max_rss_bytes, command)
    }

    fn spawn(
        &self,
        max_fixture_bytes: u64,
        max_rss_bytes: u64,
        command: &[&std::ffi::OsStr],
    ) -> std::io::Result<Child> {
        self.command(max_fixture_bytes, 0, max_rss_bytes, command)
            .spawn()
    }

    fn execute_with_reserve(
        &self,
        max_fixture_bytes: u64,
        reserve_bytes: u64,
        max_rss_bytes: u64,
        command: &[&std::ffi::OsStr],
    ) -> std::io::Result<Output> {
        self.command(max_fixture_bytes, reserve_bytes, max_rss_bytes, command)
            .output()
    }

    fn command(
        &self,
        max_fixture_bytes: u64,
        reserve_bytes: u64,
        max_rss_bytes: u64,
        command: &[&std::ffi::OsStr],
    ) -> Command {
        let mut process = Command::new("bash");
        process
            .arg(script_path())
            .arg("--fixture")
            .arg(&self.fixture)
            .arg("--max-fixture-bytes")
            .arg(max_fixture_bytes.to_string())
            .arg("--reserve-bytes")
            .arg(reserve_bytes.to_string())
            .arg("--max-rss-bytes")
            .arg(max_rss_bytes.to_string())
            .arg("--interval-seconds")
            .arg("0.05")
            .arg("--stdout")
            .arg(&self.stdout)
            .arg("--stderr")
            .arg(&self.stderr)
            .arg("--unit-name")
            .arg(&self.unit)
            .arg("--")
            .args(command);
        process
    }

    fn verdict_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.guard.json", self.stdout.display()))
    }

    fn verdict(&self) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(&fs::read(self.verdict_path())?)?)
    }
}

fn guarded_command_digest(
    root: &Path,
    fixture: &Path,
    writer: &Path,
    unit_case: &str,
    password: &str,
    variant: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let run = GuardRun::new(root, fixture.to_path_buf(), unique_unit(unit_case));
    let password_argument = format!("--rpc-password={password}");
    let mut command: Vec<&std::ffi::OsStr> = vec![
        "/usr/bin/python3".as_ref(),
        writer.as_os_str(),
        fixture.as_os_str(),
        password_argument.as_ref(),
    ];
    if let Some(argument) = variant {
        command.push(argument.as_ref());
    }
    let output = run.execute(1024, 1 << 40, &command)?;
    if !output.status.success() {
        return Err(diagnostics(&output).into());
    }
    let verdict = run.verdict()?;
    let digest = verdict["command_sha256"]
        .as_str()
        .ok_or("command_sha256 must be a string")?
        .to_owned();
    fs::remove_file(fixture)?;
    fs::remove_file(&run.stdout)?;
    fs::remove_file(&run.stderr)?;
    fs::remove_file(run.verdict_path())?;
    Ok(digest)
}

fn lock_systemd_user_units() -> Result<MutexGuard<'static, ()>, Box<dyn std::error::Error>> {
    static PROBE: LazyLock<Result<(), String>> = LazyLock::new(|| {
        let unit = unique_unit("probe");
        match Command::new("systemd-run")
            .args([
                "--user",
                "--wait",
                "--collect",
                "--quiet",
                &format!("--unit={unit}"),
                "--",
                "/bin/true",
            ])
            .output()
        {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(format!(
                "systemd user unit probe failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )),
            Err(error) => Err(format!("systemd user unit probe failed: {error}")),
        }
    });
    static SYSTEMD_USER_UNITS: Mutex<()> = Mutex::new(());
    if let Err(message) = &*PROBE {
        return Err(message.clone().into());
    }
    Ok(SYSTEMD_USER_UNITS.lock())
}

fn unique_unit(case: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("g14_guard_{case}_{}_{nanos}", std::process::id())
}

fn script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/run-g14-guarded.sh")
}

fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

fn unit_load_state(unit: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("systemctl")
        .args([
            "--user",
            "--no-pager",
            "show",
            &format!("{unit}.service"),
            "--property=LoadState",
            "--value",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "systemctl show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn diagnostics(output: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
