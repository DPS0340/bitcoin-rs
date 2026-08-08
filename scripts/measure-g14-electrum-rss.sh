#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: measure-g14-electrum-rss.sh --output <measurement.json> --host <host> --port <port> --pid <bitcoin-rs-pid> --tip-height <height> --tip-hash <64-hex> --scripthashes <path> [--sample-size <n>] [--seed <seed>] [--timeout-seconds <seconds>]' \
    '' \
    'Measures the G14 Electrum get_history p95 and bitcoin-rs RSS budget inputs against a running mainnet-tip bitcoin-rs Electrum endpoint.' \
    'The helper does not start bitcoin-rs and does not mutate node state.' \
    'The scripthash corpus must contain real 64-hex Electrum scripthashes, one per line.' \
    'It writes a JSON fragment with electrum_get_history_p95_ms and rss_bytes keys consumable by the G14 evidence manifest flow.' \
    '' \
    'Defaults: --sample-size 10000 --seed g14-electrum-rss-v1 --timeout-seconds 30'
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

python3 - "$@" <<'PY'
import argparse
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import struct
import sys
import time

SCHEMA = "g14-electrum-rss-measurement-v1"
SMOKE_SCHEMA = "g14-electrum-rss-smoke-v1"
METHOD = "blockchain.scripthash.get_history"
SUBSCRIBE_METHOD = "blockchain.headers.subscribe"
TCP_ESTABLISHED_STATE = 0x01
ACCEPTED_CONNECTION_PROOF_POLL_SECONDS = 0.01
HEADER_BYTES = 80


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def positive_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        die(f"{name} must be a positive integer: {error}")
    if number <= 0:
        die(f"{name} must be positive")
    return number


def non_negative_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        die(f"{name} must be a non-negative integer: {error}")
    if number < 0:
        die(f"{name} must be non-negative")
    return number


def positive_float(value: str, name: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        die(f"{name} must be a finite positive number: {error}")
    if not math.isfinite(number) or number <= 0.0:
        die(f"{name} must be finite and positive")
    return number


def require_hex(value: str, length: int, name: str) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        die(f"{name} must be {length} lowercase hex characters")
    return value


def rss_bytes(pid: int) -> int:
    status_path = Path(f"/proc/{pid}/status")
    try:
        lines = status_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        die(f"--pid does not expose {status_path}")
    except UnicodeDecodeError as error:
        die(f"{status_path} must be UTF-8: {error}")
    for line in lines:
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) < 2:
                die(f"{status_path} VmRSS line is malformed")
            return positive_int(parts[1], f"{status_path} VmRSS KiB") * 1024
    die(f"{status_path} does not contain VmRSS")


def process_basename(value: str) -> str:
    return Path(value).name


def process_identity(pid: int) -> dict[str, str | bool]:
    exe_path = Path(f"/proc/{pid}/exe")
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    exe_name = ""
    argv0_name = ""
    try:
        exe_name = process_basename(str(exe_path.readlink()))
    except OSError:
        pass
    try:
        cmdline = cmdline_path.read_bytes().split(b"\0")
    except OSError:
        cmdline = []
    if cmdline and cmdline[0]:
        try:
            argv0_name = process_basename(cmdline[0].decode("utf-8"))
        except UnicodeDecodeError:
            argv0_name = "<non-utf8>"
    return {
        "matches_bitcoin_rs": exe_name == "bitcoin-rs" or argv0_name == "bitcoin-rs",
        "exe_basename": exe_name,
        "argv0_basename": argv0_name,
    }


def resolve_loopback_only(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        die(f"--host must resolve for production evidence: {error}")
    if not infos:
        die("--host must resolve to at least one address for production evidence")
    addresses: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        raw = sockaddr[0]
        if not isinstance(raw, str):
            die(f"--host resolved to a non-string address: {raw!r}")
        candidate = raw.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            die(f"--host resolved to a non-IP address: {candidate!r}")
        if not ip.is_loopback:
            die(
                "--host must resolve only to loopback addresses for production evidence "
                f"(got {ip})"
            )
        text = str(ip)
        if text not in addresses:
            addresses.append(text)
    if not addresses:
        die("--host must resolve only to loopback addresses for production evidence")
    return addresses


def proc_net_ip(hex_ip: str, *, ipv6: bool) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        if ipv6:
            if len(hex_ip) != 32 or any(ch not in "0123456789abcdefABCDEF" for ch in hex_ip):
                raise ValueError(f"expected 32 hex digits, got {hex_ip!r}")
            packed = b"".join(
                struct.pack("<I", int(hex_ip[index : index + 8], 16))
                for index in range(0, 32, 8)
            )
            return ipaddress.IPv6Address(socket.inet_ntop(socket.AF_INET6, packed))
        if len(hex_ip) != 8 or any(ch not in "0123456789abcdefABCDEF" for ch in hex_ip):
            raise ValueError(f"expected 8 hex digits, got {hex_ip!r}")
        packed = struct.pack("<I", int(hex_ip, 16))
        return ipaddress.IPv4Address(socket.inet_ntoa(packed))
    except (OSError, struct.error, ValueError) as error:
        raise ValueError(str(error)) from error


def normalize_ipaddress(
    value: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(value, ipaddress.IPv6Address):
        mapped = value.ipv4_mapped
        if mapped is not None:
            return mapped
    return value


def ip_addresses_equivalent(
    left: ipaddress.IPv4Address | ipaddress.IPv6Address,
    right: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return normalize_ipaddress(left) == normalize_ipaddress(right)


def parse_proc_net_endpoint(
    endpoint: str,
    *,
    ipv6: bool,
    path: Path,
    label: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    if ":" not in endpoint:
        die(f"{path} is malformed: {label} address missing port separator")
    ip_hex, port_text = endpoint.rsplit(":", 1)
    try:
        port = int(port_text, 16)
        ip = proc_net_ip(ip_hex, ipv6=ipv6)
    except ValueError as error:
        die(f"{path} is malformed: cannot parse {label} endpoint: {error}")
    return ip, port


def process_socket_inodes(pid: int) -> set[int]:
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        entries = list(fd_dir.iterdir())
    except FileNotFoundError:
        die(f"--pid does not expose {fd_dir}")
    except OSError as error:
        die(f"--pid fd table is unreadable: {error}")
    inodes: set[int] = set()
    for entry in entries:
        try:
            target = str(entry.readlink())
        except OSError:
            continue
        if not target.startswith("socket:[") or not target.endswith("]"):
            continue
        inode_text = target[len("socket:[") : -1]
        try:
            inode = int(inode_text)
        except ValueError:
            continue
        if inode > 0:
            inodes.add(inode)
    return inodes


def connect_resolved_loopback(
    addresses: list[str], port: int, timeout_seconds: float
) -> socket.socket:
    errors: list[str] = []
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=timeout_seconds)
        except OSError as error:
            errors.append(f"{address}:{port}: {error}")
    detail = "; ".join(errors) if errors else "no resolved addresses"
    die(f"failed to connect through an explicit resolved loopback address: {detail}")


def sockname_endpoint(
    sock: socket.socket,
    *,
    which: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    try:
        endpoint = sock.getsockname() if which == "local" else sock.getpeername()
    except OSError as error:
        die(f"connected Electrum socket {which} address is unavailable: {error}")
    if not isinstance(endpoint, tuple) or len(endpoint) < 2:
        die(f"connected Electrum socket {which} address is missing")
    raw_ip, raw_port = endpoint[0], endpoint[1]
    if not isinstance(raw_ip, str):
        die(f"connected Electrum socket {which} address is non-string: {raw_ip!r}")
    if not isinstance(raw_port, int) or isinstance(raw_port, bool):
        die(f"connected Electrum socket {which} port is non-integer: {raw_port!r}")
    if raw_port <= 0 or raw_port > 65535:
        die(f"connected Electrum socket {which} port is out of range: {raw_port}")
    candidate = raw_ip.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        die(f"connected Electrum socket {which} address is not an IP: {candidate!r}")
    return ip, raw_port


def connected_client_endpoints(
    sock: socket.socket,
) -> tuple[
    ipaddress.IPv4Address | ipaddress.IPv6Address,
    int,
    ipaddress.IPv4Address | ipaddress.IPv6Address,
    int,
]:
    local_ip, local_port = sockname_endpoint(sock, which="local")
    peer_ip, peer_port = sockname_endpoint(sock, which="peer")
    if not normalize_ipaddress(peer_ip).is_loopback:
        die(f"connected Electrum socket peer must be loopback (got {peer_ip})")
    if not normalize_ipaddress(local_ip).is_loopback:
        die(f"connected Electrum socket local address must be loopback (got {local_ip})")
    return local_ip, local_port, peer_ip, peer_port


def established_socket_inodes_for_connection(
    pid: int,
    client_local_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    client_local_port: int,
    client_peer_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    client_peer_port: int,
) -> tuple[set[int], int]:
    """Find ESTABLISHED inodes whose endpoints match the client's connection.

    Server-side local endpoint must equal the client's peer endpoint, and
    server-side remote endpoint must equal the client's local endpoint.
    Searches both tcp and tcp6 so dual-stack IPv6 wildcard listeners that
    accept IPv4-mapped loopback clients are visible.
    """
    inodes: set[int] = set()
    tables_seen = 0
    unaccepted = 0
    for table, ipv6 in (("tcp", False), ("tcp6", True)):
        path = Path(f"/proc/{pid}/net/{table}")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        except OSError as error:
            die(f"{path} is unreadable: {error}")
        except UnicodeDecodeError as error:
            die(f"{path} must be UTF-8: {error}")
        tables_seen += 1
        if not lines:
            die(f"{path} is malformed: empty")
        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 10:
                die(f"{path} is malformed: expected at least 10 fields")
            local_address = parts[1]
            rem_address = parts[2]
            state_text = parts[3]
            inode_text = parts[9]
            try:
                state = int(state_text, 16)
                inode = int(inode_text)
            except ValueError:
                die(f"{path} is malformed: cannot parse socket row fields")
            if state != TCP_ESTABLISHED_STATE:
                continue
            local_ip, local_port = parse_proc_net_endpoint(
                local_address, ipv6=ipv6, path=path, label="local"
            )
            rem_ip, rem_port = parse_proc_net_endpoint(
                rem_address, ipv6=ipv6, path=path, label="remote"
            )
            if local_port != client_peer_port or rem_port != client_local_port:
                continue
            if not ip_addresses_equivalent(local_ip, client_peer_ip):
                continue
            if not ip_addresses_equivalent(rem_ip, client_local_ip):
                continue
            if inode <= 0:
                # The three-way handshake completes before accept(), so the
                # kernel reports the connection ESTABLISHED with inode 0 while
                # it waits in the listen backlog. That is a transient state, not
                # a malformed row, and it cannot weaken the ownership proof: an
                # inode of 0 is in no process fd table, so it could never
                # intersect process_socket_inodes(pid). Report it so the caller
                # keeps polling.
                unaccepted += 1
                continue
            inodes.add(inode)
    if tables_seen == 0:
        die(f"--pid {pid} does not expose /proc/{pid}/net/tcp or /proc/{pid}/net/tcp6")
    return inodes, unaccepted


def require_pid_owns_accepted_connection(
    pid: int, sock: socket.socket, *, timeout_seconds: float
) -> int:
    local_ip, local_port, peer_ip, peer_port = connected_client_endpoints(sock)
    match_inodes: set[int] = set()
    owned: set[int] = set()
    unaccepted = 0
    deadline = time.monotonic() + timeout_seconds
    while True:
        match_inodes, unaccepted = established_socket_inodes_for_connection(
            pid, local_ip, local_port, peer_ip, peer_port
        )
        if match_inodes:
            owned = match_inodes & process_socket_inodes(pid)
            if owned:
                return min(owned)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(ACCEPTED_CONNECTION_PROOF_POLL_SECONDS, remaining))
    endpoint = (
        f"client {normalize_ipaddress(local_ip)}:{local_port} -> "
        f"{normalize_ipaddress(peer_ip)}:{peer_port}"
    )
    if not match_inodes:
        if unaccepted:
            die(
                f"--pid {pid} never accepted the connection ({endpoint}): the kernel "
                f"still reports it ESTABLISHED in the listen backlog with no owning "
                f"file after {timeout_seconds:g}s"
            )
        die(
            f"--pid {pid} has no ESTABLISHED TCP socket matching accepted connection "
            f"({endpoint}) in /proc/{pid}/net/tcp or /proc/{pid}/net/tcp6"
        )
    die(
        f"--pid {pid} does not own the ESTABLISHED socket inode for accepted connection "
        f"({endpoint}) (matching inodes={sorted(match_inodes)})"
    )


def percentile_ms(samples_ns: list[int], numerator: int, denominator: int) -> float:
    if not samples_ns:
        die("cannot calculate percentile for an empty sample")
    index = math.ceil(len(samples_ns) * numerator / denominator) - 1
    index = max(0, min(index, len(samples_ns) - 1))
    return samples_ns[index] / 1_000_000.0


def sampled_scripthash(seed: str, index: int) -> str:
    return hashlib.sha256(f"{seed}:{index}".encode("utf-8")).hexdigest()


def select_scripthash_sample(values: list[str], seed: str, sample_size: int) -> list[str]:
    keyed = sorted(
        values,
        key=lambda value: (
            hashlib.sha256(f"{seed}:{value}".encode("utf-8")).digest(),
            value,
        ),
    )
    return keyed[:sample_size]


def read_scripthash_corpus(path: str) -> list[str]:
    values = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        die(f"--scripthashes is not readable: {path}")
    except UnicodeDecodeError as error:
        die(f"--scripthashes must be UTF-8: {error}")
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        values.append(require_hex(stripped, 64, f"--scripthashes line {line_number}"))
    if not values:
        die("--scripthashes must contain at least one 64-hex scripthash")
    return values


def write_json(path: str, data: dict) -> None:
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if path == "-":
        sys.stdout.write(encoded)
        return
    Path(path).write_text(encoded, encoding="utf-8")


def read_electrum_response(reader, request_id: int, label: str) -> dict:
    while True:
        line = reader.readline()
        if not line:
            die(f"Electrum server closed the connection while waiting for {label}")
        try:
            response = json.loads(line.decode("utf-8"))
        except UnicodeDecodeError as error:
            die(f"Electrum {label} response is not UTF-8: {error}")
        except json.JSONDecodeError as error:
            die(f"Electrum {label} response is not JSON: {error}")
        if not isinstance(response, dict):
            die(f"Electrum {label} response must be a JSON object")
        if "id" not in response or response["id"] is None:
            # Skip unsolicited Electrum notifications (e.g. header updates).
            continue
        if response.get("id") != request_id:
            die(f"Electrum {label} response id mismatch: expected {request_id}")
        if "error" in response and response["error"] is not None:
            die(f"Electrum {label} returned error: {response['error']!r}")
        return response


def electrum_call(reader, writer, request_id: int, method: str, params: list) -> dict:
    request = {
        "id": request_id,
        "method": method,
        "params": params,
    }
    encoded = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
    writer.write(encoded)
    writer.flush()
    return read_electrum_response(reader, request_id, method)


def header_block_hash(header_hex: str) -> str:
    try:
        header = bytes.fromhex(header_hex)
    except ValueError as error:
        die(f"{SUBSCRIBE_METHOD} hex must be valid hexadecimal: {error}")
    if len(header) != HEADER_BYTES:
        die(f"{SUBSCRIBE_METHOD} hex must decode to {HEADER_BYTES} bytes")
    digest = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    return digest[::-1].hex()


def verify_electrum_tip(reader, writer, tip_height: int, tip_hash: str) -> tuple[int, str]:
    response = electrum_call(reader, writer, 0, SUBSCRIBE_METHOD, [])
    result = response.get("result")
    if not isinstance(result, dict):
        die(f"{SUBSCRIBE_METHOD} result must be an object with height and hex")
    if "height" not in result or "hex" not in result:
        die(f"{SUBSCRIBE_METHOD} result must contain height and hex")
    height = result["height"]
    header_hex = result["hex"]
    if not isinstance(height, int) or isinstance(height, bool):
        die(f"{SUBSCRIBE_METHOD} height must be an integer")
    if height < 0:
        die(f"{SUBSCRIBE_METHOD} height must be non-negative")
    if not isinstance(header_hex, str):
        die(f"{SUBSCRIBE_METHOD} hex must be a string")
    observed_hash = header_block_hash(header_hex)
    if height != tip_height:
        die(f"Electrum tip height mismatch: expected {tip_height}, got {height}")
    if observed_hash != tip_hash:
        die(f"Electrum tip hash mismatch: expected {tip_hash}, got {observed_hash}")
    return height, observed_hash


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--help", action="store_true")
parser.add_argument("--output")
parser.add_argument("--host")
parser.add_argument("--port")
parser.add_argument("--pid")
parser.add_argument("--tip-height")
parser.add_argument("--tip-hash")
parser.add_argument("--scripthashes")
parser.add_argument("--sample-size", default="10000")
parser.add_argument("--seed", default="g14-electrum-rss-v1")
parser.add_argument("--timeout-seconds", default="30")
parser.add_argument("--generate-empty-scripthashes-for-smoke-test", action="store_true")
args = parser.parse_args(sys.argv[1:])

if args.help:
    print("""usage: measure-g14-electrum-rss.sh --output <measurement.json> --host <host> --port <port> --pid <bitcoin-rs-pid> --tip-height <height> --tip-hash <64-hex> --scripthashes <path> [--sample-size <n>] [--seed <seed>] [--timeout-seconds <seconds>]""")
    raise SystemExit(0)

for key in ("output", "host", "port", "pid", "tip_height", "tip_hash"):
    if getattr(args, key) is None:
        die(f"--{key.replace('_', '-')} is required")

port = positive_int(args.port, "--port")
if port > 65535:
    die("--port must be <= 65535")
pid = positive_int(args.pid, "--pid")
tip_height = non_negative_int(args.tip_height, "--tip-height")
tip_hash = require_hex(args.tip_hash, 64, "--tip-hash")
sample_size = positive_int(args.sample_size, "--sample-size")
timeout_seconds = positive_float(args.timeout_seconds, "--timeout-seconds")
if not args.seed.strip():
    die("--seed must not be empty")
production_evidence = not args.generate_empty_scripthashes_for_smoke_test
if args.generate_empty_scripthashes_for_smoke_test:
    if args.scripthashes is not None:
        die("--scripthashes cannot be combined with --generate-empty-scripthashes-for-smoke-test")
    scripthashes = [sampled_scripthash(args.seed, index) for index in range(sample_size)]
    corpus_source = "generated-empty-scripthashes-for-smoke-test"
elif args.scripthashes is not None:
    scripthashes = read_scripthash_corpus(args.scripthashes)
    if len(scripthashes) < sample_size:
        die("--scripthashes contains fewer entries than --sample-size")
    scripthashes = select_scripthash_sample(scripthashes, args.seed, sample_size)
    corpus_source = args.scripthashes
else:
    die("--scripthashes is required unless --generate-empty-scripthashes-for-smoke-test is set")
identity = process_identity(pid)
if production_evidence and not identity["matches_bitcoin_rs"]:
    observed = f"exe={identity['exe_basename']!r}, argv0={identity['argv0_basename']!r}"
    die(f"--pid must refer to a bitcoin-rs process for production evidence ({observed})")

resolved_loopback_addresses: list[str] | None = None
accepted_socket_inode: int | None = None
if production_evidence:
    resolved_loopback_addresses = resolve_loopback_only(args.host)

latencies_ns: list[int] = []
non_empty_history_count = 0
rss_high_water = rss_bytes(pid)
started_ns = time.monotonic_ns()

if production_evidence:
    if resolved_loopback_addresses is None:
        die("resolved loopback addresses missing for production evidence")
    sock = connect_resolved_loopback(
        resolved_loopback_addresses, port, timeout_seconds
    )
else:
    sock = socket.create_connection((args.host, port), timeout=timeout_seconds)

with sock:
    sock.settimeout(timeout_seconds)
    if production_evidence:
        if resolved_loopback_addresses is None:
            die("resolved loopback addresses missing for production evidence")
        _local_ip, _local_port, peer_ip, peer_port = connected_client_endpoints(sock)
        if peer_port != port:
            die(
                f"connected Electrum peer port mismatch: expected {port}, got {peer_port}"
            )
        resolved_ips = {
            normalize_ipaddress(ipaddress.ip_address(address))
            for address in resolved_loopback_addresses
        }
        normalized_peer = normalize_ipaddress(peer_ip)
        if normalized_peer not in resolved_ips:
            die(
                f"connected Electrum peer {peer_ip} is not one of the resolved loopback "
                f"addresses {sorted(str(ip) for ip in resolved_ips)}"
            )
        accepted_socket_inode = require_pid_owns_accepted_connection(
            pid, sock, timeout_seconds=timeout_seconds
        )
    reader = sock.makefile("rb")
    writer = sock.makefile("wb")
    verified_tip_height, verified_tip_hash = verify_electrum_tip(
        reader, writer, tip_height, tip_hash
    )
    for index in range(sample_size):
        request_id = index + 1
        before_ns = time.perf_counter_ns()
        response = electrum_call(
            reader,
            writer,
            request_id,
            METHOD,
            [scripthashes[index]],
        )
        elapsed_ns = time.perf_counter_ns() - before_ns
        result = response.get("result")
        if not isinstance(result, list):
            die(f"Electrum response {request_id} result must be an array")
        if result:
            non_empty_history_count += 1
        elif production_evidence:
            die(
                f"Electrum response {request_id} returned empty history for a caller-supplied "
                "scripthash corpus"
            )
        latencies_ns.append(elapsed_ns)
        rss_high_water = max(rss_high_water, rss_bytes(pid))

finished_ns = time.monotonic_ns()
latencies_ns.sort()
rss_final = rss_bytes(pid)
rss_high_water = max(rss_high_water, rss_final)
data = {
    "schema": SMOKE_SCHEMA if args.generate_empty_scripthashes_for_smoke_test else SCHEMA,
    "measurement_kind": "smoke" if args.generate_empty_scripthashes_for_smoke_test else "evidence",
    "method": METHOD,
    "electrum_host": args.host,
    "electrum_port": port,
    "electrum_tip_height": tip_height,
    "electrum_tip_hash": tip_hash,
    "electrum_tip_verified": True,
    "electrum_verified_tip_height": verified_tip_height,
    "electrum_verified_tip_hash": verified_tip_hash,
    "electrum_sample_size": sample_size,
    "electrum_sample_seed": args.seed,
    "electrum_non_empty_history_count": non_empty_history_count,
    "electrum_scripthash_corpus": corpus_source,
    "electrum_scripthash_corpus_sha256": hashlib.sha256(
        ("\n".join(scripthashes[:sample_size]) + "\n").encode("utf-8")
    ).hexdigest(),
    "electrum_get_history_p50_ms": percentile_ms(latencies_ns, 50, 100),
    "electrum_get_history_p95_ms": percentile_ms(latencies_ns, 95, 100),
    "electrum_get_history_p99_ms": percentile_ms(latencies_ns, 99, 100),
    "electrum_get_history_min_ms": latencies_ns[0] / 1_000_000.0,
    "electrum_get_history_max_ms": latencies_ns[-1] / 1_000_000.0,
    "electrum_measurement_elapsed_seconds": (finished_ns - started_ns) / 1_000_000_000.0,
    "rss_bytes": rss_high_water,
    "rss_final_bytes": rss_final,
    "rss_pid": pid,
    "rss_pid_argv0_basename": identity["argv0_basename"],
    "rss_pid_exe_basename": identity["exe_basename"],
    "rss_source": f"/proc/{pid}/status VmRSS",
}
if resolved_loopback_addresses is not None:
    data["electrum_resolved_loopback_addresses"] = resolved_loopback_addresses
if accepted_socket_inode is not None:
    data["electrum_accepted_socket_inode"] = accepted_socket_inode
write_json(args.output, data)
PY
