use std::cmp::{Ordering, Reverse};
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_p2p::discovery::{DiscoveredPeer, is_routable};
use bitcoin_rs_p2p::{BannedSubnet, subnet};
use hashbrown::{HashMap, HashSet};

use crate::Network;

const ADDRESS_BOOK_CAPACITY: usize = 4_096;
const ADDRESS_BOOK_FILE: &str = "peers.tsv";
const ADDRESS_BOOK_FORMAT: &str = "bitcoin-rs-peers-v1";
const INITIAL_FAILURE_BACKOFF: Duration = Duration::from_mins(1);
const MAX_FAILURE_BACKOFF: Duration = Duration::from_hours(1);
const RECENT_SUCCESS_AGE: Duration = Duration::from_hours(24 * 7);
const FRESH_ANNOUNCEMENT_AGE: Duration = Duration::from_hours(24 * 30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AddressSource {
    Dns,
    Peer,
}

#[derive(Debug)]
pub(super) enum AddressBookLoadWarning {
    Io(io::ErrorKind),
    InvalidHeader,
    NetworkMismatch,
}

pub(super) struct CandidateFilter<'a> {
    pub now: SystemTime,
    pub active: &'a HashSet<SocketAddr>,
    pub queued: &'a HashSet<SocketAddr>,
    pub banned: &'a [BannedSubnet],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AddressEntry {
    addr: SocketAddr,
    services: Option<ServiceFlags>,
    source: AddressSource,
    last_seen: SystemTime,
    last_success: Option<SystemTime>,
    consecutive_failures: u32,
    next_eligible: Option<SystemTime>,
}

pub(super) struct AddressBook {
    path: PathBuf,
    network: Network,
    entries: HashMap<SocketAddr, AddressEntry>,
    dirty: bool,
}

impl AddressBook {
    pub(super) fn load(
        data_dir: &Path,
        network: Network,
    ) -> (Self, Option<AddressBookLoadWarning>) {
        let mut book = Self::empty(data_dir, network);
        let encoded = match fs::read_to_string(&book.path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return (book, None),
            Err(error) => return (book, Some(AddressBookLoadWarning::Io(error.kind()))),
        };
        let mut lines = encoded.lines();
        let Some(header) = lines.next() else {
            return (book, Some(AddressBookLoadWarning::InvalidHeader));
        };
        let Some((format, persisted_network)) = header.split_once('\t') else {
            return (book, Some(AddressBookLoadWarning::InvalidHeader));
        };
        if format != ADDRESS_BOOK_FORMAT {
            return (book, Some(AddressBookLoadWarning::InvalidHeader));
        }
        if persisted_network != network_name(network) {
            return (book, Some(AddressBookLoadWarning::NetworkMismatch));
        }

        for line in lines {
            if let Some(entry) = parse_entry(line) {
                book.insert_loaded(entry);
            }
        }
        book.dirty = false;
        (book, None)
    }

    fn empty(data_dir: &Path, network: Network) -> Self {
        Self {
            path: data_dir.join(ADDRESS_BOOK_FILE),
            network,
            entries: HashMap::with_capacity(ADDRESS_BOOK_CAPACITY),
            dirty: false,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub(super) fn record_dns(&mut self, addr: SocketAddr, now: SystemTime) {
        self.record_candidate(addr, None, AddressSource::Dns, now);
    }

    pub(super) fn record_announcement(&mut self, peer: DiscoveredPeer, now: SystemTime) {
        let announced_at = UNIX_EPOCH + Duration::from_secs(u64::from(peer.seen_at));
        self.record_candidate(
            peer.addr,
            Some(peer.services),
            AddressSource::Peer,
            announced_at.min(now),
        );
    }

    pub(super) fn record_handshake(
        &mut self,
        addr: SocketAddr,
        services: ServiceFlags,
        now: SystemTime,
    ) {
        self.record_candidate(addr, Some(services), AddressSource::Dns, now);
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.last_success = Some(now);
            entry.consecutive_failures = 0;
            entry.next_eligible = None;
            self.dirty = true;
        }
    }

    pub(super) fn record_failure(&mut self, addr: SocketAddr, now: SystemTime) {
        let Some(entry) = self.entries.get_mut(&addr) else {
            return;
        };
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.next_eligible = Some(now + failure_backoff(entry.consecutive_failures));
        self.dirty = true;
    }

    pub(super) fn eligible_count(&self, filter: &CandidateFilter<'_>) -> usize {
        self.entries
            .values()
            .filter(|entry| is_eligible(entry, filter))
            .count()
    }

    pub(super) fn select(&self, limit: usize, filter: &CandidateFilter<'_>) -> Vec<SocketAddr> {
        if limit == 0 {
            return Vec::new();
        }
        let mut candidates: Vec<&AddressEntry> = self
            .entries
            .values()
            .filter(|entry| is_eligible(entry, filter))
            .collect();
        candidates.sort_unstable_by(|left, right| candidate_order(left, right, filter.now));

        let mut selected = Vec::with_capacity(limit.min(candidates.len()));
        let mut deferred = Vec::new();
        let mut groups = HashSet::with_capacity(candidates.len());
        for entry in candidates {
            if groups.insert(network_group(entry.addr.ip())) && selected.len() < limit {
                selected.push(entry.addr);
            } else {
                deferred.push(entry.addr);
            }
        }
        if selected.len() < limit {
            selected.extend(deferred.into_iter().take(limit - selected.len()));
        }
        selected
    }

    pub(super) fn save_if_dirty(&mut self) -> io::Result<bool> {
        if !self.dirty {
            return Ok(false);
        }
        let Some(parent) = self.path.parent() else {
            return Err(io::Error::other("address-book path has no parent"));
        };
        fs::create_dir_all(parent)?;
        let temporary = parent.join("peers.tsv.tmp");
        let mut entries: Vec<&AddressEntry> = self.entries.values().collect();
        entries.sort_unstable_by_key(|entry| entry.addr);

        let mut file = File::create(&temporary)?;
        writeln!(
            file,
            "{ADDRESS_BOOK_FORMAT}\t{}",
            network_name(self.network)
        )?;
        for entry in entries {
            write_entry(&mut file, entry)?;
        }
        file.flush()?;
        file.sync_all()?;
        fs::rename(temporary, &self.path)?;
        self.dirty = false;
        Ok(true)
    }

    fn record_candidate(
        &mut self,
        addr: SocketAddr,
        services: Option<ServiceFlags>,
        source: AddressSource,
        seen_at: SystemTime,
    ) {
        if !usable_endpoint(addr) || !services_eligible(services) {
            return;
        }
        if let Some(entry) = self.entries.get_mut(&addr) {
            let previous = entry.clone();
            entry.last_seen = entry.last_seen.max(seen_at);
            entry.source = merge_source(entry.source, source);
            entry.services = merge_services(entry.services, services);
            self.dirty |= *entry != previous;
            return;
        }
        self.make_room();
        self.entries.insert(
            addr,
            AddressEntry {
                addr,
                services,
                source,
                last_seen: seen_at,
                last_success: None,
                consecutive_failures: 0,
                next_eligible: None,
            },
        );
        self.dirty = true;
    }

    fn insert_loaded(&mut self, entry: AddressEntry) {
        if !usable_endpoint(entry.addr) || !services_eligible(entry.services) {
            return;
        }
        if self.entries.contains_key(&entry.addr) {
            self.entries.insert(entry.addr, entry);
            return;
        }
        self.make_room();
        self.entries.insert(entry.addr, entry);
    }

    fn make_room(&mut self) {
        if self.entries.len() < ADDRESS_BOOK_CAPACITY {
            return;
        }
        let evicted = self
            .entries
            .values()
            .min_by_key(|entry| {
                (
                    entry.last_success.is_some(),
                    Reverse(entry.consecutive_failures),
                    entry.last_seen,
                    entry.addr,
                )
            })
            .map(|entry| entry.addr);
        if let Some(addr) = evicted {
            self.entries.remove(&addr);
        }
    }
}

fn is_eligible(entry: &AddressEntry, filter: &CandidateFilter<'_>) -> bool {
    !filter.active.contains(&entry.addr)
        && !filter.queued.contains(&entry.addr)
        && entry.next_eligible.is_none_or(|until| until <= filter.now)
        && !subnet::is_banned(filter.banned, entry.addr.ip(), filter.now)
        && usable_endpoint(entry.addr)
        && services_eligible(entry.services)
}

fn candidate_order(left: &AddressEntry, right: &AddressEntry, now: SystemTime) -> Ordering {
    candidate_class(left, now)
        .cmp(&candidate_class(right, now))
        .then_with(|| recent_success(right, now).cmp(&recent_success(left, now)))
        .then_with(|| left.consecutive_failures.cmp(&right.consecutive_failures))
        .then_with(|| right.last_seen.cmp(&left.last_seen))
        .then_with(|| left.addr.cmp(&right.addr))
}

fn candidate_class(entry: &AddressEntry, now: SystemTime) -> u8 {
    if recent_success(entry, now).is_some() {
        return 0;
    }
    if entry.source == AddressSource::Peer
        && is_recent(entry.last_seen, now, FRESH_ANNOUNCEMENT_AGE)
    {
        return 1;
    }
    2
}

fn recent_success(entry: &AddressEntry, now: SystemTime) -> Option<SystemTime> {
    entry
        .last_success
        .filter(|success| is_recent(*success, now, RECENT_SUCCESS_AGE))
}

fn is_recent(time: SystemTime, now: SystemTime, max_age: Duration) -> bool {
    now.duration_since(time).is_ok_and(|age| age <= max_age)
}

fn usable_endpoint(addr: SocketAddr) -> bool {
    addr.port() != 0 && is_routable(addr.ip())
}

fn services_eligible(services: Option<ServiceFlags>) -> bool {
    services.is_none_or(|services| {
        services.has(ServiceFlags::NETWORK) || services.has(ServiceFlags::WITNESS)
    })
}

const fn merge_source(current: AddressSource, new: AddressSource) -> AddressSource {
    match (current, new) {
        (AddressSource::Peer, _) | (_, AddressSource::Peer) => AddressSource::Peer,
        (AddressSource::Dns, AddressSource::Dns) => AddressSource::Dns,
    }
}

fn merge_services(
    current: Option<ServiceFlags>,
    new: Option<ServiceFlags>,
) -> Option<ServiceFlags> {
    match (current, new) {
        (Some(current), Some(new)) => Some(current | new),
        (Some(current), None) => Some(current),
        (None, Some(new)) => Some(new),
        (None, None) => None,
    }
}

fn failure_backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(6);
    let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    INITIAL_FAILURE_BACKOFF
        .saturating_mul(u32::try_from(multiplier).unwrap_or(u32::MAX))
        .min(MAX_FAILURE_BACKOFF)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NetworkGroup {
    Ipv4([u8; 2]),
    Ipv6([u16; 2]),
}

fn network_group(ip: IpAddr) -> NetworkGroup {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            NetworkGroup::Ipv4([a, b])
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            NetworkGroup::Ipv6([a, b])
        }
    }
}

fn write_entry(writer: &mut File, entry: &AddressEntry) -> io::Result<()> {
    let services = entry
        .services
        .map_or_else(|| "-".to_owned(), |services| services.to_u64().to_string());
    let source = match entry.source {
        AddressSource::Dns => "d",
        AddressSource::Peer => "p",
    };
    writeln!(
        writer,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        entry.addr,
        services,
        source,
        unix_seconds(entry.last_seen),
        optional_unix_seconds(entry.last_success),
        entry.consecutive_failures,
        optional_unix_seconds(entry.next_eligible),
    )
}

fn parse_entry(line: &str) -> Option<AddressEntry> {
    let mut fields = line.split('\t');
    let addr = fields.next()?.parse().ok()?;
    let services = match fields.next()? {
        "-" => None,
        raw => Some(ServiceFlags::from(raw.parse::<u64>().ok()?)),
    };
    let source = match fields.next()? {
        "d" => AddressSource::Dns,
        "p" => AddressSource::Peer,
        _ => return None,
    };
    let last_seen = system_time(fields.next()?)?;
    let last_success = match fields.next()? {
        "-" => None,
        raw => Some(system_time(raw)?),
    };
    let consecutive_failures = fields.next()?.parse().ok()?;
    let next_eligible = match fields.next()? {
        "-" => None,
        raw => Some(system_time(raw)?),
    };
    if fields.next().is_some() {
        return None;
    }
    Some(AddressEntry {
        addr,
        services,
        source,
        last_seen,
        last_success,
        consecutive_failures,
        next_eligible,
    })
}

fn system_time(raw: &str) -> Option<SystemTime> {
    raw.parse::<u64>()
        .ok()
        .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
}

fn optional_unix_seconds(time: Option<SystemTime>) -> String {
    time.map_or_else(|| "-".to_owned(), |time| unix_seconds(time).to_string())
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

const fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet3 => "testnet3",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::str::FromStr as _;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bitcoin::p2p::ServiceFlags;
    use bitcoin_rs_p2p::discovery::DiscoveredPeer;
    use bitcoin_rs_p2p::{BannedSubnet, IpSubnet};
    use hashbrown::HashSet;

    use super::{ADDRESS_BOOK_CAPACITY, AddressBook, AddressBookLoadWarning, CandidateFilter};
    use crate::Network;

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn addr(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), 8333))
    }

    fn empty_set() -> HashSet<SocketAddr> {
        HashSet::new()
    }

    fn filter<'a>(
        active: &'a HashSet<SocketAddr>,
        queued: &'a HashSet<SocketAddr>,
        banned: &'a [BannedSubnet],
        now: SystemTime,
    ) -> CandidateFilter<'a> {
        CandidateFilter {
            now,
            active,
            queued,
            banned,
        }
    }

    #[test]
    fn persists_and_reloads_deterministically() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let first = addr(8, 8, 8, 8);
        let second = addr(1, 1, 1, 1);
        let mut book = AddressBook::load(dir.path(), Network::Mainnet).0;
        book.record_dns(first, now());
        book.record_announcement(
            DiscoveredPeer {
                addr: second,
                services: ServiceFlags::WITNESS,
                seen_at: 1_700_000_000,
            },
            now(),
        );
        book.record_handshake(first, ServiceFlags::NETWORK | ServiceFlags::WITNESS, now());
        assert!(book.save_if_dirty()?);
        assert!(!book.save_if_dirty()?);

        let original = std::fs::read_to_string(dir.path().join("peers.tsv"))?;
        let (mut loaded, warning) = AddressBook::load(dir.path(), Network::Mainnet);
        assert!(warning.is_none());
        assert_eq!(loaded.len(), 2);
        assert!(!loaded.is_dirty());
        loaded.record_dns(first, now());
        assert!(!loaded.save_if_dirty()?);
        let rewritten = std::fs::read_to_string(dir.path().join("peers.tsv"))?;
        assert_eq!(original, rewritten);
        Ok(())
    }

    #[test]
    fn invalid_header_or_network_returns_empty_recoverable_book()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("peers.tsv"), "bad\n")?;
        let (book, warning) = AddressBook::load(dir.path(), Network::Mainnet);
        assert!(book.is_empty());
        assert!(matches!(
            warning,
            Some(AddressBookLoadWarning::InvalidHeader)
        ));

        std::fs::write(
            dir.path().join("peers.tsv"),
            "bitcoin-rs-peers-v1\ttestnet3\n",
        )?;
        let (book, warning) = AddressBook::load(dir.path(), Network::Mainnet);
        assert!(book.is_empty());
        assert!(matches!(
            warning,
            Some(AddressBookLoadWarning::NetworkMismatch)
        ));
        Ok(())
    }

    #[test]
    fn malformed_rows_are_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::write(
            dir.path().join("peers.tsv"),
            concat!(
                "bitcoin-rs-peers-v1\tmainnet\n",
                "malformed\n",
                "8.8.8.8:8333\t1\td\t1700000000\t-\t0\t-\n",
                "10.0.0.1:8333\t1\td\t1700000000\t-\t0\t-\n",
            ),
        )?;
        let (book, warning) = AddressBook::load(dir.path(), Network::Mainnet);
        assert!(warning.is_none());
        assert_eq!(book.len(), 1);
        Ok(())
    }

    #[test]
    fn failure_backoff_caps_and_success_resets() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let peer = addr(8, 8, 8, 8);
        let mut book = AddressBook::load(dir.path(), Network::Mainnet).0;
        book.record_dns(peer, now());
        for _ in 0..10 {
            book.record_failure(peer, now());
        }
        let active = empty_set();
        let queued = empty_set();
        assert_eq!(
            book.eligible_count(&filter(
                &active,
                &queued,
                &[],
                now() + Duration::from_secs(3_599)
            )),
            0
        );
        assert_eq!(
            book.select(
                1,
                &filter(&active, &queued, &[], now() + Duration::from_secs(3_600))
            ),
            vec![peer]
        );

        book.record_failure(peer, now() + Duration::from_secs(4_000));
        book.record_handshake(
            peer,
            ServiceFlags::NETWORK,
            now() + Duration::from_secs(4_001),
        );
        assert_eq!(
            book.select(
                1,
                &filter(&active, &queued, &[], now() + Duration::from_secs(4_001))
            ),
            vec![peer]
        );
        Ok(())
    }

    #[test]
    fn selection_filters_state_policy_and_services() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let active_addr = addr(8, 8, 8, 8);
        let queued_addr = addr(1, 1, 1, 1);
        let banned_addr = addr(9, 9, 9, 9);
        let eligible_addr = addr(4, 4, 4, 4);
        let ineligible_service = addr(5, 5, 5, 5);
        let mut book = AddressBook::load(dir.path(), Network::Mainnet).0;
        for candidate in [active_addr, queued_addr, banned_addr, eligible_addr] {
            book.record_dns(candidate, now());
        }
        book.record_announcement(
            DiscoveredPeer {
                addr: ineligible_service,
                services: ServiceFlags::NETWORK_LIMITED,
                seen_at: 1_700_000_000,
            },
            now(),
        );
        let active = HashSet::from([active_addr]);
        let queued = HashSet::from([queued_addr]);
        let banned = [BannedSubnet {
            subnet: IpSubnet::from_str("9.9.9.9/32")?,
            banned_until: None,
            ban_created: now(),
            reason: "test".to_owned(),
        }];

        assert_eq!(
            book.select(8, &filter(&active, &queued, &banned, now())),
            vec![eligible_addr]
        );
        Ok(())
    }

    #[test]
    fn selection_prefers_success_then_announcement_then_dns()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let successful = addr(8, 8, 8, 8);
        let announced = addr(1, 1, 1, 1);
        let dns = addr(4, 4, 4, 4);
        let mut book = AddressBook::load(dir.path(), Network::Mainnet).0;
        book.record_dns(dns, now());
        book.record_announcement(
            DiscoveredPeer {
                addr: announced,
                services: ServiceFlags::WITNESS,
                seen_at: 1_799_999_900,
            },
            now(),
        );
        book.record_dns(successful, now() - Duration::from_secs(100));
        book.record_handshake(
            successful,
            ServiceFlags::NETWORK,
            now() - Duration::from_secs(50),
        );
        let active = empty_set();
        let queued = empty_set();

        assert_eq!(
            book.select(3, &filter(&active, &queued, &[], now())),
            vec![successful, announced, dns]
        );
        Ok(())
    }

    #[test]
    fn stale_history_does_not_outrank_fresh_dns() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let stale_success = addr(8, 8, 8, 8);
        let stale_announcement = addr(1, 1, 1, 1);
        let fresh_dns = addr(4, 4, 4, 4);
        let mut book = AddressBook::load(dir.path(), Network::Mainnet).0;
        let stale = now() - Duration::from_hours(24 * 31);
        book.record_dns(stale_success, stale);
        book.record_handshake(stale_success, ServiceFlags::NETWORK, stale);
        book.record_announcement(
            DiscoveredPeer {
                addr: stale_announcement,
                services: ServiceFlags::WITNESS,
                seen_at: u32::try_from(stale.duration_since(UNIX_EPOCH)?.as_secs())?,
            },
            now(),
        );
        book.record_dns(fresh_dns, now());
        let active = empty_set();
        let queued = empty_set();

        assert_eq!(
            book.select(3, &filter(&active, &queued, &[], now())),
            vec![fresh_dns, stale_announcement, stale_success]
        );
        Ok(())
    }

    #[test]
    fn selection_diversifies_network_groups_before_reuse() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let first_group_best = addr(8, 8, 8, 8);
        let first_group_second = addr(8, 8, 4, 4);
        let second_group = addr(1, 1, 1, 1);
        let mut book = AddressBook::load(dir.path(), Network::Mainnet).0;
        book.record_dns(first_group_second, now() - Duration::from_secs(2));
        book.record_dns(second_group, now() - Duration::from_secs(3));
        book.record_dns(first_group_best, now());
        let active = empty_set();
        let queued = empty_set();

        assert_eq!(
            book.select(3, &filter(&active, &queued, &[], now())),
            vec![first_group_best, second_group, first_group_second]
        );
        Ok(())
    }

    #[test]
    fn capacity_evicts_failed_entry_before_successful_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let protected = addr(8, 8, 8, 8);
        let failed = addr(11, 0, 0, 1);
        let mut book = AddressBook::load(dir.path(), Network::Mainnet).0;
        book.record_dns(protected, now());
        book.record_handshake(protected, ServiceFlags::NETWORK, now());
        book.record_dns(failed, now() - Duration::from_secs(1));
        book.record_failure(failed, now());
        for index in 2..ADDRESS_BOOK_CAPACITY {
            let second = u8::try_from(index / 256).unwrap_or(u8::MAX);
            let third = u8::try_from(index % 256).unwrap_or(u8::MAX);
            book.record_dns(addr(11, second, third, 1), now());
        }
        assert_eq!(book.len(), ADDRESS_BOOK_CAPACITY);
        let replacement = addr(12, 0, 0, 1);
        book.record_dns(replacement, now());
        assert_eq!(book.len(), ADDRESS_BOOK_CAPACITY);
        assert!(book.entries.contains_key(&protected));
        assert!(!book.entries.contains_key(&failed));
        assert!(book.entries.contains_key(&replacement));
        Ok(())
    }
}
