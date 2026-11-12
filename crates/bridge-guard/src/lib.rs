//! # bridge-guard – the gatekeeper
//!
//! Every request passes here before a node does any real work (Zero Trust Z4/Z5/Z8, docs/02). All checks are cheap,
//! in memory and bounded:
//! - token buckets per address (IPv6 per /64), per address for login puzzles, per identity for sending,
//! - one-time nonces of signed requests (replay), bounded per identity,
//! - at most N concurrent long polls per identity,
//! - login challenges (one-time, short-lived) with optional proof-of-work that rises under load (ADR 0007),
//! - mailbox quotas (counted atomically by `bridge-store`).
//!
//! Every table has a hard size limit. When a table is full and nothing can be cleaned up, the request is refused
//! (fail closed, Z8) instead of growing without bound. Time is always passed in (no clock inside) - testable.
//!
//! Layering (docs/03_ARCHITEKTUR.md): depends on `bridge-core` and `bridge-store`.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use bridge_core::pow::{MAX_POW_BITS, POW_LIFETIME_MS};
use bridge_core::{Id, Puzzle};
use bridge_store::{BlobLimits, MailboxLimits, RelayLimits};
use thiserror::Error;

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-guard";

/// Why the guard said no.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// Too many requests (or a table is full) - try again later.
    #[error("rate limited, retry after {retry_after_s} s")]
    RateLimited {
        /// Seconds until a retry makes sense.
        retry_after_s: u32,
    },
    /// This signed request (or challenge) was already used.
    #[error("replay")]
    Replay,
}

impl GuardError {
    /// Wire code (docs/04 §9).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RateLimited { .. } => "RATE_LIMITED",
            Self::Replay => "REPLAY",
        }
    }
}

/// Result type of the guard.
pub type GuardResult<T> = Result<T, GuardError>;

/// A token bucket rate: `per_second` steady, up to `burst` at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Requests per second (steady).
    pub per_second: u32,
    /// Requests at once.
    pub burst: u32,
}

/// Proof-of-work policy (ADR 0007): off by default, rises under load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowPolicy {
    /// Always ask for this many bits (0 = only under load).
    pub always_bits: u32,
    /// Bits under load.
    pub load_bits: u32,
    /// "Under load" = more login challenges per minute than this (whole node).
    pub load_challenges_per_minute: u32,
}

/// All limits of a node (defaults: docs/04 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// All requests per address.
    pub per_address: Rate,
    /// Login challenges per address.
    pub challenges_per_address: Rate,
    /// Merkle proofs, consistency proofs and evidence per address (unauthenticated, docs/06 §9).
    pub proofs_per_address: Rate,
    /// Unauthenticated reads of blobs and apps per address (`/v4/blob/info|hashes|get`, `/v4/app/manifest`,
    /// `GET /app/…`; docs/07 §7) - on top of the general bucket.
    pub reads_per_address: Rate,
    /// Name lookups per address (`/v4/names/resolve|search|list|info`, docs/08 §7) - on top of the general bucket.
    pub names_per_address: Rate,
    /// Sent envelopes per identity.
    pub sends_per_identity: Rate,
    /// Mailbox quotas.
    pub mailbox: MailboxLimits,
    /// Quotas of the relay outbox (envelopes waiting for another gateway, docs/06 §8).
    pub relay: RelayLimits,
    /// Storage for blobs: quotas per level, node totals (docs/07 §1).
    pub blobs: BlobLimits,
    /// Apps a node hosts at most at once (docs/07 §4).
    pub max_hosted_apps: u64,
    /// Apps of one owner a node hosts at most at once, by the owner's level: 0, 1, 2 and above (docs/07 §5).
    pub max_apps_per_owner: [u64; 3],
    /// Blob uploads on a node without a network (docs/07 §5): `None` = off (default - every logged-in identity is
    /// anonymous there), `Some(bytes)` = on, with this cap for all blobs of the node together.
    pub standalone_blobs: Option<u64>,
    /// Concurrent long polls per identity.
    pub polls_per_identity: u32,
    /// Identities (key cards) a node remembers at most (phase 3: membership replaces this).
    pub max_identities: u64,
    /// Size of every table (buckets, nonces, challenges).
    pub max_tracked: usize,
    /// Proof-of-work.
    pub pow: PowPolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_address: Rate { per_second: 20, burst: 40 },
            challenges_per_address: Rate { per_second: 2, burst: 10 },
            proofs_per_address: Rate { per_second: 5, burst: 10 },
            reads_per_address: Rate { per_second: 10, burst: 40 },
            names_per_address: Rate { per_second: 5, burst: 20 },
            sends_per_identity: Rate { per_second: 10, burst: 30 },
            mailbox: MailboxLimits {
                max_envelopes: 1_000,
                max_bytes: 32 * 1024 * 1024,
                max_from_one_sender: 200,
                max_node_bytes: 1024 * 1024 * 1024,
                max_seen_per_sender: 20_000,
            },
            relay: RelayLimits { max_entries: 10_000, max_bytes: 256 * 1024 * 1024, max_per_target: 5_000 },
            blobs: BlobLimits {
                quota: [50 * MIB, 1024 * MIB, 10 * 1024 * MIB],
                max_node_bytes: 20 * 1024 * MIB,
                max_blobs: 1_000_000,
                max_keep_days: 30,
                max_staged_per_owner: 4,
                max_staged: 64,
            },
            max_hosted_apps: 64,
            max_apps_per_owner: [4, 16, 64],
            standalone_blobs: None,
            max_identities: 100_000,
            polls_per_identity: 2,
            max_tracked: 100_000,
            pow: PowPolicy { always_bits: 0, load_bits: 20, load_challenges_per_minute: 600 },
        }
    }
}

const MIB: u64 = 1024 * 1024;

impl Limits {
    /// Apps an owner of `level` may have hosted at once on this node.
    #[must_use]
    pub fn apps_for(&self, level: u8) -> u64 {
        self.max_apps_per_owner[usize::from(level.min(2))]
    }
}

/// Cleaning a full table is O(n); do it at most once per second so a flood cannot make every request expensive.
const SWEEP_INTERVAL_MS: i64 = 1_000;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere must not switch the guard off: the data (counters) stays usable.
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub use bridge_core::address_key;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    milli_tokens: u64,
    last_ms: i64,
}

struct BucketTable<K> {
    buckets: HashMap<K, Bucket>,
    last_sweep_ms: i64,
}

/// Token buckets per key, bounded.
pub struct RateLimiter<K> {
    rate: Rate,
    max_keys: usize,
    table: Mutex<BucketTable<K>>,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    /// A limiter with `rate` for each key and at most `max_keys` keys.
    #[must_use]
    pub fn new(rate: Rate, max_keys: usize) -> Self {
        Self { rate, max_keys, table: Mutex::new(BucketTable { buckets: HashMap::new(), last_sweep_ms: i64::MIN }) }
    }

    fn full(&self) -> u64 {
        u64::from(self.rate.burst) * 1000
    }

    fn refill(&self, bucket: &mut Bucket, now_ms: i64) {
        let elapsed = u64::try_from(now_ms.saturating_sub(bucket.last_ms)).unwrap_or(0);
        bucket.milli_tokens = bucket
            .milli_tokens
            .saturating_add(elapsed.saturating_mul(u64::from(self.rate.per_second)))
            .min(self.full());
        bucket.last_ms = bucket.last_ms.max(now_ms);
    }

    /// Takes one token for `key`.
    pub fn check(&self, key: &K, now_ms: i64) -> GuardResult<()> {
        let mut table = lock(&self.table);
        if !table.buckets.contains_key(key) && table.buckets.len() >= self.max_keys {
            if now_ms.saturating_sub(table.last_sweep_ms) < SWEEP_INTERVAL_MS {
                return Err(GuardError::RateLimited { retry_after_s: 1 });
            }
            table.last_sweep_ms = now_ms;
            // A full bucket is the same as no bucket - those entries can go.
            let full = self.full();
            let rate = u64::from(self.rate.per_second);
            table.buckets.retain(|_, bucket| {
                let elapsed = u64::try_from(now_ms.saturating_sub(bucket.last_ms)).unwrap_or(0);
                bucket.milli_tokens.saturating_add(elapsed.saturating_mul(rate)) < full
            });
            if table.buckets.len() >= self.max_keys {
                return Err(GuardError::RateLimited { retry_after_s: 1 });
            }
        }
        let full = self.full();
        let bucket = table.buckets.entry(key.clone()).or_insert(Bucket { milli_tokens: full, last_ms: now_ms });
        let mut copy = *bucket;
        self.refill(&mut copy, now_ms);
        if copy.milli_tokens >= 1000 {
            copy.milli_tokens -= 1000;
            *bucket = copy;
            Ok(())
        } else {
            *bucket = copy;
            let missing = 1000 - copy.milli_tokens;
            let wait_ms = missing.div_ceil(u64::from(self.rate.per_second.max(1)));
            Err(GuardError::RateLimited { retry_after_s: u32::try_from(wait_ms.div_ceil(1000)).unwrap_or(u32::MAX) })
        }
    }

    /// Number of tracked keys (diagnostics).
    #[must_use]
    pub fn tracked(&self) -> usize {
        lock(&self.table).buckets.len()
    }
}

/// Live nonces per identity at most.
pub const NONCES_PER_IDENTITY: usize = 256;

/// Nonces of signed requests per identity, bounded twice (identities and nonces per identity).
struct NonceTable {
    entries: HashMap<Id, HashMap<[u8; 16], i64>>,
    last_sweep_ms: i64,
    max: usize,
}

impl NonceTable {
    fn new(max: usize) -> Self {
        Self { entries: HashMap::new(), last_sweep_ms: i64::MIN, max }
    }

    fn make_room(&mut self, now_ms: i64) -> GuardResult<()> {
        if self.entries.len() < self.max {
            return Ok(());
        }
        if now_ms.saturating_sub(self.last_sweep_ms) >= SWEEP_INTERVAL_MS {
            self.last_sweep_ms = now_ms;
            for own in self.entries.values_mut() {
                own.retain(|_, expires| *expires > now_ms);
            }
            self.entries.retain(|_, own| !own.is_empty());
        }
        if self.entries.len() >= self.max { Err(GuardError::RateLimited { retry_after_s: 5 }) } else { Ok(()) }
    }
}

struct Challenge {
    expires_ms: i64,
    puzzle: Option<Puzzle>,
}

struct ChallengeTable {
    entries: HashMap<[u8; 32], Challenge>,
    last_sweep_ms: i64,
    max: usize,
}

struct LoadMeter {
    minute: i64,
    current: u32,
    previous: u32,
}

impl LoadMeter {
    fn record(&mut self, now_ms: i64) {
        self.roll(now_ms);
        self.current = self.current.saturating_add(1);
    }
    fn roll(&mut self, now_ms: i64) {
        let minute = now_ms.div_euclid(60_000);
        if minute != self.minute {
            self.previous = if minute == self.minute + 1 { self.current } else { 0 };
            self.current = 0;
            self.minute = minute;
        }
    }
    /// Sliding estimate of the last 60 seconds.
    fn per_minute(&mut self, now_ms: i64) -> u32 {
        self.roll(now_ms);
        let into = u64::try_from(now_ms.rem_euclid(60_000)).unwrap_or(0);
        let previous_share = u64::from(self.previous) * (60_000 - into) / 60_000;
        u32::try_from(previous_share).unwrap_or(u32::MAX).saturating_add(self.current)
    }
}

/// Held while a long poll runs; dropping it frees the slot.
pub struct PollPermit {
    polls: Arc<Mutex<HashMap<Id, u32>>>,
    id: Id,
}

impl Drop for PollPermit {
    fn drop(&mut self) {
        let mut polls = lock(&self.polls);
        if let Some(count) = polls.get_mut(&self.id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                polls.remove(&self.id);
            }
        }
    }
}

/// The guard of one node (no global state: every node has its own).
pub struct Guard {
    limits: Limits,
    per_address: RateLimiter<IpAddr>,
    challenges_per_address: RateLimiter<IpAddr>,
    proofs_per_address: RateLimiter<IpAddr>,
    reads_per_address: RateLimiter<IpAddr>,
    names_per_address: RateLimiter<IpAddr>,
    sends: RateLimiter<Id>,
    nonces: Mutex<NonceTable>,
    challenges: Mutex<ChallengeTable>,
    polls: Arc<Mutex<HashMap<Id, u32>>>,
    load: Mutex<LoadMeter>,
}

impl Guard {
    /// A guard with these limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            per_address: RateLimiter::new(limits.per_address, limits.max_tracked),
            challenges_per_address: RateLimiter::new(limits.challenges_per_address, limits.max_tracked),
            proofs_per_address: RateLimiter::new(limits.proofs_per_address, limits.max_tracked),
            reads_per_address: RateLimiter::new(limits.reads_per_address, limits.max_tracked),
            names_per_address: RateLimiter::new(limits.names_per_address, limits.max_tracked),
            sends: RateLimiter::new(limits.sends_per_identity, limits.max_tracked),
            nonces: Mutex::new(NonceTable::new(limits.max_tracked)),
            challenges: Mutex::new(ChallengeTable {
                entries: HashMap::new(),
                last_sweep_ms: i64::MIN,
                max: limits.max_tracked,
            }),
            polls: Arc::new(Mutex::new(HashMap::new())),
            load: Mutex::new(LoadMeter { minute: i64::MIN, current: 0, previous: 0 }),
            limits,
        }
    }

    /// The limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Step 1 for every request: the per-address bucket.
    pub fn admit_address(&self, ip: IpAddr, now_ms: i64) -> GuardResult<()> {
        self.per_address.check(&address_key(ip), now_ms)
    }

    /// A login challenge for this address? Also measures load for the proof-of-work policy.
    pub fn admit_challenge(&self, ip: IpAddr, now_ms: i64) -> GuardResult<()> {
        self.challenges_per_address.check(&address_key(ip), now_ms)?;
        lock(&self.load).record(now_ms);
        Ok(())
    }

    /// A Merkle proof, consistency proof or evidence request for this address (tighter than the general bucket)?
    pub fn admit_proof(&self, ip: IpAddr, now_ms: i64) -> GuardResult<()> {
        self.proofs_per_address.check(&address_key(ip), now_ms)
    }

    /// An unauthenticated blob or app read for this address (tighter than the general bucket, docs/07 §7)?
    pub fn admit_read(&self, ip: IpAddr, now_ms: i64) -> GuardResult<()> {
        self.reads_per_address.check(&address_key(ip), now_ms)
    }

    /// A name lookup for this address (docs/08 §7: its own bucket, tighter than the general one)?
    pub fn admit_names(&self, ip: IpAddr, now_ms: i64) -> GuardResult<()> {
        self.names_per_address.check(&address_key(ip), now_ms)
    }

    /// How many proof-of-work bits a new challenge needs right now (0 = none).
    #[must_use]
    pub fn pow_bits(&self, now_ms: i64) -> u32 {
        let policy = self.limits.pow;
        let mut bits = policy.always_bits;
        if lock(&self.load).per_minute(now_ms) > policy.load_challenges_per_minute {
            bits = bits.max(policy.load_bits);
        }
        bits.min(MAX_POW_BITS)
    }

    /// Remembers an issued challenge (one-time, [`POW_LIFETIME_MS`]). Returns when it expires.
    pub fn register_challenge(&self, challenge: [u8; 32], puzzle: Option<Puzzle>, now_ms: i64) -> GuardResult<i64> {
        let mut table = lock(&self.challenges);
        if table.entries.len() >= table.max {
            if now_ms.saturating_sub(table.last_sweep_ms) >= SWEEP_INTERVAL_MS {
                table.last_sweep_ms = now_ms;
                table.entries.retain(|_, entry| entry.expires_ms > now_ms);
            }
            if table.entries.len() >= table.max {
                return Err(GuardError::RateLimited { retry_after_s: 5 });
            }
        }
        let expires_ms = now_ms.saturating_add(POW_LIFETIME_MS);
        table.entries.insert(challenge, Challenge { expires_ms, puzzle });
        Ok(expires_ms)
    }

    /// Takes a challenge for a login: valid only once and only before it expires. Returns its puzzle (if any).
    pub fn take_challenge(&self, challenge: &[u8; 32], now_ms: i64) -> GuardResult<Option<Puzzle>> {
        match lock(&self.challenges).entries.remove(challenge) {
            Some(entry) if entry.expires_ms > now_ms => Ok(entry.puzzle),
            _ => Err(GuardError::Replay), // unknown, used or expired - the same answer for all three
        }
    }

    /// Sending one envelope as `id`.
    pub fn admit_send(&self, id: &Id, now_ms: i64) -> GuardResult<()> {
        self.sends.check(id, now_ms)
    }

    /// Remembers the nonce of a signed request until `expires_ms`; a second use is a replay. For operations that
    /// are not idempotent (login is protected by its one-time challenge, ack is idempotent). At most
    /// [`NONCES_PER_IDENTITY`] live nonces per identity, so one identity cannot fill the table for everybody.
    pub fn remember_nonce(&self, iss: &Id, nonce: &[u8; 16], expires_ms: i64, now_ms: i64) -> GuardResult<()> {
        let mut table = lock(&self.nonces);
        if !table.entries.contains_key(iss) {
            table.make_room(now_ms)?;
        }
        let own = table.entries.entry(iss.clone()).or_default();
        if own.get(nonce).is_some_and(|expires| *expires > now_ms) {
            return Err(GuardError::Replay);
        }
        if own.len() >= NONCES_PER_IDENTITY {
            own.retain(|_, expires| *expires > now_ms);
            if own.len() >= NONCES_PER_IDENTITY {
                return Err(GuardError::RateLimited { retry_after_s: 10 });
            }
        }
        own.insert(*nonce, expires_ms);
        Ok(())
    }

    /// A slot for a long poll of `id` (at most `polls_per_identity` at once).
    pub fn try_poll(&self, id: &Id) -> GuardResult<PollPermit> {
        let mut polls = lock(&self.polls);
        if !polls.contains_key(id) && polls.len() >= self.limits.max_tracked {
            return Err(GuardError::RateLimited { retry_after_s: 1 });
        }
        let count = polls.entry(id.clone()).or_insert(0);
        if *count >= self.limits.polls_per_identity {
            return Err(GuardError::RateLimited { retry_after_s: 1 });
        }
        *count += 1;
        Ok(PollPermit { polls: Arc::clone(&self.polls), id: id.clone() })
    }

    /// Mailbox quotas for `bridge-store`.
    #[must_use]
    pub fn mailbox_limits(&self) -> MailboxLimits {
        self.limits.mailbox
    }

    /// Relay outbox quotas for `bridge-store`.
    #[must_use]
    pub fn relay_limits(&self) -> RelayLimits {
        self.limits.relay
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bridge_core::Identity;
    use rand_core::OsRng;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(COMPARTMENT, env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn bucket_burst_then_steady() {
        let limiter = RateLimiter::new(Rate { per_second: 10, burst: 5 }, 100);
        for _ in 0..5 {
            assert_eq!(limiter.check(&1, 0), Ok(()));
        }
        assert!(matches!(limiter.check(&1, 0), Err(GuardError::RateLimited { retry_after_s: 1 })));
        assert_eq!(limiter.check(&2, 0), Ok(()), "other keys are independent");
        assert!(limiter.check(&1, 50).is_err(), "half a token after 50 ms");
        assert_eq!(limiter.check(&1, 100), Ok(()), "one token after 100 ms");
        assert_eq!(limiter.check(&1, 10_000), Ok(()), "refilled");
    }

    #[test]
    fn flood_of_10000_per_second_is_cut_to_the_rate() {
        // 10,000 requests within one second from one address: only burst + rate get through.
        let guard = Guard::new(Limits::default());
        let passed = (0..10_000).filter(|i| guard.admit_address(ip(1), i / 10).is_ok()).count();
        assert!(passed <= 40 + 20 + 1, "passed {passed}");
        assert!(guard.admit_address(ip(2), 999).is_ok(), "others are not affected");
    }

    #[test]
    fn full_tables_fail_closed_and_recover() {
        let limiter = RateLimiter::new(Rate { per_second: 1, burst: 2 }, 3);
        for key in 0..3 {
            limiter.check(&key, 0).ok();
        }
        assert!(limiter.check(&99, 0).is_err(), "full and nothing to clean: refused");
        assert!(limiter.check(&99, 500).is_err(), "no second sweep within a second");
        assert_eq!(limiter.check(&99, 5_000), Ok(()), "refilled buckets were cleaned up");
        assert!(limiter.tracked() <= 3);
    }

    #[test]
    fn ipv6_is_limited_per_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(address_key(a), address_key(b));
        assert_ne!(address_key(a), address_key(c));
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(address_key(mapped), ip(1));
    }

    #[test]
    fn nonces_are_one_time() {
        let guard = Guard::new(Limits::default());
        let id = Identity::generate(&mut OsRng).id().clone();
        assert_eq!(guard.remember_nonce(&id, &[1; 16], 1_000, 0), Ok(()));
        assert_eq!(guard.remember_nonce(&id, &[1; 16], 1_000, 10), Err(GuardError::Replay));
        assert_eq!(guard.remember_nonce(&id, &[2; 16], 1_000, 10), Ok(()));
        let other = Identity::generate(&mut OsRng).id().clone();
        assert_eq!(guard.remember_nonce(&other, &[1; 16], 1_000, 10), Ok(()), "per identity");
    }

    #[test]
    fn challenges_are_one_time_and_expire() -> GuardResult<()> {
        let guard = Guard::new(Limits::default());
        guard.register_challenge([1; 32], None, 0)?;
        guard.register_challenge([2; 32], None, 0)?;
        assert_eq!(guard.take_challenge(&[1; 32], 10), Ok(None));
        assert_eq!(guard.take_challenge(&[1; 32], 10), Err(GuardError::Replay), "second use");
        assert_eq!(guard.take_challenge(&[3; 32], 10), Err(GuardError::Replay), "unknown");
        assert_eq!(guard.take_challenge(&[2; 32], POW_LIFETIME_MS), Err(GuardError::Replay), "expired");
        Ok(())
    }

    #[test]
    fn pow_rises_under_load() {
        let limits = Limits {
            challenges_per_address: Rate { per_second: 1000, burst: 1000 },
            pow: PowPolicy { always_bits: 0, load_bits: 18, load_challenges_per_minute: 50 },
            ..Limits::default()
        };
        let guard = Guard::new(limits);
        assert_eq!(guard.pow_bits(0), 0, "no load, no work");
        for i in 0..60 {
            guard.admit_challenge(ip(1), i).ok();
        }
        assert_eq!(guard.pow_bits(100), 18, "under load");
        assert_eq!(guard.pow_bits(10 * 60_000), 0, "load gone");
        let always = Guard::new(Limits { pow: PowPolicy { always_bits: 40, ..limits.pow }, ..limits });
        assert_eq!(always.pow_bits(0), MAX_POW_BITS, "capped");
    }

    /// Regression (review 3, finding 4): the unauthenticated proof endpoints have their own, tighter bucket.
    #[test]
    fn proofs_have_a_tighter_bucket_per_address() {
        let guard = Guard::new(Limits::default());
        let burst = Limits::default().proofs_per_address.burst;
        for _ in 0..burst {
            assert_eq!(guard.admit_proof(ip(1), 0), Ok(()));
        }
        assert!(matches!(guard.admit_proof(ip(1), 0), Err(GuardError::RateLimited { .. })));
        assert_eq!(guard.admit_address(ip(1), 0), Ok(()), "the general bucket is separate");
        assert_eq!(guard.admit_proof(ip(2), 0), Ok(()), "per address");
        assert_eq!(guard.admit_proof(ip(1), 1_000), Ok(()), "refills (5/s)");
    }

    #[test]
    fn polls_are_limited_per_identity() -> GuardResult<()> {
        let guard = Guard::new(Limits::default());
        let id = Identity::generate(&mut OsRng).id().clone();
        let first = guard.try_poll(&id)?;
        let _second = guard.try_poll(&id)?;
        assert!(guard.try_poll(&id).is_err());
        drop(first);
        assert!(guard.try_poll(&id).is_ok(), "slot freed");
        Ok(())
    }
}
