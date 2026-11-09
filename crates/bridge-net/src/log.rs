//! The transparency log (docs/06 §5, ADR 0006): entries, signed heads, witness cosignatures, split-view evidence.
//!
//! [`Log`] only checks the *structure* of entries. Whether an entry is valid under the rules of the network is
//! decided by [`crate::NetState`]: a log operator asks `NetState::validate_candidate` before [`Log::append`], and
//! every reader replays (invalid entries are skipped). A follower mirrors the operator's log with
//! [`Log::append_bytes`], which takes any entry of at most 64 KiB after the genesis - so even a log with garbage
//! entries (a misbehaving operator) can be followed and its heads checked; the garbage simply does not count.

use bridge_core::json::parse_strict;
use bridge_core::{Id, Identity, KeyCard, Statement};
use serde_json::{Value, json};

use crate::Cards;
use crate::error::{NetError, NetResult};
use crate::merkle::{Hash, Tree};
use crate::statements::{Body, Cosign, HEAD_LIFETIME_MS, HeadBody, Kind, LogRules, Manifest};

/// Maximum size of one log entry (canonical statement bytes).
pub const MAX_ENTRY_BYTES: usize = bridge_core::statement::MAX_STATEMENT_BYTES;
/// Maximum number of entries per page of `/v4/net/{net}/log`.
pub const MAX_PAGE_ENTRIES: usize = 256;
/// Maximum bytes per page of `/v4/net/{net}/log`.
pub const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// Maximum number of cosignatures accepted next to one head (a manifest lists at most 16 witnesses).
pub const MAX_COSIGNS: usize = 32;
/// Maximum size of a serialized witnessed head.
pub const MAX_WITNESSED_HEAD_BYTES: usize = 64 * 1024;
/// Maximum size of serialized evidence.
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024;

/// The entries of a network's log (canonical statement bytes) and their Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    net: Id,
    entries: Vec<Vec<u8>>,
    tree: Tree,
}

impl Log {
    /// An empty log of the network `net`. The first entry must be the genesis manifest.
    #[must_use]
    pub fn new(net: Id) -> Self {
        Self { net, entries: Vec::new(), tree: Tree::new() }
    }

    /// Restores a log from stored or fetched entries (checks as in [`Log::append_bytes`]).
    pub fn from_entries(net: Id, entries: &[Vec<u8>]) -> NetResult<Self> {
        let mut log = Self::new(net);
        for entry in entries {
            log.append_bytes(entry)?;
        }
        Ok(log)
    }

    /// Log operator: appends a statement; returns its index. Only log kinds of this network, at most 64 KiB;
    /// entry 0 must be the genesis manifest (version 1, signed by the network ID alone, verified). Check the
    /// statement with `NetState::validate_candidate` first.
    pub fn append(&mut self, statement: &Statement) -> NetResult<u64> {
        if statement.net() != &self.net {
            return Err(NetError::format("log entry: other network"));
        }
        if !Kind::parse(statement.kind()).is_some_and(Kind::is_log_kind) {
            return Err(NetError::format("log entry: not a log kind"));
        }
        self.append_bytes(statement.canonical_bytes())
    }

    /// Follower: appends an entry exactly as fetched; returns its index. Entry 0 must be the genesis manifest of
    /// this network (in canonical form), later entries only have to fit into 64 KiB.
    pub fn append_bytes(&mut self, entry: &[u8]) -> NetResult<u64> {
        if entry.len() > MAX_ENTRY_BYTES {
            return Err(NetError::TooLarge("log entry".into()));
        }
        if self.entries.is_empty() {
            Manifest::genesis(&parse_entry(entry)?, &self.net)?;
        }
        let index = self.tree.push_entry(entry)?;
        self.entries.push(entry.to_vec());
        Ok(index)
    }

    /// Network ID.
    #[must_use]
    pub fn net(&self) -> &Id {
        &self.net
    }

    /// Number of entries.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    /// One entry.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&[u8]> {
        usize::try_from(index).ok().and_then(|index| self.entries.get(index)).map(Vec::as_slice)
    }

    /// A page of entries starting at `from`: at most `max` (capped at 256) entries and 1 MiB (but at least one entry
    /// if there is one).
    #[must_use]
    pub fn page(&self, from: u64, max: usize) -> Vec<&[u8]> {
        let start = usize::try_from(from).unwrap_or(usize::MAX);
        let mut page = Vec::new();
        let mut bytes = 0usize;
        for entry in self.entries.iter().skip(start).take(max.min(MAX_PAGE_ENTRIES)) {
            bytes = bytes.saturating_add(entry.len());
            if bytes > MAX_PAGE_BYTES && !page.is_empty() {
                break;
            }
            page.push(entry.as_slice());
        }
        page
    }

    /// All entries.
    #[must_use]
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }

    /// The Merkle tree (proofs, roots of prefixes).
    #[must_use]
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Current root.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    /// Whether this log matches a (verified) head: the root of its first `head.size()` entries is the head's root.
    #[must_use]
    pub fn matches(&self, head: &Head) -> bool {
        self.tree.root_at(head.size).is_ok_and(|root| root == head.root)
    }

    /// Signs a head over the whole log (`iat` = now, `exp` = now + 30 days).
    pub fn issue_head(&self, operator: &Identity, now_ms: i64) -> NetResult<Statement> {
        issue_head(operator, &self.net, self.size(), self.root(), now_ms)
    }
}

/// Parses a log entry: at most 64 KiB, a statement, in canonical form (exactly one byte form per entry, so the leaf
/// hash is unambiguous).
pub fn parse_entry(entry: &[u8]) -> NetResult<Statement> {
    if entry.len() > MAX_ENTRY_BYTES {
        return Err(NetError::TooLarge("log entry".into()));
    }
    let statement = Statement::parse(entry)?;
    if statement.canonical_bytes() != entry {
        return Err(NetError::format("log entry: not canonical"));
    }
    Ok(statement)
}

/// What a witness checks about the entries a new head adds, before cosigning (docs/06 §5): each is a canonical
/// statement with `iat` at most 5 minutes after the head's `iat`. So a witnessed head never contains entries
/// dated into the future (they would move the log clock of [`crate::NetState`] forward).
pub fn check_new_entries(entries: &[Vec<u8>], head: &Head) -> NetResult<()> {
    for entry in entries {
        let statement = parse_entry(entry)?;
        if statement.times().0 > head.iat.saturating_add(bridge_core::CLOCK_SKEW_MS) {
            return Err(NetError::NotYetValid);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Heads and cosignatures

/// A verified head. Only [`verify_head`] (and [`WitnessedHead::check`]) create one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    net: Id,
    operator: Id,
    size: u64,
    root: Hash,
    iat: i64,
    exp: i64,
    hash: Hash,
}

impl Head {
    /// Network.
    #[must_use]
    pub fn net(&self) -> &Id {
        &self.net
    }
    /// The log operator who signed it.
    #[must_use]
    pub fn operator(&self) -> &Id {
        &self.operator
    }
    /// Tree size.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Root.
    #[must_use]
    pub fn root(&self) -> &Hash {
        &self.root
    }
    /// Issued at / expires (ms).
    #[must_use]
    pub fn times(&self) -> (i64, i64) {
        (self.iat, self.exp)
    }
    /// Hash of the head statement (what cosignatures refer to).
    #[must_use]
    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

/// Signs a head: kind `head`, body `{size, root}`, `exp` = `iat` + 30 days.
pub fn issue_head(operator: &Identity, net: &Id, size: u64, root: Hash, now_ms: i64) -> NetResult<Statement> {
    HeadBody { size, root }.sign(net, now_ms, now_ms.saturating_add(HEAD_LIFETIME_MS), operator)
}

/// Verifies a head of network `net` signed by `operator` alone (form and signature, not the time - old heads still
/// count as evidence; check `statement.check_time` where freshness matters).
pub fn verify_head(head: &Statement, net: &Id, operator: &KeyCard) -> NetResult<Head> {
    let body = HeadBody::from_statement(head)?;
    if head.net() != net {
        return Err(NetError::format("head: other network"));
    }
    if head.claimed_signers() != [operator.id()] {
        return Err(NetError::BadSignature);
    }
    head.verify(&[operator], 1)?;
    let (iat, exp) = head.times();
    Ok(Head {
        net: net.clone(),
        operator: operator.id().clone(),
        size: body.size,
        root: body.root,
        iat,
        exp,
        hash: head.hash_bytes(),
    })
}

/// A witness cosigns a verified head (after checking consistency with the last head of this operator it cosigned).
/// `exp` = the head's `exp`.
pub fn issue_cosign(witness: &Identity, head: &Head, now_ms: i64) -> NetResult<Statement> {
    if now_ms >= head.exp {
        return Err(NetError::Expired);
    }
    let body = Cosign { head: head.hash, log: head.operator.clone(), size: head.size, root: head.root };
    body.sign(&head.net, now_ms, head.exp, witness)
}

/// Verifies a cosignature of `witness` for exactly this head (hash, operator, size, root, network).
pub fn verify_cosign(cosign: &Statement, head: &Head, witness: &KeyCard) -> NetResult<()> {
    let body = Cosign::from_statement(cosign)?;
    if cosign.net() != &head.net {
        return Err(NetError::format("cosign: other network"));
    }
    if body.head != head.hash || body.log != head.operator || body.size != head.size || body.root != head.root {
        return Err(NetError::format("cosign: for another head"));
    }
    if cosign.claimed_signers() != [witness.id()] {
        return Err(NetError::BadSignature);
    }
    cosign.verify(&[witness], 1)?;
    Ok(())
}

/// A head with its cosignatures, as served by `GET /v4/net/{net}/head`.
#[derive(Debug, Clone, PartialEq)]
pub struct WitnessedHead {
    /// The head statement.
    pub head: Statement,
    /// Cosignatures (at most 32).
    pub cosigns: Vec<Statement>,
}

impl WitnessedHead {
    /// Checks that the head is witnessed under `rules` at `now_ms`: signed by a log operator of the rules, valid
    /// now, and cosigned by at least `witness_threshold` distinct witnesses of the rules (cosignatures that are
    /// invalid, expired, unknown or from non-witnesses are ignored). Cards come from `cards`. Which rules hold for
    /// a head depends on its size (docs/06 §5, `NetState::rules_for_head`).
    pub fn check<C: Cards + ?Sized>(&self, net: &Id, rules: &LogRules, cards: &C, now_ms: i64) -> NetResult<Head> {
        self.check_at(net, rules, cards, Some(now_ms))
    }

    /// Like [`WitnessedHead::check`], but without any time check: for a transition head from the past (docs/06 §5
    /// "Übergänge beim Aufholen") - a head expires after 30 days, what it attests stays true (signers can choose
    /// any time anyway, so a time check would not make an old statement more trustworthy).
    pub(crate) fn check_history<C: Cards + ?Sized>(&self, net: &Id, rules: &LogRules, cards: &C) -> NetResult<Head> {
        self.check_at(net, rules, cards, None)
    }

    fn check_at<C: Cards + ?Sized>(&self, net: &Id, rules: &LogRules, cards: &C, now: Option<i64>) -> NetResult<Head> {
        let head = self.check_signed(net, rules, cards, now)?;
        let mut counted: Vec<&Id> = Vec::new();
        for cosign in &self.cosigns {
            let [witness] = cosign.claimed_signers()[..] else {
                continue;
            };
            if !rules.witnesses.contains(witness) || counted.contains(&witness) {
                continue;
            }
            let Some(card) = cards.card(witness) else {
                continue;
            };
            if verify_cosign(cosign, &head, card).is_ok() && now.is_none_or(|now| cosign.check_time(now).is_ok()) {
                counted.push(witness);
            }
        }
        if counted.len() < rules.witness_threshold {
            return Err(NetError::forbidden(format!(
                "head: {} of {} witness cosignatures",
                counted.len(),
                rules.witness_threshold
            )));
        }
        Ok(head)
    }

    /// The cheap check before the entries of a head beyond the own log are fetched (docs/06 §5 "Folgende Knoten",
    /// step 1): signed by a log operator of `rules` whose card is known (signature and time verified), and enough
    /// cosignatures *may* count - see [`WitnessedHead::precheck_cosigns`]. Only the full check after fetching
    /// ([`WitnessedHead::check`] with the cards of the entries ahead) decides.
    pub fn precheck<C: Cards + ?Sized>(&self, net: &Id, rules: &LogRules, cards: &C, now_ms: i64) -> NetResult<Head> {
        let head = self.check_signed(net, rules, cards, Some(now_ms))?;
        self.precheck_cosigns(net, Some(&head), rules, cards, now_ms)?;
        Ok(head)
    }

    /// Whether enough cosignatures may count under `rules` before the entries are fetched: of distinct witnesses of
    /// the rules, those with a known card must verify against `head` (the verified head, if its operator's card is
    /// known) and be valid now; those whose card is not known yet (sealed among the entries ahead) count as "maybe"
    /// if the cosignature at least names exactly this head. Refused only if valid + maybe < `witness_threshold`.
    pub fn precheck_cosigns<C: Cards + ?Sized>(
        &self,
        net: &Id,
        head: Option<&Head>,
        rules: &LogRules,
        cards: &C,
        now_ms: i64,
    ) -> NetResult<()> {
        if self.cosigns.len() > MAX_COSIGNS {
            return Err(NetError::TooLarge("cosigns".into()));
        }
        let mut counted: Vec<&Id> = Vec::new();
        for cosign in &self.cosigns {
            let [witness] = cosign.claimed_signers()[..] else {
                continue;
            };
            if !rules.witnesses.contains(witness) || counted.contains(&witness) {
                continue;
            }
            let may = match (head, cards.card(witness)) {
                (Some(head), Some(card)) => {
                    verify_cosign(cosign, head, card).is_ok() && cosign.check_time(now_ms).is_ok()
                }
                _ => self.names_this_head(net, cosign),
            };
            if may {
                counted.push(witness);
            }
        }
        if counted.len() < rules.witness_threshold {
            return Err(NetError::forbidden(format!(
                "head: {} of {} witness cosignatures may count",
                counted.len(),
                rules.witness_threshold
            )));
        }
        Ok(())
    }

    /// Before fetching: a cosignature of the net key `master` for exactly this head (verified if `head` is the verified
    /// head, otherwise it must at least name it) - the rescue form of a transition head (docs/06 §5).
    #[must_use]
    pub fn precheck_rescue(&self, net: &Id, head: Option<&Head>, master: &KeyCard, now_ms: i64) -> bool {
        master.id() == net
            && self.cosigns.iter().any(|cosign| {
                cosign.claimed_signers() == [master.id()]
                    && match head {
                        Some(head) => verify_cosign(cosign, head, master).is_ok() && cosign.check_time(now_ms).is_ok(),
                        None => self.names_this_head(net, cosign),
                    }
            })
    }

    /// The cosignature claims exactly this head (hash, operator, size, root, network) - form only, nothing verified.
    fn names_this_head(&self, net: &Id, cosign: &Statement) -> bool {
        let (Ok(body), Ok(head)) = (Cosign::from_statement(cosign), HeadBody::from_statement(&self.head)) else {
            return false;
        };
        cosign.net() == net
            && self.head.net() == net
            && body.head == self.head.hash_bytes()
            && self.head.claimed_signers() == [&body.log]
            && (body.size, body.root) == (head.size, head.root)
    }

    /// The rescue (docs/06 §5 "Not-Wiederherstellung", ADR 0012): signed by the **first** log operator of `rules`,
    /// valid now, and cosigned by the net key `master` instead of the witness quorum. Only for the transition head of
    /// a log-rules change by a manifest signed by the net key alone - [`crate::NetState::check_witnessed`] decides
    /// when it applies; never call it for other heads.
    ///
    /// Why the first one (review 6, finding 1): without witnesses, the old log operator is the only one besides the
    /// net key who vouches for the log. A second or third operator in `logs` is just someone the net key once
    /// listed: with the words alone one could list a node of one's own as "backup" and then sign the rescue head
    /// with it. The first operator is the one that issues the heads (docs/06 §5 "Rollen im Knoten"); evidence
    /// against it is not taken into account here (it is local to each node, and all nodes must decide the same).
    pub fn check_rescue<C: Cards + ?Sized>(
        &self,
        net: &Id,
        rules: &LogRules,
        master: &KeyCard,
        cards: &C,
        now_ms: i64,
    ) -> NetResult<Head> {
        self.check_rescue_at(net, rules, master, cards, Some(now_ms))
    }

    /// Like [`WitnessedHead::check_rescue`] without any time check (a transition head from the past, see
    /// [`WitnessedHead::check_history`]).
    pub(crate) fn check_rescue_history<C: Cards + ?Sized>(
        &self,
        net: &Id,
        rules: &LogRules,
        master: &KeyCard,
        cards: &C,
    ) -> NetResult<Head> {
        self.check_rescue_at(net, rules, master, cards, None)
    }

    fn check_rescue_at<C: Cards + ?Sized>(
        &self,
        net: &Id,
        rules: &LogRules,
        master: &KeyCard,
        cards: &C,
        now: Option<i64>,
    ) -> NetResult<Head> {
        if master.id() != net {
            return Err(NetError::forbidden("rescue: not the net key"));
        }
        if !self.signed_by_first(rules) {
            return Err(NetError::forbidden("rescue: head not signed by the first log operator of the rules"));
        }
        let head = self.check_signed(net, rules, cards, now)?;
        let cosigned = self.cosigns.iter().any(|cosign| {
            cosign.claimed_signers() == [master.id()]
                && verify_cosign(cosign, &head, master).is_ok()
                && now.is_none_or(|now| cosign.check_time(now).is_ok())
        });
        if !cosigned {
            return Err(NetError::forbidden("head: no valid cosignature of the net key"));
        }
        Ok(head)
    }

    /// Whether a cosignature claims the net key `net` as signer (cheap, nothing verified).
    #[must_use]
    pub fn claims_cosign_by(&self, net: &Id) -> bool {
        self.cosigns.iter().any(|cosign| cosign.claimed_signers() == [net])
    }

    /// Whether the head claims the first log operator of `rules` as its only signer (cheap, nothing verified) - the
    /// only operator whose head counts in the rescue form ([`WitnessedHead::check_rescue`]).
    #[must_use]
    pub fn signed_by_first(&self, rules: &LogRules) -> bool {
        rules.logs.first().is_some_and(|first| self.head.claimed_signers() == [first])
    }

    /// The head part of every check: at most 32 cosignatures, signed by a log operator of `rules` with a known
    /// card, valid now (if a time is given).
    fn check_signed<C: Cards + ?Sized>(
        &self,
        net: &Id,
        rules: &LogRules,
        cards: &C,
        now: Option<i64>,
    ) -> NetResult<Head> {
        if self.cosigns.len() > MAX_COSIGNS {
            return Err(NetError::TooLarge("cosigns".into()));
        }
        let operator = match self.head.claimed_signers().as_slice() {
            [operator] if rules.logs.contains(operator) => (*operator).clone(),
            _ => return Err(NetError::forbidden("head: not signed by a log operator of the rules for its size")),
        };
        let card = cards.card(&operator).ok_or_else(|| NetError::NotFound("card of the log operator".into()))?;
        let head = verify_head(&self.head, net, card)?;
        if let Some(now) = now {
            self.head.check_time(now)?;
        }
        Ok(head)
    }

    /// The size the head claims (form only).
    pub fn size(&self) -> NetResult<u64> {
        Ok(HeadBody::from_statement(&self.head)?.size)
    }

    /// `{"head": <statement>, "cosigns": [<statement>, …]}`
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({"head": self.head.to_value(), "cosigns": self.cosigns.iter().map(Statement::to_value).collect::<Vec<_>>()})
    }

    /// Parses bytes (size first).
    pub fn parse(bytes: &[u8]) -> NetResult<Self> {
        Self::from_value(&parse_strict(bytes, MAX_WITNESSED_HEAD_BYTES)?)
    }

    /// Parses the JSON form (form only; [`WitnessedHead::check`] verifies).
    pub fn from_value(value: &Value) -> NetResult<Self> {
        let object = value.as_object().ok_or_else(|| NetError::format("witnessed head: not an object"))?;
        if object.len() != 2 {
            return Err(NetError::format("witnessed head: exactly head and cosigns"));
        }
        let head = statement_of_kind(object.get("head"), Kind::Head)?;
        let list = object
            .get("cosigns")
            .and_then(Value::as_array)
            .filter(|list| list.len() <= MAX_COSIGNS)
            .ok_or_else(|| NetError::format("cosigns: list of at most 32"))?;
        let cosigns = list.iter().map(|item| statement_of_kind(Some(item), Kind::Cosign)).collect::<NetResult<_>>()?;
        Ok(Self { head, cosigns })
    }
}

fn statement_of_kind(value: Option<&Value>, kind: Kind) -> NetResult<Statement> {
    let value = value.ok_or_else(|| NetError::format(format!("{}: missing", kind.as_str())))?;
    let statement = Statement::from_value(value.clone())?;
    if statement.kind() != kind.as_str() {
        return Err(NetError::format(format!("expected a {} statement", kind.as_str())));
    }
    Ok(statement)
}

// ---------------------------------------------------------------------------------------------------------------
// Evidence

/// Proof that a log operator showed two views that cannot both be true (docs/06 §5 "Split-View"): two valid heads
/// of the same operator and network with (a) the same size but different roots, or (b) sizes m < n where the root
/// of the first m entries of the log with head n differs from head m's root. `a` is the smaller head.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    a: Statement,
    b: Statement,
}

impl Evidence {
    /// Compares two heads. Returns evidence only if both are valid heads of the same network signed by `operator`
    /// and they contradict each other - never for consistent heads. Case (b) needs the leaves of a log that matches
    /// the larger head (`leaves_of_larger`); without it only case (a) can be detected.
    #[must_use]
    pub fn check(a: &Statement, b: &Statement, operator: &KeyCard, leaves_of_larger: Option<&Tree>) -> Option<Self> {
        let head_a = verify_head(a, a.net(), operator).ok()?;
        let head_b = verify_head(b, a.net(), operator).ok()?;
        let ((small, small_head), (large, large_head)) = if (head_a.size, head_a.hash) <= (head_b.size, head_b.hash) {
            ((a, head_a), (b, head_b))
        } else {
            ((b, head_b), (a, head_a))
        };
        let contradiction = if small_head.size == large_head.size {
            small_head.root != large_head.root
        } else {
            leaves_of_larger.is_some_and(|tree| {
                tree.root_at(large_head.size).is_ok_and(|root| root == large_head.root)
                    && tree.root_at(small_head.size).is_ok_and(|root| root != small_head.root)
            })
        };
        contradiction.then(|| Self { a: small.clone(), b: large.clone() })
    }

    /// Re-checks received evidence (it is never trusted blindly).
    #[must_use]
    pub fn verify(&self, operator: &KeyCard, leaves_of_larger: Option<&Tree>) -> bool {
        Self::check(&self.a, &self.b, operator, leaves_of_larger).is_some()
    }

    /// The operator the evidence is against (as claimed - look up its card, then [`Evidence::verify`]).
    #[must_use]
    pub fn operator(&self) -> Option<&Id> {
        match self.a.claimed_signers()[..] {
            [operator] => Some(operator),
            _ => None,
        }
    }

    /// Network (as claimed).
    #[must_use]
    pub fn net(&self) -> &Id {
        self.a.net()
    }

    /// The two heads (smaller first).
    #[must_use]
    pub fn heads(&self) -> (&Statement, &Statement) {
        (&self.a, &self.b)
    }

    /// `{"a": <head>, "b": <head>}`
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({"a": self.a.to_value(), "b": self.b.to_value()})
    }

    /// Parses bytes (size first).
    pub fn parse(bytes: &[u8]) -> NetResult<Self> {
        Self::from_value(&parse_strict(bytes, MAX_EVIDENCE_BYTES)?)
    }

    /// Parses the JSON form (form only; [`Evidence::verify`] checks).
    pub fn from_value(value: &Value) -> NetResult<Self> {
        let object = value.as_object().ok_or_else(|| NetError::format("evidence: not an object"))?;
        if object.len() != 2 {
            return Err(NetError::format("evidence: exactly a and b"));
        }
        Ok(Self {
            a: statement_of_kind(object.get("a"), Kind::Head)?,
            b: statement_of_kind(object.get("b"), Kind::Head)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use bridge_core::Role;

    use super::*;
    use crate::statements::{Ban, JoinMode};

    const T0: i64 = 1_794_200_000_000;

    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32], &[seed.wrapping_add(50); 32])
    }

    struct Setup {
        master: Identity,
        net: Id,
        operator: Identity,
        operator_card: KeyCard,
        witnesses: Vec<(Identity, KeyCard)>,
        manifest: Manifest,
        log: Log,
    }

    fn setup() -> NetResult<Setup> {
        let master = identity(1);
        let net = master.id().clone();
        let operator = identity(2);
        let operator_card = operator.key_card(Role::Node, None, T0)?;
        let witnesses: Vec<(Identity, KeyCard)> = (3..6)
            .map(|seed| {
                let witness = identity(seed);
                let card = witness.key_card(Role::Node, None, T0)?;
                Ok((witness, card))
            })
            .collect::<NetResult<_>>()?;
        let mut manifest = Manifest::template(
            JoinMode::Open,
            "Test",
            master.key_card(Role::Net, None, T0)?,
            operator.id(),
            "https://op.example",
        )?;
        manifest.witnesses = witnesses.iter().map(|(w, _)| w.id().clone()).collect();
        manifest.witness_threshold = 2;
        let mut log = Log::new(net.clone());
        log.append(&manifest.sign(&net, T0, T0 + 365 * 86_400_000, &master)?)?;
        Ok(Setup { master, net, operator, operator_card, witnesses, manifest, log })
    }

    fn ban(setup: &Setup, n: u8) -> NetResult<Statement> {
        let body = Ban { subject: identity(100 + n).id().clone(), reason: format!("{n}") };
        body.sign(&setup.net, T0 + i64::from(n), T0 + 86_400_000, &setup.master)
    }

    #[test]
    fn log_structure_rules() -> NetResult<()> {
        let mut s = setup()?;
        assert_eq!(s.log.size(), 1);
        for n in 0..5 {
            s.log.append(&ban(&s, n)?)?;
        }
        assert_eq!(s.log.size(), 6);
        // Restore from entries gives the same log; page limits
        assert_eq!(Log::from_entries(s.net.clone(), s.log.entries())?, s.log);
        assert_eq!(s.log.page(2, 2).len(), 2);
        assert_eq!(s.log.page(5, 100).len(), 1);
        assert!(s.log.page(6, 100).is_empty());
        assert!(s.log.page(u64::MAX, 100).is_empty());

        // The operator side refuses what is not a log kind or of another network.
        let head = s.log.issue_head(&s.operator, T0)?;
        assert!(s.log.append(&head).is_err());
        let other = identity(9);
        let foreign =
            Ban { subject: other.id().clone(), reason: String::new() }.sign(other.id(), T0, T0 + 1, &other)?;
        assert!(s.log.append(&foreign).is_err());
        assert_eq!(s.log.size(), 6);
        // A follower mirrors whatever the operator logged (up to 64 KiB) - the state skips it later.
        s.log.append_bytes(b"\x00garbage")?;
        assert!(matches!(s.log.append_bytes(&vec![b' '; MAX_ENTRY_BYTES + 1]), Err(NetError::TooLarge(_))));
        assert_eq!(s.log.size(), 7);
        assert!(parse_entry(b"\x00garbage").is_err());
        let spaced = String::from_utf8_lossy(ban(&s, 9)?.canonical_bytes()).replacen(',', ", ", 1);
        assert!(parse_entry(spaced.as_bytes()).is_err(), "not canonical");

        // An empty log only takes a genesis manifest of its network
        let mut empty = Log::new(s.net.clone());
        assert!(empty.append(&ban(&s, 1)?).is_err());
        let not_master = s.manifest.sign(&s.net, T0, T0 + 1, &s.operator)?;
        assert!(empty.append(&not_master).is_err());
        let version_two = s.manifest.next_version().sign(&s.net, T0, T0 + 1, &s.master)?;
        assert!(empty.append(&version_two).is_err());
        assert!(Log::from_entries(s.net.clone(), &s.log.entries()[1..]).is_err());
        let spaced = String::from_utf8_lossy(s.log.entries()[0].as_slice()).replacen(',', ", ", 1);
        assert!(Log::new(s.net.clone()).append_bytes(spaced.as_bytes()).is_err(), "genesis must be canonical");
        Ok(())
    }

    #[test]
    fn heads_cosigns_and_witnessing() -> NetResult<()> {
        let mut s = setup()?;
        s.log.append(&ban(&s, 1)?)?;
        let head_statement = s.log.issue_head(&s.operator, T0 + 10)?;
        let head = verify_head(&head_statement, &s.net, &s.operator_card)?;
        assert_eq!((head.size(), *head.root()), (2, s.log.root()));
        assert_eq!(head.times(), (T0 + 10, T0 + 10 + HEAD_LIFETIME_MS));
        assert!(s.log.matches(&head));
        // Head from a non-operator / wrong card / other net
        let fake = s.log.issue_head(&s.witnesses[0].0, T0)?;
        assert!(verify_head(&fake, &s.net, &s.operator_card).is_err());
        assert!(verify_head(&head_statement, &s.net, &s.witnesses[0].1).is_err());
        assert!(verify_head(&head_statement, identity(9).id(), &s.operator_card).is_err());

        let cosigns: Vec<Statement> =
            s.witnesses.iter().map(|(w, _)| issue_cosign(w, &head, T0 + 20)).collect::<NetResult<_>>()?;
        for (cosign, (_, card)) in cosigns.iter().zip(&s.witnesses) {
            verify_cosign(cosign, &head, card)?;
        }
        assert!(verify_cosign(&cosigns[0], &head, &s.witnesses[1].1).is_err(), "wrong witness card");
        // A cosign for another head does not count for this one
        s.log.append(&ban(&s, 2)?)?;
        let newer = verify_head(&s.log.issue_head(&s.operator, T0 + 30)?, &s.net, &s.operator_card)?;
        assert!(verify_cosign(&cosigns[0], &newer, &s.witnesses[0].1).is_err());
        assert!(issue_cosign(&s.witnesses[0].0, &head, head.times().1).is_err(), "expired head");

        let mut cards: Vec<KeyCard> = s.witnesses.iter().map(|(_, c)| c.clone()).collect();
        cards.push(s.operator_card.clone());
        let witnessed = WitnessedHead { head: head_statement.clone(), cosigns: cosigns[..2].to_vec() };
        assert_eq!(witnessed.check(&s.net, &s.manifest.log_rules(), &cards, T0 + 40)?, head);
        // Roundtrip through bytes
        let bytes = bridge_core::json::canonical(&witnessed.to_value())?;
        assert_eq!(WitnessedHead::parse(&bytes)?, witnessed);

        // Below threshold: one cosign, the same cosign twice, a cosign from a non-witness, a forged cosign
        let one = WitnessedHead { head: head_statement.clone(), cosigns: vec![cosigns[0].clone()] };
        assert!(matches!(one.check(&s.net, &s.manifest.log_rules(), &cards, T0 + 40), Err(NetError::Forbidden(_))));
        let twice =
            WitnessedHead { head: head_statement.clone(), cosigns: vec![cosigns[0].clone(), cosigns[0].clone()] };
        assert!(twice.check(&s.net, &s.manifest.log_rules(), &cards, T0 + 40).is_err());
        let outsider = identity(8);
        cards.push(outsider.key_card(Role::Node, None, T0)?);
        let foreign = WitnessedHead {
            head: head_statement.clone(),
            cosigns: vec![cosigns[0].clone(), issue_cosign(&outsider, &head, T0 + 20)?],
        };
        assert!(foreign.check(&s.net, &s.manifest.log_rules(), &cards, T0 + 40).is_err());
        let mut forged = cosigns[1].to_value();
        forged["body"]["size"] = json!(99);
        let forged = WitnessedHead {
            head: head_statement.clone(),
            cosigns: vec![cosigns[0].clone(), Statement::from_value(forged)?],
        };
        assert!(forged.check(&s.net, &s.manifest.log_rules(), &cards, T0 + 40).is_err());
        // Head from a node that is not a log operator, even with enough cosigns
        let rogue = verify_head(&fake, &s.net, &s.witnesses[0].1)?;
        let rogue = WitnessedHead {
            head: fake.clone(),
            cosigns: s.witnesses.iter().map(|(w, _)| issue_cosign(w, &rogue, T0 + 20)).collect::<NetResult<_>>()?,
        };
        assert!(rogue.check(&s.net, &s.manifest.log_rules(), &cards, T0 + 40).is_err());
        // Expired head; unknown operator card
        assert!(witnessed.check(&s.net, &s.manifest.log_rules(), &cards, head.times().1).is_err());
        assert!(witnessed.check(&s.net, &s.manifest.log_rules(), &cards[..3], T0 + 40).is_err());
        // Too many cosigns
        let many = WitnessedHead { head: head_statement, cosigns: vec![cosigns[0].clone(); MAX_COSIGNS + 1] };
        assert!(matches!(many.check(&s.net, &s.manifest.log_rules(), &cards, T0 + 40), Err(NetError::TooLarge(_))));
        assert!(WitnessedHead::parse(&bridge_core::json::canonical(&many.to_value())?).is_err());
        assert!(WitnessedHead::from_value(&json!({"head": cosigns[0].to_value(), "cosigns": []})).is_err());
        Ok(())
    }

    #[test]
    fn evidence_only_for_real_split_views() -> NetResult<()> {
        let mut s = setup()?;
        let card = s.operator_card.clone();
        for n in 0..4 {
            s.log.append(&ban(&s, n)?)?;
        }
        let honest_small = s.log.issue_head(&s.operator, T0 + 1)?;
        let honest_small_again = s.log.issue_head(&s.operator, T0 + 2)?;
        s.log.append(&ban(&s, 9)?)?;
        let honest_large = s.log.issue_head(&s.operator, T0 + 3)?;
        // Honest heads never give evidence, in any order, with or without the leaves.
        for (a, b) in
            [(&honest_small, &honest_large), (&honest_large, &honest_small), (&honest_small, &honest_small_again)]
        {
            assert!(Evidence::check(a, b, &card, Some(s.log.tree())).is_none());
            assert!(Evidence::check(a, b, &card, None).is_none());
        }

        // (a) same size, other root
        let lie = issue_head(&s.operator, &s.net, s.log.size(), [7; 32], T0 + 4)?;
        let evidence = Evidence::check(&honest_large, &lie, &card, None).ok_or(NetError::NotFound("a".into()))?;
        assert!(evidence.verify(&card, None));
        assert_eq!(evidence.operator(), Some(s.operator.id()));
        let parsed = Evidence::parse(&bridge_core::json::canonical(&evidence.to_value())?)?;
        assert_eq!(parsed, evidence);
        // (b) the smaller head's root is not a prefix of the log that matches the larger head
        let lie_small = issue_head(&s.operator, &s.net, 3, [8; 32], T0 + 5)?;
        let evidence = Evidence::check(&lie_small, &honest_large, &card, Some(s.log.tree()));
        assert!(evidence.is_some_and(|e| e.verify(&card, Some(s.log.tree())) && !e.verify(&card, None)));
        assert!(Evidence::check(&lie_small, &honest_large, &card, None).is_none(), "(b) needs the leaves");
        // (b) is not concluded from a tree that does not match the larger head
        let mut other_tree = Tree::new();
        for n in 0..9u8 {
            other_tree.push_entry(&[n])?;
        }
        assert!(Evidence::check(&lie_small, &honest_large, &card, Some(&other_tree)).is_none());

        // Not evidence: heads of different operators, a forged head, heads of different nets.
        let witness = &s.witnesses[0].0;
        let by_other = issue_head(witness, &s.net, s.log.size(), [7; 32], T0)?;
        assert!(Evidence::check(&honest_large, &by_other, &card, None).is_none());
        let mut forged = lie.to_value();
        forged["body"]["root"] = json!(bridge_core::encoding::b64(&[9; 32]));
        assert!(Evidence::check(&honest_large, &Statement::from_value(forged)?, &card, None).is_none());
        let other_net = issue_head(&s.operator, identity(9).id(), s.log.size(), [7; 32], T0)?;
        assert!(Evidence::check(&honest_large, &other_net, &card, None).is_none());
        // Malformed serialized evidence
        assert!(Evidence::from_value(&json!({"a": honest_large.to_value()})).is_err());
        assert!(Evidence::from_value(&json!({"a": ban(&s, 1)?.to_value(), "b": lie.to_value()})).is_err());
        assert!(Evidence::parse(&[b'{'; 20_000]).is_err());
        Ok(())
    }
}
