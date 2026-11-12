//! Blocklists (docs/08 §9): lists of names, apps, nodes and members that a publisher the network's manifest names
//! (`blocklists`, 0-8 IDs) wants blocked. A node treats a listed target like a banned one when it resolves, searches
//! and serves - without a log entry: the operator decides whom to trust, the publisher decides what is on the list.
//!
//! - The `blocklist` statement is not a log entry (like `app`): signed by the publisher alone, its key card in the body
//!   (the publisher needs no seal and no membership), at most [`MAX_BLOCKLIST_BYTES`], a lifetime of at most one year,
//!   bound to one network (`net`). A higher `version` replaces a lower one; an equal or lower one is ignored.
//! - Entries: `id:<id>` (an app, node or member - also the owner of a name) or `name:<skeleton>` (the confusable
//!   skeleton of a name, docs/08 §4 - so `paypa1` is caught by `name:paypal`'s skeleton too). Strictly sorted, no
//!   duplicates, at most [`MAX_BLOCKLIST_ENTRIES`].
//! - [`Blocklists`] keeps the newest valid list per publisher the manifest names now; a publisher dropped from the
//!   manifest stops counting at once, an expired list stops counting at its expiry.

use std::collections::{BTreeMap, BTreeSet};

use bridge_core::statement::Draft;
use bridge_core::{Id, Identity, KeyCard, Statement};
use serde_json::{Map, Value, json};

use crate::error::{NetError, NetResult};
use crate::names::{MAX_NAME_CHARS, MIN_NAME_CHARS, skeleton};
use crate::state::{NetState, ResolvedName};
use crate::statements::{Body, Kind};

/// Most entries of one list.
pub const MAX_BLOCKLIST_ENTRIES: usize = 10_000;
/// Largest `blocklist` statement.
pub const MAX_BLOCKLIST_BYTES: usize = 512 * 1024;
/// Longest lifetime of a list.
pub const MAX_BLOCKLIST_LIFETIME_MS: i64 = 366 * 24 * 3600 * 1000;
/// Most publishers a manifest names (the field `blocklists`).
pub const MAX_PUBLISHERS: usize = 8;

/// One entry of a blocklist.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockEntry {
    /// An app, node or member ID.
    Id(Id),
    /// The skeleton of a name (docs/08 §4).
    Name(String),
}

impl BlockEntry {
    /// The entry for a name: its skeleton.
    #[must_use]
    pub fn name(name: &str) -> Self {
        Self::Name(skeleton(name))
    }

    /// Strict parse of the wire form (`id:<id>` or `name:<skeleton>`, the skeleton as [`skeleton`] gives it).
    pub fn parse(text: &str) -> NetResult<Self> {
        if let Some(id) = text.strip_prefix("id:") {
            return Ok(Self::Id(Id::parse(id).map_err(|_| NetError::format("blocklist entry: id:<id>"))?));
        }
        if let Some(name) = text.strip_prefix("name:") {
            let ok = (MIN_NAME_CHARS..=MAX_NAME_CHARS * 2).contains(&name.len())
                && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && skeleton(name) == name;
            if !ok {
                return Err(NetError::format("blocklist entry: name:<skeleton of a name>"));
            }
            return Ok(Self::Name(name.to_owned()));
        }
        Err(NetError::format("blocklist entry: id:<id> or name:<skeleton>"))
    }

    /// The wire form.
    #[must_use]
    pub fn to_text(&self) -> String {
        match self {
            Self::Id(id) => format!("id:{id}"),
            Self::Name(name) => format!("name:{name}"),
        }
    }
}

/// A blocklist: what one publisher wants blocked in one network.
#[derive(Debug, Clone, PartialEq)]
pub struct Blocklist {
    /// The publisher (signer).
    pub publisher: Id,
    /// The publisher's key card (its ID is `publisher`).
    pub card: KeyCard,
    /// Version (1 or more); a higher one replaces a lower one.
    pub version: u64,
    /// The entries.
    pub entries: BTreeSet<BlockEntry>,
}

const FIELDS: [&str; 4] = ["publisher", "card", "version", "entries"];

impl Body for Blocklist {
    const KIND: Kind = Kind::Blocklist;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = body.as_object().ok_or_else(|| NetError::format("blocklist: body is not an object"))?;
        if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err(NetError::format("blocklist: fields publisher, card, version, entries"));
        }
        let publisher = Id::parse(object.get("publisher").and_then(Value::as_str).unwrap_or_default())
            .map_err(|_| NetError::format("blocklist: publisher"))?;
        let card = KeyCard::from_value(object.get("card").cloned().unwrap_or(Value::Null))?;
        if card.id() != &publisher {
            return Err(NetError::format("blocklist: the card is not the publisher's"));
        }
        let version = object
            .get("version")
            .and_then(Value::as_u64)
            .filter(|version| (1..=i64::MAX as u64).contains(version))
            .ok_or_else(|| NetError::format("blocklist: version 1 or more"))?;
        let list = object
            .get("entries")
            .and_then(Value::as_array)
            .filter(|list| list.len() <= MAX_BLOCKLIST_ENTRIES)
            .ok_or_else(|| NetError::format("blocklist: entries, at most 10,000"))?;
        let mut entries = BTreeSet::new();
        let mut last: Option<&str> = None;
        for item in list {
            let text = item.as_str().ok_or_else(|| NetError::format("blocklist: entries are strings"))?;
            // Strictly sorted by the wire text: one form per list, no duplicates.
            if last.is_some_and(|last| last >= text) {
                return Err(NetError::format("blocklist: entries strictly sorted"));
            }
            last = Some(text);
            entries.insert(BlockEntry::parse(text)?);
        }
        Ok(Self { publisher, card, version, entries })
    }

    fn to_body(&self) -> NetResult<Value> {
        let mut texts: Vec<String> = self.entries.iter().map(BlockEntry::to_text).collect();
        texts.sort();
        texts.dedup();
        if texts.len() > MAX_BLOCKLIST_ENTRIES {
            return Err(NetError::format("blocklist: at most 10,000 entries"));
        }
        let mut body = Map::new();
        body.insert("publisher".into(), json!(self.publisher.as_str()));
        body.insert("card".into(), self.card.to_value());
        body.insert("version".into(), json!(self.version));
        body.insert("entries".into(), json!(texts));
        let value = Value::Object(body);
        Self::from_body(&value)?;
        Ok(value)
    }
}

impl Blocklist {
    /// Signs the list as the publisher (`publisher` must be the key of the list).
    pub fn sign_list(&self, net: &Id, iat: i64, exp: i64, publisher: &Identity) -> NetResult<Statement> {
        if publisher.id() != &self.publisher {
            return Err(NetError::format("blocklist: signed by another key than the publisher"));
        }
        if exp <= iat || exp - iat > MAX_BLOCKLIST_LIFETIME_MS {
            return Err(NetError::format("blocklist: lifetime at most one year"));
        }
        let draft = Draft { kind: Kind::Blocklist.as_str(), net, iat, exp, body: self.to_body()? };
        Ok(Statement::sign_multi_with_limit(&draft, &[publisher], MAX_BLOCKLIST_BYTES)?)
    }

    /// Parses a `blocklist` statement from bytes (form only, see [`Blocklist::verify`]).
    pub fn parse_statement(bytes: &[u8]) -> NetResult<Statement> {
        Ok(Statement::parse_with_limit(bytes, MAX_BLOCKLIST_BYTES)?)
    }

    /// Everything that holds without the network state: kind, network `net`, strict body, exactly the publisher as
    /// signer with a valid signature by the card in the body, lifetime at most one year, valid at `now`.
    pub fn verify(statement: &Statement, net: &Id, now: i64) -> NetResult<Self> {
        if statement.kind() != Kind::Blocklist.as_str() {
            return Err(NetError::format("expected a blocklist statement"));
        }
        if statement.net() != net {
            return Err(NetError::format("blocklist: other network"));
        }
        let list = Self::from_body(statement.body())?;
        if statement.claimed_signers() != [&list.publisher] {
            return Err(NetError::format("blocklist: signed by the publisher alone"));
        }
        statement.verify(&[&list.card], 1)?;
        let (iat, exp) = statement.times();
        if exp - iat > MAX_BLOCKLIST_LIFETIME_MS {
            return Err(NetError::format("blocklist: lifetime at most one year"));
        }
        statement.check_time(now)?;
        Ok(list)
    }

    /// Whether the list names `id`.
    #[must_use]
    pub fn blocks_id(&self, id: &Id) -> bool {
        self.entries.contains(&BlockEntry::Id(id.clone()))
    }

    /// Whether the list names the skeleton of `name`.
    #[must_use]
    pub fn blocks_name(&self, name: &str) -> bool {
        self.entries.contains(&BlockEntry::name(name))
    }
}

/// The blocklists a node applies: the newest valid list per publisher the manifest names.
#[derive(Debug, Clone, Default)]
pub struct Blocklists {
    lists: BTreeMap<Id, (Blocklist, Statement)>,
}

impl Blocklists {
    /// Takes a list if it is valid now, its publisher is named by the manifest of `state` and it is newer than the
    /// one held. Returns whether it was taken.
    pub fn offer(&mut self, statement: &Statement, state: &NetState, now: i64) -> NetResult<bool> {
        let list = Blocklist::verify(statement, state.net(), now)?;
        let named = state.manifest().blocklists.as_ref().is_some_and(|ids| ids.contains(&list.publisher));
        if !named {
            return Err(NetError::forbidden("blocklist: the manifest does not name this publisher"));
        }
        if self.lists.get(&list.publisher).is_some_and(|(held, _)| held.version >= list.version) {
            return Ok(false);
        }
        self.lists.insert(list.publisher.clone(), (list, statement.clone()));
        Ok(true)
    }

    /// Keeps a list that was verified with [`Blocklist::verify`] against this network and whose publisher the
    /// manifest names (the caller checked both) - if it is newer than the one held. Returns whether it was kept.
    pub fn insert_checked(&mut self, list: Blocklist, statement: Statement) -> bool {
        if self.lists.get(&list.publisher).is_some_and(|(held, _)| held.version >= list.version) {
            return false;
        }
        self.lists.insert(list.publisher.clone(), (list, statement));
        true
    }

    /// Drops the lists of publishers the manifest no longer names.
    pub fn retain_named(&mut self, state: &NetState) {
        let named = state.manifest().blocklists.clone().unwrap_or_default();
        self.lists.retain(|publisher, _| named.contains(publisher));
    }

    /// The list statement of `publisher`, if held.
    #[must_use]
    pub fn statement(&self, publisher: &Id) -> Option<&Statement> {
        self.lists.get(publisher).map(|(_, statement)| statement)
    }

    /// The version held of `publisher`'s list.
    #[must_use]
    pub fn version(&self, publisher: &Id) -> Option<u64> {
        self.lists.get(publisher).map(|(list, _)| list.version)
    }

    /// Number of lists held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lists.len()
    }

    /// Whether no list is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }

    /// The lists that count at `at` (not expired).
    fn active(&self, at: i64) -> impl Iterator<Item = &Blocklist> {
        self.lists.values().filter(move |(_, statement)| statement.times().1 > at).map(|(list, _)| list)
    }

    /// The publisher of a list that names `id` at `at`.
    #[must_use]
    pub fn blocks_id(&self, id: &Id, at: i64) -> Option<&Id> {
        self.active(at).find(|list| list.blocks_id(id)).map(|list| &list.publisher)
    }

    /// The publisher of a list that names the skeleton of `name` at `at`.
    #[must_use]
    pub fn blocks_name(&self, name: &str, at: i64) -> Option<&Id> {
        self.active(at).find(|list| list.blocks_name(name)).map(|list| &list.publisher)
    }

    /// Whether a resolved name is blocked at `at`: the name itself, its target or its owner.
    #[must_use]
    pub fn blocks_resolved(&self, resolved: &ResolvedName, at: i64) -> bool {
        let body = &resolved.info.name;
        self.blocks_name(&body.name, at).is_some()
            || self.blocks_id(&body.target, at).is_some()
            || self.blocks_id(&body.owner, at).is_some()
    }

    /// Whether an app or its owner is blocked at `at`.
    #[must_use]
    pub fn blocks_app(&self, app: &Id, owner: &Id, at: i64) -> bool {
        self.blocks_id(app, at).is_some() || self.blocks_id(owner, at).is_some()
    }
}

#[cfg(test)]
mod tests {
    use bridge_core::Role;
    use rand_core::OsRng;

    use super::*;
    use crate::statements::{JoinMode, Manifest};

    const DAY: i64 = 24 * 3600 * 1000;
    const NOW: i64 = 1_800_000_000_000;

    /// A network whose genesis manifest names `publishers`.
    fn net(publishers: &[&Identity]) -> NetResult<NetState> {
        let master = Identity::generate(&mut OsRng);
        let node = Identity::generate(&mut OsRng);
        let card = master.key_card(Role::Net, None, NOW)?;
        let mut manifest = Manifest::template(JoinMode::Open, "Netz", card, node.id(), "http://127.0.0.1:7400")?;
        manifest.blocklists = Some(publishers.iter().map(|p| p.id().clone()).collect());
        let statement = manifest.sign(master.id(), NOW, NOW + 300 * DAY, &master)?;
        NetState::genesis(master.id(), statement.canonical_bytes())
    }

    fn list(publisher: &Identity, version: u64, entries: &[BlockEntry]) -> NetResult<Blocklist> {
        Ok(Blocklist {
            publisher: publisher.id().clone(),
            card: publisher.key_card(Role::Client, None, NOW)?,
            version,
            entries: entries.iter().cloned().collect(),
        })
    }

    #[test]
    fn a_named_publisher_blocks_names_apps_and_owners() -> NetResult<()> {
        let publisher = Identity::generate(&mut OsRng);
        let state = net(&[&publisher])?;
        let app = Identity::generate(&mut OsRng);
        let entries = [BlockEntry::name("paypal"), BlockEntry::Id(app.id().clone())];
        let statement = list(&publisher, 1, &entries)?.sign_list(state.net(), NOW, NOW + 30 * DAY, &publisher)?;
        // The wire form survives a round trip through bytes.
        let parsed = Blocklist::parse_statement(statement.canonical_bytes())?;
        let mut lists = Blocklists::default();
        assert!(lists.offer(&parsed, &state, NOW)?);
        assert_eq!(lists.blocks_name("paypal", NOW), Some(publisher.id()));
        assert_eq!(lists.blocks_name("paypa1", NOW), Some(publisher.id()), "confusables share the skeleton");
        assert_eq!(lists.blocks_name("shop", NOW), None);
        assert!(lists.blocks_app(app.id(), publisher.id(), NOW));
        assert_eq!(lists.blocks_id(app.id(), NOW + 31 * DAY), None, "an expired list stops counting");
        // The same version again, or an older one: ignored; a newer one replaces it.
        assert!(!lists.offer(&parsed, &state, NOW)?);
        let newer = list(&publisher, 2, &[])?.sign_list(state.net(), NOW, NOW + DAY, &publisher)?;
        assert!(lists.offer(&newer, &state, NOW)?);
        assert_eq!((lists.version(publisher.id()), lists.blocks_name("paypal", NOW)), (Some(2), None));
        let older = list(&publisher, 1, &entries)?.sign_list(state.net(), NOW, NOW + DAY, &publisher)?;
        assert!(!lists.offer(&older, &state, NOW)?, "no rollback to an older version");
        Ok(())
    }

    /// Attack: lists from publishers the manifest does not name, forged or foreign ones, bent forms.
    #[test]
    fn foreign_forged_and_bent_lists_are_refused() -> NetResult<()> {
        let publisher = Identity::generate(&mut OsRng);
        let stranger = Identity::generate(&mut OsRng);
        let state = net(&[&publisher])?;
        let other = net(&[&publisher])?;
        let mut lists = Blocklists::default();
        let entries = [BlockEntry::name("shop")];
        // Not named by the manifest.
        let foreign = list(&stranger, 1, &entries)?.sign_list(state.net(), NOW, NOW + DAY, &stranger)?;
        assert!(lists.offer(&foreign, &state, NOW).is_err());
        // Signed by another key than the card in the body says.
        let mut forged = list(&publisher, 1, &entries)?;
        assert!(forged.sign_list(state.net(), NOW, NOW + DAY, &stranger).is_err());
        forged.card = stranger.key_card(Role::Client, None, NOW)?;
        assert!(forged.to_body().is_err(), "the card must be the publisher's");
        // Another network's list.
        let elsewhere = list(&publisher, 1, &entries)?.sign_list(other.net(), NOW, NOW + DAY, &publisher)?;
        assert!(lists.offer(&elsewhere, &state, NOW).is_err());
        // Too long, not yet valid, expired.
        assert!(list(&publisher, 1, &entries)?.sign_list(state.net(), NOW, NOW + 400 * DAY, &publisher).is_err());
        let later = list(&publisher, 1, &entries)?.sign_list(state.net(), NOW + DAY, NOW + 2 * DAY, &publisher)?;
        assert!(lists.offer(&later, &state, NOW).is_err());
        assert!(lists.offer(&later, &state, NOW + 3 * DAY).is_err());
        assert!(lists.is_empty());
        // Bent entries and bodies.
        for bad in ["", "id:", "id:kaputt", "name:", "name:PayPal", "name:pay pal", "shop", "name:a", "url:x"] {
            assert!(BlockEntry::parse(bad).is_err(), "{bad:?}");
        }
        let mut body = list(&publisher, 1, &[BlockEntry::name("ab"), BlockEntry::name("cd")])?.to_body()?;
        body["entries"] = json!(["name:cd", "name:ab"]);
        assert!(Blocklist::from_body(&body).is_err(), "unsorted");
        body["entries"] = json!(["name:ab", "name:ab"]);
        assert!(Blocklist::from_body(&body).is_err(), "duplicates");
        body["entries"] = json!(["name:ab"]);
        body["extra"] = json!(1);
        assert!(Blocklist::from_body(&body).is_err(), "unknown field");
        body.as_object_mut().map(|object| object.remove("extra"));
        body["version"] = json!(0);
        assert!(Blocklist::from_body(&body).is_err(), "version 0");
        let many: Vec<BlockEntry> = (0..=MAX_BLOCKLIST_ENTRIES).map(|i| BlockEntry::Name(format!("n{i:05}"))).collect();
        assert!(list(&publisher, 1, &many)?.to_body().is_err(), "more than 10,000 entries");
        Ok(())
    }

    #[test]
    fn a_publisher_dropped_from_the_manifest_stops_counting() -> NetResult<()> {
        let publisher = Identity::generate(&mut OsRng);
        let state = net(&[&publisher])?;
        let statement =
            list(&publisher, 1, &[BlockEntry::name("shop")])?.sign_list(state.net(), NOW, NOW + DAY, &publisher)?;
        let mut lists = Blocklists::default();
        lists.offer(&statement, &state, NOW)?;
        lists.retain_named(&state);
        assert_eq!(lists.len(), 1);
        let without = net(&[])?;
        lists.retain_named(&without);
        assert!(lists.is_empty());
        Ok(())
    }
}
