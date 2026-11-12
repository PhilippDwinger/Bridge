//! Names and labels of a network (docs/08 §2-§5, ADR 0018): the `name` and `label` statements (log entries), the
//! name rules of the manifest, and the deterministic helpers every node uses the same way - syntax, the confusable
//! skeleton, reserved words, addresses.
//!
//! - A name is `[a-z0-9-]`, 2-40 characters, no leading/trailing/double hyphen, and never a valid ID (so an input is
//!   always either a name or an ID). ASCII only: no homoglyphs from other scripts.
//! - The **skeleton** maps look-alike characters onto one form (digits to letters, `m`/`w`/`d` split into `rn`/`vv`/`cl`
//!   so the order of replacements does not matter). Two names with the same skeleton can not both hold.
//! - A name whose skeleton contains the skeleton of a reserved word needs an owner of level 3.
//! - App names are signed by the app key **and** the owner (`sigs`) - the state learns who owns an app without its
//!   manifest being in the log; both cards travel in the body (members of level 0/1 have no card in the log).

use std::collections::BTreeSet;

use bridge_core::{Id, Identity, KeyCard, Role, Statement};
use serde_json::{Map, Value, json};

use crate::error::{NetError, NetResult};
use crate::statements::{
    Body, DAY_MS, Kind, MAX_REASON_CHARS, card, check_text, checked, fields, id, ids_value, number, object, text,
};

/// Shortest name.
pub const MIN_NAME_CHARS: usize = 2;
/// Longest name.
pub const MAX_NAME_CHARS: usize = 40;
/// Longest short name of a network (`short` in the manifest).
pub const MAX_SHORT_CHARS: usize = 24;
/// Longest tag.
pub const MAX_TAG_CHARS: usize = 24;
/// Most tags of a name.
pub const MAX_TAGS: usize = 8;
/// Longest description of a name.
pub const MAX_NAME_DESCRIPTION_CHARS: usize = 200;
/// Most host hints of an app name.
pub const MAX_NAME_HOSTS: usize = 8;
/// Longest lifetime of a name (renewal by the same owner keeps it).
pub const MAX_NAME_LIFETIME_MS: i64 = 365 * DAY_MS;
/// Longest contact (Meldeweg) in the manifest.
pub const MAX_CONTACT_CHARS: usize = 200;
/// Most reserved words a manifest adds.
pub const MAX_RESERVED_WORDS: usize = 64;
/// Highest number of names per level a manifest may allow.
pub const MAX_QUOTA_PER_LEVEL: u64 = 1_000;
/// Most blocklist publishers in a manifest.
pub const MAX_BLOCKLISTS: usize = 8;
/// Reserved words that hold in every network (docs/08 §4); the manifest adds its own.
pub const BASE_RESERVED: [&str; 15] = [
    "bank", "login", "paypal", "admin", "support", "official", "secure", "wallet", "verify", "update", "account",
    "bridge", "password", "passwort", "konto",
];

/// `[a-z0-9-]`, `min..=max` characters, no leading, trailing or double hyphen.
pub fn check_word(text: &str, min: usize, max: usize, what: &str) -> NetResult<()> {
    let ok = (min..=max).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
        && !text.contains("--");
    if ok {
        Ok(())
    } else {
        Err(NetError::format(format!("{what}: {min}-{max} of a-z 0-9 -, no leading, trailing or double hyphen")))
    }
}

/// Name syntax (docs/08 §3): a word of 2-40 characters that is not a valid ID.
pub fn check_name(name: &str) -> NetResult<()> {
    check_word(name, MIN_NAME_CHARS, MAX_NAME_CHARS, "name")?;
    if Id::parse(name).is_ok() {
        return Err(NetError::format("name: must not look like an ID"));
    }
    Ok(())
}

/// Short name of a network (`short`): a word of 2-24 characters.
pub fn check_short(short: &str) -> NetResult<()> {
    check_word(short, MIN_NAME_CHARS, MAX_SHORT_CHARS, "short")
}

/// The confusable skeleton of a name (docs/08 §4). Input is lowered first, so it also works for search queries.
#[must_use]
pub fn skeleton(name: &str) -> String {
    let mut out = String::with_capacity(name.len().saturating_mul(2));
    for c in name.chars().map(|c| c.to_ascii_lowercase()) {
        match c {
            '-' => {}
            '0' => out.push('o'),
            '1' | 'i' => out.push('l'),
            '2' => out.push('z'),
            '3' => out.push('e'),
            '4' => out.push('a'),
            '5' => out.push('s'),
            '6' | '8' => out.push('b'),
            '7' => out.push('t'),
            '9' => out.push('g'),
            'm' => out.push_str("rn"),
            'w' => out.push_str("vv"),
            'd' => out.push_str("cl"),
            other => out.push(other),
        }
    }
    out
}

/// Whether a skeleton contains the skeleton of a reserved word (the fixed list or `extra` from the manifest).
#[must_use]
pub fn is_reserved(skeleton_of_name: &str, extra: &[String]) -> bool {
    reserved_skeletons(extra).iter().any(|word| skeleton_of_name.contains(word.as_str()))
}

/// The skeletons of all reserved words of a network: the fixed list and `extra` from the manifest.
#[must_use]
pub fn reserved_skeletons(extra: &[String]) -> Vec<String> {
    BASE_RESERVED.iter().copied().chain(extra.iter().map(String::as_str)).map(skeleton).collect()
}

/// Whether a name or one of its tags contains a reserved word (docs/08 §4; tags since review 9). `reserved`: the
/// skeletons of [`reserved_skeletons`].
#[must_use]
pub fn name_is_reserved(name_skeleton: &str, tags: &[String], reserved: &[String]) -> bool {
    let hit = |skeleton_of: &str| reserved.iter().any(|word| skeleton_of.contains(word.as_str()));
    hit(name_skeleton) || tags.iter().any(|tag| hit(&skeleton(tag)))
}

/// Whether a word of a description contains a reserved word (such words do not count for the search of owners below
/// level 3, docs/08 §7). `reserved`: the skeletons of [`reserved_skeletons`].
#[must_use]
pub fn description_is_reserved(description: &str, reserved: &[String]) -> bool {
    description_words(description).any(|word| {
        let word = skeleton(&word);
        reserved.iter().any(|reserved| word.contains(reserved.as_str()))
    })
}

/// Text as the search compares it (docs/10 §5): lower case, umlauts and accents of Latin letters removed
/// (`ä→a`, `é→e`, `ß→ss`, `æ→ae` …) - so `Läden`, `laden` and `LADEN` are the same word.
#[must_use]
pub fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars().flat_map(char::to_lowercase) {
        match c {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => out.push('a'),
            'ç' | 'ć' | 'č' => out.push('c'),
            'ď' | 'đ' => out.push('d'),
            'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ė' | 'ę' | 'ě' => out.push('e'),
            'ì' | 'í' | 'î' | 'ï' | 'ī' | 'į' | 'ı' => out.push('i'),
            'ł' | 'ľ' | 'ĺ' => out.push('l'),
            'ñ' | 'ń' | 'ň' => out.push('n'),
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => out.push('o'),
            'ř' | 'ŕ' => out.push('r'),
            'ś' | 'š' | 'ş' => out.push('s'),
            'ť' | 'ţ' => out.push('t'),
            'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' | 'ų' => out.push('u'),
            'ý' | 'ÿ' => out.push('y'),
            'ź' | 'ż' | 'ž' => out.push('z'),
            'ß' => out.push_str("ss"),
            'æ' => out.push_str("ae"),
            'œ' => out.push_str("oe"),
            other => out.push(other),
        }
    }
    out
}

/// The words of a description, folded (split at everything that is no letter or digit).
fn description_words(description: &str) -> impl Iterator<Item = String> + '_ {
    description.split(|c: char| !c.is_alphanumeric()).filter(|word| !word.is_empty()).map(fold)
}

/// The words of a description as the search compares them: lower case, each after one space (` mein laden`) - so
/// "a word starts with `q`" is a plain substring test for ` q` (docs/08 §7, no allocation per name and search).
#[must_use]
pub fn search_words(description: &str) -> String {
    let mut out = String::with_capacity(description.len().saturating_add(8));
    for word in description_words(description) {
        out.push(' ');
        out.push_str(&word);
    }
    out
}

/// Splits an address `name.short` (or a plain `name`) into name and short name. Exactly one dot at most; the parts
/// are not checked here.
#[must_use]
pub fn split_address(address: &str) -> (&str, Option<&str>) {
    match address.split_once('.') {
        Some((name, short)) => (name, Some(short)),
        None => (address, None),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Categories, kinds, rules

/// Self-declared or labeled category of a name or target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// For everybody.
    General,
    /// 18+.
    Adult,
}

impl Category {
    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Adult => "adult",
        }
    }

    /// The category for a wire name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "general" => Some(Self::General),
            "adult" => Some(Self::Adult),
            _ => None,
        }
    }

    fn from_field(object: &Map<String, Value>) -> NetResult<Self> {
        Self::parse(text(object, "category")?).ok_or_else(|| NetError::format("category: general or adult"))
    }
}

/// What a name points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameKind {
    /// A Bridge app (target = app ID).
    App,
    /// A node (target = node ID = owner).
    Node,
    /// A member (target = member ID = owner).
    Member,
}

impl NameKind {
    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Node => "node",
            Self::Member => "member",
        }
    }

    /// The kind for a wire name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "app" => Some(Self::App),
            "node" => Some(Self::Node),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

/// Whether a network allows 18+ content (manifest field `adult`, default `forbidden`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdultPolicy {
    /// Allowed when labeled (never shown in the safe search).
    Allowed,
    /// Not allowed: adult names are refused, adult-labeled names and apps are dropped.
    Forbidden,
}

impl AdultPolicy {
    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Forbidden => "forbidden",
        }
    }

    /// The policy for a wire name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "allowed" => Some(Self::Allowed),
            "forbidden" => Some(Self::Forbidden),
            _ => None,
        }
    }
}

/// Name rules of the manifest (`names`, docs/08 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRules {
    /// Lowest level of an owner to register a name (0-3).
    pub min_level: u8,
    /// Active names per owner, by the owner's level 0-3 (each 0-1000).
    pub quota: [u64; 4],
    /// Reserved words besides [`BASE_RESERVED`] (0-64, name syntax).
    pub reserved: Vec<String>,
}

impl Default for NameRules {
    fn default() -> Self {
        Self { min_level: 1, quota: [0, 3, 20, 100], reserved: Vec::new() }
    }
}

impl NameRules {
    /// Active names an owner of `level` may have.
    #[must_use]
    pub fn quota_for(&self, level: u8) -> u64 {
        self.quota[usize::from(level.min(3))]
    }

    pub(crate) fn parse(value: &Value) -> NetResult<Self> {
        let names = object(value, "names")?;
        fields(names, &["min_level", "quota", "reserved"], &[], "names")?;
        let min_level =
            u8::try_from(number(names, "min_level", 0, 3)?).map_err(|_| NetError::format("names.min_level"))?;
        let list = names
            .get("quota")
            .and_then(Value::as_array)
            .filter(|list| list.len() == 4)
            .ok_or_else(|| NetError::format("names.quota: four numbers (levels 0-3)"))?;
        let mut quota = [0u64; 4];
        for (slot, item) in quota.iter_mut().zip(list) {
            *slot = item
                .as_u64()
                .filter(|count| *count <= MAX_QUOTA_PER_LEVEL)
                .ok_or_else(|| NetError::format("names.quota: integers 0..=1000"))?;
        }
        let list = names
            .get("reserved")
            .and_then(Value::as_array)
            .filter(|list| list.len() <= MAX_RESERVED_WORDS)
            .ok_or_else(|| NetError::format("names.reserved: 0..=64 words"))?;
        let mut reserved: Vec<String> = Vec::with_capacity(list.len());
        for item in list {
            let word = item.as_str().ok_or_else(|| NetError::format("names.reserved: strings"))?;
            check_word(word, MIN_NAME_CHARS, MAX_NAME_CHARS, "names.reserved")?;
            if reserved.iter().any(|known| known == word) {
                return Err(NetError::format("names.reserved: duplicate"));
            }
            reserved.push(word.to_owned());
        }
        Ok(Self { min_level, quota, reserved })
    }

    pub(crate) fn to_value(&self) -> Value {
        json!({"min_level": self.min_level, "quota": self.quota, "reserved": self.reserved})
    }
}

/// 0..=max distinct IDs (an empty list is fine).
pub(crate) fn id_set(value: Option<&Value>, max: usize, what: &str) -> NetResult<Vec<Id>> {
    let list = value
        .and_then(Value::as_array)
        .filter(|list| list.len() <= max)
        .ok_or_else(|| NetError::format(format!("{what}: 0..={max} ids")))?;
    let mut seen = BTreeSet::new();
    let mut ids = Vec::with_capacity(list.len());
    for item in list {
        let id = Id::parse(item.as_str().ok_or_else(|| NetError::format(format!("{what}: not a string")))?)?;
        if !seen.insert(id.clone()) {
            return Err(NetError::format(format!("{what}: duplicate")));
        }
        ids.push(id);
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------------------------------------------
// The `name` statement

/// A name (docs/08 §3): the body of a `name` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct Name {
    /// The name (syntax: [`check_name`]).
    pub name: String,
    /// What it points to.
    pub kind: NameKind,
    /// The target: app ID, or the owner itself for nodes and members.
    pub target: Id,
    /// The owner (member or node).
    pub owner: Id,
    /// The owner's key card (role `node` for node names, `client` for member names, `client` or `node` for apps).
    pub owner_card: KeyCard,
    /// App names: the app key's card (role `app`, ID = target). Others: none.
    pub card: Option<KeyCard>,
    /// Description (0-200 characters).
    pub description: String,
    /// Tags (0-8, distinct, 2-24 characters of `[a-z0-9-]`).
    pub tags: Vec<String>,
    /// Self-declared category.
    pub category: Category,
    /// App names: hints where the app is hosted (0-8 node IDs; never trusted, only a shortcut).
    pub hosts: Vec<Id>,
}

const NAME_FIELDS: [&str; 8] = ["name", "kind", "target", "owner", "owner_card", "description", "tags", "category"];

impl Name {
    /// The signers this name needs, ascending (app names: app key and owner; others: the owner).
    #[must_use]
    pub fn signers(&self) -> Vec<Id> {
        let mut signers = vec![self.owner.clone()];
        if self.kind == NameKind::App {
            signers.push(self.target.clone());
        }
        signers.sort();
        signers
    }

    /// The cards that verify its signatures (from the body).
    #[must_use]
    pub fn cards(&self) -> Vec<&KeyCard> {
        let mut cards = vec![&self.owner_card];
        cards.extend(self.card.as_ref());
        cards
    }

    /// Signs the name: by the owner alone, or - for app names - by the app key and the owner. Checks that the keys
    /// fit the body.
    pub fn sign_name(
        &self,
        net: &Id,
        iat: i64,
        exp: i64,
        owner: &Identity,
        app: Option<&Identity>,
    ) -> NetResult<Statement> {
        if owner.id() != &self.owner {
            return Err(NetError::format("name: sign with the owner's key"));
        }
        match (self.kind, app) {
            (NameKind::App, Some(app)) if app.id() == &self.target => self.sign_multi(net, iat, exp, &[app, owner]),
            (NameKind::App, _) => Err(NetError::format("name: an app name is signed by the app key too")),
            (_, None) => self.sign(net, iat, exp, owner),
            (_, Some(_)) => Err(NetError::format("name: only app names have a second signer")),
        }
    }
}

impl Body for Name {
    const KIND: Kind = Kind::Name;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "name")?;
        fields(object, &NAME_FIELDS, &["card", "hosts"], "name")?;
        let name = text(object, "name")?;
        check_name(name)?;
        let kind =
            NameKind::parse(text(object, "kind")?).ok_or_else(|| NetError::format("kind: app, node or member"))?;
        let target = id(object, "target")?;
        let owner = id(object, "owner")?;
        let owner_card = card(object.get("owner_card"), "owner_card")?;
        if owner_card.id() != &owner {
            return Err(NetError::format("owner_card: must be the owner's own card"));
        }
        let card = match object.get("card") {
            None => None,
            Some(value) => Some(card(Some(value), "card")?),
        };
        let description = text(object, "description")?;
        check_text(description, 0, MAX_NAME_DESCRIPTION_CHARS, false, "description")?;
        let list = object
            .get("tags")
            .and_then(Value::as_array)
            .filter(|list| list.len() <= MAX_TAGS)
            .ok_or_else(|| NetError::format("tags: 0..=8 tags"))?;
        let mut tags: Vec<String> = Vec::with_capacity(list.len());
        for item in list {
            let tag = item.as_str().ok_or_else(|| NetError::format("tags: strings"))?;
            check_word(tag, MIN_NAME_CHARS, MAX_TAG_CHARS, "tag")?;
            if tags.iter().any(|known| known == tag) {
                return Err(NetError::format("tags: duplicate"));
            }
            tags.push(tag.to_owned());
        }
        let category = Category::from_field(object)?;
        let hosts = match object.get("hosts") {
            None => Vec::new(),
            Some(value) => {
                let hosts = id_set(Some(value), MAX_NAME_HOSTS, "hosts")?;
                if hosts.is_empty() {
                    return Err(NetError::format("hosts: leave the field out instead of an empty list"));
                }
                hosts
            }
        };
        match kind {
            NameKind::App => {
                if owner == target {
                    return Err(NetError::format("name: the app key can not own its own name"));
                }
                if !card.as_ref().is_some_and(|card| card.id() == &target && card.role() == Role::App) {
                    return Err(NetError::format("card: an app name carries the app key's card (role app)"));
                }
                if !matches!(owner_card.role(), Role::Client | Role::Node) {
                    return Err(NetError::format("owner_card: role client or node"));
                }
            }
            NameKind::Node | NameKind::Member => {
                if owner != target {
                    return Err(NetError::format("name: a node or member name points to its owner"));
                }
                if card.is_some() || !hosts.is_empty() {
                    return Err(NetError::format("name: card and hosts only for app names"));
                }
                let role = if kind == NameKind::Node { Role::Node } else { Role::Client };
                if owner_card.role() != role {
                    return Err(NetError::format(format!("owner_card: role {}", role.as_str())));
                }
            }
        }
        Ok(Self {
            name: name.to_owned(),
            kind,
            target,
            owner,
            owner_card,
            card,
            description: description.to_owned(),
            tags,
            category,
            hosts,
        })
    }

    fn to_body(&self) -> NetResult<Value> {
        let mut object = Map::new();
        object.insert("name".into(), json!(self.name));
        object.insert("kind".into(), json!(self.kind.as_str()));
        object.insert("target".into(), json!(self.target.as_str()));
        object.insert("owner".into(), json!(self.owner.as_str()));
        object.insert("owner_card".into(), self.owner_card.to_value());
        if let Some(card) = &self.card {
            object.insert("card".into(), card.to_value());
        }
        object.insert("description".into(), json!(self.description));
        object.insert("tags".into(), json!(self.tags));
        object.insert("category".into(), json!(self.category.as_str()));
        if !self.hosts.is_empty() {
            object.insert("hosts".into(), ids_value(&self.hosts));
        }
        checked::<Self>(Value::Object(object))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The `label` statement

/// What a label (or a report) is about: a name or an ID - unambiguous, because names can not be IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelTarget {
    /// A name.
    Name(String),
    /// An app, node or member ID.
    Id(Id),
}

impl LabelTarget {
    /// Parses a name or an ID.
    pub fn parse(text: &str) -> NetResult<Self> {
        if let Ok(id) = Id::parse(text) {
            return Ok(Self::Id(id));
        }
        check_name(text)?;
        Ok(Self::Name(text.to_owned()))
    }

    /// The text form.
    #[must_use]
    pub fn as_text(&self) -> &str {
        match self {
            Self::Name(name) => name,
            Self::Id(id) => id.as_str(),
        }
    }
}

/// A label (docs/08 §5): an admin's statement about the category of a name or target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// The labeled name or ID.
    pub target: LabelTarget,
    /// The category.
    pub category: Category,
    /// Reason (0-200 characters).
    pub reason: String,
}

impl Body for Label {
    const KIND: Kind = Kind::Label;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "label")?;
        fields(object, &["target", "category", "reason"], &[], "label")?;
        let target = LabelTarget::parse(text(object, "target")?)?;
        let reason = text(object, "reason")?;
        check_text(reason, 0, MAX_REASON_CHARS, false, "reason")?;
        Ok(Self { target, category: Category::from_field(object)?, reason: reason.to_owned() })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(json!({
            "target": self.target.as_text(),
            "category": self.category.as_str(),
            "reason": self.reason,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_794_200_000_000;

    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32], &[seed.wrapping_add(7); 32])
    }

    #[test]
    fn name_syntax() {
        for good in ["shop", "a1", "mein-laden", "x".repeat(40).as_str(), "123"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in ["", "a", "-shop", "shop-", "sh--op", "Shop", "shöp", "sh op", "sh.op", "x".repeat(41).as_str()] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        // An ID is never a name.
        let id = identity(1).id().to_string();
        assert!(check_word(&id, 2, 40, "x").is_ok() && check_name(&id).is_err());
        assert!(check_short("meinnetz").is_ok() && check_short(&"x".repeat(25)).is_err());
    }

    #[test]
    fn folding_ignores_case_umlauts_and_accents() {
        assert_eq!(fold("Läden Café ÉCOLE Straße Ærø Œuvre"), "laden cafe ecole strasse aero oeuvre");
        assert_eq!(search_words("Größter Laden – für Müller!"), " grosster laden fur muller");
        assert_eq!(fold("日本 abc"), "日本 abc", "other scripts stay");
    }

    #[test]
    fn skeletons_catch_look_alikes() {
        let same = |a: &str, b: &str| assert_eq!(skeleton(a), skeleton(b), "{a} ~ {b}");
        same("shop", "sh0p");
        same("shop", "s-hop");
        same("paypal", "paypa1");
        same("paypal", "paypai");
        same("modem", "rnodern");
        same("wallet", "vvallet");
        same("bank", "8ank");
        same("cloud", "doud");
        same("best", "be5t");
        same("Shop", "shop");
        assert_ne!(skeleton("shop"), skeleton("shops"));
        assert_ne!(skeleton("abc"), skeleton("abd"));
        assert!(skeleton(&"m".repeat(40)).len() <= 80, "bounded");
    }

    #[test]
    fn reserved_words_as_part_of_the_skeleton() {
        assert!(is_reserved(&skeleton("paypal-login"), &[]));
        assert!(is_reserved(&skeleton("paypa1"), &[]));
        assert!(is_reserved(&skeleton("my-8ank"), &[]));
        assert!(is_reserved(&skeleton("badminton"), &[]), "strict on purpose");
        assert!(!is_reserved(&skeleton("shop"), &[]));
        assert!(is_reserved(&skeleton("sparkasse-x"), &["sparkasse".into()]));
        // Review 9: tags count like the name; descriptions are looked at word by word.
        let reserved = reserved_skeletons(&["sparkasse".into()]);
        assert!(name_is_reserved(&skeleton("shop"), &["paypa1".into()], &reserved), "a reserved tag");
        assert!(name_is_reserved(&skeleton("shop"), &["sparkasse".into()], &reserved), "a tag of the manifest");
        assert!(!name_is_reserved(&skeleton("shop"), &["laden".into()], &reserved));
        assert!(description_is_reserved("Ihr PayPal-Konto", &reserved));
        assert!(description_is_reserved("Die 8ank am Markt", &reserved));
        assert!(!description_is_reserved("Ein kleiner Laden", &reserved));
        assert_eq!(search_words("Der Shop, an der Ecke!"), " der shop an der ecke");
        assert_eq!(search_words(""), "");
        assert_eq!(split_address("shop.meinnetz"), ("shop", Some("meinnetz")));
        assert_eq!(split_address("shop"), ("shop", None));
    }

    #[test]
    fn name_bodies_are_strict() -> NetResult<()> {
        let (owner, app) = (identity(2), identity(3));
        let owner_card = owner.key_card(Role::Client, None, T0)?;
        let name = Name {
            name: "shop".into(),
            kind: NameKind::App,
            target: app.id().clone(),
            owner: owner.id().clone(),
            owner_card: owner_card.clone(),
            card: Some(app.key_card(Role::App, None, T0)?),
            description: "Mein Laden".into(),
            tags: vec!["laden".into()],
            category: Category::General,
            hosts: vec![identity(4).id().clone()],
        };
        let body = name.to_body()?;
        assert_eq!(Name::from_body(&body)?, name);
        let refuse = |path: &str, value: Value| {
            let mut bad = body.clone();
            if value.is_null() {
                bad.as_object_mut().map(|object| object.remove(path));
            } else {
                bad[path] = value;
            }
            assert!(Name::from_body(&bad).is_err(), "{path}");
        };
        refuse("extra", json!(1));
        refuse("name", json!("Shop"));
        refuse("kind", json!("site"));
        refuse("card", Value::Null);
        refuse("card", owner_card.to_value());
        refuse("owner_card", app.key_card(Role::Client, None, T0)?.to_value());
        refuse("owner", json!(app.id().as_str()));
        refuse("description", json!("x".repeat(201)));
        refuse("tags", json!(["a"]));
        refuse("tags", json!(["laden", "laden"]));
        refuse("tags", json!(["a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1", "i1"]));
        refuse("category", json!("18+"));
        refuse("hosts", json!([]));
        refuse("hosts", json!(["x"]));
        // Signing: app names need both keys, in the right roles.
        assert!(name.sign_name(&identity(9).id().clone(), T0, T0 + 1, &owner, None).is_err());
        assert!(name.sign_name(&identity(9).id().clone(), T0, T0 + 1, &app, Some(&owner)).is_err());
        let signed = name.sign_name(&identity(9).id().clone(), T0, T0 + 1, &owner, Some(&app))?;
        assert_eq!(signed.claimed_signers().len(), 2);
        // Node names point to their owner, no app card, role node.
        let node = identity(5);
        let node_name = Name {
            kind: NameKind::Node,
            target: node.id().clone(),
            owner: node.id().clone(),
            owner_card: node.key_card(Role::Node, None, T0)?,
            card: None,
            hosts: Vec::new(),
            ..name.clone()
        };
        assert_eq!(Name::from_body(&node_name.to_body()?)?, node_name);
        let mut bad = node_name.clone();
        bad.target = app.id().clone();
        assert!(bad.to_body().is_err());
        let mut bad = node_name;
        bad.owner_card = node.key_card(Role::Client, None, T0)?;
        assert!(bad.to_body().is_err(), "a node name needs a node card");
        Ok(())
    }

    #[test]
    fn labels_and_rules() -> NetResult<()> {
        let label = Label { target: LabelTarget::parse("shop")?, category: Category::Adult, reason: "18+".into() };
        assert_eq!(Label::from_body(&label.to_body()?)?, label);
        let id = identity(6).id().clone();
        assert_eq!(LabelTarget::parse(id.as_str())?, LabelTarget::Id(id));
        assert!(LabelTarget::parse("Not A Name").is_err());
        assert!(Label::from_body(&json!({"target": "shop", "category": "adult"})).is_err());
        let rules = NameRules::default();
        assert_eq!((rules.quota_for(0), rules.quota_for(1), rules.quota_for(9)), (0, 3, 100));
        assert_eq!(NameRules::parse(&rules.to_value())?, rules);
        assert!(NameRules::parse(&json!({"min_level": 4, "quota": [0, 0, 0, 0], "reserved": []})).is_err());
        assert!(NameRules::parse(&json!({"min_level": 1, "quota": [0, 0, 0], "reserved": []})).is_err());
        assert!(NameRules::parse(&json!({"min_level": 1, "quota": [0, 0, 0, 1001], "reserved": []})).is_err());
        assert!(NameRules::parse(&json!({"min_level": 1, "quota": [0, 0, 0, 1], "reserved": ["Bad"]})).is_err());
        assert!(NameRules::parse(&json!({"min_level": 1, "quota": [0, 0, 0, 1], "reserved": ["a", "a"]})).is_err());
        assert!(NameRules::parse(&json!({"min_level": 1, "quota": [0, 0, 0, 1]})).is_err());
        Ok(())
    }
}
