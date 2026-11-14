//! The built-in server building block `builtin:records` (docs/13 §4, ADR 0031): collections of entries on the app's
//! event log - for templates like a guest book, a poll or sign-ups, without server code of their own.
//!
//! - `api/add {"c","f"}` → `{"id","t"}`; `api/list {"c","limit"?,"before"?}` → `{"records","total"}` (newest first);
//!   `api/remove {"c","id"}` (own entries only); `api/me` → `{"user","name"}`; `api/count {"c","by"}` and
//!   `api/counts {"cs","by"}` → how many live entries have each value of a field (and the caller's own: `mine`);
//!   `list` with `"mine": true` → only the caller's own entries.
//! - Collections `pub-…` (anybody), `user-…` (logged in), `vote-…` (logged in, the newest entry per user counts).
//! - Fields: 1-16 keys `[a-z][a-z0-9_]{0,31}`, values text (≤ 1,000 characters, no control characters but line
//!   breaks), whole numbers or booleans; an event at most [`crate::appserver::MAX_EVENT_BYTES`].
//!
//! The logic is pure ([`handle`] over an [`EventLog`]); the node gives it the newest events and appends.

use std::collections::{BTreeMap, HashMap, HashSet};

use bridge_core::crypto::sha256_parts;
use bridge_core::json::parse_strict;
use serde_json::{Map, Value, json};

/// The name of the building block in an app manifest.
pub(crate) const RECORDS: &str = "builtin:records";
/// Most events a call looks at (the newest).
pub(crate) const MAX_SCANNED: usize = 5000;
/// Most entries per `list` answer.
const MAX_LIST: usize = 100;
/// Most fields of an entry.
const MAX_FIELDS: usize = 16;
/// Longest text value.
const MAX_TEXT_CHARS: usize = 1000;
/// Largest request body.
pub(crate) const MAX_BODY: usize = 8 * 1024;

/// One event as the building block sees it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Event {
    /// Time of the host that took it (ms).
    pub(crate) t: i64,
    /// Its data.
    pub(crate) data: Vec<u8>,
}

/// The app's event log: the newest events (newest first) and appending.
pub(crate) trait EventLog {
    fn newest(&self, limit: usize) -> Vec<Event>;
    fn count(&self) -> u64;
    fn append(&mut self, data: &[u8]) -> Result<(), String>;
}

/// Who calls (from a valid Bridge Login app token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Caller {
    pub(crate) user: String,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Public,
    User,
    Vote,
}

fn kind_of(collection: &str) -> Option<Kind> {
    let (kind, name) = collection.split_once('-')?;
    let name_ok = !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !name_ok {
        return None;
    }
    match kind {
        "pub" => Some(Kind::Public),
        "user" => Some(Kind::User),
        "vote" => Some(Kind::Vote),
        _ => None,
    }
}

fn key_ok(key: &str) -> bool {
    let mut bytes = key.bytes();
    key.len() <= 32
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn fields_ok(fields: &Map<String, Value>) -> Result<(), &'static str> {
    if fields.is_empty() || fields.len() > MAX_FIELDS {
        return Err("f: 1-16 fields");
    }
    for (key, value) in fields {
        if !key_ok(key) {
            return Err("f: keys a-z, 0-9, _ (up to 32)");
        }
        let ok = match value {
            Value::String(text) => {
                text.chars().count() <= MAX_TEXT_CHARS && !text.chars().any(|c| c.is_control() && c != '\n')
            }
            Value::Number(number) => number.is_i64(),
            Value::Bool(_) => true,
            _ => false,
        };
        if !ok {
            return Err("f: text (up to 1000 characters), whole numbers or true/false");
        }
    }
    Ok(())
}

fn answer(status: u16, value: Value) -> (u16, Value) {
    (status, value)
}

fn refused(status: u16, message: &str) -> (u16, Value) {
    answer(status, json!({"error": message}))
}

/// Handles `api/<path>` with the request `body` for `caller` at `now`.
pub(crate) fn handle(
    path: &str,
    body: &[u8],
    caller: Option<&Caller>,
    now: i64,
    log: &mut dyn EventLog,
) -> (u16, Value) {
    let request = if body.iter().all(u8::is_ascii_whitespace) {
        Map::new()
    } else {
        match parse_strict(body, MAX_BODY) {
            Ok(Value::Object(object)) => object,
            _ => return refused(400, "body: a JSON object (up to 8 KiB)"),
        }
    };
    if path == "me" {
        return answer(200, json!({"user": caller.map(|c| &c.user), "name": caller.map(|c| &c.name)}));
    }
    if path == "counts" {
        return counts(&request, caller, log);
    }
    let Some(collection) = request.get("c").and_then(Value::as_str) else {
        return refused(400, "c: the collection");
    };
    let Some(kind) = kind_of(collection) else {
        return refused(400, "c: pub-…, user-… or vote-… (a-z, 0-9, -)");
    };
    match path {
        "add" => add(&request, collection, kind, caller, now, log),
        "list" => list(&request, collection, kind, caller, log),
        "count" => count(&request, collection, kind, caller, log),
        "remove" => remove(&request, collection, caller, log),
        _ => refused(404, "unknown: add, list, count, counts, remove, me"),
    }
}

fn add(
    request: &Map<String, Value>,
    collection: &str,
    kind: Kind,
    caller: Option<&Caller>,
    now: i64,
    log: &mut dyn EventLog,
) -> (u16, Value) {
    if kind != Kind::Public && caller.is_none() {
        return refused(401, "log in first (Bridge Login)");
    }
    let Some(fields) = request.get("f").and_then(Value::as_object) else { return refused(400, "f: an object") };
    if let Err(message) = fields_ok(fields) {
        return refused(400, message);
    }
    let user = caller.map(|c| c.user.as_str());
    let digest = sha256_parts(&[
        b"bridge4/records/id\n",
        &now.to_be_bytes(),
        user.unwrap_or_default().as_bytes(),
        &log.count().to_be_bytes(),
        collection.as_bytes(),
        Value::Object(fields.clone()).to_string().as_bytes(),
    ]);
    let id: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    let event = json!({"k": "add", "c": collection, "id": id, "u": user, "n": caller.map(|c| &c.name), "f": fields});
    let bytes = event.to_string().into_bytes();
    if bytes.len() > crate::appserver::MAX_EVENT_BYTES {
        return refused(413, "entry too large (4 KiB)");
    }
    match log.append(&bytes) {
        Ok(()) => answer(200, json!({"id": id, "t": now})),
        Err(_) => refused(507, "no room for more entries"),
    }
}

fn remove(
    request: &Map<String, Value>,
    collection: &str,
    caller: Option<&Caller>,
    log: &mut dyn EventLog,
) -> (u16, Value) {
    let Some(caller) = caller else { return refused(401, "log in first (Bridge Login)") };
    let Some(id) = request.get("id").and_then(Value::as_str).filter(|id| id.len() == 12) else {
        return refused(400, "id: the entry");
    };
    let event = json!({"k": "del", "c": collection, "id": id, "u": caller.user});
    match log.append(event.to_string().as_bytes()) {
        Ok(()) => answer(200, json!({"ok": true})),
        Err(_) => refused(507, "no room for more entries"),
    }
}

/// A live entry: the event and its data.
type Entry = (Event, Map<String, Value>);

/// Most collections of one `counts` call.
const MAX_COUNTED: usize = 32;
/// Most distinct values counted per collection.
const MAX_VALUES: usize = 100;

/// The live entries of each wanted collection (`None`: of every collection), newest first, in one pass over the
/// newest events: removed entries (by their author or by moderation) and older votes of a user are out. A moderated
/// vote also hides the user's older votes in that collection (until they vote again).
fn live_in(wanted: Option<&[(&str, Kind)]>, log: &dyn EventLog) -> HashMap<String, Vec<Entry>> {
    let mut removed: HashSet<(String, String, String)> = HashSet::new();
    let mut moderated: HashSet<(String, String)> = HashSet::new();
    let mut voted: HashSet<(String, String)> = HashSet::new();
    let mut out: HashMap<String, Vec<Entry>> =
        wanted.unwrap_or_default().iter().map(|(collection, _)| ((*collection).to_owned(), Vec::new())).collect();
    for event in log.newest(MAX_SCANNED) {
        let Ok(Value::Object(data)) = serde_json::from_slice::<Value>(&event.data) else { continue };
        let Some(collection) = data.get("c").and_then(Value::as_str) else { continue };
        let kind = match wanted {
            Some(wanted) => wanted.iter().find(|(wanted, _)| *wanted == collection).map(|(_, kind)| *kind),
            None => kind_of(collection),
        };
        let Some(kind) = kind else { continue };
        let collection = collection.to_owned();
        let id = data.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
        let user = data.get("u").and_then(Value::as_str).map(str::to_owned);
        match data.get("k").and_then(Value::as_str) {
            Some("del") => {
                if let Some(user) = user {
                    removed.insert((collection, id, user));
                }
            }
            Some("mod") => {
                moderated.insert((collection, id));
            }
            Some("add") => {
                if moderated.contains(&(collection.clone(), id.clone())) {
                    if let (Kind::Vote, Some(user)) = (kind, user) {
                        voted.insert((collection, user));
                    }
                    continue;
                }
                if let Some(user) = &user
                    && removed.contains(&(collection.clone(), id, user.clone()))
                {
                    continue;
                }
                if kind == Kind::Vote && !user.is_some_and(|user| voted.insert((collection.clone(), user))) {
                    continue; // anonymous, or an older vote of this user
                }
                out.entry(collection).or_default().push((event, data));
            }
            _ => {}
        }
    }
    out
}

fn live(collection: &str, kind: Kind, log: &dyn EventLog) -> Vec<Entry> {
    live_in(Some(&[(collection, kind)]), log).remove(collection).unwrap_or_default()
}

/// The newest live entries of every collection for moderation (docs/13 §6): `{"entries": [{"c","id","t","u","n","f"}],
/// "total", "next"}` - at most `limit` (≤ 100) older than `before`.
pub(crate) fn entries(log: &dyn EventLog, before: Option<i64>, limit: usize) -> Value {
    let mut all: Vec<(String, Entry)> = live_in(None, log)
        .into_iter()
        .flat_map(|(collection, entries)| entries.into_iter().map(move |entry| (collection.clone(), entry)))
        .collect();
    all.sort_by_key(|(_, (event, _))| std::cmp::Reverse(event.t));
    let total = all.len();
    let limit = limit.clamp(1, MAX_LIST);
    let shown: Vec<Value> = all
        .iter()
        .filter(|(_, (event, _))| before.is_none_or(|before| event.t < before))
        .take(limit)
        .map(|(collection, (event, data))| {
            json!({
                "c": collection, "id": data.get("id").cloned().unwrap_or(Value::Null), "t": event.t,
                "u": data.get("u").cloned().unwrap_or(Value::Null), "n": data.get("n").cloned().unwrap_or(Value::Null),
                "f": data.get("f").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let next = if shown.len() == limit { shown.last().and_then(|entry| entry.get("t").cloned()) } else { None };
    json!({"entries": shown, "total": total, "next": next})
}

/// Removes an entry of anybody (moderation, docs/13 §6): appends `{"k":"mod","c","id"}`. Only the node's admin path
/// calls this - the app's `api/` never writes `mod`.
pub(crate) fn moderate(log: &mut dyn EventLog, collection: &str, id: &str) -> Result<(), String> {
    if kind_of(collection).is_none() {
        return Err("c: pub-…, user-… or vote-…".into());
    }
    if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("id: an entry (12 hex characters)".into());
    }
    let event = json!({"k": "mod", "c": collection, "id": id});
    log.append(event.to_string().as_bytes())
}

/// How many `entries` have each value of the field `by`; `mine`: the value of the caller's newest entry.
fn tally(entries: &[Entry], by: &str, caller: Option<&Caller>) -> Value {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut mine = Value::Null;
    for (_, data) in entries {
        if mine.is_null()
            && let Some(caller) = caller
            && data.get("u").and_then(Value::as_str) == Some(caller.user.as_str())
        {
            mine = data.get("f").and_then(|fields| fields.get(by)).cloned().unwrap_or(Value::Null);
        }
        let value = match data.get("f").and_then(|fields| fields.get(by)) {
            Some(Value::String(text)) => text.chars().take(80).collect(),
            Some(other @ (Value::Number(_) | Value::Bool(_))) => other.to_string(),
            _ => continue,
        };
        if counts.len() < MAX_VALUES || counts.contains_key(&value) {
            *counts.entry(value).or_insert(0) += 1;
        }
    }
    json!({"counts": counts, "total": entries.len(), "mine": mine})
}

fn by_field(request: &Map<String, Value>) -> Option<&str> {
    request.get("by").and_then(Value::as_str).filter(|by| key_ok(by))
}

/// `api/count {"c","by"}`: how many live entries have each value of the field `by` (polls: one count per answer) and
/// the caller's own value (`mine`).
fn count(
    request: &Map<String, Value>,
    collection: &str,
    kind: Kind,
    caller: Option<&Caller>,
    log: &dyn EventLog,
) -> (u16, Value) {
    let Some(by) = by_field(request) else { return refused(400, "by: a field") };
    answer(200, tally(&live(collection, kind, log), by, caller))
}

/// `api/counts {"cs": [...], "by"}`: [`count`] for up to 32 collections at once (dates with "Ich komme").
fn counts(request: &Map<String, Value>, caller: Option<&Caller>, log: &dyn EventLog) -> (u16, Value) {
    let Some(by) = by_field(request) else { return refused(400, "by: a field") };
    let Some(names) =
        request.get("cs").and_then(Value::as_array).filter(|cs| !cs.is_empty() && cs.len() <= MAX_COUNTED)
    else {
        return refused(400, "cs: 1-32 collections");
    };
    let mut wanted: Vec<(&str, Kind)> = Vec::new();
    for name in names {
        let Some((name, kind)) = name.as_str().and_then(|name| kind_of(name).map(|kind| (name, kind))) else {
            return refused(400, "cs: pub-…, user-… or vote-… (a-z, 0-9, -)");
        };
        if !wanted.iter().any(|(seen, _)| *seen == name) {
            wanted.push((name, kind));
        }
    }
    let live = live_in(Some(&wanted), log);
    let out: Map<String, Value> =
        live.iter().map(|(collection, entries)| (collection.clone(), tally(entries, by, caller))).collect();
    answer(200, json!({"counts": out}))
}

/// `api/list {"c","limit"?,"before"?,"mine"?}`: newest first; `mine` only the caller's own entries (their vote).
fn list(
    request: &Map<String, Value>,
    collection: &str,
    kind: Kind,
    caller: Option<&Caller>,
    log: &dyn EventLog,
) -> (u16, Value) {
    let limit = request.get("limit").and_then(Value::as_u64).map_or(50, |n| usize::try_from(n).unwrap_or(MAX_LIST));
    let limit = limit.clamp(1, MAX_LIST);
    let before = request.get("before").and_then(Value::as_i64).unwrap_or(i64::MAX);
    let mine = match request.get("mine") {
        None | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => match caller {
            Some(caller) => Some(caller.user.as_str()),
            None => return refused(401, "log in first (Bridge Login)"),
        },
        Some(_) => return refused(400, "mine: true or false"),
    };
    let entries = live(collection, kind, log);
    let own = |data: &Map<String, Value>| mine.is_none_or(|user| data.get("u").and_then(Value::as_str) == Some(user));
    let records: Vec<Value> = entries
        .iter()
        .filter(|(event, data)| event.t < before && own(data))
        .take(limit)
        .map(|(event, data)| {
            json!({
                "id": data.get("id").cloned().unwrap_or(Value::Null), "t": event.t,
                "u": data.get("u").cloned().unwrap_or(Value::Null), "n": data.get("n").cloned().unwrap_or(Value::Null),
                "f": data.get("f").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let total = entries.len();
    answer(200, json!({"records": records, "total": total}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Memory {
        events: Vec<Event>,
        now: i64,
    }

    impl EventLog for Memory {
        fn newest(&self, limit: usize) -> Vec<Event> {
            self.events.iter().rev().take(limit).cloned().collect()
        }
        fn count(&self) -> u64 {
            self.events.len() as u64
        }
        fn append(&mut self, data: &[u8]) -> Result<(), String> {
            self.now += 1;
            self.events.push(Event { t: self.now, data: data.to_vec() });
            Ok(())
        }
    }

    fn caller(name: &str) -> Caller {
        Caller { user: format!("u{name}"), name: name.to_owned() }
    }

    fn call(log: &mut Memory, path: &str, body: Value, who: Option<&Caller>) -> (u16, Value) {
        let now = log.now + 1;
        handle(path, body.to_string().as_bytes(), who, now, log)
    }

    #[test]
    fn a_guest_book_and_its_attacks() {
        let mut log = Memory::default();
        let anna = caller("Anna");
        let (status, made) = call(&mut log, "add", json!({"c": "pub-buch", "f": {"text": "Hallo!"}}), None);
        assert_eq!(status, 200, "{made}");
        call(&mut log, "add", json!({"c": "pub-buch", "f": {"text": "Ich bin Anna", "sterne": 5}}), Some(&anna));
        let (_, listed) = call(&mut log, "list", json!({"c": "pub-buch"}), None);
        assert_eq!(listed["total"], 2);
        assert_eq!(listed["records"][0]["n"], "Anna", "newest first, with the name");
        assert_eq!(listed["records"][1]["u"], Value::Null, "anonymous");
        for (body, why) in [
            (json!({"c": "pub-buch", "f": {}}), "no fields"),
            (json!({"c": "pub-buch", "f": {"Text": "x"}}), "upper case key"),
            (json!({"c": "pub-buch", "f": {"text": {"nested": 1}}}), "nested"),
            (json!({"c": "pub-buch", "f": {"text": "x".repeat(1001)}}), "too long"),
            (json!({"c": "pub-buch", "f": {"text": "a\u{0}b"}}), "control"),
            (json!({"c": "pub-buch", "f": {"n": 1.5}}), "no whole number"),
            (json!({"c": "buch", "f": {"text": "x"}}), "no kind"),
            (json!({"c": "pub-Buch", "f": {"text": "x"}}), "upper case collection"),
            (json!({"c": "admin-x", "f": {"text": "x"}}), "unknown kind"),
            (json!({"f": {"text": "x"}}), "no collection"),
        ] {
            assert_eq!(call(&mut log, "add", body, Some(&anna)).0, 400, "{why}");
        }
        let many: Map<String, Value> = (0..17).map(|i| (format!("k{i}"), json!(1))).collect();
        assert_eq!(call(&mut log, "add", json!({"c": "pub-buch", "f": many}), None).0, 400, "17 fields");
        assert_eq!(handle("add", b"[1]", None, 9, &mut log).0, 400, "no object");
        assert_eq!(call(&mut log, "nix", json!({"c": "pub-buch"}), None).0, 404);
        assert_eq!(log.events.len(), 2, "nothing refused went in");
    }

    #[test]
    fn only_own_entries_go_and_logins_are_needed() {
        let mut log = Memory::default();
        let (anna, ben) = (caller("Anna"), caller("Ben"));
        assert_eq!(call(&mut log, "add", json!({"c": "user-liste", "f": {"x": 1}}), None).0, 401);
        let (_, made) = call(&mut log, "add", json!({"c": "user-liste", "f": {"x": 1}}), Some(&anna));
        let id = made["id"].as_str().unwrap_or_default().to_owned();
        assert_eq!(id.len(), 12);
        assert_eq!(call(&mut log, "remove", json!({"c": "user-liste", "id": id}), None).0, 401);
        call(&mut log, "remove", json!({"c": "user-liste", "id": id}), Some(&ben));
        assert_eq!(call(&mut log, "list", json!({"c": "user-liste"}), None).1["total"], 1, "Ben can not remove it");
        call(&mut log, "remove", json!({"c": "user-liste", "id": id}), Some(&anna));
        assert_eq!(call(&mut log, "list", json!({"c": "user-liste"}), None).1["total"], 0, "Anna can");
        assert_eq!(call(&mut log, "me", json!({}), Some(&anna)).1, json!({"user": "uAnna", "name": "Anna"}));
        assert_eq!(call(&mut log, "me", json!({}), None).1["user"], Value::Null);
    }

    #[test]
    fn the_newest_vote_counts() {
        let mut log = Memory::default();
        let (anna, ben) = (caller("Anna"), caller("Ben"));
        assert_eq!(call(&mut log, "add", json!({"c": "vote-frage", "f": {"a": 1}}), None).0, 401);
        call(&mut log, "add", json!({"c": "vote-frage", "f": {"a": 1}}), Some(&anna));
        call(&mut log, "add", json!({"c": "vote-frage", "f": {"a": 2}}), Some(&ben));
        call(&mut log, "add", json!({"c": "vote-frage", "f": {"a": 3}}), Some(&anna));
        let (_, listed) = call(&mut log, "list", json!({"c": "vote-frage"}), None);
        assert_eq!(listed["total"], 2);
        let answers: Vec<i64> =
            listed["records"].as_array().into_iter().flatten().filter_map(|r| r["f"]["a"].as_i64()).collect();
        assert_eq!(answers, [3, 2], "Anna's newer vote replaced her first");
        let (_, counted) = call(&mut log, "count", json!({"c": "vote-frage", "by": "a"}), None);
        assert_eq!(counted, json!({"counts": {"2": 1, "3": 1}, "total": 2, "mine": null}));
        let (_, counted) = call(&mut log, "count", json!({"c": "vote-frage", "by": "a"}), Some(&anna));
        assert_eq!(counted["mine"], 3, "the newest vote of Anna");
        assert_eq!(call(&mut log, "count", json!({"c": "vote-frage", "by": "A!"}), None).0, 400);
        let (_, both) =
            call(&mut log, "counts", json!({"cs": ["vote-frage", "vote-leer", "vote-frage"], "by": "a"}), None);
        assert_eq!(
            both,
            json!({"counts": {"vote-frage": {"counts": {"2": 1, "3": 1}, "total": 2, "mine": null},
                              "vote-leer": {"counts": {}, "total": 0, "mine": null}}})
        );
        let (_, mine) = call(&mut log, "list", json!({"c": "vote-frage", "mine": true}), Some(&anna));
        assert_eq!(
            (mine["records"].as_array().map(Vec::len), mine["records"][0]["f"]["a"].clone()),
            (Some(1), json!(3))
        );
        assert_eq!(call(&mut log, "list", json!({"c": "vote-frage", "mine": true}), None).0, 401);
        assert_eq!(call(&mut log, "list", json!({"c": "vote-frage", "mine": 1}), Some(&anna)).0, 400);
        let many: Vec<String> = (0..33).map(|i| format!("vote-t{i}")).collect();
        for bad in [
            json!({"cs": many, "by": "a"}),
            json!({"cs": [], "by": "a"}),
            json!({"cs": ["x"], "by": "a"}),
            json!({"cs": ["vote-frage"]}),
            json!({"cs": "vote-frage", "by": "a"}),
        ] {
            assert_eq!(call(&mut log, "counts", bad.clone(), None).0, 400, "{bad}");
        }
        // Other collections are separate; paging by time.
        call(&mut log, "add", json!({"c": "vote-andere", "f": {"a": 1}}), Some(&anna));
        assert_eq!(call(&mut log, "list", json!({"c": "vote-frage"}), None).1["total"], 2);
        let (_, page) = call(&mut log, "list", json!({"c": "vote-frage", "limit": 1}), None);
        let first_t = page["records"][0]["t"].as_i64().unwrap_or(0);
        let (_, next) = call(&mut log, "list", json!({"c": "vote-frage", "limit": 1, "before": first_t}), None);
        assert_eq!(next["records"][0]["f"]["a"], 2);
    }

    /// Moderation (docs/13 §6): the host's admin path removes anybody's entry; the app's own API cannot.
    #[test]
    fn moderation_removes_any_entry() -> Result<(), String> {
        let mut log = Memory::default();
        let (anna, ben) = (caller("Anna"), caller("Ben"));
        let (_, spam) = call(&mut log, "add", json!({"c": "pub-buch", "f": {"text": "Spam!"}}), None);
        call(&mut log, "add", json!({"c": "pub-buch", "f": {"text": "Hallo"}}), Some(&anna));
        call(&mut log, "add", json!({"c": "vote-frage", "f": {"a": 1}}), Some(&ben));
        let (_, vote) = call(&mut log, "add", json!({"c": "vote-frage", "f": {"a": 2}}), Some(&ben));
        let listed = entries(&log, None, 100);
        assert_eq!(listed["total"], 3, "Ben's older vote does not count: {listed}");
        assert_eq!(listed["entries"][0]["c"], "vote-frage", "newest first, every collection");
        let id = |answer: &Value| answer["id"].as_str().unwrap_or_default().to_owned();
        moderate(&mut log, "pub-buch", &id(&spam))?;
        moderate(&mut log, "vote-frage", &id(&vote))?;
        let (_, book) = call(&mut log, "list", json!({"c": "pub-buch"}), None);
        assert_eq!((book["total"].clone(), book["records"][0]["f"]["text"].clone()), (json!(1), json!("Hallo")));
        let (_, counted) = call(&mut log, "count", json!({"c": "vote-frage", "by": "a"}), None);
        assert_eq!(counted["total"], 0, "a moderated vote does not bring back the older one");
        call(&mut log, "add", json!({"c": "vote-frage", "f": {"a": 3}}), Some(&ben));
        assert_eq!(call(&mut log, "count", json!({"c": "vote-frage", "by": "a"}), None).1["total"], 1, "voting again");
        assert_eq!(entries(&log, None, 100)["total"], 2);
        // Paging.
        let first = entries(&log, None, 1);
        assert!(first["next"].is_i64());
        let rest = entries(&log, first["next"].as_i64(), 100);
        assert_eq!(rest["entries"].as_array().map(Vec::len), Some(1));
        // Attacks: bad collections and ids are refused; the app's API knows no `mod`.
        for (collection, bad) in [("buch", "000000000000"), ("pub-buch", "xyz"), ("pub-buch", "ABCDEF123456")] {
            assert!(moderate(&mut log, collection, bad).is_err(), "{collection} {bad}");
        }
        assert_eq!(call(&mut log, "mod", json!({"c": "pub-buch", "id": id(&spam)}), Some(&anna)).0, 404);
        let (_, made) = call(&mut log, "add", json!({"c": "pub-buch", "f": {"k": "mod", "id": "x"}}), None);
        assert_eq!(made["id"].as_str().map(str::len), Some(12), "a field named k is just a field");
        assert_eq!(call(&mut log, "list", json!({"c": "pub-buch"}), None).1["total"], 2);
        Ok(())
    }
}
