//! Agent cards (docs/10 §3, ADR 0022): a member (the owner) gives a program - e.g. an AI - its **own** key with few
//! rights, one home node, a short lifetime. The statement `agent` is not a log entry; it is the agent's home entry
//! and travels with its envelopes so other gateways and recipients can check it themselves.
//!
//! Checked here: form (exact fields, cards, scopes, bounds), single signer = the owner, lifetime at most 30 days, time,
//! signature with the owner's card from the body. Whether the owner is a member (and not banned) and whether the agent
//! was revoked are the caller's checks (state, node).

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::keys::{Identity, KeyCard, Role};
use crate::statement::{Draft, Statement};

/// Statement kind (`t`) of agent cards.
pub const KIND: &str = "agent";

/// Longest lifetime of an agent statement: 30 days.
pub const AGENT_MAX_LIFETIME_MS: i64 = 30 * 24 * 3600 * 1000;
/// Most recipients in `to`.
pub const MAX_AGENT_TO: usize = 32;
/// Highest `rate` (sends per hour).
pub const MAX_AGENT_RATE: u64 = 3600;
/// `rate` when the statement has none.
pub const DEFAULT_AGENT_RATE: u64 = 60;
/// Longest `note` in characters.
pub const MAX_AGENT_NOTE_CHARS: usize = 64;

/// What an agent may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Fetch and acknowledge messages.
    Receive,
    /// Send messages.
    Send,
}

impl Scope {
    /// All scopes in wire order (alphabetical - a body lists them so).
    pub const ALL: [Scope; 2] = [Scope::Receive, Scope::Send];

    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }

    /// The scope for a wire name (unknown scopes make a statement invalid).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == text)
    }
}

/// The body of an `agent` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    /// The agent's ID (= `card.id`).
    pub agent: Id,
    /// The agent's key card (role `client`).
    pub card: KeyCard,
    /// The owner's key card (role `client` or `admin`; its ID is the statement's signer).
    pub owner: KeyCard,
    /// The only node the agent may log in at (its home).
    pub node: Id,
    /// What it may do (not empty, no duplicates).
    pub scopes: BTreeSet<Scope>,
    /// Whom it may write to (`None`: every member).
    pub to: Option<Vec<Id>>,
    /// Sends per hour.
    pub rate: u64,
    /// Name or purpose.
    pub note: Option<String>,
}

impl Agent {
    /// Whether the agent may `scope`.
    #[must_use]
    pub fn may(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Whether the agent may write to `recipient`.
    #[must_use]
    pub fn may_write_to(&self, recipient: &Id) -> bool {
        self.may(Scope::Send) && self.to.as_ref().is_none_or(|list| list.contains(recipient))
    }

    /// Checks an `agent` statement fully (see module docs) and returns its body.
    pub fn check(statement: &Statement, net: &Id, now_ms: i64) -> CoreResult<Self> {
        let agent = Self::from_statement(statement)?;
        if statement.net() != net {
            return Err(CoreError::format("agent: other network"));
        }
        if statement.claimed_signers() != [agent.owner.id()] {
            return Err(CoreError::BadSignature); // must be signed by the owner alone
        }
        let (iat, exp) = statement.times();
        if exp - iat > AGENT_MAX_LIFETIME_MS {
            return Err(CoreError::format("agent: lifetime over 30 days"));
        }
        statement.check_time(now_ms)?;
        statement.verify(&[&agent.owner], 1)?;
        Ok(agent)
    }

    /// Issues an agent statement as `owner` for `days` (1-30) from `now_ms`.
    pub fn issue(&self, net: &Id, owner: &Identity, now_ms: i64, days: u32) -> CoreResult<Statement> {
        if !(1..=30).contains(&days) {
            return Err(CoreError::format("agent: 1..=30 days"));
        }
        if owner.id() != self.owner.id() {
            return Err(CoreError::format("agent: the owner signs"));
        }
        let draft = Draft {
            kind: KIND,
            net,
            iat: now_ms,
            exp: now_ms + i64::from(days) * 24 * 3600 * 1000,
            body: self.to_body()?,
        };
        Statement::sign(&draft, owner)
    }
}

impl Agent {
    /// Parses the body of an `agent` statement after checking its kind. Does not verify the signature.
    pub fn from_statement(statement: &Statement) -> CoreResult<Self> {
        if statement.kind() != KIND {
            return Err(CoreError::format("expected an agent statement"));
        }
        Self::from_body(statement.body())
    }

    /// Strict parse of a body (exact fields, cards, scopes, bounds).
    pub fn from_body(body: &Value) -> CoreResult<Self> {
        let object = body.as_object().ok_or_else(|| CoreError::format("agent: not an object"))?;
        if let Some(unknown) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
            return Err(CoreError::format(format!("agent: unknown field {unknown:?}")));
        }
        let agent = Id::parse(text(object, "agent")?)?;
        let card = KeyCard::from_value(object.get("card").cloned().unwrap_or(Value::Null))?;
        let owner = KeyCard::from_value(object.get("owner").cloned().unwrap_or(Value::Null))?;
        if card.id() != &agent || card.role() != Role::Client {
            return Err(CoreError::format("agent: card must be the agent's client card"));
        }
        if !matches!(owner.role(), Role::Client | Role::Admin) {
            return Err(CoreError::format("agent: owner card must be a client or admin card"));
        }
        if owner.id() == &agent {
            return Err(CoreError::format("agent: the agent can not be its own owner"));
        }
        let node = Id::parse(text(object, "node")?)?;
        let scopes = scopes(object.get("scopes"))?;
        let to = match object.get("to") {
            None => None,
            Some(value) => Some(id_list(value)?),
        };
        let rate = match object.get("rate") {
            None => DEFAULT_AGENT_RATE,
            Some(value) => value
                .as_u64()
                .filter(|rate| (1..=MAX_AGENT_RATE).contains(rate))
                .ok_or_else(|| CoreError::format("agent rate: integer 1..=3600"))?,
        };
        let note = match object.get("note") {
            None => None,
            Some(_) => {
                let note = text(object, "note")?;
                let count = note.chars().count();
                if count == 0 || count > MAX_AGENT_NOTE_CHARS || note.chars().any(char::is_control) {
                    return Err(CoreError::format("agent note: 1..=64 characters, no control characters"));
                }
                Some(note.to_owned())
            }
        };
        Ok(Self { agent, card, owner, node, scopes, to, rate, note })
    }

    /// The JSON body (checked with [`Agent::from_body`]).
    pub fn to_body(&self) -> CoreResult<Value> {
        let mut body = Map::new();
        body.insert("agent".into(), json!(self.agent.as_str()));
        body.insert("card".into(), self.card.to_value());
        body.insert("owner".into(), self.owner.to_value());
        body.insert("node".into(), json!(self.node.as_str()));
        body.insert("scopes".into(), Value::Array(self.scopes.iter().map(|scope| json!(scope.as_str())).collect()));
        if let Some(to) = &self.to {
            body.insert("to".into(), Value::Array(to.iter().map(|id| json!(id.as_str())).collect()));
        }
        if self.rate != DEFAULT_AGENT_RATE {
            body.insert("rate".into(), json!(self.rate));
        }
        if let Some(note) = &self.note {
            body.insert("note".into(), json!(note));
        }
        let body = Value::Object(body);
        Self::from_body(&body)?; // a builder can never produce what others refuse
        Ok(body)
    }
}

/// The fields of a body (`agent`, `card`, `owner`, `node`, `scopes` required).
const FIELDS: [&str; 8] = ["agent", "card", "owner", "node", "scopes", "to", "rate", "note"];

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> CoreResult<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::format(format!("agent {name}: missing or not a string")))
}

/// `to`: 1..=32 distinct IDs.
fn id_list(value: &Value) -> CoreResult<Vec<Id>> {
    let list = value
        .as_array()
        .filter(|list| (1..=MAX_AGENT_TO).contains(&list.len()))
        .ok_or_else(|| CoreError::format("agent to: 1..=32 ids"))?;
    let mut ids: Vec<Id> = Vec::with_capacity(list.len());
    for item in list {
        let id = Id::parse(item.as_str().ok_or_else(|| CoreError::format("agent to: not a string"))?)?;
        if ids.contains(&id) {
            return Err(CoreError::format("agent to: duplicate"));
        }
        ids.push(id);
    }
    Ok(ids)
}

/// `scopes`: 1..=2 distinct known scopes.
fn scopes(value: Option<&Value>) -> CoreResult<BTreeSet<Scope>> {
    let list = value
        .and_then(Value::as_array)
        .filter(|list| (1..=Scope::ALL.len()).contains(&list.len()))
        .ok_or_else(|| CoreError::format("agent scopes: 1..=2 scopes"))?;
    let mut scopes = BTreeSet::new();
    for item in list {
        let scope = item
            .as_str()
            .and_then(Scope::parse)
            .ok_or_else(|| CoreError::format("agent scopes: only send and receive"))?;
        if !scopes.insert(scope) {
            return Err(CoreError::format("agent scopes: duplicate"));
        }
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_794_200_000_000;
    const DAY: i64 = 24 * 3600 * 1000;

    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32], &[seed.wrapping_add(100); 32])
    }

    fn net() -> Id {
        identity(1).id().clone()
    }

    fn agent_body(owner: &Identity, agent: &Identity) -> CoreResult<Agent> {
        Ok(Agent {
            agent: agent.id().clone(),
            card: agent.key_card(Role::Client, Some("KI"), T0)?,
            owner: owner.key_card(Role::Client, None, T0)?,
            node: identity(9).id().clone(),
            scopes: [Scope::Send, Scope::Receive].into_iter().collect(),
            to: Some(vec![identity(7).id().clone()]),
            rate: 10,
            note: Some("Rika KI".into()),
        })
    }

    #[test]
    fn issue_and_check() -> CoreResult<()> {
        let (owner, agent) = (identity(2), identity(3));
        let body = agent_body(&owner, &agent)?;
        let statement = body.issue(&net(), &owner, T0, 7)?;
        let checked = Agent::check(&statement, &net(), T0 + 1000)?;
        assert_eq!(checked, body);
        assert!(checked.may_write_to(identity(7).id()));
        assert!(!checked.may_write_to(identity(8).id()), "only the listed recipients");
        // Expired, other network, too long.
        assert!(Agent::check(&statement, &net(), T0 + 8 * DAY).is_err());
        assert!(Agent::check(&statement, identity(5).id(), T0).is_err());
        assert!(body.issue(&net(), &owner, T0, 31).is_err());
        let draft = Draft { kind: "agent", net: &net(), iat: T0, exp: T0 + 31 * DAY, body: body.to_body()? };
        assert!(Agent::check(&Statement::sign(&draft, &owner)?, &net(), T0).is_err(), "lifetime over 30 days");
        Ok(())
    }

    #[test]
    fn signer_must_be_the_owner_of_the_body() -> CoreResult<()> {
        let (owner, agent, thief) = (identity(2), identity(3), identity(4));
        let body = agent_body(&owner, &agent)?;
        // Signed by somebody else - refused although the body names the owner.
        let draft = Draft { kind: "agent", net: &net(), iat: T0, exp: T0 + DAY, body: body.to_body()? };
        assert!(Agent::check(&Statement::sign(&draft, &thief)?, &net(), T0).is_err());
        // The thief puts its own card as owner: valid statement - but of the thief, not of the owner.
        let mut stolen = body.clone();
        stolen.owner = thief.key_card(Role::Client, None, T0)?;
        let statement = stolen.issue(&net(), &thief, T0, 1)?;
        assert_eq!(Agent::check(&statement, &net(), T0)?.owner.id(), thief.id());
        // Tampered body (other scopes) breaks the signature.
        let statement = body.issue(&net(), &owner, T0, 1)?;
        let mut value = statement.to_value();
        value["body"]["rate"] = json!(3600);
        assert!(Agent::check(&Statement::from_value(value)?, &net(), T0).is_err());
        Ok(())
    }

    #[test]
    fn strict_form() -> CoreResult<()> {
        let (owner, agent) = (identity(2), identity(3));
        let good = agent_body(&owner, &agent)?.to_body()?;
        let bad = |change: &dyn Fn(&mut Value)| {
            let mut body = good.clone();
            change(&mut body);
            Agent::from_body(&body).is_err()
        };
        assert!(bad(&|b| b["scopes"] = json!(["send", "files"])), "unknown scope");
        assert!(bad(&|b| b["scopes"] = json!(["send", "send"])), "duplicate scope");
        assert!(bad(&|b| b["scopes"] = json!([])), "no scope");
        assert!(bad(&|b| b["rate"] = json!(0)));
        assert!(bad(&|b| b["rate"] = json!(3601)));
        assert!(bad(&|b| b["note"] = json!("a\nb")));
        assert!(bad(&|b| b["note"] = json!("x".repeat(65))));
        assert!(bad(&|b| b["extra"] = json!(1)), "unknown field");
        assert!(bad(&|b| b["agent"] = json!(identity(5).id().as_str())), "agent is not the card's ID");
        assert!(bad(&|b| b["to"] = json!([])));
        let owner_card = owner.key_card(Role::Client, None, T0)?;
        assert!(bad(&|b| b["card"] = owner_card.to_value()), "card of another identity");
        let node_card = agent.key_card(Role::Node, None, T0)?;
        assert!(bad(&|b| b["card"] = node_card.to_value()), "the agent is a client");
        // Agent = owner.
        let mut same = agent_body(&owner, &owner)?;
        same.agent = owner.id().clone();
        same.card = owner.key_card(Role::Client, None, T0)?;
        assert!(same.to_body().is_err());
        // No `to`, default rate: both omitted in the body and read back the same.
        let mut open = agent_body(&owner, &agent)?;
        open.to = None;
        open.rate = DEFAULT_AGENT_RATE;
        let body = open.to_body()?;
        assert!(body.get("to").is_none() && body.get("rate").is_none());
        assert_eq!(Agent::from_body(&body)?, open);
        assert!(open.may_write_to(identity(8).id()));
        let mut receive_only = open.clone();
        receive_only.scopes = [Scope::Receive].into_iter().collect();
        assert!(!receive_only.may_write_to(identity(8).id()));
        Ok(())
    }
}
