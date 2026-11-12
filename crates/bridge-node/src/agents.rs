//! Agent cards at a node (docs/10 §3, ADR 0022). An agent logs in only at its home node with an `agent` statement of
//! its owner; its session may only send (scope `send`, recipients in `to`, `rate` per hour) and fetch/acknowledge
//! (scope `receive`) - everything else is refused (default deny). Every use checks again: statement valid, owner still
//! a member and not banned, agent not revoked. The statement is the agent's home entry (exchanged like `home`), so
//! envelopes find it; relays of its envelopes carry it so the receiving gateway checks it too.

use std::collections::{HashMap, VecDeque};

use bridge_core::{Agent, Scope};
use bridge_core::{Id, KeyCard, SignedRequest, Statement};
use bridge_store::HomeRow;
use serde_json::{Value, json};

use crate::{Node, NodeError, NodeResult, lock};

/// Most agents with a session at one node at once.
pub(crate) const MAX_AGENTS: usize = 10_000;
/// Most agents of one owner at one node at once (their home entries share the table with the members').
pub(crate) const MAX_AGENTS_PER_OWNER: usize = 16;
/// A revocation is kept this long (the longest lifetime of an agent statement, plus the clock skew).
const REVOCATION_KEPT_MS: i64 = bridge_core::agent::AGENT_MAX_LIFETIME_MS + bridge_core::CLOCK_SKEW_MS;
const HOUR_MS: i64 = 3600 * 1000;

/// What a session is used for (agents: only these, members: everything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// `/v4/send`.
    Send,
    /// `/v4/poll`, `/v4/ack`.
    Receive,
    /// `/v4/card`.
    Card,
    /// Anything else.
    Other,
}

/// An agent logged in here (RAM, like sessions).
pub(crate) struct AgentGrant {
    pub(crate) agent: Agent,
    iat: i64,
    exp: i64,
    /// Times of the sends of the last hour (at most `rate`).
    sent: VecDeque<i64>,
}

/// The agents of a node.
#[derive(Default)]
pub(crate) struct Agents {
    grants: HashMap<Id, AgentGrant>,
}

impl Node {
    /// Login of an agent (after the login request's signature was verified with `card`): checks the statement and the
    /// owner, then stores the home entry and the grant.
    pub(crate) async fn agent_login(&self, card: &KeyCard, statement: &Value, now: i64) -> NodeResult<()> {
        let (me, net) = (self.inner.identity.id().clone(), self.inner.net.clone());
        let statement = Statement::from_value(statement.clone())?;
        let agent = Agent::check(&statement, &net, now)?;
        if &agent.agent != card.id() || agent.card.to_value() != card.to_value() {
            return Err(NodeError::forbidden("agent: the statement is for another key"));
        }
        if agent.node != me {
            return Err(NodeError::forbidden("agent: log in at the home node named in the statement"));
        }
        let max_homes = self.with_core(|core| -> NodeResult<u64> {
            if !core.is_gateway(&me, now) {
                return Err(NodeError::forbidden("this node is not a gateway of the network (yet)"));
            }
            core.state.check_login(agent.owner.id(), now)?;
            Ok(core.state.manifest().limits.members)
        })??;
        let (iat, exp) = statement.times();
        self.agent_not_revoked(&agent, iat, now).await?;
        {
            let agents = lock(&self.inner.agents);
            let of_owner = agents
                .grants
                .iter()
                .filter(|(id, grant)| *id != card.id() && grant.exp > now && grant.agent.owner.id() == agent.owner.id())
                .count();
            if of_owner >= MAX_AGENTS_PER_OWNER {
                return Err(NodeError {
                    retry_after: Some(3600),
                    ..NodeError::new(429, "QUOTA_EXCEEDED", "too many agents of this owner at this node")
                });
            }
        }
        let row = HomeRow {
            member: agent.agent.to_string(),
            node: me.to_string(),
            iat,
            exp,
            seq: 0,
            home: statement.canonical_bytes().to_vec(),
            card: card.to_bytes()?,
        };
        let key = net.to_string();
        if matches!(
            self.blocking(move |store| store.home_put(&key, &row, max_homes)).await?,
            bridge_store::HomeStored::Full
        ) {
            return Err(NodeError { retry_after: Some(3600), ..NodeError::quota() });
        }
        let mut agents = lock(&self.inner.agents);
        if !agents.grants.contains_key(card.id()) && agents.grants.len() >= MAX_AGENTS {
            agents.grants.retain(|_, grant| grant.exp > now);
            if agents.grants.len() >= MAX_AGENTS {
                return Err(NodeError {
                    retry_after: Some(60),
                    ..NodeError::new(429, "RATE_LIMITED", "too many agents")
                });
            }
        }
        // A newer statement replaces the grant; an older one never comes back over a newer.
        let keep_sent = match agents.grants.get(card.id()) {
            Some(old) if old.iat > iat => return Err(NodeError::forbidden("agent: a newer statement is in use")),
            Some(old) => old.sent.clone(),
            None => VecDeque::new(),
        };
        agents.grants.insert(card.id().clone(), AgentGrant { agent, iat, exp, sent: keep_sent });
        Ok(())
    }

    /// The session check of an agent: grant valid, owner still a member, this node still a gateway, `usage` allowed.
    pub(crate) fn agent_session_check(&self, id: &Id, usage: Use, now: i64) -> NodeResult<()> {
        let owner = {
            let mut agents = lock(&self.inner.agents);
            let Some(grant) = agents.grants.get(id) else { return Err(NodeError::no_session()) };
            if grant.exp <= now {
                agents.grants.remove(id);
                return Err(NodeError::new(401, "EXPIRED", "agent statement expired"));
            }
            let allowed = match usage {
                Use::Send => grant.agent.may(Scope::Send),
                Use::Receive => grant.agent.may(Scope::Receive),
                Use::Card => true,
                Use::Other => false,
            };
            if !allowed {
                return Err(NodeError::forbidden("agents may only do what their statement allows"));
            }
            grant.agent.owner.id().clone()
        };
        let me = self.inner.identity.id();
        self.with_core(|core| -> NodeResult<()> {
            if !core.is_gateway(me, now) {
                return Err(NodeError::forbidden("this node is no longer a gateway of the network"));
            }
            core.state.check_login(&owner, now)?;
            Ok(())
        })?
    }

    /// An agent's send: recipient allowed, within `rate` per hour, not across networks. Counts the send.
    pub(crate) fn agent_admit_send(&self, id: &Id, to: &Id, across_networks: bool, now: i64) -> NodeResult<()> {
        let mut agents = lock(&self.inner.agents);
        let grant = agents.grants.get_mut(id).ok_or_else(NodeError::no_session)?;
        if across_networks {
            return Err(NodeError::forbidden("agents do not write across networks"));
        }
        if !grant.agent.may_write_to(to) {
            return Err(NodeError::forbidden("the agent may not write to this recipient"));
        }
        while grant.sent.front().is_some_and(|time| *time <= now - HOUR_MS) {
            grant.sent.pop_front();
        }
        if grant.sent.len() as u64 >= grant.agent.rate {
            let wait = grant.sent.front().map_or(60, |first| (first + HOUR_MS - now) / 1000 + 1);
            return Err(NodeError {
                retry_after: u32::try_from(wait.max(1)).ok(),
                ..NodeError::new(429, "RATE_LIMITED", "agent rate per hour reached")
            });
        }
        grant.sent.push_back(now);
        Ok(())
    }

    /// Fails if statements of the agent's owner for it, issued at `iat`, were revoked here.
    async fn agent_not_revoked(&self, agent: &Agent, iat: i64, now: i64) -> NodeResult<()> {
        let (id, owner) = (agent.agent.to_string(), agent.owner.id().to_string());
        match self.blocking(move |store| store.agent_revoked_before(&id, &owner, now)).await? {
            Some(before) if iat <= before => Err(NodeError::forbidden("agent revoked")),
            _ => Ok(()),
        }
    }

    /// The valid agent statement behind the home entry of `id` (stored here or exchanged): checked, owner still a
    /// member and not banned; at its home node also not revoked. `None` for members and everything invalid.
    pub(crate) async fn agent_home(&self, id: &Id, now: i64) -> NodeResult<Option<(Agent, Statement)>> {
        let (net, member) = (self.inner.net.to_string(), id.to_string());
        let Some(row) = self.blocking(move |store| store.home_get(&net, &member, now)).await? else {
            return Ok(None);
        };
        let Ok(statement) = Statement::parse(&row.home) else { return Ok(None) };
        if statement.kind() != "agent" {
            return Ok(None);
        }
        let Ok(agent) = Agent::check(&statement, &self.inner.net, now) else { return Ok(None) };
        if &agent.agent != id || self.with_core(|core| core.state.check_login(agent.owner.id(), now).is_err())? {
            return Ok(None);
        }
        if &agent.node == self.inner.identity.id()
            && self.agent_not_revoked(&agent, statement.times().0, now).await.is_err()
        {
            return Ok(None);
        }
        Ok(Some((agent, statement)))
    }

    /// Checks the agent statement of a relayed envelope's sender (receiving gateway): for this sender and its card,
    /// owner a member and not banned, allowed to write to `to`. Keeps it as the agent's home entry (if newer), so the
    /// recipient's poll can show whom the agent acts for.
    pub(crate) async fn agent_relayed(&self, statement: &Value, sender: &KeyCard, to: &Id, now: i64) -> NodeResult<()> {
        let statement = Statement::from_value(statement.clone())?;
        let agent = Agent::check(&statement, &self.inner.net, now)?;
        if &agent.agent != sender.id() || agent.card.to_value() != sender.to_value() {
            return Err(NodeError::forbidden("agent: the statement is for another key"));
        }
        if !agent.may_write_to(to) {
            return Err(NodeError::forbidden("the agent may not write to this recipient"));
        }
        let max_homes = self.with_core(|core| -> NodeResult<Option<u64>> {
            core.state.check_login(agent.owner.id(), now)?;
            Ok(core.is_gateway(&agent.node, now).then_some(core.state.manifest().limits.members))
        })??;
        if let Some(max_homes) = max_homes {
            let (iat, exp) = statement.times();
            let row = HomeRow {
                member: agent.agent.to_string(),
                node: agent.node.to_string(),
                iat,
                exp,
                seq: 0,
                home: statement.canonical_bytes().to_vec(),
                card: sender.to_bytes()?,
            };
            let key = self.inner.net.to_string();
            // Best effort: a full table only means the recipient does not see the owner.
            let _ = self.blocking(move |store| store.home_put(&key, &row, max_homes)).await;
        }
        Ok(())
    }

    /// The agent statement of an agent homed here (to attach to its relayed envelopes).
    pub(crate) async fn agent_statement_of(&self, id: &Id, now: i64) -> Option<Value> {
        // From the home entry (not the session): envelopes in the outbox outlive a restart of the node.
        self.agent_home(id, now).await.ok().flatten().map(|(_, statement)| statement.to_value())
    }

    /// `POST /v4/agent/revoke`: the owner (logged in, signed request `agent-revoke`) revokes its agent here.
    pub(crate) async fn agent_revoke(&self, request: &crate::Request, now: i64) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, now)?;
        let signed = SignedRequest::parse(&request.body)?;
        signed.check(self.inner.identity.id(), now)?;
        if signed.op() != "agent-revoke" || signed.iss() != &caller {
            return Err(NodeError::forbidden("agent-revoke must be signed by the logged-in owner"));
        }
        let card = self.known_card(&caller).await?.ok_or_else(NodeError::no_session)?;
        signed.verify(&card)?;
        self.inner.guard.remember_nonce(
            signed.iss(),
            signed.nonce(),
            signed.iat().saturating_add(bridge_core::CLOCK_SKEW_MS),
            now,
        )?;
        let agent = Id::parse(signed.body().get("agent").and_then(Value::as_str).unwrap_or_default())?;
        let (key, owner) = (agent.to_string(), caller.to_string());
        let until = now.saturating_add(REVOCATION_KEPT_MS);
        if !self.blocking(move |store| store.agent_revoke(&key, &owner, now, until, now)).await? {
            return Err(NodeError::quota());
        }
        // Its session and home entry here end now (only if they belong to this owner).
        let ended = {
            let mut agents = lock(&self.inner.agents);
            match agents.grants.get(&agent) {
                Some(grant) if grant.agent.owner.id() == &caller => agents.grants.remove(&agent).is_some(),
                _ => false,
            }
        };
        if ended {
            lock(&self.inner.sessions).remove_identity(&agent);
        }
        let (net, member) = (self.inner.net.to_string(), agent.to_string());
        let row = self.blocking(move |store| store.home_get(&net, &member, i64::MIN)).await?;
        let owned_here = row.as_ref().is_some_and(|row| {
            Statement::parse(&row.home)
                .ok()
                .is_some_and(|statement| statement.kind() == "agent" && statement.claimed_signers() == [&caller])
        });
        if owned_here {
            let (net, member) = (self.inner.net.to_string(), agent.to_string());
            self.blocking(move |store| store.home_delete(&net, &member)).await?;
        }
        Ok(json!({"ok": true, "ended": ended}).to_string().into_bytes())
    }
}
