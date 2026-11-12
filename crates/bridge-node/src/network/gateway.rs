//! The gateway (docs/06 §7, §8): login only for members that are not banned, join (modes, invite codes,
//! proof-of-work), `home` entries (registered at login, exchanged between gateways together with the member's
//! card), and where an envelope for a member goes (here, or relayed to its home gateway).

use bridge_core::encoding::b64;
use bridge_core::json::canonical;
use bridge_core::{Id, KeyCard, Role, SignedRequest, Statement};
use bridge_net::{Body, Home, Invite, JoinMode, Member};
use bridge_store::{HomeRow, HomeStored};
use serde_json::{Value, json};

use super::MEMBER_LIFETIME_MS;
use super::peer::Endpoint;
use crate::{Node, NodeError, NodeResult, lock};

/// Most `home` entries per answer of `/v4/node/homes`.
pub const MAX_HOMES_PER_ANSWER: u32 = 256;
/// Gateways asked for `home` entries per round.
const HOME_PEERS_PER_ROUND: usize = 8;
/// Pages taken from one gateway per round.
const HOME_PAGES_PER_ROUND: usize = 4;
/// A `home` entry whose member (or gateway) this node does not know yet is fetched again while it is younger than
/// this - the own log may simply be a sync round behind the other gateway's.
const HOME_RETRY_WINDOW_MS: i64 = 2 * 60 * 1000;

/// Why a `home` entry from another gateway was not taken.
enum HomeRejected {
    /// Maybe later: the member or its gateway is not (yet) known here.
    NotYet,
    /// Never (bad form, signature, network ...).
    Invalid(NodeError),
}

/// Where an envelope for a recipient goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Route {
    /// Into the mailbox here.
    Local,
    /// To the recipient's home gateway.
    Relay(Id),
}

impl Node {
    /// Network checks of a login (after its signature was verified): this node is a gateway, the caller is a
    /// member and not banned; an attached `home` statement is checked and stored.
    pub(crate) async fn net_login(&self, card: &KeyCard, home: Option<&Value>, now: i64) -> NodeResult<()> {
        let (me, net) = (self.inner.identity.id().clone(), self.inner.net.clone());
        let max_homes = self.with_core(|core| -> NodeResult<u64> {
            if !core.is_gateway(&me, now) {
                return Err(NodeError::forbidden("this node is not a gateway of the network (yet)"));
            }
            core.state.check_login(card.id(), now)?;
            Ok(core.state.manifest().limits.members)
        })??;
        let Some(home) = home else { return Ok(()) };
        let statement = Statement::from_value(home.clone())?;
        let checked = Home::check(&statement, &net, card, now)?;
        if checked.node != me {
            return Err(NodeError::bad_format("home: must name this node"));
        }
        let (iat, exp) = statement.times();
        let row = HomeRow {
            member: card.id().to_string(),
            node: me.to_string(),
            iat,
            exp,
            seq: 0,
            home: statement.canonical_bytes().to_vec(),
            card: card.to_bytes()?,
        };
        let key = net.to_string();
        match self.blocking(move |store| store.home_put(&key, &row, max_homes)).await? {
            HomeStored::Stored | HomeStored::Older => Ok(()),
            HomeStored::Full => Err(NodeError { retry_after: Some(3600), ..NodeError::quota() }),
        }
    }

    /// Network check of every session use: this node is still a gateway, the caller still a member.
    pub(crate) fn net_session_check(&self, id: &Id, now: i64) -> NodeResult<()> {
        if self.network().is_none() {
            return Ok(());
        }
        let me = self.inner.identity.id();
        self.with_core(|core| -> NodeResult<()> {
            if !core.is_gateway(me, now) {
                return Err(NodeError::forbidden("this node is no longer a gateway of the network"));
            }
            core.state.check_login(id, now)?;
            Ok(())
        })?
    }

    /// Where an envelope for `to` goes: its `home` entry decides (registered at login, exchanged between
    /// gateways). Non-members, members without a home entry and members whose home is no gateway any more:
    /// `UNKNOWN_IDENTITY` (a known card is not enough - relayed senders' cards are known here too).
    pub(crate) async fn route_recipient(&self, to: &Id, now: i64) -> NodeResult<Route> {
        let unknown = || NodeError::new(404, "UNKNOWN_IDENTITY", "recipient unknown here");
        if !self.with_core(|core| core.state.level(to, now).is_some())? {
            // Not a member: an agent with a valid statement (docs/10 §3.2) goes to its home node.
            let (agent, _) = self.agent_home(to, now).await?.ok_or_else(unknown)?;
            if &agent.node == self.inner.identity.id() {
                return Ok(Route::Local);
            }
            if self.with_core(|core| core.is_gateway(&agent.node, now))? {
                return Ok(Route::Relay(agent.node));
            }
            return Err(unknown());
        }
        let (net, member) = (self.inner.net.to_string(), to.to_string());
        let home = self.blocking(move |store| store.home_get(&net, &member, now)).await?.ok_or_else(unknown)?;
        let node = Id::parse(&home.node)?;
        if &node == self.inner.identity.id() {
            return Ok(Route::Local);
        }
        if self.with_core(|core| core.is_gateway(&node, now))? {
            return Ok(Route::Relay(node));
        }
        Err(unknown())
    }

    /// The card of a member homed at another gateway (from the exchanged `home` entries).
    pub(crate) async fn home_card(&self, id: &Id, now: i64) -> NodeResult<Option<KeyCard>> {
        if self.network().is_none() {
            return Ok(None);
        }
        let (net, member) = (self.inner.net.to_string(), id.to_string());
        match self.blocking(move |store| store.home_get(&net, &member, now)).await? {
            Some(row) => Ok(Some(KeyCard::parse(&row.card)?)),
            None => Ok(None),
        }
    }

    /// `POST /v4/net/join` (docs/06 §7).
    pub(crate) async fn join(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        if !self.with_core(|core| core.is_gateway(&me, now))? {
            return Err(NodeError::forbidden("this node is not a gateway of the network (yet)"));
        }
        let request = SignedRequest::parse(body)?;
        request.check(&me, now)?;
        if request.op() != "join" {
            return Err(NodeError::bad_format("op: expected join"));
        }
        let text = |name: &str| request.body().get(name).and_then(Value::as_str);
        let challenge = bridge_core::encoding::b64_fixed::<32>(text("challenge").unwrap_or_default(), "challenge")?;
        let puzzle = self.inner.guard.take_challenge(&challenge, now).map_err(|error| match error {
            bridge_guard::GuardError::Replay => NodeError::new(401, "EXPIRED", "challenge unknown, used or expired"),
            other => other.into(),
        })?;
        let required = self.with_core(|core| core.state.manifest().join.pow_bits)?;
        let pow_required = || NodeError::new(403, "POW_REQUIRED", "proof of work required");
        if puzzle.as_ref().map_or(0, bridge_core::Puzzle::bits) < required {
            return Err(pow_required());
        }
        if let Some(puzzle) = puzzle {
            let solution = text("pow").ok_or_else(pow_required)?;
            puzzle.check_solution(&bridge_core::encoding::b64_fixed::<8>(solution, "pow")?, now)?;
        }
        let card = KeyCard::from_value(request.body().get("card").cloned().unwrap_or(Value::Null))?;
        if card.id() != request.iss() {
            return Err(NodeError::new(401, "BAD_SIGNATURE", "card does not belong to the caller"));
        }
        if !matches!(card.role(), Role::Client | Role::Node) {
            return Err(NodeError::forbidden("only clients and nodes join as members"));
        }
        request.verify(&card)?;
        let code = match text("code") {
            Some(code) => {
                bridge_core::link::check_invite_code(code)?;
                Some(Invite::hash_code(code))
            }
            None => None,
        };
        let member = card.id().clone();
        let already = self.with_core(|core| -> NodeResult<bool> {
            if core.state.is_banned(&member, now) {
                return Err(NodeError::new(403, "BANNED", "banned"));
            }
            if core.state.is_member(&member, now) {
                return Ok(true);
            }
            match core.state.manifest().join.mode {
                JoinMode::Open => {}
                JoinMode::Closed => return Err(NodeError::forbidden("closed network: only an admin admits members")),
                JoinMode::Invite => match &code {
                    Some(hash) if core.state.invite_left(hash, now).is_some_and(|left| left > 0) => {}
                    _ => return Err(NodeError::forbidden("invite code missing, invalid or used up")),
                },
            }
            Ok(false)
        })??;
        if already {
            return Ok(br#"{"member":null,"already":true}"#.to_vec());
        }
        // In open networks a code is not needed; it is only recorded when it is an invite with uses left (a used-up
        // or unknown code is ignored there - recording it would make the membership invalid).
        let code = code.filter(|hash| {
            self.with_core(|core| core.state.invite_left(hash, now).is_some_and(|left| left > 0)).unwrap_or(false)
        });
        let statement = Member { member: member.clone(), invite: code }.sign(
            &self.inner.net,
            now,
            now.saturating_add(MEMBER_LIFETIME_MS),
            &self.inner.identity,
        )?;
        self.submit_to_operator(&statement).await?;
        self.wait_until(|core, now| core.state.is_member(&member, now)).await;
        Ok(json!({"member": statement.to_value()}).to_string().into_bytes())
    }

    /// Gives a statement to the active log operator (this node itself, or over the network); returns where it
    /// ended up in the log.
    pub(crate) async fn submit_to_operator(&self, statement: &Statement) -> NodeResult<super::operator::Appended> {
        let operator = self.with_core(|core| core.active_operator().cloned())?.ok_or_else(NodeError::unavailable)?;
        if &operator == self.inner.identity.id() {
            return self.operator_append(statement).await;
        }
        let body = self
            .signed(&operator, "submit", json!({"statement": statement.to_value()}))
            .map_err(|_| NodeError::unavailable())?;
        let mut last = NodeError::unavailable();
        for endpoint in self.reach(&operator).iter().take(8) {
            match self.peer_post(endpoint, &self.net_path("submit"), body.clone()).await {
                Ok(answer) if answer.status == 200 => {
                    if let Some(network) = self.network() {
                        network.wake_sync.notify_one();
                    }
                    let number = |name: &str| answer.body.get(name).and_then(Value::as_u64).unwrap_or(0);
                    return Ok(super::operator::Appended { index: number("index"), size: number("size") });
                }
                Ok(answer) => {
                    last =
                        NodeError::new(answer.status, crate::error::known_code(answer.code()), "log operator refused");
                    if answer.status < 500 {
                        break;
                    }
                }
                Err(error) => tracing::debug!(%endpoint, %error, "submit to the log operator"),
            }
        }
        Err(last)
    }

    /// Waits (at most `join_wait`) until `done` holds for the replayed state, waking the sync on every change.
    pub(crate) async fn wait_until(&self, done: impl Fn(&super::Core, i64) -> bool) {
        let Some(network) = self.network() else { return };
        let deadline = tokio::time::Instant::now() + network.timing.join_wait;
        let mut changes = network.applied.subscribe();
        loop {
            let finished = lock(&network.core).as_ref().is_some_and(|core| done(core, self.now()));
            if finished || tokio::time::Instant::now() >= deadline {
                return;
            }
            network.wake_sync.notify_one();
            let _ = tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::now() + network.timing.sync),
                changes.changed(),
            )
            .await;
        }
    }

    /// `POST /v4/node/homes`: a gateway fetches the `home` entries of members homed here (signed request,
    /// `op:"homes"`, `body:{"since":n}`).
    pub(crate) async fn homes_out(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        let request = SignedRequest::parse(body)?;
        request.check(&me, now)?;
        if request.op() != "homes" {
            return Err(NodeError::bad_format("op: expected homes"));
        }
        let card = self
            .with_core(|core| core.gateway_card(request.iss(), now))?
            .ok_or_else(|| NodeError::forbidden("only gateways of the network exchange homes"))?;
        request.verify(&card)?;
        // Read-only and repeatable: no nonce table needed.
        let since = request.body().get("since").and_then(Value::as_i64).filter(|n| *n >= 0).unwrap_or(0);
        let (net, node) = (self.inner.net.to_string(), me.to_string());
        let rows = self
            .blocking(move |store| store.homes_of_node_since(&net, &node, since, MAX_HOMES_PER_ANSWER, now))
            .await?;
        let next = rows.last().map_or(since, |row| row.seq);
        let mut out = br#"{"homes":["#.to_vec();
        for (index, row) in rows.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            // Stored bytes are canonical JSON written by this node.
            out.extend_from_slice(br#"{"card":"#);
            out.extend_from_slice(&row.card);
            out.extend_from_slice(br#","home":"#);
            out.extend_from_slice(&row.home);
            out.extend_from_slice(format!(r#","seq":{}}}"#, row.seq).as_bytes());
        }
        out.extend_from_slice(format!(r#"],"next":{next}}}"#).as_bytes());
        Ok(out)
    }

    /// One round of the home exchange: fetch new entries from up to 8 other gateways (LAN first).
    pub(crate) async fn homes_round(&self) {
        let now = self.now();
        let me = self.inner.identity.id().clone();
        let gateways = self
            .with_core(|core| {
                if !core.is_gateway(&me, now) {
                    return Vec::new();
                }
                core.state
                    .gateways(now)
                    .into_iter()
                    .filter(|(id, _)| id != &me)
                    .filter_map(|(id, card)| card.map(|card| (id, card.tls().copied(), card.urls().to_vec())))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let Some(network) = self.network() else { return };
        let gateways: Vec<(bridge_core::Id, Vec<Endpoint>)> = gateways
            .into_iter()
            .map(|(id, tls, urls)| {
                let endpoints = self.endpoints_of(&id, tls, &urls);
                (id, endpoints)
            })
            .filter(|(_, endpoints)| !endpoints.is_empty())
            .collect();
        for (id, endpoints) in self.pick_homes(gateways) {
            for _ in 0..HOME_PAGES_PER_ROUND {
                let since = lock(&network.peers).homes_since.get(&id).copied().unwrap_or(0);
                match self.fetch_homes(&id, &endpoints, since).await {
                    Ok((count, next)) => {
                        let mut peers = lock(&network.peers);
                        if peers.homes_since.len() >= 1024 {
                            peers.homes_since.clear();
                        }
                        peers.homes_since.insert(id.clone(), next.max(since));
                        if count < MAX_HOMES_PER_ANSWER as usize {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!(gateway = %id, %error, "home exchange");
                        break;
                    }
                }
            }
        }
    }

    fn pick_homes<T>(&self, gateways: Vec<T>) -> Vec<T> {
        // Rotate through the gateways (no per-peer gap: the gossip uses that).
        let Some(network) = self.network() else { return Vec::new() };
        if gateways.is_empty() {
            return Vec::new();
        }
        let count = gateways.len();
        let mut peers = lock(&network.peers);
        let start = peers.homes_cursor % count;
        peers.homes_cursor = peers.homes_cursor.wrapping_add(HOME_PEERS_PER_ROUND);
        let mut gateways = gateways;
        gateways.rotate_left(start);
        gateways.truncate(count.min(HOME_PEERS_PER_ROUND));
        gateways
    }

    async fn fetch_homes(
        &self,
        gateway: &bridge_core::Id,
        endpoints: &[Endpoint],
        since: i64,
    ) -> Result<(usize, i64), String> {
        let body = self.signed(gateway, "homes", json!({"since": since}))?;
        let answer = self.peer_post_any(endpoints, "/v4/node/homes", body).await?.ok()?;
        let list = answer.get("homes").and_then(Value::as_array).ok_or("homes missing")?;
        if list.len() > MAX_HOMES_PER_ANSWER as usize {
            return Err("too many homes".into());
        }
        let next = answer.get("next").and_then(Value::as_i64).ok_or("next missing")?;
        let now = self.now();
        let mut done = since;
        for item in list {
            let seq = item.get("seq").and_then(Value::as_i64).filter(|seq| *seq > done).ok_or("bad seq")?;
            match self.accept_home(item).await {
                Ok(()) => {}
                Err(HomeRejected::NotYet) if Self::home_iat(item) > now.saturating_sub(HOME_RETRY_WINDOW_MS) => {
                    // Fetch it again next round (do not move the cursor past it).
                    return Ok((0, done));
                }
                Err(HomeRejected::NotYet) => tracing::debug!("old home entry of an unknown member skipped"),
                Err(HomeRejected::Invalid(error)) => tracing::debug!(error = %error.message, "home entry not taken"),
            }
            done = seq;
        }
        Ok((list.len(), next.max(done)))
    }

    fn home_iat(item: &Value) -> i64 {
        item.get("home").and_then(|home| home.get("iat")).and_then(Value::as_i64).unwrap_or(0)
    }

    /// Takes a `home` entry from another gateway: self-signed by a member of the network, naming a gateway.
    async fn accept_home(&self, item: &Value) -> Result<(), HomeRejected> {
        let invalid = HomeRejected::Invalid;
        let now = self.now();
        let card =
            KeyCard::from_value(item.get("card").cloned().unwrap_or(Value::Null)).map_err(|e| invalid(e.into()))?;
        let statement =
            Statement::from_value(item.get("home").cloned().unwrap_or(Value::Null)).map_err(|e| invalid(e.into()))?;
        // A member's `home`, or an agent's statement naming its home node (docs/10 §3.2).
        let (node, member_of) = if statement.kind() == "agent" {
            let agent = bridge_core::Agent::check(&statement, &self.inner.net, now).map_err(|e| invalid(e.into()))?;
            if &agent.agent != card.id() || agent.card.to_value() != card.to_value() {
                return Err(invalid(NodeError::bad_format("agent home: other card")));
            }
            (agent.node, agent.owner.id().clone())
        } else {
            let home = Home::check(&statement, &self.inner.net, &card, now).map_err(|e| invalid(e.into()))?;
            (home.node, card.id().clone())
        };
        let max_homes = self
            .with_core(|core| {
                (core.state.check_login(&member_of, now).is_ok() && core.is_gateway(&node, now))
                    .then_some(core.state.manifest().limits.members)
            })
            .map_err(invalid)?
            .ok_or(HomeRejected::NotYet)?;
        let (iat, exp) = statement.times();
        let row = HomeRow {
            member: card.id().to_string(),
            node: node.to_string(),
            iat,
            exp,
            seq: 0,
            home: statement.canonical_bytes().to_vec(),
            card: canonical(&card.to_value()).map_err(|e| invalid(e.into()))?,
        };
        let net = self.inner.net.to_string();
        self.blocking(move |store| store.home_put(&net, &row, max_homes)).await.map_err(invalid)?;
        Ok(())
    }

    /// The hash of an envelope as the relay request names it.
    pub(crate) fn envelope_hash(bytes: &[u8]) -> String {
        b64(&bridge_core::crypto::sha256(bytes))
    }
}
