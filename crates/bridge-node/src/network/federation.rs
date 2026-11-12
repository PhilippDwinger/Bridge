//! Federation at a node (docs/10 §6, ADR 0023): members of connected networks write to each other.
//!
//! - **Out**: a client's envelope with `dnet` goes into the outbox (persisted, retried until its `ttl`) with the other
//!   network's ID as target; the relay duty hands it to the gateways this network listed for it
//!   (`POST /v4/fed/relay`), one after the other until one takes it (only the one where the recipient lives does).
//! - **In**: a listed gateway of a connected network delivers: our `federation` statement for that network is in
//!   effect, the caller is in its list (signature with that card), the envelope is for us (`dnet`) and signed by its
//!   sender, the sender is not banned here, the recipient is a member with its home here. Never another hop.
//! - **Cards**: `POST /v4/fed/card` answers a listed gateway with the card of a member homed here.
//!
//! Both directions need both networks' statements (each side checks its own log).

use bridge_core::envelope::MAX_ENVELOPE_BYTES;
use bridge_core::json::{canonical, parse_strict};
use bridge_core::request::MAX_REQUEST_BYTES;
use bridge_core::{CLOCK_SKEW_MS, Envelope, Id, KeyCard, Role, SignedRequest};
use bridge_net::FederationInfo;
use bridge_transport::{Method, Request};
use serde_json::{Value, json};

use super::peer::Endpoint;
use crate::{Node, NodeError, NodeResult, body_object};

/// Largest federation relay request (envelope + signed request + framing).
const MAX_FED_RELAY_BYTES: usize = MAX_ENVELOPE_BYTES + MAX_REQUEST_BYTES + 1024;

/// What became of one federation delivery attempt (see `relay`).
pub(crate) enum FedAttempt {
    /// Delivered (or already there).
    Done,
    /// No listed gateway took it for good reasons (bad envelope) - drop.
    Refused(String),
    /// Try again later.
    Retry(String),
}

impl Node {
    /// The federation with `peer` in effect now, or `FORBIDDEN`.
    pub(crate) fn federation_with(&self, peer: &Id, now: i64) -> NodeResult<FederationInfo> {
        self.network().ok_or_else(|| NodeError::forbidden("not in a network"))?;
        self.with_core(|core| core.state.federation(peer, now))?
            .ok_or_else(|| NodeError::forbidden("this network is not connected to that network"))
    }

    /// Routes `/v4/fed/...`.
    pub(crate) async fn route_fed(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        self.network().ok_or_else(NodeError::not_found)?;
        match (request.method, request.path.as_str()) {
            (Method::Post, "/v4/fed/relay") => self.fed_relay_in(&request.body, now).await,
            (Method::Post, "/v4/fed/card") => self.fed_card_out(&request.body, now).await,
            _ => Err(NodeError::not_found()),
        }
    }

    /// The endpoints of a gateway of a connected network: its addresses were confirmed by this network's key (in the
    /// federation statement), so they are not guarded; LAN addresses only pinned.
    fn fed_endpoints(&self, card: &KeyCard) -> Vec<Endpoint> {
        let mut endpoints = self.lan_endpoints_of(card.id(), card.tls().copied());
        for url in card.urls().iter().take(bridge_core::keys::MAX_URLS) {
            endpoints.push(Endpoint::public(url));
        }
        endpoints
    }

    /// One attempt to hand an outbox item to the network `peer` (relay duty).
    pub(crate) async fn fed_deliver(&self, peer: &Id, envelope: &[u8], card: &[u8], now: i64) -> FedAttempt {
        let Ok(info) = self.federation_with(peer, now) else {
            return FedAttempt::Refused("not connected to that network any more".into());
        };
        let Ok(card) = KeyCard::parse(card) else { return FedAttempt::Refused("bad stored card".into()) };
        let body = json!({"envelope": Self::envelope_hash(envelope), "card": card.to_value()});
        let mut last = FedAttempt::Retry("no gateway of the other network reachable".into());
        for gateway in &info.gateways {
            let Ok(request) = self.signed(gateway.id(), "fed-relay", body.clone()) else {
                return FedAttempt::Retry("cannot sign".into());
            };
            // Canonical order of the two keys: "envelope" < "rq". Both parts are canonical JSON already.
            let mut wire = br#"{"envelope":"#.to_vec();
            wire.extend_from_slice(envelope);
            wire.extend_from_slice(br#","rq":"#);
            wire.extend_from_slice(&request);
            wire.push(b'}');
            for endpoint in self.fed_endpoints(gateway).iter().take(8) {
                match self.peer_post(endpoint, "/v4/fed/relay", wire.clone()).await {
                    Ok(answer) if answer.status == 200 || answer.code() == "REPLAY" => return FedAttempt::Done,
                    Ok(answer) if matches!(answer.code(), "BAD_FORMAT" | "TOO_LARGE" | "BAD_SIGNATURE") => {
                        return FedAttempt::Refused(format!("{} {}", answer.status, answer.code()));
                    }
                    // Not homed there, busy, not connected (yet) on that side: the next gateway, then later.
                    Ok(answer) => {
                        last = FedAttempt::Retry(format!("{} {}", answer.status, answer.code()));
                        break;
                    }
                    Err(error) => last = FedAttempt::Retry(error),
                }
            }
        }
        last
    }

    /// `POST /v4/fed/relay` (receiving gateway of the target network).
    async fn fed_relay_in(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        if body.len() > MAX_FED_RELAY_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "relay request too large"));
        }
        let Value::Object(outer) = parse_strict(body, MAX_FED_RELAY_BYTES)? else {
            return Err(NodeError::bad_format("fed relay: not an object"));
        };
        if outer.len() != 2 {
            return Err(NodeError::bad_format("fed relay: exactly envelope and rq"));
        }
        let rq = outer.get("rq").cloned().ok_or_else(|| NodeError::bad_format("fed relay: rq missing"))?;
        if canonical(&rq)?.len() > MAX_REQUEST_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "request too large"));
        }
        let request = SignedRequest::from_value(rq)?;
        request.check(&me, now)?;
        if request.op() != "fed-relay" {
            return Err(NodeError::bad_format("op: expected fed-relay"));
        }
        let envelope_value =
            outer.get("envelope").cloned().ok_or_else(|| NodeError::bad_format("fed relay: envelope"))?;
        let bytes = canonical(&envelope_value)?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "envelope too large"));
        }
        let envelope = Envelope::from_value(envelope_value)?;
        if envelope.dnet() != Some(&self.inner.net) {
            return Err(NodeError::forbidden("the envelope is not for this network"));
        }
        // Our statement for the sender's network, and the caller one of the gateways we listed there.
        let info = self.federation_with(envelope.net(), now)?;
        let caller = info
            .gateways
            .iter()
            .find(|card| card.id() == request.iss())
            .ok_or_else(|| NodeError::forbidden("not a listed gateway of that network"))?;
        request.verify(caller)?;
        self.inner.guard.remember_nonce(
            request.iss(),
            request.nonce(),
            request.iat().saturating_add(CLOCK_SKEW_MS),
            now,
        )?;
        if request.body().get("envelope").and_then(Value::as_str) != Some(Self::envelope_hash(&bytes).as_str()) {
            return Err(NodeError::bad_format("fed relay: envelope hash does not match"));
        }
        envelope.check_time(now)?;
        let sender = KeyCard::from_value(request.body().get("card").cloned().unwrap_or(Value::Null))?;
        if sender.id() != envelope.from() || matches!(sender.role(), Role::Net | Role::App) {
            return Err(NodeError::new(401, "BAD_SIGNATURE", "card is not the sender's"));
        }
        let unknown = || NodeError::new(404, "UNKNOWN_IDENTITY", "recipient does not live here");
        self.with_core(|core| -> NodeResult<()> {
            if core.state.is_banned(envelope.from(), now) {
                return Err(NodeError::new(403, "BANNED", "sender banned in this network"));
            }
            if !core.state.is_member(envelope.to(), now) {
                return Err(unknown());
            }
            Ok(())
        })??;
        let (net, recipient) = (self.inner.net.to_string(), envelope.to().to_string());
        let home = self.blocking(move |store| store.home_get(&net, &recipient, now)).await?;
        if home.is_none_or(|home| home.node != me.as_str()) {
            return Err(unknown());
        }
        self.inner.guard.admit_send(envelope.from(), now)?;
        envelope.verify(&sender)?;
        let (id, card, max_cards) =
            (sender.id().to_string(), sender.to_bytes()?, self.inner.guard.limits().max_identities);
        if !self.blocking(move |store| store.put_card(&id, &card, now, max_cards)).await? {
            return Err(NodeError { retry_after: Some(3600), ..NodeError::new(429, "QUOTA_EXCEEDED", "node is full") });
        }
        self.deliver_local(&envelope, now).await?;
        Ok(br#"{"ok":true}"#.to_vec())
    }

    /// `POST /v4/fed/card` (signed request `fed-card` of a listed gateway of a connected network, `{"id"}`): the card
    /// of a member homed here.
    async fn fed_card_out(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let request = SignedRequest::parse(body)?;
        request.check(self.inner.identity.id(), now)?;
        if request.op() != "fed-card" {
            return Err(NodeError::bad_format("op: expected fed-card"));
        }
        // Which connected network lists the caller as its gateway.
        let caller = self.with_core(|core| {
            core.state.federations(now).into_iter().find_map(|peer| {
                core.state.federation(&peer, now)?.gateways.into_iter().find(|card| card.id() == request.iss())
            })
        })?;
        let caller = caller.ok_or_else(|| NodeError::forbidden("not a listed gateway of a connected network"))?;
        request.verify(&caller)?;
        self.inner.guard.admit_send(request.iss(), now)?;
        let id = Id::parse(request.body().get("id").and_then(Value::as_str).unwrap_or_default())?;
        if !self.with_core(|core| core.state.is_member(&id, now))? {
            return Err(NodeError::not_found());
        }
        let (net, member) = (self.inner.net.to_string(), id.to_string());
        let home =
            self.blocking(move |store| store.home_get(&net, &member, now)).await?.ok_or_else(NodeError::not_found)?;
        let card = KeyCard::parse(&home.card)?;
        Ok(json!({"card": card.to_value()}).to_string().into_bytes())
    }

    /// The card of `id` in the connected network `peer`, asked from the gateways this network listed for it.
    pub(crate) async fn fed_card_of(&self, id: &Id, peer: &Id, now: i64) -> NodeResult<KeyCard> {
        let info = self.federation_with(peer, now)?;
        for gateway in &info.gateways {
            let Ok(request) = self.signed(gateway.id(), "fed-card", json!({"id": id.as_str()})) else { continue };
            for endpoint in self.fed_endpoints(gateway).iter().take(8) {
                let Ok(answer) = self.peer_post(endpoint, "/v4/fed/card", request.clone()).await else { continue };
                if let Ok(answer) = answer.ok() {
                    let card = KeyCard::from_value(answer.get("card").cloned().unwrap_or(Value::Null))?;
                    if card.id() != id {
                        return Err(NodeError::bad_format("the other network answered another card"));
                    }
                    return Ok(card);
                }
                break; // that gateway does not know it: the next one
            }
        }
        Err(NodeError::not_found())
    }

    /// For a poll answer: the `federation` statements of the networks in `nets` (other than ours) and the card of our
    /// net key, so the client can check them itself (docs/10 §6.3).
    pub(crate) fn fed_proofs(&self, nets: &[Id], now: i64) -> (Vec<(String, Vec<u8>)>, Option<Value>) {
        if nets.is_empty() || self.network().is_none() {
            return (Vec::new(), None);
        }
        self.with_core(|core| {
            let statements = nets
                .iter()
                .filter_map(|peer| core.state.federation(peer, now).map(|info| (peer.to_string(), info.statement)))
                .collect();
            (statements, Some(core.state.manifest().card.to_value()))
        })
        .unwrap_or_default()
    }

    /// `POST /v4/card` with `net`: the body of a card request for another network.
    pub(crate) fn fed_card_request(body: &[u8]) -> NodeResult<(Id, Option<Id>)> {
        let object = body_object(body, 1024)?;
        let id = Id::parse(object.get("id").and_then(Value::as_str).unwrap_or_default())?;
        let net = match object.get("net") {
            None => None,
            Some(value) => Some(Id::parse(value.as_str().unwrap_or_default())?),
        };
        Ok((id, net))
    }
}
