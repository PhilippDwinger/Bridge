//! Relay between gateways (docs/06 §8). The sending gateway checks an envelope like in phase 2, keeps it in its
//! outbox (persisted, replay-protected) and hands it to the recipient's home gateway with `POST /v4/node/relay`,
//! retried until its `ttl` ends. The receiving gateway checks everything again: the caller is a gateway of the
//! network, the request is for it and fresh (and used once), the envelope is intact and signed by a member that is
//! not banned (its card travels along, self-certifying), the recipient lives here, quotas and replay as in phase 2.
//! Never more than one hop: a relayed envelope is only ever delivered locally.
//!
//! Wire format (docs/06 §8): `{"envelope": <envelope>, "rq": <rq op "relay">}` with
//! `rq.body = {"envelope": "<Base64url SHA-256 of the envelope's canonical bytes>", "card": <sender card>}` - the
//! signed request binds the envelope by its hash, so envelopes up to 256 KiB fit although a request has 64 KiB.

use std::collections::BTreeSet;

use bridge_core::envelope::MAX_ENVELOPE_BYTES;
use bridge_core::json::{canonical, parse_strict};
use bridge_core::request::MAX_REQUEST_BYTES;
use bridge_core::{CLOCK_SKEW_MS, Envelope, Id, KeyCard, SignedRequest};
use bridge_store::{Delivered, Outgoing, RelayItem};
use serde_json::{Value, json};

use crate::{Node, NodeError, NodeResult};

/// Largest relay request (envelope + signed request + framing).
pub const MAX_RELAY_BYTES: usize = MAX_ENVELOPE_BYTES + MAX_REQUEST_BYTES + 1024;
/// Envelopes taken from the outbox per round.
const RELAY_BATCH: u32 = 64;
/// After this many attempts an envelope the target keeps refusing is dropped (unreachable targets are retried until
/// the envelope expires).
pub const MAX_REFUSED_ATTEMPTS: u32 = 50;
/// Answers that can never turn into a delivery: drop at once.
const FINAL_REFUSALS: [&str; 6] = ["BAD_FORMAT", "TOO_LARGE", "BAD_SIGNATURE", "EXPIRED", "NOT_YET_VALID", "BANNED"];

/// What became of one delivery attempt.
enum Attempt {
    /// Delivered (or already there).
    Done,
    /// Refused for good (the target says it can not take it).
    Refused(String),
    /// Try again later (target down, busy, or not a gateway right now).
    Retry(String),
}

impl Node {
    /// Puts a checked envelope for a member of another gateway into the outbox and wakes the relay duty.
    pub(crate) async fn relay_enqueue(
        &self,
        envelope: &Envelope,
        sender: &KeyCard,
        target: &Id,
        now: i64,
    ) -> NodeResult<()> {
        let network = self.network().ok_or_else(NodeError::not_found)?;
        let (target, from, env_id, expires_at) =
            (target.to_string(), envelope.from().to_string(), *envelope.id(), envelope.expires_at());
        let (bytes, card) = (envelope.to_bytes()?, sender.to_bytes()?);
        let (limits, mailbox) = (self.inner.guard.relay_limits(), self.inner.guard.mailbox_limits());
        let outcome = self
            .blocking(move |store| {
                let item = RelayItem {
                    target: &target,
                    sender: &from,
                    env_id: &env_id,
                    expires_at,
                    envelope: &bytes,
                    card: &card,
                    now,
                };
                store.relay_enqueue(&item, &limits, &mailbox)
            })
            .await?;
        match outcome {
            Delivered::Stored => {
                network.wake_relay.notify_one();
                Ok(())
            }
            Delivered::Replay => Err(NodeError::new(409, "REPLAY", "envelope already delivered")),
            Delivered::MailboxFull | Delivered::SenderLimit | Delivered::NodeFull => Err(NodeError::quota()),
        }
    }

    /// One round of the relay duty: every due envelope in the outbox, one attempt each.
    pub(crate) async fn relay_round(&self) {
        let Some(network) = self.network() else { return };
        let now = self.now();
        let retry = i64::try_from(network.timing.relay_retry.as_millis()).unwrap_or(i64::MAX);
        let due = match self.blocking(move |store| store.relay_due(now, RELAY_BATCH)).await {
            Ok(due) => due,
            Err(_) => return,
        };
        let mut unreachable: BTreeSet<String> = BTreeSet::new();
        for item in due {
            let attempt = if unreachable.contains(&item.target) {
                Attempt::Retry("target unreachable in this round".into())
            } else {
                self.relay_one(&item).await
            };
            let seq = item.seq;
            let result = match attempt {
                Attempt::Done => self.blocking(move |store| store.relay_done(seq)).await,
                Attempt::Refused(reason) => {
                    tracing::warn!(target = %item.target, %reason, "relay refused - envelope dropped");
                    self.blocking(move |store| store.relay_done(seq)).await
                }
                Attempt::Retry(reason) => {
                    tracing::debug!(target = %item.target, %reason, "relay later");
                    unreachable.insert(item.target.clone());
                    let next = self.now().saturating_add(retry);
                    self.blocking(move |store| store.relay_later(seq, next)).await
                }
            };
            if result.is_err() {
                return;
            }
        }
    }

    async fn relay_one(&self, item: &Outgoing) -> Attempt {
        let now = self.now();
        let Ok(target) = Id::parse(&item.target) else { return Attempt::Refused("bad target".into()) };
        let endpoints = match self.with_core(|core| core.gateway_card(&target, now)) {
            Ok(Some(card)) => self.endpoints_of(&target, card.tls().copied(), card.urls()),
            _ => Vec::new(),
        };
        if endpoints.is_empty() {
            return Attempt::Retry("target is not a gateway with an address right now".into());
        }
        let Ok(card) = KeyCard::parse(&item.card) else { return Attempt::Refused("bad stored card".into()) };
        let body = json!({"envelope": Self::envelope_hash(&item.envelope), "card": card.to_value()});
        let Ok(request) = self.signed(&target, "relay", body) else { return Attempt::Retry("cannot sign".into()) };
        // Canonical order of the two keys: "envelope" < "rq". Both parts are canonical JSON already.
        let mut wire = br#"{"envelope":"#.to_vec();
        wire.extend_from_slice(&item.envelope);
        wire.extend_from_slice(br#","rq":"#);
        wire.extend_from_slice(&request);
        wire.push(b'}');
        let mut last = Attempt::Retry("no address".into());
        // LAN endpoints first (pinned to the target's card), then its public addresses.
        for endpoint in endpoints.iter().take(8) {
            match self.peer_post(endpoint, "/v4/node/relay", wire.clone()).await {
                Ok(answer) if answer.status == 200 || answer.code() == "REPLAY" => return Attempt::Done,
                Ok(answer) if answer.status == 429 || answer.status >= 500 => {
                    return Attempt::Retry(format!("{} {}", answer.status, answer.code()));
                }
                // Refusals like NOT_MEMBER, FORBIDDEN or UNKNOWN_IDENTITY may only mean that the target's log is a
                // round behind: retried a bounded number of times.
                Ok(answer) if !FINAL_REFUSALS.contains(&answer.code()) && item.attempts < MAX_REFUSED_ATTEMPTS => {
                    return Attempt::Retry(format!("{} {}", answer.status, answer.code()));
                }
                Ok(answer) => return Attempt::Refused(format!("{} {}", answer.status, answer.code())),
                Err(error) => last = Attempt::Retry(error),
            }
        }
        last
    }

    /// `POST /v4/node/relay` (receiving gateway).
    pub(crate) async fn relay_in(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        if body.len() > MAX_RELAY_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "relay request too large"));
        }
        let Value::Object(outer) = parse_strict(body, MAX_RELAY_BYTES)? else {
            return Err(NodeError::bad_format("relay: not an object"));
        };
        if outer.len() != 2 {
            return Err(NodeError::bad_format("relay: exactly envelope and rq"));
        }
        let rq = outer.get("rq").cloned().ok_or_else(|| NodeError::bad_format("relay: rq missing"))?;
        if canonical(&rq)?.len() > MAX_REQUEST_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "request too large"));
        }
        let request = SignedRequest::from_value(rq)?;
        request.check(&me, now)?;
        if request.op() != "relay" {
            return Err(NodeError::bad_format("op: expected relay"));
        }
        let caller = self
            .with_core(|core| core.gateway_card(request.iss(), now))?
            .ok_or_else(|| NodeError::forbidden("only gateways of the network relay"))?;
        request.verify(&caller)?;
        self.inner.guard.remember_nonce(
            request.iss(),
            request.nonce(),
            request.iat().saturating_add(CLOCK_SKEW_MS),
            now,
        )?;

        let envelope_value = outer.get("envelope").cloned().ok_or_else(|| NodeError::bad_format("relay: envelope"))?;
        let bytes = canonical(&envelope_value)?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "envelope too large"));
        }
        let envelope = Envelope::from_value(envelope_value)?;
        if request.body().get("envelope").and_then(Value::as_str) != Some(Self::envelope_hash(&bytes).as_str()) {
            return Err(NodeError::bad_format("relay: envelope hash does not match"));
        }
        envelope.check_time(now)?;
        if envelope.net() != &self.inner.net {
            return Err(NodeError::forbidden("wrong network"));
        }
        let sender = KeyCard::from_value(request.body().get("card").cloned().unwrap_or(Value::Null))?;
        if sender.id() != envelope.from() {
            return Err(NodeError::new(401, "BAD_SIGNATURE", "card is not the sender's"));
        }
        let unknown = || NodeError::new(404, "UNKNOWN_IDENTITY", "recipient does not live here");
        self.with_core(|core| -> NodeResult<()> {
            core.state.check_login(envelope.from(), now)?;
            if core.state.level(envelope.to(), now).is_none() {
                return Err(unknown());
            }
            Ok(())
        })??;
        let (net, member) = (self.inner.net.to_string(), envelope.to().to_string());
        let home = self.blocking(move |store| store.home_get(&net, &member, now)).await?;
        if home.is_none_or(|home| home.node != me.as_str()) {
            return Err(unknown());
        }
        self.inner.guard.admit_send(envelope.from(), now)?;
        envelope.verify(&sender)?;
        let (id, card, max_cards) =
            (sender.id().to_string(), sender.to_bytes()?, self.inner.guard.limits().max_identities);
        // The recipient's poll answer carries the sender's card from this table.
        if !self.blocking(move |store| store.put_card(&id, &card, now, max_cards)).await? {
            return Err(NodeError { retry_after: Some(3600), ..NodeError::new(429, "QUOTA_EXCEEDED", "node is full") });
        }
        self.deliver_local(&envelope, now).await?;
        Ok(br#"{"ok":true}"#.to_vec())
    }
}
