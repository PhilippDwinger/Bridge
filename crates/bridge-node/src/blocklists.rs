//! Blocklists at a node (docs/08 §9): the newest valid list of every publisher the manifest names, applied when names
//! resolve, searches answer and apps are served (a listed name, app, node or member counts as banned - `404`, no
//! difference to "unknown"). Lists come in through `POST /v4/names/blocklist/update` (anybody: the publisher's
//! signature is the proof, like `/v4/app/update`) and spread by themselves: every node asks up to
//! [`PEERS_PER_ROUND`] peers for each named publisher's list once a round (`NetTiming::blocklists`). Kept in the
//! store, loaded again at the start.

use std::sync::Arc;

use bridge_core::Id;
use bridge_core::json::canonical;
use bridge_net::{Blocklist, Blocklists};
use bridge_transport::{Method, Request};
use serde_json::{Value, json};

use crate::{Node, NodeError, NodeResult, body_object, lock};

/// Peers asked per publisher and round.
const PEERS_PER_ROUND: usize = 3;
/// Largest query body.
const MAX_QUERY_BYTES: usize = 256;

impl Node {
    /// The lists that apply now (a snapshot: cheap to clone, never held across a lock).
    pub(crate) fn blocklists(&self) -> Arc<Blocklists> {
        self.network().map_or_else(|| Arc::new(Blocklists::default()), |network| Arc::clone(&lock(&network.blocklists)))
    }

    /// Whether an app or its owner is on a list that applies at `now`.
    pub(crate) fn app_blocked(&self, app: &Id, owner: &Id, now: i64) -> bool {
        self.blocklists().blocks_app(app, owner, now)
    }

    /// Routes `/v4/names/blocklist[/update]`.
    pub(crate) async fn route_blocklists(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        match (request.method, request.path.as_str()) {
            (Method::Post, "/v4/names/blocklist") => self.blocklist_get(&request.body),
            (Method::Post, "/v4/names/blocklist/update") => self.blocklist_update(&request.body, now).await,
            _ => Err(NodeError::not_found()),
        }
    }

    /// `POST /v4/names/blocklist` `{"publisher","after"?}`: the list this node holds for a publisher (`404` if none);
    /// with `after`, only if its version is higher (else `{"statement":null,"version"}` - nothing to send).
    fn blocklist_get(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let body = body_object(body, MAX_QUERY_BYTES)?;
        let publisher = Id::parse(body.get("publisher").and_then(Value::as_str).unwrap_or_default())?;
        let after = crate::optional_u64(&body, "after", 0, u64::MAX)?;
        let lists = self.blocklists();
        let statement = lists.statement(&publisher).ok_or_else(NodeError::not_found)?;
        let version = lists.version(&publisher).unwrap_or(0);
        if version <= after {
            return Ok(json!({"statement": null, "version": version}).to_string().into_bytes());
        }
        let value: Value = serde_json::from_slice(statement.canonical_bytes()).map_err(|_| NodeError::unavailable())?;
        Ok(json!({"statement": value}).to_string().into_bytes())
    }

    /// `POST /v4/names/blocklist/update` (a `blocklist` statement): taken if valid, named by the manifest and newer.
    async fn blocklist_update(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let statement = Blocklist::parse_statement(body)?;
        let taken = self.offer_blocklist(&statement, now).await?;
        let list = Blocklist::verify(&statement, &self.inner.net, now)?;
        Ok(json!({"taken": taken, "version": self.blocklists().version(&list.publisher)}).to_string().into_bytes())
    }

    /// Verifies a list against the network and keeps it if it is newer (memory and store). Returns whether it was
    /// taken.
    pub(crate) async fn offer_blocklist(&self, statement: &bridge_core::Statement, now: i64) -> NodeResult<bool> {
        let network = self.network().ok_or_else(NodeError::not_found)?;
        let state = self.with_core(|core| Arc::clone(&core.state))?;
        // Verified once, outside every lock (up to 10,000 entries); only the swap happens under it.
        let list = Blocklist::verify(statement, &network.net, now)?;
        if !state.manifest().blocklists.as_ref().is_some_and(|named| named.contains(&list.publisher)) {
            return Err(NodeError::forbidden("blocklist: the manifest does not name this publisher"));
        }
        let version = list.version;
        if self.blocklists().version(&list.publisher).is_some_and(|held| held >= version) {
            return Ok(false);
        }
        let (net, publisher, bytes) =
            (network.net.to_string(), list.publisher.to_string(), statement.canonical_bytes().to_vec());
        let stored = self.blocking(move |store| store.blocklist_put(&net, &publisher, version, &bytes, now)).await?;
        if !stored {
            tracing::warn!(publisher = %list.publisher, "blocklist not stored (table full?) - kept in memory");
        }
        let mut held = lock(&network.blocklists);
        // Another offer may have won meanwhile: only a newer version replaces.
        if held.version(&list.publisher).is_some_and(|held| held >= version) {
            return Ok(false);
        }
        let publisher = list.publisher.clone();
        let mut merged = (**held).clone();
        merged.insert_checked(list, statement.clone());
        *held = Arc::new(merged);
        tracing::info!(%publisher, version, "blocklist taken");
        Ok(true)
    }

    /// One round: forget lists of publishers the manifest no longer names, then ask peers for every named one.
    pub(crate) async fn blocklists_round(&self) {
        let Some(network) = self.network() else { return };
        let Ok(state) = self.with_core(|core| Arc::clone(&core.state)) else { return };
        {
            let mut held = lock(&network.blocklists);
            if !held.is_empty() {
                let mut kept = (**held).clone();
                kept.retain_named(&state);
                *held = Arc::new(kept);
            }
        }
        let named: Vec<Id> = state.manifest().blocklists.clone().unwrap_or_default();
        let keep: Vec<String> = named.iter().map(ToString::to_string).collect();
        let net = network.net.to_string();
        if let Err(error) = self.blocking(move |store| store.blocklists_retain(&net, &keep)).await {
            tracing::debug!(?error, "blocklists retain");
        }
        for publisher in named.iter().take(bridge_net::blocklist::MAX_PUBLISHERS) {
            for peer in self.pick_peers(self.peer_candidates(), PEERS_PER_ROUND) {
                // Only a newer list travels (`after`): an unchanged one costs a few bytes per round.
                let after = self.blocklists().version(publisher).unwrap_or(0);
                let body = json!({"publisher": publisher.as_str(), "after": after}).to_string().into_bytes();
                let Ok(answer) = self.peer_post_any(&peer, "/v4/names/blocklist", body.clone()).await else { continue };
                let Ok(answer) = answer.ok() else { continue };
                let Some(value) = answer.get("statement") else { continue };
                let Ok(bytes) = canonical(value) else { continue };
                let Ok(statement) = Blocklist::parse_statement(&bytes) else { continue };
                let held = self.blocklists().version(publisher);
                let offered = Blocklist::verify(&statement, &network.net, self.now()).map(|list| list.version);
                if offered.is_ok_and(|version| held.is_none_or(|held| version > held)) {
                    if let Err(error) = self.offer_blocklist(&statement, self.now()).await {
                        tracing::debug!(?error, "blocklist from a peer refused");
                    }
                }
            }
        }
    }
}
