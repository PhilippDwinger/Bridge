//! The HTTP endpoints of BridgeNet (docs/06 §9). Cheap checks first, bounded bodies and answers, signed requests
//! for everything that changes something, the error codes of docs/04 §9. Read endpoints take their parameters as a
//! small JSON body (`POST`), because the transport hands the node no query string. The unauthenticated proof,
//! evidence and transition-head endpoints have a tighter limit per address; proofs never compute under the lock of
//! the network core: they work on a cheap snapshot of the Merkle tree (O(log n) per proof).

use bridge_core::encoding::b64;
use bridge_core::json::canonical;
use bridge_core::{Id, KeyCard, SignedRequest, Statement};
use bridge_net::{Evidence, WitnessedHead};
use bridge_transport::{Method, Request};
use serde_json::{Value, json};

use crate::{Node, NodeError, NodeResult, body_object, optional_u64};

/// Largest body of the small read requests (`log`, `proof`, `consistency`).
const MAX_QUERY_BYTES: usize = 1024;

impl Node {
    /// Routes `/v4/net/...` and `/v4/node/...`. A node without a network knows none of them.
    pub(crate) async fn route_network(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let network = self.network().ok_or_else(NodeError::not_found)?;
        match (request.method, request.path.as_str()) {
            (Method::Post, "/v4/net/join") => return self.join(&request.body, now).await,
            (Method::Post, "/v4/node/relay") => return self.relay_in(&request.body, now).await,
            (Method::Post, "/v4/node/homes") => return self.homes_out(&request.body, now).await,
            (Method::Post, "/v4/node/app") => return self.app_offer_in(&request.body, now).await,
            (Method::Post, "/v4/node/watch") => return self.watch_in(&request.body, request.peer, now).await,
            _ => {}
        }
        let rest = request.path.strip_prefix("/v4/net/").ok_or_else(NodeError::not_found)?;
        let (net, action) = rest.split_once('/').ok_or_else(NodeError::not_found)?;
        if net != network.net.as_str() {
            return Err(NodeError::not_found());
        }
        if matches!(action, "proof" | "consistency" | "evidence" | "head/at") {
            self.inner.guard.admit_proof(request.peer, now)?;
        }
        match (request.method, action) {
            (Method::Get, "head") => self.serve_head(),
            (Method::Get, "head/latest") => self.serve_latest_head(),
            (Method::Post, "head/at") => self.serve_transition(&request.body),
            (Method::Get, "manifest") => self.serve_manifest(),
            (Method::Get, "evidence") => self.serve_evidence(),
            (Method::Post, "log") => self.serve_log(&request.body),
            (Method::Post, "proof") => self.serve_proof(&request.body),
            (Method::Post, "consistency") => self.serve_consistency(&request.body),
            (Method::Post, "submit") => self.submit(&request.body, now).await,
            (Method::Post, "cosign") => self.cosign_in(&request.body).await,
            (Method::Post, "evidence") => self.evidence_in(&request.body).await,
            _ => Err(NodeError::not_found()),
        }
    }

    /// `GET /v4/net/{net}/head`: the newest witnessed head this node holds the log for.
    fn serve_head(&self) -> NodeResult<Vec<u8>> {
        let value = self.with_core(|core| core.best_witnessed().map(|witnessed| witnessed.value.to_value()))?;
        Ok(canonical(&value.ok_or_else(NodeError::not_found)?)?)
    }

    /// `GET /v4/net/{net}/head/latest`: the operator's newest head, witnessed or not (for witnesses) - only while
    /// this node is the operator for that head's size.
    fn serve_latest_head(&self) -> NodeResult<Vec<u8>> {
        let value = self.with_core(|core| {
            let issued = core.issued.back()?;
            if core.operator_for_head(issued.head.size()).as_ref() != Some(&core.me) {
                return None;
            }
            Some(WitnessedHead { head: issued.statement.clone(), cosigns: issued.cosigns.clone() }.to_value())
        })?;
        Ok(canonical(&value.ok_or_else(NodeError::not_found)?)?)
    }

    /// `POST /v4/net/{net}/head/at` `{"size":n}`: the transition head of that size this node keeps (the witnessed
    /// head that ends with a change of the log rules, docs/06 §5) - `NOT_FOUND` if it keeps none.
    fn serve_transition(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let query = body_object(body, MAX_QUERY_BYTES)?;
        let size = optional_u64(&query, "size", 0, bridge_net::merkle::MAX_TREE_SIZE)?;
        let value = self.with_core(|core| core.transitions.get(&size).map(WitnessedHead::to_value))?;
        Ok(canonical(&value.ok_or_else(NodeError::not_found)?)?)
    }

    /// `GET /v4/net/{net}/manifest`: the statement of the current manifest and its log index.
    fn serve_manifest(&self) -> NodeResult<Vec<u8>> {
        let (index, entry) =
            self.with_core(|core| (core.manifest_index, core.log.entry(core.manifest_index).map(<[u8]>::to_vec)))?;
        let statement = Statement::parse(&entry.ok_or_else(NodeError::not_found)?)?;
        Ok(json!({"manifest": statement.to_value(), "index": index}).to_string().into_bytes())
    }

    /// `POST /v4/net/{net}/log` `{"from":i,"max":n}`: entries as Base64url (exact bytes, garbage included).
    fn serve_log(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let query = body_object(body, MAX_QUERY_BYTES)?;
        let from = optional_u64(&query, "from", 0, bridge_net::merkle::MAX_TREE_SIZE)?;
        let max = optional_u64(&query, "max", 256, 256)?.max(1);
        let (entries, size) = self.with_core(|core| {
            let page: Vec<String> =
                core.log.page(from, usize::try_from(max).unwrap_or(256)).into_iter().map(b64).collect();
            (page, core.log.size())
        })?;
        Ok(json!({"entries": entries, "size": size}).to_string().into_bytes())
    }

    /// `POST /v4/net/{net}/proof` `{"index":i,"size":n}`: inclusion proof of entry `i` in the tree of size `n`.
    fn serve_proof(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let query = body_object(body, MAX_QUERY_BYTES)?;
        let index = optional_u64(&query, "index", 0, bridge_net::merkle::MAX_TREE_SIZE)?;
        let size = optional_u64(&query, "size", 0, bridge_net::merkle::MAX_TREE_SIZE)?;
        if index >= size {
            return Err(NodeError::bad_format("index must be below size"));
        }
        let tree = self.tree_up_to(size)?;
        let proof = tree.inclusion(index, size).map_err(|_| NodeError::not_found())?;
        let proof: Vec<String> = proof.iter().map(|hash| b64(hash)).collect();
        Ok(json!({"index": index, "size": size, "proof": proof}).to_string().into_bytes())
    }

    /// `POST /v4/net/{net}/consistency` `{"from":m,"to":n}`: consistency proof between the trees of sizes m and n.
    fn serve_consistency(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let query = body_object(body, MAX_QUERY_BYTES)?;
        let from = optional_u64(&query, "from", 0, bridge_net::merkle::MAX_TREE_SIZE)?;
        let to = optional_u64(&query, "to", 0, bridge_net::merkle::MAX_TREE_SIZE)?;
        if from > to {
            return Err(NodeError::bad_format("from must not be above to"));
        }
        let tree = self.tree_up_to(to)?;
        let proof = tree.consistency(from, to).map_err(|_| NodeError::not_found())?;
        let proof: Vec<String> = proof.iter().map(|hash| b64(hash)).collect();
        Ok(json!({"from": from, "to": to, "proof": proof}).to_string().into_bytes())
    }

    /// A snapshot of the Merkle tree (cheap: shared chunks) if the log has at least `size` entries - proofs are
    /// only served for sizes up to the own log size, and computed outside the lock.
    fn tree_up_to(&self, size: u64) -> NodeResult<bridge_net::Tree> {
        self.with_core(|core| (size <= core.log.size()).then(|| core.log.tree().clone()))?
            .ok_or_else(NodeError::not_found)
    }

    /// `POST /v4/net/{net}/submit`: `rq` with `op:"submit"`, `body:{"statement":…}` from the network key, an admin
    /// or a gateway - at the active log operator. A gateway that is not the operator hands statements of the
    /// network key and admins on to it, once (requests of gateways are never handed on: no loops).
    async fn submit(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        let (operator, gateway) = self.with_core(|core| {
            (core.is_active_operator(), core.active_operator().is_some() && core.is_gateway(&me, now))
        })?;
        if !operator && !gateway {
            return Err(NodeError::forbidden("this node is not the log operator of the network"));
        }
        let request = SignedRequest::parse(body)?;
        request.check(&me, now)?;
        if request.op() != "submit" {
            return Err(NodeError::bad_format("op: expected submit"));
        }
        let caller = self.submitter_card(request.iss(), now)?;
        request.verify(&caller)?;
        self.inner.guard.remember_nonce(
            request.iss(),
            request.nonce(),
            request.iat().saturating_add(bridge_core::CLOCK_SKEW_MS),
            now,
        )?;
        self.inner.guard.admit_send(request.iss(), now)?;
        let statement = Statement::from_value(request.body().get("statement").cloned().unwrap_or(Value::Null))?;
        if statement.net() != &self.inner.net {
            return Err(NodeError::bad_format("statement: other network"));
        }
        if !operator {
            let by_admin = self.with_core(|core| !core.state.admin_rights(request.iss(), now).is_empty())?;
            if !by_admin {
                return Err(NodeError::forbidden("this node is not the log operator of the network"));
            }
            let appended = self.submit_to_operator(&statement).await?;
            return Ok(json!({"index": appended.index, "size": appended.size, "hash": statement.hash()})
                .to_string()
                .into_bytes());
        }
        let appended = self.operator_append(&statement).await?;
        Ok(json!({"index": appended.index, "size": appended.size, "hash": statement.hash()}).to_string().into_bytes())
    }

    /// Who may submit: the network key, an admin with any right, a gateway, a watcher (docs/06 §9, §11.6).
    fn submitter_card(&self, id: &Id, now: i64) -> NodeResult<KeyCard> {
        self.with_core(|core| {
            // The network key has all rights; an admin has at least one.
            if !core.state.admin_rights(id, now).is_empty() || core.state.is_watcher(id, now) {
                return core.state.card_of(id).cloned();
            }
            core.gateway_card(id, now)
        })?
        .ok_or_else(|| NodeError::forbidden("only the network key, admins, gateways and watchers submit"))
    }

    /// `POST /v4/net/{net}/cosign`: a witness's `cosign` statement (self-signed; repeating it changes nothing) - at
    /// a node that is the operator for one of the heads it issued (the size decides, docs/06 §5).
    async fn cosign_in(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let operating = self.with_core(|core| {
            core.issued.iter().any(|issued| core.operator_for_head(issued.head.size()).as_ref() == Some(&core.me))
        })?;
        if !operating {
            return Err(NodeError::forbidden("this node is not the log operator of the network"));
        }
        let cosign = Statement::parse(body)?;
        let witnessed = self.accept_cosign(&cosign).await?;
        Ok(json!({"ok": true, "witnessed": witnessed}).to_string().into_bytes())
    }

    /// `GET /v4/net/{net}/evidence`: all evidence this node holds (at most 16).
    fn serve_evidence(&self) -> NodeResult<Vec<u8>> {
        let list = self.with_core(|core| core.evidence.values().map(Evidence::to_value).collect::<Vec<_>>())?;
        Ok(json!({"evidence": list}).to_string().into_bytes())
    }

    /// `POST /v4/net/{net}/evidence`: reported evidence - verified like self-found evidence, never taken blindly.
    async fn evidence_in(&self, body: &[u8]) -> NodeResult<Vec<u8>> {
        let evidence = Evidence::parse(body)?;
        let new = self.record_evidence(evidence, true).await?;
        Ok(json!({"ok": true, "new": new}).to_string().into_bytes())
    }
}
