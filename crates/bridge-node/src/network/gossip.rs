//! Gossip and evidence (docs/06 §5 "Split-View und Absetzen"): nodes ask each other for their heads and compare
//! them with every head of the same operator they keep. Two heads that cannot both be true are evidence; whoever
//! holds verified evidence deposes the operator locally at once (refuses its heads, stops cosigning them, and - if
//! it is the operator itself - stops operating, fail closed), stores the evidence, raises the alarm and passes the
//! evidence on. Evidence from others is never taken blindly: it is verified like a self-found one.

use bridge_core::json::canonical;
use bridge_net::{Evidence, WitnessedHead, verify_head};
use bridge_store::MAX_EVIDENCE_PER_NET;
use serde_json::Value;

use crate::{Node, NodeError, NodeResult};

/// Peers asked per gossip round.
const PEERS_PER_ROUND: usize = 8;
/// Peers evidence is pushed to.
const PUSH_PEERS: usize = 16;

impl Node {
    /// One gossip round: heads and evidence of up to 8 peers.
    pub(crate) async fn gossip_round(&self) {
        if self.with_core(|_| ()).is_err() {
            return;
        }
        let peers = self.pick_peers(self.peer_candidates(), PEERS_PER_ROUND);
        for peer in peers {
            if let Ok(answer) = self.peer_get_any(&peer, &self.net_path("head")).await.and_then(super::peer::Answer::ok)
            {
                if let Ok(witnessed) = WitnessedHead::from_value(&Value::Object(answer)) {
                    self.compare_head(&witnessed.head).await;
                }
            }
            if let Ok(answer) =
                self.peer_get_any(&peer, &self.net_path("evidence")).await.and_then(super::peer::Answer::ok)
            {
                let list = answer.get("evidence").and_then(Value::as_array).cloned().unwrap_or_default();
                for item in list.iter().take(MAX_EVIDENCE_PER_NET) {
                    if let Ok(evidence) = Evidence::from_value(item) {
                        // Invalid or known evidence is simply not taken.
                        let _ = self.record_evidence(evidence, true).await;
                    }
                }
            }
        }
    }

    /// Compares a head seen at a peer with the heads this node keeps.
    pub(crate) async fn compare_head(&self, head: &bridge_core::Statement) {
        let net = match self.network() {
            Some(network) => network.net.clone(),
            None => return,
        };
        let found = self.with_core(|core| {
            let operator = match head.claimed_signers().as_slice() {
                [operator] if core.state.log_operators().contains(operator) => (*operator).clone(),
                _ => return None,
            };
            let card = core.state.card_of(&operator)?;
            verify_head(head, &net, card).ok()?;
            core.find_evidence(&operator, head, None)
        });
        if let Ok(Some(evidence)) = found {
            let _ = self.record_evidence(evidence, true).await;
        }
    }

    /// Takes evidence (self-found or reported): verifies it, deposes the operator, stores it, raises the alarm and
    /// - with `push` - passes it on. Returns whether it was new.
    pub(crate) async fn record_evidence(&self, evidence: Evidence, push: bool) -> NodeResult<bool> {
        let network = self.network().ok_or_else(NodeError::not_found)?;
        let operator = evidence.operator().cloned().ok_or_else(|| NodeError::bad_format("evidence: no operator"))?;
        let checks = self.with_core(|core| -> NodeResult<Option<(bridge_core::KeyCard, bridge_net::Tree)>> {
            if evidence.net() != &network.net {
                return Err(NodeError::bad_format("evidence: other network"));
            }
            // Only against log operators of the manifest - nobody else's heads count, and nobody can fill the
            // evidence table with "evidence" against their own key.
            if !core.state.log_operators().contains(&operator) {
                return Err(NodeError::forbidden("evidence: not against a log operator"));
            }
            if core.evidence.contains_key(&operator) {
                return Ok(None);
            }
            let card =
                core.state.card_of(&operator).ok_or_else(|| NodeError::forbidden("evidence: unknown operator"))?;
            // A snapshot of the tree is cheap (shared chunks); the signatures are checked outside the lock.
            Ok(Some((card.clone(), core.log.tree().clone())))
        })??;
        let Some((card, tree)) = checks else { return Ok(false) };
        // Only heads up to the own log size can be checked against it (cheaply: O(log n) per root).
        if !evidence.verify(&card, Some(&tree)) {
            return Err(NodeError::forbidden("evidence does not hold"));
        }
        let bytes = canonical(&evidence.to_value())?;
        let (net, key, now) = (network.net.to_string(), operator.to_string(), self.now());
        let stored = bytes.clone();
        self.blocking(move |store| store.net_evidence_put(&net, &key, &stored, now)).await?;
        let new = self.with_core(|core| core.evidence.insert(operator.clone(), evidence).is_none())?;
        if new {
            // The alarm (docs/06 §5): log now; the owner dashboard shows /v4/net/{net}/evidence.
            tracing::error!(%operator, net = %network.net, "ALARM: log operator showed two different logs - deposed here");
            if push {
                let node = self.clone();
                tokio::spawn(async move { node.push_evidence(bytes).await });
            }
        }
        Ok(new)
    }

    async fn push_evidence(&self, bytes: Vec<u8>) {
        let path = self.net_path("evidence");
        for peer in self.distinct(self.peer_candidates(), PUSH_PEERS) {
            if let Err(error) = self.peer_post_any(&peer, &path, bytes.clone()).await {
                tracing::debug!(%error, "evidence push");
            }
        }
    }
}
