//! The log operator (docs/06 §5): accepts statements that are valid under the state of all previous entries,
//! stores them before they count, issues heads (as soon as there are new entries, otherwise every 10 minutes) and
//! collects the witnesses' cosignatures until a head is witnessed. A manifest that changes the log rules gets its
//! own head at once ("transition head", checked against the rules from before the change); no further entry is
//! taken until that head is witnessed - except a rescue manifest of the net key (docs/06 §5, ADR 0012), whose
//! transition head may be cosigned by the net key instead of the witnesses.

use bridge_core::{Id, Statement};
use bridge_net::{Body, Kind, Manifest, WitnessedHead, verify_cosign};

use crate::{Node, NodeError, NodeResult};

/// Where a statement ended up in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Appended {
    pub(crate) index: u64,
    pub(crate) size: u64,
}

impl Node {
    fn head_refresh_ms(&self) -> i64 {
        self.network()
            .map_or(i64::MAX, |network| i64::try_from(network.timing.head_refresh.as_millis()).unwrap_or(i64::MAX))
    }

    /// Appends `statement` as the active log operator: check against the state (rights at replay time and now),
    /// store, then append and replay in memory. After a change of the log rules, the head of exactly that size is
    /// issued right away.
    pub(crate) async fn operator_append(&self, statement: &Statement) -> NodeResult<Appended> {
        let network = self.network().ok_or_else(NodeError::not_found)?;
        let serial = network.append.lock().await;
        let now = self.now();
        let index = self.with_core(|core| -> NodeResult<u64> {
            if !core.is_active_operator() {
                return Err(NodeError::forbidden("this node is not the log operator of the network"));
            }
            if core.transition_pending() && !is_rescue(statement, &core.state) {
                return Err(NodeError {
                    retry_after: Some(2),
                    ..NodeError::new(503, "UNAVAILABLE", "the log rules changed: waiting for the witnesses")
                });
            }
            core.state.validate_candidate(statement, now)?;
            Ok(core.log.size())
        })??;
        let bytes = statement.canonical_bytes().to_vec();
        let (net, stored) = (network.net.to_string(), vec![bytes.clone()]);
        if !self.blocking(move |store| store.net_log_append(&net, index, &stored)).await? {
            return Err(NodeError::unavailable());
        }
        let (identity, card, refresh) = (&self.inner.identity, &self.inner.card, self.head_refresh_ms());
        let (size, row) = self.with_core(|core| -> NodeResult<(u64, Option<bridge_store::HeadRow>)> {
            core.extend(&[bytes]).map_err(|e| {
                tracing::error!(%e, "stored entry could not be appended in memory");
                NodeError::unavailable()
            })?;
            // The transition head: issued now, before anything else can be appended (docs/06 §5).
            let changed = core.state.last_rules_change() == index && index > 0;
            let row = if changed { core.issue_head(identity, card, now, refresh, true) } else { None };
            Ok((core.log.size(), row))
        })??;
        drop(serial);
        network.applied.send_replace(size);
        if row.is_some() {
            tracing::info!(index, "log rules changed: transition head issued");
            self.store_head(row).await;
            network.wake_witness.notify_one();
        }
        network.wake_head.notify_one();
        tracing::info!(index, kind = statement.kind(), "log entry appended");
        Ok(Appended { index, size })
    }

    /// One round of the operator duty: issue a head when there are new entries or the last one is old - for every
    /// size this node is the operator of (docs/06 §5).
    pub(crate) async fn head_round(&self) {
        let Some(network) = self.network() else { return };
        let now = self.now();
        let (identity, card, refresh) = (&self.inner.identity, &self.inner.card, self.head_refresh_ms());
        let row = self.with_core(|core| core.issue_head(identity, card, now, refresh, false));
        if let Ok(Some(row)) = row {
            self.store_head(Some(row)).await;
            network.wake_witness.notify_one();
        }
    }

    /// A witness's cosignature for one of the heads this node issued. It counts for a head only if the witness is
    /// one of the log rules for that head's size, and only while this node is the operator for that size. Once a
    /// head has `witness_threshold` cosignatures, it is the newest witnessed head (if it is newer).
    pub(crate) async fn accept_cosign(&self, cosign: &Statement) -> NodeResult<bool> {
        let network = self.network().ok_or_else(NodeError::not_found)?;
        let now = self.now();
        let net = network.net.clone();
        let noted = self.with_core(|core| -> NodeResult<super::Noted> {
            let witness = match cosign.claimed_signers().as_slice() {
                [witness] => (*witness).clone(),
                _ => return Err(NodeError::forbidden("cosign: exactly one witness signs")),
            };
            // Cheap checks first: a witness of the rules for one of the waiting heads, which this node operates - or
            // the net key for the transition head of its own rescue (never for any other head).
            let me = core.me.clone();
            let by_master = witness == net;
            let candidates: Vec<usize> = core
                .issued
                .iter()
                .enumerate()
                .filter_map(|(position, issued)| {
                    let size = issued.head.size();
                    let rules = core.state.rules_for_head(size)?;
                    let counts =
                        if by_master { core.state.rescue_head(size) } else { rules.witnesses.contains(&witness) };
                    (counts && core.operator_for_head(size).as_ref() == Some(&me)).then_some(position)
                })
                .collect();
            if candidates.is_empty() {
                return Err(NodeError::forbidden("cosign: not from a witness of the log rules for a waiting head"));
            }
            let card = core.state.card_of(&witness).cloned().ok_or_else(|| NodeError::forbidden("cosign: no card"))?;
            cosign.check_time(now)?;
            let position = candidates
                .into_iter()
                .find(|position| {
                    core.issued.get(*position).is_some_and(|issued| verify_cosign(cosign, &issued.head, &card).is_ok())
                })
                .ok_or_else(|| NodeError::new(404, "NOT_FOUND", "cosign: no such head waiting"))?;
            let issued = core.issued.get_mut(position).ok_or_else(NodeError::unavailable)?;
            issued.cosigns.retain(|known| known.claimed_signers().first() != Some(&&witness));
            issued.cosigns.push(cosign.clone());
            let value = WitnessedHead { head: issued.statement.clone(), cosigns: issued.cosigns.clone() };
            let Ok(head) = core.check_witnessed(&value, now) else {
                return Ok(super::Noted::default()); // not enough cosignatures yet
            };
            Ok(core.note_witnessed(head, value))
        })??;
        let witnessed = noted.head.is_some();
        self.store_noted(noted).await;
        if witnessed {
            // A witnessed transition head lets the operator take entries again; followers can catch up.
            network.wake_sync.notify_one();
        }
        Ok(witnessed)
    }
}

/// A rescue manifest (docs/06 §5, ADR 0012): a manifest signed by the net key alone that changes the log rules in
/// force. The operator takes it even while it waits for a transition head (the candidate check decides the rest).
fn is_rescue(statement: &Statement, state: &bridge_net::NetState) -> bool {
    let net: &Id = state.net();
    Kind::parse(statement.kind()) == Some(Kind::Manifest)
        && statement.claimed_signers() == [net]
        && Manifest::from_statement(statement)
            .is_ok_and(|manifest| manifest.log_rules() != state.manifest().log_rules())
}
