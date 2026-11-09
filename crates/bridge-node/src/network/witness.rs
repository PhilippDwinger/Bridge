//! The witness (docs/06 §5): fetches each log operator's newest head, checks it against every head of that operator
//! it keeps (split view → evidence), checks that the new entries extend its log to exactly the head's root, are
//! consistent with the last head it cosigned (of any operator - consistency is about the log) and are not dated
//! into the future, and only then cosigns. A witness never cosigns a head smaller than its last one, and only heads
//! for whose size it is a witness of the log rules (the rules after the head's first n − 1 entries).

use bridge_core::{Id, KeyCard, Statement};
use bridge_net::{Ahead, Head, RulesAhead, WitnessedHead, check_new_entries, issue_cosign, verify_head};
use serde_json::Value;

use super::head_row;
use super::peer::Endpoint;
use crate::Node;

/// What to do with an operator's head.
enum Plan {
    /// Already cosigned, or older than the last cosigned head.
    Done,
    /// The head contradicts a head this witness keeps.
    Evidence(bridge_net::Evidence),
    /// All entries are here: check them and cosign.
    Cosign { head: Head, entries: Vec<Vec<u8>> },
    /// Entries `[start, head.size)` are missing; `known` are the own entries to check as well, `tree` a snapshot
    /// of the own tree, `last` the last cosigned head, `master` and `version` the net key's card and the manifest
    /// version (for [`Ahead::parse`]).
    Fetch {
        head: Head,
        start: u64,
        tree: bridge_net::Tree,
        known: Vec<Vec<u8>>,
        last: Option<Head>,
        master: KeyCard,
        version: u64,
    },
}

impl Node {
    /// One round of the witness duty: every operator of the log rules this node may witness under (for a head of
    /// the own log size, and for the next one), unless deposed.
    pub(crate) async fn witness_round(&self) {
        let me = self.inner.identity.id().clone();
        let operators = self
            .with_core(|core| {
                let size = core.log.size();
                let mut operators: Vec<Id> = Vec::new();
                for rules in [core.state.rules_for_head(size), core.state.rules_for_head(size.saturating_add(1))]
                    .into_iter()
                    .flatten()
                {
                    if rules.witnesses.contains(&me) {
                        for operator in rules.logs {
                            if !core.evidence.contains_key(&operator) && !operators.contains(&operator) {
                                operators.push(operator);
                            }
                        }
                    }
                }
                operators
            })
            .unwrap_or_default();
        for operator in operators {
            if let Err(error) = self.witness_one(&operator).await {
                tracing::debug!(%operator, %error, "witness");
            }
        }
    }

    /// The newest head of `operator` (its own issued head when this node is the operator), and where it came from
    /// (the cosignature goes back there).
    async fn latest_head_of(&self, operator: &Id) -> Result<(Statement, Option<Endpoint>), String> {
        if operator == self.inner.identity.id() {
            let latest = self.with_core(|core| core.issued.back().map(|issued| issued.statement.clone()));
            return latest.map_err(|e| e.message)?.map(|head| (head, None)).ok_or_else(|| "no head yet".into());
        }
        let mut last = String::from("operator has no address");
        for endpoint in self.reach(operator).iter().take(8) {
            match self.peer_get(endpoint, &self.net_path("head/latest")).await.and_then(super::peer::Answer::ok) {
                Ok(answer) => {
                    let value = WitnessedHead::from_value(&Value::Object(answer)).map_err(|e| e.to_string())?;
                    return Ok((value.head, Some(endpoint.clone())));
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    async fn witness_one(&self, operator: &Id) -> Result<(), String> {
        let (statement, source) = self.latest_head_of(operator).await?;
        let now = self.now();
        let me = self.inner.identity.id().clone();
        let net = self.network().ok_or("no network")?.net.clone();
        let plan = self
            .with_core(|core| -> Result<Plan, String> {
                let card = core.state.card_of(operator).cloned().ok_or("no card of the operator")?;
                let head = verify_head(&statement, &net, &card).map_err(|e| e.to_string())?;
                statement.check_time(now).map_err(|e| e.to_string())?;
                if let Some(evidence) = core.find_evidence(operator, &statement, None) {
                    return Ok(Plan::Evidence(evidence));
                }
                if core.cosigned.get(operator).is_some_and(|(last, _)| last.hash() == head.hash()) {
                    return Ok(Plan::Done);
                }
                let last = core.last_cosigned().cloned();
                if last.as_ref().is_some_and(|last| last.size() > head.size()) {
                    return Ok(Plan::Done); // never back
                }
                let from = last.as_ref().map_or(0, Head::size);
                let size = core.log.size();
                let range = |to: u64| -> Vec<Vec<u8>> {
                    let (from, to) = (usize::try_from(from).unwrap_or(usize::MAX), usize::try_from(to).unwrap_or(0));
                    core.log.entries().get(from.min(to)..to).map(<[Vec<u8>]>::to_vec).unwrap_or_default()
                };
                if head.size() <= size {
                    let rules = core.state.rules_for_head(head.size()).ok_or("no log rules for the head")?;
                    if !rules.witnesses.contains(&me) || !rules.logs.contains(operator) {
                        return Ok(Plan::Done); // not this witness's head (docs/06 §5)
                    }
                    if !core.log.matches(&head) {
                        return Err("head does not match the own log".into());
                    }
                    if let Some(last) = &last {
                        if core.log.tree().root_at(last.size()).ok().as_ref() != Some(last.root()) {
                            return Err("own log does not match the last cosigned head".into());
                        }
                    }
                    let entries = range(head.size());
                    return Ok(Plan::Cosign { head, entries });
                }
                let (master, version) = (core.state.manifest().card.clone(), core.state.manifest().version);
                let tree = core.log.tree().clone();
                Ok(Plan::Fetch { known: range(size), head, start: size, tree, last, master, version })
            })
            .map_err(|e| e.message)??;
        let (head, entries) = match plan {
            Plan::Done => return Ok(()),
            Plan::Evidence(evidence) => {
                self.record_evidence(evidence, true).await.map_err(|e| e.message)?;
                return Err("split view".into());
            }
            Plan::Cosign { head, entries } => (head, entries),
            Plan::Fetch { head, start, mut tree, mut known, last, master, version } => {
                let from = source.as_ref().ok_or("no address")?;
                let fetched = self.fetch_entries(from, start, head.size()).await?;
                for entry in &fetched {
                    tree.push_entry(entry).map_err(|e| e.to_string())?;
                }
                let evidence = self
                    .with_core(|core| core.find_evidence(operator, &statement, Some(&tree)))
                    .map_err(|e| e.message)?;
                if let Some(evidence) = evidence {
                    self.record_evidence(evidence, true).await.map_err(|e| e.message)?;
                    return Err("split view".into());
                }
                if tree.size() != head.size() || &tree.root() != head.root() {
                    return Err("entries do not give the head's root".into());
                }
                if let Some(last) = &last {
                    if tree.root_at(last.size()).ok().as_ref() != Some(last.root()) {
                        return Err("head is not consistent with the last cosigned head".into());
                    }
                }
                // The role for this head: only known without replaying if no signed change of the rules comes first.
                let ahead = Ahead::parse(&master, version, &fetched);
                let rules = self
                    .with_core(|core| {
                        if core.log.size() != start {
                            return Err("log changed in the meantime".to_owned());
                        }
                        match core.state.rules_ahead(&ahead) {
                            RulesAhead::Known(rules) => Ok(rules),
                            RulesAhead::Replay => Err("the log rules change before this head: sync first".into()),
                            RulesAhead::Refuse => Err("too much to check ahead of this head".into()),
                        }
                    })
                    .map_err(|e| e.message)??;
                if !rules.witnesses.contains(&me) || !rules.logs.contains(operator) {
                    return Ok(()); // not this witness's head
                }
                known.extend(fetched);
                (head, known)
            }
        };
        check_new_entries(&entries, &head).map_err(|e| format!("new entries: {e}"))?;
        let cosign = issue_cosign(&self.inner.identity, &head, now).map_err(|e| e.to_string())?;
        if operator == self.inner.identity.id() {
            self.accept_cosign(&cosign).await.map_err(|e| e.message)?;
        } else {
            let source = source.ok_or("no address")?;
            self.peer_post(&source, &self.net_path("cosign"), cosign.canonical_bytes().to_vec()).await?.ok()?;
        }
        let row = self
            .with_core(|core| {
                let row = head_row(operator, "cosigned", head.size(), &statement, &[]);
                if !core.cosigned.contains_key(operator) && core.cosigned.len() >= super::MAX_TRACKED_OPERATORS {
                    // Operators of old manifests are forgotten first (bounded map).
                    let current = core.state.log_operators().to_vec();
                    core.cosigned.retain(|id, _| current.contains(id));
                }
                core.cosigned.insert(operator.clone(), (head, statement));
                row
            })
            .map_err(|e| e.message)?;
        self.store_head(row).await;
        Ok(())
    }
}
