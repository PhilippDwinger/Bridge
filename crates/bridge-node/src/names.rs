//! Names at a node (docs/08 §7): resolve and search from the node's own replayed state, the name rules of the
//! network, and submitting names (and the revocation of own names) through a gateway.
//!
//! The read endpoints need no session; they have their own bucket per address (`Limits::names_per_address`) on top
//! of the general one. A search runs on a snapshot of the state in a blocking thread - never on a worker thread, never
//! under the core lock - and at most [`MAX_SEARCHES_AT_ONCE`] run at once on the node (review 9); its work is bounded
//! by `NetState::search`. Everything that does not resolve is `404 NOT_FOUND` - no difference between "unknown" and
//! "banned" (docs/04 §9). App details (`app`, `open`) come from what this node knows about the app (hosted, or in the
//! reader's memory); only for callers that may use the reader does it fetch a version itself - so nobody on the
//! Internet can use a node to send lookups to other nodes.

use std::sync::Arc;

use bridge_core::encoding::b64;
use bridge_core::{Id, Statement};
use bridge_net::{Body, Category, Kind, Manifest, Name, NameKind, NetState, ResolvedName, Revoke, RevokeTarget};
use bridge_transport::{Method, Request};
use serde_json::{Value, json};

use crate::{Node, NodeError, NodeResult, body_object, optional_u64};

/// Largest body of the read endpoints.
const MAX_QUERY_BYTES: usize = 1024;
/// Largest name input (`name.short`).
const MAX_NAME_INPUT: usize = 80;
/// Default number of search results.
const DEFAULT_RESULTS: u64 = 20;
/// Most name searches that run at once on a node, all callers together (review 9) - on top of the bucket per address.
/// More: `429 RATE_LIMITED` at once (no queue).
pub const MAX_SEARCHES_AT_ONCE: usize = 2;

/// The address of a name in this network: `name.short` (or the bare name without `short`).
fn address(manifest: &Manifest, name: &str) -> String {
    match &manifest.short {
        Some(short) => format!("{name}.{short}"),
        None => name.to_owned(),
    }
}

/// A resolved name as JSON (docs/08 §7), without `app` and `open` (`null`).
fn name_value(state: &NetState, manifest: &Manifest, resolved: &ResolvedName) -> Value {
    let body = &resolved.info.name;
    let mut warnings: Vec<&str> = Vec::new();
    if resolved.owner_level < 2 {
        warnings.push("owner_level_low");
    }
    if manifest.contact.is_none() {
        warnings.push("no_contact");
    }
    if resolved.category == Category::Adult {
        warnings.push("adult");
    }
    if resolved.category != body.category {
        warnings.push("label_override");
    }
    // A node's card from its seal is checked by the network; without a seal only the node's own card from the name
    // is there - its addresses are the node's word alone (review 9: `card_verified: false`, warning).
    let (card, card_verified) = match body.kind {
        NameKind::App => (Value::Null, Value::Null),
        NameKind::Node => match state.card_of(&body.target) {
            Some(card) => (card.to_value(), json!(true)),
            None => {
                warnings.push("card_unverified");
                (body.owner_card.to_value(), json!(false))
            }
        },
        NameKind::Member => (body.owner_card.to_value(), json!(false)),
    };
    let label = |category: Option<Category>| category.map_or(Value::Null, |category| json!(category.as_str()));
    json!({
        "name": body.name,
        "address": address(manifest, &body.name),
        "net": state.net().as_str(),
        "kind": body.kind.as_str(),
        "target": body.target.as_str(),
        "owner": body.owner.as_str(),
        "description": body.description,
        "tags": body.tags,
        "category": resolved.category.as_str(),
        "declared": body.category.as_str(),
        "expires": resolved.info.exp,
        "statement": b64(&resolved.info.hash),
        "card": card,
        "card_verified": card_verified,
        "safety": {
            "owner_level": resolved.owner_level,
            "contact": manifest.contact.is_some(),
            "reserved": resolved.reserved,
            "labels": {"name": label(resolved.name_label), "target": label(resolved.target_label)},
            "adult_policy": manifest.adult_policy().as_str(),
            "warnings": warnings,
        },
        "app": Value::Null,
        "open": Value::Null,
    })
}

fn not_found() -> NodeError {
    NodeError::not_found()
}

impl Node {
    /// Routes `/v4/names/...` (names exist only in a network).
    pub(crate) async fn route_names(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        if self.network().is_none() {
            return Err(not_found());
        }
        if request.path != "/v4/names/submit" {
            self.inner.guard.admit_names(request.peer, now)?;
        }
        if request.path.starts_with("/v4/names/blocklist") {
            return self.route_blocklists(request, now).await;
        }
        match (request.method, request.path.as_str()) {
            (Method::Get, "/v4/names/info") => self.names_info(),
            (Method::Post, "/v4/names/resolve") => self.names_resolve(request, now).await,
            (Method::Post, "/v4/names/search") => self.names_search(&request.body, now).await,
            (Method::Post, "/v4/names/list") => self.names_list(&request.body, now),
            (Method::Post, "/v4/names/submit") => self.names_submit(request, now).await,
            _ => Err(not_found()),
        }
    }

    /// `GET /v4/names/info`: the network's rules for names (docs/08 §2).
    fn names_info(&self) -> NodeResult<Vec<u8>> {
        let value = self.with_core(|core| {
            let manifest = core.state.manifest();
            let rules = manifest.name_rules();
            json!({
                "net": core.state.net().as_str(),
                "name": manifest.name,
                "short": manifest.short,
                "contact": manifest.contact,
                "adult": manifest.adult_policy().as_str(),
                "names": {"min_level": rules.min_level, "quota": rules.quota, "reserved": rules.reserved},
                "blocklists": manifest.blocklists.clone().unwrap_or_default().iter().map(Id::as_str).collect::<Vec<_>>(),
            })
        })?;
        Ok(value.to_string().into_bytes())
    }

    /// `POST /v4/names/resolve` `{"name"}` (docs/08 §7).
    async fn names_resolve(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(&request.body, MAX_QUERY_BYTES)?;
        let name = body
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= MAX_NAME_INPUT)
            .ok_or_else(|| NodeError::bad_format("name: a name or name.short"))?;
        let blocklists = self.blocklists();
        let (mut value, app, owner) = self.with_core(|core| -> NodeResult<_> {
            let resolved = core.state.resolve_name(&name.to_ascii_lowercase(), now).map_err(|_| not_found())?;
            // A blocklisted name, target or owner is like a banned one (docs/08 §9): not found.
            if blocklists.blocks_resolved(&resolved, now) {
                return Err(not_found());
            }
            let value = name_value(&core.state, core.state.manifest(), &resolved);
            let body = &resolved.info.name;
            let app = (body.kind == NameKind::App).then(|| body.target.clone());
            Ok((value, app, body.owner.clone()))
        })??;
        if let Some(app) = app {
            let fetch = self.reader_allows(request);
            let mut warnings: Vec<Value> = value["safety"]["warnings"].as_array().cloned().unwrap_or_default();
            match self.app_view(&app, fetch, now).await {
                Some((version, hosts)) => {
                    let owner_matches = version.manifest.owner == owner;
                    let hosts: Vec<Value> = hosts
                        .iter()
                        .map(|(id, card)| {
                            let urls: Vec<&str> =
                                card.iter().flat_map(|card| card.urls().iter().map(String::as_str)).collect();
                            json!({"id": id.as_str(), "urls": urls})
                        })
                        .collect();
                    value["app"] = json!({
                        "name": version.manifest.name,
                        "description": version.manifest.description,
                        "version": version.manifest.version,
                        "entry": version.manifest.entry,
                        "owner_matches": owner_matches,
                        "hosts": hosts,
                    });
                    if owner_matches {
                        value["open"] = json!(format!("/app/{app}/"));
                    } else {
                        warnings.push(json!("owner_mismatch"));
                    }
                }
                None => warnings.push(json!("app_unknown")),
            }
            value["safety"]["warnings"] = Value::Array(warnings);
        }
        Ok(value.to_string().into_bytes())
    }

    /// `POST /v4/names/search` `{"q","safe"?,"max"?}` (docs/08 §7): on a snapshot of the state in a blocking thread,
    /// at most [`MAX_SEARCHES_AT_ONCE`] at once (see module docs).
    async fn names_search(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(body, MAX_QUERY_BYTES)?;
        let query = body
            .get("q")
            .and_then(Value::as_str)
            .filter(|query| !query.trim().is_empty() && query.chars().count() <= bridge_net::state::MAX_QUERY_CHARS)
            .ok_or_else(|| NodeError::bad_format("q: 1-64 characters"))?;
        if query.chars().any(char::is_control) {
            return Err(NodeError::bad_format("q: no control characters"));
        }
        let safe = match body.get("safe") {
            None => true,
            Some(value) => value.as_bool().ok_or_else(|| NodeError::bad_format("safe: true or false"))?,
        };
        let max = optional_u64(&body, "max", DEFAULT_RESULTS, bridge_net::state::MAX_SEARCH_RESULTS as u64)?.max(1);
        let max = usize::try_from(max).unwrap_or(1);
        // Only names of one kind (docs/10 §5).
        let kind = match body.get("kind") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(bridge_net::NameKind::parse)
                    .ok_or_else(|| NodeError::bad_format("kind: app, node or member"))?,
            ),
        };
        // The slot travels into the blocking thread: a caller that gives up does not free it before the work is done.
        let slot = Arc::clone(&self.inner.searches).try_acquire_owned().map_err(|_| NodeError {
            retry_after: Some(1),
            ..NodeError::new(429, "RATE_LIMITED", "too many searches at once")
        })?;
        let query = query.to_owned();
        let blocklists = self.blocklists();
        self.on_snapshot(move |state| {
            let search = state.search_kind(&query, safe, max, now, kind);
            let manifest = state.manifest();
            let list: Vec<Value> = search
                .results
                .iter()
                .filter(|result| !blocklists.blocks_resolved(result, now))
                .map(|result| name_value(state, manifest, result))
                .collect();
            drop(slot);
            json!({"results": list, "more": search.more}).to_string().into_bytes()
        })
        .await
    }

    /// `POST /v4/names/list` `{"owner"}`: the names of an owner that resolve now.
    fn names_list(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(body, MAX_QUERY_BYTES)?;
        let owner = Id::parse(body.get("owner").and_then(Value::as_str).unwrap_or_default())?;
        let blocklists = self.blocklists();
        let value = self.with_core(|core| {
            let manifest = core.state.manifest();
            let list: Vec<Value> = core
                .state
                .names_of(&owner, now)
                .iter()
                .filter(|name| !blocklists.blocks_resolved(name, now))
                .map(|name| name_value(&core.state, manifest, name))
                .collect();
            json!({"names": list})
        })?;
        Ok(value.to_string().into_bytes())
    }

    /// `POST /v4/names/submit` (session): a `name` statement of the logged-in member, or the `revoke` of one of its
    /// names. Checked like the log operator does, handed to it, and waited for until it holds here.
    async fn names_submit(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, now)?;
        let statement = Statement::parse(&request.body)?;
        if statement.net() != &self.inner.net {
            return Err(NodeError::bad_format("statement: other network"));
        }
        self.inner.guard.admit_send(&caller, now)?;
        // What to wait for once it is in the log.
        let done: Box<dyn Fn(&NetState) -> bool + Send + Sync> = match Kind::parse(statement.kind()) {
            Some(Kind::Name) => {
                let name = Name::from_statement(&statement)?;
                if name.owner != caller {
                    return Err(NodeError::forbidden("only the owner submits its name"));
                }
                let hash = statement.hash_bytes();
                Box::new(move |state: &NetState| state.name_info(&name.name).is_some_and(|info| info.hash == hash))
            }
            Some(Kind::Revoke) => {
                let revoke = Revoke::from_statement(&statement)?;
                let RevokeTarget::Statement(target) = revoke.target else {
                    return Err(NodeError::forbidden("only the revocation of an own name"));
                };
                let owner = self.with_core(|core| core.state.name_by_hash(&target).map(|info| info.name.owner))?;
                if owner.as_ref() != Some(&caller) || statement.claimed_signers() != [&caller] {
                    return Err(NodeError::forbidden("only the revocation of an own name"));
                }
                Box::new(move |state: &NetState| state.name_by_hash(&target).is_none())
            }
            _ => return Err(NodeError::bad_format("statement: a name or the revocation of one")),
        };
        self.with_core(|core| core.state.validate_candidate(&statement, now))??;
        let appended = self.submit_to_operator(&statement).await?;
        self.wait_until(move |core, _| done(&core.state)).await;
        Ok(json!({"ok": true, "hash": statement.hash(), "index": appended.index}).to_string().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Clock as _;

    #[test]
    fn addresses_use_the_short_name() -> Result<(), bridge_net::NetError> {
        let master = bridge_core::Identity::from_secret_bytes(&[1; 32], &[2; 32]);
        let node = bridge_core::Identity::from_secret_bytes(&[3; 32], &[4; 32]);
        let card = master.key_card(bridge_core::Role::Net, None, 0)?;
        let mut manifest =
            Manifest::template(bridge_net::JoinMode::Open, "Netz", card, node.id(), "https://x.example")?;
        assert_eq!(address(&manifest, "shop"), "shop");
        manifest.short = Some("meinnetz".into());
        assert_eq!(address(&manifest, "shop"), "shop.meinnetz");
        Ok(())
    }

    /// Review 9, finding 1: a search once ran on a worker thread under the core lock - 380 ms at 100,000 names, every
    /// other request of the node waited. Now the work runs on a snapshot in a blocking thread while the lock stays
    /// free, and at most `MAX_SEARCHES_AT_ONCE` searches run at once on the node, whoever asks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn searches_run_beside_the_lock_with_a_node_wide_limit() -> Result<(), String> {
        let e = |error: &dyn std::fmt::Display| error.to_string();
        let dir = tempfile::tempdir().map_err(|error| e(&error))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|error| e(&error))?;
        let url = format!("http://{}", listener.local_addr().map_err(|error| e(&error))?);
        let words = bridge_core::Mnemonic::generate(&mut rand_core::OsRng);
        let options = crate::admin::NetOptions {
            short: Some("netz".into()),
            contact: Some("abuse@test.example".into()),
            adult: false,
        };
        let now = crate::SystemClock.now_ms();
        let created = crate::admin::create_network_with_options(
            dir.path(),
            "Netz",
            &url,
            bridge_net::JoinMode::Open,
            now,
            &words,
            &options,
        )?;
        let mut config = crate::NodeConfig::new(dir.path());
        config.network = Some(crate::NetConfig::new(created.net.clone()));
        config.urls = vec![url.clone()];
        let running = crate::start(config, listener).await?;
        let node = running.node.clone();
        // The work on a snapshot holds no lock: the core is free (and usable) while it runs.
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let work = tokio::spawn({
            let node = node.clone();
            async move {
                node.on_snapshot(move |state| {
                    let _ = entered.send(());
                    let _ = released.recv_timeout(std::time::Duration::from_secs(20));
                    state.size()
                })
                .await
            }
        });
        started.await.map_err(|error| e(&error))?;
        let network = node.network().ok_or("no network")?;
        // Background tasks may hold the lock for a moment; the search itself never does.
        let mut free = false;
        for _ in 0..200 {
            if network.core.try_lock().is_ok() {
                free = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(free, "the core lock is free while the search works");
        assert!(node.with_core(|core| core.log.size()).map_err(|error| error.message)? >= 1);
        release.send(()).map_err(|error| e(&error))?;
        let size = work.await.map_err(|error| e(&error))?.map_err(|error| error.message)?;
        assert!(size >= 1);
        // All search slots taken: the next search is refused at once for anybody; free again, it answers.
        let slots = Arc::clone(&node.inner.searches)
            .try_acquire_many_owned(u32::try_from(MAX_SEARCHES_AT_ONCE).unwrap_or(1))
            .map_err(|error| e(&error))?;
        let http =
            bridge_transport::HttpClient::new(&url, std::time::Duration::from_secs(10)).map_err(|error| e(&error))?;
        let query = br#"{"q":"shop"}"#.to_vec();
        let busy = http.post("/v4/names/search", None, query.clone()).await.map_err(|error| e(&error))?;
        assert_eq!(busy.status, 429);
        drop(slots);
        let answer = http.post("/v4/names/search", None, query).await.map_err(|error| e(&error))?;
        assert_eq!(answer.status, 200);
        running.shutdown().await;
        Ok(())
    }
}
