//! Apps stage 2 (docs/09 §13, docs/07 §6): server code and the event log per app.
//!
//! - **Server code**: an app version may name a `.wasm` file (`server`). Every host runs it for
//!   `POST /app/<id>/api/<path>` in the sandbox (entry `handle`, input `{"path","body"}` with the body as Base64url,
//!   output `{"status","type","body"}`), with the capabilities `log` and `events` - nothing else. The answer goes out
//!   with the app's sandbox headers like every file of the app.
//! - **Event log**: the server code appends events (`event_append`, at most [`MAX_EVENT_BYTES`], 16 per call); each
//!   is a statement `appevent` signed by this host (`{"app","host","seq","data"}`, `seq` 1, 2, … without gaps). Every
//!   app round, a host fetches the new events of every other valid host of the app (`POST /v4/app/events`), checks
//!   each signature against that host's card and the sequence, and keeps them. All hosts read the same order
//!   `(iat, host, seq)` (`event_count`, `event_read`) - Bridge spreads events, the app computes its state from them.

use std::sync::Arc;

use bridge_core::encoding::{b64, b64_var};
use bridge_core::json::parse_strict;
use bridge_core::{Draft, Id, Identity, KeyCard, Statement};
use bridge_store::{EventRow, Store};
use bridge_transport::{Request, Response};
use bridge_wasm::{Grants, Host, Limits};
use serde_json::{Value, json};

use crate::apps::Version;
use crate::{Node, NodeError, NodeResult, body_object};

/// Largest request body of the server code.
const MAX_API_BODY: usize = 64 * 1024;
/// Largest event.
pub const MAX_EVENT_BYTES: usize = 4096;
/// Most events one call appends.
const MAX_APPENDS_PER_CALL: u32 = 16;
/// Most events per answer of `/v4/app/events`.
const EVENTS_PER_ANSWER: usize = 256;
/// Fuel of one call of the server code.
const SERVER_FUEL: u64 = 100_000_000;
/// Lifetime of an event statement (the event stays; the time only bounds the statement form).
const EVENT_LIFETIME_MS: i64 = 365 * 24 * 3600 * 1000;

struct AppHost {
    store: Arc<Store>,
    identity: Identity,
    net: Id,
    app: Id,
    appended: u32,
    now: i64,
}

impl Host for AppHost {
    fn log(&mut self, line: &str) {
        tracing::info!(app = %self.app, "{line}");
    }

    fn event_append(&mut self, data: &[u8]) -> Result<(), String> {
        if data.len() > MAX_EVENT_BYTES || self.appended >= MAX_APPENDS_PER_CALL {
            return Err("event too large or too many".into());
        }
        let (app, host) = (self.app.to_string(), self.identity.id().to_string());
        let seq = self.store.app_event_last(&app, &host).map_err(|e| e.to_string())? + 1;
        let body = json!({"app": app, "host": host, "seq": seq, "data": b64(data)});
        let draft = Draft { kind: "appevent", net: &self.net, iat: self.now, exp: self.now + EVENT_LIFETIME_MS, body };
        let statement = Statement::sign(&draft, &self.identity).map_err(|e| e.to_string())?;
        let row = EventRow { host, seq, iat: self.now, statement: statement.canonical_bytes().to_vec() };
        if !self.store.app_event_add(&app, &row).map_err(|e| e.to_string())? {
            return Err("event log full".into());
        }
        self.appended += 1;
        Ok(())
    }

    fn event_count(&self) -> u64 {
        self.store.app_event_count(self.app.as_str()).unwrap_or(0)
    }

    fn event_read(&self, index: u64) -> Option<Vec<u8>> {
        let row = self.store.app_event_at(self.app.as_str(), index).ok()??;
        event_data(&row.statement)
    }
}

/// The data of a stored event statement.
fn event_data(bytes: &[u8]) -> Option<Vec<u8>> {
    let statement = Statement::parse(bytes).ok()?;
    b64_var(statement.body().get("data")?.as_str()?, "data", MAX_EVENT_BYTES).ok()
}

/// Checks an event from another host: kind, network, signer = `host` (verified with its card), body of this app and
/// host, data within bounds. Returns the row to store.
fn checked_event(value: &Value, net: &Id, app: &Id, host: &Id, card: &KeyCard) -> Option<EventRow> {
    let statement = Statement::from_value(value.clone()).ok()?;
    if statement.kind() != "appevent" || statement.net() != net || statement.claimed_signers() != [host] {
        return None;
    }
    statement.verify(&[card], 1).ok()?;
    let body = statement.body().as_object()?;
    if body.len() != 4 || body.get("app")?.as_str()? != app.as_str() || body.get("host")?.as_str()? != host.as_str() {
        return None;
    }
    b64_var(body.get("data")?.as_str()?, "data", MAX_EVENT_BYTES).ok()?;
    let seq = body.get("seq")?.as_u64()?;
    Some(EventRow {
        host: host.to_string(),
        seq,
        iat: statement.times().0,
        statement: statement.canonical_bytes().to_vec(),
    })
}

impl Node {
    /// `POST /app/<id>/api/<path>` at a host: runs the version's server code.
    pub(crate) async fn app_api(
        &self,
        request: &Request,
        app: &Id,
        version: &Version,
        path: &str,
    ) -> NodeResult<Response> {
        let now = self.now();
        if request.body.len() > MAX_API_BODY {
            return Err(NodeError::new(413, "TOO_LARGE", "request too large"));
        }
        let server = version.manifest.server.as_deref().ok_or_else(NodeError::not_found)?;
        let file = version.manifest.file(server).ok_or_else(NodeError::not_found)?;
        if file.size > bridge_wasm::MAX_MODULE_BYTES as u64 {
            return Err(NodeError::forbidden("server code too large"));
        }
        // The slot first: reading the module (up to 4 MiB) is work too.
        let slot = Arc::clone(&self.inner.plugin_calls).try_acquire_owned().map_err(|_| NodeError {
            retry_after: Some(1),
            ..NodeError::new(429, "RATE_LIMITED", "too many calls at once")
        })?;
        let parts = bridge_core::blob::parts_for(file.size)?;
        let mut module = Vec::with_capacity(usize::try_from(file.size).unwrap_or(0));
        for index in 0..parts {
            module.extend(self.read_part(&file.blob, index).await?.ok_or_else(NodeError::unavailable)?);
        }
        let input = json!({"path": path, "body": b64(&request.body)}).to_string().into_bytes();
        let (sign, receive) = self.inner.identity.secret_bytes();
        let host = AppHost {
            store: Arc::clone(&self.inner.store),
            identity: Identity::from_secret_bytes(&sign, &receive),
            net: self.inner.net.clone(),
            app: app.clone(),
            appended: 0,
            now,
        };
        let limits = Limits { fuel: SERVER_FUEL, deterministic: false, ..Limits::default() };
        let grants = Grants { log: true, events: true, ..Grants::default() };
        let ran = tokio::task::spawn_blocking(move || {
            let result = bridge_wasm::run(&module, "handle", &input, limits, grants, host);
            drop(slot);
            result
        })
        .await
        .map_err(|_| NodeError::unavailable())?;
        let (outcome, _) = ran.map_err(|error| NodeError::new(500, "SERVER_CODE", error.to_string()))?;
        let Ok(Value::Object(answer)) = parse_strict(&outcome.output, bridge_wasm::MAX_IO_BYTES) else {
            return Err(NodeError::new(500, "SERVER_CODE", "the server code answered no JSON object"));
        };
        let status = answer.get("status").and_then(Value::as_u64).filter(|s| (200..=599).contains(s)).unwrap_or(500);
        let kind = answer
            .get("type")
            .and_then(Value::as_str)
            .filter(|kind| kind.len() <= 100 && kind.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
            .unwrap_or("application/octet-stream");
        let body =
            b64_var(answer.get("body").and_then(Value::as_str).unwrap_or_default(), "body", bridge_wasm::MAX_IO_BYTES)?;
        let mut response = Response::ok(body).with_header("content-type", kind.to_owned());
        response.status = u16::try_from(status).unwrap_or(500);
        Ok(response)
    }

    /// `POST /v4/app/events` `{"app","after"}`: this host's own events of an app it hosts with server code, after
    /// `after`, at most 256 (anybody may read them: hosts fetch from each other; the data is the app's public log).
    pub(crate) async fn app_events_out(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(body, 1024)?;
        let app = Id::parse(body.get("app").and_then(Value::as_str).unwrap_or_default())?;
        let after = crate::optional_u64(&body, "after", 0, u64::MAX)?;
        let version = self.inner.apps.current(&app).ok_or_else(NodeError::not_found)?;
        if version.manifest.server.is_none() || self.still_valid(&version, now).is_err() {
            return Err(NodeError::not_found());
        }
        let (key, me) = (app.to_string(), self.inner.identity.id().to_string());
        let rows = self.blocking(move |store| store.app_events_of(&key, &me, after, EVENTS_PER_ANSWER)).await?;
        let events: Vec<Value> = rows
            .iter()
            .filter_map(|row| Statement::parse(&row.statement).ok())
            .map(|statement| statement.to_value())
            .collect();
        Ok(json!({"events": events}).to_string().into_bytes())
    }

    /// Fetches the new events of every other valid host of `app` (server code only). Bounded: one page per host.
    pub(crate) async fn sync_app_events(&self, app: &Id) {
        let now = self.now();
        let Some(version) = self.inner.apps.current(app) else { return };
        if version.manifest.server.is_none() {
            return;
        }
        let Ok(hosts) = self.still_valid(&version, now) else { return };
        let me = self.inner.identity.id().clone();
        for (host, card) in hosts.into_iter().filter(|(host, _)| host != &me) {
            let Some(card) = card else { continue };
            let (key, peer) = (app.to_string(), host.to_string());
            let Ok(after) = self.blocking(move |store| store.app_event_last(&key, &peer)).await else { continue };
            let body = json!({"app": app.as_str(), "after": after}).to_string().into_bytes();
            let endpoints = self.endpoints_of(&host, card.tls().copied(), card.urls());
            let Ok(answer) = self.peer_post_any(&endpoints, "/v4/app/events", body).await else { continue };
            let Ok(answer) = answer.ok() else { continue };
            let list = answer.get("events").and_then(Value::as_array).cloned().unwrap_or_default();
            for value in list.iter().take(EVENTS_PER_ANSWER) {
                let Some(row) = checked_event(value, &self.inner.net, app, &host, &card) else { break };
                let key = app.to_string();
                // Out of sequence (a gap, a repeat) is refused by the store - the rest of the page waits for the next
                // round.
                match self.blocking(move |store| store.app_event_add(&key, &row)).await {
                    Ok(true) => {}
                    _ => break,
                }
            }
        }
    }
}
