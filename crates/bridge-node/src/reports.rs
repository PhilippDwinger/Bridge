//! Reports at a node (docs/08 §6, ADR 0018): members report names and apps at their gateway; the gateway keeps them
//! and hands them on to the active log operator, where admins see all of them. Not in the log (who reports is
//! private); a report never triggers anything by itself.
//!
//! - `POST /v4/report` (session + signed request of the member): checked cheap first, bounded per member and node,
//!   duplicates (same report, or an open one of the same member about the same target) answered as such.
//! - **The text is sealed** (review 9): `sealed` is an envelope from the member to a log operator of the network (Z1) -
//!   the gateway that takes the report and hands it on can not read it, only the log operator opens it, for the
//!   admins' view. Target and reason stay readable (the gateway needs them for its bounds).
//! - A full table makes room with the open reports of the lowest level first; open reports of level 0 age out after
//!   [`KEEP_OPEN_LEVEL0_MS`].
//! - `POST /v4/node/report` (gateway → log operator): the gateway's request carries the member's signed report and
//!   card - no gateway can invent reports in a member's name.
//! - `POST /v4/admin/reports` / `POST /v4/admin/report` (admins with `bans` or `seals`, or the net key): read, and set
//!   the status `open`/`done`.

use bridge_core::crypto::sha256;
use bridge_core::encoding::b64;
use bridge_core::json::{canonical, parse_strict};
use bridge_core::{CLOCK_SKEW_MS, Envelope, Id, KeyCard, Role, SignedRequest};
use bridge_net::statements::check_text;
use bridge_net::{LabelTarget, Right};
use bridge_store::{ReportLimits, ReportRow, ReportStored};
use bridge_transport::{Method, Request};
use serde_json::{Map, Value, json};

use crate::{Node, NodeError, NodeResult, optional_u64};

/// Longest free text of a report.
pub const MAX_REPORT_TEXT_CHARS: usize = 500;
/// A report handed on later than this after it was signed is refused (and no longer handed on).
const MAX_REPORT_AGE_MS: i64 = 7 * 24 * 3600 * 1000;
/// Reports handed on per round.
const FORWARD_PER_ROUND: u32 = 16;
/// Handled reports are deleted this long after they were handled.
pub(crate) const KEEP_DONE_MS: i64 = 90 * 24 * 3600 * 1000;
/// Most reports in one admin answer.
const MAX_LISTED: u64 = 100;
/// Open reports of members of level 0 are deleted this long after they came in (review 9).
pub(crate) const KEEP_OPEN_LEVEL0_MS: i64 = 30 * 24 * 3600 * 1000;
/// Longest sealed text: 500 characters of up to 4 bytes, plus the AEAD tag.
const MAX_SEALED_BYTES: usize = MAX_REPORT_TEXT_CHARS * 4 + 16;

/// Reasons of a report (wire names).
const REASONS: [&str; 5] = ["illegal", "phishing", "adult_unlabeled", "spam", "other"];

/// The body of a report, checked strictly (the sealed text only in its form, see [`Node::check_sealed`]).
struct ReportBody {
    target: String,
    reason: String,
    sealed: Option<Envelope>,
}

fn parse_body(body: &Value) -> NodeResult<ReportBody> {
    let Value::Object(object) = body else { return Err(NodeError::bad_format("report: not an object")) };
    if object.len() != 3 || !["target", "reason", "sealed"].iter().all(|key| object.contains_key(*key)) {
        return Err(NodeError::bad_format(
            "report: exactly target, reason, sealed (the text sealed to the log operator)",
        ));
    }
    let field = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default();
    let target = LabelTarget::parse(field("target")).map_err(|_| NodeError::bad_format("target: a name or an ID"))?;
    let reason = field("reason");
    if !REASONS.contains(&reason) {
        return Err(NodeError::bad_format("reason: illegal, phishing, adult_unlabeled, spam or other"));
    }
    let sealed = match object.get("sealed") {
        Some(Value::Null) | None => None,
        Some(value @ Value::Object(_)) => Some(Envelope::from_value(value.clone())?),
        Some(_) => return Err(NodeError::bad_format("sealed: null or an envelope")),
    };
    if sealed.as_ref().is_some_and(|envelope| envelope.ciphertext_len() > MAX_SEALED_BYTES) {
        return Err(NodeError::bad_format("sealed: at most 500 characters of text"));
    }
    Ok(ReportBody { target: target.as_text().to_owned(), reason: reason.to_owned(), sealed })
}

/// The sealed text of a stored report (inside the member's signed request), if any.
fn sealed_of(row: &ReportRow) -> Option<Envelope> {
    let request = SignedRequest::parse(&row.request).ok()?;
    parse_body(request.body()).ok()?.sealed
}

/// The ID of a report: Base64url SHA-256 of the canonical bytes of the member's signed request.
fn report_id(bytes: &[u8]) -> String {
    b64(&sha256(bytes))
}

/// A report for the admins: the text opened if it is sealed to this node (`text: null` if it is sealed to another log
/// operator; `sealed_to` names it).
fn row_value(row: &ReportRow, me: &bridge_core::Identity) -> Value {
    let (text, sealed_to) = match sealed_of(row) {
        Some(envelope) => (open_text(&envelope, row, me), Some(envelope.to().to_string())),
        None if row.text.is_empty() => (Some(String::new()), None),
        None => (Some(row.text.clone()), None), // a report from before the texts were sealed
    };
    json!({
        "id": row.id,
        "reporter": row.reporter,
        "target": row.target,
        "reason": row.reason,
        "text": text,
        "sealed_to": sealed_to,
        "level": row.level,
        "received": row.received,
        "status": row.status,
        "via": row.via,
        "handled_by": row.handled_by,
        "handled_at": row.handled_at,
    })
}

/// Opens a sealed text with this node's key and the reporter's card; checked like a text (`None` if it is not for
/// this node or not a valid text).
fn open_text(envelope: &Envelope, row: &ReportRow, me: &bridge_core::Identity) -> Option<String> {
    let card = KeyCard::parse(&row.card).ok()?;
    let bytes = envelope.open(me, &card).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    check_text(&text, 0, MAX_REPORT_TEXT_CHARS, true, "text").ok()?;
    Some(text)
}

impl Node {
    fn report_limits(&self) -> ReportLimits {
        ReportLimits::default()
    }

    /// A sealed text (review 9): an envelope of this network, from the reporter (signed with its card), for a log
    /// operator of the current rules; at the gateway also valid now (`fresh`) - handed on, the age of the report counts
    /// (up to 7 days, like the longest envelope). Nobody but that operator can read it - the gateway checks the form.
    fn check_sealed(&self, sealed: Option<&Envelope>, card: &KeyCard, now: i64, fresh: bool) -> NodeResult<()> {
        let Some(envelope) = sealed else { return Ok(()) };
        if envelope.net() != &self.inner.net || envelope.from() != card.id() {
            return Err(NodeError::forbidden("sealed: an envelope of the reporter in this network"));
        }
        if !self.with_core(|core| core.state.log_operators().contains(envelope.to()))? {
            return Err(NodeError::forbidden("sealed: the text is sealed to a log operator of the network"));
        }
        if fresh {
            envelope.check_time(now)?;
        }
        envelope.verify(card)?;
        Ok(())
    }

    async fn store_report(&self, row: ReportRow, now: i64) -> NodeResult<ReportStored> {
        let net = self.inner.net.to_string();
        let limits = self.report_limits();
        let stored = self.blocking(move |store| store.report_put(&net, &row, &limits, now)).await?;
        match stored {
            ReportStored::ReporterLimit => Err(NodeError {
                retry_after: Some(3600),
                ..NodeError::new(429, "RATE_LIMITED", "too many reports from this member today")
            }),
            ReportStored::Full => {
                Err(NodeError { retry_after: Some(3600), ..NodeError::new(429, "QUOTA_EXCEEDED", "report table full") })
            }
            other => Ok(other),
        }
    }

    /// `POST /v4/report`: a member reports a name or an ID (docs/08 §6).
    pub(crate) async fn report_in(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        if self.network().is_none() {
            return Err(NodeError::not_found());
        }
        let caller = self.session(request, now)?;
        let signed = SignedRequest::parse(&request.body)?;
        signed.check(self.inner.identity.id(), now)?;
        if signed.op() != "report" || signed.iss() != &caller {
            return Err(NodeError::forbidden("a report is signed by the logged-in member"));
        }
        let card = self.known_card(&caller).await?.ok_or_else(NodeError::no_session)?;
        signed.verify(&card)?;
        self.inner.guard.remember_nonce(
            signed.iss(),
            signed.nonce(),
            signed.iat().saturating_add(CLOCK_SKEW_MS),
            now,
        )?;
        let body = parse_body(signed.body())?;
        self.check_sealed(body.sealed.as_ref(), &card, now, true)?;
        let bytes = canonical(&signed.to_value())?;
        let (operator, level) =
            self.with_core(|core| (core.is_active_operator(), core.state.level(&caller, now).unwrap_or(0)))?;
        let row = ReportRow {
            id: report_id(&bytes),
            reporter: caller.to_string(),
            target: body.target,
            reason: body.reason,
            text: String::new(),
            request: bytes,
            card: card.to_bytes()?,
            via: self.inner.identity.id().to_string(),
            received: now,
            status: "open".into(),
            handled_by: None,
            handled_at: None,
            forwarded: operator,
            level,
        };
        let id = row.id.clone();
        let (id, duplicate) = match self.store_report(row, now).await? {
            ReportStored::Duplicate(known) => (known, true),
            _ => (id, false),
        };
        if !duplicate && !operator {
            let node = self.clone();
            tokio::spawn(async move { node.reports_round().await });
        }
        Ok(json!({"ok": true, "id": id, "duplicate": duplicate, "forwarded": operator}).to_string().into_bytes())
    }

    /// `POST /v4/node/report`: a gateway hands a member's report on to this node, the active log operator.
    pub(crate) async fn node_report_in(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        if !self.with_core(|core| core.is_active_operator())? {
            return Err(NodeError::forbidden("this node is not the log operator of the network"));
        }
        let outer = SignedRequest::parse(body)?;
        outer.check(&me, now)?;
        if outer.op() != "report" {
            return Err(NodeError::bad_format("op: expected report"));
        }
        let gateway = self
            .with_core(|core| core.gateway_card(outer.iss(), now))?
            .ok_or_else(|| NodeError::forbidden("only gateways hand reports on"))?;
        outer.verify(&gateway)?;
        self.inner.guard.remember_nonce(outer.iss(), outer.nonce(), outer.iat().saturating_add(CLOCK_SKEW_MS), now)?;
        let Value::Object(fields) = outer.body() else { return Err(NodeError::bad_format("body: not an object")) };
        if fields.len() != 2 {
            return Err(NodeError::bad_format("body: exactly report and card"));
        }
        let inner = SignedRequest::from_value(fields.get("report").cloned().unwrap_or(Value::Null))?;
        let card = KeyCard::from_value(fields.get("card").cloned().unwrap_or(Value::Null))?;
        if inner.op() != "report" || inner.aud() != outer.iss() || inner.iss() != card.id() {
            return Err(NodeError::forbidden("the report must be the member's, handed in at this gateway"));
        }
        if !matches!(card.role(), Role::Client | Role::Node) {
            return Err(NodeError::forbidden("reports come from members"));
        }
        inner.verify(&card)?;
        if inner.iat() < now.saturating_sub(MAX_REPORT_AGE_MS) || inner.iat() > now.saturating_add(CLOCK_SKEW_MS) {
            return Err(NodeError::new(401, "EXPIRED", "report too old or from the future"));
        }
        let level = self
            .with_core(|core| core.state.level(card.id(), now))?
            .ok_or_else(|| NodeError::new(403, "NOT_MEMBER", "the reporter is no member"))?;
        let parsed = parse_body(inner.body())?;
        self.check_sealed(parsed.sealed.as_ref(), &card, now, false)?;
        let bytes = canonical(&inner.to_value())?;
        let row = ReportRow {
            id: report_id(&bytes),
            reporter: card.id().to_string(),
            target: parsed.target,
            reason: parsed.reason,
            text: String::new(),
            request: bytes,
            card: card.to_bytes()?,
            via: outer.iss().to_string(),
            received: now,
            status: "open".into(),
            handled_by: None,
            handled_at: None,
            forwarded: true,
            level,
        };
        let duplicate = matches!(self.store_report(row, now).await?, ReportStored::Duplicate(_));
        Ok(json!({"ok": true, "duplicate": duplicate}).to_string().into_bytes())
    }

    /// One round of handing reports on to the active log operator (at most 16, oldest first, at most 7 days old).
    /// A final refusal (4xx other than 429) marks a report as handed on too - it stays here, it is not retried.
    pub(crate) async fn reports_round(&self) {
        let Ok(Some(operator)) = self.with_core(|core| core.active_operator().cloned()) else { return };
        let (net, now) = (self.inner.net.to_string(), self.now());
        let since = now.saturating_sub(MAX_REPORT_AGE_MS);
        let Ok(rows) = self.blocking(move |store| store.reports_unforwarded(&net, since, FORWARD_PER_ROUND)).await
        else {
            return;
        };
        if rows.is_empty() {
            return;
        }
        let me = self.inner.identity.id().clone();
        let endpoints = self.reach(&operator);
        for row in rows {
            let done = if operator == me {
                true
            } else {
                let (Ok(report), Ok(card)) = (parse_strict(&row.request, 64 * 1024), parse_strict(&row.card, 4096))
                else {
                    self.mark_forwarded(&row.id).await;
                    continue;
                };
                let Ok(body) = self.signed(&operator, "report", json!({"report": report, "card": card})) else {
                    continue;
                };
                match self.peer_post_any(&endpoints, "/v4/node/report", body).await {
                    Ok(answer) if answer.status == 200 => true,
                    Ok(answer) if (400..500).contains(&answer.status) && answer.status != 429 => {
                        tracing::info!(report = %row.id, code = answer.code(), "the log operator refused a report");
                        true
                    }
                    _ => false,
                }
            };
            if done {
                self.mark_forwarded(&row.id).await;
            }
        }
    }

    async fn mark_forwarded(&self, id: &str) {
        let (net, id) = (self.inner.net.to_string(), id.to_owned());
        if let Err(error) = self.blocking(move |store| store.report_forwarded(&net, &id)).await {
            tracing::warn!(error = %error.message, "could not mark a report as handed on");
        }
    }

    /// An admin request for the reports (`op`): signed by an admin with `bans` or `seals`, or the net key; fresh, for
    /// this node, used once. Returns the admin and the body.
    fn admin_request(&self, body: &[u8], op: &str, now: i64) -> NodeResult<(Id, Map<String, Value>)> {
        let request = SignedRequest::parse(body)?;
        request.check(self.inner.identity.id(), now)?;
        if request.op() != op {
            return Err(NodeError::bad_format(format!("op: expected {op}")));
        }
        let card = self
            .with_core(|core| {
                let rights = core.state.admin_rights(request.iss(), now);
                (rights.has(Right::Bans) || rights.has(Right::Seals))
                    .then(|| core.state.card_of(request.iss()).cloned())
                    .flatten()
            })?
            .ok_or_else(|| NodeError::forbidden("only admins with the right bans or seals read reports"))?;
        request.verify(&card)?;
        self.inner.guard.remember_nonce(
            request.iss(),
            request.nonce(),
            request.iat().saturating_add(CLOCK_SKEW_MS),
            now,
        )?;
        let Value::Object(fields) = request.body().clone() else {
            return Err(NodeError::bad_format("body: not an object"));
        };
        Ok((request.iss().clone(), fields))
    }

    /// Routes `/v4/admin/...`.
    pub(crate) async fn route_admin(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        if self.network().is_none() {
            return Err(NodeError::not_found());
        }
        match (request.method, request.path.as_str()) {
            (Method::Post, "/v4/admin/reports") => self.admin_reports(&request.body, now).await,
            (Method::Post, "/v4/admin/report") => self.admin_report_status(&request.body, now).await,
            _ => Err(NodeError::not_found()),
        }
    }

    /// `POST /v4/admin/reports` `{"status"?,"max"?,"before"?}` → newest first.
    async fn admin_reports(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let (_, fields) = self.admin_request(body, "reports", now)?;
        if let Some(unknown) = fields.keys().find(|key| !["status", "max", "before"].contains(&key.as_str())) {
            return Err(NodeError::bad_format(format!("unknown field {unknown}")));
        }
        let status = match fields.get("status").map(|value| value.as_str()) {
            None | Some(Some("open")) => Some("open"),
            Some(Some("done")) => Some("done"),
            Some(Some("all")) => None,
            Some(_) => return Err(NodeError::bad_format("status: open, done or all")),
        };
        let max = optional_u64(&fields, "max", 50, MAX_LISTED)?.max(1);
        let before = match fields.get("before") {
            None => None,
            Some(value) => Some(value.as_i64().ok_or_else(|| NodeError::bad_format("before: a time (ms)"))?),
        };
        let (net, status) = (self.inner.net.to_string(), status.map(str::to_owned));
        let max_u32 = u32::try_from(max).unwrap_or(1);
        let rows = self.blocking(move |store| store.reports_list(&net, status.as_deref(), before, max_u32)).await?;
        let next = if rows.len() as u64 == max { rows.last().map(|row| json!(row.received)) } else { None };
        let list: Vec<Value> = rows.iter().map(|row| row_value(row, &self.inner.identity)).collect();
        Ok(json!({"reports": list, "next": next.unwrap_or(Value::Null)}).to_string().into_bytes())
    }

    /// `POST /v4/admin/report` `{"id","status":"done|open"}`.
    async fn admin_report_status(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let (admin, fields) = self.admin_request(body, "report-status", now)?;
        if fields.len() != 2 {
            return Err(NodeError::bad_format("body: exactly id and status"));
        }
        let id = fields
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| id.len() == 43)
            .ok_or_else(|| NodeError::bad_format("id: a report ID"))?;
        let status = match fields.get("status").and_then(Value::as_str) {
            Some(status @ ("open" | "done")) => status.to_owned(),
            _ => return Err(NodeError::bad_format("status: open or done")),
        };
        let (net, id, by) = (self.inner.net.to_string(), id.to_owned(), admin.to_string());
        if !self.blocking(move |store| store.report_set_status(&net, &id, &status, &by, now)).await? {
            return Err(NodeError::not_found());
        }
        Ok(br#"{"ok":true}"#.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_bodies_are_strict() -> Result<(), bridge_core::CoreError> {
        let (member, operator) = (
            bridge_core::Identity::from_secret_bytes(&[1; 32], &[2; 32]),
            bridge_core::Identity::from_secret_bytes(&[3; 32], &[4; 32]),
        );
        let net = Id::of_sign_key(&[9; 32]);
        let to = operator.key_card(Role::Node, None, 0)?;
        let seal = |text: &[u8]| -> Result<Value, bridge_core::CoreError> {
            let address = bridge_core::Address { net: &net, to: &to, kind: bridge_core::Kind::Msg, iat: 1, ttl: 60 };
            let envelope = Envelope::seal(&member, &address, text, &mut rand_core::OsRng)?;
            parse_strict(&envelope.to_bytes()?, 64 * 1024)
        };
        let ok = json!({"target": "shop", "reason": "phishing", "sealed": seal("Zeile 1\nZeile 2".as_bytes())?});
        let parsed = parse_body(&ok).map_err(|e| bridge_core::CoreError::BadFormat(e.message))?;
        assert_eq!(parsed.sealed.as_ref().map(|envelope| envelope.to().clone()), Some(operator.id().clone()));
        assert!(parse_body(&json!({"target": "shop", "reason": "phishing", "sealed": null})).is_ok(), "no text");
        for bad in [
            json!({"target": "shop", "reason": "phishing"}),
            // Review 9: a plain text is refused - it would be readable at every gateway on the way.
            json!({"target": "shop", "reason": "phishing", "text": "Zeile 1"}),
            json!({"target": "shop", "reason": "phishing", "sealed": null, "text": ""}),
            json!({"target": "shop", "reason": "phishing", "sealed": "Zeile 1"}),
            json!({"target": "shop", "reason": "phishing", "sealed": {"v": 4}}),
            json!({"target": "shop", "reason": "phishing", "sealed": seal(&[b'x'; 2001])?}),
            json!({"target": "Shop!", "reason": "phishing", "sealed": null}),
            json!({"target": "shop", "reason": "boring", "sealed": null}),
            json!([]),
        ] {
            assert!(parse_body(&bad).is_err(), "{bad}");
        }
        assert_eq!(report_id(b"x").len(), 43);
        Ok(())
    }
}
