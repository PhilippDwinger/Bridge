//! Bridge Login at a node (docs/11 §9, ADR 0027).
//!
//! - **Only storage nodes with level ≥ 2 hold accounts** (`NetState::login_nodes`) and only with a public `https`
//!   address (its host is the WebAuthn relying party, its origin the only one accepted). Others answer `info` with
//!   the reason and refuse the rest (`FORBIDDEN`).
//! - **Challenges**: 32 random bytes, 2 minutes, each once, at most [`MAX_CHALLENGES`] open (in RAM).
//! - **Register / recover / assert**: client data (type, challenge, origin), authenticator data (RP ID hash, user
//!   present), signature (assert) and signature counter (only upwards, if the authenticator counts). New accounts: at
//!   most [`MAX_REGISTRATIONS_PER_HOUR`] per address and hour.
//! - **Tokens**: a session (12 h) and app tokens (1 h) signed by this node; an app token for the server code of an
//!   app is checked against the issuer's storage seal (`X-Bridge-Login`, [`Node::app_login`]).
//! - **Exchange**: every round a storage node fetches the entries other storage nodes got since last time
//!   (`/v4/node/accounts`, signed node request) and checks each one itself.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use bridge_core::encoding::{b64, b64_fixed, b64_var};
use bridge_core::login::{
    APP_TOKEN_KIND, APP_TOKEN_LIFETIME_MS, Account, AppToken, Entry, MAX_ENTRY_BYTES, RECOVERY_CODE_BYTES,
    SESSION_KIND, SESSION_LIFETIME_MS, Session, account_id, app_user, check_name, token_statement, token_text,
};
use bridge_core::webauthn::{
    Credential, MAX_AUTH_DATA, MAX_CLIENT_DATA, MAX_CREDENTIAL_ID, MAX_SIGNATURE, MAX_SPKI, check_auth_data,
    check_client_data, relying_party,
};
use bridge_core::{Draft, Id, KeyCard, SignedRequest, Statement};
use bridge_store::LoginApplied;
use bridge_transport::{Method, Request};
use rand_core::{OsRng, RngCore};
use serde_json::{Map, Value, json};

use crate::network::Endpoint;
use crate::{Node, NodeError, NodeResult, body_object, lock};

/// How long a challenge holds.
const CHALLENGE_MS: i64 = 2 * 60 * 1000;
/// Most open challenges.
pub(crate) const MAX_CHALLENGES: usize = 10_000;
/// New accounts per address and hour.
pub(crate) const MAX_REGISTRATIONS_PER_HOUR: u32 = 5;
/// Addresses whose registrations are counted at once.
const MAX_TRACKED: usize = 10_000;
/// Entries per exchange answer.
const ENTRIES_PER_ANSWER: usize = 200;
/// Largest login request body.
const MAX_LOGIN_BODY: usize = 16 * 1024;
/// Hour in ms.
const HOUR_MS: i64 = 3600 * 1000;

/// What a node keeps for Bridge Login in RAM.
#[derive(Default)]
pub(crate) struct LoginState {
    challenges: Mutex<HashMap<[u8; 32], i64>>,
    registrations: Mutex<HashMap<IpAddr, (i64, u32)>>,
    since: Mutex<HashMap<Id, i64>>,
}

fn field<'a>(body: &'a Map<String, Value>, name: &str) -> NodeResult<&'a str> {
    body.get(name).and_then(Value::as_str).ok_or_else(|| NodeError::bad_format(format!("{name} missing")))
}

fn credential_of(value: Option<&Value>) -> NodeResult<Credential> {
    let object = value.and_then(Value::as_object).ok_or_else(|| NodeError::bad_format("credential missing"))?;
    let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default();
    let alg = object.get("alg").and_then(Value::as_i64).ok_or_else(|| NodeError::bad_format("credential.alg"))?;
    Ok(Credential::new(
        b64_var(text("id"), "credential.id", MAX_CREDENTIAL_ID)?,
        alg,
        b64_var(text("key"), "credential.key", MAX_SPKI)?,
    )?)
}

/// The challenge inside client data (Base64url) - only to find it; [`check_client_data`] compares exactly.
fn challenge_of(client_data: &[u8]) -> NodeResult<[u8; 32]> {
    let value: Value = serde_json::from_slice(client_data).map_err(|_| NodeError::bad_format("client data"))?;
    let text = value.get("challenge").and_then(Value::as_str).unwrap_or_default();
    Ok(b64_fixed::<32>(text, "challenge")?)
}

impl Node {
    /// The relying party of this node: the host of its first public address that can be one, and its origin.
    fn relying_party(&self) -> Option<(String, String)> {
        self.inner.card.urls().iter().find_map(|url| relying_party(url))
    }

    /// Why this node can not take logins now - or `None`.
    pub(crate) fn login_blocker(&self, now: i64) -> Option<&'static str> {
        let me = self.inner.identity.id();
        let holds = self.with_core(|core| core.state.login_nodes(now).iter().any(|(id, _)| id == me)).ok()?;
        if !holds {
            return Some("Dieser Knoten hält keine Konten (Speicher-Siegel ab Stufe 2 fehlt) – Login ist hier aus.");
        }
        if self.relying_party().is_none() {
            return Some("Login braucht eine öffentliche https-Adresse des Knotens.");
        }
        None
    }

    fn login_ready(&self, now: i64) -> NodeResult<(String, String)> {
        if let Some(reason) = self.login_blocker(now) {
            return Err(NodeError::forbidden(reason));
        }
        self.relying_party().ok_or_else(|| NodeError::forbidden("no public address"))
    }

    /// `/v4/login/...` (docs/11 §9.4).
    pub(crate) async fn route_login(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        if self.network().is_none() {
            return Err(NodeError::not_found());
        }
        self.inner.guard.admit_read(request.peer, now)?;
        match (request.method, request.path.as_str()) {
            (Method::Get, "/v4/login/info") => Ok(self.login_info(now).to_string().into_bytes()),
            (Method::Post, "/v4/login/challenge") => self.login_challenge(now),
            (Method::Post, "/v4/login/register") => self.login_register(request, now).await,
            (Method::Post, "/v4/login/assert") => self.login_assert(request, now).await,
            (Method::Post, "/v4/login/recover") => self.login_recover(request, now).await,
            (Method::Post, "/v4/login/app") => self.login_app(request, now).await,
            _ => Err(NodeError::not_found()),
        }
    }

    fn login_info(&self, now: i64) -> Value {
        let nodes = self.with_core(|core| core.state.login_nodes(now).len()).unwrap_or(0);
        let blocker = self.login_blocker(now);
        let (rp_id, origin) = self.relying_party().unzip();
        json!({"enabled": blocker.is_none(), "reason": blocker, "rp_id": rp_id, "origin": origin, "login_nodes": nodes})
    }

    fn login_challenge(&self, now: i64) -> NodeResult<Vec<u8>> {
        self.login_ready(now)?;
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        let mut open = lock(&self.inner.login.challenges);
        open.retain(|_, expires| *expires > now);
        if open.len() >= MAX_CHALLENGES {
            return Err(NodeError { retry_after: Some(10), ..NodeError::new(429, "RATE_LIMITED", "too many logins") });
        }
        open.insert(challenge, now.saturating_add(CHALLENGE_MS));
        Ok(json!({"challenge": b64(&challenge)}).to_string().into_bytes())
    }

    /// Takes a challenge (once): whether it was handed out here and is still good.
    fn take_challenge(&self, challenge: &[u8; 32], now: i64) -> bool {
        lock(&self.inner.login.challenges).remove(challenge).is_some_and(|expires| expires > now)
    }

    /// Checks client and authenticator data of a ceremony (`kind`) against a challenge of this node.
    fn check_ceremony(&self, body: &Map<String, Value>, kind: &str, now: i64) -> NodeResult<(Vec<u8>, Vec<u8>, u32)> {
        let (rp_id, origin) = self.login_ready(now)?;
        let client = b64_var(field(body, "client_data")?, "client_data", MAX_CLIENT_DATA)?;
        let auth = b64_var(field(body, "auth_data")?, "auth_data", MAX_AUTH_DATA)?;
        let challenge = challenge_of(&client)?;
        if !self.take_challenge(&challenge, now) {
            return Err(NodeError::forbidden("challenge unknown or expired"));
        }
        check_client_data(&client, kind, &challenge, &origin)?;
        let data = check_auth_data(&auth, &rp_id)?;
        Ok((client, auth, data.sign_count))
    }

    async fn login_register(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(&request.body, MAX_LOGIN_BODY)?;
        let name = field(&body, "name")?.trim().to_owned();
        check_name(&name)?;
        let credential = credential_of(body.get("credential"))?;
        let recovery = b64_fixed::<32>(field(&body, "recovery")?, "recovery")?;
        self.admit_registration(request.peer, now)?;
        self.check_ceremony(&body, "webauthn.create", now)?;
        let account = account_id(&credential.key, &recovery);
        let entry = Entry::Create { account: account.clone(), name: name.clone(), credential, recovery, at: now };
        self.apply_entry(&entry).await?;
        self.count_registration(request.peer, now);
        let session = self.session_token(&account, now)?;
        Ok(json!({"account": account.as_str(), "name": name, "session": session}).to_string().into_bytes())
    }

    async fn login_assert(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(&request.body, MAX_LOGIN_BODY)?;
        let cred_id = b64_var(field(&body, "credential_id")?, "credential_id", MAX_CREDENTIAL_ID)?;
        let signature = b64_var(field(&body, "signature")?, "signature", MAX_SIGNATURE)?;
        let (client, auth, count) = self.check_ceremony(&body, "webauthn.get", now)?;
        let net = self.inner.net.to_string();
        let (lookup_net, lookup_id) = (net.clone(), cred_id.clone());
        let state = self
            .blocking(move |store| store.login_account_by_credential(&lookup_net, &lookup_id))
            .await?
            .ok_or_else(|| NodeError::forbidden("unknown passkey"))?;
        let account = Account::from_value(&serde_json::from_str(&state).map_err(|_| NodeError::unavailable())?)?;
        account.credential.verify_assertion(&auth, &client, &signature)?;
        let (counter_net, counter_id) = (net.clone(), cred_id.clone());
        let seen = self.blocking(move |store| store.login_counter(&counter_net, &counter_id)).await?;
        if (count > 0 || seen > 0) && count <= seen {
            return Err(NodeError::forbidden("signature counter went back (copied passkey?)"));
        }
        if count > 0 {
            self.blocking(move |store| store.login_counter_set(&net, &cred_id, count)).await?;
        }
        let session = self.session_token(&account.id, now)?;
        Ok(json!({"account": account.id.as_str(), "name": account.name, "session": session}).to_string().into_bytes())
    }

    async fn login_recover(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(&request.body, MAX_LOGIN_BODY)?;
        let account = Id::parse(field(&body, "account")?)?;
        let code = b64_var(field(&body, "code")?, "code", RECOVERY_CODE_BYTES)?;
        let credential = credential_of(body.get("credential"))?;
        let recovery = b64_fixed::<32>(field(&body, "recovery")?, "recovery")?;
        self.check_ceremony(&body, "webauthn.create", now)?;
        let current = self.account(&account).await?.ok_or_else(|| NodeError::forbidden("unknown account"))?;
        let entry = Entry::Recover {
            account: account.clone(),
            version: current.version.saturating_add(1),
            credential,
            code,
            recovery,
            at: now,
        };
        let updated = self.apply_entry(&entry).await?;
        let session = self.session_token(&account, now)?;
        Ok(json!({"account": account.as_str(), "name": updated.name, "session": session}).to_string().into_bytes())
    }

    async fn login_app(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        self.login_ready(now)?;
        let body = body_object(&request.body, MAX_LOGIN_BODY)?;
        let app = Id::parse(field(&body, "app")?)?;
        let statement = token_statement(field(&body, "session")?)?;
        let session = Session::from_statement(&statement, &self.inner.net, now)?;
        self.verify_issuer(&statement, &session.node, now)?;
        let account = self.account(&session.account).await?.ok_or_else(NodeError::no_session)?;
        let user = app_user(&account.id, &app);
        let exp = now.saturating_add(APP_TOKEN_LIFETIME_MS);
        let token = Statement::sign(
            &Draft {
                kind: APP_TOKEN_KIND,
                net: &self.inner.net,
                iat: now,
                exp,
                body: json!({"app": app.as_str(), "user": user.as_str(), "name": account.name}),
            },
            &self.inner.identity,
        )?;
        Ok(json!({"token": token_text(&token), "user": user.as_str(), "name": account.name, "exp": exp})
            .to_string()
            .into_bytes())
    }

    /// A session for `account`, signed here.
    fn session_token(&self, account: &Id, now: i64) -> NodeResult<String> {
        let statement = Statement::sign(
            &Draft {
                kind: SESSION_KIND,
                net: &self.inner.net,
                iat: now,
                exp: now.saturating_add(SESSION_LIFETIME_MS),
                body: json!({"account": account.as_str()}),
            },
            &self.inner.identity,
        )?;
        Ok(token_text(&statement))
    }

    /// The issuer of a token must be a storage node with level ≥ 2 now, and the token signed by it.
    fn verify_issuer(&self, statement: &Statement, issuer: &Id, now: i64) -> NodeResult<()> {
        let card: Option<KeyCard> = self.with_core(|core| {
            core.state.login_nodes(now).into_iter().find(|(id, _)| id == issuer).and_then(|(_, card)| card)
        })?;
        let card = card.ok_or_else(|| NodeError::new(401, "NO_SESSION", "token of a node that holds no accounts"))?;
        statement.verify(&[&card], 1).map_err(|_| NodeError::new(401, "NO_SESSION", "token not signed by its node"))?;
        Ok(())
    }

    /// The user an app token in `X-Bridge-Login` names for `app` (docs/11 §9.4): `None` without the header, `401`
    /// for a token that does not hold.
    pub(crate) fn app_login(&self, request: &Request, app: &Id, now: i64) -> NodeResult<Option<(Id, String)>> {
        let Some(text) = request.login.as_deref() else { return Ok(None) };
        let unauthorized = || NodeError::new(401, "NO_SESSION", "login token does not hold");
        let statement = token_statement(text).map_err(|_| unauthorized())?;
        let token = AppToken::from_statement(&statement, &self.inner.net, app, now).map_err(|_| unauthorized())?;
        self.verify_issuer(&statement, &token.node, now)?;
        Ok(Some((token.user, token.name)))
    }

    fn admit_registration(&self, peer: IpAddr, now: i64) -> NodeResult<()> {
        let hour = now.div_euclid(HOUR_MS);
        let counted =
            lock(&self.inner.login.registrations).get(&peer).filter(|(at, _)| *at == hour).map_or(0, |(_, n)| *n);
        if counted >= MAX_REGISTRATIONS_PER_HOUR {
            return Err(NodeError {
                retry_after: Some(3600),
                ..NodeError::new(429, "RATE_LIMITED", "too many new accounts")
            });
        }
        Ok(())
    }

    fn count_registration(&self, peer: IpAddr, now: i64) {
        let hour = now.div_euclid(HOUR_MS);
        let mut counts = lock(&self.inner.login.registrations);
        counts.retain(|_, (at, _)| *at == hour);
        if counts.len() >= MAX_TRACKED && !counts.contains_key(&peer) {
            return;
        }
        let entry = counts.entry(peer).or_insert((hour, 0));
        entry.1 = entry.1.saturating_add(1);
    }

    /// The account as stored here.
    async fn account(&self, id: &Id) -> NodeResult<Option<Account>> {
        let (net, account) = (self.inner.net.to_string(), id.to_string());
        let stored = self.blocking(move |store| store.login_account(&net, &account)).await?;
        match stored {
            None => Ok(None),
            Some((state, _)) => {
                Ok(Some(Account::from_value(&serde_json::from_str(&state).map_err(|_| NodeError::unavailable())?)?))
            }
        }
    }

    /// Checks an entry against the stored account and stores it with the new state.
    async fn apply_entry(&self, entry: &Entry) -> NodeResult<Account> {
        let current = self.account(entry.account()).await?;
        let next = entry.apply(current.as_ref()).map_err(|error| match error {
            bridge_core::CoreError::BadSignature => NodeError::forbidden("recovery code does not fit"),
            other => NodeError::from(other),
        })?;
        let bytes = entry.to_bytes()?;
        let state = next.to_value().to_string();
        let (net, account, cred_id, version, updated) =
            (self.inner.net.to_string(), next.id.to_string(), next.credential.id.clone(), next.version, next.updated);
        let applied = self
            .blocking(move |store| store.login_apply(&net, &account, version, &cred_id, &state, &bytes, updated))
            .await?;
        match applied {
            LoginApplied::Applied | LoginApplied::Known => Ok(next),
            LoginApplied::Conflict => Err(NodeError::forbidden("account changed meanwhile, or passkey in use")),
            LoginApplied::Full => Err(NodeError::quota()),
        }
    }

    /// `POST /v4/node/accounts` (signed node request, op `accounts`, from a storage node of the network): the
    /// entries after `since` in arrival order (at most [`ENTRIES_PER_ANSWER`]) and the next `since`.
    pub(crate) async fn accounts_out(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        let request = SignedRequest::parse(body)?;
        request.check(&me, now)?;
        if request.op() != "accounts" {
            return Err(NodeError::bad_format("op: expected accounts"));
        }
        let card: Option<KeyCard> = self.with_core(|core| {
            core.state.login_nodes(now).into_iter().find(|(id, _)| id == request.iss()).and_then(|(_, card)| card)
        })?;
        request.verify(&card.ok_or_else(|| NodeError::forbidden("only storage nodes exchange accounts"))?)?;
        let since = request.body().get("since").and_then(Value::as_i64).filter(|n| *n >= 0).unwrap_or(0);
        let net = self.inner.net.to_string();
        let rows = self.blocking(move |store| store.login_entries_since(&net, since, ENTRIES_PER_ANSWER)).await?;
        let next = rows.last().map_or(since, |(seq, _)| *seq);
        let entries: Vec<Value> =
            rows.iter().filter_map(|(_, entry)| serde_json::from_slice::<Value>(entry).ok()).collect();
        Ok(json!({"entries": entries, "next": next}).to_string().into_bytes())
    }

    /// One exchange round: a storage node fetches new entries from the other storage nodes and checks each one.
    pub(crate) async fn accounts_round(&self) {
        let now = self.now();
        let me = self.inner.identity.id().clone();
        let peers = self
            .with_core(|core| {
                let nodes = core.state.login_nodes(now);
                if !nodes.iter().any(|(id, _)| id == &me) {
                    return Vec::new();
                }
                nodes
                    .into_iter()
                    .filter(|(id, _)| id != &me)
                    .filter_map(|(id, card)| card.map(|card| (id, card.tls().copied(), card.urls().to_vec())))
                    .take(8)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (id, tls, urls) in peers {
            let endpoints = self.endpoints_of(&id, tls, &urls);
            if endpoints.is_empty() {
                continue;
            }
            for _ in 0..4 {
                let since = lock(&self.inner.login.since).get(&id).copied().unwrap_or(0);
                match self.fetch_accounts(&id, &endpoints, since).await {
                    Ok((count, next)) => {
                        let mut cursors = lock(&self.inner.login.since);
                        if cursors.len() >= 1024 {
                            cursors.clear();
                        }
                        cursors.insert(id.clone(), next.max(since));
                        if count < ENTRIES_PER_ANSWER {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!(node = %id, %error, "account exchange");
                        break;
                    }
                }
            }
        }
    }

    async fn fetch_accounts(&self, node: &Id, endpoints: &[Endpoint], since: i64) -> Result<(usize, i64), String> {
        let body = self.signed(node, "accounts", json!({"since": since}))?;
        let answer = self.peer_post_any(endpoints, "/v4/node/accounts", body).await?.ok()?;
        let list = answer.get("entries").and_then(Value::as_array).ok_or("entries missing")?;
        if list.len() > ENTRIES_PER_ANSWER {
            return Err("too many entries".into());
        }
        let next = answer.get("next").and_then(Value::as_i64).ok_or("next missing")?;
        for item in list {
            if item.to_string().len() > MAX_ENTRY_BYTES {
                continue;
            }
            match Entry::from_value(item) {
                Ok(entry) => {
                    if let Err(error) = self.apply_entry(&entry).await {
                        tracing::debug!(account = %entry.account(), error = %error.message, "account entry refused");
                    }
                }
                Err(error) => tracing::debug!(%error, "account entry malformed"),
            }
        }
        Ok((list.len(), next))
    }
}
