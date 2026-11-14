//! "Angemeldet bleiben" (docs/11 §16): after a passkey ceremony with `"remember": true` the entrance hands out a
//! remember key as an `HttpOnly` cookie (path of its public address, 30 days); `POST /v4/login/resume` trades it for a
//! new session and a new key (the old one is used up), `POST /v4/login/logout` throws it away. The node keeps only the
//! key's hash, bound to the account and the device (passkey) - a removed device or a recovery ends it.

use bridge_core::Id;
use bridge_core::crypto::sha256;
use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::json::parse_strict;
use bridge_core::login::Account;
use bridge_core::webauthn::relying_party;
use bridge_transport::{Method, Request, Response};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};

use crate::login::MAX_LOGIN_BODY;
use crate::{Node, NodeError, NodeResult};

/// The cookie's name.
pub(crate) const COOKIE: &str = "bl_remember";
/// How long a remember key holds.
pub(crate) const REMEMBER_MS: i64 = 30 * 24 * 3600 * 1000;
/// The paths answered here (they may set or clear the cookie).
pub(crate) const PATHS: [&str; 6] = [
    "/v4/login/assert",
    "/v4/login/register",
    "/v4/login/recover",
    "/v4/login/pair/wait",
    "/v4/login/resume",
    "/v4/login/logout",
];

/// The value of the cookie `bl_remember` in a `Cookie` header (exactly 32 bytes as Base64url), if any.
fn remember_key(cookies: Option<&str>) -> Option<[u8; 32]> {
    cookies?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .and_then(|(_, value)| b64_fixed::<32>(value.trim(), "cookie").ok())
}

impl Node {
    /// The path of the node's public `https` address (`/bridge4/testnetz/`), `/` if it has none.
    fn cookie_path(&self) -> String {
        let url = self.inner.card.urls().iter().find(|url| relying_party(url).is_some()).cloned().unwrap_or_default();
        let after = url.split_once("://").map_or("", |(_, rest)| rest);
        let path = after.find('/').map_or("/", |at| &after[at..]);
        let clean = path.split(['?', '#']).next().unwrap_or("/");
        if clean.ends_with('/') { clean.to_owned() } else { format!("{clean}/") }
    }

    fn set_cookie(&self, key: Option<&[u8; 32]>) -> String {
        let path = self.cookie_path();
        match key {
            Some(key) => format!(
                "{COOKIE}={}; Path={path}; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
                b64(key),
                REMEMBER_MS / 1000
            ),
            None => format!("{COOKIE}=; Path={path}; Max-Age=0; HttpOnly; Secure; SameSite=Strict"),
        }
    }

    /// A new remember key for `account`'s device `cred_id`; returns its cookie.
    async fn remember(&self, account: &str, cred_id: Vec<u8>, now: i64) -> NodeResult<String> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let (net, hash, account) = (self.inner.net.to_string(), sha256(&key), account.to_owned());
        self.blocking(move |store| {
            store.login_remember_add(&net, &hash, &account, &cred_id, now.saturating_add(REMEMBER_MS), now)
        })
        .await?;
        Ok(self.set_cookie(Some(&key)))
    }

    /// The paths of [`PATHS`]: the login answer as usual, plus the cookie (docs/11 §16).
    pub(crate) async fn login_with_cookie(&self, request: Request, now: i64) -> Response {
        let path = request.path.clone();
        let result = match path.as_str() {
            "/v4/login/resume" => self.resume(&request, now).await,
            "/v4/login/logout" => self.logout(&request).await,
            _ => self.ceremony(request, now).await,
        };
        match result {
            Ok((body, cookie)) => {
                let response = Response::ok(body.to_string().into_bytes());
                match cookie {
                    Some(cookie) => response.with_header("set-cookie", cookie),
                    None => response,
                }
            }
            Err((error, clear)) => {
                let response = error.to_response();
                if clear { response.with_header("set-cookie", self.set_cookie(None)) } else { response }
            }
        }
    }

    /// A ceremony (`assert`, `register`, `recover`, `pair/wait`): with `"remember": true` and a session in the answer,
    /// a remember key for the device that just proved itself.
    async fn ceremony(&self, request: Request, now: i64) -> Result<(Value, Option<String>), (NodeError, bool)> {
        let asked = parse_strict(&request.body, MAX_LOGIN_BODY).ok();
        let remember = asked.as_ref().and_then(|body| body.get("remember")).and_then(Value::as_bool) == Some(true);
        // The passkey of the ceremony, as the node checked it.
        let request_cred = asked.as_ref().and_then(|body| {
            body.get("credential_id")
                .or_else(|| body.get("credential").and_then(|credential| credential.get("id")))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        let path = request.path.clone();
        let bytes = self.route_login(&request, now).await.map_err(|error| (error, false))?;
        let answer: Value = serde_json::from_slice(&bytes).map_err(|_| (NodeError::unavailable(), false))?;
        let account = answer.get("account").and_then(Value::as_str);
        let has_session = answer.get("session").and_then(Value::as_str).is_some();
        let cred = if path == "/v4/login/pair/wait" {
            answer.get("credential_id").and_then(Value::as_str).map(str::to_owned)
        } else {
            request_cred
        };
        let cred = cred.and_then(|text| bridge_core::encoding::b64_var(&text, "credential", 1024).ok());
        let cookie = match (remember && has_session, account, cred) {
            (true, Some(account), Some(cred)) => {
                Some(self.remember(account, cred, now).await.map_err(|error| (error, false))?)
            }
            _ => None,
        };
        Ok((answer, cookie))
    }

    /// `POST /v4/login/resume`: the remember key of the cookie for a new session and a new key.
    async fn resume(&self, request: &Request, now: i64) -> Result<(Value, Option<String>), (NodeError, bool)> {
        if request.method != Method::Post || self.network().is_none() {
            return Err((NodeError::not_found(), false));
        }
        self.inner.guard.admit_read(request.peer, now).map_err(|refused| (NodeError::from(refused), false))?;
        if request.fetch_site.as_deref().is_some_and(|site| site != "same-origin") {
            return Err((NodeError::forbidden("only from the page of this entrance"), false));
        }
        self.login_ready(now).map_err(|error| (error, false))?;
        let gone = || (NodeError::new(401, "UNAUTHORIZED", "not remembered (any more)"), true);
        let key = remember_key(request.cookies.as_deref()).ok_or_else(gone)?;
        let (net, hash) = (self.inner.net.to_string(), sha256(&key));
        let (account_text, cred_id) = self
            .blocking(move |store| store.login_remember_take(&net, &hash, now))
            .await
            .map_err(|error| (error, false))?
            .ok_or_else(gone)?;
        let account_id = Id::parse(&account_text).map_err(|_| gone())?;
        let account: Account = self.account(&account_id).await.map_err(|error| (error, false))?.ok_or_else(gone)?;
        if account.device(&cred_id).is_none() {
            return Err(gone()); // the device was removed, or the account recovered
        }
        let session = self.session_token(&account.id, now).map_err(|error| (error, false))?;
        let cookie = self.remember(account.id.as_str(), cred_id.clone(), now).await.map_err(|error| (error, false))?;
        let answer = json!({
            "account": account.id.as_str(), "name": account.name, "session": session, "credential_id": b64(&cred_id),
        });
        Ok((answer, Some(cookie)))
    }

    /// `POST /v4/login/logout`: forgets the remember key and clears the cookie.
    async fn logout(&self, request: &Request) -> Result<(Value, Option<String>), (NodeError, bool)> {
        if request.method != Method::Post || self.network().is_none() {
            return Err((NodeError::not_found(), false));
        }
        if let Some(key) = remember_key(request.cookies.as_deref()) {
            let (net, hash) = (self.inner.net.to_string(), sha256(&key));
            let _ = self.blocking(move |store| store.login_remember_take(&net, &hash, i64::MAX)).await;
        }
        Ok((json!({"ok": true}), Some(self.set_cookie(None))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cookie_is_found_only_in_its_exact_form() {
        let key = [7u8; 32];
        let value = b64(&key);
        assert_eq!(remember_key(Some(&format!("a=1; {COOKIE}={value}; b=2"))), Some(key));
        for bad in [
            String::new(),
            format!("{COOKIE}x={value}"),
            format!("{COOKIE}={value}A"),
            format!("{COOKIE}="),
            "a=1".to_owned(),
        ] {
            assert_eq!(remember_key(Some(&bad)), None, "{bad}");
        }
        assert_eq!(remember_key(None), None);
    }
}
