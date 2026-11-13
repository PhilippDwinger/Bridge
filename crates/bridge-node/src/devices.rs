//! Several devices per Bridge Login account (docs/11 §14): the list, removing a device, and adding one with a
//! **pairing code** (or its QR code) shown on a device that is logged in. All state here is in RAM and bounded; what
//! counts are the account entries `add` and `remove`, signed by a passkey of the account - every storage node checks
//! that signature itself (`bridge-core::login`).
//!
//! Adding (A: logged in, B: the new device):
//! 1. A: `pair/start {session, link}` → code (8 characters without look-alikes, 5 minutes, used once) and the QR code
//!    of `<link>#koppeln=<code>` (`link`: a page of this node's own public origin - the hash never reaches a server).
//! 2. B: `pair/join {code, label}` → ticket, challenge, account name. Wrong codes: at most [`MAX_PAIR_FAILURES`] per
//!    address in 10 minutes.
//! 3. B: `pair/offer {ticket, credential, client_data, auth_data}` (WebAuthn create with that challenge) → check
//!    digits (3 digits from the ticket and the new passkey).
//! 4. A: `pair/status {session, code}` → the waiting device (label, check digits) and the challenge of the `add`
//!    entry; `pair/approve {session, code, credential_id, client_data, auth_data, signature}` → the entry goes in.
//!    `pair/cancel {session, code}` refuses it.
//! 5. B: `pair/wait {ticket}` → its session, once approved.
//!
//! Removing: `remove/prepare {session, target}` → the challenge of the `remove` entry; `remove {session,
//! credential_id, client_data, auth_data, signature}` → the entry goes in (the last device stays).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use bridge_core::Id;
use bridge_core::crypto::sha256_parts;
use bridge_core::encoding::{b64, b64_fixed, b64_var};
use bridge_core::login::{Account, Approval, Entry, MAX_DEVICES, Session, check_name, token_statement};
use bridge_core::webauthn::{
    MAX_AUTH_DATA, MAX_CLIENT_DATA, MAX_CREDENTIAL_ID, MAX_SIGNATURE, check_auth_data, check_client_data,
};
use bridge_transport::Request;
use qrcodegen::{QrCode, QrCodeEcc};
use rand_core::{OsRng, RngCore};
use serde_json::{Map, Value, json};

use crate::login::{MAX_LOGIN_BODY, credential_of, field};
use crate::{Node, NodeError, NodeResult, body_object, lock};

/// How long a pairing code holds.
const PAIR_MS: i64 = 5 * 60 * 1000;
/// How long a prepared `remove` waits for its approval.
const PREPARED_MS: i64 = 2 * 60 * 1000;
/// Most pairings and prepared entries at once.
const MAX_OPEN: usize = 10_000;
/// Wrong codes per address in [`FAILURE_WINDOW_MS`].
pub(crate) const MAX_PAIR_FAILURES: u32 = 5;
const FAILURE_WINDOW_MS: i64 = 10 * 60 * 1000;
/// Addresses whose wrong codes are counted at once.
const MAX_TRACKED: usize = 10_000;
/// Longest page link in a QR code.
const MAX_LINK: usize = 512;
/// Characters of a pairing code: no 0/O, 1/I/L.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// Length of a pairing code.
const CODE_LEN: usize = 8;

/// One device being added.
struct Pairing {
    account: Id,
    expires: i64,
    ticket: Option<[u8; 16]>,
    label: String,
    entry: Option<Entry>,
    check: Option<String>,
    done: Option<Value>,
    cancelled: bool,
}

#[derive(Default)]
struct Open {
    pairings: HashMap<String, Pairing>,
    tickets: HashMap<[u8; 16], String>,
    failures: HashMap<IpAddr, (i64, u32)>,
    prepared: HashMap<[u8; 32], (Id, Entry, i64)>,
}

impl Open {
    fn prune(&mut self, now: i64) {
        let gone: Vec<String> =
            self.pairings.iter().filter(|(_, pairing)| pairing.expires <= now).map(|(code, _)| code.clone()).collect();
        for code in gone {
            self.drop_pairing(&code);
        }
        self.prepared.retain(|_, (_, _, expires)| *expires > now);
        self.failures.retain(|_, (start, _)| now.saturating_sub(*start) < FAILURE_WINDOW_MS);
    }

    fn drop_pairing(&mut self, code: &str) {
        if let Some(ticket) = self.pairings.remove(code).and_then(|pairing| pairing.ticket) {
            self.tickets.remove(&ticket);
        }
    }

    fn by_ticket(&mut self, ticket: &[u8; 16]) -> Option<(String, &mut Pairing)> {
        let code = self.tickets.get(ticket)?.clone();
        let pairing = self.pairings.get_mut(&code)?;
        Some((code, pairing))
    }
}

/// What a node keeps for adding and removing devices.
#[derive(Default)]
pub(crate) struct DeviceState {
    open: Mutex<Open>,
}

/// A pairing code as typed (spaces, dashes, lower case) in its stored form - or `None`.
fn normalize(code: &str) -> Option<String> {
    let clean: String =
        code.chars().filter(|c| !matches!(c, '-' | ' ')).map(|c| c.to_ascii_uppercase()).take(CODE_LEN + 1).collect();
    (clean.len() == CODE_LEN && clean.bytes().all(|b| CODE_ALPHABET.contains(&b))).then_some(clean)
}

fn new_code() -> String {
    let mut code = String::with_capacity(CODE_LEN);
    let limit = (256 / CODE_ALPHABET.len() * CODE_ALPHABET.len()) as u8;
    while code.len() < CODE_LEN {
        let mut byte = [0u8; 1];
        OsRng.fill_bytes(&mut byte);
        if byte[0] < limit {
            code.push(char::from(CODE_ALPHABET[usize::from(byte[0]) % CODE_ALPHABET.len()]));
        }
    }
    code
}

fn shown(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

/// Three check digits both devices show: from the ticket and the new passkey.
fn check_digits(ticket: &[u8; 16], key: &[u8]) -> String {
    let hash = sha256_parts(&[b"bridge4/login/pair\n", ticket, key]);
    format!("{:03}", u16::from_be_bytes([hash[0], hash[1]]) % 1000)
}

fn with_approval(mut entry: Entry, signed: Approval) -> Entry {
    if let Entry::Add { approval, .. } | Entry::Remove { approval, .. } = &mut entry {
        *approval = signed;
    }
    entry
}

fn unsigned() -> Approval {
    Approval { credential_id: Vec::new(), client_data: Vec::new(), auth_data: Vec::new(), signature: Vec::new() }
}

fn devices_of(account: &Account) -> Value {
    let devices: Vec<Value> = account
        .devices
        .iter()
        .map(|device| json!({"id": b64(&device.credential.id), "label": device.label, "added": device.added}))
        .collect();
    json!({"name": account.name, "devices": devices})
}

/// The QR code of `text` as rows of `0`/`1` (error correction M).
fn qr(text: &str) -> NodeResult<Value> {
    let code =
        QrCode::encode_text(text, QrCodeEcc::Medium).map_err(|_| NodeError::bad_format("link too long for a QR"))?;
    let size = code.size();
    let mut modules = String::with_capacity(usize::try_from(size * size).unwrap_or(0));
    for y in 0..size {
        for x in 0..size {
            modules.push(if code.get_module(x, y) { '1' } else { '0' });
        }
    }
    Ok(json!({"size": size, "modules": modules}))
}

impl Node {
    /// `/v4/login/devices`, `/v4/login/remove…`, `/v4/login/pair/…` (see module docs).
    pub(crate) async fn route_devices(&self, path: &str, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        self.login_ready(now)?;
        let body = body_object(&request.body, MAX_LOGIN_BODY)?;
        let answer = match path {
            "/v4/login/devices" => devices_of(&self.session_account(&body, now).await?),
            "/v4/login/remove/prepare" => self.remove_prepare(&body, now).await?,
            "/v4/login/remove" => self.remove_device(&body, now).await?,
            "/v4/login/pair/start" => self.pair_start(&body, now).await?,
            "/v4/login/pair/join" => self.pair_join(&body, request.peer, now).await?,
            "/v4/login/pair/offer" => self.pair_offer(&body, now).await?,
            "/v4/login/pair/status" => self.pair_status(&body, now).await?,
            "/v4/login/pair/approve" => self.pair_approve(&body, now).await?,
            "/v4/login/pair/cancel" => self.pair_cancel(&body, now).await?,
            "/v4/login/pair/wait" => self.pair_wait(&body, now)?,
            _ => return Err(NodeError::not_found()),
        };
        Ok(answer.to_string().into_bytes())
    }

    /// The account of the session in `body` (issued by a storage node of the network, not expired).
    async fn session_account(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Account> {
        let statement = token_statement(field(body, "session")?).map_err(|_| NodeError::no_session())?;
        let session = Session::from_statement(&statement, &self.inner.net, now).map_err(|_| NodeError::no_session())?;
        self.verify_issuer(&statement, &session.node, now)?;
        self.account(&session.account).await?.ok_or_else(NodeError::no_session)
    }

    /// The WebAuthn get ceremony of an approval at this entrance: type, exactly `challenge`, this origin and RP ID.
    fn approval_of(&self, body: &Map<String, Value>, challenge: &[u8; 32], now: i64) -> NodeResult<Approval> {
        let (rp_id, origin) = self.login_ready(now)?;
        let approval = Approval {
            credential_id: b64_var(field(body, "credential_id")?, "credential_id", MAX_CREDENTIAL_ID)?,
            client_data: b64_var(field(body, "client_data")?, "client_data", MAX_CLIENT_DATA)?,
            auth_data: b64_var(field(body, "auth_data")?, "auth_data", MAX_AUTH_DATA)?,
            signature: b64_var(field(body, "signature")?, "signature", MAX_SIGNATURE)?,
        };
        check_client_data(&approval.client_data, "webauthn.get", challenge, &origin)?;
        check_auth_data(&approval.auth_data, &rp_id)?;
        Ok(approval)
    }

    async fn remove_prepare(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let account = self.session_account(body, now).await?;
        let target = b64_var(field(body, "target")?, "target", MAX_CREDENTIAL_ID)?;
        if account.device(&target).is_none() {
            return Err(NodeError::bad_format("no such device"));
        }
        if account.devices.len() < 2 {
            return Err(NodeError::forbidden("the last device stays"));
        }
        let entry = Entry::Remove {
            account: account.id.clone(),
            version: account.version.saturating_add(1),
            target,
            at: now,
            approval: unsigned(),
        };
        let challenge = entry.approval_challenge()?;
        let mut open = lock(&self.inner.login.devices.open);
        open.prune(now);
        if open.prepared.len() >= MAX_OPEN {
            return Err(NodeError { retry_after: Some(10), ..NodeError::new(429, "RATE_LIMITED", "too many at once") });
        }
        open.prepared.insert(challenge, (account.id, entry, now.saturating_add(PREPARED_MS)));
        Ok(json!({"challenge": b64(&challenge)}))
    }

    async fn remove_device(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let account = self.session_account(body, now).await?;
        let client = b64_var(field(body, "client_data")?, "client_data", MAX_CLIENT_DATA)?;
        let challenge = crate::login::challenge_of(&client)?;
        let prepared = lock(&self.inner.login.devices.open).prepared.remove(&challenge);
        let Some((_, entry, _)) = prepared.filter(|(owner, _, expires)| *owner == account.id && *expires > now) else {
            return Err(NodeError::forbidden("nothing prepared for this approval"));
        };
        let approval = self.approval_of(body, &challenge, now)?;
        let next = self.apply_entry(&with_approval(entry, approval)).await?;
        Ok(devices_of(&next))
    }

    async fn pair_start(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let account = self.session_account(body, now).await?;
        if account.devices.len() >= MAX_DEVICES {
            return Err(NodeError::forbidden("at most 8 devices - remove one first"));
        }
        let (_, origin) = self.login_ready(now)?;
        let link = field(body, "link")?;
        let fits = link.len() <= MAX_LINK
            && link.strip_prefix(origin.as_str()).is_some_and(|rest| rest.starts_with('/'))
            && link.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'#' | b'"' | b'<' | b'>' | b'\\' | b'`'));
        if !fits {
            return Err(NodeError::bad_format("link: a page of this entrance"));
        }
        let code = new_code();
        let picture = qr(&format!("{link}#koppeln={}", shown(&code)))?;
        let mut open = lock(&self.inner.login.devices.open);
        open.prune(now);
        let earlier: Vec<String> =
            open.pairings.iter().filter(|(_, p)| p.account == account.id).map(|(code, _)| code.clone()).collect();
        for code in earlier {
            open.drop_pairing(&code);
        }
        if open.pairings.len() >= MAX_OPEN {
            return Err(NodeError { retry_after: Some(10), ..NodeError::new(429, "RATE_LIMITED", "too many at once") });
        }
        let expires = now.saturating_add(PAIR_MS);
        open.pairings.insert(
            code.clone(),
            Pairing {
                account: account.id,
                expires,
                ticket: None,
                label: String::new(),
                entry: None,
                check: None,
                done: None,
                cancelled: false,
            },
        );
        Ok(json!({"code": shown(&code), "exp": expires, "qr": picture}))
    }

    async fn pair_join(&self, body: &Map<String, Value>, peer: IpAddr, now: i64) -> NodeResult<Value> {
        let label = field(body, "label")?.trim().to_owned();
        check_name(&label)?;
        let (account, ticket) = {
            let mut open = lock(&self.inner.login.devices.open);
            open.prune(now);
            if open.failures.get(&peer).is_some_and(|(_, count)| *count >= MAX_PAIR_FAILURES) {
                return Err(NodeError {
                    retry_after: Some(600),
                    ..NodeError::new(429, "RATE_LIMITED", "too many wrong codes - wait 10 minutes")
                });
            }
            let code = normalize(field(body, "code")?);
            let found = code.as_ref().and_then(|code| {
                open.pairings.get(code).filter(|p| p.ticket.is_none() && !p.cancelled).map(|p| p.account.clone())
            });
            let (Some(code), Some(account)) = (code, found) else {
                if open.failures.len() < MAX_TRACKED || open.failures.contains_key(&peer) {
                    let entry = open.failures.entry(peer).or_insert((now, 0));
                    entry.1 = entry.1.saturating_add(1);
                }
                return Err(NodeError::forbidden("code unknown, used or expired"));
            };
            let mut ticket = [0u8; 16];
            OsRng.fill_bytes(&mut ticket);
            if let Some(pairing) = open.pairings.get_mut(&code) {
                pairing.ticket = Some(ticket);
                pairing.label = label;
            }
            open.tickets.insert(ticket, code);
            (account, ticket)
        };
        let challenge = self.new_challenge(now)?;
        let name = self.account(&account).await?.map(|account| account.name).unwrap_or_default();
        Ok(json!({"ticket": b64(&ticket), "challenge": b64(&challenge), "name": name}))
    }

    async fn pair_offer(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let ticket = b64_fixed::<16>(field(body, "ticket")?, "ticket")?;
        let credential = credential_of(body.get("credential"))?;
        self.check_ceremony(body, "webauthn.create", now)?;
        let (account, label) = {
            let mut open = lock(&self.inner.login.devices.open);
            open.prune(now);
            let (_, pairing) = open
                .by_ticket(&ticket)
                .filter(|(_, p)| p.entry.is_none() && !p.cancelled)
                .ok_or_else(|| NodeError::forbidden("pairing unknown or expired"))?;
            (pairing.account.clone(), pairing.label.clone())
        };
        let current = self.account(&account).await?.ok_or_else(|| NodeError::forbidden("account unknown"))?;
        if current.devices.len() >= MAX_DEVICES {
            return Err(NodeError::forbidden("at most 8 devices"));
        }
        if current.device(&credential.id).is_some() {
            return Err(NodeError::forbidden("this passkey is there already"));
        }
        let check = check_digits(&ticket, &credential.key);
        let entry = Entry::Add {
            account,
            version: current.version.saturating_add(1),
            credential,
            label,
            at: now,
            approval: unsigned(),
        };
        let mut open = lock(&self.inner.login.devices.open);
        let (_, pairing) = open.by_ticket(&ticket).ok_or_else(|| NodeError::forbidden("pairing expired"))?;
        pairing.entry = Some(entry);
        pairing.check = Some(check.clone());
        Ok(json!({"check": check}))
    }

    async fn pair_status(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let account = self.session_account(body, now).await?;
        let code = normalize(field(body, "code")?).ok_or_else(|| NodeError::bad_format("code"))?;
        let mut open = lock(&self.inner.login.devices.open);
        open.prune(now);
        let Some(pairing) = open.pairings.get(&code).filter(|p| p.account == account.id) else {
            return Ok(json!({"state": "expired"}));
        };
        Ok(if pairing.cancelled {
            json!({"state": "cancelled"})
        } else if pairing.done.is_some() {
            json!({"state": "done"})
        } else if let (Some(entry), Some(check)) = (&pairing.entry, &pairing.check) {
            json!({"state": "offered", "label": pairing.label, "check": check,
                   "challenge": b64(&entry.approval_challenge()?), "exp": pairing.expires})
        } else if pairing.ticket.is_some() {
            json!({"state": "joined", "exp": pairing.expires})
        } else {
            json!({"state": "waiting", "exp": pairing.expires})
        })
    }

    async fn pair_approve(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let account = self.session_account(body, now).await?;
        let code = normalize(field(body, "code")?).ok_or_else(|| NodeError::bad_format("code"))?;
        let entry = {
            let mut open = lock(&self.inner.login.devices.open);
            open.prune(now);
            open.pairings
                .get(&code)
                .filter(|p| p.account == account.id && p.done.is_none() && !p.cancelled)
                .and_then(|p| p.entry.clone())
                .ok_or_else(|| NodeError::forbidden("no device waits for this code"))?
        };
        let approval = self.approval_of(body, &entry.approval_challenge()?, now)?;
        let next = self.apply_entry(&with_approval(entry, approval)).await?;
        let session = self.session_token(&next.id, now)?;
        if let Some(pairing) = lock(&self.inner.login.devices.open).pairings.get_mut(&code) {
            pairing.done = Some(json!({"account": next.id.as_str(), "name": next.name, "session": session}));
        }
        Ok(devices_of(&next))
    }

    async fn pair_cancel(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let account = self.session_account(body, now).await?;
        let code = normalize(field(body, "code")?).ok_or_else(|| NodeError::bad_format("code"))?;
        let mut open = lock(&self.inner.login.devices.open);
        if let Some(pairing) = open.pairings.get_mut(&code).filter(|p| p.account == account.id && p.done.is_none()) {
            pairing.cancelled = true;
        }
        Ok(json!({"ok": true}))
    }

    fn pair_wait(&self, body: &Map<String, Value>, now: i64) -> NodeResult<Value> {
        let ticket = b64_fixed::<16>(field(body, "ticket")?, "ticket")?;
        let mut open = lock(&self.inner.login.devices.open);
        open.prune(now);
        let Some((code, pairing)) = open.by_ticket(&ticket) else { return Ok(json!({"state": "expired"})) };
        if pairing.cancelled {
            return Ok(json!({"state": "cancelled"}));
        }
        let Some(done) = pairing.done.take() else { return Ok(json!({"state": "waiting"})) };
        open.drop_pairing(&code);
        let mut answer = done;
        if let Some(object) = answer.as_object_mut() {
            object.insert("state".into(), json!("done"));
        }
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_check_digits() {
        let code = new_code();
        assert_eq!(code.len(), CODE_LEN);
        assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
        assert_eq!(normalize(&shown(&code).to_lowercase()), Some(code.clone()));
        assert_eq!(normalize(" k7qx m3pa "), Some("K7QXM3PA".to_owned()));
        for bad in ["K7QX-M3P", "K7QX-M3PA1", "O7QX-M3PA", "I7QX-M3PA", "L7QX-M3PA", "K7QX_M3PA", ""] {
            assert_eq!(normalize(bad), None, "{bad}");
        }
        assert!(!CODE_ALPHABET.iter().any(|b| b"01OIL".contains(b)));
        let digits = check_digits(&[1; 16], b"key");
        assert!(digits.len() == 3 && digits.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(digits, check_digits(&[1; 16], b"key"), "both devices compute the same");
    }

    #[test]
    fn qr_modules() -> NodeResult<()> {
        let picture = qr("https://pc.example/bridge4/netz/web/shop/#koppeln=K7QX-M3PA")?;
        let size = picture["size"].as_u64().unwrap_or(0) as usize;
        assert!(size >= 21 && picture["modules"].as_str().is_some_and(|m| m.len() == size * size));
        Ok(())
    }
}
