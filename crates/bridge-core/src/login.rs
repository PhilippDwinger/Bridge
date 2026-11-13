//! Bridge Login (docs/11 §9, ADR 0027): accounts as **self-certifying entries** and the tokens a node issues.
//!
//! - **Account** = ID, display name (not unique), its passkeys (one per device, at most 8), the hash of its recovery
//!   code, version.
//!   `account = H("bridge4/login/account" ‖ key ‖ recovery hash)` - nobody can make an entry for an ID without the key
//!   and the code that went into it.
//! - **Entries**: `create` (version 1), `recover` (version + 1: a new passkey and a new code hash, proved by the old
//!   code in clear - that code is worthless afterwards, every other device is out), `add` and `remove` (a device more or
//!   less, signed by a passkey of the account: a WebAuthn assertion over [`Entry::approval_challenge`], docs/11 §14).
//!   Every storage node checks every entry itself; a node can not take an account over (only refuse service).
//! - **Tokens** (statements signed by the node that checked the passkey): a **session** (`t: "session"`, at most
//!   12 h, `{account}`) and an **app token** (`t: "login"`, at most 1 h, `{app, user, name}` with `user = H(account,
//!   app)` - one ID per app, no tracking across apps). Sent as Base64url of their canonical bytes.

use serde_json::{Map, Value, json};

use crate::crypto::sha256_parts;
use crate::encoding::{b64, b64_fixed, b64_var};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::json::{canonical, parse_strict};
use crate::statement::{MAX_STATEMENT_BYTES, Statement};
use crate::webauthn::{
    Credential, MAX_AUTH_DATA, MAX_CLIENT_DATA, MAX_CREDENTIAL_ID, MAX_SIGNATURE, MAX_SPKI, check_approval,
};

/// Longest display name.
pub const MAX_NAME_CHARS: usize = 40;
/// Bytes of a recovery code (120 bits - 24 characters of Base32).
pub const RECOVERY_CODE_BYTES: usize = 15;
/// Largest entry (an approval carries client data of up to 4 KiB).
pub const MAX_ENTRY_BYTES: usize = 16 * 1024;
/// Most devices (passkeys) of one account.
pub const MAX_DEVICES: usize = 8;
/// Longest session.
pub const SESSION_LIFETIME_MS: i64 = 12 * 3600 * 1000;
/// Longest app token.
pub const APP_TOKEN_LIFETIME_MS: i64 = 3600 * 1000;
/// Statement kind of a session.
pub const SESSION_KIND: &str = "session";
/// Statement kind of an app token.
pub const APP_TOKEN_KIND: &str = "login";

/// The hash of a recovery code as the network keeps it.
#[must_use]
pub fn recovery_hash(code: &[u8]) -> [u8; 32] {
    sha256_parts(&[b"bridge4/login/recovery\n", code])
}

/// The account ID of a first passkey and recovery hash.
#[must_use]
pub fn account_id(key: &[u8], recovery: &[u8; 32]) -> Id {
    Id::of_digest(&sha256_parts(&[b"bridge4/login/account\n", key, recovery]))
}

/// The user ID an app sees for an account (one per app).
#[must_use]
pub fn app_user(account: &Id, app: &Id) -> Id {
    Id::of_digest(&sha256_parts(&[
        b"bridge4/login/user\n",
        account.as_str().as_bytes(),
        b"\n",
        app.as_str().as_bytes(),
    ]))
}

/// A display name: 1-40 characters, no control characters, no space at the ends.
pub fn check_name(name: &str) -> CoreResult<()> {
    let count = name.chars().count();
    if count == 0 || count > MAX_NAME_CHARS || name.trim() != name || name.chars().any(char::is_control) {
        return Err(CoreError::format("name: 1-40 characters, no control characters"));
    }
    Ok(())
}

/// One passkey of an account, with the name its owner gave the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The passkey.
    pub credential: Credential,
    /// Name of the device (1-40 characters, like a display name).
    pub label: String,
    /// Added (ms).
    pub added: i64,
}

/// An account as the entries made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Its ID.
    pub id: Id,
    /// Its display name.
    pub name: String,
    /// Its passkeys, one per device (1-[`MAX_DEVICES`]).
    pub devices: Vec<Device>,
    /// The hash of its recovery code.
    pub recovery: [u8; 32],
    /// Version (1 = created).
    pub version: u32,
    /// Created (ms).
    pub created: i64,
    /// Last entry (ms).
    pub updated: i64,
}

impl Account {
    /// The device with the passkey `id`.
    #[must_use]
    pub fn device(&self, id: &[u8]) -> Option<&Device> {
        self.devices.iter().find(|device| device.credential.id == id)
    }
}

/// A passkey of the account signing an entry (WebAuthn assertion over [`Entry::approval_challenge`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The signing passkey.
    pub credential_id: Vec<u8>,
    /// Client data JSON.
    pub client_data: Vec<u8>,
    /// Authenticator data.
    pub auth_data: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
}

impl Approval {
    fn to_value(&self) -> Value {
        json!({
            "cred": b64(&self.credential_id), "client_data": b64(&self.client_data),
            "auth_data": b64(&self.auth_data), "sig": b64(&self.signature),
        })
    }

    fn from_value(value: Option<&Value>) -> CoreResult<Self> {
        let object = value.and_then(Value::as_object).ok_or_else(|| CoreError::format("approval"))?;
        exact(object, &["cred", "client_data", "auth_data", "sig"])?;
        let text = |name: &str| object.get(name).and_then(Value::as_str).ok_or_else(|| CoreError::format(name));
        Ok(Self {
            credential_id: b64_var(text("cred")?, "approval.cred", MAX_CREDENTIAL_ID)?,
            client_data: b64_var(text("client_data")?, "approval.client_data", MAX_CLIENT_DATA)?,
            auth_data: b64_var(text("auth_data")?, "approval.auth_data", MAX_AUTH_DATA)?,
            signature: b64_var(text("sig")?, "approval.sig", MAX_SIGNATURE)?,
        })
    }
}

/// One account entry (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A new account.
    Create {
        /// Its ID.
        account: Id,
        /// Display name.
        name: String,
        /// The passkey.
        credential: Credential,
        /// Recovery hash.
        recovery: [u8; 32],
        /// When (ms).
        at: i64,
    },
    /// A new passkey and recovery code, proved by the old code - every other device is out.
    Recover {
        /// The account.
        account: Id,
        /// Its new version.
        version: u32,
        /// The new passkey.
        credential: Credential,
        /// The old recovery code (in clear).
        code: Vec<u8>,
        /// The new recovery hash.
        recovery: [u8; 32],
        /// When (ms).
        at: i64,
    },
    /// A further device, approved by a passkey of the account.
    Add {
        /// The account.
        account: Id,
        /// Its new version.
        version: u32,
        /// The new passkey.
        credential: Credential,
        /// Name of the new device.
        label: String,
        /// When (ms).
        at: i64,
        /// A passkey of the account signs it.
        approval: Approval,
    },
    /// A device less (at least one stays), approved by a passkey of the account.
    Remove {
        /// The account.
        account: Id,
        /// Its new version.
        version: u32,
        /// The passkey that goes.
        target: Vec<u8>,
        /// When (ms).
        at: i64,
        /// A passkey of the account signs it.
        approval: Approval,
    },
}

/// The label of the first device (create, recover).
pub const FIRST_DEVICE: &str = "Gerät 1";

fn credential_value(credential: &Credential) -> Value {
    json!({"id": b64(&credential.id), "alg": credential.alg.cose(), "key": b64(&credential.key)})
}

fn credential_of(value: Option<&Value>) -> CoreResult<Credential> {
    let object = value.and_then(Value::as_object).filter(|o| o.len() == 3).ok_or_else(|| CoreError::format("cred"))?;
    let text = |name: &str| object.get(name).and_then(Value::as_str).ok_or_else(|| CoreError::format("cred"));
    let alg = object.get("alg").and_then(Value::as_i64).ok_or_else(|| CoreError::format("cred: alg"))?;
    Credential::new(
        b64_var(text("id")?, "cred.id", MAX_CREDENTIAL_ID)?,
        alg,
        b64_var(text("key")?, "cred.key", MAX_SPKI)?,
    )
}

fn exact(object: &Map<String, Value>, fields: &[&str]) -> CoreResult<()> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(CoreError::format("entry: exactly the fields of its kind"));
    }
    Ok(())
}

fn later_version(number: i64) -> CoreResult<u32> {
    u32::try_from(number).ok().filter(|v| *v >= 2).ok_or_else(|| CoreError::format("entry: version 2 or more"))
}

impl Entry {
    /// Parses an entry (strict JSON, exactly the fields of its kind, every value checked).
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        Self::from_value(&parse_strict(bytes, MAX_ENTRY_BYTES)?)
    }

    /// From a parsed value (see [`Entry::parse`]).
    pub fn from_value(value: &Value) -> CoreResult<Self> {
        let object = value.as_object().ok_or_else(|| CoreError::format("entry: not an object"))?;
        let text = |name: &str| object.get(name).and_then(Value::as_str).ok_or_else(|| CoreError::format(name));
        let number = |name: &str| object.get(name).and_then(Value::as_i64).ok_or_else(|| CoreError::format(name));
        let account = Id::parse(text("account")?)?;
        let at = number("at")?;
        match text("op")? {
            "create" => {
                exact(object, &["op", "v", "account", "name", "cred", "recovery", "at"])?;
                if number("v")? != 1 {
                    return Err(CoreError::format("entry: create is version 1"));
                }
                let name = text("name")?.to_owned();
                check_name(&name)?;
                let credential = credential_of(object.get("cred"))?;
                let recovery = b64_fixed::<32>(text("recovery")?, "recovery")?;
                if account_id(&credential.key, &recovery) != account {
                    return Err(CoreError::format("entry: account is not H(key, recovery)"));
                }
                Ok(Self::Create { account, name, credential, recovery, at })
            }
            "recover" => {
                exact(object, &["op", "v", "account", "cred", "code", "recovery", "at"])?;
                let version = later_version(number("v")?)?;
                let credential = credential_of(object.get("cred"))?;
                let code = b64_var(text("code")?, "code", RECOVERY_CODE_BYTES)?;
                if code.len() != RECOVERY_CODE_BYTES {
                    return Err(CoreError::format("entry: code has 15 bytes"));
                }
                let recovery = b64_fixed::<32>(text("recovery")?, "recovery")?;
                Ok(Self::Recover { account, version, credential, code, recovery, at })
            }
            "add" => {
                exact(object, &["op", "v", "account", "cred", "label", "at", "approval"])?;
                let version = later_version(number("v")?)?;
                let credential = credential_of(object.get("cred"))?;
                let label = text("label")?.to_owned();
                check_name(&label)?;
                let approval = Approval::from_value(object.get("approval"))?;
                Ok(Self::Add { account, version, credential, label, at, approval })
            }
            "remove" => {
                exact(object, &["op", "v", "account", "target", "at", "approval"])?;
                let version = later_version(number("v")?)?;
                let target = b64_var(text("target")?, "target", MAX_CREDENTIAL_ID)?;
                let approval = Approval::from_value(object.get("approval"))?;
                Ok(Self::Remove { account, version, target, at, approval })
            }
            _ => Err(CoreError::format("entry: op create, recover, add or remove")),
        }
    }

    /// The JSON value (what [`Entry::from_value`] reads).
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut value = self.unsigned_value();
        if let (Self::Add { approval, .. } | Self::Remove { approval, .. }, Some(object)) =
            (self, value.as_object_mut())
        {
            object.insert("approval".into(), approval.to_value());
        }
        value
    }

    /// The value without the approval - what an approving passkey signs (see [`Entry::approval_challenge`]).
    fn unsigned_value(&self) -> Value {
        match self {
            Self::Create { account, name, credential, recovery, at } => json!({
                "op": "create", "v": 1, "account": account.as_str(), "name": name,
                "cred": credential_value(credential), "recovery": b64(recovery), "at": at,
            }),
            Self::Recover { account, version, credential, code, recovery, at } => json!({
                "op": "recover", "v": version, "account": account.as_str(),
                "cred": credential_value(credential), "code": b64(code), "recovery": b64(recovery), "at": at,
            }),
            Self::Add { account, version, credential, label, at, .. } => json!({
                "op": "add", "v": version, "account": account.as_str(), "cred": credential_value(credential),
                "label": label, "at": at,
            }),
            Self::Remove { account, version, target, at, .. } => json!({
                "op": "remove", "v": version, "account": account.as_str(), "target": b64(target), "at": at,
            }),
        }
    }

    /// The challenge an approving passkey signs: `H("bridge4/login/approve\n" ‖ canonical entry without approval)`.
    pub fn approval_challenge(&self) -> CoreResult<[u8; 32]> {
        Ok(sha256_parts(&[b"bridge4/login/approve\n", &canonical(&self.unsigned_value())?]))
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        canonical(&self.to_value())
    }

    /// The account it is about.
    #[must_use]
    pub fn account(&self) -> &Id {
        match self {
            Self::Create { account, .. }
            | Self::Recover { account, .. }
            | Self::Add { account, .. }
            | Self::Remove { account, .. } => account,
        }
    }

    /// Its version.
    #[must_use]
    pub fn version(&self) -> u32 {
        match self {
            Self::Create { .. } => 1,
            Self::Recover { version, .. } | Self::Add { version, .. } | Self::Remove { version, .. } => *version,
        }
    }

    fn approved(&self, current: &Account, approval: &Approval) -> CoreResult<()> {
        let device = current.device(&approval.credential_id).ok_or(CoreError::BadSignature)?;
        check_approval(&approval.client_data, &approval.auth_data, &self.approval_challenge()?)?;
        device.credential.verify_assertion(&approval.auth_data, &approval.client_data, &approval.signature)
    }

    /// Applies the entry to the account as it is (`None`: not known yet) - or why not. `create` only for an unknown
    /// account; every other entry only as the next version: `recover` with the code that belongs to the current hash
    /// (every device but the new one is out), `add` and `remove` signed by a passkey of the account (at most
    /// [`MAX_DEVICES`] devices, at least one stays).
    pub fn apply(&self, current: Option<&Account>) -> CoreResult<Account> {
        let Some(current) = current else {
            return match self {
                Self::Create { account, name, credential, recovery, at } => Ok(Account {
                    id: account.clone(),
                    name: name.clone(),
                    devices: vec![Device { credential: credential.clone(), label: FIRST_DEVICE.into(), added: *at }],
                    recovery: *recovery,
                    version: 1,
                    created: *at,
                    updated: *at,
                }),
                _ => Err(CoreError::format("entry: unknown account")),
            };
        };
        if matches!(self, Self::Create { .. }) {
            return Err(CoreError::format("entry: account exists"));
        }
        if &current.id != self.account() || self.version() != current.version.saturating_add(1) {
            return Err(CoreError::format("entry: not the next version of this account"));
        }
        let mut next = current.clone();
        next.version = self.version();
        match self {
            Self::Create { .. } => return Err(CoreError::format("entry: account exists")), // handled above
            Self::Recover { credential, code, recovery, at, .. } => {
                if recovery_hash(code) != current.recovery {
                    return Err(CoreError::BadSignature);
                }
                if *recovery == current.recovery {
                    return Err(CoreError::format("entry: a new recovery code is needed"));
                }
                next.devices = vec![Device { credential: credential.clone(), label: FIRST_DEVICE.into(), added: *at }];
                next.recovery = *recovery;
                next.updated = *at;
            }
            Self::Add { credential, label, at, approval, .. } => {
                self.approved(current, approval)?;
                if current.devices.len() >= MAX_DEVICES {
                    return Err(CoreError::format("entry: at most 8 devices"));
                }
                if current.device(&credential.id).is_some() {
                    return Err(CoreError::format("entry: this passkey is there already"));
                }
                next.devices.push(Device { credential: credential.clone(), label: label.clone(), added: *at });
                next.updated = *at;
            }
            Self::Remove { target, at, approval, .. } => {
                self.approved(current, approval)?;
                if current.device(target).is_none() {
                    return Err(CoreError::format("entry: no such device"));
                }
                if current.devices.len() < 2 {
                    return Err(CoreError::format("entry: the last device stays"));
                }
                next.devices.retain(|device| device.credential.id != *target);
                next.updated = *at;
            }
        }
        Ok(next)
    }
}

impl Account {
    /// The stored form: the fields of the current state plus version and times.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let devices: Vec<Value> = self
            .devices
            .iter()
            .map(|device| {
                json!({"cred": credential_value(&device.credential), "label": device.label, "added": device.added})
            })
            .collect();
        json!({
            "account": self.id.as_str(), "name": self.name, "devices": devices,
            "recovery": b64(&self.recovery), "v": self.version, "created": self.created, "updated": self.updated,
        })
    }

    /// From the stored form (checked like an entry). The form before several devices (`cred`, one passkey) is read as
    /// one device.
    pub fn from_value(value: &Value) -> CoreResult<Self> {
        let object = value.as_object().ok_or_else(|| CoreError::format("account"))?;
        let text = |name: &str| object.get(name).and_then(Value::as_str).ok_or_else(|| CoreError::format(name));
        let number = |name: &str| object.get(name).and_then(Value::as_i64).ok_or_else(|| CoreError::format(name));
        let created = number("created")?;
        let devices = if object.contains_key("cred") {
            exact(object, &["account", "name", "cred", "recovery", "v", "created", "updated"])?;
            vec![Device { credential: credential_of(object.get("cred"))?, label: FIRST_DEVICE.into(), added: created }]
        } else {
            exact(object, &["account", "name", "devices", "recovery", "v", "created", "updated"])?;
            let list = object
                .get("devices")
                .and_then(Value::as_array)
                .filter(|list| (1..=MAX_DEVICES).contains(&list.len()))
                .ok_or_else(|| CoreError::format("devices: 1-8"))?;
            let mut devices = Vec::with_capacity(list.len());
            for item in list {
                let device = item.as_object().ok_or_else(|| CoreError::format("device"))?;
                exact(device, &["cred", "label", "added"])?;
                let label = device.get("label").and_then(Value::as_str).ok_or_else(|| CoreError::format("label"))?;
                check_name(label)?;
                devices.push(Device {
                    credential: credential_of(device.get("cred"))?,
                    label: label.to_owned(),
                    added: device.get("added").and_then(Value::as_i64).ok_or_else(|| CoreError::format("added"))?,
                });
            }
            devices
        };
        let name = text("name")?.to_owned();
        check_name(&name)?;
        Ok(Self {
            id: Id::parse(text("account")?)?,
            name,
            devices,
            recovery: b64_fixed::<32>(text("recovery")?, "recovery")?,
            version: u32::try_from(number("v")?).map_err(|_| CoreError::format("v"))?,
            created,
            updated: number("updated")?,
        })
    }
}

/// A checked session (the statement's signature is checked by the caller with the issuing node's card).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The account.
    pub account: Id,
    /// The issuing node (the statement's signer).
    pub node: Id,
}

/// A checked app token (signature as for [`Session`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppToken {
    /// The app.
    pub app: Id,
    /// The user ID for this app.
    pub user: Id,
    /// The display name.
    pub name: String,
    /// The issuing node.
    pub node: Id,
}

/// The statement of a token sent as Base64url (at most 64 KiB) - form only.
pub fn token_statement(text: &str) -> CoreResult<Statement> {
    Statement::parse(&b64_var(text, "token", MAX_STATEMENT_BYTES)?)
}

/// The token form of a statement: Base64url of its canonical bytes.
#[must_use]
pub fn token_text(statement: &Statement) -> String {
    b64(statement.canonical_bytes())
}

fn single_signer(statement: &Statement) -> CoreResult<Id> {
    match statement.claimed_signers().as_slice() {
        [node] => Ok((*node).clone()),
        _ => Err(CoreError::format("token: exactly one signer")),
    }
}

fn check_lifetime(statement: &Statement, net: &Id, now: i64, max: i64) -> CoreResult<()> {
    statement.check_time(now)?;
    let (iat, exp) = statement.times();
    if statement.net() != net || exp.saturating_sub(iat) > max {
        return Err(CoreError::format("token: other network or too long"));
    }
    Ok(())
}

impl Session {
    /// Form, kind, network and lifetime of a session statement.
    pub fn from_statement(statement: &Statement, net: &Id, now: i64) -> CoreResult<Self> {
        if statement.kind() != SESSION_KIND {
            return Err(CoreError::format("token: no session"));
        }
        check_lifetime(statement, net, now, SESSION_LIFETIME_MS)?;
        let body = statement.body().as_object().filter(|o| o.len() == 1).ok_or_else(|| CoreError::format("session"))?;
        let account = Id::parse(body.get("account").and_then(Value::as_str).unwrap_or_default())?;
        Ok(Self { account, node: single_signer(statement)? })
    }
}

impl AppToken {
    /// Form, kind, network, lifetime and the user ID (it must belong to the app) of an app token; `app`: the app it
    /// must be for.
    pub fn from_statement(statement: &Statement, net: &Id, app: &Id, now: i64) -> CoreResult<Self> {
        if statement.kind() != APP_TOKEN_KIND {
            return Err(CoreError::format("token: no app token"));
        }
        check_lifetime(statement, net, now, APP_TOKEN_LIFETIME_MS)?;
        let body = statement.body().as_object().filter(|o| o.len() == 3).ok_or_else(|| CoreError::format("token"))?;
        let field = |name: &str| body.get(name).and_then(Value::as_str).unwrap_or_default();
        if Id::parse(field("app"))? != *app {
            return Err(CoreError::format("token: for another app"));
        }
        let name = field("name").to_owned();
        check_name(&name)?;
        Ok(Self { app: app.clone(), user: Id::parse(field("user"))?, name, node: single_signer(statement)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;
    use crate::statement::Draft;

    fn credential(seed: u8) -> CoreResult<Credential> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        spki.extend_from_slice(&key.verifying_key().to_bytes());
        Credential::new(vec![seed; 8], -8, spki)
    }

    #[test]
    fn create_and_recover() -> CoreResult<()> {
        let code = [5u8; RECOVERY_CODE_BYTES];
        let first = credential(1)?;
        let recovery = recovery_hash(&code);
        let account = account_id(&first.key, &recovery);
        let create = Entry::Create {
            account: account.clone(),
            name: "Paddy".into(),
            credential: first.clone(),
            recovery,
            at: 10,
        };
        assert_eq!(Entry::parse(&create.to_bytes()?)?, create, "round trip");
        let state = create.apply(None)?;
        assert_eq!((state.version, state.name.as_str()), (1, "Paddy"));
        assert_eq!(Account::from_value(&state.to_value())?, state);
        assert!(create.apply(Some(&state)).is_err(), "twice");
        // Recovery: the old code, a new passkey and code.
        let new_code = [6u8; RECOVERY_CODE_BYTES];
        let recover = Entry::Recover {
            account: account.clone(),
            version: 2,
            credential: credential(2)?,
            code: code.to_vec(),
            recovery: recovery_hash(&new_code),
            at: 20,
        };
        assert_eq!(Entry::parse(&recover.to_bytes()?)?, recover);
        let recovered = recover.apply(Some(&state))?;
        assert_eq!(
            (recovered.version, recovered.devices[0].credential.id.clone(), recovered.created),
            (2, vec![2; 8], 10)
        );
        assert_eq!(recovered.devices.len(), 1, "every other device is out");
        assert!(recover.apply(Some(&recovered)).is_err(), "the old code is worthless now / wrong version");
        let variant = |version: u32, code: Vec<u8>, recovery: [u8; 32]| -> CoreResult<Entry> {
            Ok(Entry::Recover { account: account.clone(), version, credential: credential(2)?, code, recovery, at: 20 })
        };
        let wrong = variant(2, [9u8; RECOVERY_CODE_BYTES].to_vec(), recovery_hash(&new_code))?;
        assert_eq!(wrong.apply(Some(&state)), Err(CoreError::BadSignature));
        assert!(variant(2, code.to_vec(), recovery)?.apply(Some(&state)).is_err(), "a new code is needed");
        assert!(variant(3, code.to_vec(), recovery_hash(&new_code))?.apply(Some(&state)).is_err(), "no version skip");
        Ok(())
    }

    /// A WebAuthn assertion of the test passkey `seed` (Ed25519) over `entry`'s approval challenge.
    fn approval(seed: u8, entry: &Entry, kind: &str) -> CoreResult<Approval> {
        use ed25519_dalek::Signer as _;
        let challenge = entry.approval_challenge()?;
        let client_data = json!({"type": kind, "challenge": b64(&challenge), "origin": "https://pc.example"})
            .to_string()
            .into_bytes();
        let mut auth_data = crate::crypto::sha256(b"pc.example").to_vec();
        auth_data.extend_from_slice(&[0x05, 0, 0, 0, 0]);
        let mut message = auth_data.clone();
        message.extend_from_slice(&crate::crypto::sha256(&client_data));
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        Ok(Approval { credential_id: vec![seed; 8], client_data, auth_data, signature: key.sign(&message).to_vec() })
    }

    fn add(account: &Id, version: u32, seed: u8, signer: u8, kind: &str) -> CoreResult<Entry> {
        let mut entry = Entry::Add {
            account: account.clone(),
            version,
            credential: credential(seed)?,
            label: format!("Gerät {seed}"),
            at: 30,
            approval: Approval {
                credential_id: Vec::new(),
                client_data: Vec::new(),
                auth_data: Vec::new(),
                signature: Vec::new(),
            },
        };
        let signed = approval(signer, &entry, kind)?;
        if let Entry::Add { approval, .. } = &mut entry {
            *approval = signed;
        }
        Ok(entry)
    }

    fn unsigned() -> Approval {
        Approval { credential_id: Vec::new(), client_data: Vec::new(), auth_data: Vec::new(), signature: Vec::new() }
    }

    fn removal(account: &Id, version: u32, target: u8, signer: u8) -> CoreResult<Entry> {
        let entry =
            |approval| Entry::Remove { account: account.clone(), version, target: vec![target; 8], at: 40, approval };
        let signed = approval(signer, &entry(unsigned()), "webauthn.get")?;
        Ok(entry(signed))
    }

    #[test]
    fn devices_are_added_and_removed_by_a_passkey_of_the_account() -> CoreResult<()> {
        let recovery = recovery_hash(&[5u8; RECOVERY_CODE_BYTES]);
        let first = credential(1)?;
        let account = account_id(&first.key, &recovery);
        let state =
            Entry::Create { account: account.clone(), name: "Paddy".into(), credential: first, recovery, at: 10 }
                .apply(None)?;
        // Attacks: the new passkey signs itself, the wrong ceremony, a changed entry after signing.
        assert_eq!(add(&account, 2, 2, 2, "webauthn.get")?.apply(Some(&state)), Err(CoreError::BadSignature));
        assert!(add(&account, 2, 2, 1, "webauthn.create")?.apply(Some(&state)).is_err());
        let mut changed = add(&account, 2, 2, 1, "webauthn.get")?;
        if let Entry::Add { label, .. } = &mut changed {
            *label = "Fremd".into();
        }
        assert!(changed.apply(Some(&state)).is_err(), "the signature covers the whole entry");
        assert!(add(&account, 3, 2, 1, "webauthn.get")?.apply(Some(&state)).is_err(), "no version skip");
        // Device 2, approved by device 1.
        let second = add(&account, 2, 2, 1, "webauthn.get")?;
        assert_eq!(Entry::parse(&second.to_bytes()?)?, second, "round trip");
        let state = second.apply(Some(&state))?;
        assert_eq!(state.devices.iter().map(|d| d.label.as_str()).collect::<Vec<_>>(), [FIRST_DEVICE, "Gerät 2"]);
        assert_eq!(Account::from_value(&state.to_value())?, state);
        assert!(add(&account, 3, 2, 1, "webauthn.get")?.apply(Some(&state)).is_err(), "the same passkey twice");
        // Device 1 goes, approved by device 2; the last one stays.
        let remove = removal(&account, 3, 1, 2)?;
        assert_eq!(Entry::parse(&remove.to_bytes()?)?, remove);
        let state = remove.apply(Some(&state))?;
        assert_eq!(state.devices.len(), 1);
        assert!(state.device(&[1; 8]).is_none() && state.device(&[2; 8]).is_some());
        assert!(removal(&account, 4, 2, 2)?.apply(Some(&state)).is_err(), "the last device stays");
        assert!(removal(&account, 4, 1, 2)?.apply(Some(&state)).is_err(), "no such device");
        // At most 8 devices.
        let mut state = state;
        for seed in 3..=9u8 {
            state = add(&account, state.version + 1, seed, 2, "webauthn.get")?.apply(Some(&state))?;
        }
        assert_eq!(state.devices.len(), MAX_DEVICES);
        assert!(add(&account, state.version + 1, 10, 2, "webauthn.get")?.apply(Some(&state)).is_err());
        // The stored form from before several devices is read as one device.
        let mut old =
            Entry::Create { account: account.clone(), name: "Alt".into(), credential: credential(1)?, recovery, at: 5 }
                .apply(None)?
                .to_value();
        let cred = old["devices"][0]["cred"].clone();
        if let Some(object) = old.as_object_mut() {
            object.remove("devices");
            object.insert("cred".into(), cred);
        }
        assert_eq!(Account::from_value(&old)?.devices.len(), 1);
        Ok(())
    }

    #[test]
    fn forged_or_odd_entries() -> CoreResult<()> {
        let recovery = recovery_hash(&[5u8; RECOVERY_CODE_BYTES]);
        let first = credential(1)?;
        // Someone else's account ID with an own key: refused when parsed.
        let mut value = Entry::Create {
            account: account_id(&first.key, &recovery),
            name: "X".into(),
            credential: credential(3)?,
            recovery,
            at: 1,
        }
        .to_value();
        assert!(Entry::from_value(&value).is_err());
        value["account"] = json!(account_id(&credential(3)?.key, &recovery).as_str());
        Entry::from_value(&value)?;
        for (field, bad) in [
            ("name", json!("")),
            ("name", json!(" Paddy")),
            ("name", json!("a\nb")),
            ("name", json!("x".repeat(41))),
            ("v", json!(2)),
            ("op", json!("delete")),
            ("recovery", json!("AAAA")),
            ("extra", json!(1)),
        ] {
            let mut odd = value.clone();
            odd[field] = bad;
            assert!(Entry::from_value(&odd).is_err(), "{field}");
        }
        assert!(Entry::parse(&[b'{'; 17_000]).is_err(), "too large");
        Ok(())
    }

    #[test]
    fn tokens() -> CoreResult<()> {
        let node = Identity::from_secret_bytes(&[1u8; 32], &[2u8; 32]);
        let net = Identity::from_secret_bytes(&[3u8; 32], &[4u8; 32]).id().clone();
        let account = account_id(&credential(1)?.key, &recovery_hash(&[5u8; 15]));
        let app = Identity::from_secret_bytes(&[5u8; 32], &[6u8; 32]).id().clone();
        let other = Identity::from_secret_bytes(&[7u8; 32], &[8u8; 32]).id().clone();
        let user = app_user(&account, &app);
        assert_ne!(user, app_user(&account, &other), "one user ID per app");
        let session = Statement::sign(
            &Draft {
                kind: SESSION_KIND,
                net: &net,
                iat: 1000,
                exp: 1000 + SESSION_LIFETIME_MS,
                body: json!({"account": account.as_str()}),
            },
            &node,
        )?;
        let parsed = token_statement(&token_text(&session))?;
        assert_eq!(
            Session::from_statement(&parsed, &net, 2000)?,
            Session { account: account.clone(), node: node.id().clone() }
        );
        assert!(Session::from_statement(&parsed, &other, 2000).is_err(), "other network");
        assert!(Session::from_statement(&parsed, &net, 1000 + SESSION_LIFETIME_MS + 1).is_err(), "expired");
        let long = Statement::sign(
            &Draft {
                kind: SESSION_KIND,
                net: &net,
                iat: 1000,
                exp: 1001 + SESSION_LIFETIME_MS,
                body: json!({"account": account.as_str()}),
            },
            &node,
        )?;
        assert!(Session::from_statement(&long, &net, 2000).is_err(), "too long");
        let token = Statement::sign(
            &Draft {
                kind: APP_TOKEN_KIND,
                net: &net,
                iat: 1000,
                exp: 1000 + APP_TOKEN_LIFETIME_MS,
                body: json!({"app": app.as_str(), "user": user.as_str(), "name": "Paddy"}),
            },
            &node,
        )?;
        let checked = AppToken::from_statement(&token, &net, &app, 2000)?;
        assert_eq!((checked.user, checked.name.as_str()), (user, "Paddy"));
        assert!(AppToken::from_statement(&token, &net, &other, 2000).is_err(), "for another app");
        assert!(Session::from_statement(&token, &net, 2000).is_err(), "an app token is no session");
        assert!(AppToken::from_statement(&session, &net, &app, 2000).is_err(), "a session is no app token");
        assert!(token_statement("!!!").is_err());
        Ok(())
    }
}
