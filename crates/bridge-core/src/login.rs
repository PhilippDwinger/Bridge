//! Bridge Login (docs/11 §9, ADR 0027): accounts as **self-certifying entries** and the tokens a node issues.
//!
//! - **Account** = ID, display name (not unique), one passkey, the hash of its recovery code, version.
//!   `account = H("bridge4/login/account" ‖ key ‖ recovery hash)` - nobody can make an entry for an ID without the key
//!   and the code that went into it.
//! - **Entries**: `create` (version 1) and `recover` (version + 1: a new passkey and a new code hash, proved by the
//!   old code in clear - that code is worthless afterwards). Every storage node checks every entry itself; a node can
//!   not take an account over (only refuse service).
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
use crate::webauthn::{Credential, MAX_CREDENTIAL_ID, MAX_SPKI};

/// Longest display name.
pub const MAX_NAME_CHARS: usize = 40;
/// Bytes of a recovery code (120 bits - 24 characters of Base32).
pub const RECOVERY_CODE_BYTES: usize = 15;
/// Largest entry.
pub const MAX_ENTRY_BYTES: usize = 8 * 1024;
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

/// An account as the entries made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Its ID.
    pub id: Id,
    /// Its display name.
    pub name: String,
    /// Its passkey.
    pub credential: Credential,
    /// The hash of its recovery code.
    pub recovery: [u8; 32],
    /// Version (1 = created).
    pub version: u32,
    /// Created (ms).
    pub created: i64,
    /// Last entry (ms).
    pub updated: i64,
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
    /// A new passkey and recovery code, proved by the old code.
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
}

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
                let version = u32::try_from(number("v")?)
                    .ok()
                    .filter(|v| *v >= 2)
                    .ok_or_else(|| CoreError::format("entry: recover is version 2 or more"))?;
                let credential = credential_of(object.get("cred"))?;
                let code = b64_var(text("code")?, "code", RECOVERY_CODE_BYTES)?;
                if code.len() != RECOVERY_CODE_BYTES {
                    return Err(CoreError::format("entry: code has 15 bytes"));
                }
                let recovery = b64_fixed::<32>(text("recovery")?, "recovery")?;
                Ok(Self::Recover { account, version, credential, code, recovery, at })
            }
            _ => Err(CoreError::format("entry: op create or recover")),
        }
    }

    /// The JSON value (what [`Entry::from_value`] reads).
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Create { account, name, credential, recovery, at } => json!({
                "op": "create", "v": 1, "account": account.as_str(), "name": name,
                "cred": credential_value(credential), "recovery": b64(recovery), "at": at,
            }),
            Self::Recover { account, version, credential, code, recovery, at } => json!({
                "op": "recover", "v": version, "account": account.as_str(),
                "cred": credential_value(credential), "code": b64(code), "recovery": b64(recovery), "at": at,
            }),
        }
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        canonical(&self.to_value())
    }

    /// The account it is about.
    #[must_use]
    pub fn account(&self) -> &Id {
        match self {
            Self::Create { account, .. } | Self::Recover { account, .. } => account,
        }
    }

    /// Its version.
    #[must_use]
    pub fn version(&self) -> u32 {
        match self {
            Self::Create { .. } => 1,
            Self::Recover { version, .. } => *version,
        }
    }

    /// The passkey it brings.
    #[must_use]
    pub fn credential(&self) -> &Credential {
        match self {
            Self::Create { credential, .. } | Self::Recover { credential, .. } => credential,
        }
    }

    /// Applies the entry to the account as it is (`None`: not known yet) - or why not. `create` only for an unknown
    /// account; `recover` only as the next version and with the code that belongs to the current hash.
    pub fn apply(&self, current: Option<&Account>) -> CoreResult<Account> {
        match (self, current) {
            (Self::Create { account, name, credential, recovery, at }, None) => Ok(Account {
                id: account.clone(),
                name: name.clone(),
                credential: credential.clone(),
                recovery: *recovery,
                version: 1,
                created: *at,
                updated: *at,
            }),
            (Self::Recover { account, version, credential, code, recovery, at }, Some(current)) => {
                if &current.id != account || *version != current.version.saturating_add(1) {
                    return Err(CoreError::format("entry: not the next version of this account"));
                }
                if recovery_hash(code) != current.recovery {
                    return Err(CoreError::BadSignature);
                }
                if *recovery == current.recovery {
                    return Err(CoreError::format("entry: a new recovery code is needed"));
                }
                Ok(Account {
                    credential: credential.clone(),
                    recovery: *recovery,
                    version: *version,
                    updated: *at,
                    ..current.clone()
                })
            }
            (Self::Create { .. }, Some(_)) => Err(CoreError::format("entry: account exists")),
            (Self::Recover { .. }, None) => Err(CoreError::format("entry: unknown account")),
        }
    }
}

impl Account {
    /// The stored form: the entry fields of the current state (`create`-like) plus version and times.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "account": self.id.as_str(), "name": self.name, "cred": credential_value(&self.credential),
            "recovery": b64(&self.recovery), "v": self.version, "created": self.created, "updated": self.updated,
        })
    }

    /// From the stored form (checked like an entry).
    pub fn from_value(value: &Value) -> CoreResult<Self> {
        let object = value.as_object().ok_or_else(|| CoreError::format("account"))?;
        exact(object, &["account", "name", "cred", "recovery", "v", "created", "updated"])?;
        let text = |name: &str| object.get(name).and_then(Value::as_str).ok_or_else(|| CoreError::format(name));
        let number = |name: &str| object.get(name).and_then(Value::as_i64).ok_or_else(|| CoreError::format(name));
        let name = text("name")?.to_owned();
        check_name(&name)?;
        Ok(Self {
            id: Id::parse(text("account")?)?,
            name,
            credential: credential_of(object.get("cred"))?,
            recovery: b64_fixed::<32>(text("recovery")?, "recovery")?,
            version: u32::try_from(number("v")?).map_err(|_| CoreError::format("v"))?,
            created: number("created")?,
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
        assert_eq!((recovered.version, recovered.credential.id.clone(), recovered.created), (2, vec![2; 8], 10));
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
        assert!(Entry::parse(&[b'{'; 9000]).is_err(), "too large");
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
