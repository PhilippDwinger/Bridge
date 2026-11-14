//! The owner backup (docs/12 §10): the body of a `backup` statement - a log entry signed by the net key or an admin
//! with the right `rules` that names the app holding the encrypted backup of the owner's keys. The newest one in
//! effect counts; a new PC finds the backup with the 24 words and one address of the network.

use bridge_core::{Id, Identity, Statement};
use serde_json::{Value, json};

use crate::error::{NetError, NetResult};
use crate::statements::{Body, Kind, fields, id, object};

/// Longest lifetime of a `backup` statement (a year, like the app version it points to, and a day more).
pub const MAX_BACKUP_LIFETIME_MS: i64 = bridge_core::app::MAX_APP_LIFETIME_MS + 24 * 3600 * 1000;

/// The body of a `backup` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    /// The app whose only file is the encrypted backup.
    pub app: Id,
}

impl Backup {
    /// Signs it as `admin` for `iat` .. `exp` (at most [`MAX_BACKUP_LIFETIME_MS`]).
    pub fn sign_backup(&self, net: &Id, iat: i64, exp: i64, admin: &Identity) -> NetResult<Statement> {
        if exp.saturating_sub(iat) > MAX_BACKUP_LIFETIME_MS {
            return Err(NetError::format("backup: at most a year"));
        }
        self.sign(net, iat, exp, admin)
    }
}

impl Body for Backup {
    const KIND: Kind = Kind::Backup;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "backup")?;
        fields(object, &["app"], &[], "backup")?;
        Ok(Self { app: id(object, "app")? })
    }

    fn to_body(&self) -> NetResult<Value> {
        crate::statements::checked::<Self>(json!({"app": self.app.as_str()}))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn strict_body() -> NetResult<()> {
        let (app, admin, net) =
            (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
        let body = Backup { app: app.id().clone() };
        let statement = body.sign_backup(net.id(), 1_000, 2_000, &admin)?;
        assert_eq!(Backup::from_statement(&statement)?, body);
        assert!(body.sign_backup(net.id(), 0, MAX_BACKUP_LIFETIME_MS + 1, &admin).is_err(), "too long");
        for bad in [json!({}), json!({"app": "x"}), json!({"app": app.id().as_str(), "more": 1}), json!([])] {
            assert!(Backup::from_body(&bad).is_err(), "{bad}");
        }
        Ok(())
    }
}
