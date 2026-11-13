//! Deleting an app (docs/07 §10, ADR 0028): the body of a `retire` statement - a log entry signed by the app key and
//! its owner (like the versions) that ends the app: while it holds, every version is invalid and the names pointing to
//! the app end. Who may sign and the effects live in the state.

use bridge_core::{Id, Identity, KeyCard, Role, Statement};
use serde_json::{Value, json};

use crate::error::{NetError, NetResult};
use crate::statements::{Body, Kind, card, fields, id, object};

/// Shortest lifetime of a retirement: as long as any version issued before it may hold (one year).
pub const MIN_RETIRE_LIFETIME_MS: i64 = bridge_core::app::MAX_APP_LIFETIME_MS;
/// Longest lifetime of a retirement.
pub const MAX_RETIRE_LIFETIME_MS: i64 = MIN_RETIRE_LIFETIME_MS + 24 * 3600 * 1000;

/// The body of a `retire` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct Retire {
    /// The app.
    pub app: Id,
    /// Its owner (a member).
    pub owner: Id,
    /// The app key's card (role `app`).
    pub card: KeyCard,
    /// The owner's card (role `client` or `node`).
    pub owner_card: KeyCard,
}

impl Retire {
    /// The body for `app`, owned by `owner`.
    pub fn new(app: &Identity, owner: &Identity, at: i64) -> NetResult<Self> {
        Ok(Self {
            app: app.id().clone(),
            owner: owner.id().clone(),
            card: app.key_card(Role::App, None, at)?,
            owner_card: owner.key_card(Role::Client, None, at)?,
        })
    }

    /// The signers it needs, ascending: app key and owner.
    #[must_use]
    pub fn signers(&self) -> Vec<Id> {
        let mut signers = vec![self.app.clone(), self.owner.clone()];
        signers.sort();
        signers
    }

    /// The cards that verify its signatures (from the body).
    #[must_use]
    pub fn cards(&self) -> Vec<&KeyCard> {
        vec![&self.card, &self.owner_card]
    }

    /// Signs it with the app key and the owner; `iat` .. `iat` + [`MIN_RETIRE_LIFETIME_MS`] + one hour.
    pub fn sign_retire(&self, net: &Id, iat: i64, app: &Identity, owner: &Identity) -> NetResult<Statement> {
        if app.id() != &self.app || owner.id() != &self.owner {
            return Err(NetError::format("retire: sign with the app key and its owner"));
        }
        let exp = iat.saturating_add(MIN_RETIRE_LIFETIME_MS).saturating_add(3600 * 1000);
        self.sign_multi(net, iat, exp, &[app, owner])
    }
}

impl Body for Retire {
    const KIND: Kind = Kind::Retire;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "retire")?;
        fields(object, &["app", "owner", "card", "owner_card"], &[], "retire")?;
        let app = id(object, "app")?;
        let owner = id(object, "owner")?;
        if app == owner {
            return Err(NetError::format("retire: the app key is not its own owner"));
        }
        let card = card(object.get("card"), "card")?;
        if card.id() != &app || card.role() != Role::App {
            return Err(NetError::format("card: the app key's card (role app)"));
        }
        let owner_card = card_of_owner(object.get("owner_card"))?;
        if owner_card.id() != &owner {
            return Err(NetError::format("owner_card: must be the owner's own card"));
        }
        Ok(Self { app, owner, card, owner_card })
    }

    fn to_body(&self) -> NetResult<Value> {
        crate::statements::checked::<Self>(json!({
            "app": self.app.as_str(),
            "owner": self.owner.as_str(),
            "card": self.card.to_value(),
            "owner_card": self.owner_card.to_value(),
        }))
    }
}

fn card_of_owner(value: Option<&Value>) -> NetResult<KeyCard> {
    let owner_card = card(value, "owner_card")?;
    if !matches!(owner_card.role(), Role::Client | Role::Node) {
        return Err(NetError::format("owner_card: role client or node"));
    }
    Ok(owner_card)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn strict_body_and_signers() -> NetResult<()> {
        let (app, owner, net) =
            (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
        let body = Retire::new(&app, &owner, 1_000)?;
        let statement = body.sign_retire(net.id(), 1_000, &app, &owner)?;
        assert_eq!(Retire::from_statement(&statement)?, body);
        let mut signers: Vec<Id> = statement.claimed_signers().into_iter().cloned().collect();
        signers.sort();
        assert_eq!(signers, body.signers());
        assert!(body.sign_retire(net.id(), 1_000, &owner, &app).is_err(), "keys swapped");
        let mut value = body.to_body()?;
        value["extra"] = json!(1);
        assert!(Retire::from_body(&value).is_err(), "unknown field");
        let mut swapped = body.to_body()?;
        swapped["card"] = body.owner_card.to_value();
        assert!(Retire::from_body(&swapped).is_err(), "owner card as app card");
        let mut same = body.to_body()?;
        same["owner"] = json!(app.id().as_str());
        assert!(Retire::from_body(&same).is_err(), "app owns itself");
        Ok(())
    }
}
