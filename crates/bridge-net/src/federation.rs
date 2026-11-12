//! Federation (docs/10 §6, ADR 0023): the body of a `federation` statement - a log entry signed by the net key alone
//! that names another network and 1-8 of its gateways (their node cards). Effective only both ways: each network
//! lists the other. The checks of who signs and how many live in the state.

use std::collections::BTreeSet;

use bridge_core::{Id, KeyCard, Role};
use serde_json::{Value, json};

use crate::error::{NetError, NetResult};
use crate::statements::{Body, Kind, fields, id, object};

/// Most gateways of the other network in one statement.
pub const MAX_FEDERATION_GATEWAYS: usize = 8;
/// Most networks one network is connected to.
pub const MAX_FEDERATIONS: usize = 32;
/// The only scope so far: messages.
pub const SCOPE_MESSAGES: &str = "messages";

/// The body of a `federation` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct Federation {
    /// The other network.
    pub peer: Id,
    /// Gateways of the other network that may deliver from it and take envelopes for it (node cards with addresses).
    pub gateways: Vec<KeyCard>,
}

impl Federation {
    /// The card of a listed gateway.
    #[must_use]
    pub fn gateway(&self, id: &Id) -> Option<&KeyCard> {
        self.gateways.iter().find(|card| card.id() == id)
    }
}

impl Body for Federation {
    const KIND: Kind = Kind::Federation;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "federation")?;
        fields(object, &["peer", "gateways", "scope"], &[], "federation")?;
        let peer = id(object, "peer")?;
        let list = object
            .get("gateways")
            .and_then(Value::as_array)
            .filter(|list| (1..=MAX_FEDERATION_GATEWAYS).contains(&list.len()))
            .ok_or_else(|| NetError::format("federation gateways: 1..=8 node cards"))?;
        let mut seen = BTreeSet::new();
        let mut gateways = Vec::with_capacity(list.len());
        for item in list {
            let card = KeyCard::from_value(item.clone())?;
            if card.role() != Role::Node || card.urls().is_empty() {
                return Err(NetError::format("federation gateways: node cards with addresses"));
            }
            if card.id() == &peer || !seen.insert(card.id().clone()) {
                return Err(NetError::format("federation gateways: distinct nodes, not the network key"));
            }
            gateways.push(card);
        }
        let scope = object.get("scope").and_then(Value::as_array);
        if scope.is_none_or(|scope| scope.len() != 1 || scope[0].as_str() != Some(SCOPE_MESSAGES)) {
            return Err(NetError::format("federation scope: exactly [\"messages\"]"));
        }
        Ok(Self { peer, gateways })
    }

    fn to_body(&self) -> NetResult<Value> {
        let gateways: Vec<Value> = self.gateways.iter().map(KeyCard::to_value).collect();
        crate::statements::checked::<Self>(
            json!({"peer": self.peer.as_str(), "gateways": gateways, "scope": [SCOPE_MESSAGES]}),
        )
    }
}

#[cfg(test)]
mod tests {
    use bridge_core::Identity;

    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32], &[seed.wrapping_add(100); 32])
    }

    fn gateway(seed: u8) -> NetResult<KeyCard> {
        Ok(identity(seed).key_card_with(Role::Node, None, &[format!("https://n{seed}.example")], None, 1)?)
    }

    #[test]
    fn strict_form() -> NetResult<()> {
        let body = Federation { peer: identity(1).id().clone(), gateways: vec![gateway(2)?, gateway(3)?] };
        let value = body.to_body()?;
        assert_eq!(Federation::from_body(&value)?, body);
        assert_eq!(body.gateway(identity(3).id()), Some(&body.gateways[1]));
        let bad = |change: &dyn Fn(&mut Value)| {
            let mut value = value.clone();
            change(&mut value);
            Federation::from_body(&value).is_err()
        };
        assert!(bad(&|v| v["scope"] = json!(["messages", "names"])));
        assert!(bad(&|v| v["scope"] = json!([])));
        assert!(bad(&|v| v["gateways"] = json!([])));
        let card = gateway(2)?.to_value();
        assert!(bad(&|v| v["gateways"] = json!([card.clone(), card.clone()])), "duplicate");
        assert!(bad(&|v| v["gateways"] = json!(vec![card.clone(); 9])), "too many");
        let client = identity(4).key_card(Role::Client, None, 1)?.to_value();
        assert!(bad(&|v| v["gateways"] = json!([client.clone()])), "only node cards");
        let no_urls = identity(5).key_card(Role::Node, None, 1)?.to_value();
        assert!(bad(&|v| v["gateways"] = json!([no_urls.clone()])), "with addresses");
        assert!(bad(&|v| v["extra"] = json!(1)));
        Ok(())
    }
}
