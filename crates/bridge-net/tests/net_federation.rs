//! Federation in the network state (docs/10 §6.1, ADR 0023): only the net key connects networks, not with itself,
//! at most 32, a newer statement replaces the older, only the net key revokes, replay gives the same state.

mod common;

use bridge_net::federation::MAX_FEDERATIONS;
use bridge_net::{Federation, JoinMode, NetError, NetResult, Revoke, RevokeTarget, Right};
use common::{DAY, MIN, Net, T0, identity, node_card};

fn federation(peer: u8, gateways: &[u8]) -> NetResult<Federation> {
    let mut cards = Vec::new();
    for seed in gateways {
        cards.push(node_card(&identity(*seed), &format!("https://gw{seed}.example"))?);
    }
    Ok(Federation { peer: identity(peer).id().clone(), gateways: cards })
}

#[test]
fn only_the_net_key_connects_and_revokes() -> NetResult<()> {
    let mut net = Net::new(JoinMode::Open)?;
    let admin = net.delegate(20, &[Right::Members, Right::Seals, Right::Bans, Right::Rules], T0 + MIN)?;
    let peer = identity(100).id().clone();

    // An admin with every right can not connect networks.
    let by_admin = net.sign(&federation(100, &[101])?, &admin, T0 + 2 * MIN)?;
    net.skip(&by_admin)?;
    assert!(net.state.federation(&peer, T0 + 3 * MIN).is_none());

    // The net key can.
    let first = net.sign(&federation(100, &[101])?, &net.master, T0 + 3 * MIN)?;
    net.accept(&first)?;
    let info =
        net.state.federation(&peer, T0 + 4 * MIN).ok_or_else(|| NetError::NotFound("federation in effect".into()))?;
    assert_eq!(info.gateways.len(), 1);
    assert_eq!(info.statement, first.canonical_bytes());
    assert_eq!(net.state.federations(T0 + 4 * MIN), vec![peer.clone()]);

    // Not with itself.
    let own = Federation { peer: net.net.clone(), gateways: federation(100, &[101])?.gateways };
    let itself = net.sign(&own, &net.master, T0 + 4 * MIN)?;
    net.skip(&itself)?;

    // A newer statement replaces the older; an older one does not come back.
    let second = net.sign(&federation(100, &[101, 102])?, &net.master, T0 + 5 * MIN)?;
    net.accept(&second)?;
    assert_eq!(
        net.state
            .federation(&peer, T0 + 6 * MIN)
            .ok_or_else(|| NetError::NotFound("still in effect".into()))?
            .gateways
            .len(),
        2
    );
    let stale = net.sign(&federation(100, &[103])?, &net.master, T0 + 4 * MIN + 1)?;
    net.skip(&stale)?;

    // The admin can not revoke it, the net key can.
    let target = RevokeTarget::Statement(second.hash_bytes());
    let revoke = Revoke { target: target.clone(), reason: "Test".into() };
    net.skip(&net.sign(&revoke, &admin, T0 + 7 * MIN)?)?;
    net.accept(&net.sign(&revoke, &net.master, T0 + 8 * MIN)?)?;
    assert!(net.state.federation(&peer, T0 + 9 * MIN).is_none());

    // Replay from the log gives the same state.
    assert_eq!(net.replayed()?, net.state);
    Ok(())
}

#[test]
fn at_most_32_networks_and_expiry() -> NetResult<()> {
    let mut net = Net::new(JoinMode::Open)?;
    for index in 0..MAX_FEDERATIONS {
        let statement = net.sign(&federation(100 + index as u8, &[200])?, &net.master, T0 + MIN + index as i64)?;
        net.accept(&statement)?;
    }
    let one_more = net.sign(&federation(150, &[200])?, &net.master, T0 + 2 * MIN)?;
    net.skip(&one_more)?;
    assert_eq!(net.state.federations(T0 + 3 * MIN).len(), MAX_FEDERATIONS);
    // After its expiry a federation is not in effect.
    let lifetime =
        net.state.federation(identity(100).id(), T0 + 3 * MIN).ok_or_else(|| NetError::NotFound("in effect".into()))?;
    assert!(!lifetime.gateways.is_empty());
    assert!(net.state.federation(identity(100).id(), T0 + 3 * 366 * DAY).is_none());
    Ok(())
}
