//! The owner backup in the log (docs/12 §10): a `backup` entry names the app that holds it - signed by the net key or
//! an admin with `rules`, at most a year, the newest counts, revocable by those who could sign it.

mod common;

use bridge_net::{Backup, NetError, NetResult, Revoke, RevokeTarget, Right};
use common::{DAY, MIN, Net, T0, identity};

#[test]
fn the_newest_backup_entry_of_an_admin_with_rules_counts() -> NetResult<()> {
    let mut net = Net::new(bridge_net::JoinMode::Invite)?;
    let id = net.net.clone();
    let rules = net.delegate(10, &[Right::Rules], T0 + MIN)?;
    let seals = net.delegate(11, &[Right::Seals, Right::Members], T0 + MIN)?;
    let (first, second) = (identity(20), identity(21));
    assert!(net.state.backup_app(T0 + 2 * MIN).is_none());

    // Attacks: a stranger, an admin without `rules`, too long, two signers.
    let body = Backup { app: first.id().clone() };
    let stranger = body.sign_backup(&id, T0 + 2 * MIN, T0 + 30 * DAY, &identity(30))?;
    assert!(matches!(net.skip(&stranger)?, NetError::Forbidden(_) | NetError::NotMember));
    let without = body.sign_backup(&id, T0 + 2 * MIN, T0 + 30 * DAY, &seals)?;
    assert!(matches!(net.skip(&without)?, NetError::Forbidden(_)), "needs rules");
    assert!(body.sign_backup(&id, T0, T0 + 400 * DAY, &rules).is_err(), "too long");
    let long = bridge_net::Body::sign(&body, &id, T0 + 2 * MIN, T0 + 400 * DAY, &rules)?;
    assert!(matches!(net.skip(&long)?, NetError::Forbidden(_)), "too long in the log too");
    let both = net.sign_multi(&body, &[&rules, &seals], T0 + 2 * MIN)?;
    assert!(matches!(net.skip(&both)?, NetError::BadFormat(_)), "one signer");

    // The admin with `rules` points to the first app, later to the second; an older one does not replace it.
    let one = body.sign_backup(&id, T0 + 3 * MIN, T0 + 300 * DAY, &rules)?;
    net.accept(&one)?;
    assert_eq!(net.state.backup_app(T0 + 4 * MIN), Some((first.id().clone(), T0 + 3 * MIN)));
    let two = Backup { app: second.id().clone() }.sign_backup(&id, T0 + 5 * MIN, T0 + 300 * DAY, &net.master)?;
    net.accept(&two)?;
    assert_eq!(net.state.backup_app(T0 + 6 * MIN).map(|(app, _)| app), Some(second.id().clone()));
    let older = body.sign_backup(&id, T0 + 4 * MIN, T0 + 300 * DAY, &rules)?;
    assert!(matches!(net.skip(&older)?, NetError::Forbidden(_)), "not newer");
    assert_eq!(net.replayed()?.backup_app(T0 + 6 * MIN).map(|(app, _)| app), Some(second.id().clone()));
    // It ends with its lifetime; an admin with `rules` can revoke it, one without can not.
    assert!(net.state.backup_app(T0 + 301 * DAY).is_none());
    let target = RevokeTarget::Statement(two.hash_bytes());
    let undo = Revoke { target: target.clone(), reason: String::new() };
    let refused = net.sign(&undo, &seals, T0 + 7 * MIN)?;
    assert!(matches!(net.skip(&refused)?, NetError::Forbidden(_)));
    let revoked = net.sign(&undo, &rules, T0 + 8 * MIN)?;
    net.accept(&revoked)?;
    assert!(net.state.backup_app(T0 + 9 * MIN).is_none());
    Ok(())
}
