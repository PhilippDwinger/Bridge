//! Attacks on the network state, the log and the heads (docs/06 §3-§6). Every invalid entry must be skipped -
//! never accepted, never a panic - and honest data must never be taken for evidence.

mod common;

use bridge_core::json::canonical;
use bridge_core::{Identity, Role, Statement};
use bridge_net::{
    Applied, Ban, Body, Delegation, Evidence, Invite, JoinMode, Log, Member, NetError, NetResult, NetState, Revoke,
    RevokeTarget, Right, Rights, Seal, Services, WitnessedHead, check_new_entries, issue_cosign, issue_head,
    verify_head,
};
use common::{DAY, MIN, Net, T0, expect_skip, identity, node_card};
use serde_json::json;

fn member(who: &Identity) -> Member {
    Member { member: who.id().clone(), invite: None }
}

fn ban(who: &Identity) -> Ban {
    Ban { subject: who.id().clone(), reason: "test".into() }
}

fn level1(who: &Identity) -> Seal {
    Seal { subject: who.id().clone(), level: 1, services: Services::NONE, card: None }
}

fn revoke_statement(statement: &Statement) -> Revoke {
    Revoke { target: RevokeTarget::Statement(statement.hash_bytes()), reason: String::new() }
}

fn revoke_identity(who: &Identity, cascade: bool) -> Revoke {
    Revoke { target: RevokeTarget::Identity { id: who.id().clone(), cascade }, reason: String::new() }
}

/// Re-encodes a modified statement value as canonical log bytes (bypassing all builders).
fn bytes_of(value: &serde_json::Value) -> NetResult<Vec<u8>> {
    Ok(canonical(value)?)
}

#[test]
fn genesis_must_be_version_1_signed_by_the_net_key_alone() -> NetResult<()> {
    let n = Net::new(JoinMode::Open)?;
    let genesis = n.log.entries()[0].clone();
    let manifest = n.state.manifest().clone();
    let other = identity(9);
    let bad = [
        manifest.sign(&n.net, T0, T0 + DAY, &other)?, // not the net key
        manifest.sign_multi(&n.net, T0, T0 + DAY, &[&n.master, &other])?, // not alone
        manifest.next_version().sign(&n.net, T0, T0 + DAY, &n.master)?, // version 2
        ban(&other).sign(&n.net, T0, T0 + DAY, &n.master)?, // not a manifest
        manifest.sign(other.id(), T0, T0 + DAY, &n.master)?, // other network field
    ];
    for statement in &bad {
        assert!(NetState::genesis(&n.net, statement.canonical_bytes()).is_err());
        assert!(NetState::replay(&n.net, &[statement.canonical_bytes().to_vec(), genesis.clone()]).is_err());
        assert!(Log::new(n.net.clone()).append(statement).is_err());
    }
    // A manifest whose card is another net key, presented as genesis of that other net: still refused for ours.
    assert!(NetState::genesis(other.id(), &genesis).is_err());
    assert!(NetState::replay(&n.net, &[]).is_err());
    // Tampered genesis
    let mut value = n.log.entries()[0].clone();
    let position = value.iter().position(|b| *b == b'T').unwrap_or(0);
    value[position] = b'X';
    assert!(NetState::genesis(&n.net, &value).is_err());
    Ok(())
}

#[test]
fn manifest_version_jump_rollback_and_rights() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let current = n.state.manifest().clone();
    let mut jump = current.next_version();
    jump.version = 3;
    assert!(matches!(n.skip(&n.sign(&jump, &n.master, T0 + 1)?)?, NetError::Forbidden(_)));
    assert!(matches!(n.skip(&n.sign(&current, &n.master, T0 + 1)?)?, NetError::Forbidden(_)), "same version again");
    let v2 = current.next_version();
    n.accept(&n.sign(&v2, &n.master, T0 + 2)?)?;
    assert!(n.skip(&n.sign(&v2, &n.master, T0 + 3)?).is_ok(), "v2 twice");
    assert!(n.skip(&n.sign(&current, &n.master, T0 + 3)?).is_ok(), "rollback to v1");
    // Admin without "rules", node without delegation
    let seals_only = n.delegate(10, &[Right::Seals], T0 + 4)?;
    assert!(matches!(n.skip(&n.sign(&v2.next_version(), &seals_only, T0 + 5)?)?, NetError::Forbidden(_)));
    assert!(n.skip(&n.sign(&v2.next_version(), &n.owner, T0 + 5)?).is_ok());
    // A manifest that swaps the master card for another key
    let mut foreign = v2.next_version();
    foreign.card = identity(9).key_card(Role::Net, None, T0)?;
    assert!(matches!(n.skip(&n.sign(&foreign, &n.master, T0 + 6)?)?, NetError::BadFormat(_)));
    assert_eq!(n.state.manifest().version, 2);
    Ok(())
}

#[test]
fn admins_need_the_right_and_a_valid_delegation() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Invite)?;
    let seals_only = n.delegate(10, &[Right::Seals], T0 + 1)?;
    let victim = identity(20);
    for statement in [
        n.sign(&Invite { code_hash: [1; 32], uses: 1 }, &seals_only, T0 + 2)?,
        n.sign(&member(&victim), &seals_only, T0 + 2)?,
        n.sign(&ban(&victim), &seals_only, T0 + 2)?,
    ] {
        assert!(matches!(n.skip(&statement)?, NetError::Forbidden(_)));
    }
    // Only the master delegates.
    let body = Delegation {
        admin: identity(21).id().clone(),
        rights: Rights::all(),
        card: identity(21).key_card(Role::Admin, None, T0)?,
    };
    assert!(matches!(n.skip(&n.sign(&body, &seals_only, T0 + 3)?)?, NetError::Forbidden(_)));
    // Delegation to a fake card (not the admin's own) is malformed.
    let mut value = n.sign(&body, &n.master, T0 + 3)?.to_value();
    value["body"]["card"] = identity(22).key_card(Role::Admin, None, T0)?.to_value();
    assert!(matches!(expect_skip(n.push_bytes(&bytes_of(&value)?)?)?, NetError::BadFormat(_) | NetError::BadSignature));

    // Expired delegation: rights end with exp.
    let short = identity(23);
    let body =
        Delegation { admin: short.id().clone(), rights: Rights::all(), card: short.key_card(Role::Admin, None, T0)? };
    n.accept(&body.sign(&n.net, T0 + 4, T0 + DAY, &n.master)?)?;
    n.accept(&n.sign(&level1(&victim), &short, T0 + 5)?)?;
    assert!(matches!(n.skip(&n.sign(&level1(&identity(24)), &short, T0 + DAY)?)?, NetError::Forbidden(_)));
    // ... and a back-dated statement can not use it once the log clock is past the expiry.
    n.accept(&n.sign(&ban(&identity(25)), &n.master, T0 + 2 * DAY)?)?;
    assert!(matches!(n.skip(&n.sign(&level1(&identity(24)), &short, T0 + DAY - MIN)?)?, NetError::Forbidden(_)));

    // Revoked delegation (by hash): rights end at once; the delegation can not be re-appended.
    let revoked_admin = identity(26);
    let body = Delegation {
        admin: revoked_admin.id().clone(),
        rights: Rights::all(),
        card: revoked_admin.key_card(Role::Admin, None, T0)?,
    };
    let delegation = n.sign(&body, &n.master, T0 + 2 * DAY)?;
    n.accept(&delegation)?;
    n.accept(&n.sign(&revoke_statement(&delegation), &n.master, T0 + 2 * DAY + 1)?)?;
    assert!(n.state.admin_rights(revoked_admin.id(), T0 + 2 * DAY + 2).is_empty());
    assert!(matches!(
        n.skip(&n.sign(&level1(&identity(27)), &revoked_admin, T0 + 2 * DAY + 2)?)?,
        NetError::Forbidden(_)
    ));
    assert!(matches!(n.skip(&delegation)?, NetError::Forbidden(_)), "revoked delegation re-appended");

    // Replaced delegation: fewer rights now; the old one (more rights) can not come back, even after the new one
    // is revoked.
    let admin = identity(28);
    let card = admin.key_card(Role::Admin, None, T0)?;
    let all = n.sign(
        &Delegation { admin: admin.id().clone(), rights: Rights::all(), card: card.clone() },
        &n.master,
        T0 + 3 * DAY,
    )?;
    let fewer = Delegation { admin: admin.id().clone(), rights: Rights::of(&[Right::Members]), card };
    let fewer = n.sign(&fewer, &n.master, T0 + 3 * DAY + 1)?;
    n.accept(&all)?;
    n.accept(&fewer)?;
    assert_eq!(n.state.admin_rights(admin.id(), T0 + 3 * DAY + 2), Rights::of(&[Right::Members]));
    n.accept(&n.sign(&revoke_statement(&fewer), &n.master, T0 + 3 * DAY + 2)?)?;
    assert!(n.skip(&all).is_ok(), "replaced delegation re-appended");
    assert!(n.state.admin_rights(admin.id(), T0 + 3 * DAY + 3).is_empty());
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

#[test]
fn banned_issuers_and_subjects() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let a = n.delegate(10, &[Right::Members, Right::Seals, Right::Bans], T0 + 1)?;
    let b = n.delegate(11, &[Right::Bans], T0 + 1)?;
    let ban_a = n.sign(&ban(&a), &b, T0 + 2)?;
    n.accept(&ban_a)?;
    assert!(n.state.admin_rights(a.id(), T0 + 3).is_empty(), "banned admins have no rights");
    let reason = n.skip(&n.sign(&level1(&identity(20)), &a, T0 + 3)?)?;
    assert_eq!(reason, NetError::Banned);
    // Banned identities do not receive grants; the gateway can not admit them.
    let x = identity(21);
    n.accept(&n.sign(&ban(&x), &b, T0 + 4)?)?;
    assert_eq!(n.skip(&n.sign(&member(&x), &n.owner, T0 + 5)?)?, NetError::Banned);
    assert_eq!(n.skip(&n.sign(&level1(&x), &n.master, T0 + 5)?)?, NetError::Banned);
    // The same ban twice, the net key banned, too many bans of one identity.
    assert!(n.skip(&ban_a).is_ok());
    assert!(matches!(
        n.skip(&n.sign(&Ban { subject: n.net.clone(), reason: String::new() }, &b, T0 + 6)?)?,
        NetError::Forbidden(_)
    ));
    let y = identity(22);
    for i in 0..8 {
        n.accept(&n.sign(&Ban { subject: y.id().clone(), reason: format!("{i}") }, &b, T0 + 7)?)?;
    }
    assert!(matches!(
        n.skip(&n.sign(&Ban { subject: y.id().clone(), reason: "9".into() }, &b, T0 + 7)?)?,
        NetError::QuotaExceeded(_)
    ));
    // Lifting a ban: revoke it.
    n.accept(&n.sign(&revoke_statement(&ban_a), &b, T0 + 8)?)?;
    assert!(!n.state.is_banned(a.id(), T0 + 9));
    n.accept(&n.sign(&level1(&identity(20)), &a, T0 + 9)?)?;
    Ok(())
}

#[test]
fn seal_level_3_needs_enough_distinct_admins() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |manifest| manifest.approvals.seal3 = 2)?;
    let a = n.delegate(10, &[Right::Seals], T0 + 1)?;
    let b = n.delegate(11, &[Right::Seals], T0 + 1)?;
    let members_only = n.delegate(12, &[Right::Members], T0 + 1)?;
    let outsider = identity(13);
    let node = identity(20);
    let seal = Net::gateway_seal(&node, 3)?;
    assert!(matches!(n.skip(&n.sign(&seal, &a, T0 + 2)?)?, NetError::Forbidden(_)), "one admin");
    assert!(
        matches!(n.skip(&n.sign_multi(&seal, &[&a, &members_only], T0 + 2)?)?, NetError::Forbidden(_)),
        "second without seals"
    );
    assert!(n.skip(&n.sign_multi(&seal, &[&a, &outsider], T0 + 2)?).is_ok(), "second is no admin");

    // The same admin twice in "sigs" is refused outright (it never counts twice).
    let one = n.sign_multi(&seal, &[&a], T0 + 2)?;
    let mut value = one.to_value();
    let entry = value["sigs"][0].clone();
    value["sigs"] = json!([entry.clone(), entry]);
    assert!(matches!(expect_skip(n.push_bytes(&bytes_of(&value)?)?)?, NetError::BadFormat(_)));
    // A signature of B copied under A's name, or B's signature removed from a valid pair
    let pair = n.sign_multi(&seal, &[&a, &b], T0 + 2)?;
    let mut value = pair.to_value();
    value["sigs"][1]["sig"] = value["sigs"][0]["sig"].clone();
    assert_eq!(expect_skip(n.push_bytes(&bytes_of(&value)?)?)?, NetError::BadSignature);
    let mut value = pair.to_value();
    if let Some(list) = value["sigs"].as_array_mut() {
        list.pop();
    }
    assert!(matches!(expect_skip(n.push_bytes(&bytes_of(&value)?)?)?, NetError::Forbidden(_)));
    // Two distinct admins with "seals": accepted; the master alone also may.
    n.accept(&pair)?;
    assert_eq!(n.state.level(node.id(), T0 + 3), Some(3));
    n.accept(&n.sign(&Net::gateway_seal(&identity(21), 3)?, &n.master, T0 + 3)?)?;
    // Seals of level 1-2 need one admin with "seals".
    assert!(matches!(n.skip(&n.sign(&level1(&identity(22)), &members_only, T0 + 4)?)?, NetError::Forbidden(_)));
    n.accept(&n.sign(&level1(&identity(22)), &a, T0 + 4)?)?;
    Ok(())
}

#[test]
fn members_only_via_gateways_or_admins() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let x = identity(20);
    // Random identity and a level-1 node with "gateway" service do not count as gateway.
    let random = identity(30);
    assert!(matches!(n.skip(&n.sign(&member(&x), &random, T0 + 1)?)?, NetError::Forbidden(_)));
    n.seal_owner(T0 + 2)?; // the first gateway seal ends the start-gateway exception
    let weak = identity(31);
    let weak_seal = Seal {
        subject: weak.id().clone(),
        level: 1,
        services: Services::of(&[bridge_net::Service::Gateway]),
        card: Some(node_card(&weak, "https://weak.example")?),
    };
    n.accept(&n.sign(&weak_seal, &n.master, T0 + 3)?)?;
    assert!(matches!(n.skip(&n.sign(&member(&x), &weak, T0 + 4)?)?, NetError::Forbidden(_)));
    assert!(n.state.gateways(T0 + 4).iter().all(|(id, _)| id != weak.id()));
    // A second start gateway of a new manifest version does not count any more after the first gateway seal.
    let late = identity(32);
    let mut v2 = n.state.manifest().next_version();
    v2.gateways.push(bridge_net::GatewayEntry {
        id: late.id().clone(),
        url: "https://late.example".into(),
        card: Some(node_card(&late, "https://late.example")?),
    });
    n.accept(&n.sign(&v2, &n.master, T0 + 5)?)?;
    assert!(matches!(n.skip(&n.sign(&member(&x), &late, T0 + 6)?)?, NetError::Forbidden(_)));
    // The sealed owner gateway may.
    n.accept(&n.sign(&member(&x), &n.owner, T0 + 6)?)?;
    // A gateway seal that expired, a revoked gateway seal
    let g = identity(33);
    let seal = Net::gateway_seal(&g, 2)?;
    let seal_statement = seal.sign(&n.net, T0 + 7, T0 + DAY, &n.master)?;
    n.accept(&seal_statement)?;
    n.accept(&n.sign(&member(&identity(21)), &g, T0 + 8)?)?;
    assert!(matches!(n.skip(&n.sign(&member(&identity(22)), &g, T0 + DAY)?)?, NetError::Forbidden(_)));
    Ok(())
}

#[test]
fn start_gateway_without_card_and_member_limit() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |manifest| {
        manifest.gateways[0].card = None;
        manifest.limits.members = 2;
    })?;
    // Without a card nobody can verify what the start gateway signs.
    assert!(matches!(n.skip(&n.sign(&member(&identity(20)), &n.owner, T0 + 1)?)?, NetError::Forbidden(_)));
    let admin = n.delegate(10, &[Right::Members], T0 + 1)?;
    n.accept(&n.sign(&member(&identity(20)), &admin, T0 + 2)?)?;
    n.accept(&n.sign(&member(&identity(21)), &admin, T0 + 2)?)?;
    assert!(matches!(n.skip(&n.sign(&member(&identity(22)), &admin, T0 + 3)?)?, NetError::QuotaExceeded(_)));
    // Renewing an existing member is fine at the limit.
    n.accept(&n.sign(&member(&identity(21)), &admin, T0 + 4)?)?;
    Ok(())
}

#[test]
fn invite_rules() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Invite)?;
    let admin = n.delegate(10, &[Right::Members], T0 + 1)?;
    let code = Invite::hash_code("ABC");
    let with = |who: &Identity, code| Member { member: who.id().clone(), invite: Some(code) };
    // Unknown code
    assert!(matches!(n.skip(&n.sign(&with(&identity(20), code), &n.owner, T0 + 2)?)?, NetError::NotFound(_)));
    let invite = Invite { code_hash: code, uses: 1 }.sign(&n.net, T0 + 2, T0 + DAY, &admin)?;
    n.accept(&invite)?;
    // The same code twice
    assert!(n.skip(&n.sign(&Invite { code_hash: code, uses: 1000 }, &admin, T0 + 3)?).is_ok());
    n.accept(&n.sign(&with(&identity(20), code), &n.owner, T0 + 3)?)?;
    assert!(matches!(n.skip(&n.sign(&with(&identity(21), code), &n.owner, T0 + 4)?)?, NetError::QuotaExceeded(_)));
    // Expired code
    let code2 = Invite::hash_code("DEF");
    n.accept(&Invite { code_hash: code2, uses: 5 }.sign(&n.net, T0 + 5, T0 + DAY, &admin)?)?;
    assert_eq!(n.skip(&n.sign(&with(&identity(22), code2), &n.owner, T0 + DAY)?)?, NetError::Expired);
    // Revoked code
    let code3 = Invite::hash_code("GHI");
    let invite3 = n.sign(&Invite { code_hash: code3, uses: 5 }, &admin, T0 + DAY)?;
    n.accept(&invite3)?;
    n.accept(&n.sign(&revoke_statement(&invite3), &admin, T0 + DAY + 1)?)?;
    assert!(matches!(n.skip(&n.sign(&with(&identity(23), code3), &n.owner, T0 + DAY + 2)?)?, NetError::NotFound(_)));
    assert_eq!(n.state.invite_left(&code3, T0 + DAY + 2), None);
    Ok(())
}

#[test]
fn revocations_need_the_right() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let a = n.delegate(10, &[Right::Members, Right::Seals, Right::Bans], T0 + 1)?;
    let members_only = n.delegate(11, &[Right::Members], T0 + 1)?;
    let x = identity(20);
    let seal = n.sign(&level1(&x), &a, T0 + 2)?;
    n.accept(&seal)?;
    let x_member = n.sign(&member(&x), &n.owner, T0 + 2)?;
    n.accept(&x_member)?;
    // A member revoking a seal, an admin without "seals" revoking a seal, an admin revoking a delegation.
    assert!(matches!(n.skip(&n.sign(&revoke_statement(&seal), &x, T0 + 3)?)?, NetError::Forbidden(_)));
    assert!(matches!(n.skip(&n.sign(&revoke_statement(&seal), &members_only, T0 + 3)?)?, NetError::Forbidden(_)));
    let delegation_of_a = n.log.entries()[1].clone();
    let delegation_of_a = Statement::parse(&delegation_of_a)?;
    assert!(matches!(n.skip(&n.sign(&revoke_statement(&delegation_of_a), &a, T0 + 3)?)?, NetError::Forbidden(_)));
    // Identity revocations by admins: never for admins, never with cascade, only with members + seals.
    assert!(matches!(n.skip(&n.sign(&revoke_identity(&members_only, false), &a, T0 + 3)?)?, NetError::Forbidden(_)));
    assert!(matches!(n.skip(&n.sign(&revoke_identity(&x, true), &a, T0 + 3)?)?, NetError::Forbidden(_)));
    assert!(matches!(n.skip(&n.sign(&revoke_identity(&x, false), &members_only, T0 + 3)?)?, NetError::Forbidden(_)));
    // Unknown statement, the net key, revoking a revocation or a manifest
    let unknown = Revoke { target: RevokeTarget::Statement([9; 32]), reason: String::new() };
    assert!(matches!(n.skip(&n.sign(&unknown, &n.master, T0 + 4)?)?, NetError::NotFound(_)));
    let net_key =
        Revoke { target: RevokeTarget::Identity { id: n.net.clone(), cascade: false }, reason: String::new() };
    assert!(matches!(n.skip(&n.sign(&net_key, &n.master, T0 + 4)?)?, NetError::Forbidden(_)));
    let genesis = Statement::parse(&n.log.entries()[0])?;
    assert!(matches!(n.skip(&n.sign(&revoke_statement(&genesis), &n.master, T0 + 4)?)?, NetError::NotFound(_)));
    // The original issuer may revoke its own statement (the gateway its member), the master everything.
    n.accept(&n.sign(&revoke_statement(&x_member), &n.owner, T0 + 5)?)?;
    let first_revoke = Statement::parse(n.log.entry(n.log.size() - 1).unwrap_or_default())?;
    assert!(matches!(n.skip(&n.sign(&revoke_statement(&first_revoke), &n.master, T0 + 6)?)?, NetError::NotFound(_)));
    n.accept(&n.sign(&revoke_statement(&seal), &n.master, T0 + 6)?)?;
    assert_eq!(n.state.level(x.id(), T0 + 7), None);
    Ok(())
}

#[test]
fn identity_revocation_and_cascade() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let thief_victim = n.delegate(10, &[Right::Members, Right::Seals, Right::Bans], T0 + 1)?;
    let other_admin = n.delegate(11, &[Right::Members, Right::Seals], T0 + 1)?;
    let (m1, m2, s1, banned) = (identity(20), identity(21), identity(22), identity(23));
    let code = Invite::hash_code("stolen");
    n.accept(&n.sign(&Invite { code_hash: code, uses: 10 }, &thief_victim, T0 + 2)?)?;
    n.accept(&n.sign(&member(&m1), &thief_victim, T0 + 2)?)?;
    n.accept(&n.sign(&member(&m2), &other_admin, T0 + 2)?)?;
    n.accept(&n.sign(&level1(&s1), &thief_victim, T0 + 2)?)?;
    n.accept(&n.sign(&ban(&banned), &thief_victim, T0 + 2)?)?;
    // Non-cascade identity revocation of a member by an admin: membership gone, old statement can not return,
    // a new (later) membership is possible.
    let m2_member = n.sign(&member(&m2), &other_admin, T0 + 2)?;
    n.accept(&n.sign(&revoke_identity(&m2, false), &other_admin, T0 + 3)?)?;
    assert!(!n.state.is_member(m2.id(), T0 + 4));
    assert!(n.skip(&m2_member).is_ok());
    let older = Member { member: m2.id().clone(), invite: None }.sign(&n.net, T0 + 3, T0 + DAY, &other_admin)?;
    assert!(matches!(n.skip(&older)?, NetError::Forbidden(_)), "iat not after the revocation");
    n.accept(&n.sign(&member(&m2), &other_admin, T0 + 4)?)?;
    assert!(n.state.is_member(m2.id(), T0 + 5));

    // The admin key is stolen: the master revokes it with cascade.
    n.accept(&n.sign(&revoke_identity(&thief_victim, true), &n.master, T0 + 5)?)?;
    assert!(n.state.admin_rights(thief_victim.id(), T0 + 6).is_empty());
    assert!(!n.state.is_member(m1.id(), T0 + 6), "member issued by the stolen key");
    assert_eq!(n.state.level(s1.id(), T0 + 6), None, "seal issued by the stolen key");
    assert_eq!(n.state.invite_left(&code, T0 + 6), None, "invite issued by the stolen key");
    // Bans issued by the stolen key go too (review 3, finding 7: a thief could otherwise fill the ban table).
    assert!(!n.state.is_banned(banned.id(), T0 + 6), "ban issued by the stolen key");
    assert!(n.state.is_member(m2.id(), T0 + 6), "members of other admins stay");
    // The stolen key can do nothing any more - not even with a fresh delegation from the master.
    assert!(matches!(n.skip(&n.sign(&member(&identity(24)), &thief_victim, T0 + 6)?)?, NetError::Forbidden(_)));
    let fresh = Delegation {
        admin: thief_victim.id().clone(),
        rights: Rights::all(),
        card: thief_victim.key_card(Role::Admin, None, T0)?,
    };
    assert!(matches!(n.skip(&n.sign(&fresh, &n.master, T0 + 7)?)?, NetError::Forbidden(_)));
    assert!(matches!(n.skip(&n.sign(&member(&thief_victim), &other_admin, T0 + 7)?)?, NetError::Forbidden(_)));
    // Statements it issued earlier can not be re-appended.
    assert!(n.skip(&n.sign(&member(&m1), &thief_victim, T0 + 2)?).is_ok());
    // Members it admitted can join again through someone else.
    n.accept(&n.sign(&member(&m1), &other_admin, T0 + 8)?)?;
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

#[test]
fn multi_signed_seal_is_removed_by_cascade_of_one_signer() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |manifest| manifest.approvals.seal3 = 2)?;
    let a = n.delegate(10, &[Right::Seals], T0 + 1)?;
    let b = n.delegate(11, &[Right::Seals], T0 + 1)?;
    let node = identity(20);
    n.accept(&n.sign_multi(&Net::gateway_seal(&node, 3)?, &[&a, &b], T0 + 2)?)?;
    n.accept(&n.sign(&revoke_identity(&a, true), &n.master, T0 + 3)?)?;
    assert_eq!(n.state.level(node.id(), T0 + 4), None);
    assert!(n.state.gateways(T0 + 4).iter().all(|(id, _)| id != node.id()));
    Ok(())
}

#[test]
fn tampered_foreign_and_garbage_entries_never_count() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let admin = n.delegate(10, &[Right::Members, Right::Seals, Right::Bans], T0 + 1)?;
    let x = identity(20);
    let valid = n.sign(&level1(&x), &admin, T0 + 2)?;
    // Tampered body / time / kind / signer
    for (path, value) in [
        ("/body/level", json!(3)),
        ("/body/subject", json!(identity(21).id().as_str())),
        ("/exp", json!(T0 + 300 * DAY)),
        ("/t", json!("ban")),
        ("/iss", json!(identity(21).id().as_str())),
    ] {
        let mut tampered = valid.to_value();
        if let Some(field) = tampered.pointer_mut(path) {
            *field = value;
        }
        let reason = expect_skip(n.push_bytes(&bytes_of(&tampered)?)?)?;
        assert!(
            matches!(reason, NetError::BadSignature | NetError::Forbidden(_) | NetError::BadFormat(_)),
            "{path}: {reason:?}"
        );
    }
    // Other network, non-canonical bytes, not a log kind
    let other = identity(30);
    let foreign = level1(&x).sign(other.id(), T0 + 2, T0 + DAY, &admin)?;
    assert!(matches!(expect_skip(n.push(&foreign)?)?, NetError::BadFormat(_)));
    let spaced = String::from_utf8_lossy(valid.canonical_bytes()).replacen(',', " ,", 1);
    assert!(matches!(expect_skip(n.push_bytes(spaced.as_bytes())?)?, NetError::BadFormat(_)));
    let head = n.log.issue_head(&n.owner, T0 + 3)?;
    assert!(matches!(expect_skip(n.push_bytes(head.canonical_bytes())?)?, NetError::BadFormat(_)));
    // Garbage of all kinds never panics and never counts.
    let before = n.state.clone();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut garbage: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"null".to_vec(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        "[".repeat(200).into_bytes(),
        json!({"v": 4, "t": "seal", "net": n.net.as_str(), "iat": 0, "exp": 1, "body": {}, "sig": "x"})
            .to_string()
            .into_bytes(),
        vec![0xff; 100],
    ];
    for _ in 0..200 {
        let length = (next() % 300) as usize;
        garbage.push((0..length).map(|_| (next() & 0xff) as u8).collect());
    }
    // Every single-byte change of a valid entry
    let bytes = valid.canonical_bytes().to_vec();
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1 << (next() % 8);
        garbage.push(changed);
    }
    for entry in &garbage {
        assert!(matches!(n.push_bytes(entry)?, Applied::Skipped(_)));
    }
    assert!(matches!(n.push_bytes(&vec![b' '; 70 * 1024]), Err(NetError::TooLarge(_))), "the log refuses > 64 KiB");
    assert!(matches!(n.state.apply(&vec![b' '; 70 * 1024]), Applied::Skipped(NetError::TooLarge(_))));
    // Apart from the entry counter, nothing changed.
    let mut expected = before;
    for _ in 0..garbage.len() + 1 {
        expected.apply(b"x");
    }
    assert_eq!(expected, n.state);
    // The valid entry still works after all this.
    n.accept(&valid)?;
    let replayed = NetState::replay(&n.net, n.log.entries())?;
    assert_eq!(replayed.level(x.id(), T0 + 3), Some(1));
    Ok(())
}

#[test]
fn daily_entry_limit() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |manifest| manifest.limits.log_entries_per_day = 10)?;
    let admin = n.delegate(10, &[Right::Members, Right::Bans], T0 + 1)?; // master entries do not count
    for i in 0..10u8 {
        n.accept(&n.sign(&member(&identity(100 + i)), &n.owner, T0 + 2)?)?;
    }
    assert!(matches!(n.skip(&n.sign(&member(&identity(120)), &n.owner, T0 + 3)?)?, NetError::QuotaExceeded(_)));
    // Bans and revocations have a reserve of 10 % (here: 1).
    n.accept(&n.sign(&ban(&identity(121)), &admin, T0 + 3)?)?;
    assert!(matches!(n.skip(&n.sign(&ban(&identity(122)), &admin, T0 + 3)?)?, NetError::QuotaExceeded(_)));
    // The master is not limited.
    n.accept(&n.sign(&ban(&identity(123)), &n.master, T0 + 3)?)?;
    // The next day counts again.
    n.accept(&n.sign(&member(&identity(120)), &n.owner, T0 + DAY)?)?;
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

#[test]
fn candidate_checks_of_the_log_operator() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let admin = identity(10);
    let card = admin.key_card(Role::Admin, None, T0)?;
    let delegation = Delegation { admin: admin.id().clone(), rights: Rights::all(), card };
    n.accept(&delegation.sign(&n.net, T0 + 1, T0 + DAY, &n.master)?)?;
    let now = T0 + 10;
    n.state.validate_candidate(&n.sign(&member(&identity(20)), &admin, now)?, now)?;
    // Dated into the future, expired, not allowed
    let future = n.sign(&member(&identity(20)), &admin, now + 6 * MIN)?;
    assert_eq!(n.state.validate_candidate(&future, now), Err(NetError::NotYetValid));
    let expired = member(&identity(20)).sign(&n.net, now - 2 * MIN, now - MIN, &admin)?;
    assert_eq!(n.state.validate_candidate(&expired, now), Err(NetError::Expired));
    let stranger = n.sign(&member(&identity(20)), &identity(11), now)?;
    assert!(n.state.validate_candidate(&stranger, now).is_err());
    // Back-dated by an admin whose delegation has expired by now: replay alone would take it (quiet log), the
    // operator must not.
    let backdated = n.sign(&member(&identity(21)), &admin, T0 + DAY - MIN)?;
    assert!(n.state.validate_candidate(&backdated, T0 + DAY + MIN).is_err());
    // Witnesses refuse heads with entries dated after the head.
    n.accept(&future)?;
    let head_statement = n.log.issue_head(&n.owner, now)?;
    let head = verify_head(&head_statement, &n.net, &n.owner_card)?;
    assert_eq!(check_new_entries(&n.log.entries()[1..], &head), Err(NetError::NotYetValid));
    let later = verify_head(&n.log.issue_head(&n.owner, now + MIN)?, &n.net, &n.owner_card)?;
    check_new_entries(&n.log.entries()[1..], &later)?;
    Ok(())
}

#[test]
fn heads_cosigns_and_split_view_against_the_state() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |manifest| {
        manifest.witnesses = vec![identity(1).id().clone(), identity(2).id().clone(), identity(3).id().clone()];
        manifest.witness_threshold = 2;
    })?;
    n.seal_owner(T0 + 1)?;
    let (w2, w3) = (identity(2), identity(3));
    for witness in [&w2, &w3] {
        let seal = Seal {
            subject: witness.id().clone(),
            level: 3,
            services: Services::of(&[bridge_net::Service::Witness]),
            card: Some(node_card(witness, "https://w.example")?),
        };
        n.accept(&n.sign(&seal, &n.master, T0 + 2)?)?;
    }
    let outsider = identity(4);
    let head_statement = n.log.issue_head(&n.owner, T0 + 3)?;
    let head = verify_head(&head_statement, &n.net, &n.owner_card)?;
    let manifest = n.state.rules_for_head(head.size()).ok_or(NetError::NotFound("rules".into()))?;
    let cards = (&n.state, vec![outsider.key_card(Role::Node, None, T0)?]);
    // Threshold 2: one witness is not enough; an outsider does not count; two witnesses are.
    let one = WitnessedHead { head: head_statement.clone(), cosigns: vec![issue_cosign(&w2, &head, T0 + 4)?] };
    assert!(one.check(&n.net, &manifest, &cards, T0 + 5).is_err());
    let with_outsider = WitnessedHead {
        head: head_statement.clone(),
        cosigns: vec![issue_cosign(&w2, &head, T0 + 4)?, issue_cosign(&outsider, &head, T0 + 4)?],
    };
    assert!(with_outsider.check(&n.net, &manifest, &cards, T0 + 5).is_err());
    let two = WitnessedHead {
        head: head_statement.clone(),
        cosigns: vec![issue_cosign(&w2, &head, T0 + 4)?, issue_cosign(&w3, &head, T0 + 4)?],
    };
    assert_eq!(two.check(&n.net, &manifest, &cards, T0 + 5)?, head);
    // A head of a node that is no log operator, even fully cosigned.
    let rogue_statement = issue_head(&w2, &n.net, head.size(), *head.root(), T0 + 3)?;
    let rogue_head =
        verify_head(&rogue_statement, &n.net, n.state.card_of(w2.id()).ok_or(NetError::NotFound("w2".into()))?)?;
    let rogue = WitnessedHead {
        head: rogue_statement,
        cosigns: vec![issue_cosign(&w2, &rogue_head, T0 + 4)?, issue_cosign(&w3, &rogue_head, T0 + 4)?],
    };
    assert!(matches!(rogue.check(&n.net, &manifest, &cards, T0 + 5), Err(NetError::Forbidden(_))));

    // Split view: the operator shows a second log with one other entry. (a) same size, (b) a prefix that does not fit.
    let mut fork = Log::from_entries(n.net.clone(), &n.log.entries()[..n.log.entries().len() - 1])?;
    let other_entry = n.sign(&ban(&identity(50)), &n.master, T0 + 2)?;
    fork.append(&other_entry)?;
    let fork_head = fork.issue_head(&n.owner, T0 + 6)?;
    let evidence =
        Evidence::check(&head_statement, &fork_head, &n.owner_card, None).ok_or(NetError::NotFound("a".into()))?;
    assert!(evidence.verify(&n.owner_card, None));
    n.accept(&n.sign(&ban(&identity(51)), &n.master, T0 + 7)?)?;
    let honest_large = n.log.issue_head(&n.owner, T0 + 8)?;
    assert!(Evidence::check(&head_statement, &honest_large, &n.owner_card, Some(n.log.tree())).is_none());
    assert!(Evidence::check(&fork_head, &honest_large, &n.owner_card, Some(n.log.tree())).is_some(), "(b)");
    assert!(Evidence::check(&fork_head, &honest_large, &n.owner_card, Some(fork.tree())).is_none(), "tree must fit");
    // Heads of different operators are never evidence against one of them.
    let w2_card = n.state.card_of(w2.id()).cloned().ok_or(NetError::NotFound("w2".into()))?;
    assert!(Evidence::check(&head_statement, &fork_head, &w2_card, None).is_none());
    Ok(())
}

#[test]
fn bogus_manifest_bodies_in_the_log() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let v2 = n.state.manifest().next_version();
    let valid = n.sign(&v2, &n.master, T0 + 1)?;
    for (path, value) in [
        ("/body/witness_threshold", json!(5)),
        ("/body/logs", json!([])),
        ("/body/limits/members", json!(2_000_000)),
        ("/body/extra", json!(true)),
    ] {
        let mut changed = valid.to_value();
        if path == "/body/extra" {
            changed["body"]["extra"] = value;
        } else if let Some(field) = changed.pointer_mut(path) {
            *field = value;
        }
        // Re-sign so only the body rules can refuse it.
        let draft = bridge_core::Draft {
            kind: "manifest",
            net: &n.net,
            iat: T0 + 1,
            exp: T0 + DAY,
            body: changed["body"].clone(),
        };
        let statement = Statement::sign(&draft, &n.master)?;
        assert!(matches!(n.skip(&statement)?, NetError::BadFormat(_)), "{path}");
    }
    n.accept(&valid)?;
    Ok(())
}
