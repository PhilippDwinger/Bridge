//! Phase 8, step 3 (docs/11 §14): one Bridge Login account on several devices. A device that is logged in shows a
//! pairing code, the new device creates its own passkey, both show the same check digits, the old device approves with
//! its passkey - an `add` entry every storage node checks itself. Removing works the same way (the last device stays).

mod login_common;

use bridge_core::encoding::b64;
use bridge_net::JoinMode;
use bridge_tests::net::{TestNet, eventually};
use login_common::{Entrance, Passkey, code, login_node};
use serde_json::{Value, json};

type TestResult = Result<(), String>;

/// A WebAuthn get ceremony of `passkey` over `challenge` (Base64url) at `entrance`, as the request body fields.
fn approve(entrance: &Entrance, passkey: &Passkey, challenge: &str, counter: u32) -> Value {
    let (client, auth) = (entrance.client_data("webauthn.get", challenge), entrance.auth_data(counter));
    json!({
        "credential_id": b64(&passkey.id),
        "client_data": b64(&client),
        "auth_data": b64(&auth),
        "signature": passkey.sign(&auth, &client),
    })
}

fn merged(mut base: Value, more: Value) -> Value {
    if let (Some(base), Some(more)) = (base.as_object_mut(), more.as_object()) {
        for (key, value) in more {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

async fn ok(entrance: &Entrance, path: &str, body: &Value) -> Result<Value, String> {
    match entrance.post(path, body).await? {
        (200, answer) => Ok(answer),
        other => Err(format!("{path}: {other:?}")),
    }
}

/// B joins with `code`, creates `passkey` and offers it; returns (ticket, check digits).
async fn offer(entrance: &Entrance, code: &str, passkey: &Passkey, label: &str) -> Result<(String, String), String> {
    let joined = ok(entrance, "pair/join", &json!({"code": code, "label": label})).await?;
    let ticket = joined["ticket"].as_str().unwrap_or_default().to_owned();
    let challenge = joined["challenge"].as_str().unwrap_or_default();
    let body = json!({
        "ticket": ticket,
        "credential": passkey.credential(),
        "client_data": b64(&entrance.client_data("webauthn.create", challenge)),
        "auth_data": b64(&entrance.auth_data(0)),
    });
    let offered = ok(entrance, "pair/offer", &body).await?;
    Ok((ticket, offered["check"].as_str().unwrap_or_default().to_owned()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_second_device_is_paired_approved_and_removed() -> TestResult {
    let net = TestNet::create(JoinMode::Invite).await?;
    let (_a, a) = login_node(&net, "a.tail1234.ts.net", false).await?;
    let (first, second) = (Passkey::new(1), Passkey::new(2));
    let made = ok(&a, "register", &a.register_body("Paddy", &first, &code(7)).await?).await?;
    let session = made["session"].as_str().unwrap_or_default().to_owned();
    let devices = ok(&a, "devices", &json!({"session": session})).await?;
    assert_eq!(devices["devices"].as_array().map(Vec::len), Some(1), "{devices}");
    assert_eq!(devices["devices"][0]["label"], json!("Gerät 1"));

    // A shows a code (and its QR code) - only for a page of its own entrance.
    let link = "https://a.tail1234.ts.net/bridge4/testnetz/web/shop/";
    let (status, _) = a.post("pair/start", &json!({"session": session, "link": "https://evil.example/x"})).await?;
    assert_eq!(status, 400, "a link of another origin");
    let started = ok(&a, "pair/start", &json!({"session": session, "link": link})).await?;
    let pairing = started["code"].as_str().unwrap_or_default().to_owned();
    assert!(pairing.len() == 9 && pairing.as_bytes()[4] == b'-', "{pairing}");
    let size = started["qr"]["size"].as_u64().unwrap_or(0) as usize;
    assert!(size >= 21 && started["qr"]["modules"].as_str().is_some_and(|m| m.len() == size * size));
    let status = ok(&a, "pair/status", &json!({"session": session, "code": pairing})).await?;
    assert_eq!(status["state"], json!("waiting"));

    // B types it (lower case, with spaces), creates its own passkey; both see the same check digits.
    let typed = pairing.to_lowercase().replace('-', " ");
    let (ticket, check) = offer(&a, &typed, &second, "Handy").await?;
    assert!(check.len() == 3 && check.bytes().all(|b| b.is_ascii_digit()), "{check}");
    let (status, _) = a.post("pair/join", &json!({"code": pairing, "label": "Dieb"})).await?;
    assert_eq!(status, 403, "a code counts once");
    let shown = ok(&a, "pair/status", &json!({"session": session, "code": pairing})).await?;
    assert_eq!(
        (shown["state"].clone(), shown["check"].clone(), shown["label"].clone()),
        (json!("offered"), json!(check), json!("Handy"))
    );
    let challenge = shown["challenge"].as_str().unwrap_or_default().to_owned();
    let waiting = ok(&a, "pair/wait", &json!({"ticket": ticket})).await?;
    assert_eq!(waiting["state"], json!("waiting"));

    // Attacks: the new passkey approves itself; another session than the account's.
    let own = merged(json!({"session": session, "code": pairing}), approve(&a, &second, &challenge, 0));
    assert_eq!(a.post("pair/approve", &own).await?.0, 403, "only a passkey of the account approves");
    let stranger = ok(&a, "register", &a.register_body("Fremd", &Passkey::new(9), &code(9)).await?).await?;
    let foreign =
        merged(json!({"session": stranger["session"], "code": pairing}), approve(&a, &Passkey::new(9), &challenge, 0));
    assert_eq!(a.post("pair/approve", &foreign).await?.0, 403, "a stranger can not approve it");

    // A approves with its passkey: two devices; B gets its session and logs in with its own passkey.
    let approved = ok(
        &a,
        "pair/approve",
        &merged(json!({"session": session, "code": pairing}), approve(&a, &first, &challenge, 0)),
    )
    .await?;
    let labels: Vec<&str> =
        approved["devices"].as_array().into_iter().flatten().filter_map(|d| d["label"].as_str()).collect();
    assert_eq!(labels, ["Gerät 1", "Handy"]);
    let done = ok(&a, "pair/wait", &json!({"ticket": ticket})).await?;
    assert_eq!((done["state"].clone(), done["account"].clone()), (json!("done"), made["account"].clone()));
    assert!(done["session"].as_str().is_some_and(|s| !s.is_empty()));
    let (status, logged) = a.assert(&second, 0).await?;
    assert_eq!((status, logged["account"].clone()), (200, made["account"].clone()));
    assert_eq!(a.assert(&first, 0).await?.0, 200, "the first device still works");

    // The second storage node gets the `add` entry and checks the approval itself.
    let (_b, b) = login_node(&net, "b.tail1234.ts.net", false).await?;
    eventually("the second device reached the other storage node", || async {
        match b.assert(&second, 0).await? {
            (200, _) => Ok(()),
            other => Err(format!("{other:?}")),
        }
    })
    .await?;

    // Removing: prepared, approved by a passkey of the account; the last device stays.
    let target = b64(&second.id);
    let prepared = ok(&a, "remove/prepare", &json!({"session": session, "target": target})).await?;
    let challenge = prepared["challenge"].as_str().unwrap_or_default();
    let removed = ok(&a, "remove", &merged(json!({"session": session}), approve(&a, &first, challenge, 0))).await?;
    assert_eq!(removed["devices"].as_array().map(Vec::len), Some(1));
    assert_eq!(a.assert(&second, 0).await?.0, 403, "the removed passkey is out");
    let (status, _) = a.post("remove/prepare", &json!({"session": session, "target": b64(&first.id)})).await?;
    assert_eq!(status, 403, "the last device stays");

    // A refuses a device: B learns it.
    let started = ok(&a, "pair/start", &json!({"session": session, "link": link})).await?;
    let pairing = started["code"].as_str().unwrap_or_default().to_owned();
    let (ticket, _) = offer(&a, &pairing, &Passkey::new(3), "Laptop").await?;
    ok(&a, "pair/cancel", &json!({"session": session, "code": pairing})).await?;
    assert_eq!(ok(&a, "pair/wait", &json!({"ticket": ticket})).await?["state"], json!("cancelled"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guessing_codes_is_cut_off() -> TestResult {
    let net = TestNet::create(JoinMode::Invite).await?;
    let (_a, a) = login_node(&net, "a.tail1234.ts.net", false).await?;
    for guess in ["AAAA-AAAA", "BBBB-BBBB", "CCCC-CCCC", "DDDD-DDDD", "EEEE-EEEE"] {
        assert_eq!(a.post("pair/join", &json!({"code": guess, "label": "Rate"})).await?.0, 403, "{guess}");
    }
    assert_eq!(a.post("pair/join", &json!({"code": "FFFF-FFFF", "label": "Rate"})).await?.0, 429, "5 per address");
    let (status, _) = a.post("pair/start", &json!({"session": "kaputt", "link": "x"})).await?;
    assert_eq!(status, 401, "a session is needed");
    Ok(())
}
