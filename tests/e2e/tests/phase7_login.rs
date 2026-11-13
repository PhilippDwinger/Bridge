//! Phase 7, step 4 (docs/11 §9, ADR 0027): Bridge Login - accounts with passkeys at the storage nodes of a network.
//! A test authenticator (ES256 via `es256_test_sign`) stands in for the browser: register, log in, recover, the
//! account exchange between storage nodes, app tokens for the server code of an app and the frame's login script.

use bridge_core::encoding::b64;
use bridge_core::login::{account_id, app_user, recovery_hash};
use bridge_core::{Draft, Id, Identity, Role, Statement};
use bridge_net::{Category, JoinMode, Name, NameKind, Seal, Services};
use bridge_node::admin::YEAR_MS;
use bridge_sdk::AppDraft;
use bridge_tests::apps::{AppNet, get, header, served};
use bridge_tests::net::{TestNet, eventually};
use bridge_tests::now_ms;
use rand_core::OsRng;
use serde_json::json;

mod login_common;

use login_common::{Entrance, Passkey, code, e, login_node};

type TestResult = Result<(), String>;

const DAY_MS: i64 = 24 * 3600 * 1000;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn accounts_register_log_in_recover_and_reach_every_storage_node() -> TestResult {
    let net = TestNet::create(JoinMode::Invite).await?;
    // Without a storage node at level 2 login is off (and says why).
    let owner = Entrance { url: net.owner.url.clone(), rp_id: "x".into(), origin: "https://x".into() };
    let info = owner.info().await?;
    assert_eq!(info["enabled"], json!(false), "{info}");
    assert!(info["reason"].as_str().unwrap_or_default().contains("Speicher"), "{info}");
    assert_eq!(owner.post("challenge", &json!({})).await?.0, 403);

    let (_a, a) = login_node(&net, "a.tail1234.ts.net", false).await?;
    let info = a.info().await?;
    assert_eq!(
        (info["rp_id"].as_str(), info["origin"].as_str()),
        (Some("a.tail1234.ts.net"), Some("https://a.tail1234.ts.net"))
    );
    assert_eq!(info["login_nodes"], json!(1));

    // Register: the account ID follows from key and recovery hash.
    let (first, first_code) = (Passkey::new(1), code(7));
    let (status, made) = a.post("register", &a.register_body("Paddy", &first, &first_code).await?).await?;
    assert_eq!(status, 200, "{made}");
    let account = made["account"].as_str().unwrap_or_default().to_owned();
    assert_eq!(account, account_id(&first.spki, &recovery_hash(&first_code)).to_string());
    assert_eq!(made["name"], json!("Paddy"));
    assert!(made["session"].as_str().is_some_and(|s| !s.is_empty()));

    // Attacks on register: a used challenge, another origin or RP, the wrong ceremony, a passkey of another account.
    let body = a.register_body("Zwei", &Passkey::new(2), &code(8)).await?;
    assert_eq!(a.post("register", &body).await?.0, 200);
    assert_eq!(a.post("register", &body).await?.0, 403, "a challenge counts once");
    let evil = Entrance { origin: "https://evil.example".into(), ..a.clone() };
    let (status, _) = a.post("register", &evil.register_body("Böse", &Passkey::new(3), &code(9)).await?).await?;
    assert_eq!(status, 400, "foreign origin");
    let other_rp = Entrance { rp_id: "evil.example".into(), ..a.clone() };
    let (status, _) = a.post("register", &other_rp.register_body("Böse", &Passkey::new(3), &code(9)).await?).await?;
    assert_eq!(status, 400, "foreign RP ID");
    let challenge = a.challenge().await?;
    let mut wrong = a.register_body("Böse", &Passkey::new(3), &code(9)).await?;
    wrong["client_data"] = json!(b64(&a.client_data("webauthn.get", &challenge)));
    assert_eq!(a.post("register", &wrong).await?.0, 400, "a login is no registration");
    let (status, _) = a.post("register", &a.register_body("Dieb", &first, &code(10)).await?).await?;
    assert_eq!(status, 403, "a passkey belongs to one account");
    for name in ["", "   ", &"x".repeat(41), "a\u{7}b"] {
        let (status, _) = a.post("register", &a.register_body(name, &Passkey::new(4), &code(11)).await?).await?;
        assert_eq!(status, 400, "name {name:?}");
    }

    // Log in: signature and counter.
    let (status, logged) = a.assert(&first, 1).await?;
    assert_eq!(status, 200, "{logged}");
    assert_eq!((logged["account"].as_str(), logged["name"].as_str()), (Some(account.as_str()), Some("Paddy")));
    assert_eq!(a.assert(&first, 1).await?.0, 403, "the counter must go up (copied passkey)");
    assert_eq!(a.assert(&first, 5).await?.0, 200);
    let forged = Passkey { secret: [9; 32], ..Passkey::new(1) };
    assert_ne!(a.assert(&forged, 6).await?.0, 200, "signed with another key");
    assert_eq!(a.assert(&Passkey::new(5), 1).await?.0, 403, "unknown passkey");

    // App tokens: one user ID per app.
    let session = logged["session"].as_str().unwrap_or_default().to_owned();
    let (shop, blog) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
    let (status, token) = a.post("app", &json!({"session": session, "app": shop.id().as_str()})).await?;
    assert_eq!(status, 200, "{token}");
    let account_id_parsed = Id::parse(&account).map_err(e)?;
    assert_eq!(token["user"], json!(app_user(&account_id_parsed, shop.id()).to_string()));
    let (_, other) = a.post("app", &json!({"session": session, "app": blog.id().as_str()})).await?;
    assert_ne!(token["user"], other["user"], "no tracking across apps");
    let mut tampered = session.clone();
    tampered.replace_range(10..11, if &tampered[10..11] == "A" { "B" } else { "A" });
    assert_ne!(a.post("app", &json!({"session": tampered, "app": shop.id().as_str()})).await?.0, 200);
    let fake = forged_session(&net, &account)?;
    assert_eq!(
        a.post("app", &json!({"session": fake, "app": shop.id().as_str()})).await?.0,
        401,
        "a stranger's session"
    );

    // Recover: only with the old code, then the old passkey and code are worthless.
    let (second, second_code) = (Passkey::new(6), code(12));
    let (status, _) = a.recover(&account, &code(99), &second, &second_code).await?;
    assert_eq!(status, 403, "wrong code");
    let (status, recovered) = a.recover(&account, &first_code, &second, &second_code).await?;
    assert_eq!(status, 200, "{recovered}");
    assert_eq!(recovered["account"].as_str(), Some(account.as_str()));
    assert_eq!(a.assert(&first, 9).await?.0, 403, "the old passkey is gone");
    assert_eq!(a.assert(&second, 0).await?.0, 200, "an authenticator without a counter");
    let (status, _) = a.recover(&account, &first_code, &Passkey::new(13), &code(13)).await?;
    assert_eq!(status, 403, "the old code is used up");

    // A second storage node gets every account by the exchange and can check the passkey itself.
    let (_b, b) = login_node(&net, "b.tail1234.ts.net", false).await?;
    assert_eq!(b.info().await?["login_nodes"], json!(2));
    let logged_b = eventually("account reached the second storage node", || async {
        match b.assert(&second, 0).await? {
            (200, answer) => Ok(answer),
            other => Err(format!("{other:?}")),
        }
    })
    .await?;
    assert_eq!(logged_b["name"], json!("Paddy"));
    // A session of A counts at B (A is a storage node of the network).
    let (status, _) = b.post("app", &json!({"session": session, "app": shop.id().as_str()})).await?;
    assert_eq!(status, 200);
    Ok(())
}

/// A session signed by a node that holds no accounts.
fn forged_session(net: &TestNet, account: &str) -> Result<String, String> {
    let stranger = Identity::generate(&mut OsRng);
    let now = now_ms();
    let statement = Statement::sign(
        &Draft { kind: "session", net: &net.net, iat: now, exp: now + 3600 * 1000, body: json!({"account": account}) },
        &stranger,
    )
    .map_err(e)?;
    Ok(bridge_core::login::token_text(&statement))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn registrations_per_address_are_limited() -> TestResult {
    let net = TestNet::create(JoinMode::Invite).await?;
    let (_a, a) = login_node(&net, "a.tail1234.ts.net", false).await?;
    for seed in 0..5u8 {
        let (status, answer) =
            a.post("register", &a.register_body("Viele", &Passkey::new(20 + seed), &code(seed)).await?).await?;
        assert_eq!(status, 200, "{answer}");
    }
    let (status, _) = a.post("register", &a.register_body("Viele", &Passkey::new(30), &code(30)).await?).await?;
    assert_eq!(status, 429, "at most 5 new accounts per address and hour");
    Ok(())
}

/// Server code that answers `user` (`dXNlcg`) when its input is longer than without login, else `anon` (`YW5vbg`).
fn who_server() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (memory (export "memory") 1)
          (data (i32.const 0) "{\22status\22:200,\22type\22:\22text/plain\22,\22body\22:\22dXNlcg\22}")
          (data (i32.const 100) "{\22status\22:200,\22type\22:\22text/plain\22,\22body\22:\22YW5vbg\22}")
          (func (export "alloc") (param i32) (result i32) i32.const 1024)
          (func (export "handle") (param $p i32) (param $l i32) (result i64)
            (if (result i64) (i32.gt_u (local.get $l) (i32.const 60))
              (then (i64.const 50))
              (else (i64.or (i64.shl (i64.const 100) (i64.const 32)) (i64.const 50))))))"#,
    )
    .unwrap_or_default()
}

async fn api(url: &str, token: Option<&str>) -> Result<(u16, String), String> {
    let mut request = reqwest::Client::new().post(url).body(Vec::new());
    if let Some(token) = token {
        request = request.header("x-bridge-login", token);
    }
    let answer = request.send().await.map_err(e)?;
    let status = answer.status().as_u16();
    Ok((status, answer.text().await.map_err(e)?))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn server_code_gets_the_user_of_a_valid_app_token_only() -> TestResult {
    let apps = AppNet::new(0).await?;
    let host = &apps.net.owner;
    let folder = tempfile::tempdir().map_err(e)?;
    std::fs::write(folder.path().join("index.html"), b"<!doctype html><h1>Wer?</h1>").map_err(e)?;
    std::fs::write(folder.path().join("server.wasm"), who_server()).map_err(e)?;
    let app = Identity::generate(&mut OsRng);
    let draft = AppDraft {
        name: "Wer".into(),
        description: String::new(),
        entry: "index.html".into(),
        version: 1,
        hosts: vec![host.id()],
    };
    apps.owner_at(host).await?.publish_folder(&app, folder.path(), &draft).await.map_err(e)?;
    served(&format!("{}/app/{}/", host.url, app.id()), b"<!doctype html><h1>Wer?</h1>").await?;

    let (_a, a) = login_node(&apps.net, "a.tail1234.ts.net", false).await?;
    let (status, made) = a.post("register", &a.register_body("Gast", &Passkey::new(40), &code(40)).await?).await?;
    assert_eq!(status, 200, "{made}");
    let session = made["session"].as_str().unwrap_or_default();
    let (_, token) = a.post("app", &json!({"session": session, "app": app.id().as_str()})).await?;
    let token = token["token"].as_str().unwrap_or_default().to_owned();
    let other_app = Identity::generate(&mut OsRng);
    let (_, foreign) = a.post("app", &json!({"session": session, "app": other_app.id().as_str()})).await?;
    let foreign = foreign["token"].as_str().unwrap_or_default().to_owned();

    let url = format!("{}/app/{}/api/who", host.url, app.id());
    assert_eq!(api(&url, None).await?, (200, "anon".to_owned()), "no header: no user");
    assert_eq!(api(&url, Some(&token)).await?, (200, "user".to_owned()), "the host checked the token");
    assert_eq!(api(&url, Some(&foreign)).await?.0, 401, "a token of another app");
    assert_eq!(api(&url, Some("kaputt")).await?.0, 401);
    assert_eq!(api(&url, Some(&"A".repeat(5000))).await?.0, 400, "header too long");
    let now = now_ms();
    let stranger = Identity::generate(&mut OsRng);
    let fake = Statement::sign(
        &Draft {
            kind: "login",
            net: &apps.net.net,
            iat: now,
            exp: now + 600_000,
            body: json!({"app": app.id().as_str(), "user": app.id().as_str(), "name": "Fake"}),
        },
        &stranger,
    )
    .map_err(e)?;
    assert_eq!(api(&url, Some(&bridge_core::login::token_text(&fake))).await?.0, 401, "issuer holds no accounts");
    // The browser's preflight for the header.
    let preflight = reqwest::Client::new().request(reqwest::Method::OPTIONS, &url).send().await.map_err(e)?;
    assert_eq!(preflight.status().as_u16(), 204);
    let allowed =
        preflight.headers().get("access-control-allow-headers").and_then(|v| v.to_str().ok()).unwrap_or_default();
    assert!(allowed.contains("X-Bridge-Login"), "{allowed}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_frame_of_a_login_node_carries_bridges_login_script() -> TestResult {
    let apps = AppNet::new(0).await?;
    let (net, owner_node, owner) = (&apps.net, &apps.net.owner, apps.owner());
    let seal = Seal { subject: owner.id().clone(), level: 2, services: Services::NONE, card: None };
    net.admin.submit(&net.admin.sign(&seal, YEAR_MS)?).await?;
    let folder = tempfile::tempdir().map_err(e)?;
    std::fs::write(folder.path().join("index.html"), b"<!doctype html><h1>Laden</h1>").map_err(e)?;
    let app = Identity::generate(&mut OsRng);
    let draft = AppDraft {
        name: "Laden".into(),
        description: String::new(),
        entry: "index.html".into(),
        version: 1,
        hosts: vec![owner_node.id()],
    };
    apps.owner_at(owner_node).await?.publish_folder(&app, folder.path(), &draft).await.map_err(e)?;
    let name = Name {
        name: "shop".into(),
        kind: NameKind::App,
        target: app.id().clone(),
        owner: owner.id().clone(),
        owner_card: owner.key_card(Role::Client, None, now_ms()).map_err(e)?,
        card: Some(app.key_card(Role::App, None, now_ms()).map_err(e)?),
        description: String::new(),
        tags: Vec::new(),
        category: Category::General,
        hosts: vec![owner_node.id()],
    };
    let now = now_ms();
    net.admin.submit(&name.sign_name(&net.net, now, now + 30 * DAY_MS, &owner, Some(&app)).map_err(e)?).await?;

    let (public, _) = login_node(net, "pc.tail1234.ts.net", true).await?;
    let (headers, frame) = eventually("frame with login", || async {
        let (status, headers, body) = get(&format!("{}/web/shop/", public.url)).await?;
        let page = String::from_utf8_lossy(&body).into_owned();
        if status == 200 { Ok((headers, page)) } else { Err(format!("{status} {page}")) }
    })
    .await?;
    assert!(frame.contains(&format!("id=\"bridge-login\" class=\"bl\" data-app=\"{}\"", app.id())), "{frame}");
    assert!(frame.contains("<script src=\"../../login.js\"></script>"), "{frame}");
    assert_eq!(frame.matches("<script").count(), 1, "only Bridge's own script: {frame}");
    let csp = header(&headers, "content-security-policy");
    assert!(
        csp.contains("script-src 'self'") && csp.contains("connect-src 'self'") && !csp.contains("unsafe-eval"),
        "{csp}"
    );
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(header(&headers, "cross-origin-opener-policy"), "same-origin");
    let (status, headers, script) = get(&format!("{}/login.js", public.url)).await?;
    assert_eq!(status, 200);
    assert!(header(&headers, "content-type").starts_with("text/javascript"));
    assert_eq!(header(&headers, "x-content-type-options"), "nosniff");
    let script = String::from_utf8_lossy(&script);
    assert!(
        script.contains("navigator.credentials") && !script.contains("innerHTML") && !script.contains("localStorage")
    );
    Ok(())
}
