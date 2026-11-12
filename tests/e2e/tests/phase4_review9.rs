//! Review 9 (phase 4) across nodes: node names say whether their card is verified; the loopback reader listener
//! serves the own browser of a node that trusts a local proxy (Tailscale Funnel), and nothing else.

use bridge_core::{Identity, Role, Statement};
use bridge_net::{Category, JoinMode, Member, Name, NameKind, Seal, Services};
use bridge_node::admin::YEAR_MS;
use bridge_node::{ReaderAccess, keyfile};
use bridge_sdk::AppDraft;
use bridge_tests::apps::{AppNet, app_folder, get, gone, served};
use bridge_tests::net::{TestNet, TestNode, eventually, test_config};
use bridge_tests::now_ms;
use rand_core::OsRng;
use serde_json::{Value, json};
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

const DAY_MS: i64 = 24 * 3600 * 1000;
const ENTRY: &[u8] = b"<!doctype html><h1>Hallo Bridge-App</h1>";

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// A POST of JSON: status and parsed answer.
async fn post(url: &str, path: &str, body: &Value, headers: &[(&str, &str)]) -> Result<(u16, Value), String> {
    let mut request = reqwest::Client::new().post(format!("{url}{path}")).body(body.to_string());
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.map_err(e)?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.map_err(e)?;
    Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
}

/// A node name of `node` (owner = target = the node), signed by the node's key, handed in by the admin.
async fn node_name(net: &TestNet, name: &str, node: &Identity) -> Result<(), String> {
    let body = Name {
        name: name.into(),
        kind: NameKind::Node,
        target: node.id().clone(),
        owner: node.id().clone(),
        owner_card: node
            .key_card_with(Role::Node, None, &["https://phish.example".into()], None, now_ms())
            .map_err(e)?,
        card: None,
        description: "Ein Knoten".into(),
        tags: Vec::new(),
        category: Category::General,
        hosts: Vec::new(),
    };
    let now = now_ms();
    let statement: Statement = body.sign_name(&net.net, now, now + 30 * DAY_MS, node, None).map_err(e)?;
    net.admin.submit(&statement).await?;
    Ok(())
}

/// Review 9, finding 9: a node name of a node without a seal once returned the node's own card (with whatever
/// addresses it claims) like a checked one. It is marked now: `card_verified: false` and the warning
/// `card_unverified`; a sealed node's card comes from its seal (`true`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_names_say_whether_their_card_is_verified() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let other = net.add_node(&[]).await?;
    let other_key = keyfile::load_or_create(other.dir.path())?;
    // A member of level 1 without a card in the log (sealed by the admin without card).
    net.admin.submit(&net.admin.sign(&Member { member: other.id(), invite: None }, YEAR_MS)?).await?;
    let seal = Seal { subject: other.id(), level: 1, services: Services::NONE, card: None };
    net.admin.submit(&net.admin.sign(&seal, YEAR_MS)?).await?;
    node_name(&net, "nebenan", &other_key).await?;
    let owner_key = keyfile::load_or_create(net.owner.dir.path())?;
    node_name(&net, "zentrale", &owner_key).await?;
    let resolve = |name: &'static str| {
        let url = net.owner.url.clone();
        async move {
            eventually(name, || async {
                let (status, answer) = post(&url, "/v4/names/resolve", &json!({"name": name}), &[]).await?;
                if status == 200 { Ok(answer) } else { Err(format!("{status} {answer}")) }
            })
            .await
        }
    };
    let unsealed = resolve("nebenan").await?;
    assert_eq!(unsealed["card_verified"], json!(false), "{unsealed}");
    assert!(unsealed["safety"]["warnings"].as_array().is_some_and(|list| list.contains(&json!("card_unverified"))));
    assert_eq!(unsealed["card"]["urls"], json!(["https://phish.example"]), "only the node's own word");
    let sealed = resolve("zentrale").await?;
    assert_eq!(sealed["card_verified"], json!(true), "{sealed}");
    assert!(!sealed["safety"]["warnings"].as_array().is_some_and(|list| list.contains(&json!("card_unverified"))));
    assert_ne!(sealed["card"]["urls"], json!(["https://phish.example"]), "the card from the seal");
    Ok(())
}

/// Review 9, open point of the UI: a node behind Tailscale Funnel trusts the proxy on 127.0.0.1, so its reader refused
/// the user's own browser. Its loopback listener (`reader_listen`) serves the reader and the name lookups to this
/// computer - without trusting any proxy - and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loopback_reader_serves_the_own_browser_of_a_node_behind_a_proxy() -> TestResult {
    let apps = AppNet::new(0).await?;
    let (net, owner_node, owner) = (&apps.net, &apps.net.owner, apps.owner());
    let seal = Seal { subject: owner.id().clone(), level: 2, services: Services::NONE, card: None };
    net.admin.submit(&net.admin.sign(&seal, YEAR_MS)?).await?;
    let (folder, _) = app_folder(10)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(owner_node).await?;
    let draft = AppDraft {
        name: "Laden".into(),
        description: String::new(),
        entry: "index.html".into(),
        version: 1,
        hosts: vec![owner_node.id()],
    };
    client.publish_folder(&app, folder.path(), &draft).await.map_err(e)?;
    // A node like BridgeControll starts one behind Tailscale Funnel: the local proxy is trusted.
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let mut config = test_config(dir.path(), Some(net.membership(&[])), "https://pc.tail1234.ts.net/k1");
    config.reader.access = ReaderAccess::Local;
    config.server.trusted_proxies = vec![[127, 0, 0, 1].into()];
    config.reader_listen = Some(([127, 0, 0, 1], 0).into());
    let node = bridge_node::start(config, listener).await?;
    let reader = node.reader_addr().ok_or("no loopback reader")?;
    let funnel = TestNode { dir, node, url };
    net.synced(&funnel).await?;
    let reader_url = format!("http://{reader}");
    let path = format!("/app/{}/", app.id());
    // The main listener can not tell this browser from the Internet: closed (fail closed, as before).
    gone(&format!("{}{path}", funnel.url)).await?;
    // The loopback listener serves it, checked part by part like any reader.
    served(&format!("{reader_url}{path}"), ENTRY).await?;
    // Name lookups there fetch the app for the own browser (`open`).
    let name = Name {
        name: "shop".into(),
        kind: NameKind::App,
        target: app.id().clone(),
        owner: owner.id().clone(),
        owner_card: owner.key_card(Role::Client, None, now_ms()).map_err(e)?,
        card: Some(app.key_card(Role::App, None, now_ms()).map_err(e)?),
        description: "Ein Laden".into(),
        tags: Vec::new(),
        category: Category::General,
        hosts: vec![owner_node.id()],
    };
    let now = now_ms();
    net.admin.submit(&name.sign_name(&net.net, now, now + 30 * DAY_MS, &owner, Some(&app)).map_err(e)?).await?;
    let resolved = eventually("resolved at the loopback reader", || async {
        let (status, answer) = post(&reader_url, "/v4/names/resolve", &json!({"name": "shop.testnetz"}), &[]).await?;
        if status == 200 && answer["open"].is_string() { Ok(answer) } else { Err(format!("{status} {answer}")) }
    })
    .await?;
    assert_eq!(resolved["open"], json!(path));
    let (status, found) = post(&reader_url, "/v4/names/search", &json!({"q": "shop", "safe": false}), &[]).await?;
    assert_eq!((status, found["results"][0]["name"].clone()), (200, json!("shop")), "{found}");
    // Nothing else is served there - not the API, not what writes.
    for (method, path) in [("GET", "/v4/info"), ("POST", "/v4/names/submit"), ("POST", "/v4/send"), ("GET", "/admin")] {
        let request = reqwest::Client::new().request(method.parse().map_err(e)?, format!("{reader_url}{path}"));
        let status = request.body("{}").send().await.map_err(e)?.status().as_u16();
        assert_eq!(status, 404, "{method} {path}");
    }
    // A forwarding header or a foreign `Host` (DNS rebinding) still closes the reader there.
    let forwarded = reqwest::Client::new().get(format!("{reader_url}{path}")).header("x-forwarded-for", "8.8.8.8");
    assert_eq!(forwarded.send().await.map_err(e)?.status().as_u16(), 404);
    let rebound = reqwest::Client::new().get(format!("{reader_url}{path}")).header("host", "evil.example");
    assert_eq!(rebound.send().await.map_err(e)?.status().as_u16(), 404);
    let (status, _, _) = get(&format!("{reader_url}{path}")).await?;
    assert_eq!(status, 200);
    // Only a loopback address can be the loopback listener.
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let mut config = test_config(dir.path(), None, "http://127.0.0.1:1");
    config.reader_listen = Some(([0, 0, 0, 0], 0).into());
    let refused = bridge_node::start(config, listener).await;
    assert!(refused.is_err_and(|error| error.contains("loopback")));
    Ok(())
}
