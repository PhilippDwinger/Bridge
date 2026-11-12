//! Phase 4 acceptance (docs/05, docs/08, ADR 0018): an app on another PC gets the name `shop`; a node of the user
//! resolves `shop.testnetz` and loads the app through its own reader (verified part by part); a search for "shop" lists
//! it; forged names (other owner, wrong signer, confusable, reserved word at a low level, over quota, banned owner) are
//! refused; 18+ names are hidden in the safe search and refused - or stop the app - in networks that forbid them;
//! reports flow to the owner node and are bounded; the reader refuses strangers and manipulated parts.

use bridge_core::blob::PART_BYTES;
use bridge_core::{Address, Envelope, Id, Identity, KeyCard, Kind, Role, SignedRequest, Statement};
use bridge_net::{Body, Category, Name, NameKind, Seal, Services};
use bridge_node::admin::{NetOptions, YEAR_MS};
use bridge_node::{ReaderAccess, keyfile};
use bridge_sdk::{AppDraft, Client};
use bridge_tests::apps::{
    AppNet, app_folder, copy, corrupting_proxy, get, gone, header, node_behind, served, wait_gateway,
};
use bridge_tests::net::{TestNet, TestNode, eventually, test_config, wait_for};
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

fn draft(hosts: Vec<Id>) -> AppDraft {
    AppDraft { name: "Laden".into(), description: String::new(), entry: "index.html".into(), version: 1, hosts }
}

/// A POST with a JSON (or raw) body and an optional session: status and parsed answer.
async fn post(url: &str, path: &str, body: Vec<u8>, session: Option<&str>) -> Result<(u16, Value), String> {
    let client = reqwest::Client::new();
    let mut request = client.post(format!("{url}{path}")).body(body);
    if let Some(token) = session {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(e)?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await.map_err(e)?;
    Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
}

async fn post_json(url: &str, path: &str, body: &Value) -> Result<(u16, Value), String> {
    post(url, path, body.to_string().into_bytes(), None).await
}

/// A GET with extra headers: status and body.
async fn get_with(url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), String> {
    let mut request = reqwest::Client::new().get(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.map_err(e)?;
    let status = response.status().as_u16();
    Ok((status, response.bytes().await.map_err(e)?.to_vec()))
}

/// The admin seals a member (no card, no services) at `level`.
async fn seal_member(net: &TestNet, id: &Id, level: u8) -> Result<(), String> {
    let seal = Seal { subject: id.clone(), level, services: Services::NONE, card: None };
    net.admin.submit(&net.admin.sign(&seal, YEAR_MS)?).await?;
    Ok(())
}

fn member_name(name: &str, owner: &Identity, category: Category) -> Result<Name, String> {
    Ok(Name {
        name: name.into(),
        kind: NameKind::Member,
        target: owner.id().clone(),
        owner: owner.id().clone(),
        owner_card: owner.key_card(Role::Client, None, now_ms()).map_err(e)?,
        card: None,
        description: String::new(),
        tags: Vec::new(),
        category,
        hosts: Vec::new(),
    })
}

fn app_name(name: &str, owner: &Identity, app: &Identity, hosts: Vec<Id>) -> Result<Name, String> {
    Ok(Name {
        name: name.into(),
        kind: NameKind::App,
        target: app.id().clone(),
        owner: owner.id().clone(),
        owner_card: owner.key_card(Role::Client, None, now_ms()).map_err(e)?,
        card: Some(app.key_card(Role::App, None, now_ms()).map_err(e)?),
        description: "Ein Laden für Kleidung".into(),
        tags: vec!["laden".into(), "kleidung".into()],
        category: Category::General,
        hosts,
    })
}

fn signed(net: &Id, name: &Name, owner: &Identity, app: Option<&Identity>) -> Result<Statement, String> {
    let now = now_ms();
    name.sign_name(net, now, now + 30 * DAY_MS, owner, app).map_err(e)
}

/// Hands a statement in at a gateway (`/v4/names/submit`) with the session of `client`.
async fn submit(node: &TestNode, client: &Client, statement: &Statement) -> Result<(u16, Value), String> {
    post(&node.url, "/v4/names/submit", statement.canonical_bytes().to_vec(), client.session_token()).await
}

fn code(answer: &Value) -> &str {
    answer.get("error").and_then(Value::as_str).unwrap_or_default()
}

/// A member that joined at the owner node, logged in there.
async fn member(net: &TestNet) -> Result<(Identity, Client), String> {
    let identity = Identity::generate(&mut OsRng);
    drop(Client::join(copy(&identity), &net.link(None)).await.map_err(e)?);
    let client = eventually("member login", || async {
        let mut client = Client::new(copy(&identity), &net.owner.url, Some(net.owner.id())).map_err(e)?;
        client.connect().await.map_err(e)?;
        Ok(client)
    })
    .await?;
    Ok((identity, client))
}

/// Waits until `node` resolves `name` (status 200) and returns the answer.
async fn resolved(node: &TestNode, name: &str) -> Result<Value, String> {
    eventually(name, || async {
        let (status, answer) = post_json(&node.url, "/v4/names/resolve", &json!({"name": name})).await?;
        if status == 200 { Ok(answer) } else { Err(format!("status {status} {answer}")) }
    })
    .await
}

/// Waits until `node` no longer resolves `name`.
async fn unresolved(node: &TestNode, name: &str) -> Result<(), String> {
    eventually(name, || async {
        let (status, _) = post_json(&node.url, "/v4/names/resolve", &json!({"name": name})).await?;
        if status == 404 { Ok(()) } else { Err(format!("status {status}")) }
    })
    .await
}

async fn search(node: &TestNode, query: &str, safe: bool) -> Result<Vec<String>, String> {
    let (status, answer) = post_json(&node.url, "/v4/names/search", &json!({"q": query, "safe": safe})).await?;
    if status != 200 {
        return Err(format!("search: {status} {answer}"));
    }
    Ok(answer["results"]
        .as_array()
        .map(|list| list.iter().filter_map(|item| item["name"].as_str().map(str::to_owned)).collect())
        .unwrap_or_default())
}

/// A further node of the network with its own reader settings (a "user's PC").
async fn reader_node(net: &TestNet, access: ReaderAccess) -> Result<TestNode, String> {
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let mut config = test_config(dir.path(), Some(net.membership(&[])), &url);
    config.reader.access = access;
    let node = bridge_node::start(config, listener).await?;
    let node = TestNode { dir, node, url };
    net.synced(&node).await?;
    Ok(node)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shop_resolves_and_opens_through_the_own_node() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (owner_node, host) = (&apps.net.owner, &apps.hosts[0]);
    let owner = apps.owner();
    seal_member(&apps.net, owner.id(), 2).await?;
    let mine = reader_node(&apps.net, ReaderAccess::Local).await?;
    apps.synced().await?;
    // The app lives on the other PC only.
    let (folder, big) = app_folder(3 * PART_BYTES + 77)?;
    let app = Identity::generate(&mut OsRng);
    let at_host = apps.owner_at(host).await?;
    at_host.publish_folder(&app, folder.path(), &draft(vec![host.id()])).await.map_err(e)?;
    served(&format!("{}/app/{}/", host.url, app.id()), ENTRY).await?;
    // The owner names it at a gateway (the owner node) - app key and owner sign.
    let name = app_name("shop", &owner, &app, vec![host.id()])?;
    let statement = signed(&apps.net.net, &name, &owner, Some(&app))?;
    let at_owner = apps.owner_at(owner_node).await?;
    let (status, answer) = submit(owner_node, &at_owner, &statement).await?;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["hash"], json!(statement.hash()));

    // The user's own node resolves `shop.testnetz` from its own log ...
    let found = resolved(&mine, "shop.testnetz").await?;
    assert_eq!(found["kind"], json!("app"));
    assert_eq!(found["target"], json!(app.id().as_str()));
    assert_eq!(found["address"], json!("shop.testnetz"));
    assert_eq!(found["owner"], json!(owner.id().as_str()));
    assert_eq!(found["safety"]["owner_level"], json!(2));
    assert_eq!(found["safety"]["contact"], json!(true));
    assert_eq!(found["safety"]["warnings"], json!([]), "{found}");
    assert_eq!(found["app"]["owner_matches"], json!(true));
    assert_eq!(found["app"]["hosts"][0]["id"], json!(host.id().as_str()));
    let open = found["open"].as_str().ok_or("no open path")?.to_owned();
    assert_eq!(open, format!("/app/{}/", app.id()));
    // ... and loads the app through its own reader: checked, with the sandbox of a host.
    let (status, headers, body) = get(&format!("{}{open}", mine.url)).await?;
    assert_eq!((status, body.as_slice()), (200, ENTRY));
    assert_eq!(header(&headers, "content-security-policy"), "sandbox allow-scripts allow-forms allow-popups");
    assert_eq!(header(&headers, "content-type"), "text/html; charset=utf-8");
    let (status, _, body) = get(&format!("{}{open}assets/big.bin", mine.url)).await?;
    assert_eq!((status, body.len()), (200, big.len()));
    assert_eq!(body, big, "streamed part by part, each checked");
    assert!(mine.node.reader_bytes() > 0, "kept in the reader's memory");
    // The reader is no host: it does not offer the app to others.
    let (status, _) = post_json(&mine.url, "/v4/app/manifest", &json!({"app": app.id().as_str()})).await?;
    assert_eq!(status, 404);

    // A search for "shop" lists it (safe search: the owner has level 2); the rules of the network are public.
    assert_eq!(search(&mine, "shop", true).await?, ["shop"]);
    assert_eq!(search(&mine, "kleidung", true).await?, ["shop"], "by tag");
    let (status, info) = bridge_tests::apps::get(&format!("{}/v4/names/info", mine.url))
        .await
        .map(|(s, _, b)| (s, serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null)))?;
    assert_eq!(status, 200);
    assert_eq!((info["short"].clone(), info["adult"].clone()), (json!("testnetz"), json!("forbidden")));
    assert_eq!(info["names"]["min_level"], json!(1));
    // Another network's address, an unknown name, garbage: 404 / 400.
    assert_eq!(post_json(&mine.url, "/v4/names/resolve", &json!({"name": "shop.anderes"})).await?.0, 404);
    assert_eq!(post_json(&mine.url, "/v4/names/resolve", &json!({"name": "laden"})).await?.0, 404);
    assert_eq!(post(&mine.url, "/v4/names/resolve", b"{nope".to_vec(), None).await?.0, 400);

    // Replay determinism: after a restart the node computes the same name from its log.
    let addr = mine.node.local_addr();
    let TestNode { dir, node, url } = mine;
    node.shutdown().await;
    let mut config = test_config(dir.path(), Some(apps.net.membership(&[])), &url);
    config.reader.access = ReaderAccess::Local;
    let mine = TestNode { node: bridge_tests::start_node_on(config, addr).await?, dir, url };
    let again = resolved(&mine, "shop.testnetz").await?;
    assert_eq!(again["statement"], found["statement"]);
    // Not-Aus: a ban of the app stops resolving and reading at once.
    let ban = bridge_net::Ban { subject: app.id().clone(), reason: "Phishing".into() };
    apps.net.admin.submit(&apps.net.admin.sign(&ban, DAY_MS)?).await?;
    unresolved(&mine, "shop").await?;
    gone(&format!("{}{open}", mine.url)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_and_unruly_names_are_refused() -> TestResult {
    let apps = AppNet::new(0).await?;
    let net = &apps.net;
    let gateway = &net.owner;
    let owner = apps.owner();
    let (mallory, mallorys) = member(net).await?;
    seal_member(net, owner.id(), 1).await?;
    seal_member(net, mallory.id(), 1).await?;
    let owners = apps.owner_at(gateway).await?;
    let mine = signed(&net.net, &member_name("shop", &owner, Category::General)?, &owner, None)?;
    let (status, answer) = eventually("level 1 known", || async {
        let (status, answer) = submit(gateway, &owners, &mine).await?;
        if status == 403 && code(&answer) == "FORBIDDEN" && answer.to_string().contains("level") {
            return Err("level not there yet".into());
        }
        Ok((status, answer))
    })
    .await?;
    assert_eq!(status, 200, "{answer}");

    // Somebody else's name in my session; a taken name; a confusable; a reserved word at level 1.
    let (status, _) = submit(gateway, &mallorys, &mine).await?;
    assert_eq!(status, 403);
    for (name, why) in
        [("shop", "taken"), ("sh0p", "confusable"), ("5-hop", "confusable"), ("paypal-login", "reserved")]
    {
        let statement = signed(&net.net, &member_name(name, &mallory, Category::General)?, &mallory, None)?;
        let (status, answer) = submit(gateway, &mallorys, &statement).await?;
        assert_eq!((status, code(&answer)), (403, "FORBIDDEN"), "{name}: {answer}");
        assert!(answer.to_string().contains(why), "{name}: {answer}");
    }
    // Signed by a stranger instead of the owner in the body; a signature that does not fit.
    let stranger = Identity::generate(&mut OsRng);
    let body = member_name("mallory", &mallory, Category::General)?;
    let forged = body.sign(&net.net, now_ms(), now_ms() + DAY_MS, &stranger).map_err(e)?;
    assert_eq!(submit(gateway, &mallorys, &forged).await?.0, 403);
    let good = signed(&net.net, &body, &mallory, None)?;
    let mut value = good.to_value();
    value["body"]["description"] = json!("untergeschoben");
    let tampered = Statement::from_value(value).map_err(e)?;
    let (status, answer) = submit(gateway, &mallorys, &tampered).await?;
    assert_eq!((status, code(&answer)), (401, "BAD_SIGNATURE"));
    // The log operator refuses the forged one as well, also when an admin hands it in.
    let refused = net.admin.submit(&forged).await;
    assert!(refused.as_ref().is_err_and(|error| error.contains("FORBIDDEN")), "{refused:?}");
    // Quota of level 1: three names, the fourth is refused.
    for name in ["m-eins", "m-zwei", "m-drei"] {
        let statement = signed(&net.net, &member_name(name, &mallory, Category::General)?, &mallory, None)?;
        let (status, answer) = submit(gateway, &mallorys, &statement).await?;
        assert_eq!(status, 200, "{name}: {answer}");
    }
    let fourth = signed(&net.net, &member_name("m-vier", &mallory, Category::General)?, &mallory, None)?;
    let (status, answer) = submit(gateway, &mallorys, &fourth).await?;
    assert_eq!((status, code(&answer)), (429, "QUOTA_EXCEEDED"), "{answer}");
    // 18+ in a network that forbids it.
    let adult = signed(&net.net, &member_name("nachts", &owner, Category::Adult)?, &owner, None)?;
    assert_eq!(submit(gateway, &owners, &adult).await?.0, 403);
    // A banned owner: its names stop resolving, its session ends.
    resolved(gateway, "m-eins").await?;
    let ban = bridge_net::Ban { subject: mallory.id().clone(), reason: "Spam".into() };
    net.admin.submit(&net.admin.sign(&ban, DAY_MS)?).await?;
    unresolved(gateway, "m-eins").await?;
    let later = signed(&net.net, &member_name("m-fuenf", &mallory, Category::General)?, &mallory, None)?;
    let (status, answer) = submit(gateway, &mallorys, &later).await?;
    assert_eq!((status, code(&answer)), (403, "BANNED"), "{answer}");
    // The owner revokes its own name through the gateway; then it is free.
    let hash = bridge_core::encoding::b64_fixed::<32>(&mine.hash(), "hash").map_err(e)?;
    let revoke = bridge_net::Revoke { target: bridge_net::RevokeTarget::Statement(hash), reason: String::new() };
    let revoke = revoke.sign(&net.net, now_ms(), now_ms() + DAY_MS, &owner).map_err(e)?;
    assert_eq!(submit(gateway, &mallorys, &revoke).await?.0, 403, "only the owner");
    let (status, answer) = submit(gateway, &owners, &revoke).await?;
    assert_eq!(status, 200, "{answer}");
    unresolved(gateway, "shop").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adult_names_hidden_in_safe_search_and_labels_work() -> TestResult {
    let options = NetOptions { adult: true, ..TestNet::options() };
    let apps = AppNet::with_options(0, &options).await?;
    let (net, gateway, owner) = (&apps.net, &apps.net.owner, apps.owner());
    seal_member(net, owner.id(), 2).await?;
    let owners = apps.owner_at(gateway).await?;
    let adult = signed(&net.net, &member_name("nachts", &owner, Category::Adult)?, &owner, None)?;
    let (status, answer) = eventually("level 2 known", || async {
        let (status, answer) = submit(gateway, &owners, &adult).await?;
        if status == 403 { Err(format!("{answer}")) } else { Ok((status, answer)) }
    })
    .await?;
    assert_eq!(status, 200, "{answer}");
    let found = resolved(gateway, "nachts").await?;
    assert_eq!(found["category"], json!("adult"));
    assert!(found["safety"]["warnings"].to_string().contains("adult"));
    assert!(search(gateway, "nachts", true).await?.is_empty(), "the safe search never shows 18+");
    assert_eq!(search(gateway, "nachts", false).await?, ["nachts"]);
    // Review 9: 18+ from any side wins - a label `general` does not make the owner's own 18+ harmless.
    let target = bridge_net::LabelTarget::Name("nachts".into());
    net.admin.label(target, Category::General, 30, "kein 18+").await?;
    let found = eventually("label", || async {
        let found = resolved(gateway, "nachts").await?;
        if found["safety"]["labels"]["name"] == json!("general") { Ok(found) } else { Err("not yet".into()) }
    })
    .await?;
    assert_eq!((found["category"].clone(), found["declared"].clone()), (json!("adult"), json!("adult")));
    assert!(search(gateway, "nachts", true).await?.is_empty(), "still never in the safe search");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adult_label_stops_an_app_in_a_forbidding_network() -> TestResult {
    let apps = AppNet::new(0).await?;
    let (net, owner_node, owner) = (&apps.net, &apps.net.owner, apps.owner());
    seal_member(net, owner.id(), 2).await?;
    let mine = reader_node(net, ReaderAccess::Local).await?;
    let (folder, _) = app_folder(10)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(owner_node).await?;
    client.publish_folder(&app, folder.path(), &draft(vec![owner_node.id()])).await.map_err(e)?;
    let statement = signed(&net.net, &app_name("shop", &owner, &app, vec![owner_node.id()])?, &owner, Some(&app))?;
    let (status, answer) = eventually("level 2 known", || async {
        let (status, answer) = submit(owner_node, &client, &statement).await?;
        if status == 403 { Err(format!("{answer}")) } else { Ok((status, answer)) }
    })
    .await?;
    assert_eq!(status, 200, "{answer}");
    served(&format!("{}/app/{}/", mine.url, app.id()), ENTRY).await?;
    // Labeled 18+: the host stops, the reader refuses, the name no longer resolves.
    let target = bridge_net::LabelTarget::Id(app.id().clone());
    net.admin.label(target, Category::Adult, 30, "18+ ohne Kennzeichnung").await?;
    gone(&format!("{}/app/{}/", owner_node.url, app.id())).await?;
    gone(&format!("{}/app/{}/", mine.url, app.id())).await?;
    unresolved(&mine, "shop").await?;
    Ok(())
}

/// The text of the test reports.
const REPORT_TEXT: &str = "Sieht aus wie\neine Bank-Seite";

/// A member's signed report for the gateway `aud`, its text sealed to the log operator `to` (review 9).
fn report(identity: &Identity, aud: &Id, to: (&Id, &KeyCard), target: &str, reason: &str) -> Result<Vec<u8>, String> {
    let address = Address { net: to.0, to: to.1, kind: Kind::Msg, iat: now_ms(), ttl: 7 * 24 * 3600 };
    let sealed = Envelope::seal(identity, &address, REPORT_TEXT.as_bytes(), &mut OsRng).map_err(e)?;
    let sealed: Value = serde_json::from_slice(&sealed.to_bytes().map_err(e)?).map_err(e)?;
    let body = json!({"target": target, "reason": reason, "sealed": sealed});
    SignedRequest::sign(identity, aud, "report", body, now_ms(), &mut OsRng).and_then(|r| r.to_bytes()).map_err(e)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reports_flow_to_the_owner_node_and_are_bounded() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (owner_node, gateway) = (&apps.net.owner, &apps.hosts[0]);
    let owner = apps.owner();
    let session = apps.owner_at(gateway).await?;
    let token = session.session_token();
    let to = (&apps.net.net, owner_node.node.card());
    // Review 9: a plain text is refused - every gateway on the way could read it.
    let plain = json!({"target": "shop", "reason": "phishing", "text": REPORT_TEXT});
    let plain = SignedRequest::sign(&owner, &gateway.id(), "report", plain, now_ms(), &mut OsRng)
        .and_then(|r| r.to_bytes())
        .map_err(e)?;
    assert_eq!(post(&gateway.url, "/v4/report", plain, token).await?.0, 400);
    // Sealed to somebody who is no log operator (the gateway itself): refused.
    let wrong = report(&owner, &gateway.id(), (&apps.net.net, gateway.node.card()), "shop", "phishing")?;
    let (status, answer) = post(&gateway.url, "/v4/report", wrong, token).await?;
    assert_eq!((status, code(&answer)), (403, "FORBIDDEN"), "{answer}");
    // Handed in at a gateway that is not the log operator.
    let (status, first) =
        post(&gateway.url, "/v4/report", report(&owner, &gateway.id(), to, "shop", "phishing")?, token).await?;
    assert_eq!(status, 200, "{first}");
    assert_eq!((first["duplicate"].clone(), first["forwarded"].clone()), (json!(false), json!(false)));
    let id = first["id"].as_str().ok_or("no id")?.to_owned();
    let (status, again) =
        post(&gateway.url, "/v4/report", report(&owner, &gateway.id(), to, "shop", "spam")?, token).await?;
    assert_eq!((status, again["duplicate"].clone(), again["id"].clone()), (200, json!(true), json!(id)));
    // It arrives at the owner node (signed by the member, handed on by the gateway).
    let listed = eventually("report at the owner node", || async {
        let reports = apps.net.admin.reports("open", 100).await?;
        reports.into_iter().find(|report| report["id"] == json!(id)).ok_or_else(|| "not yet".to_owned())
    })
    .await?;
    assert_eq!(listed["via"], json!(gateway.id().as_str()));
    assert_eq!(listed["reporter"], json!(owner.id().as_str()));
    assert_eq!(listed["reason"], json!("phishing"));
    // The log operator opens the text for its admins; the gateway that took it never held it in plain.
    assert_eq!(
        (listed["text"].clone(), listed["sealed_to"].clone()),
        (json!(REPORT_TEXT), json!(owner_node.id().as_str()))
    );
    let store = bridge_store::Store::open(&gateway.dir.path().join(bridge_node::DB_FILE)).map_err(e)?;
    let kept = store.report_get(apps.net.net.as_str(), &id).map_err(e)?.ok_or("not kept at the gateway")?;
    assert!(kept.text.is_empty(), "no text column at the gateway");
    assert!(!String::from_utf8_lossy(&kept.request).contains("Bank-Seite"), "no plain text in the request");
    // Ten a day per member and node.
    for index in 0..9 {
        let target = format!("ziel-{index}");
        let (status, answer) =
            post(&gateway.url, "/v4/report", report(&owner, &gateway.id(), to, &target, "spam")?, token).await?;
        assert_eq!(status, 200, "{index}: {answer}");
    }
    let (status, answer) =
        post(&gateway.url, "/v4/report", report(&owner, &gateway.id(), to, "zuviel", "spam")?, token).await?;
    assert_eq!((status, code(&answer)), (429, "RATE_LIMITED"), "{answer}");
    // Without a session, with a request for another node, replayed: refused.
    let bytes = report(&owner, &gateway.id(), to, "ohne", "other")?;
    assert_eq!(post(&gateway.url, "/v4/report", bytes.clone(), None).await?.0, 401);
    let other = report(&owner, &owner_node.id(), to, "anderer", "other")?;
    assert_eq!(post(&gateway.url, "/v4/report", other, token).await?.0, 401);
    // Admins handle it; members can not read reports.
    apps.net.admin.report_status(&id, "done").await?;
    assert!(apps.net.admin.reports("done", 10).await?.iter().any(|report| report["id"] == json!(id)));
    let peek = SignedRequest::sign(&owner, &owner_node.id(), "reports", json!({}), now_ms(), &mut OsRng)
        .and_then(|r| r.to_bytes())
        .map_err(e)?;
    let (status, answer) = post(&owner_node.url, "/v4/admin/reports", peek, None).await?;
    assert_eq!((status, code(&answer)), (403, "FORBIDDEN"));
    // A gateway can not invent reports: the inner report must be a member's, addressed to that gateway.
    let gateway_key = keyfile::load_or_create(gateway.dir.path())?;
    let stranger = Identity::generate(&mut OsRng);
    let forged_inner = |who: &Identity, aud: &Id| -> Result<Vec<u8>, String> {
        let inner: Value = serde_json::from_slice(&report(who, aud, to, "erfunden", "illegal")?).map_err(e)?;
        let card = who.key_card(Role::Client, None, now_ms()).map_err(e)?.to_value();
        SignedRequest::sign(
            &gateway_key,
            &owner_node.id(),
            "report",
            json!({"report": inner, "card": card}),
            now_ms(),
            &mut OsRng,
        )
        .and_then(|r| r.to_bytes())
        .map_err(e)
    };
    let (status, answer) =
        post(&owner_node.url, "/v4/node/report", forged_inner(&stranger, &gateway.id())?, None).await?;
    assert_eq!((status, code(&answer)), (403, "NOT_MEMBER"), "{answer}");
    let (status, _) = post(&owner_node.url, "/v4/node/report", forged_inner(&owner, &owner_node.id())?, None).await?;
    assert_eq!(status, 403, "addressed to another node than the gateway that hands it on");
    // A real member's report handed on by the gateway is taken - once.
    let (other_member, _) = member(&apps.net).await?;
    let once = forged_inner(&other_member, &gateway.id())?;
    assert_eq!(post(&owner_node.url, "/v4/node/report", once.clone(), None).await?.0, 200);
    assert_eq!(post(&owner_node.url, "/v4/node/report", once, None).await?.0, 409, "replay");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reader_refuses_strangers_and_manipulated_parts() -> TestResult {
    let apps = AppNet::new(0).await?;
    let owner_node = &apps.net.owner;
    // A host behind a proxy that flips a byte in every part it hands out.
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let real = format!("http://{}", listener.local_addr().map_err(e)?);
    let (_proxy_server, proxy, proxy_url) = corrupting_proxy(&real).await?;
    let liar = node_behind(&apps.net, &proxy_url, listener).await?;
    apps.net.seal_as(&liar, "gateway,web").await?;
    wait_gateway(&liar).await?;
    let mine = reader_node(&apps.net, ReaderAccess::Local).await?;
    let off = reader_node(&apps.net, ReaderAccess::Off).await?;
    // App A on the owner node and the liar; app B on the liar only.
    let (folder, big) = app_folder(4 * PART_BYTES)?;
    let (a, b) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
    let at_owner = apps.owner_at(owner_node).await?;
    at_owner.publish_folder(&a, folder.path(), &draft(vec![owner_node.id(), liar.id()])).await.map_err(e)?;
    served(&format!("{real}/app/{}/", a.id()), ENTRY).await?;
    let at_liar = apps.owner_at(&liar).await?;
    at_liar.publish_folder(&b, folder.path(), &draft(vec![liar.id()])).await.map_err(e)?;
    served(&format!("{real}/app/{}/", b.id()), ENTRY).await?;
    apps.net.synced(&mine).await?;

    // Every wrong part is refused; the honest host fills in.
    let base = format!("{}/app/{}", mine.url, a.id());
    served(&format!("{base}/assets/big.bin"), &big).await?;
    assert!(proxy.corrupted.load(std::sync::atomic::Ordering::SeqCst) > 0, "the liar was asked and caught");
    // Only the liar has app B: the reader never hands out its bytes.
    let (status, body) = get_with(&format!("{}/app/{}/", mine.url, b.id()), &[]).await?;
    assert_ne!(status, 200, "never a manipulated file");
    assert_ne!(body.as_slice(), ENTRY);
    // Not for strangers: forwarded requests, foreign host names (DNS rebinding, Funnel), a node with the reader off.
    for headers in [
        vec![("x-forwarded-for", "8.8.8.8")],
        vec![("forwarded", "for=8.8.8.8")],
        vec![("x-real-ip", "8.8.8.8")],
        vec![("host", "evil.example")],
        vec![("host", "pc.tail1234.ts.net")],
    ] {
        let (status, _) = get_with(&format!("{base}/"), &headers).await?;
        assert_eq!(status, 404, "{headers:?}");
    }
    let (status, _) = get_with(&format!("{base}/"), &[("host", "localhost")]).await?;
    assert_eq!(status, 200, "localhost is the own computer");
    let (status, _) = get_with(&format!("{}/app/{}/", off.url, a.id()), &[]).await?;
    assert_eq!(status, 404, "reader off");
    // The memory is bounded.
    assert!(mine.node.reader_bytes() <= bridge_node::ReaderConfig::default().cache_bytes);
    wait_for("liar still sealed", || liar.status().gateway).await?;
    Ok(())
}
