//! Phase 7, step 1 (docs/11 §4): a node behind the gate of a public network - the reader `public`, the start page
//! `/`, the frame `/web/<name>/`, and what visitors from the Internet may see (owners with level ≥ 2, never in a
//! network that allows 18+).

use bridge_core::{Identity, Role};
use bridge_net::{Category, Name, NameKind, Seal, Services};
use bridge_node::ReaderAccess;
use bridge_node::admin::{NetOptions, YEAR_MS};
use bridge_sdk::AppDraft;
use bridge_tests::apps::{AppNet, app_folder, get, gone, header, served};
use bridge_tests::net::{TestNet, TestNode, eventually, test_config};
use bridge_tests::now_ms;
use rand_core::OsRng;
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

const DAY_MS: i64 = 24 * 3600 * 1000;
const ENTRY: &[u8] = b"<!doctype html><h1>Hallo Bridge-App</h1>";

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Seals the app owner with `level` (no services).
async fn seal_owner(apps: &AppNet, level: u8) -> TestResult {
    let seal = Seal { subject: apps.owner().id().clone(), level, services: Services::NONE, card: None };
    apps.net.admin.submit(&apps.net.admin.sign(&seal, YEAR_MS)?).await?;
    Ok(())
}

/// Publishes an app hosted by the owner node and names it `shop` with `description`; returns the app identity.
async fn shop(apps: &AppNet, description: &str) -> Result<Identity, String> {
    let (net, owner_node, owner) = (&apps.net, &apps.net.owner, apps.owner());
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
    let name = Name {
        name: "shop".into(),
        kind: NameKind::App,
        target: app.id().clone(),
        owner: owner.id().clone(),
        owner_card: owner.key_card(Role::Client, None, now_ms()).map_err(e)?,
        card: Some(app.key_card(Role::App, None, now_ms()).map_err(e)?),
        description: description.into(),
        tags: Vec::new(),
        category: Category::General,
        hosts: vec![owner_node.id()],
    };
    let now = now_ms();
    net.admin.submit(&name.sign_name(&net.net, now, now + 30 * DAY_MS, &owner, Some(&app)).map_err(e)?).await?;
    Ok(app)
}

/// A node like BridgeControll starts one behind the gate: reader `public`, the local proxy trusted, its own loopback
/// reader for this PC's browser; sealed with `level` (3: a website entrance, docs/11 §13; 0: no seal).
async fn public_node(net: &TestNet, level: u8) -> Result<TestNode, String> {
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let mut config = test_config(dir.path(), Some(net.membership(&[])), "https://pc.tail1234.ts.net/bridge4/testnetz");
    config.reader.access = ReaderAccess::Public;
    config.server.trusted_proxies = vec![[127, 0, 0, 1].into()];
    config.reader_listen = Some(([127, 0, 0, 1], 0).into());
    let node = bridge_node::start(config, listener).await?;
    let public = TestNode { dir, node, url };
    net.synced(&public).await?;
    if level > 0 {
        net.admin.seal(&public.url, &public.id(), level, Services::NONE).await?;
        net.synced(&public).await?;
    }
    Ok(public)
}

fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_public_node_shows_start_page_frame_and_apps_of_trusted_owners() -> TestResult {
    let apps = AppNet::new(0).await?;
    seal_owner(&apps, 1).await?;
    let app = shop(&apps, "Ein <b>Laden</b> & \"mehr\"").await?;
    let public = public_node(&apps.net, 3).await?;
    let app_path = format!("/app/{}/", app.id());
    // Through the proxy (every request to the main port here) the app of an owner with level 1 is not shown ...
    let reader = public.node.reader_addr().ok_or("no loopback reader")?;
    served(&format!("http://{reader}{app_path}"), ENTRY).await?; // ... the own browser sees it,
    gone(&format!("{}{app_path}", public.url)).await?; // the Internet does not,
    let (status, _, body) = get(&format!("{}/web/shop/", public.url)).await?;
    assert_eq!(status, 404, "no frame either: {}", text(&body));
    let (status, _, body) = get(&format!("{}/", public.url)).await?;
    assert!(status == 200 && text(&body).contains("Noch keine öffentlichen Websites"), "{}", text(&body));
    // ... level 2: everything public.
    seal_owner(&apps, 2).await?;
    served(&format!("{}{app_path}", public.url), ENTRY).await?;
    let start = eventually("start page lists the shop", || async {
        let (status, headers, body) = get(&format!("{}/", public.url)).await?;
        let page = text(&body);
        if status == 200 && page.contains("href=\"web/shop/\"") { Ok((headers, page)) } else { Err(page) }
    })
    .await?;
    let (headers, page) = start;
    assert!(page.contains("Ein &lt;b&gt;Laden&lt;/b&gt; &amp; &quot;mehr&quot;"), "description escaped: {page}");
    assert!(page.contains("mailto:abuse@test.example") && !page.contains("<script"), "{page}");
    assert!(header(&headers, "content-type").starts_with("text/html"));
    assert!(header(&headers, "content-security-policy").starts_with("default-src 'none'"));
    assert_eq!(header(&headers, "x-frame-options"), "DENY");
    // The frame: the app below `../../app/<id>/` in a sandbox, network and report contact above.
    let (status, headers, body) = get(&format!("{}/web/shop", public.url)).await?;
    assert_eq!((status, header(&headers, "location")), (308, "shop/".to_owned()));
    let (status, headers, body2) = get(&format!("{}/web/shop/", public.url)).await?;
    let frame = text(&body2);
    assert_eq!(status, 200, "{frame} / {}", text(&body));
    assert!(frame.contains(&format!("src=\"../../app/{}/\"", app.id())), "{frame}");
    assert!(frame.contains("sandbox=\"allow-scripts allow-forms allow-popups\""), "{frame}");
    assert!(!frame.contains("allow-same-origin") && !frame.contains("<script"), "{frame}");
    assert!(header(&headers, "content-security-policy").contains("frame-ancestors 'none'"));
    // Unknown names, deeper paths, other methods: nothing.
    for path in ["/web/nix/", "/web/shop/x", "/web/SHOP/", "/web/sh%6fp/", "/web/"] {
        let (status, _, _) = get(&format!("{}{path}", public.url)).await?;
        assert_eq!(status, 404, "{path}");
    }
    let posted = reqwest::Client::new().post(format!("{}/", public.url)).body("{}").send().await.map_err(e)?;
    assert_eq!(posted.status().as_u16(), 404);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_without_the_public_reader_have_no_public_pages() -> TestResult {
    let apps = AppNet::new(0).await?;
    seal_owner(&apps, 2).await?;
    shop(&apps, "Ein Laden").await?;
    // The owner node runs with the default reader (`local`): `/` and `/web/` are what they were - 404.
    for path in ["/", "/web/shop/"] {
        let (status, headers, _) = get(&format!("{}{path}", apps.net.owner.url)).await?;
        assert_eq!(status, 404, "{path}");
        assert!(header(&headers, "content-type").starts_with("application/json"), "{path}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_network_that_allows_18_plus_shows_nothing_to_the_internet() -> TestResult {
    let options = NetOptions { adult: true, ..TestNet::options() };
    let apps = AppNet::with_options(0, &options).await?;
    seal_owner(&apps, 2).await?;
    let app = shop(&apps, "Ein Laden").await?;
    let public = public_node(&apps.net, 3).await?;
    let app_path = format!("/app/{}/", app.id());
    let reader = public.node.reader_addr().ok_or("no loopback reader")?;
    served(&format!("http://{reader}{app_path}"), ENTRY).await?; // the own browser decides itself (Bridge-Browser)
    let (status, _, _) = get(&format!("{}{app_path}", public.url)).await?;
    assert_eq!(status, 404, "never to visitors from the Internet");
    let (status, _, _) = get(&format!("{}/web/shop/", public.url)).await?;
    assert_eq!(status, 404);
    let (status, _, body) = get(&format!("{}/", public.url)).await?;
    assert!(status == 200 && !text(&body).contains("web/shop/"), "{}", text(&body));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_level_3_node_shows_websites_to_the_internet() -> TestResult {
    let apps = AppNet::new(0).await?;
    seal_owner(&apps, 2).await?;
    let app = shop(&apps, "Ein Laden").await?;
    // A member's PC behind its own gate: reachable for the protocol, but no website entrance (level 2).
    let member = public_node(&apps.net, 2).await?;
    let app_path = format!("/app/{}/", app.id());
    let (status, _, body) = get(&format!("{}/", member.url)).await?;
    assert!(status == 404 && text(&body).contains("keine Websites"), "{status} {}", text(&body));
    for path in ["/web/shop/", "/login.js", app_path.as_str()] {
        let (status, _, _) = get(&format!("{}{path}", member.url)).await?;
        assert_eq!(status, 404, "{path}");
    }
    let (status, _, _) = get(&format!("{}/v4/info", member.url)).await?;
    assert_eq!(status, 200, "the protocol stays");
    let reader = member.node.reader_addr().ok_or("no loopback reader")?;
    served(&format!("http://{reader}{app_path}"), ENTRY).await?; // its own browser sees the app
    // The owner trusts it with level 3: now it is a website entrance too.
    apps.net.admin.seal(&member.url, &member.id(), 3, Services::NONE).await?;
    served(&format!("{}{app_path}", member.url), ENTRY).await?;
    eventually("start page", || async {
        let (status, _, body) = get(&format!("{}/", member.url)).await?;
        if status == 200 && text(&body).contains("web/shop/") { Ok(()) } else { Err(text(&body)) }
    })
    .await
}
