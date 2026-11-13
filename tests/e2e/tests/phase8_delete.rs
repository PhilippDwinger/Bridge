//! Phase 8, step 1 (docs/07 §10, ADR 0028): an app deleted by its owner (`retire` in the log) is served nowhere any
//! more - also by a host that was off while it happened and learns it from the log later - its name is free, and no
//! host takes a version of it again.

use bridge_core::{Identity, Role};
use bridge_net::{Category, Name, NameKind, Retire, Seal, Services};
use bridge_node::admin::YEAR_MS;
use bridge_sdk::{AppDraft, BlobSource};
use bridge_tests::apps::{AppNet, app_folder, get, gone, served};
use bridge_tests::net::{eventually, test_config};
use bridge_tests::{now_ms, start_node_on};
use rand_core::OsRng;

type TestResult = Result<(), String>;

const ENTRY: &[u8] = b"<!doctype html><h1>Hallo Bridge-App</h1>";
const DAY_MS: i64 = 24 * 3600 * 1000;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn draft(version: u64, hosts: Vec<bridge_core::Id>) -> AppDraft {
    AppDraft { name: "Laden".into(), description: String::new(), entry: "index.html".into(), version, hosts }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_deleted_app_is_gone_everywhere_also_on_a_host_that_was_off() -> TestResult {
    let mut apps = AppNet::new(1).await?;
    let owner = apps.owner();
    let seal = Seal { subject: owner.id().clone(), level: 2, services: Services::NONE, card: None };
    apps.net.admin.submit(&apps.net.admin.sign(&seal, YEAR_MS)?).await?;
    let (owner_node, host_id) = (apps.net.owner.id(), apps.hosts[0].id());
    let (folder, _) = app_folder(10)?;
    let (app, other) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
    let client = apps.owner_at(&apps.net.owner).await?;
    for one in [&app, &other] {
        client
            .publish_folder(one, folder.path(), &draft(1, vec![owner_node.clone(), host_id.clone()]))
            .await
            .map_err(e)?;
    }
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
        hosts: vec![owner_node.clone()],
    };
    let now = now_ms();
    let named = name.sign_name(&apps.net.net, now, now + 30 * DAY_MS, &owner, Some(&app)).map_err(e)?;
    apps.net.admin.submit(&named).await?;
    for node in apps.all() {
        for one in [&app, &other] {
            served(&format!("{}/app/{}/", node.url, one.id()), ENTRY).await?;
        }
    }

    // The second host goes off; the owner deletes the app meanwhile.
    let host = apps.hosts.remove(0);
    let (dir, url, addr) = (host.dir, host.url, host.node.local_addr());
    host.node.shutdown().await;
    let retire = Retire::new(&app, &owner, now_ms()).map_err(e)?;
    let statement = retire.sign_retire(&apps.net.net, now_ms(), &app, &owner).map_err(e)?;
    apps.net.admin.submit(&statement).await?;
    gone(&format!("{}/app/{}/", apps.net.owner.url, app.id())).await?;
    served(&format!("{}/app/{}/", apps.net.owner.url, other.id()), ENTRY).await?;
    let (_, state) = apps.net.admin.load_state().await?;
    assert!(state.is_retired(app.id(), now_ms()) && state.resolve_name("shop", now_ms()).is_err(), "name ended");

    // Back on: it learns the deletion from the log and stops too (the other app keeps running).
    let config = test_config(dir.path(), Some(apps.net.membership(&[])), &url);
    let node = start_node_on(config, addr).await?;
    gone(&format!("{url}/app/{}/", app.id())).await?;
    served(&format!("{url}/app/{}/", other.id()), ENTRY).await?;

    // No host takes a version of it again, the owner can not publish it again either.
    let again = client.publish_folder(&app, folder.path(), &draft(2, vec![owner_node.clone()])).await;
    assert!(again.is_err(), "a deleted app stays deleted");
    let source = BlobSource::new(&apps.net.owner.url).map_err(e)?;
    assert!(bridge_sdk::fetch_app(&source, app.id(), &apps.net.net).await.is_err());
    // The name is free for another app.
    let mut renamed = name.clone();
    renamed.target = other.id().clone();
    renamed.card = Some(other.key_card(Role::App, None, now_ms()).map_err(e)?);
    let now = now_ms();
    let renamed = renamed.sign_name(&apps.net.net, now, now + 30 * DAY_MS, &owner, Some(&other)).map_err(e)?;
    eventually("name free again", || async { apps.net.admin.submit(&renamed).await.map(|_| ()) }).await?;
    let (status, _, _) = get(&format!("{url}/app/{}/index.html", app.id())).await?;
    assert_eq!(status, 404);
    node.shutdown().await;
    Ok(())
}
