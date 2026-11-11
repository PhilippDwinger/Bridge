//! Phase 4a acceptance (docs/05, docs/07): the owner publishes an app on two hosts, the second host fetches the
//! version itself; one host goes down, the other keeps serving; a host the owner removes stops; a host that hands
//! out manipulated parts is detected (the part is fetched from another host); a banned app or owner is served
//! nowhere; a download takes parts from several hosts in parallel, checks each one and resumes.

use std::sync::atomic::Ordering;

use bridge_core::app::AppFile;
use bridge_core::blob::{HashList, PART_BYTES};
use bridge_core::{BlobId, Identity};
use bridge_sdk::{AppDraft, BlobSource};
use bridge_tests::apps::{AppNet, app_folder, corrupting_proxy, get, gone, header, node_behind, served, wait_gateway};
use bridge_tests::net::eventually;
use rand_core::OsRng;
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn draft(version: u64, hosts: Vec<bridge_core::Id>) -> AppDraft {
    AppDraft { name: "Testspiel".into(), description: String::new(), entry: "index.html".into(), version, hosts }
}

const ENTRY: &[u8] = b"<!doctype html><h1>Hallo Bridge-App</h1>";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hosts_fetch_failover_and_headers() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (owner_node, host) = (&apps.net.owner, &apps.hosts[0]);
    let (folder, big) = app_folder(3 * PART_BYTES + 1234)?;
    let app = Identity::generate(&mut OsRng);
    // The owner uploads to the owner node only and publishes there; it lists both hosts.
    let client = apps.owner_at(owner_node).await?;
    let (statement, published) =
        client.publish_folder(&app, folder.path(), &draft(1, vec![owner_node.id(), host.id()])).await.map_err(e)?;
    assert!(published.active, "all files were uploaded first: served at once");
    assert_eq!(published.version, 1);
    let base = |node: &bridge_tests::net::TestNode| format!("{}/app/{}", node.url, app.id());

    // Served at the owner node with the sandbox headers; the entry under `/`, a redirect without the slash.
    let (status, headers, body) = get(&format!("{}/", base(owner_node))).await?;
    assert_eq!((status, body.as_slice()), (200, ENTRY));
    assert_eq!(header(&headers, "content-security-policy"), "sandbox allow-scripts allow-forms allow-popups");
    assert_eq!(header(&headers, "x-content-type-options"), "nosniff");
    assert_eq!(header(&headers, "content-type"), "text/html; charset=utf-8");
    let entry_blob = HashList::of(ENTRY).map_err(e)?.id();
    assert_eq!(header(&headers, "etag"), format!("\"{entry_blob}\""));
    assert_eq!(header(&headers, "cache-control"), "no-cache");
    assert!(!header(&headers, "content-security-policy").contains("allow-same-origin"));
    let (status, headers, _) = get(&base(owner_node)).await?;
    assert_eq!((status, header(&headers, "location")), (308, format!("{}/", app.id())));
    let (status, headers, body) = get(&format!("{}/assets/big.bin", base(owner_node))).await?;
    assert_eq!((status, body.len()), (200, big.len()));
    assert_eq!(body, big, "large files are streamed part by part");
    assert_eq!(header(&headers, "content-type"), "application/octet-stream");
    let (_, headers, _) = get(&format!("{}/style.css", base(owner_node))).await?;
    assert_eq!(header(&headers, "content-type"), "text/css; charset=utf-8");

    // The second host was never given the files: it learns the version from the owner node and fetches them.
    served(&format!("{}/", base(host)), ENTRY).await?;
    served(&format!("{}/assets/big.bin", base(host)), &big).await?;
    // Both hosts answer the manifest; the client verifies both signatures.
    let version =
        bridge_sdk::fetch_app(&BlobSource::new(&host.url).map_err(e)?, app.id(), &apps.net.net).await.map_err(e)?;
    assert_eq!(version.statement.hash(), statement.hash());
    assert_eq!(version.hosts.len(), 2, "cards of both hosts come along");

    // The owner node goes down: the second host keeps serving.
    let owner_url = base(owner_node);
    let AppNet { net, hosts, .. } = apps;
    net.owner.node.shutdown().await;
    assert!(get(&format!("{owner_url}/")).await.is_err(), "the owner node is down");
    let host = &hosts[0];
    served(&format!("{}/app/{}/", host.url, app.id()), ENTRY).await?;
    served(&format!("{}/app/{}/assets/big.bin", host.url, app.id()), &big).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_host_stops_and_new_versions_spread() -> TestResult {
    let apps = AppNet::new(2).await?;
    let (owner_node, a, b) = (&apps.net.owner, &apps.hosts[0], &apps.hosts[1]);
    let (folder, _) = app_folder(10)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(owner_node).await?;
    let (v1, _) = client
        .publish_folder(&app, folder.path(), &draft(1, vec![owner_node.id(), a.id(), b.id()]))
        .await
        .map_err(e)?;
    for node in apps.all() {
        served(&format!("{}/app/{}/", node.url, app.id()), ENTRY).await?;
    }
    // Version 2 without host b and with a new entry file - published at host a this time.
    let files: Vec<AppFile> = bridge_core::AppManifest::from_body(v1.body()).map_err(e)?.files;
    let mut with_new = files.clone();
    let page = b"<h1>Version 2</h1>";
    let at_a = apps.owner_at(a).await?;
    let blob: BlobId = at_a.upload_blob(page, 1).await.map_err(e)?;
    with_new.push(AppFile { path: "v2.html".into(), blob, size: page.len() as u64, kind: bridge_core::FileType::Html });
    let mut second = draft(2, vec![owner_node.id(), a.id()]);
    second.entry = "v2.html".into();
    let v2 = at_a.sign_app(&app, &second, with_new).map_err(e)?;
    assert!(at_a.publish_app(&v2).await.map_err(e)?.active);
    // The owner node fetches version 2 from host a; host b finds a version without itself and stops.
    served(&format!("{}/app/{}/", owner_node.url, app.id()), page).await?;
    gone(&format!("{}/app/{}/", b.url, app.id())).await?;
    gone(&format!("{}/app/{}/index.html", b.url, app.id())).await?;
    // b no longer answers the manifest either; version 1 can not come back anywhere (rollback).
    let at_owner = apps.owner_at(owner_node).await?;
    let old = at_owner.publish_app(&v1).await;
    assert!(matches!(old, Err(bridge_sdk::SdkError::Node { ref code, .. }) if code == "REPLAY"), "{old:?}");
    let answer = BlobSource::new(&b.url).map_err(e)?;
    assert!(bridge_sdk::fetch_app(&answer, app.id(), &apps.net.net).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manipulated_parts_are_detected_and_fetched_elsewhere() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (owner_node, honest) = (&apps.net.owner, &apps.hosts[0]);
    // A host behind a proxy that flips a byte in every part it hands out (its card names the proxy).
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let real = format!("http://{}", listener.local_addr().map_err(e)?);
    let (proxy_server, proxy, proxy_url) = corrupting_proxy(&real).await?;
    let liar = node_behind(&apps.net, &proxy_url, listener).await?;
    apps.net.seal_as(&liar, "gateway,web").await?;
    wait_gateway(&liar).await?;
    apps.net.synced(honest).await?;

    let (folder, big) = app_folder(8 * PART_BYTES)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(owner_node).await?;
    let (v1, _) =
        client.publish_folder(&app, folder.path(), &draft(1, vec![owner_node.id(), liar.id()])).await.map_err(e)?;
    // The lying host fetched honestly (from the owner node) - only what it hands out is changed.
    served(&format!("{real}/app/{}/assets/big.bin", app.id()), &big).await?;

    // Version 2 adds the honest host: it fetches from the owner node and the liar in parallel.
    let files = bridge_core::AppManifest::from_body(v1.body()).map_err(e)?.files;
    let v2 = client.sign_app(&app, &draft(2, vec![owner_node.id(), liar.id(), honest.id()]), files).map_err(e)?;
    client.publish_app(&v2).await.map_err(e)?;
    served(&format!("{}/app/{}/assets/big.bin", honest.url, app.id()), &big).await?;
    assert!(proxy.corrupted.load(Ordering::SeqCst) > 0, "the liar did hand out wrong parts");

    // A client downloading from the liar and an honest host: every wrong part is rejected, the blob is right.
    let blob = HashList::of(&big).map_err(e)?.id();
    let before = proxy.corrupted.load(Ordering::SeqCst);
    let sources = vec![BlobSource::new(&proxy_url).map_err(e)?, BlobSource::new(&owner_node.url).map_err(e)?];
    let dir = tempfile::tempdir().map_err(e)?;
    let dest = dir.path().join("big.bin");
    let report = bridge_sdk::download_blob(&sources, &blob, &dest).await.map_err(e)?;
    assert_eq!(std::fs::read(&dest).map_err(e)?, big);
    assert!(report.rejected >= 1 && proxy.corrupted.load(Ordering::SeqCst) > before, "{report:?}");
    assert_eq!(report.fetched, 8);
    // In memory as well.
    assert_eq!(bridge_sdk::fetch_blob(&sources, &blob, 1 << 30).await.map_err(e)?, big);
    proxy_server.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn banned_app_and_banned_owner_are_served_nowhere() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (owner_node, host) = (&apps.net.owner, &apps.hosts[0]);
    let (folder, _) = app_folder(10)?;
    let client = apps.owner_at(owner_node).await?;
    let (first, second) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
    for app in [&first, &second] {
        client.publish_folder(app, folder.path(), &draft(1, vec![owner_node.id(), host.id()])).await.map_err(e)?;
    }
    for node in apps.all() {
        for app in [&first, &second] {
            served(&format!("{}/app/{}/", node.url, app.id()), ENTRY).await?;
        }
    }
    // A ban of the app ID (the network log works on app IDs too): gone on both hosts, the other app stays.
    apps.net.admin.ban(first.id().clone(), 1, "Phishing").await?;
    for node in apps.all() {
        gone(&format!("{}/app/{}/", node.url, first.id())).await?;
        served(&format!("{}/app/{}/", node.url, second.id()), ENTRY).await?;
    }
    // A ban of the owner: all its apps are gone.
    apps.net.admin.ban(apps.owner().id().clone(), 1, "Missbrauch").await?;
    for node in apps.all() {
        gone(&format!("{}/app/{}/", node.url, second.id())).await?;
    }
    // A host never takes a banned app back.
    let manifest = BlobSource::new(&host.url).map_err(e)?;
    assert!(bridge_sdk::fetch_app(&manifest, second.id(), &apps.net.net).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_download_resume_and_damaged_files() -> TestResult {
    let apps = AppNet::new(1).await?;
    let (owner_node, host) = (&apps.net.owner, &apps.hosts[0]);
    let (folder, big) = app_folder(10 * PART_BYTES + 7)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(owner_node).await?;
    client.publish_folder(&app, folder.path(), &draft(1, vec![owner_node.id(), host.id()])).await.map_err(e)?;
    served(&format!("{}/app/{}/assets/big.bin", host.url, app.id()), &big).await?;
    let blob = HashList::of(&big).map_err(e)?.id();
    let sources = vec![BlobSource::new(&owner_node.url).map_err(e)?, BlobSource::new(&host.url).map_err(e)?];

    // Parallel: both hosts deliver parts.
    let dir = tempfile::tempdir().map_err(e)?;
    let dest = dir.path().join("big.bin");
    let report = bridge_sdk::download_blob(&sources, &blob, &dest).await.map_err(e)?;
    assert_eq!(std::fs::read(&dest).map_err(e)?, big);
    assert_eq!((report.parts, report.fetched, report.reused, report.rejected), (11, 11, 0, 0));
    assert!(report.per_source.iter().all(|count| *count > 0), "{report:?}");

    // Resume: an interrupted download (parts 3 and 10 missing, part 5 damaged) fetches only those three.
    let partial = dir.path().join("again.bin.part");
    let mut data = big.clone();
    data.truncate(10 * PART_BYTES);
    data[3 * PART_BYTES..4 * PART_BYTES].fill(0);
    data[5 * PART_BYTES + 9] ^= 1;
    std::fs::write(&partial, &data).map_err(e)?;
    let report = bridge_sdk::download_blob(&sources, &blob, &dir.path().join("again.bin")).await.map_err(e)?;
    assert_eq!((report.fetched, report.reused), (3, 8));
    assert_eq!(std::fs::read(dir.path().join("again.bin")).map_err(e)?, big);

    // A damaged blob file at a host: it never serves the wrong bytes, and repairs itself from the other host.
    let file = bridge_tests::apps::files_below(&bridge_tests::apps::blob_dir(host))
        .into_iter()
        .find(|path| std::fs::metadata(path).is_ok_and(|meta| meta.len() == big.len() as u64))
        .ok_or("blob file of big.bin not found")?;
    let mut bytes = std::fs::read(&file).map_err(e)?;
    bytes[2 * PART_BYTES + 1] ^= 0x55;
    std::fs::write(&file, &bytes).map_err(e)?;
    let url = format!("{}/app/{}/assets/big.bin", host.url, app.id());
    let damaged = get(&url).await;
    assert!(damaged.as_ref().map_or(true, |(_, _, body)| body != &bytes), "the damaged bytes are never served");
    served(&url, &big).await?;
    eventually("downloads from the repaired host", || async {
        let one = vec![BlobSource::new(&host.url).map_err(e)?];
        let data = bridge_sdk::fetch_blob(&one, &blob, 1 << 30).await.map_err(e)?;
        if data == big { Ok(()) } else { Err("wrong data".into()) }
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_keeps_hosted_apps_and_their_files() -> TestResult {
    let mut apps = AppNet::new(1).await?;
    let (folder, big) = app_folder(2 * PART_BYTES + 1)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(&apps.net.owner).await?;
    let hosts = vec![apps.net.owner.id(), apps.hosts[0].id()];
    client.publish_folder(&app, folder.path(), &draft(1, hosts)).await.map_err(e)?;
    let host = apps.hosts.remove(0);
    served(&format!("{}/app/{}/assets/big.bin", host.url, app.id()), &big).await?;
    let host = host.restart(Some(apps.net.membership(&[]))).await?;
    let (status, _, body) = get(&format!("{}/app/{}/assets/big.bin", host.url, app.id())).await?;
    assert_eq!((status, body == big), (200, true), "served right after the restart, from its own disk");
    served(&format!("{}/app/{}/", host.url, app.id()), ENTRY).await?;
    Ok(())
}
