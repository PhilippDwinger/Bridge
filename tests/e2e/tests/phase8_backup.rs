//! Phase 8, step 5 (docs/12 §10): the owner backup. The owner node's keys go - sealed for the 24 words - into a
//! Bridge app on the web hosts, a `backup` entry in the log names it. The owner PC dies; a new folder gets everything
//! back with the words and the address of a member's node, and the node runs again as the network's log operator.

use bridge_core::Mnemonic;
use bridge_net::JoinMode;
use bridge_node::admin::AdminClient;
use bridge_node_cli::{apps, backup};
use bridge_tests::net::{TestNet, eventually, membership, test_config, wait_for};
use bridge_tests::start_node_on;
use rand_core::OsRng;
use serde_json::json;

type TestResult = Result<(), String>;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_owner_comes_back_with_the_24_words() -> TestResult {
    let net = TestNet::create(JoinMode::Invite).await?;
    let member = net.add_node(&[]).await?;
    net.seal_as(&member, "gateway,web").await?;
    let owner_dir = net.owner.dir.path().to_path_buf();
    let shop = apps::create(&owner_dir, "Laden")?;

    // The backup: the owner node becomes a web host too, two hosts, a `backup` entry.
    let settings = json!({"name": "Owner-Knoten", "listen_port": 7401});
    let made = backup::make(&owner_dir, &settings, Some(&net.owner.url), false).await?;
    assert!(made.published && made.statement, "{made:?}");
    assert_eq!(made.hosts, 2);
    let again = backup::make(&owner_dir, &settings, Some(&net.owner.url), false).await?;
    assert!(!again.published && !again.statement, "nothing changed: {again:?}");
    let source = bridge_sdk::BlobSource::new(&member.url).map_err(|e| e.to_string())?;
    eventually("the member hosts the backup", || async {
        let version = bridge_sdk::fetch_app(&source, &made.app, &net.net).await.map_err(|e| e.to_string())?;
        let file = version.manifest.files.first().ok_or("no file")?;
        bridge_sdk::fetch_blob(std::slice::from_ref(&source), &file.blob, 2 * 1024 * 1024)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await?;

    // While the owner node still answers, nothing is restored; other words find no network there.
    let target = tempfile::tempdir().map_err(|e| e.to_string())?;
    let refused = backup::restore(&net.master, &member.url, target.path()).await;
    assert!(refused.as_ref().is_err_and(|e| e.contains("antwortet noch")), "{refused:?}");
    let stranger = Mnemonic::generate(&mut OsRng).to_identity().map_err(|e| e.to_string())?;
    assert!(backup::restore(&stranger, &member.url, target.path()).await.is_err());

    // The owner PC dies. The words and the member's address bring the owner node back - on the same address (the new
    // PC got the old Tailscale name).
    let (old_id, old_url, addr) = (net.owner.id(), net.owner.url.clone(), net.owner.node.local_addr());
    let TestNet { owner, net: net_id, master, .. } = net;
    owner.node.shutdown().await;
    drop(owner.dir);
    let restored = backup::restore(&master, &member.url, target.path()).await?;
    assert_eq!((restored.net.clone(), restored.node.clone()), (net_id.clone(), old_id.clone()));
    assert_eq!(restored.settings, settings);
    let keys: Vec<String> = apps::list(target.path(), 10)?.into_iter().map(|(_, name)| name).collect();
    assert_eq!(keys, ["Laden"]);
    assert!(apps::load(target.path(), &shop).is_ok(), "the app key is back");
    let config = test_config(target.path(), Some(membership(&net_id, std::slice::from_ref(&member.url))), &old_url);
    let node = start_node_on(config, addr).await?;
    assert_eq!(node.card().id(), &old_id);
    wait_for("the log is back", || node.net_status().is_some_and(|status| status.size >= 5)).await?;

    // It is the log operator again: the restored admin key gets a new entry into the log.
    let admin = AdminClient::load(target.path(), Some(&old_url))?;
    let (code, _) = eventually("the operator takes entries", || admin.invite(1, 7)).await?;
    assert_eq!(code.len(), 14, "{code}");
    let (_, state) = admin.load_state().await?;
    assert_eq!(state.backup_app(bridge_tests::now_ms()).map(|(app, _)| app), Some(made.app.clone()));
    // A second restore into another folder: the owner node answers again - refused.
    let other = tempfile::tempdir().map_err(|e| e.to_string())?;
    assert!(backup::restore(&master, &member.url, other.path()).await.is_err());
    node.shutdown().await;
    Ok(())
}
