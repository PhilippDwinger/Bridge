//! Phase 5, plugins of foreign publishers (docs/09 §12): a publisher signs a plugin (a WebAssembly counter with `kv`
//! and `caller`), the operator installs it, members call it; updates need a higher version and allowed capabilities;
//! the kill switch (local and by a ban in the log) stops it; tampered modules and ungranted imports are refused.

use bridge_core::Identity;
use bridge_net::JoinMode;
use bridge_node::plugins::{self, PluginSpec};
use bridge_sdk::Client;
use bridge_tests::apps::copy;
use bridge_tests::net::TestNet;
use rand_core::OsRng;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// `handle` counts calls in `kv` under "n" and answers `<count>:<caller>`-ish bytes: the count (1 byte) and the
/// caller ID. `extra` adds imports.
fn counter(extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
          (import "bridge" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "bridge" "kv_put" (func $put (param i32 i32 i32 i32) (result i32)))
          (import "bridge" "caller" (func $caller (param i32 i32) (result i32)))
          {extra}
          (memory (export "memory") 1)
          (data (i32.const 16) "n")
          (func (export "alloc") (param i32) (result i32) i32.const 1024)
          (func (export "handle") (param i32 i32) (result i64)
            (local $len i32)
            (if (i32.lt_s (call $get (i32.const 16) (i32.const 1) (i32.const 32) (i32.const 1)) (i32.const 1))
              (then (i32.store8 (i32.const 32) (i32.const 0))))
            (i32.store8 (i32.const 32) (i32.add (i32.load8_u (i32.const 32)) (i32.const 1)))
            (drop (call $put (i32.const 16) (i32.const 1) (i32.const 32) (i32.const 1)))
            (i32.store8 (i32.const 4096) (i32.load8_u (i32.const 32)))
            (local.set $len (call $caller (i32.const 4097) (i32.const 64)))
            (i64.or (i64.shl (i64.const 4096) (i64.const 32)) (i64.extend_i32_u (i32.add (local.get $len) (i32.const 1))))))"#
    ))
    .unwrap_or_default()
}

fn spec(version: u64, capabilities: &[&str]) -> PluginSpec {
    PluginSpec {
        name: "Zähler".into(),
        version,
        capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
        fuel: 10_000_000,
        kv: 1024,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plugins_run_with_their_capabilities_and_can_be_stopped() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let data = net.owner.dir.path().to_path_buf();
    let publisher = Identity::generate(&mut OsRng);
    let now = bridge_tests::now_ms();
    let module = counter("");
    let manifest = plugins::new_manifest(&publisher, &spec(1, &["kv", "caller"]), &module, now)?;
    let statement = manifest.sign(&publisher, now)?;
    let installed = plugins::install(&data, statement.canonical_bytes(), &module, false, now)?;
    assert_eq!((installed.version, installed.previous), (1, None));

    let member = Identity::generate(&mut OsRng);
    let client = Client::join(copy(&member), &net.link(None)).await.map_err(e)?;
    let first = client.plugin_call(publisher.id(), b"").await.map_err(e)?;
    let second = client.plugin_call(publisher.id(), b"").await.map_err(e)?;
    assert_eq!((first[0], second[0]), (1, 2), "the plugin keeps its count in kv");
    assert_eq!(&second[1..], member.id().as_str().as_bytes(), "it sees who calls");

    // Updates: same version refused; more capabilities only when allowed.
    assert!(plugins::install(&data, statement.canonical_bytes(), &module, false, now).is_err());
    let more = counter(r#"(import "bridge" "log" (func (param i32 i32)))"#);
    let wider =
        plugins::new_manifest(&publisher, &spec(2, &["kv", "log", "caller"]), &more, now)?.sign(&publisher, now)?;
    assert!(plugins::install(&data, wider.canonical_bytes(), &more, false, now).is_err());
    assert_eq!(plugins::install(&data, wider.canonical_bytes(), &more, true, now)?.previous, Some(1));
    assert_eq!(client.plugin_call(publisher.id(), b"").await.map_err(e)?[0], 3, "the data stays across updates");

    // Kill switch, local.
    plugins::set_disabled(&data, publisher.id(), true)?;
    assert!(client.plugin_call(publisher.id(), b"").await.is_err());
    plugins::set_disabled(&data, publisher.id(), false)?;
    assert_eq!(client.plugin_call(publisher.id(), b"").await.map_err(e)?[0], 4);
    // Kill switch, network: a ban of the plugin ID in the log.
    net.admin.ban(publisher.id().clone(), 30, "Plugin gesperrt").await?;
    bridge_tests::net::eventually("ban stops the plugin", || async {
        match client.plugin_call(publisher.id(), b"").await {
            Err(error) if error.to_string().contains("FORBIDDEN") => Ok(()),
            other => Err(format!("{other:?}")),
        }
    })
    .await?;
    Ok(())
}

/// Attack: a module that does not match its statement, an import the statement does not grant, a statement signed
/// by someone else, a module swapped on disk after the install.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_plugins_are_refused() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let data = net.owner.dir.path().to_path_buf();
    let publisher = Identity::generate(&mut OsRng);
    let now = bridge_tests::now_ms();
    let module = counter("");
    let statement =
        plugins::new_manifest(&publisher, &spec(1, &["kv", "caller"]), &module, now)?.sign(&publisher, now)?;
    let other = counter(r#"(func $unused)"#);
    assert!(plugins::install(&data, statement.canonical_bytes(), &other, false, now).is_err(), "hash");
    let narrow = plugins::new_manifest(&publisher, &spec(1, &["kv"]), &module, now)?.sign(&publisher, now)?;
    assert!(plugins::install(&data, narrow.canonical_bytes(), &module, false, now).is_err(), "caller not granted");
    let stranger = Identity::generate(&mut OsRng);
    let manifest = plugins::new_manifest(&publisher, &spec(1, &["kv", "caller"]), &module, now)?;
    assert!(manifest.sign(&stranger, now).is_err(), "only the plugin key signs");
    plugins::install(&data, statement.canonical_bytes(), &module, false, now)?;
    // Swapped on disk: the next call verifies again and refuses.
    std::fs::write(plugins::plugin_dir(&data, publisher.id()).join(plugins::MODULE_FILE), &other).map_err(e)?;
    let member = Identity::generate(&mut OsRng);
    let client = Client::join(copy(&member), &net.link(None)).await.map_err(e)?;
    assert!(client.plugin_call(publisher.id(), b"").await.is_err());
    Ok(())
}
