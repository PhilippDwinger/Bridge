//! `bridge-node release …` (docs/12 §6): key, signing an announcement from the files of a release (served on this PC
//! instead of GitHub - `--base` exists only in test builds), checking it.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

use bridge_core::crypto::sha256;
use bridge_core::encoding::b64;
use bridge_core::release::verify_announcement;
use bridge_node_cli::release;
use bridge_transport::{Handler, Request, Response, ServerConfig, serve};
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

struct Files(HashMap<String, Vec<u8>>);

impl Handler for Files {
    async fn handle(&self, request: Request) -> Response {
        match self.0.get(&request.path) {
            Some(body) => Response::ok(body.clone()),
            None => Response::error(404, "NOT_FOUND", "nicht da", None),
        }
    }
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|text| (*text).to_owned()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_is_signed_from_its_own_files_and_checked() -> TestResult {
    let windows = b"MZ windows program".to_vec();
    let mut files = HashMap::new();
    files.insert("/dl/bc-v1.2.3/bridgecontroll-windows-x86_64.exe".to_owned(), windows.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let base = format!("http://127.0.0.1:{}/dl/", listener.local_addr().map_err(|e| e.to_string())?.port());
    let server = serve(listener, ServerConfig::default(), Arc::new(Files(files))).map_err(|e| e.to_string())?;
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let key_file = dir.path().join("release-key.txt");
    let out = dir.path().join("releases").join("bridgecontroll.json");
    let (key, out_text) = (key_file.display().to_string(), out.display().to_string());

    assert_eq!(bridge_node_cli::run_cli(args(&["release", "keygen", "--out", &key])).await, ExitCode::SUCCESS);
    assert_eq!(bridge_node_cli::run_cli(args(&["release", "keygen", "--out", &key])).await, ExitCode::from(2));
    let public = release::load_key(&key_file)?.public();
    let sign = ["release", "sign", "--key", &key, "--tag", "bc-v1.2.3", "--notes", "Neu", "--out", &out_text];
    assert_eq!(bridge_node_cli::run_cli(args(&[&sign[..], &["--base", &base]].concat())).await, ExitCode::SUCCESS);

    // Only the Windows file is in the release: only it is announced, with the hash of what was really served.
    let now = i64::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_millis(),
    )
    .map_err(|e| e.to_string())?;
    let (signed, signer) = verify_announcement(&std::fs::read(&out).map_err(|e| e.to_string())?, &[public], now)
        .map_err(|e| e.to_string())?;
    assert_eq!((signed.version.to_string(), signer, signed.notes.as_str()), ("1.2.3".to_owned(), public, "Neu"));
    assert_eq!(signed.files.len(), 1);
    assert_eq!((signed.files[0].size, signed.files[0].sha256), (windows.len() as u64, sha256(&windows)));
    assert_eq!(signed.files[0].url, format!("{base}bc-v1.2.3/bridgecontroll-windows-x86_64.exe"));
    let verify = ["release", "verify", "--file", &out_text, "--public", &b64(&public)];
    assert_eq!(bridge_node_cli::run_cli(args(&verify)).await, ExitCode::SUCCESS);
    let stranger = b64(&[5; 32]);
    let wrong = ["release", "verify", "--file", &out_text, "--public", &stranger];
    assert_eq!(bridge_node_cli::run_cli(args(&wrong)).await, ExitCode::from(2), "another key");

    // A tag without files, a bad tag, a base that is not this PC: refused.
    for (tag, base) in [("bc-v2.0.0", base.as_str()), ("v1.2.3", base.as_str()), ("bc-v1.2.3", "http://example.org/")] {
        let other = dir.path().join("other.json").display().to_string();
        let sign = ["release", "sign", "--key", &key, "--tag", tag, "--out", &other, "--base", base];
        assert_eq!(bridge_node_cli::run_cli(args(&sign)).await, ExitCode::from(2), "{tag} {base}");
        assert!(!dir.path().join("other.json").exists());
    }
    server.shutdown().await;
    Ok(())
}
