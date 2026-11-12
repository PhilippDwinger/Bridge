//! The start menu entry "BridgeControll" (Paddy, 12.11.2026): made at the first start if there is none, renewed with
//! the button (`POST /api/startmenu`), never without a place set (tests and `Options::new` touch nothing).

mod common;

use common::{TestResult, start, start_with, wait_for};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_start_makes_the_entry_and_the_button_renews_it() -> TestResult {
    let menu = tempfile::tempdir().map_err(|e| e.to_string())?;
    let place = menu.path().join("applications");
    let app = start_with(|options| options.menu_dir = Some(place.clone())).await?;
    let entry = place.join(if cfg!(windows) { "BridgeControll.lnk" } else { "bridgecontroll.desktop" });
    if !cfg!(windows) {
        wait_for(20, "entry made at the first start", || async { Ok(entry.is_file().then_some(())) }).await?;
        let (_, overview) = app.get("/api/overview").await?;
        assert_eq!(overview["startmenu"], json!({"supported": true, "exists": true}));
        std::fs::remove_file(&entry).map_err(|e| e.to_string())?;
        let done = app.ok("/api/startmenu", &json!({})).await?;
        assert_eq!(done, json!({"ok": true, "renamed_old": false}));
        assert!(entry.is_file());
        let text = std::fs::read_to_string(&entry).map_err(|e| e.to_string())?;
        assert!(text.contains("Name=BridgeControll\n") && text.contains("bridgecontroll4.svg"), "{text}");
    }
    app.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_place_nothing_is_touched() -> TestResult {
    let app = start().await?;
    let (_, overview) = app.get("/api/overview").await?;
    assert_eq!(overview["startmenu"], json!({"supported": false, "exists": false}));
    let (status, answer) = app.post("/api/startmenu", &json!({})).await?;
    assert_eq!(status, 400);
    assert!(answer["error"].as_str().is_some_and(|e| e.contains("Startmenü")), "{answer}");
    app.shutdown().await;
    Ok(())
}
