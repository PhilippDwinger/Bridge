//! The watchdog of the node processes (ADR 0017): a node that crashes is started again with backoff, one that
//! crashes too often is given up, a stop is clean (standard input closed → the node shuts down itself).

mod common;

use std::time::Duration;

use bridgecontroll::supervisor::{Backoff, Launch, RunState, Supervisor};
use common::{TestResult, free_port, node_exe, wait_for};

fn launch(dir: &std::path::Path, port: u16) -> Launch {
    Launch {
        id: "0a1b2c3d".into(),
        mode: "node",
        args: vec![
            "--data".into(),
            dir.join("node").display().to_string(),
            "--listen".into(),
            format!("127.0.0.1:{port}"),
        ],
        log: dir.join("logs").join("0a1b2c3d.log"),
    }
}

async fn answers(port: u16) -> bool {
    let Ok(http) = bridge_transport::HttpClient::new(&format!("http://127.0.0.1:{port}"), Duration::from_secs(2))
    else {
        return false;
    };
    http.get("/v4/info").await.is_ok_and(|answer| answer.status == 200)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_loop_gives_up_and_a_manual_start_begins_anew() -> TestResult {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    // The port is taken: the node ends with an error at every start.
    let blocker = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    let port = blocker.local_addr().map_err(|e| e.to_string())?.port();
    let supervisor = Supervisor::new(node_exe(), Backoff::scaled(Duration::from_millis(20)));
    supervisor.start(launch(dir.path(), port));
    let failed = wait_for(60, "watchdog gives up", || async {
        let status = supervisor.status("0a1b2c3d");
        Ok((status.state == RunState::Failed).then_some(status))
    })
    .await?;
    assert_eq!(failed.restarts, 5, "five restarts, then no more: {failed:?}");
    assert!(failed.last_exit.as_deref().is_some_and(|text| text.contains("Code 2")), "{failed:?}");
    let log = std::fs::read_to_string(dir.path().join("logs").join("0a1b2c3d.log")).map_err(|e| e.to_string())?;
    assert!(log.contains("zu oft abgestürzt") && log.contains("kann nicht auf"), "{log}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(supervisor.status("0a1b2c3d").state, RunState::Failed, "stays given up");

    // Free the port and start by hand: it runs, the count begins anew.
    drop(blocker);
    supervisor.start(launch(dir.path(), port));
    let running = wait_for(30, "runs after a manual start", || async {
        let status = supervisor.status("0a1b2c3d");
        Ok((status.state == RunState::Running && answers(port).await).then_some(status))
    })
    .await?;
    assert_eq!(running.restarts, 0);
    supervisor.stop_all().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_stop_closes_the_node() -> TestResult {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let port = free_port()?;
    let supervisor = Supervisor::new(node_exe(), Backoff::scaled(Duration::from_millis(20)));
    supervisor.start(launch(dir.path(), port));
    wait_for(30, "node answers", || async {
        Ok((supervisor.status("0a1b2c3d").state == RunState::Running
            && tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok())
        .then_some(()))
    })
    .await?;
    // Starting again while it runs changes nothing.
    let pid = supervisor.status("0a1b2c3d").pid;
    supervisor.start(launch(dir.path(), port));
    assert_eq!(supervisor.status("0a1b2c3d").pid, pid);
    let started = std::time::Instant::now();
    supervisor.stop("0a1b2c3d").await;
    assert!(
        started.elapsed() < Duration::from_secs(9),
        "stopped by closing stdin, not by the kill after the grace time"
    );
    assert_eq!(supervisor.status("0a1b2c3d").state, RunState::Off);
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err(), "the node closed its listener");
    let log = std::fs::read_to_string(dir.path().join("logs").join("0a1b2c3d.log")).map_err(|e| e.to_string())?;
    assert!(log.contains("lauscht auf") && log.contains("Knoten gestoppt") && !log.contains("hart beendet"), "{log}");
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_node_is_started_again() -> TestResult {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let port = free_port()?;
    let supervisor = Supervisor::new(node_exe(), Backoff::scaled(Duration::from_millis(20)));
    supervisor.start(launch(dir.path(), port));
    let first = wait_for(30, "node runs", || async {
        let status = supervisor.status("0a1b2c3d");
        Ok((status.state == RunState::Running && tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok())
            .then_some(status))
    })
    .await?;
    let pid = first.pid.ok_or("no pid")?;
    let killed =
        std::process::Command::new("kill").arg("-9").arg(pid.to_string()).status().map_err(|e| e.to_string())?;
    assert!(killed.success());
    let again = wait_for(30, "node runs again", || async {
        let status = supervisor.status("0a1b2c3d");
        Ok((status.state == RunState::Running
            && status.pid != Some(pid)
            && tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok())
        .then_some(status))
    })
    .await?;
    assert_eq!(again.restarts, 1);
    assert!(again.last_exit.as_deref().is_some_and(|text| text.contains("abgestürzt")), "{again:?}");
    supervisor.stop_all().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_missing_program_fails_at_once() -> TestResult {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let supervisor = Supervisor::new(dir.path().join("does-not-exist"), Backoff::standard());
    supervisor.start(launch(dir.path(), 1));
    let failed = wait_for(10, "fails", || async {
        let status = supervisor.status("0a1b2c3d");
        Ok((status.state == RunState::Failed).then_some(status))
    })
    .await?;
    assert!(failed.last_exit.as_deref().is_some_and(|text| text.contains("nicht startbar")), "{failed:?}");
    Ok(())
}
