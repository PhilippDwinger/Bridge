//! Every node runs as its own process (ADR 0017): the same program in node mode (`bridgecontroll node --supervised
//! …`), watched here.
//!
//! - **Watchdog**: a node that ends without being asked to is started again after 1, 2, 4, 8, 16 s; more than
//!   [`Backoff::max_restarts`] ends within [`Backoff::window`] and the watchdog gives up (state `failed`, like v1:
//!   five restarts in ten minutes). A manual start begins anew.
//! - **Clean stop**: the node's standard input is closed - in node mode with `--supervised` that is the signal to
//!   shut down cleanly (background duties, mDNS goodbye, listeners). It works the same on every system and needs no
//!   signals (no `unsafe`). After [`Backoff::stop_grace`] the process is killed. When BridgeControll itself ends, the
//!   pipes close too, so no node outlives it unsupervised.
//! - **Logs**: standard output and error go line by line into a rotating log file per node (bounded lines,
//!   bounded files).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::process::Command;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::logfile::{DEFAULT_KEEP, DEFAULT_MAX_BYTES, RotatingLog};
use crate::now_ms;

/// Longest piece of node output kept as one line.
const MAX_PIPE_LINE: usize = 8 * 1024;

/// Restart and stop timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Waits before the 1st, 2nd, … restart (the last one repeats).
    pub steps: [Duration; 5],
    /// Most restarts within [`Backoff::window`]; one more end and the watchdog gives up.
    pub max_restarts: usize,
    /// The window for counting ends.
    pub window: Duration,
    /// How long a clean stop may take before the process is killed.
    pub stop_grace: Duration,
}

impl Backoff {
    /// 1/2/4/8/16 s, at most 5 restarts in 10 min, 10 s to stop.
    #[must_use]
    pub fn standard() -> Self {
        Self::scaled(Duration::from_secs(1))
    }

    /// The same steps with another base (tests: milliseconds).
    #[must_use]
    pub fn scaled(base: Duration) -> Self {
        Self {
            steps: [base, base * 2, base * 4, base * 8, base * 16],
            max_restarts: 5,
            window: Duration::from_secs(600),
            stop_grace: Duration::from_secs(10),
        }
    }

    fn delay(&self, ends: usize) -> Duration {
        self.steps[ends.saturating_sub(1).min(self.steps.len() - 1)]
    }
}

/// What a node process does right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Not started (or stopped).
    Off,
    /// The process runs.
    Running,
    /// Asked to stop, waiting for it to end.
    Stopping,
    /// Ended unexpectedly; waits before the next start.
    Waiting,
    /// Ended too often - the watchdog gave up.
    Failed,
}

impl RunState {
    /// Name in the API.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Waiting => "waiting",
            Self::Failed => "failed",
        }
    }
}

/// Status of one node process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStatus {
    /// State.
    pub state: RunState,
    /// Process ID while it runs.
    pub pid: Option<u32>,
    /// Restarts by the watchdog since the last manual start.
    pub restarts: u32,
    /// How the process last ended (German, for people).
    pub last_exit: Option<String>,
    /// When the next start is due (ms since 1970), while waiting.
    pub retry_at: Option<i64>,
    /// When the running process started (ms since 1970).
    pub started_at: Option<i64>,
}

impl ProcStatus {
    fn off() -> Self {
        Self { state: RunState::Off, pid: None, restarts: 0, last_exit: None, retry_at: None, started_at: None }
    }
}

/// How to start one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The node's local ID (key of the supervisor).
    pub id: String,
    /// Arguments after `node --supervised`.
    pub args: Vec<String>,
    /// Its log file.
    pub log: PathBuf,
}

struct Handle {
    status: Arc<Mutex<ProcStatus>>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// Starts, watches and stops the node processes of the app.
pub struct Supervisor {
    exe: PathBuf,
    backoff: Backoff,
    procs: Mutex<HashMap<String, Handle>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Supervisor {
    /// A supervisor that starts nodes with the program `exe` (normally this program itself).
    #[must_use]
    pub fn new(exe: PathBuf, backoff: Backoff) -> Self {
        Self { exe, backoff, procs: Mutex::new(HashMap::new()) }
    }

    /// Starts a node (nothing happens if it runs or waits for a restart already). A failed or stopped node starts
    /// anew (restart count reset).
    pub fn start(&self, launch: Launch) {
        let mut procs = lock(&self.procs);
        if let Some(handle) = procs.get(&launch.id) {
            let state = lock(&handle.status).state;
            if matches!(state, RunState::Running | RunState::Waiting | RunState::Stopping) && !handle.task.is_finished()
            {
                return;
            }
        }
        let status = Arc::new(Mutex::new(ProcStatus::off()));
        let (stop, stopped) = watch::channel(false);
        let task =
            tokio::spawn(supervise(self.exe.clone(), launch.clone(), self.backoff, Arc::clone(&status), stopped));
        procs.insert(launch.id, Handle { status, stop, task });
    }

    /// Stops a node cleanly (killed after the grace time) and waits until it ended.
    pub async fn stop(&self, id: &str) {
        let handle = lock(&self.procs).remove(id);
        let Some(handle) = handle else { return };
        let _ = handle.stop.send(true);
        let mut task = handle.task;
        if tokio::time::timeout(self.backoff.stop_grace + Duration::from_secs(5), &mut task).await.is_err() {
            task.abort();
        }
    }

    /// Stops all nodes (all asked at once, then waited for).
    pub async fn stop_all(&self) {
        let handles: Vec<Handle> = lock(&self.procs).drain().map(|(_, handle)| handle).collect();
        for handle in &handles {
            let _ = handle.stop.send(true);
        }
        let deadline = tokio::time::Instant::now() + self.backoff.stop_grace + Duration::from_secs(5);
        for handle in handles {
            let mut task = handle.task;
            if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
            }
        }
    }

    /// The status of a node (`off` if unknown).
    #[must_use]
    pub fn status(&self, id: &str) -> ProcStatus {
        lock(&self.procs).get(id).map_or_else(ProcStatus::off, |handle| lock(&handle.status).clone())
    }
}

/// The watchdog of one node (see module docs).
async fn supervise(
    exe: PathBuf,
    launch: Launch,
    backoff: Backoff,
    status: Arc<Mutex<ProcStatus>>,
    mut stop: watch::Receiver<bool>,
) {
    let set = |change: &dyn Fn(&mut ProcStatus)| change(&mut lock(&status));
    let log = match RotatingLog::open(&launch.log, DEFAULT_MAX_BYTES, DEFAULT_KEEP) {
        Ok(log) => log,
        Err(error) => {
            set(&|s| {
                s.state = RunState::Failed;
                s.last_exit = Some(format!("Log-Datei nicht nutzbar: {error}"));
            });
            return;
        }
    };
    let mut ends: VecDeque<Instant> = VecDeque::new();
    loop {
        if *stop.borrow() {
            set(&|s| s.state = RunState::Off);
            return;
        }
        let mut child = match command(&exe, &launch.args).spawn() {
            Ok(child) => child,
            Err(error) => {
                let text = format!("Programm nicht startbar: {error}");
                log.line(&format!("== BridgeControll: {text}"));
                set(&|s| {
                    s.state = RunState::Failed;
                    s.pid = None;
                    s.last_exit = Some(text.clone());
                });
                return;
            }
        };
        let pid = child.id();
        log.line(&format!("== BridgeControll: Knoten gestartet (Prozess {})", pid.unwrap_or(0)));
        let stdin = child.stdin.take();
        let pipes = [pipe(child.stdout.take(), log.clone()), pipe(child.stderr.take(), log.clone())];
        set(&|s| {
            s.state = RunState::Running;
            s.pid = pid;
            s.retry_at = None;
            s.started_at = Some(now_ms());
        });
        let ended = tokio::select! {
            ended = child.wait() => Some(ended),
            _ = stop.changed() => None,
        };
        let Some(ended) = ended else {
            set(&|s| s.state = RunState::Stopping);
            drop(stdin); // the signal for a clean stop
            if tokio::time::timeout(backoff.stop_grace, child.wait()).await.is_err() {
                log.line("== BridgeControll: Knoten hat nicht rechtzeitig beendet - hart beendet");
                let _ = child.kill().await;
            }
            finish(pipes).await;
            log.line("== BridgeControll: Knoten gestoppt");
            set(&|s| {
                s.state = RunState::Off;
                s.pid = None;
                s.started_at = None;
            });
            return;
        };
        drop(stdin);
        finish(pipes).await;
        let text = match ended {
            Ok(code) => match code.code() {
                Some(0) => "unerwartet beendet (Code 0)".to_owned(),
                Some(code) => format!("abgestürzt (Code {code})"),
                None => "abgestürzt (beendet von außen)".to_owned(),
            },
            Err(error) => format!("Zustand unbekannt: {error}"),
        };
        log.line(&format!("== BridgeControll: Knoten {text}"));
        let now = Instant::now();
        ends.push_back(now);
        while ends.front().is_some_and(|first| now.duration_since(*first) > backoff.window) {
            ends.pop_front();
        }
        if ends.len() > backoff.max_restarts {
            log.line("== BridgeControll: zu oft abgestürzt - kein weiterer Neustart (Starten von Hand beginnt neu)");
            set(&|s| {
                s.state = RunState::Failed;
                s.pid = None;
                s.started_at = None;
                s.last_exit = Some(text.clone());
            });
            return;
        }
        let delay = backoff.delay(ends.len());
        let retry_at = now_ms().saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX));
        set(&|s| {
            s.state = RunState::Waiting;
            s.pid = None;
            s.started_at = None;
            s.last_exit = Some(text.clone());
            s.retry_at = Some(retry_at);
        });
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = stop.changed() => {
                set(&|s| {
                    s.state = RunState::Off;
                    s.retry_at = None;
                });
                return;
            }
        }
        set(&|s| s.restarts = s.restarts.saturating_add(1));
    }
}

/// The command for one node process: `<exe> node --supervised <args>`, pipes for all three streams, killed if the
/// supervisor goes away; no console window on Windows.
fn command(exe: &Path, args: &[String]) -> Command {
    let mut command = Command::new(exe);
    command
        .arg("node")
        .arg("--supervised")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// Copies one output stream of a node into its log, line by line (a line longer than [`MAX_PIPE_LINE`] is cut).
fn pipe(stream: Option<impl AsyncRead + Unpin + Send + 'static>, log: RotatingLog) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(mut stream) = stream else { return };
        let mut buffer: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 2048];
        loop {
            let read = match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            for &byte in &chunk[..read] {
                if byte == b'\n' {
                    log.line(&String::from_utf8_lossy(&buffer));
                    buffer.clear();
                } else if buffer.len() < MAX_PIPE_LINE {
                    buffer.push(byte);
                }
            }
        }
        if !buffer.is_empty() {
            log.line(&String::from_utf8_lossy(&buffer));
        }
    })
}

/// Waits a little for the output copiers to finish (they end when the process closes its streams).
async fn finish(pipes: [JoinHandle<()>; 2]) {
    for pipe in pipes {
        let _ = tokio::time::timeout(Duration::from_secs(2), pipe).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_steps() {
        let standard = Backoff::standard();
        let delays: Vec<u64> = (1..=7).map(|n| standard.delay(n).as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 16, 16]);
        assert_eq!((standard.max_restarts, standard.window.as_secs()), (5, 600));
        assert_eq!(Backoff::scaled(Duration::from_millis(10)).delay(3), Duration::from_millis(40));
    }

    #[test]
    fn states_have_api_names() {
        let names: Vec<&str> =
            [RunState::Off, RunState::Running, RunState::Stopping, RunState::Waiting, RunState::Failed]
                .iter()
                .map(|state| state.as_str())
                .collect();
        assert_eq!(names, vec!["off", "running", "stopping", "waiting", "failed"]);
    }
}
