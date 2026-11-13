//! Downloads from fixed hosts (docs/12 §3-4: BridgeControll's updates from GitHub). Unlike [`crate::HttpClient`],
//! redirects are followed - but only to hosts of a [`HostRule`] (GitHub sends release files on to its download host),
//! at most [`MAX_REDIRECTS`] times, and only over `https` (plain `http` only where the rule allows it: tests).
//! Bodies are bounded; a file is written while it arrives, with its exact size checked and its SHA-256 returned.
//! What the file must be is not decided here: the caller compares size and hash with a signed announcement.

use std::path::Path;
use std::time::Duration;

use bridge_core::crypto::Hasher;
use tokio::io::AsyncWriteExt as _;

use crate::{TransportError, TransportResult};

/// Most redirects followed.
pub const MAX_REDIRECTS: usize = 5;

/// Which hosts a download may touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    /// Allowed hosts: `example.com` (exactly this host) or `.example.com` (every host below it).
    pub hosts: Vec<String>,
    /// Also `http://` (only for tests on 127.0.0.1).
    pub allow_http: bool,
}

impl HostRule {
    /// Whether `url` may be fetched: `https` (or `http` if allowed), no user or password, an allowed host.
    #[must_use]
    pub fn allows(&self, url: &reqwest::Url) -> bool {
        let scheme_ok = url.scheme() == "https" || (self.allow_http && url.scheme() == "http");
        let Some(host) = url.host_str() else { return false };
        let host = host.to_ascii_lowercase();
        let host_ok = self.hosts.iter().any(|allowed| match allowed.strip_prefix('.') {
            Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
            None => host == *allowed,
        });
        scheme_ok && host_ok && url.username().is_empty() && url.password().is_none()
    }
}

fn client(rule: &HostRule, timeout: Duration) -> TransportResult<reqwest::Client> {
    let follow = rule.clone();
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if follow.allows(attempt.url()) {
            attempt.follow()
        } else {
            let host = attempt.url().host_str().unwrap_or("?").to_owned();
            attempt.error(format!("redirect to a host that is not allowed: {host}"))
        }
    });
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(15))
        .redirect(policy)
        .user_agent(concat!("bridgecontroll/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| TransportError::Config(e.to_string()))
}

async fn start(url: &str, rule: &HostRule, timeout: Duration, max_bytes: u64) -> TransportResult<reqwest::Response> {
    let parsed = reqwest::Url::parse(url).map_err(|e| TransportError::Config(e.to_string()))?;
    if url.len() > 2048 || !rule.allows(&parsed) {
        return Err(TransportError::Refused(format!("not an allowed address: {}", parsed.host_str().unwrap_or("?"))));
    }
    let response = client(rule, timeout)?.get(parsed).send().await.map_err(|e| crate::connection_error(&e))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(TransportError::Connection(format!("HTTP {status}")));
    }
    if response.content_length().is_some_and(|length| length > max_bytes) {
        return Err(TransportError::TooLarge);
    }
    Ok(response)
}

/// GETs `url` (at most `max_bytes`, answer `200` only) and returns the body.
pub async fn fetch(url: &str, rule: &HostRule, max_bytes: usize, timeout: Duration) -> TransportResult<Vec<u8>> {
    let mut response = start(url, rule, timeout, max_bytes as u64).await?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| crate::connection_error(&e))? {
        if body.len() + chunk.len() > max_bytes {
            return Err(TransportError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// GETs `url` into a new file `path` (it must not exist yet) - exactly `size` bytes, or the file is removed and an
/// error returned. Returns the SHA-256 of what was written.
pub async fn download_to(
    url: &str,
    rule: &HostRule,
    path: &Path,
    size: u64,
    timeout: Duration,
) -> TransportResult<[u8; 32]> {
    let response = start(url, rule, timeout, size).await?;
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .map_err(|e| TransportError::Config(format!("{}: {e}", path.display())))?;
    let result = write_file(response, file, path, size).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(path).await;
    }
    result
}

async fn write_file(
    mut response: reqwest::Response,
    mut file: tokio::fs::File,
    path: &Path,
    size: u64,
) -> TransportResult<[u8; 32]> {
    let mut hasher = Hasher::default();
    let mut written: u64 = 0;
    while let Some(chunk) = response.chunk().await.map_err(|e| crate::connection_error(&e))? {
        written = written.saturating_add(chunk.len() as u64);
        if written > size {
            return Err(TransportError::TooLarge);
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| TransportError::Config(format!("{}: {e}", path.display())))?;
    }
    if written != size {
        return Err(TransportError::Connection(format!("{written} of {size} bytes")));
    }
    file.sync_all().await.map_err(|e| TransportError::Config(format!("{}: {e}", path.display())))?;
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bridge_core::crypto::sha256;
    use tokio::net::TcpListener;

    use super::*;
    use crate::{Handler, Request, Response, ServerConfig, serve};

    struct Files {
        port: u16,
    }

    impl Handler for Files {
        async fn handle(&self, request: Request) -> Response {
            let moved = |to: String| Response { status: 302, ..Response::ok(Vec::new()) }.with_header("location", to);
            match request.path.as_str() {
                "/file" => Response::ok(b"hello world".to_vec()),
                "/near" => moved(format!("http://127.0.0.1:{}/file", self.port)),
                "/far" => moved(format!("http://localhost:{}/file", self.port)),
                "/loop" => moved(format!("http://127.0.0.1:{}/loop", self.port)),
                _ => Response::error(404, "NOT_FOUND", "no", None),
            }
        }
    }

    async fn files() -> Result<(crate::RunningServer, String), String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let server = serve(listener, ServerConfig::default(), Arc::new(Files { port })).map_err(|e| e.to_string())?;
        Ok((server, format!("http://127.0.0.1:{port}")))
    }

    fn local() -> HostRule {
        HostRule { hosts: vec!["127.0.0.1".into()], allow_http: true }
    }

    #[tokio::test]
    async fn downloads_exactly_what_is_allowed() -> Result<(), String> {
        let (server, base) = files().await?;
        let dir = std::env::temp_dir().join(format!("bridge-download-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.map_err(|e| e.to_string())?;
        let wait = Duration::from_secs(5);
        let target = dir.join("a");
        let hash =
            download_to(&format!("{base}/near"), &local(), &target, 11, wait).await.map_err(|e| e.to_string())?;
        assert_eq!(hash, sha256(b"hello world"), "followed the redirect to an allowed host");
        assert_eq!(tokio::fs::read(&target).await.map_err(|e| e.to_string())?, b"hello world");
        // The file exists: refused, and the existing file stays.
        assert!(download_to(&format!("{base}/file"), &local(), &target, 11, wait).await.is_err());
        assert!(target.exists());
        // Wrong size (shorter or longer): error, nothing left behind.
        for size in [10, 12] {
            let path = dir.join(format!("size{size}"));
            assert!(download_to(&format!("{base}/file"), &local(), &path, size, wait).await.is_err(), "{size}");
            assert!(!path.exists(), "{size}");
        }
        // Redirects to another host, endless redirects, a host outside the rule, plain http without the rule.
        let path = dir.join("b");
        for url in [format!("{base}/far"), format!("{base}/loop"), format!("{base}/missing")] {
            assert!(download_to(&url, &local(), &path, 11, wait).await.is_err(), "{url}");
            assert!(!path.exists());
        }
        let strict = HostRule { hosts: vec!["127.0.0.1".into()], allow_http: false };
        assert!(matches!(fetch(&format!("{base}/file"), &strict, 100, wait).await, Err(TransportError::Refused(_))));
        assert!(matches!(fetch(&format!("{base}/file"), &local(), 5, wait).await, Err(TransportError::TooLarge)));
        assert_eq!(
            fetch(&format!("{base}/file"), &local(), 11, wait).await.map_err(|e| e.to_string())?,
            b"hello world"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
        server.shutdown().await;
        Ok(())
    }

    fn rule(hosts: &[&str]) -> HostRule {
        HostRule { hosts: hosts.iter().map(|h| (*h).to_owned()).collect(), allow_http: false }
    }

    fn allowed(rule: &HostRule, text: &str) -> Result<bool, String> {
        Ok(rule.allows(&reqwest::Url::parse(text).map_err(|e| e.to_string())?))
    }

    #[test]
    fn host_rules() -> Result<(), String> {
        let github = rule(&["github.com", ".githubusercontent.com"]);
        for good in [
            "https://github.com/PhilippDwinger/Bridge/releases/download/bc-v0.2.0/x.exe",
            "https://objects.githubusercontent.com/abc",
            "https://raw.githubusercontent.com/PhilippDwinger/Bridge/bridge-4/releases/bridgecontroll.json",
            "https://GITHUB.com/x",
        ] {
            assert!(allowed(&github, good)?, "{good}");
        }
        for bad in [
            "http://github.com/x",
            "https://github.com.evil.com/x",
            "https://evilgithub.com/x",
            "https://githubusercontent.com/x",
            "https://x.githubusercontent.com.evil/x",
            "https://user:pw@github.com/x",
            "ftp://github.com/x",
            "https://127.0.0.1/x",
        ] {
            assert!(!allowed(&github, bad)?, "{bad}");
        }
        let local = HostRule { hosts: vec!["127.0.0.1".into()], allow_http: true };
        assert!(allowed(&local, "http://127.0.0.1:8080/x")? && !allowed(&local, "http://localhost:8080/x")?);
        Ok(())
    }
}
