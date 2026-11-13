//! Routes and the routing decision (docs/11 §3) - pure functions, no I/O.

use serde_json::Value;

/// Most routes in one file.
pub const MAX_ROUTES: usize = 64;
/// Longest request target (path and query).
pub const MAX_TARGET: usize = 2048;
/// Longest network key.
pub const MAX_KEY: usize = 64;
/// The prefix Tailscale Funnel mounts the gate at; removed if Tailscale did not cut it off.
pub const PREFIX: &str = "bridge4";

/// One public network on this PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The network key in the path (`/bridge4/<key>/…`): lower case letters, digits, `-`.
    pub key: String,
    /// The port of the network's node on `127.0.0.1`.
    pub port: u16,
    /// Websites and apps public (`false`: the Not-Aus - only `/v4/` goes through).
    pub web: bool,
}

/// The routes of the gate (from the file BridgeControll writes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Routes {
    routes: Vec<Route>,
}

/// Whether `key` may be a network key: 1-64 of `a-z 0-9 -`, not the gate's own prefix or Bridge 3's.
#[must_use]
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY
        && key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && key != PREFIX
        && key != "bridge3"
}

impl Routes {
    /// Routes from a list (checked like [`Routes::parse`]).
    ///
    /// # Errors
    /// Too many routes, an invalid key or port, a key twice.
    pub fn new(routes: Vec<Route>) -> Result<Self, String> {
        if routes.len() > MAX_ROUTES {
            return Err(format!("höchstens {MAX_ROUTES} Routen"));
        }
        for (index, route) in routes.iter().enumerate() {
            if !valid_key(&route.key) {
                return Err(format!("Route {index}: ungültiger Schlüssel"));
            }
            if route.port < 1024 {
                return Err(format!("Route {index}: Port 1024-65535"));
            }
            if routes[..index].iter().any(|other| other.key == route.key) {
                return Err(format!("Route {index}: Schlüssel doppelt"));
            }
        }
        Ok(Self { routes })
    }

    /// `{"routes":[{"key":"testnetz","port":7401,"web":true}, …]}` - nothing else, every field required.
    ///
    /// # Errors
    /// Not this form, or [`Routes::new`] refuses it.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 64 * 1024 {
            return Err("Routen-Datei zu groß".into());
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("Routen-Datei: {e}"))?;
        let object = value.as_object().filter(|o| o.len() == 1).ok_or("Routen-Datei: nur {\"routes\": [...]}")?;
        let list = object.get("routes").and_then(Value::as_array).ok_or("Routen-Datei: routes fehlt")?;
        let mut routes = Vec::with_capacity(list.len().min(MAX_ROUTES));
        for item in list.iter().take(MAX_ROUTES + 1) {
            let item = item.as_object().filter(|o| o.len() == 3).ok_or("Route: key, port, web")?;
            let key = item.get("key").and_then(Value::as_str).ok_or("Route: key")?;
            let port =
                item.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).ok_or("Route: port")?;
            let web = item.get("web").and_then(Value::as_bool).ok_or("Route: web")?;
            routes.push(Route { key: key.to_owned(), port, web });
        }
        Self::new(routes)
    }

    /// The file form ([`Routes::parse`] reads it back).
    #[must_use]
    pub fn to_json(&self) -> String {
        let list: Vec<Value> =
            self.routes.iter().map(|r| serde_json::json!({"key": r.key, "port": r.port, "web": r.web})).collect();
        serde_json::json!({ "routes": list }).to_string()
    }

    /// The route of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Route> {
        self.routes.iter().find(|route| route.key == key)
    }

    /// All routes.
    #[must_use]
    pub fn all(&self) -> &[Route] {
        &self.routes
    }
}

/// What the gate does with a request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// `/`: the gate's own small page (no list - other networks of this PC stay unknown).
    Home,
    /// `308` to this relative location (`<key>/`).
    Redirect(String),
    /// To the node on `127.0.0.1:<port>` with this target (path and query, without `/bridge4/<key>`).
    Forward {
        /// The node's port.
        port: u16,
        /// Path (starting with `/`) and query.
        target: String,
    },
    /// The network's websites are switched off (Not-Aus): `503`.
    Off,
    /// No such network: `404`.
    NotFound,
    /// A target the gate never forwards (too long, odd characters, `..`, encoded slashes): `400`.
    Bad,
}

/// The routing decision for a request target (path and query, as sent) - see docs/11 §3.
#[must_use]
pub fn decide(routes: &Routes, target: &str) -> Decision {
    if target.len() > MAX_TARGET {
        return Decision::Bad;
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if !clean_path(path) || query.is_some_and(|query| !clean_query(query)) {
        return Decision::Bad;
    }
    let mut rest = path;
    if let Some(after) = rest.strip_prefix('/').and_then(|r| r.strip_prefix(PREFIX)) {
        if after.is_empty() || after.starts_with('/') {
            rest = if after.is_empty() { "/" } else { after };
        }
    }
    let Some(inner) = rest.strip_prefix('/') else { return Decision::Bad };
    if inner.is_empty() {
        return Decision::Home;
    }
    let (key, tail) = match inner.split_once('/') {
        Some((key, tail)) => (key, Some(tail)),
        None => (inner, None),
    };
    if !valid_key(key) {
        return Decision::NotFound;
    }
    let Some(route) = routes.get(key) else { return Decision::NotFound };
    let Some(tail) = tail else { return Decision::Redirect(format!("{key}/")) };
    let forwarded = format!("/{tail}");
    if !route.web && web_path(&forwarded) {
        return Decision::Off;
    }
    let target = match query {
        Some(query) => format!("{forwarded}?{query}"),
        None => forwarded,
    };
    Decision::Forward { port: route.port, target }
}

/// Paths of websites and apps (switched off by the Not-Aus): the start page, `/web/…`, `/app/…`.
fn web_path(path: &str) -> bool {
    path == "/" || path == "/web" || path == "/app" || path.starts_with("/web/") || path.starts_with("/app/")
}

/// A path the gate forwards: starts with `/`; only RFC 3986 path characters and valid `%XX`; no empty segment
/// except a trailing `/`; no `.`/`..` segment (also encoded); no encoded `/`, `\` or NUL.
fn clean_path(path: &str) -> bool {
    let Some(inner) = path.strip_prefix('/') else { return false };
    if !escapes_ok(path, |b| is_pchar(b) || b == b'/') {
        return false;
    }
    let segments: Vec<&str> = inner.split('/').collect();
    let last = segments.len().saturating_sub(1);
    segments.iter().enumerate().all(|(index, segment)| {
        if segment.is_empty() {
            return index == last; // `//` never, a trailing `/` (or the root) yes
        }
        let decoded_dots = segment.replace("%2e", ".").replace("%2E", ".");
        decoded_dots != "." && decoded_dots != ".."
    })
}

fn clean_query(query: &str) -> bool {
    escapes_ok(query, |b| is_pchar(b) || b == b'/' || b == b'?')
}

/// Every byte allowed or part of a valid `%XX` that is not `/`, `\` or NUL.
fn escapes_ok(text: &str, allowed: impl Fn(u8) -> bool) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let (Some(high), Some(low)) = (bytes.get(index + 1), bytes.get(index + 2)) else { return false };
            let (Some(high), Some(low)) = (hex(*high), hex(*low)) else { return false };
            if matches!(high * 16 + low, b'/' | b'\\' | 0) {
                return false;
            }
            index += 3;
        } else if allowed(byte) {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// RFC 3986 `pchar` without `%` (handled apart): unreserved, sub-delims, `:` and `@`.
fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes() -> Routes {
        Routes::new(vec![
            Route { key: "testnetz".into(), port: 7401, web: true },
            Route { key: "zu".into(), port: 7402, web: false },
        ])
        .unwrap_or_default()
    }

    fn forward(port: u16, target: &str) -> Decision {
        Decision::Forward { port, target: target.into() }
    }

    #[test]
    fn routing_with_and_without_the_prefix() {
        let r = routes();
        for prefix in ["", "/bridge4"] {
            let d = |rest: &str| decide(&r, &format!("{prefix}{rest}"));
            assert_eq!(d("/testnetz/v4/info"), forward(7401, "/v4/info"), "{prefix}");
            assert_eq!(d("/testnetz/"), forward(7401, "/"));
            assert_eq!(d("/testnetz/web/shop/"), forward(7401, "/web/shop/"));
            assert_eq!(d("/testnetz/app/abc/x.js?v=1&a=b"), forward(7401, "/app/abc/x.js?v=1&a=b"));
            assert_eq!(d("/testnetz"), Decision::Redirect("testnetz/".into()));
            assert_eq!(d("/nix/v4/info"), Decision::NotFound);
            assert_eq!(d("/Testnetz/v4/info"), Decision::NotFound);
            // Not-Aus: websites and apps off, the protocol stays.
            assert_eq!(d("/zu/"), Decision::Off);
            assert_eq!(d("/zu/web/shop/"), Decision::Off);
            assert_eq!(d("/zu/app/abc/"), Decision::Off);
            assert_eq!(d("/zu/app"), Decision::Off);
            assert_eq!(d("/zu/v4/poll"), forward(7402, "/v4/poll"));
        }
        assert_eq!(decide(&r, "/"), Decision::Home);
        assert_eq!(decide(&r, "/bridge4"), Decision::Home);
        assert_eq!(decide(&r, "/bridge4/"), Decision::Home);
        assert_eq!(decide(&r, "/bridge4x/v4"), Decision::NotFound, "only the whole segment is the prefix");
        // The prefix goes once only: `/bridge4/bridge4/…` is the (invalid) key `bridge4`.
        assert_eq!(decide(&r, "/bridge4/bridge4/testnetz/v4/info"), Decision::NotFound);
    }

    #[test]
    fn odd_targets_are_refused() {
        let r = routes();
        for bad in [
            "",
            "testnetz/v4",
            "/testnetz/../x",
            "/testnetz/./x",
            "/testnetz/%2e%2e/x",
            "/testnetz/%2E./x",
            "/testnetz/a%2fb",
            "/testnetz/a%2Fb",
            "/testnetz/a%5cb",
            "/testnetz/a%00b",
            "/testnetz/a%zzb",
            "/testnetz/a%2",
            "/testnetz//v4",
            "//testnetz/v4",
            "/testnetz/a b",
            "/testnetz/a\\b",
            "/testnetz/a\"b",
            "/testnetz/a<b",
            "/testnetz/v4?x=<",
            "/testnetz/v4?x=%2f",
        ] {
            assert_eq!(decide(&r, bad), Decision::Bad, "{bad:?}");
        }
        assert_eq!(decide(&r, &format!("/testnetz/{}", "a".repeat(MAX_TARGET))), Decision::Bad);
        assert_eq!(decide(&r, "/testnetz/a%20b%C3%A4"), forward(7401, "/a%20b%C3%A4"));
        assert_eq!(decide(&r, "/testnetz/v4?q=a/b?c"), forward(7401, "/v4?q=a/b?c"));
    }

    #[test]
    fn route_files() -> Result<(), String> {
        let r = routes();
        assert_eq!(Routes::parse(r.to_json().as_bytes())?, r);
        assert_eq!(Routes::parse(br#"{"routes":[]}"#)?.all().len(), 0);
        for bad in [
            r#"{"routes":[{"key":"a","port":7401}]}"#,
            r#"{"routes":[{"key":"a","port":7401,"web":true,"x":1}]}"#,
            r#"{"routes":[{"key":"A","port":7401,"web":true}]}"#,
            r#"{"routes":[{"key":"bridge4","port":7401,"web":true}]}"#,
            r#"{"routes":[{"key":"bridge3","port":7401,"web":true}]}"#,
            r#"{"routes":[{"key":"a","port":80,"web":true}]}"#,
            r#"{"routes":[{"key":"a","port":70000,"web":true}]}"#,
            r#"{"routes":[{"key":"a","port":7401,"web":true},{"key":"a","port":7402,"web":true}]}"#,
            r#"{"routes":[],"more":1}"#,
            r#"[]"#,
        ] {
            assert!(Routes::parse(bad.as_bytes()).is_err(), "{bad}");
        }
        let many: Vec<Route> =
            (0..=MAX_ROUTES).map(|n| Route { key: format!("n{n}"), port: 7401, web: true }).collect();
        assert!(Routes::new(many).is_err());
        Ok(())
    }
}
