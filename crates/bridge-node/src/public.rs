//! Public pages of a node behind the gate of a public network (docs/11 §4, ADR 0025) - only with the reader
//! `public`:
//!
//! - `GET /`: the start page - the network's name, its report contact and up to 100 app names that resolve now with
//!   the safe search's rules (no 18+, owner level ≥ 2, block lists), links `web/<name>/`.
//! - `GET /web/<name>/`: the frame - a bar with network, name and report contact above the app in a sandboxed
//!   `iframe` (`../../app/<app-id>/`); `/web/<name>` → `308` to `<name>/`.
//! - Both are static HTML without scripts (CSP `default-src 'none'`), `no-store`, never framed by others; every text
//!   from the network is HTML-escaped, the contact becomes a link only as a plain e-mail address or `https://` URL.
//! - With Bridge Login on at this node (docs/11 §9.4) the frame has one script: Bridge's own `/login.js` (CSP
//!   `script-src 'self'`, `connect-src 'self'`, no inline code) and is isolated from other windows of the origin
//!   (`Cross-Origin-Opener-Policy: same-origin`).
//! - Visitors from the Internet (requests through the trusted proxy) see apps only of owners with level ≥ 2 in a
//!   network that forbids 18+ ([`Node::public_visible`]) - for the frame, the start page and `/app/…` alike.
//! - Only a node sealed with **level 3** shows websites to the Internet ([`Node::website_entrance`], docs/11 §13): the
//!   owner node, or a node the owner trusts that much. Any other public node (a member's PC behind its gate) is
//!   reachable for the protocol only; its `/` says so, `/web/…` and `/app/…` are `404` for visitors from the Internet.

use bridge_core::Id;
use bridge_net::{Category, NameKind};
use bridge_transport::{Method, Request, Response};

use crate::reader::ReaderAccess;
use crate::{Node, NodeError};

/// Longest name in a `/web/` path (names are shorter, docs/08 §3).
const MAX_WEB_NAME: usize = 64;

/// CSP of the pages: no scripts, no images, only inline styles; the frame may show this origin (the app below
/// `/app/`, itself in an opaque sandbox origin).
const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; base-uri 'none'; \
                        form-action 'none'; frame-ancestors 'none'";

/// CSP of the frame with Bridge Login: as [`PAGE_CSP`] plus Bridge's own script and its calls to this origin.
const LOGIN_CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; \
                         frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The shell's login script (docs/11 §9.4).
const LOGIN_JS: &str = include_str!("login.js");

/// The sandbox of the `iframe` - the same rights as the app's own CSP `sandbox` (docs/07 §5).
const FRAME_SANDBOX: &str = "allow-scripts allow-forms allow-popups";

const STYLE: &str = "html,body{margin:0;height:100%}body{font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;\
color:#1d2433;background:#f6f7fb}main{max-width:44rem;margin:0 auto;padding:2rem 1rem}h1{font-size:1.6rem;margin:0 0 \
.25rem}h2{font-size:1.1rem;margin:2rem 0 .5rem}ul{padding-left:1.2rem}li{margin:.35rem 0}a{color:#2448c8}.muted{color:\
#5b6475}footer{margin-top:2.5rem;font-size:.9rem;color:#5b6475}table{border-collapse:collapse;width:100%}td{padding:.35rem \
.5rem .35rem 0;border-bottom:1px solid #e3e6ee}.ok{color:#1b7a3a}.warn{color:#8a5a00}.bad{color:#b3261e}.frame{display:flex;flex-direction:column;height:100%}\
.bar{display:flex;flex-wrap:wrap;gap:.25rem 1rem;align-items:center;padding:.4rem .8rem;background:#1d2433;color:#fff;\
font-size:.85rem}.bar a{color:#cfd8ff}.bar .end{margin-left:auto}iframe{flex:1;border:0;width:100%;background:#fff}.bl{display:inline-flex;gap:.5rem;\
align-items:center}.bl-link{background:none;border:0;padding:0;color:#cfd8ff;font:inherit;cursor:pointer;\
text-decoration:underline}.bl-shade{position:fixed;inset:0;background:rgba(10,14,25,.55);display:flex;align-items:\
center;justify-content:center;padding:1rem}.bl-box{background:#fff;color:#1d2433;border-radius:10px;padding:1.2rem;\
width:100%;max-width:24rem;max-height:90vh;overflow:auto}.bl-box h2{margin:0 0 .5rem;font-size:1.2rem}.bl-box h3{\
margin:1rem 0 .3rem;font-size:1rem}.bl-field{display:block;margin:.4rem 0;font-size:.9rem}.bl-field input{display:\
block;width:100%;box-sizing:border-box;margin-top:.2rem;padding:.45rem;font:inherit;border:1px solid #c4c9d6;\
border-radius:6px}.bl-btn{display:block;width:100%;margin:.5rem 0;padding:.55rem;font:inherit;color:#fff;background:\
#2448c8;border:0;border-radius:6px;cursor:pointer}.bl-btn:disabled{opacity:.6}.bl-err{color:#b3261e;min-height:1.2em;\
margin:.4rem 0}.bl-muted{color:#5b6475;font-size:.9rem;margin:.3rem 0}.bl-code{font:600 1.05rem ui-monospace,monospace;\
word-break:break-all;background:#f0f2f7;padding:.4rem;border-radius:6px;margin:.2rem 0 .6rem}.bl-more{margin-top:1rem}\
.bl-close{color:#2448c8;margin-top:.5rem}.bl-big{font:700 1.6rem ui-monospace,monospace;letter-spacing:.08em;\
text-align:center;margin:.6rem 0}.bl-qr{display:block;width:180px;height:180px;margin:.4rem auto}.bl-dev{display:flex;\
gap:.6rem;align-items:center;padding:.45rem 0;border-bottom:1px solid #e3e6ee}.bl-dev span:first-child{flex:1}\
.bl-danger{color:#b3261e}.bl-check{display:flex;gap:.45rem;align-items:center;margin:.3rem 0 .4rem;font-size:.9rem}.bl-choice .bl-btn{margin-top:.2rem}";

impl Node {
    /// Whether the app of `owner` may go to this request (docs/11 §4): always for callers on this PC and in the
    /// network's own ways; through the trusted proxy (the Internet) only in a network that forbids 18+ and for an
    /// owner with level ≥ 2.
    pub(crate) fn public_visible(&self, request: &Request, owner: &Id, now: i64) -> bool {
        !request.forwarded
            || (self.website_entrance(now)
                && self.with_core(|core| core.state.public_owner(owner, now)).unwrap_or(false))
    }

    /// Whether this node shows the network's websites to visitors from the Internet: a seal of level 3 (docs/11 §13).
    pub(crate) fn website_entrance(&self, now: i64) -> bool {
        let me = self.inner.identity.id();
        self.with_core(|core| core.state.level(me, now).is_some_and(|level| level >= 3)).unwrap_or(false)
    }

    /// Whether `path` is one of the public pages (only with the reader `public`).
    pub(crate) fn is_public_page(&self, path: &str) -> bool {
        self.inner.reader.access() == ReaderAccess::Public
            && (path == "/" || path == "/login.js" || path == "/status" || path.starts_with("/web/"))
    }

    /// `GET /` and `GET /web/<name>[/]` (see module docs).
    pub(crate) fn public_page(&self, request: &Request) -> Response {
        if request.method != Method::Get || self.network().is_none() {
            return page(404, "Nicht gefunden", "<main><h1>Nicht gefunden</h1></main>");
        }
        let now = self.now();
        if let Err(refused) = self.inner.guard.admit_read(request.peer, now) {
            return NodeError::from(refused).to_response();
        }
        // The status page is no website: every public node of the network shows it (docs/11 §15).
        if request.path == "/status" {
            return self.status_page(now);
        }
        if !self.website_entrance(now) {
            return page(
                404,
                "Keine Websites",
                "<main><h1>Hier gibt es keine Websites</h1><p class=\"muted\">Dieser Knoten ist nur für das \
                 Bridge-Protokoll erreichbar. Die Websites seines Netzes zeigen die Eingänge des Owners.</p></main>",
            );
        }
        if request.path == "/" {
            return self.start_page(now);
        }
        if request.path == "/login.js" {
            return Response::ok(LOGIN_JS.as_bytes().to_vec())
                .with_header("content-type", "text/javascript; charset=utf-8")
                .with_header("x-content-type-options", "nosniff")
                .with_header("cache-control", "no-cache");
        }
        let rest = request.path.strip_prefix("/web/").unwrap_or_default();
        match rest.split_once('/') {
            None if valid_web_name(rest) => {
                Response { status: 308, ..Response::ok(Vec::new()) }.with_header("location", format!("{rest}/"))
            }
            Some((name, "")) if valid_web_name(name) => self.frame_page(name, now),
            _ => not_found_page(),
        }
    }

    /// `GET /status` (docs/11 §15): what the network can do and whether its log is witnessed - nothing secret, no
    /// names of members, no addresses.
    fn status_page(&self, now: i64) -> Response {
        let me = self.inner.identity.id().clone();
        let content = self.with_core(|core| {
            let state = &core.state;
            let looks = |status: &str| match status {
                "green" => ("ok", "Bereit"),
                "yellow" => ("warn", "Geht, aber schwach"),
                _ => ("bad", "Fehlt"),
            };
            let rows: String = state
                .abilities(now)
                .iter()
                .map(|ability| {
                    let (class, text) = looks(ability.status());
                    format!(
                        "<tr><td>{}</td><td class=\"{class}\">{text}</td><td class=\"muted\">{} von {}</td></tr>",
                        escape(ability.name),
                        ability.have,
                        ability.green
                    )
                })
                .collect();
            let witnessed = core.best_witnessed().map(|witnessed| (witnessed.head.size(), witnessed.head.times().0));
            let log = match witnessed {
                Some((size, at)) => {
                    format!("{size} Einträge, zuletzt bezeugt {}", ago(now.saturating_sub(at)))
                }
                None => "noch nicht bezeugt".to_owned(),
            };
            let operator = state.manifest().logs.first().is_some_and(|id| id == &me);
            format!(
                "<main><h1>{}</h1><p class=\"muted\">Status des BridgeNetzes</p>\
                 <h2>Dieser Eingang</h2><p class=\"ok\">läuft{}</p>\
                 <h2>Transparenz-Log</h2><p>{log}</p>\
                 <h2>Was kann das Netz?</h2><table>{rows}</table></main>",
                escape(&state.manifest().name),
                if operator { " – Log-Führer" } else { "" },
            )
        });
        match content {
            Ok(content) => page(200, "Status", &content).with_header("cache-control", "no-cache"),
            Err(_) => page(503, "Status", "<main><h1>Status</h1><p>Der Knoten lädt das Log noch.</p></main>"),
        }
    }

    fn start_page(&self, now: i64) -> Response {
        let blocklists = self.blocklists();
        let content = self.with_core(|core| {
            let manifest = core.state.manifest();
            let names: Vec<String> = core
                .state
                .public_app_names(bridge_net::state::MAX_PUBLIC_NAMES, now)
                .iter()
                .filter(|name| !blocklists.blocks_resolved(name, now))
                .map(|name| {
                    let body = &name.info.name;
                    let description = if body.description.is_empty() {
                        String::new()
                    } else {
                        format!(" <span class=\"muted\">– {}</span>", escape(&body.description))
                    };
                    format!("<li><a href=\"web/{0}/\">{0}</a>{description}</li>", escape(&body.name))
                })
                .collect();
            let list = if names.is_empty() {
                "<p class=\"muted\">Noch keine öffentlichen Websites.</p>".to_owned()
            } else {
                format!("<ul>{}</ul>", names.concat())
            };
            format!(
                "<main><h1>{}</h1><p class=\"muted\">Ein öffentliches BridgeNet (Bridge 4).</p><h2>Websites</h2>{list}\
                 <footer>Problem melden: {} · <a href=\"status\">Status</a></footer></main>",
                escape(&manifest.name),
                contact_html(manifest.contact.as_deref())
            )
        });
        match content {
            Ok(content) => page(200, "Bridge 4", &content),
            Err(_) => not_found_page(),
        }
    }

    fn frame_page(&self, name: &str, now: i64) -> Response {
        let blocklists = self.blocklists();
        let found = self.with_core(|core| {
            let resolved = core.state.resolve_name(name, now).ok()?;
            let body = &resolved.info.name;
            let shown = body.kind == NameKind::App
                && resolved.category == Category::General
                && core.state.public_owner(&body.owner, now)
                && !blocklists.blocks_resolved(&resolved, now);
            let manifest = core.state.manifest();
            shown.then(|| {
                (
                    body.name.clone(),
                    body.target.clone(),
                    body.owner.clone(),
                    manifest.name.clone(),
                    manifest.contact.clone(),
                )
            })
        });
        let Ok(Some((name, app, owner, net, contact))) = found else { return not_found_page() };
        if self.app_blocked(&app, &owner, now) {
            return not_found_page();
        }
        let (name, net) = (escape(&name), escape(&net));
        let login = self.login_blocker(now).is_none();
        let (slot, script) = if login {
            (
                format!("<span id=\"bridge-login\" class=\"bl\" data-app=\"{app}\"></span> · "),
                "<script src=\"../../login.js\"></script>",
            )
        } else {
            (String::new(), "")
        };
        let content = format!(
            "<div class=\"frame\"><div class=\"bar\"><strong>{net}</strong><span>{name}</span><span class=\"end\">\
             {slot}<a href=\"../../app/{app}/\" target=\"_top\" rel=\"noreferrer\">Nur die Seite</a> · Problem melden: {}\
             </span></div><iframe src=\"../../app/{app}/\" sandbox=\"{FRAME_SANDBOX}\" referrerpolicy=\"no-referrer\" \
             title=\"{name}\"></iframe></div>{script}",
            contact_html(contact.as_deref())
        );
        let response = page(200, &format!("{name} – {net}"), &content);
        if !login {
            return response;
        }
        let mut response = response;
        response.headers.retain(|(header, _)| header != "content-security-policy");
        response
            .with_header("content-security-policy", LOGIN_CSP)
            .with_header("cross-origin-opener-policy", "same-origin")
    }
}

/// A name as it may stand in a `/web/` path: the name syntax's characters only (docs/08 §3) - lower case letters,
/// digits, `-` and one `.` before the network's short name; the state decides the rest.
fn valid_web_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_WEB_NAME
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn not_found_page() -> Response {
    page(404, "Nicht gefunden", "<main><h1>Nicht gefunden</h1><p>Diese Seite gibt es hier nicht (mehr).</p></main>")
}

/// A whole HTML page with the headers of the public pages. `title` must be escaped already.
fn page(status: u16, title: &str, content: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width,initial-scale=1\"><title>{title}</title><style>{STYLE}</style></head><body>\
         {content}</body></html>"
    );
    Response { status, ..Response::ok(html.into_bytes()) }
        .with_header("content-type", "text/html; charset=utf-8")
        .with_header("content-security-policy", PAGE_CSP)
        .with_header("x-frame-options", "DENY")
        .with_header("referrer-policy", "no-referrer")
}

/// "vor 12 s", "vor 5 min", "vor 3 h", "vor 2 Tagen".
fn ago(ms: i64) -> String {
    let seconds = ms.max(0) / 1000;
    match seconds {
        0..60 => format!("vor {seconds} s"),
        60..3600 => format!("vor {} min", seconds / 60),
        3600..86_400 => format!("vor {} h", seconds / 3600),
        _ => format!("vor {} Tagen", seconds / 86_400),
    }
}

/// HTML-escapes text (also quotes, so it is safe in attributes).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// The report contact as HTML: a `mailto:` link for a plain e-mail address, a link for an `https://` URL of safe
/// characters, else the escaped text.
fn contact_html(contact: Option<&str>) -> String {
    let Some(contact) = contact.map(str::trim).filter(|c| !c.is_empty()) else {
        return "<span class=\"muted\">kein Meldeweg angegeben</span>".to_owned();
    };
    let text = escape(contact);
    if plain_email(contact) {
        format!("<a href=\"mailto:{text}\" target=\"_top\">{text}</a>")
    } else if safe_https(contact) {
        format!("<a href=\"{text}\" target=\"_blank\" rel=\"noopener noreferrer\">{text}</a>")
    } else {
        text
    }
}

fn plain_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else { return false };
    let local_ok = !local.is_empty()
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'));
    let domain_ok = domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
    text.len() <= 200 && local_ok && domain_ok
}

fn safe_https(text: &str) -> bool {
    text.len() <= 200
        && text.strip_prefix("https://").is_some_and(|rest| {
            !rest.is_empty()
                && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~/?#[]@!$&()*+,;=%:".contains(&b))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_and_contacts() {
        assert_eq!(escape("<a href='x'>&\"</a>"), "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;");
        assert_eq!(escape("a\u{7}b"), "a b");
        assert!(contact_html(Some("meldungen@beispiel.de")).contains("href=\"mailto:meldungen@beispiel.de\""));
        assert!(contact_html(Some("https://beispiel.de/melden")).contains("href=\"https://beispiel.de/melden\""));
        for bad in ["javascript:alert(1)", "http://x.de", "a@b", "x\"@y.de", "https://x.de/\"onmouseover=", "<b>@x.de"]
        {
            let html = contact_html(Some(bad));
            assert!(!html.contains("href"), "{bad}: {html}");
            assert!(!html.contains('<') || html.starts_with("<span"), "{bad}: {html}");
        }
        assert!(contact_html(None).contains("kein Meldeweg"));
        assert!(contact_html(Some("  ")).contains("kein Meldeweg"));
    }

    #[test]
    fn web_names_and_page_headers() {
        assert!(valid_web_name("testseite") && valid_web_name("shop.testnetz") && valid_web_name("a-1"));
        for bad in ["", "Shop", "a/b", "a%2e", "..x/", "a b", &"a".repeat(65)] {
            assert!(!valid_web_name(bad), "{bad}");
        }
        let response = page(200, "T", "<main></main>");
        let header = |name: &str| response.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
        assert_eq!(header("content-security-policy").as_deref(), Some(PAGE_CSP));
        assert!(PAGE_CSP.contains("default-src 'none'") && !PAGE_CSP.contains("script"));
        assert_eq!(header("x-frame-options").as_deref(), Some("DENY"));
        assert!(!FRAME_SANDBOX.contains("allow-same-origin") && !FRAME_SANDBOX.contains("allow-top-navigation"));
    }
}
