//! The JSON API of the UI (only reached through [`crate::http`], i.e. with the session, the right `Host` and - for
//! every `POST` - the right `Origin`). Bodies are strict JSON objects (at most 64 KiB). Errors are `{"error": text}`
//! in German.
//!
//! | Call | What |
//! |---|---|
//! | `GET /api/overview` | all nodes of this PC with live status (start page) |
//! | `GET /api/nodes/<id>/dashboard[?q=…]` | owner dashboard (or a member node's own view) |
//! | `GET /api/nodes/<id>/log[?lines=n]` | the end of a node's log |
//! | `GET /api/nodes/<id>/reports[?status=open\|done\|all]` | reports at an owner node |
//! | `POST /api/nodes/<id>/start` · `stop` · `settings` · `delete` | run and change nodes |
//! | `POST /api/nodes/<id>/invite` · `seal` · `unseal` · `ban` · `unban` | admin actions of an owner node |
//! | `POST /api/nodes/<id>/name-register` · `name-revoke` · `report-status` · `report-action` · `contact` | names, reports, Meldeweg (owner) |
//! | `POST /api/nodes/<id>/report` | report a name or ID of the node's network (member key of this PC) |
//! | `POST /api/nodes/<id>/public` · `public-web` · `public-off` | public through the gate (docs/11 §5) |
//! | `POST /api/nodes/<id>/login-on` | Bridge Login at the public owner node (docs/11 §9.2) |
//! | `POST /api/nodes/<id>/bridge3-add` · `/api/bridge3/settings` · `/api/bridge3/<id>/start\|stop\|delete`, `GET /api/bridge3/<id>/log` | Bridge 3 servers (docs/11 §8) |
//! | `GET /api/browser` · `POST /api/browser/resolve` · `/api/browser/search` | the Bridge-Browser |
//! | `POST /api/wizard/start` · `short` · `confirm` · `check` · `create` · `cancel` | assistant "Neues BridgeNet" |
//! | `POST /api/join/check` · `/api/join` | "Netz beitreten" |
//! | `POST /api/qr` · `/api/settings` · `/api/quit` | QR code, start with the system, end the app |

use bridge_core::json::parse_strict;
use bridge_net::JoinMode;
use hyper::Method;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::http::{Answer, Call, MAX_BODY_BYTES};
use crate::ops::{self, JoinRequest, Reach, SealRequest};
use crate::{App, browser, config, logfile, moderation, now_ms, qr};

/// Routes one API call.
pub async fn route(app: &App, call: &Call<'_>) -> Answer {
    let rest = call.path.strip_prefix("/api/").unwrap_or_default();
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() > 3 {
        return Answer::error(404, "Nicht gefunden");
    }
    if call.method == Method::GET {
        return match parts.as_slice() {
            ["overview"] => Answer::json(200, &ops::overview(app).await),
            ["update"] => Answer::json(200, &app.updater.status()),
            ["templates"] => Answer::json(200, &crate::templates::list()),
            ["browser"] => Answer::json(200, &browser::nodes(app).await),
            ["nodes", id, "dashboard"] => result(ops::dashboard(app, id, call.query).await),
            ["nodes", id, "log"] => log(app, id, call.query),
            ["bridge3", id, "log"] if config::check_bridge3_id(id).is_ok() => {
                log_of(app, &crate::bridge3::proc_id(id), call.query)
            }
            ["nodes", id, "reports"] if config::check_id(id).is_ok() => {
                result(moderation::reports(app, id, call.query).await)
            }
            _ => Answer::error(404, "Nicht gefunden"),
        };
    }
    let body = match body(call.body) {
        Ok(body) => body,
        Err(answer) => return answer,
    };
    match parts.as_slice() {
        ["nodes", id, action] => node_action(app, id, action, &body).await,
        ["bridge3", "settings"] => result(crate::bridge3::settings(app, &body).await),
        ["bridge3", id, action] if config::check_bridge3_id(id).is_ok() => match *action {
            "start" => result(crate::bridge3::start(app, id).await),
            "stop" => result(crate::bridge3::stop(app, id).await),
            "delete" => result(crate::bridge3::delete(app, id, text(&body, "confirm")).await),
            _ => Answer::error(404, "Nicht gefunden"),
        },
        ["wizard", step] => wizard(app, step, &body).await,
        ["browser", "resolve"] => result(browser::resolve(app, &body).await),
        ["browser", "search"] => result(browser::search(app, &body).await),
        ["join", "check"] => Answer::json(200, &ops::join_check(text(&body, "link")).await),
        ["join"] => result(join(app, &body).await),
        ["qr"] => match qr::svg(text(&body, "text")) {
            Ok(svg) => Answer::json(200, &json!({"svg": svg})),
            Err(error) => Answer::error(400, &error),
        },
        ["settings"] => match body.get("login_autostart").and_then(Value::as_bool) {
            Some(enabled) => result(ops::set_login_autostart(app, enabled).map(|()| json!({"ok": true}))),
            None => Answer::error(400, "login_autostart fehlt"),
        },
        ["startmenu"] => result(ops::set_startmenu(app).await),
        ["restore"] => result(crate::backup::restore(app, &body).await),
        ["update", "check"] => result(crate::update::check(app).await),
        ["update", "install"] => result(crate::update::install(app, false).await),
        ["update", "auto"] => match body.get("on").and_then(Value::as_bool) {
            Some(on) => result(crate::update::set_auto(app, on)),
            None => Answer::error(400, "on fehlt"),
        },
        ["quit"] => {
            app.quit.notify_waiters();
            app.quit.notify_one();
            Answer::json(200, &json!({"ok": true}))
        }
        _ => Answer::error(404, "Nicht gefunden"),
    }
}

fn result(result: Result<Value, String>) -> Answer {
    match result {
        Ok(value) => Answer::json(200, &value),
        Err(error) => Answer::error(400, &error),
    }
}

/// The body as a strict JSON object (empty body = empty object).
fn body(bytes: &[u8]) -> Result<Map<String, Value>, Answer> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Map::new());
    }
    match parse_strict(bytes, MAX_BODY_BYTES) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(Answer::error(400, "Ungültiges JSON")),
    }
}

fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or_default()
}

fn number(body: &Map<String, Value>, name: &str, default: u32) -> Result<u32, String> {
    match body.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or(format!("{name}: eine Zahl")),
    }
}

fn log(app: &App, id: &str, query: &str) -> Answer {
    if config::check_id(id).is_err() {
        return Answer::error(404, "Nicht gefunden");
    }
    log_of(app, id, query)
}

/// The end of a process log (`id`: a node ID, or a Bridge 3 server's `b3-<id>` - both checked by the caller).
fn log_of(app: &App, id: &str, query: &str) -> Answer {
    let lines = ops::query_value(query, "lines").parse::<usize>().unwrap_or(200).clamp(1, 1000);
    Answer::json(200, &json!({"lines": logfile::tail(&app.node_log(id), lines)}))
}

async fn node_action(app: &App, id: &str, action: &str, body: &Map<String, Value>) -> Answer {
    if config::check_id(id).is_err() {
        return Answer::error(404, "Nicht gefunden");
    }
    match action {
        "start" => {
            let entry = app.config.lock().await.node(id).cloned();
            match entry {
                Some(entry) => {
                    app.start_node(&entry);
                    Answer::json(200, &json!({"ok": true}))
                }
                None => Answer::error(404, "Diesen Knoten gibt es nicht (mehr)."),
            }
        }
        "stop" => {
            app.supervisor.stop(id).await;
            Answer::json(200, &json!({"ok": true}))
        }
        "settings" => result(ops::settings(app, id, body).await),
        "backup" => result(crate::backup::backup_now(app, id, true).await),
        "delete" => result(ops::delete(app, id, text(body, "confirm")).await),
        "invite" => match (number(body, "uses", 5), number(body, "days", 30)) {
            (Ok(uses), Ok(days)) => result(ops::invite(app, id, uses, days).await),
            (Err(error), _) | (_, Err(error)) => Answer::error(400, &error),
        },
        "seal" => result(seal(app, id, body).await),
        "unseal" => result(ops::unseal(app, id, text(body, "node")).await),
        "ban" => match number(body, "days", 30) {
            Ok(days) => result(ops::ban(app, id, text(body, "subject"), days, text(body, "reason")).await),
            Err(error) => Answer::error(400, &error),
        },
        "unban" => result(ops::unban(app, id, text(body, "subject")).await),
        "report" => result(browser::report(app, id, body).await),
        "name-register" => result(moderation::register_name(app, id, body).await),
        "name-revoke" => result(moderation::revoke_name(app, id, body).await),
        "report-status" => result(moderation::report_status(app, id, body).await),
        "report-action" => result(moderation::report_action(app, id, body).await),
        "contact" => result(moderation::set_contact(app, id, body).await),
        "public" => match optional_port(body) {
            Ok(port) => result(crate::public::make_public(app, id, port).await),
            Err(error) => Answer::error(400, &error),
        },
        "public-web" => match body.get("on").and_then(Value::as_bool) {
            Some(on) => result(crate::public::set_web(app, id, on).await),
            None => Answer::error(400, "on: true oder false"),
        },
        "public-off" => result(crate::public::make_private(app, id).await),
        "login-on" => result(crate::public::login_on(app, id).await),
        "bridge3-add" => result(crate::bridge3::add(app, id, body).await),
        "site-check" => result(crate::sites::check(app, id, body).await),
        "site-publish" => result(crate::sites::publish(app, id, body).await),
        "site-delete" => result(crate::sites::delete(app, id, body).await),
        "template-publish" => result(crate::templates::publish(app, id, body).await),
        "template-load" => result(crate::templates::load(app, id, body).await),
        "site-entries" => result(crate::templates::entries(app, id, body).await),
        "site-entry-remove" => result(crate::templates::remove_entry(app, id, body).await),
        _ => Answer::error(404, "Nicht gefunden"),
    }
}

/// `funnel_port` of a body: absent or `null` → none, else 443, 8443 or 10000.
fn optional_port(body: &Map<String, Value>) -> Result<Option<u16>, String> {
    match body.get("funnel_port") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| config::FUNNEL_PORTS.contains(port))
            .map(Some)
            .ok_or_else(|| "Funnel-Port: 443, 8443 oder 10000".to_owned()),
    }
}

async fn seal(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let level = u8::try_from(number(body, "level", 2)?).map_err(|_| "Stufe 1-3")?;
    let services = ops::parse_services(body.get("services").and_then(Value::as_array).map_or(&[][..], Vec::as_slice))?;
    let optional = |name: &str| body.get(name).and_then(Value::as_str).map(str::to_owned);
    let request = SealRequest {
        confirm: text(body, "confirm").to_owned(),
        local: optional("local"),
        ausweis: optional("ausweis"),
        level,
        services,
    };
    ops::seal(app, id, request).await
}

async fn join(app: &App, body: &Map<String, Value>) -> Result<Value, String> {
    let flag = |name: &str| body.get(name).and_then(Value::as_bool).unwrap_or(false);
    let request = JoinRequest {
        link: text(body, "link").to_owned(),
        name: text(body, "name").to_owned(),
        reach: Reach::from_json(body)?,
        offer_gateway: flag("offer_gateway"),
        host_apps: flag("host_apps"),
        autostart_login: flag("autostart_login"),
    };
    ops::join(app, request).await
}

/// The assistant's steps.
async fn wizard(app: &App, step: &str, body: &Map<String, Value>) -> Answer {
    let now = now_ms();
    let id = text(body, "wizard");
    match step {
        "short" => {
            let name = text(body, "name");
            let name: String = name.chars().take(config::MAX_NAME_CHARS).collect();
            Answer::json(200, &json!({"short": bridge_node::admin::derive_short(&name)}))
        }
        "start" => {
            let name = text(body, "name").trim().to_owned();
            if let Err(error) = config::check_name(&name, "Name des Netzes") {
                return Answer::field_error(400, "name", &error);
            }
            let mode = match text(body, "template") {
                "open" => JoinMode::Open,
                "invite" => JoinMode::Invite,
                "closed" => JoinMode::Closed,
                _ => return Answer::error(400, "Art: open, invite oder closed"),
            };
            // The operator's rules first (docs/08 §2) - no words are made for a network that could not be created.
            let options = match crate::wizard::net_options(
                &name,
                text(body, "contact"),
                text(body, "short"),
                text(body, "adult"),
            ) {
                Ok(options) => options,
                Err((field, error)) => return Answer::field_error(400, field, &error),
            };
            let (id, words, quiz) = app.wizards.begin(name, mode, options, now);
            match words_answer(&id, &words, quiz) {
                Ok(bytes) => Answer::secret_json(200, bytes),
                Err(error) => {
                    app.wizards.cancel(&id);
                    Answer::error(500, &error)
                }
            }
        }
        "confirm" => {
            let answers: Vec<(usize, String)> = body
                .get("answers")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .take(8)
                        .filter_map(|item| {
                            let position = item.get("position").and_then(Value::as_u64)?;
                            let word = item.get("word").and_then(Value::as_str)?;
                            (word.len() <= 32).then(|| (usize::try_from(position).unwrap_or(0), word.to_owned()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let written = body.get("written").and_then(Value::as_bool).unwrap_or(false);
            match app.wizards.confirm(id, &answers, written, now) {
                Ok(()) => Answer::json(200, &json!({"ok": true})),
                Err(error) => Answer::error(400, &error),
            }
        }
        "check" => {
            let reach = match Reach::from_json(body) {
                Ok(reach) => reach,
                Err(error) => return Answer::json(200, &json!({"ok": false, "errors": {"listen_port": error}})),
            };
            let config = app.config.lock().await;
            let errors: Map<String, Value> = reach
                .check(&config, None, false)
                .into_iter()
                .map(|(field, error)| (field.to_owned(), json!(error)))
                .collect();
            Answer::json(200, &json!({"ok": errors.is_empty(), "errors": errors}))
        }
        "create" => {
            let reach = match Reach::from_json(body) {
                Ok(reach) => reach,
                Err(error) => return Answer::error(400, &error),
            };
            let uses = match number(body, "uses", 5) {
                Ok(uses) if (1..=1000).contains(&uses) => uses,
                _ => return Answer::error(400, "Nutzungen: 1-1000"),
            };
            let wizard = match app.wizards.take(id, now) {
                Ok(wizard) => wizard,
                Err(error) => return Answer::error(400, &error),
            };
            match ops::create_net(app, &wizard, &reach, uses).await {
                Ok(value) => Answer::json(200, &value),
                Err(error) => {
                    // Nothing created (e.g. a port taken meanwhile): keep the words for another try.
                    if error.retry {
                        app.wizards.put_back(id.to_owned(), wizard);
                    }
                    Answer::error(400, &error.message)
                }
            }
        }
        "cancel" => {
            app.wizards.cancel(id);
            Answer::json(200, &json!({"ok": true}))
        }
        _ => Answer::error(404, "Nicht gefunden"),
    }
}

/// `{"wizard":…,"quiz":[…],"words":[…]}` built by hand into a buffer that is wiped afterwards (no copies of the
/// words in `serde_json` values). BIP-39 English words are lowercase letters only - anything else is refused.
fn words_answer(id: &str, words: &str, quiz: [usize; 3]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    out.extend_from_slice(
        format!("{{\"wizard\":\"{id}\",\"quiz\":[{},{},{}],\"words\":[", quiz[0], quiz[1], quiz[2]).as_bytes(),
    );
    for (index, word) in words.split(' ').enumerate() {
        if word.is_empty() || !word.bytes().all(|byte| byte.is_ascii_lowercase()) {
            return Err("interner Fehler: unerwartetes Wort".into());
        }
        if index > 0 {
            out.push(b',');
        }
        out.push(b'"');
        out.extend_from_slice(word.as_bytes());
        out.push(b'"');
    }
    out.extend_from_slice(b"]}");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_answer_is_valid_json() -> Result<(), String> {
        let words = "abandon ability able about above absent absorb abstract absurd abuse access accident account \
                     accuse achieve acid acoustic acquire across act action actor actress actual";
        let bytes = words_answer("abc", words, [1, 5, 24])?;
        let value = parse_strict(&bytes, 4096).map_err(|e| e.to_string())?;
        assert_eq!(value["words"].as_array().map(Vec::len), Some(24));
        assert_eq!(value["quiz"], json!([1, 5, 24]));
        assert!(words_answer("abc", "ab\"c", [1, 2, 3]).is_err(), "never escapes into the JSON");
        assert!(words_answer("abc", "a  b", [1, 2, 3]).is_err());
        Ok(())
    }

    #[test]
    fn bodies() {
        assert!(body(b"").is_ok_and(|object| object.is_empty()));
        assert!(body(b"{\"a\":1}").is_ok());
        assert!(body(b"[1]").is_err());
        assert!(body(b"{\"a\":1,\"a\":2}").is_err(), "strict: duplicate keys");
        let map: Map<String, Value> = json!({"uses": 3, "bad": "x"}).as_object().cloned().unwrap_or_default();
        assert_eq!(number(&map, "uses", 1), Ok(3));
        assert_eq!(number(&map, "missing", 7), Ok(7));
        assert!(number(&map, "bad", 1).is_err());
    }
}
