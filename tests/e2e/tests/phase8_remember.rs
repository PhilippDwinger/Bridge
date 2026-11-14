//! Phase 8, step 6 (docs/11 §16): "angemeldet bleiben". A ceremony with `remember` hands out an HttpOnly cookie for
//! the path of the entrance; `resume` trades it for a session and a new key (the old one is used up); logout, a
//! recovery (the device is out) and a foreign `Sec-Fetch-Site` end it.

mod login_common;

use bridge_core::encoding::b64;
use bridge_net::JoinMode;
use bridge_tests::net::TestNet;
use login_common::{Entrance, Passkey, code, e, login_node};
use serde_json::{Value, json};

type TestResult = Result<(), String>;

/// A POST with an optional `Cookie` and `Sec-Fetch-Site`; returns status, answer and `Set-Cookie`.
async fn post(
    entrance: &Entrance,
    path: &str,
    body: &Value,
    cookie: Option<&str>,
    site: Option<&str>,
) -> Result<(u16, Value, Option<String>), String> {
    let mut request = reqwest::Client::new()
        .post(format!("{}/v4/login/{path}", entrance.url))
        .header("content-type", "application/json")
        .body(body.to_string());
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    if let Some(site) = site {
        request = request.header("sec-fetch-site", site);
    }
    let answer = request.send().await.map_err(e)?;
    let status = answer.status().as_u16();
    let set = answer.headers().get("set-cookie").and_then(|value| value.to_str().ok()).map(str::to_owned);
    let cors = answer.headers().get("access-control-allow-origin").is_some();
    if cors {
        return Err(format!("{path}: an answer with a cookie must not allow other origins"));
    }
    let bytes = answer.bytes().await.map_err(e)?;
    Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null), set))
}

/// `bl_remember=<value>` of a `Set-Cookie`.
fn pair(set: &str) -> String {
    set.split(';').next().unwrap_or_default().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn staying_logged_in_with_an_http_only_cookie() -> TestResult {
    let net = TestNet::create(JoinMode::Invite).await?;
    let (_node, entrance) = login_node(&net, "a.tail1234.ts.net", false).await?;
    let passkey = Passkey::new(1);

    // Without `remember`: no cookie.
    let plain = entrance.register_body("Paddy", &passkey, &code(1)).await?;
    let (status, made, set) = post(&entrance, "register", &plain, None, None).await?;
    assert_eq!((status, set), (200, None), "{made}");
    // A login with `remember`: the cookie, scoped to this entrance's path, invisible to scripts.
    let challenge = entrance.challenge().await?;
    let (client, auth) = (entrance.client_data("webauthn.get", &challenge), entrance.auth_data(1));
    let body = json!({
        "credential_id": b64(&passkey.id), "client_data": b64(&client), "auth_data": b64(&auth),
        "signature": passkey.sign(&auth, &client), "remember": true,
    });
    let (status, _, set) = post(&entrance, "assert", &body, None, None).await?;
    let set = set.ok_or("no cookie")?;
    assert_eq!(status, 200);
    for part in ["bl_remember=", "Path=/bridge4/testnetz/", "Max-Age=2592000", "HttpOnly", "Secure", "SameSite=Strict"]
    {
        assert!(set.contains(part), "{part}: {set}");
    }
    let first = pair(&set);

    // Resume: a session and a new key; the old key is used up.
    let (status, resumed, set) = post(&entrance, "resume", &json!({}), Some(&first), Some("same-origin")).await?;
    assert_eq!((status, resumed["account"].clone()), (200, made["account"].clone()), "{resumed}");
    assert!(resumed["session"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(resumed["credential_id"], json!(b64(&passkey.id)));
    let second = pair(&set.ok_or("no new cookie")?);
    assert_ne!(second, first, "rotated");
    let (status, _, set) = post(&entrance, "resume", &json!({}), Some(&first), None).await?;
    assert_eq!(status, 401, "used up");
    assert!(set.is_some_and(|set| set.contains("Max-Age=0")), "cleared");
    // From another site (an app, a foreign page): refused; garbage cookies too.
    let (status, _, _) = post(&entrance, "resume", &json!({}), Some(&second), Some("cross-site")).await?;
    assert_eq!(status, 403);
    for bad in ["bl_remember=abc", "bl_remember=", "other=1"] {
        assert_eq!(post(&entrance, "resume", &json!({}), Some(bad), None).await?.0, 401, "{bad}");
    }

    // Logout ends it.
    let (_, _, set) = post(&entrance, "resume", &json!({}), Some(&second), None).await?;
    let third = pair(&set.ok_or("no cookie")?);
    let (status, _, set) = post(&entrance, "logout", &json!({}), Some(&third), None).await?;
    assert!(status == 200 && set.is_some_and(|set| set.contains("Max-Age=0")));
    assert_eq!(post(&entrance, "resume", &json!({}), Some(&third), None).await?.0, 401);

    // A recovery puts every other device out - and its remembered logins with it.
    let (_, _, set) = post(&entrance, "assert", &json!({}), None, None).await?; // (refused: nothing set)
    assert!(set.is_none());
    let challenge = entrance.challenge().await?;
    let (client, auth) = (entrance.client_data("webauthn.get", &challenge), entrance.auth_data(2));
    let body = json!({
        "credential_id": b64(&passkey.id), "client_data": b64(&client), "auth_data": b64(&auth),
        "signature": passkey.sign(&auth, &client), "remember": true,
    });
    let (_, _, set) = post(&entrance, "assert", &body, None, None).await?;
    let fourth = pair(&set.ok_or("no cookie")?);
    let account = made["account"].as_str().unwrap_or_default().to_owned();
    let (status, _) = entrance.recover(&account, &code(1), &Passkey::new(2), &code(2)).await?;
    assert_eq!(status, 200);
    assert_eq!(post(&entrance, "resume", &json!({}), Some(&fourth), None).await?.0, 401, "the device is out");
    Ok(())
}
