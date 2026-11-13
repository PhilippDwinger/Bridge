//! Shared by the Bridge Login tests: a test authenticator (ES256) and a login node's entrance as a browser sees it.
#![allow(dead_code)]

use bridge_core::crypto::{es256_test_sign, sha256};
use bridge_core::encoding::b64;
use bridge_core::login::recovery_hash;
use bridge_node::ReaderAccess;
use bridge_tests::apps::get;
use bridge_tests::net::{TestNet, TestNode, eventually, test_config};
use serde_json::{Value, json};
use tokio::net::TcpListener;

pub fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// A test passkey (ES256).
pub struct Passkey {
    pub secret: [u8; 32],
    pub id: Vec<u8>,
    pub spki: Vec<u8>,
}

impl Passkey {
    pub fn new(seed: u8) -> Self {
        let secret = [seed; 32];
        let (spki, _) = es256_test_sign(&secret, b"");
        Self { secret, id: vec![seed; 16], spki }
    }

    pub fn credential(&self) -> Value {
        json!({"id": b64(&self.id), "alg": -7, "key": b64(&self.spki)})
    }

    pub fn sign(&self, auth: &[u8], client: &[u8]) -> String {
        let mut message = auth.to_vec();
        message.extend_from_slice(&sha256(client));
        b64(&es256_test_sign(&self.secret, &message).1)
    }
}

/// The entrance of a login node as a browser sees it.
#[derive(Clone)]
pub struct Entrance {
    pub url: String,
    pub rp_id: String,
    pub origin: String,
}

impl Entrance {
    pub fn auth_data(&self, counter: u32) -> Vec<u8> {
        let mut auth = sha256(self.rp_id.as_bytes()).to_vec();
        auth.push(0x05); // user present + verified
        auth.extend_from_slice(&counter.to_be_bytes());
        auth
    }

    pub fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        let answer = reqwest::Client::new()
            .post(format!("{}/v4/login/{path}", self.url))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(e)?;
        let status = answer.status().as_u16();
        let bytes = answer.bytes().await.map_err(e)?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
    }

    pub async fn info(&self) -> Result<Value, String> {
        let (status, _, body) = get(&format!("{}/v4/login/info", self.url)).await?;
        if status != 200 {
            return Err(format!("info: {status}"));
        }
        serde_json::from_slice(&body).map_err(e)
    }

    pub async fn challenge(&self) -> Result<String, String> {
        match self.post("challenge", &json!({})).await? {
            (200, answer) => Ok(answer["challenge"].as_str().unwrap_or_default().to_owned()),
            other => Err(format!("challenge: {other:?}")),
        }
    }

    /// A register request for `passkey` with recovery `code` (a fresh challenge unless given).
    pub async fn register_body(&self, name: &str, passkey: &Passkey, code: &[u8]) -> Result<Value, String> {
        let challenge = self.challenge().await?;
        Ok(json!({
            "name": name,
            "credential": passkey.credential(),
            "client_data": b64(&self.client_data("webauthn.create", &challenge)),
            "auth_data": b64(&self.auth_data(0)),
            "recovery": b64(&recovery_hash(code)),
        }))
    }

    pub async fn assert(&self, passkey: &Passkey, counter: u32) -> Result<(u16, Value), String> {
        let challenge = self.challenge().await?;
        let (client, auth) = (self.client_data("webauthn.get", &challenge), self.auth_data(counter));
        let body = json!({
            "credential_id": b64(&passkey.id),
            "client_data": b64(&client),
            "auth_data": b64(&auth),
            "signature": passkey.sign(&auth, &client),
        });
        self.post("assert", &body).await
    }

    pub async fn recover(
        &self,
        account: &str,
        code: &[u8],
        passkey: &Passkey,
        new_code: &[u8],
    ) -> Result<(u16, Value), String> {
        let challenge = self.challenge().await?;
        let body = json!({
            "account": account,
            "code": b64(code),
            "credential": passkey.credential(),
            "client_data": b64(&self.client_data("webauthn.create", &challenge)),
            "auth_data": b64(&self.auth_data(0)),
            "recovery": b64(&recovery_hash(new_code)),
        });
        self.post("recover", &body).await
    }
}

/// A node with the public address `https://<host>/bridge4/testnetz` (its relying party) besides its loopback
/// address, sealed `gateway,storage` at level 2 - a login node. `public`: with the public reader (frame pages) and
/// level 3 (a website entrance).
pub async fn login_node(net: &TestNet, host: &str, public: bool) -> Result<(TestNode, Entrance), String> {
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let mut config = test_config(dir.path(), Some(net.membership(&[])), &url);
    config.urls.push(format!("https://{host}/bridge4/testnetz"));
    if public {
        config.reader.access = ReaderAccess::Public;
        config.server.trusted_proxies = vec![[127, 0, 0, 1].into()];
    }
    let node = bridge_node::start(config, listener).await?;
    let node = TestNode { dir, node, url: url.clone() };
    net.synced(&node).await?;
    if public {
        // A website entrance needs level 3 (docs/11 §13).
        let services = bridge_node::admin::parse_services("gateway,storage")?;
        net.admin.seal(&node.url, &node.id(), 3, services).await?;
        bridge_tests::net::wait_for("node is a gateway", || node.status().gateway).await?;
    } else {
        net.seal_as(&node, "gateway,storage").await?;
    }
    let entrance = Entrance { url, rp_id: host.to_owned(), origin: format!("https://{host}") };
    eventually("login is on", || async {
        let info = entrance.info().await?;
        if info["enabled"] == json!(true) { Ok(()) } else { Err(info.to_string()) }
    })
    .await?;
    Ok((node, entrance))
}

pub fn code(seed: u8) -> Vec<u8> {
    vec![seed; 15]
}
