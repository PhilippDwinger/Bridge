//! Test vectors for the SDKs in other languages (docs/10 §2.2, ADR 0021): made by the Rust core, **deterministic**
//! (fixed secrets, a fixed random source), compared with `sdk/vectors/vectors.json`. Any change of a format shows up
//! here first. `BRIDGE_WRITE_VECTORS=1 cargo test -p bridge-tests --test sdk_vectors` writes the file anew.

use std::collections::BTreeSet;

use bridge_core::crypto::sha256;
use bridge_core::encoding::{b64, base32};
use bridge_core::json::{canonical, parse_strict};
use bridge_core::{
    Address, Agent, Content, ContentType, Draft, Envelope, Id, Identity, JoinLink, KeyCard, Kind, Puzzle, Role, Scope,
    SignedRequest, Statement,
};
use bridge_net::{Body, Federation};
use rand_core::{CryptoRng, RngCore};
use serde_json::{Value, json};

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// A deterministic random source for vectors only: SHA-256(seed ‖ counter) blocks.
struct VectorRng {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

impl VectorRng {
    fn new(label: &str) -> Self {
        Self { seed: sha256(label.as_bytes()), counter: 0, buffer: Vec::new() }
    }
}

impl RngCore for VectorRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.buffer.is_empty() {
                let mut block = self.seed.to_vec();
                block.extend_from_slice(&self.counter.to_be_bytes());
                self.counter += 1;
                self.buffer = sha256(&block).to_vec();
            }
            *byte = self.buffer.remove(0);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for VectorRng {}

const T0: i64 = 1_794_200_000_000;
const HOUR: i64 = 3_600_000;

fn identity(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32], &[seed.wrapping_add(100); 32])
}

fn text(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(e)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The 14 encodings of the 8 Ed25519 points of small order (7 values, sign bit clear and set) - every SDK refuses
/// them as public keys.
fn weak_keys() -> Vec<[u8; 32]> {
    let mut values: Vec<[u8; 32]> = Vec::new();
    let mut zero = [0u8; 32];
    values.push(zero);
    zero[0] = 1;
    values.push(zero);
    values.push([
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf,
        0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
    ]);
    values.push([
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20,
        0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    ]);
    for low in [0xec, 0xed, 0xee] {
        let mut value = [0xffu8; 32];
        value[0] = low;
        value[31] = 0x7f;
        values.push(value);
    }
    let mut all = Vec::new();
    for value in values {
        all.push(value);
        let mut signed = value;
        signed[31] |= 0x80;
        all.push(signed);
    }
    all
}

/// `S + L` (little endian) - the same signature in a non-canonical form, refused by strict verification.
fn plus_l(signature: &[u8]) -> Vec<u8> {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut out = signature.to_vec();
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(out[32 + index]) + u16::from(L[index]) + carry;
        out[32 + index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

fn json_vectors() -> Result<Value, String> {
    let valid = [
        r#"{"b":2,"a":1,"c":{"z":null,"y":[true,false]}}"#,
        r#"  { "v" : 4 , "t" : "key" }  "#,
        r#"{"€":1,"$":2,"😀":3,"ﬀ":4,"\u0080":5}"#,
        r#"["\u0000\u001f\b\f\n\r\t\"\\/", "\u007f é", "😀"]"#,
        r#"[0,1,-1,9007199254740991,-9007199254740991]"#,
        r#""ä日本😀""#,
        r#"{"empty":{},"list":[]}"#,
        r#"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"#,
    ];
    let invalid = [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1.5}"#,
        r#"[1e3]"#,
        r#"[1.0]"#,
        r#"[9007199254740992]"#,
        r#"[-9007199254740992]"#,
        r#"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"#,
        r#"{"a":1} x"#,
        r#"["\x"]"#,
        r#"["\ud800"]"#,
        r#"[NaN]"#,
        r#"[Infinity]"#,
        r#"{a:1}"#,
        r#"[1,]"#,
        r#"[01]"#,
        r#"[-0]"#,
        "[\"a\u{1}\"]",
        "",
        r#"'a'"#,
    ];
    let mut canonical_list = Vec::new();
    for input in valid {
        let value = parse_strict(input.as_bytes(), 1 << 20).map_err(|error| format!("{input}: {error}"))?;
        canonical_list.push(json!({"in": input, "out": text(&canonical(&value).map_err(e)?)?}));
    }
    for input in invalid {
        if parse_strict(input.as_bytes(), 1 << 20).is_ok() {
            return Err(format!("the core takes {input:?}"));
        }
    }
    // Bytes that are not UTF-8: refused (the SDK gets bytes).
    if parse_strict(b"[\"\xff\"]", 100).is_ok() {
        return Err("not UTF-8 taken".into());
    }
    Ok(json!({"canonical": canonical_list, "invalid": invalid, "invalid_bytes_hex": [hex(b"[\"\xff\"]")]}))
}

fn encoding_vectors() -> Value {
    let base32_cases: Vec<Value> = ["", "f", "fo", "foo", "foob", "fooba", "foobar"]
        .iter()
        .map(|input| json!({"hex": hex(input.as_bytes()), "b32": base32(input.as_bytes())}))
        .collect();
    let b64_cases: Vec<Value> = [&b""[..], b"\x00", b"\x00\x01", b"\xfb\xff\xbf", b"hello world!"]
        .iter()
        .map(|bytes| json!({"hex": hex(bytes), "b64": b64(bytes)}))
        .collect();
    json!({
        "base32": base32_cases,
        "b64": b64_cases,
        // Padding, other alphabets, trailing bits that are not zero, whitespace.
        "b64_invalid": ["AA==", "AB", "AAA=", "+/8", "A", "AAAA AAAA", "AAAAA"],
    })
}

fn identity_vectors() -> Result<Value, String> {
    let mut list = Vec::new();
    for (seed, role, name, iat) in
        [(1u8, Role::Client, Some("Spiel A"), T0), (2, Role::Client, None, T0 + 1), (3, Role::Admin, None, T0)]
    {
        let identity = identity(seed);
        let card = identity.key_card(role, name, iat).map_err(e)?;
        let (sign, receive) = identity.secret_bytes();
        list.push(json!({
            "sign_secret": b64(sign.as_slice()),
            "box_secret": b64(receive.as_slice()),
            "sign_public": b64(&identity.sign_public()),
            "box_public": b64(&identity.receive_public()),
            "id": identity.id().as_str(),
            "role": role.as_str(),
            "name": name,
            "iat": iat,
            "card": text(&card.to_bytes().map_err(e)?)?,
        }));
    }
    // A node card with addresses and a TLS pin.
    let node = identity(4);
    let urls = vec!["https://pc.tail91b057.ts.net:8443/n1".to_owned(), "http://192.168.1.20:7700".to_owned()];
    let card = node.key_card_with(Role::Node, Some("Knoten"), &urls, Some(sha256(b"certificate")), T0).map_err(e)?;
    let (sign, receive) = node.secret_bytes();
    list.push(json!({
        "sign_secret": b64(sign.as_slice()),
        "box_secret": b64(receive.as_slice()),
        "sign_public": b64(&node.sign_public()),
        "box_public": b64(&node.receive_public()),
        "id": node.id().as_str(),
        "role": "node",
        "name": "Knoten",
        "iat": T0,
        "urls": urls,
        "tls": b64(&sha256(b"certificate")),
        "card": text(&card.to_bytes().map_err(e)?)?,
    }));
    // Cards every SDK refuses.
    let good = identity(1).key_card(Role::Client, Some("Spiel A"), T0).map_err(e)?.to_value();
    let other = identity(2);
    let mut bad = Vec::new();
    let mut changed = good.clone();
    changed["name"] = json!("Fake");
    bad.push(json!({"why": "name changed after signing", "card": changed.to_string()}));
    let mut changed = good.clone();
    changed["sign"] = json!(b64(&other.sign_public()));
    bad.push(json!({"why": "another signing key (id no longer fits)", "card": changed.to_string()}));
    let mut changed = good.clone();
    changed["role"] = json!("god");
    bad.push(json!({"why": "unknown role", "card": changed.to_string()}));
    let mut changed = good.clone();
    changed["v"] = json!(3);
    bad.push(json!({"why": "wrong version", "card": changed.to_string()}));
    let mut changed = good.clone();
    changed["urls"] = json!(["https://a.example"]);
    bad.push(json!({"why": "urls on a client card", "card": changed.to_string()}));
    for item in &bad {
        let card = item["card"].as_str().unwrap_or_default();
        if KeyCard::parse(card.as_bytes()).is_ok() {
            return Err(format!("core takes {item}"));
        }
    }
    Ok(json!({"valid": list, "invalid": bad}))
}

fn signature_vectors() -> Result<Value, String> {
    // A valid statement signature, then the same with S + L: refused.
    let net = identity(9).id().clone();
    let signer = identity(1);
    let draft = Draft { kind: "seal", net: &net, iat: T0, exp: T0 + HOUR, body: json!({"x": 1}) };
    let statement = Statement::sign(&draft, &signer).map_err(e)?;
    let signature = bridge_core::encoding::b64_var(statement.to_value()["sig"].as_str().unwrap_or_default(), "sig", 64)
        .map_err(e)?;
    let mut malleable = statement.to_value();
    malleable["sig"] = json!(b64(&plus_l(&signature)));
    let card = signer.key_card(Role::Admin, None, T0).map_err(e)?;
    if Statement::from_value(malleable.clone()).map_err(e)?.verify(&[&card], 1).is_ok() {
        return Err("core takes S + L".into());
    }
    // The identity point as key with R = identity, S = 0 verifies under plain RFC 8032 for every message - refused.
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1;
    let mut weak_signature = identity_point.to_vec();
    weak_signature.extend_from_slice(&[0u8; 32]);
    Ok(json!({
        "weak_keys": weak_keys().iter().map(|key| b64(key)).collect::<Vec<_>>(),
        "weak_signature": {
            "public": b64(&identity_point),
            "domain": "key",
            "message": "{}",
            "sig": b64(&weak_signature),
        },
        "malleable": {"statement": text(&canonical(&malleable).map_err(e)?)?, "signer_card": text(&card.to_bytes().map_err(e)?)?},
    }))
}

fn statement_vectors() -> Result<Value, String> {
    let net = identity(9).id().clone();
    let (alice, bob, carol) = (identity(1), identity(2), identity(3));
    let body = json!({"subject": identity(5).id().as_str(), "level": 2, "services": ["gateway"], "note": "Grüße 😀"});
    let draft = Draft { kind: "seal", net: &net, iat: T0, exp: T0 + 30 * 24 * HOUR, body: body.clone() };
    let single = Statement::sign(&draft, &alice).map_err(e)?;
    let multi = Statement::sign_multi(&draft, &[&carol, &alice, &bob]).map_err(e)?;
    let one = json!({
        "signers": [1],
        "kind": "seal",
        "net": net.as_str(),
        "iat": T0,
        "exp": T0 + 30 * 24 * HOUR,
        "body": text(&canonical(&body).map_err(e)?)?,
        "statement": text(statement_bytes(&single))?,
        "hash": single.hash(),
    });
    let several = json!({
        "signers": [1, 2, 3],
        "kind": "seal",
        "net": net.as_str(),
        "iat": T0,
        "exp": T0 + 30 * 24 * HOUR,
        "body": text(&canonical(&body).map_err(e)?)?,
        "statement": text(statement_bytes(&multi))?,
        "hash": multi.hash(),
    });
    // Forms every SDK refuses.
    let mut bad = Vec::new();
    let mut value = multi.to_value();
    if let Some(list) = value["sigs"].as_array_mut() {
        list.reverse();
    }
    bad.push(json!({"why": "sigs not ascending", "statement": value.to_string()}));
    let mut value = single.to_value();
    value["t"] = json!("env");
    bad.push(json!({"why": "reserved kind", "statement": value.to_string()}));
    let mut value = single.to_value();
    value["exp"] = json!(T0);
    bad.push(json!({"why": "exp not after iat", "statement": value.to_string()}));
    let mut value = single.to_value();
    value["sigs"] = json!([]);
    bad.push(json!({"why": "sig and sigs", "statement": value.to_string()}));
    for item in &bad {
        if Statement::parse(item["statement"].as_str().unwrap_or_default().as_bytes()).is_ok() {
            return Err(format!("core takes {item}"));
        }
    }
    Ok(json!({"valid": [one, several], "invalid": bad}))
}

fn statement_bytes(statement: &Statement) -> &[u8] {
    statement.canonical_bytes()
}

fn request_vectors() -> Result<Value, String> {
    let caller = identity(1);
    let node = identity(4).id().clone();
    let mut rng = VectorRng::new("requests");
    let body = json!({"acks": [{"from": identity(2).id().as_str(), "id": b64(&[7u8; 16])}]});
    let request = SignedRequest::sign(&caller, &node, "ack", body.clone(), T0, &mut rng).map_err(e)?;
    let value = request.to_value();
    let mut tampered = value.clone();
    tampered["op"] = json!("login");
    Ok(json!({
        "signer": 1,
        "aud": node.as_str(),
        "op": "ack",
        "iat": T0,
        "body": text(&canonical(&body).map_err(e)?)?,
        "nonce": value["n"],
        "request": text(&canonical(&value).map_err(e)?)?,
        "tampered": text(&canonical(&tampered).map_err(e)?)?,
    }))
}

fn content_vectors() -> Result<Value, String> {
    let card = identity(1).key_card(Role::Client, Some("Spiel A"), T0).map_err(e)?;
    let mut with_all = Content::data(ContentType::Task, "application/json", br#"{"prompt":"Hallo"}"#.to_vec());
    with_all.reply = Some([9u8; 16]);
    with_all.card = Some(card);
    let mut list = Vec::new();
    for (label, content) in [
        ("text", Content::text(ContentType::Direct, "Hallo Welt äöü 😀")),
        ("data", Content::data(ContentType::Event, "application/octet-stream", vec![0, 1, 2, 255])),
        ("task with reply and card", with_all),
    ] {
        list.push(json!({"label": label, "content": text(&content.to_bytes().map_err(e)?)?}));
    }
    let invalid = [
        r#"{"v":4,"type":"direct","ctype":"text/plain"}"#,
        r#"{"v":4,"type":"direct","ctype":"text/plain","body":"a","data":"AA"}"#,
        r#"{"v":4,"type":"nope","ctype":"text/plain","body":"a"}"#,
        r#"{"v":4,"type":"direct","ctype":"text plain","body":"a"}"#,
        r#"{"v":3,"type":"direct","ctype":"text/plain","body":"a"}"#,
    ];
    for item in invalid {
        if Content::parse(item.as_bytes()).is_ok() {
            return Err(format!("core takes {item}"));
        }
    }
    Ok(json!({"valid": list, "invalid": invalid}))
}

fn envelope_vectors() -> Result<Value, String> {
    let (alice, bob) = (identity(1), identity(2));
    let net = identity(9).id().clone();
    let other_net = identity(8).id().clone();
    let alice_card = alice.key_card(Role::Client, None, T0).map_err(e)?;
    let bob_card = bob.key_card(Role::Client, None, T0).map_err(e)?;
    let content = Content::text(ContentType::Direct, "Hallo Bob – geheim 😀").to_bytes().map_err(e)?;
    let address = Address { net: &net, to: &bob_card, kind: Kind::Msg, iat: T0, ttl: 600 };
    let mut rng = VectorRng::new("envelopes");
    let envelope = Envelope::seal(&alice, &address, &content, &mut rng).map_err(e)?;
    let to_net = Envelope::seal_for_net(&alice, &address, &other_net, &content, &mut rng).map_err(e)?;
    let mut bad = Vec::new();
    // Changed ciphertext (signature breaks).
    let mut value = envelope.to_value_for_tests();
    let ct = value["ct"].as_str().unwrap_or_default().to_owned();
    let flipped = match ct.strip_prefix('A') {
        Some(rest) => format!("B{rest}"),
        None => format!("A{}", ct.get(1..).unwrap_or_default()),
    };
    value["ct"] = json!(flipped);
    bad.push(json!({"why": "ciphertext changed", "envelope": value.to_string(), "fails": "signature"}));
    // The sender changes the kind and signs again: the AEAD (header in the AAD) breaks.
    let mut value = envelope.to_value_for_tests();
    value["kind"] = json!("evt");
    if let Some(object) = value.as_object_mut() {
        object.remove("sig");
    }
    let resigned = resign(&alice, &value)?;
    bad.push(json!({"why": "kind changed and signed again", "envelope": resigned.to_string(), "fails": "open"}));
    // dnet removed: signature breaks.
    let mut value = to_net.to_value_for_tests();
    if let Some(object) = value.as_object_mut() {
        object.remove("dnet");
    }
    bad.push(json!({"why": "dnet removed", "envelope": value.to_string(), "fails": "signature"}));
    for item in &bad {
        let parsed = Envelope::parse(item["envelope"].as_str().unwrap_or_default().as_bytes()).map_err(e)?;
        if parsed.open(&bob, &alice_card).is_ok() {
            return Err(format!("core opens {item}"));
        }
    }
    Ok(json!({
        "sender": 1,
        "recipient": 2,
        "net": net.as_str(),
        "now": T0 + 1000,
        "plain": text(&envelope.to_bytes().map_err(e)?)?,
        "to_net": {"envelope": text(&to_net.to_bytes().map_err(e)?)?, "dnet": other_net.as_str()},
        "plaintext": text(&content)?,
        "invalid": bad,
    }))
}

/// Signs an envelope value (without `sig`) as `sender` (domain `env`) - only to build a vector the AEAD must refuse.
fn resign(sender: &Identity, value: &Value) -> Result<Value, String> {
    let bytes = canonical(value).map_err(e)?;
    let signature = bridge_core::crypto::sign_for_vectors(sender, "env", &bytes);
    let mut out = value.clone();
    out["sig"] = json!(b64(&signature));
    Ok(out)
}

fn pow_vectors() -> Result<Value, String> {
    let node = identity(4);
    let card = node.key_card(Role::Node, None, T0).map_err(e)?;
    let mut rng = VectorRng::new("pow");
    let puzzle = Puzzle::issue(&node, 10, T0, &mut rng).map_err(e)?;
    let solution = puzzle.solve(1 << 24).ok_or("no solution")?;
    puzzle.check_solution(&solution, T0 + 1).map_err(e)?;
    Ok(json!({
        "puzzle": text(&canonical(&puzzle.to_value()).map_err(e)?)?,
        "node_card": text(&card.to_bytes().map_err(e)?)?,
        "solution": b64(&solution),
        "bits": 10,
    }))
}

fn link_vectors() -> Result<Value, String> {
    let net = identity(9).id().clone();
    let node = identity(4).id().clone();
    let pin = sha256(b"certificate");
    let full = JoinLink {
        net: net.clone(),
        gateway: "https://pc.tail91b057.ts.net:8443/n1".into(),
        code: Some("Abc-123".into()),
        node: Some(node.clone()),
        tls: Some(pin),
    };
    let plain = format!("bridge4://join?net={net}&gw=http://127.0.0.1:7400&future=1");
    let mut valid = Vec::new();
    for link in [full.to_link(), plain] {
        let parsed = JoinLink::parse(&link).map_err(e)?;
        valid.push(json!({
            "link": link,
            "net": parsed.net.as_str(),
            "gateway": parsed.gateway,
            "code": parsed.code,
            "node": parsed.node.as_ref().map(Id::as_str),
            "tls": parsed.tls.map(|tls| b64(&tls)),
        }));
    }
    let good = format!("net={net}&gw=https%3A%2F%2Fa.example");
    let invalid = vec![
        format!("bridge4://join?{good}&net={net}"),
        "bridge4://join?gw=https%3A%2F%2Fa.example".to_owned(),
        format!("bridge4://join?net={net}"),
        "bridge4://join?net=XYZ&gw=https%3A%2F%2Fa.example".to_owned(),
        format!("bridge4://join?net={net}&gw=ftp%3A%2F%2Fa"),
        format!("bridge4://join?{good}&code=a b"),
        format!("bridge4://join?{good}&code=abc"),
        format!("bridge4://join?{good}&code=%zz"),
        format!("bridge4://join?{good}{}", "&x=1".repeat(10)),
        format!("bridge4://join?{good}&tls={}", b64(&pin)),
        format!("bridge4://join?{good}&node={net}"),
        format!("https://join?{good}"),
        format!("bridge4://join?net={net}&gw=https%3A%2F%2Fa.example%2F..%2Fx"),
    ];
    for link in &invalid {
        if JoinLink::parse(link).is_ok() {
            return Err(format!("core takes {link}"));
        }
    }
    Ok(json!({"valid": valid, "invalid": invalid}))
}

fn agent_vectors() -> Result<Value, String> {
    let net = identity(9).id().clone();
    let (owner, agent, stranger) = (identity(1), identity(6), identity(7));
    let body = Agent {
        agent: agent.id().clone(),
        card: agent.key_card(Role::Client, Some("Rika KI"), T0).map_err(e)?,
        owner: owner.key_card(Role::Client, None, T0).map_err(e)?,
        node: identity(4).id().clone(),
        scopes: [Scope::Send, Scope::Receive].into_iter().collect::<BTreeSet<_>>(),
        to: Some(vec![identity(2).id().clone()]),
        rate: 10,
        note: Some("Rika KI".into()),
    };
    let statement = body.issue(&net, &owner, T0, 7).map_err(e)?;
    let draft = Draft { kind: "agent", net: &net, iat: T0, exp: T0 + 7 * 24 * HOUR, body: body.to_body().map_err(e)? };
    let forged = Statement::sign(&draft, &stranger).map_err(e)?;
    let long = Draft { kind: "agent", net: &net, iat: T0, exp: T0 + 31 * 24 * HOUR, body: body.to_body().map_err(e)? };
    let too_long = Statement::sign(&long, &owner).map_err(e)?;
    let now = T0 + HOUR;
    Agent::check(&statement, &net, now).map_err(e)?;
    for bad in [&forged, &too_long] {
        if Agent::check(bad, &net, now).is_ok() {
            return Err("core takes a bad agent statement".into());
        }
    }
    Ok(json!({
        "net": net.as_str(),
        "now": now,
        "valid": {"statement": text(statement.canonical_bytes())?, "agent": agent.id().as_str(),
                  "owner": owner.id().as_str(), "note": "Rika KI", "to": [identity(2).id().as_str()], "rate": 10,
                  "scopes": ["receive", "send"]},
        "invalid": [
            {"why": "signed by somebody else than the owner in the body", "statement": text(forged.canonical_bytes())?},
            {"why": "lifetime over 30 days", "statement": text(too_long.canonical_bytes())?},
            {"why": "expired", "statement": text(statement.canonical_bytes())?, "now": T0 + 8 * 24 * HOUR},
            {"why": "other network", "statement": text(statement.canonical_bytes())?, "net": identity(8).id().as_str()},
        ],
    }))
}

fn federation_vectors() -> Result<Value, String> {
    let master = identity(9);
    let net = master.id().clone();
    let peer = identity(8).id().clone();
    let master_card = master.key_card(Role::Net, None, T0).map_err(e)?;
    let gateway = identity(5).key_card_with(Role::Node, None, &["https://gw.example".into()], None, T0).map_err(e)?;
    let body = Federation { peer: peer.clone(), gateways: vec![gateway] };
    let statement = body.sign(&net, T0, T0 + 365 * 24 * HOUR, &master).map_err(e)?;
    let by_admin = body.sign(&net, T0, T0 + 365 * 24 * HOUR, &identity(3)).map_err(e)?;
    Ok(json!({
        "net": net.as_str(),
        "master": text(&master_card.to_bytes().map_err(e)?)?,
        "now": T0 + HOUR,
        "valid": {"statement": text(statement.canonical_bytes())?, "peer": peer.as_str()},
        "invalid": [
            {"why": "not signed by the net key", "statement": text(by_admin.canonical_bytes())?, "peer": peer.as_str()},
            {"why": "for another peer", "statement": text(statement.canonical_bytes())?, "peer": identity(7).id().as_str()},
        ],
    }))
}

fn build() -> Result<Value, String> {
    Ok(json!({
        "about": "Bridge 4 test vectors (docs/10 §2.2). Made by tests/e2e/tests/sdk_vectors.rs - do not edit by hand.",
        "version": 1,
        "identity_rule": "identity N = sign secret [N; 32 bytes], box secret [N+100; 32 bytes]",
        "json": json_vectors()?,
        "encoding": encoding_vectors(),
        "identities": identity_vectors()?,
        "signatures": signature_vectors()?,
        "statements": statement_vectors()?,
        "request": request_vectors()?,
        "content": content_vectors()?,
        "envelope": envelope_vectors()?,
        "pow": pow_vectors()?,
        "links": link_vectors()?,
        "agents": agent_vectors()?,
        "federation": federation_vectors()?,
    }))
}

#[test]
fn vectors_match_the_file() -> TestResult {
    let built = serde_json::to_string_pretty(&build()?).map_err(e)? + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/vectors/vectors.json");
    if std::env::var("BRIDGE_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &built).map_err(e)?;
        return Ok(());
    }
    // A Windows checkout may turn `\n` into `\r\n` (core.autocrlf) - the content is what counts.
    let stored = std::fs::read_to_string(&path)
        .map_err(|error| format!("{}: {error} (BRIDGE_WRITE_VECTORS=1)", path.display()))?
        .replace("\r\n", "\n");
    assert!(stored == built, "sdk/vectors/vectors.json is out of date - BRIDGE_WRITE_VECTORS=1 writes it anew");
    Ok(())
}

#[test]
fn vectors_are_deterministic() -> TestResult {
    assert_eq!(build()?, build()?);
    Ok(())
}
