//! Phase 6 (docs/10 §3, ADR 0022): agent cards. An owner gives a program its own key with few rights; the agent may
//! only send (to `to`, `rate` per hour) and receive, logs in only at its home node, is reachable across gateways, and
//! loses everything at once when revoked or when its owner is banned. Recipients see the owner; forged statements
//! are refused.

use std::time::{Duration, Instant};

use bridge_core::{Agent, Content, ContentType, Identity, Payload, Role, Scope};
use bridge_net::JoinMode;
use bridge_sdk::{AgentRights, Client, SdkError};
use bridge_tests::net::{TestNet, eventually, joined};
use bridge_transport::HttpClient;
use rand_core::OsRng;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn text(content: &Content) -> String {
    match &content.payload {
        Payload::Text(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

fn code_of<T: std::fmt::Debug>(result: Result<T, SdkError>) -> String {
    match result {
        Err(SdkError::Node { code, .. }) => code,
        other => format!("{other:?}"),
    }
}

fn copy(identity: &Identity) -> Identity {
    let (sign, receive) = identity.secret_bytes();
    Identity::from_secret_bytes(&sign, &receive)
}

async fn send_when_routed(from: &Client, to: &Id, content: &Content) -> Result<(), String> {
    let card = eventually("card of the recipient", || async { from.card_of(to).await.map_err(e) }).await?;
    eventually("envelope accepted", || async { from.send(&card, content).await.map(|_| ()).map_err(e) }).await
}

use bridge_core::Id;

async fn receive_one(client: &mut Client) -> Result<bridge_sdk::Received, String> {
    let deadline = Instant::now() + bridge_tests::net::PATIENCE;
    loop {
        let inbox = client.receive(1).await.map_err(e)?;
        if let Some(message) = inbox.messages.into_iter().next() {
            return Ok(message);
        }
        if Instant::now() >= deadline {
            return Err("no message arrived".into());
        }
    }
}

/// An agent client at `url` (its home node) with `statement`.
async fn agent_at(key: &Identity, url: &str, statement: bridge_core::Statement) -> Result<Client, SdkError> {
    let mut client = Client::new(copy(key), url, None)?.with_agent(statement)?;
    client.connect().await?;
    Ok(client)
}

/// The error code of a login (or "ok").
fn login_code(result: Result<Client, SdkError>) -> String {
    code_of(result.map(|_| ()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_send_and_receive_within_their_rights_across_gateways() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let second = net.add_node(&[]).await?;
    net.seal_gateway(&second).await?;
    net.synced(&second).await?;
    let alice = joined(&net.link(None)).await?; // the owner, at the owner node
    let mut bob = joined(&second.link(&net.net, None)).await?; // at the second gateway
    let carol = joined(&net.link(None)).await?;

    let key = Identity::generate(&mut OsRng);
    let card = key.key_card(Role::Client, Some("Rika KI"), 1).map_err(e)?;
    let rights = AgentRights {
        to: Some(vec![bob.identity().id().clone()]),
        rate: 3,
        note: Some("Rika KI".into()),
        ..AgentRights::default()
    };
    let statement = alice.issue_agent(&card, &rights).map_err(e)?;
    let mut agent = agent_at(&key, &net.owner.url, statement.clone()).await.map_err(e)?;

    // Agent -> Bob crosses gateways (relay with the statement); Bob sees the owner.
    send_when_routed(&agent, bob.identity().id(), &Content::text(ContentType::Direct, "Hallo von der KI")).await?;
    let message = receive_one(&mut bob).await?;
    assert_eq!(text(&message.content), "Hallo von der KI");
    assert_eq!(&message.from, key.id());
    let of = message.agent_of.ok_or("Bob should see whom the agent acts for")?;
    assert_eq!((&of.owner, of.note.as_deref()), (alice.identity().id(), Some("Rika KI")));

    // Bob -> agent: found through the exchanged home entry at the second gateway.
    send_when_routed(&bob, key.id(), &Content::text(ContentType::Response, "Hallo KI")).await?;
    assert_eq!(text(&receive_one(&mut agent).await?.content), "Hallo KI");

    // Only to `to`.
    let to_carol = agent.card_of(carol.identity().id()).await.map_err(e)?;
    assert_eq!(code_of(agent.send(&to_carol, &Content::text(ContentType::Direct, "x")).await), "FORBIDDEN");
    // `rate` per hour: 1 sent, 2 more, then no more.
    let to_bob = agent.card_of(bob.identity().id()).await.map_err(e)?;
    for _ in 0..2 {
        agent.send(&to_bob, &Content::text(ContentType::Direct, "noch eine")).await.map_err(e)?;
    }
    assert_eq!(code_of(agent.send(&to_bob, &Content::text(ContentType::Direct, "zu viel")).await), "RATE_LIMITED");

    // Everything else with the agent's session is forbidden (default deny).
    let raw = HttpClient::new(&net.owner.url, Duration::from_secs(10)).map_err(e)?;
    let token = agent.session_token().ok_or("agent session")?.to_owned();
    for path in ["/v4/names/submit", "/v4/blob/begin", "/v4/report", "/v4/agent/revoke"] {
        let answer = raw.post(path, Some(&token), b"{}".to_vec()).await.map_err(e)?;
        assert_eq!(answer.status, 403, "{path}: {}", String::from_utf8_lossy(&answer.body));
    }

    // A member that is also somebody's agent keeps its own rights in its own session.
    let carol_key = copy(carol.identity());
    let carol_card = carol.card().clone();
    let as_agent = alice.issue_agent(&carol_card, &AgentRights::default()).map_err(e)?;
    let _carol_agent = agent_at(&carol_key, &net.owner.url, as_agent).await.map_err(e)?;
    let carol_token = carol.session_token().ok_or("carol's session")?.to_owned();
    let answer = raw.post("/v4/names/submit", Some(&carol_token), b"{}".to_vec()).await.map_err(e)?;
    assert_ne!(answer.status, 403, "{}", String::from_utf8_lossy(&answer.body));

    // Only at its home node.
    let elsewhere = agent_at(&key, &second.url, statement.clone()).await;
    assert_eq!(login_code(elsewhere), "FORBIDDEN");

    // A receive-only agent can not send.
    let listener_key = Identity::generate(&mut OsRng);
    let listener_card = listener_key.key_card(Role::Client, None, 1).map_err(e)?;
    let listen_only = AgentRights { send: false, ..AgentRights::default() };
    let listener = agent_at(&listener_key, &net.owner.url, alice.issue_agent(&listener_card, &listen_only).map_err(e)?)
        .await
        .map_err(e)?;
    let card_of_bob = listener.card_of(bob.identity().id()).await.map_err(e)?;
    assert_eq!(code_of(listener.send(&card_of_bob, &Content::text(ContentType::Direct, "x")).await), "FORBIDDEN");

    // Revoked: the session ends, the statement is dead, the agent is unknown.
    assert!(alice.revoke_agent(key.id()).await.map_err(e)?, "the agent's session ended");
    assert_eq!(code_of(agent.receive(0).await), "NO_SESSION");
    assert_eq!(login_code(agent_at(&key, &net.owner.url, statement).await), "FORBIDDEN");
    let to_agent = carol.card_of(key.id()).await;
    if let Ok(card) = to_agent {
        assert_eq!(code_of(carol.send(&card, &Content::text(ContentType::Direct, "x")).await), "UNKNOWN_IDENTITY");
    }
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_statements_and_banned_owners() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let alice = joined(&net.link(None)).await?;
    let dave = joined(&net.link(None)).await?;
    let node = alice.node_card().ok_or("node card")?.id().clone();

    // The agent signs its own statement naming Alice as owner: refused.
    let key = Identity::generate(&mut OsRng);
    let card = key.key_card(Role::Client, None, 1).map_err(e)?;
    let body = Agent {
        agent: key.id().clone(),
        card: card.clone(),
        owner: alice.card().clone(),
        node: node.clone(),
        scopes: [Scope::Send, Scope::Receive].into_iter().collect(),
        to: None,
        rate: 60,
        note: None,
    };
    let draft = bridge_core::Draft {
        kind: "agent",
        net: &net.net,
        iat: bridge_tests::now_ms(),
        exp: bridge_tests::now_ms() + 3_600_000,
        body: body.to_body().map_err(e)?,
    };
    let forged = bridge_core::Statement::sign(&draft, &key).map_err(e)?;
    assert_eq!(login_code(agent_at(&key, &net.owner.url, forged).await), "BAD_SIGNATURE");

    // An owner that is not a member: its agent can not log in.
    let outsider = Identity::generate(&mut OsRng);
    let mut stranger = body.clone();
    stranger.owner = outsider.key_card(Role::Client, None, 1).map_err(e)?;
    let statement = stranger.issue(&net.net, &outsider, bridge_tests::now_ms(), 1).map_err(e)?;
    assert_eq!(login_code(agent_at(&key, &net.owner.url, statement).await), "NOT_MEMBER");

    // Dave's agent works until Dave is banned - then at once not any more.
    let statement = dave.issue_agent(&card, &AgentRights::default()).map_err(e)?;
    let mut agent = agent_at(&key, &net.owner.url, statement.clone()).await.map_err(e)?;
    agent.receive(0).await.map_err(e)?;
    // At most 16 agents of one owner at a node.
    let mut more = Vec::new();
    for _ in 0..15 {
        let key = Identity::generate(&mut OsRng);
        let card = key.key_card(Role::Client, None, 1).map_err(e)?;
        more.push(
            agent_at(&key, &net.owner.url, dave.issue_agent(&card, &AgentRights::default()).map_err(e)?)
                .await
                .map_err(e)?,
        );
    }
    let key17 = Identity::generate(&mut OsRng);
    let card17 = key17.key_card(Role::Client, None, 1).map_err(e)?;
    let seventeenth =
        agent_at(&key17, &net.owner.url, dave.issue_agent(&card17, &AgentRights::default()).map_err(e)?).await;
    assert_eq!(login_code(seventeenth), "QUOTA_EXCEEDED");
    net.admin.ban(dave.identity().id().clone(), 30, "Test").await?;
    let deadline = Instant::now() + bridge_tests::net::PATIENCE;
    let banned = loop {
        match agent.receive(0).await {
            Err(SdkError::Node { code, .. }) => break code,
            other if Instant::now() >= deadline => return Err(format!("still served: {other:?}")),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    assert!(["BANNED", "NOT_MEMBER", "FORBIDDEN"].contains(&banned.as_str()), "{banned}");
    let again = login_code(agent_at(&key, &net.owner.url, statement).await);
    assert!(["BANNED", "NOT_MEMBER", "FORBIDDEN"].contains(&again.as_str()), "{again}");
    net.owner.node.shutdown().await;
    Ok(())
}
