//! # bridge-ai – the local AI service (docs/10 §4, ADR 0024)
//!
//! The logic of `bridge-node ai`, without network or keys: check who may ask, check and read a task, build the request
//! for a **local** model server (Ollama or OpenAI-compatible, loopback only), read its answer, build the reply. The
//! program connects this to the network (Rust SDK) and to the model server (HTTP).
//!
//! Zero Trust here: tasks are strict JSON with exact fields and bounds; replies only to the verified sender (the
//! program); the model server must be on this machine; answers are bounded; per-sender rate per hour.

use std::collections::{HashMap, VecDeque};

use bridge_core::Id;
use bridge_core::json::parse_strict;
use bridge_plugin_api::{Reply, Task};
use serde_json::{Map, Value, json};

/// Media type of tasks and replies.
pub const JSON: &str = "application/json";
/// Largest prompt in bytes.
pub const MAX_PROMPT_BYTES: usize = 32 * 1024;
/// Largest system text in bytes.
pub const MAX_SYSTEM_BYTES: usize = 8 * 1024;
/// Largest task (JSON) in bytes.
pub const MAX_TASK_BYTES: usize = 48 * 1024;
/// Highest `max_tokens`.
pub const MAX_TOKENS: u64 = 4096;
/// `max_tokens` when the task names none.
pub const DEFAULT_TOKENS: u64 = 512;
/// Longest answer text in bytes (longer is cut, `"truncated": true`).
pub const MAX_ANSWER_BYTES: usize = 64 * 1024;
/// Largest answer of the model server in bytes.
pub const MAX_BACKEND_BYTES: usize = 1024 * 1024;
/// Most senders the rate limiter remembers.
const MAX_SENDERS: usize = 10_000;
const HOUR_MS: i64 = 3600 * 1000;

/// The kind of model server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// Ollama (`POST /api/generate`).
    Ollama,
    /// OpenAI-compatible (`POST /v1/chat/completions`, e.g. llama.cpp server, LM Studio).
    OpenAi,
}

impl Api {
    /// From `ollama` / `openai`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "ollama" => Some(Self::Ollama),
            "openai" => Some(Self::OpenAi),
            _ => None,
        }
    }
}

/// Who may ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allow {
    /// Everybody who can reach the service (members of the network, and of connected networks).
    Members,
    /// Only these identities.
    List(Vec<Id>),
}

/// The service's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Kind of model server.
    pub api: Api,
    /// Its address (loopback only, see [`check_backend`]).
    pub backend: String,
    /// The default model.
    pub model: String,
    /// Further models a task may name.
    pub models: Vec<String>,
    /// Who may ask.
    pub allow: Allow,
    /// Whether agents (docs/10 §3) may ask (only if they are allowed themselves).
    pub allow_agents: bool,
    /// Tasks per sender and hour.
    pub rate: u32,
}

/// A checked task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiRequest {
    /// The prompt.
    pub prompt: String,
    /// The system text.
    pub system: Option<String>,
    /// The model to use.
    pub model: String,
    /// Most tokens of the answer.
    pub max_tokens: u64,
}

/// Checks the model server address: `http(s)://` + `127.0.0.1`, `[::1]` or `localhost`, an optional port, an optional
/// path of safe characters. Anything else is refused - the service never talks to another machine.
pub fn check_backend(url: &str) -> Result<(), String> {
    let refuse = || {
        Err("--backend: nur ein Modell-Server auf diesem PC (http://127.0.0.1:…, http://[::1]:…, http://localhost:…)"
            .to_owned())
    };
    let Some(rest) = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://")) else { return refuse() };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let port = if let Some(after) = authority.strip_prefix("[::1]") {
        after
    } else if let Some(after) = authority.strip_prefix("127.0.0.1") {
        after
    } else if authority.len() >= 9 && authority[..9].eq_ignore_ascii_case("localhost") {
        &authority[9..]
    } else {
        return refuse();
    };
    let port_ok = port.is_empty()
        || port.strip_prefix(':').is_some_and(|digits| {
            !digits.is_empty() && digits.len() <= 5 && digits.bytes().all(|b| b.is_ascii_digit())
        });
    let path_ok = path.len() <= 100
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_'))
        && !path.split('/').any(|segment| segment == "..");
    if port_ok && path_ok { Ok(()) } else { refuse() }
}

/// Whether `task`'s sender may ask (`Err`: the reply that says no).
pub fn access(task: &Task, config: &Config) -> Result<(), Reply> {
    let listed = match &config.allow {
        Allow::Members => true,
        Allow::List(ids) => ids.contains(&task.from),
    };
    if !listed || (task.agent_of.is_some() && !config.allow_agents) {
        return Err(error(task, "NOT_ALLOWED", "du darfst diesen Dienst nicht nutzen"));
    }
    Ok(())
}

/// Reads and checks a task (`Err`: the reply that says why not).
pub fn parse_task(task: &Task, config: &Config) -> Result<AiRequest, Reply> {
    let bad = |message: &str| error(task, "BAD_TASK", message);
    if task.ctype != JSON {
        return Err(bad("Aufgaben sind application/json"));
    }
    let Ok(Value::Object(object)) = parse_strict(&task.data, MAX_TASK_BYTES) else {
        return Err(bad("kein JSON-Objekt (oder zu groß)"));
    };
    if let Some(unknown) =
        object.keys().find(|key| !["prompt", "system", "model", "max_tokens"].contains(&key.as_str()))
    {
        return Err(bad(&format!("unbekanntes Feld {unknown:?}")));
    }
    let text = |name: &str, max: usize| -> Result<Option<String>, Reply> {
        match object.get(name) {
            None => Ok(None),
            Some(Value::String(text)) if !text.is_empty() && text.len() <= max => Ok(Some(text.clone())),
            Some(_) => Err(bad(&format!("{name}: Text mit 1 bis {max} Bytes"))),
        }
    };
    let prompt = text("prompt", MAX_PROMPT_BYTES)?.ok_or_else(|| bad("prompt fehlt"))?;
    let system = text("system", MAX_SYSTEM_BYTES)?;
    let model = match text("model", 100)? {
        Some(model) if model == config.model || config.models.contains(&model) => model,
        _ => config.model.clone(),
    };
    let max_tokens = match object.get("max_tokens") {
        None => DEFAULT_TOKENS,
        Some(value) => value
            .as_u64()
            .filter(|tokens| (1..=MAX_TOKENS).contains(tokens))
            .ok_or_else(|| bad("max_tokens: 1 bis 4096"))?,
    };
    Ok(AiRequest { prompt, system, model, max_tokens })
}

/// Path and body of the request to the model server.
#[must_use]
pub fn backend_request(api: Api, request: &AiRequest) -> (&'static str, Vec<u8>) {
    match api {
        Api::Ollama => {
            let mut body = json!({
                "model": request.model,
                "prompt": request.prompt,
                "stream": false,
                "options": {"num_predict": request.max_tokens},
            });
            if let Some(system) = &request.system {
                body["system"] = json!(system);
            }
            ("/api/generate", body.to_string().into_bytes())
        }
        Api::OpenAi => {
            let mut messages = Vec::new();
            if let Some(system) = &request.system {
                messages.push(json!({"role": "system", "content": system}));
            }
            messages.push(json!({"role": "user", "content": request.prompt}));
            let body = json!({"model": request.model, "messages": messages, "max_tokens": request.max_tokens});
            ("/v1/chat/completions", body.to_string().into_bytes())
        }
    }
}

/// The answer text from the model server's answer (bounded; the server is local but its answer is still checked).
pub fn parse_backend(api: Api, bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_BACKEND_BYTES {
        return Err("Antwort des Modell-Servers zu groß".into());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "Antwort des Modell-Servers ist kein JSON".to_owned())?;
    let text = match api {
        Api::Ollama => value.get("response").and_then(Value::as_str),
        Api::OpenAi => value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str),
    };
    text.map(str::to_owned).ok_or_else(|| "Antwort des Modell-Servers ohne Text".into())
}

/// The reply with the model's answer (cut at [`MAX_ANSWER_BYTES`] on a character boundary).
#[must_use]
pub fn answer(task: &Task, model: &str, text: &str) -> Reply {
    let mut object = Map::new();
    let mut end = text.len().min(MAX_ANSWER_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    object.insert("text".into(), json!(&text[..end]));
    object.insert("model".into(), json!(model));
    if end < text.len() {
        object.insert("truncated".into(), json!(true));
    }
    Reply { task: task.id, ctype: JSON.into(), data: Value::Object(object).to_string().into_bytes() }
}

/// A reply with an error code (`BAD_TASK`, `NOT_ALLOWED`, `RATE_LIMITED`, `BUSY`, `BACKEND`).
#[must_use]
pub fn error(task: &Task, code: &str, message: &str) -> Reply {
    Reply {
        task: task.id,
        ctype: JSON.into(),
        data: json!({"error": code, "message": message}).to_string().into_bytes(),
    }
}

/// Tasks per sender and hour (bounded memory).
#[derive(Debug, Default)]
pub struct Limiter {
    seen: HashMap<Id, VecDeque<i64>>,
}

impl Limiter {
    /// Counts a task of `from` at `now`; `Err`: the reply that says to wait.
    pub fn admit(&mut self, task: &Task, rate: u32, now: i64) -> Result<(), Reply> {
        if !self.seen.contains_key(&task.from) && self.seen.len() >= MAX_SENDERS {
            self.seen.retain(|_, times| times.back().is_some_and(|last| *last > now - HOUR_MS));
            if self.seen.len() >= MAX_SENDERS {
                return Err(error(task, "BUSY", "zu viele Fragende - später noch einmal"));
            }
        }
        let times = self.seen.entry(task.from.clone()).or_default();
        while times.front().is_some_and(|time| *time <= now - HOUR_MS) {
            times.pop_front();
        }
        if times.len() >= rate as usize {
            return Err(error(task, "RATE_LIMITED", "zu viele Aufgaben in dieser Stunde"));
        }
        times.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> Id {
        Id::of_sign_key(&[seed; 32])
    }

    fn config() -> Config {
        Config {
            api: Api::Ollama,
            backend: "http://127.0.0.1:11434".into(),
            model: "llama3.2".into(),
            models: vec!["qwen2.5".into()],
            allow: Allow::List(vec![id(1)]),
            allow_agents: false,
            rate: 2,
        }
    }

    fn task(from: u8, data: Value) -> Task {
        Task { id: [7; 16], from: id(from), agent_of: None, ctype: JSON.into(), data: data.to_string().into_bytes() }
    }

    fn code(reply: &Reply) -> String {
        let value: Value = serde_json::from_slice(&reply.data).unwrap_or_default();
        value.get("error").and_then(Value::as_str).unwrap_or("").to_owned()
    }

    #[test]
    fn backend_must_be_loopback() {
        for good in ["http://127.0.0.1:11434", "http://localhost:1234", "https://[::1]:8080/v1", "http://LOCALHOST"] {
            assert!(check_backend(good).is_ok(), "{good}");
        }
        for bad in [
            "http://192.168.1.5:11434",
            "http://127.0.0.1.evil.com:80",
            "http://localhost.evil.com",
            "http://localhost@evil.com",
            "https://api.openai.com/v1",
            "http://127.0.0.1:11434/../x",
            "http://127.0.0.1:11434?x=1",
            "ftp://127.0.0.1",
            "http://[::2]:1",
            "http://127.0.0.1:",
        ] {
            assert!(check_backend(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tasks_are_checked() -> Result<(), String> {
        let config = config();
        let ok = parse_task(&task(1, json!({"prompt": "Hallo", "model": "qwen2.5", "max_tokens": 64})), &config)
            .map_err(|_| "valid task")?;
        assert_eq!((ok.prompt.as_str(), ok.model.as_str(), ok.max_tokens), ("Hallo", "qwen2.5", 64));
        let other = parse_task(&task(1, json!({"prompt": "x", "model": "unbekannt"})), &config).map_err(|_| "valid")?;
        assert_eq!((other.model.as_str(), other.max_tokens), ("llama3.2", DEFAULT_TOKENS), "unknown model: default");
        for bad in [
            json!({}),
            json!({"prompt": ""}),
            json!({"prompt": "x", "max_tokens": 0}),
            json!({"prompt": "x", "max_tokens": 4097}),
            json!({"prompt": "x", "tools": []}),
            json!({"prompt": 5}),
            json!({"prompt": "x".repeat(MAX_PROMPT_BYTES + 1)}),
            json!(["x"]),
        ] {
            assert_eq!(
                parse_task(&task(1, bad.clone()), &config).map(|_| ()).map_err(|r| code(&r)),
                Err("BAD_TASK".into()),
                "{bad}"
            );
        }
        let mut text = task(1, json!({"prompt": "x"}));
        text.ctype = "text/plain".into();
        assert!(parse_task(&text, &config).is_err());
        let mut float = task(1, json!({}));
        float.data = br#"{"prompt":"x","max_tokens":1.5}"#.to_vec();
        assert!(parse_task(&float, &config).is_err(), "strict JSON");
        Ok(())
    }

    #[test]
    fn access_and_rate() {
        let mut config = config();
        assert!(access(&task(1, json!({})), &config).is_ok());
        assert_eq!(access(&task(2, json!({})), &config).map_err(|r| code(&r)), Err("NOT_ALLOWED".into()));
        let mut agent = task(1, json!({}));
        agent.agent_of = Some(id(9));
        assert!(access(&agent, &config).is_err(), "agents only when allowed");
        config.allow_agents = true;
        assert!(access(&agent, &config).is_ok());
        config.allow = Allow::Members;
        assert!(access(&task(2, json!({})), &config).is_ok());
        let mut limiter = Limiter::default();
        let first = task(1, json!({}));
        assert!(limiter.admit(&first, 2, 0).is_ok());
        assert!(limiter.admit(&first, 2, 1).is_ok());
        assert_eq!(limiter.admit(&first, 2, 2).map_err(|r| code(&r)), Err("RATE_LIMITED".into()));
        assert!(limiter.admit(&task(2, json!({})), 2, 2).is_ok(), "per sender");
        assert!(limiter.admit(&first, 2, HOUR_MS + 1).is_ok(), "after an hour");
    }

    #[test]
    fn backend_requests_and_answers() -> Result<(), String> {
        let request = AiRequest { prompt: "Hi".into(), system: Some("Kurz".into()), model: "m".into(), max_tokens: 9 };
        let (path, body) = backend_request(Api::Ollama, &request);
        let body: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        assert_eq!(
            (path, &body["prompt"], &body["system"], &body["stream"]),
            ("/api/generate", &json!("Hi"), &json!("Kurz"), &json!(false))
        );
        let (path, body) = backend_request(Api::OpenAi, &request);
        let body: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        assert_eq!((path, body["messages"][1]["content"].as_str()), ("/v1/chat/completions", Some("Hi")));
        assert_eq!(parse_backend(Api::Ollama, br#"{"response":"Hallo!","done":true,"eval_duration":1.5}"#)?, "Hallo!");
        assert_eq!(
            parse_backend(Api::OpenAi, br#"{"choices":[{"message":{"role":"assistant","content":"Hi"}}]}"#)?,
            "Hi"
        );
        assert!(parse_backend(Api::Ollama, b"{}").is_err());
        assert!(parse_backend(Api::Ollama, b"<html>").is_err());
        let long = "ä".repeat(MAX_ANSWER_BYTES);
        let reply = answer(&task(1, json!({})), "m", &long);
        let value: Value = serde_json::from_slice(&reply.data).map_err(|e| e.to_string())?;
        assert_eq!(value["truncated"], json!(true));
        assert!(value["text"].as_str().is_some_and(|text| text.len() <= MAX_ANSWER_BYTES));
        Ok(())
    }
}
