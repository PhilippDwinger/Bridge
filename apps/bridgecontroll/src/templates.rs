//! "Website aus Vorlage" (docs/13, ADR 0031): a template built into this program, a few settings, a design - and the
//! owner node hosts it like any uploaded website ([`crate::sites`]). User-facing texts are German.
//!
//! - Every template is `template.json` (name, description, fields) and its `app.js`, plus the shared `index.html`,
//!   `base.css`, `bridge.js` and the Bridge Login helper `login.js` (sdk/javascript). Nothing is read at runtime.
//! - Settings are checked against the fields (kind, length, lines, format) - unknown ones are refused. They go into the
//!   site as `config.json`; the page only ever sets them as text.
//! - A design is one CSS file that sets the variables `base.css` uses (`--bg`, `--fg`, `--muted`, `--accent`,
//!   `--on-accent`, `--card`, `--line`, `--radius`, `--font`, `--font-head`) - the interface for design plugins.
//! - Templates with entries get `server.records` (the built-in building block, docs/13 §4).
//! - The site is put together in `<owner node>/templates/build-<random>/` and removed after the upload; the raw
//!   settings stay in `<owner node>/templates/<app-id>.json` for "Bearbeiten".

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use bridge_core::Id;
use bridge_core::json::parse_strict;
use rand_core::{OsRng, RngCore};
use serde_json::{Map, Value, json};

use crate::App;
use crate::ops::entry_of;

/// The folder below the owner node with the saved settings (and the short-lived build folders).
pub const TEMPLATES_DIR: &str = "templates";
/// The start file of every template.
const START: &str = "index.html";
/// Largest saved settings file read back.
const MAX_SAVED_BYTES: u64 = 64 * 1024;
/// Most fields of a template.
const MAX_FIELDS: usize = 24;
/// Longest link (a setting or a line).
const MAX_LINK_CHARS: usize = 300;
/// Most lines of a text area.
const MAX_AREA_LINES: usize = 100;

macro_rules! bytes {
    ($file:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/", $file)) as &[u8]
    };
}

/// One built-in template.
struct Embedded {
    id: &'static str,
    spec: &'static str,
    files: &'static [(&'static str, &'static [u8])],
}

/// Files of every template.
static SHARED: &[(&str, &[u8])] = &[
    ("index.html", bytes!("index.html")),
    ("base.css", bytes!("base.css")),
    ("bridge.js", bytes!("bridge.js")),
    ("login.js", include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../sdk/javascript/src/login.js"))),
];

/// The built-in templates, in the order they are offered.
static TEMPLATES: &[Embedded] = &[
    Embedded {
        id: "visitenkarte",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/visitenkarte/template.json")),
        files: &[("app.js", bytes!("visitenkarte/app.js"))],
    },
    Embedded {
        id: "gaestebuch",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/gaestebuch/template.json")),
        files: &[("app.js", bytes!("gaestebuch/app.js"))],
    },
    Embedded {
        id: "umfrage",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/umfrage/template.json")),
        files: &[("app.js", bytes!("umfrage/app.js"))],
    },
    Embedded {
        id: "termine",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/termine/template.json")),
        files: &[("app.js", bytes!("termine/app.js"))],
    },
    Embedded {
        id: "anmeldung",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/anmeldung/template.json")),
        files: &[("app.js", bytes!("anmeldung/app.js"))],
    },
    Embedded {
        id: "ideen",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/ideen/template.json")),
        files: &[("app.js", bytes!("ideen/app.js"))],
    },
    Embedded {
        id: "countdown",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/countdown/template.json")),
        files: &[("app.js", bytes!("countdown/app.js"))],
    },
    Embedded {
        id: "rezept",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/rezept/template.json")),
        files: &[("app.js", bytes!("rezept/app.js"))],
    },
    Embedded {
        id: "wunschliste",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/wunschliste/template.json")),
        files: &[("app.js", bytes!("wunschliste/app.js"))],
    },
    Embedded {
        id: "pinnwand",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/pinnwand/template.json")),
        files: &[("app.js", bytes!("pinnwand/app.js"))],
    },
    Embedded {
        id: "faq",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/faq/template.json")),
        files: &[("app.js", bytes!("faq/app.js"))],
    },
    Embedded {
        id: "speisekarte",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/speisekarte/template.json")),
        files: &[("app.js", bytes!("speisekarte/app.js"))],
    },
    Embedded {
        id: "infoseite",
        spec: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/infoseite/template.json")),
        files: &[("app.js", bytes!("infoseite/app.js"))],
    },
];

/// One built-in design: its CSS and the colors for the preview in the dialog (background, card, text, accent).
pub struct Design {
    /// Its id (the value of `design` in a request).
    pub id: &'static str,
    /// Its name in the dialog.
    pub name: &'static str,
    css: &'static [u8],
    preview: [&'static str; 4],
}

/// The built-in designs; the first is the default.
pub static DESIGNS: &[Design] = &[
    Design {
        id: "hell",
        name: "Hell",
        css: bytes!("designs/hell.css"),
        preview: ["#f4f6fa", "#ffffff", "#1a2233", "#2563eb"],
    },
    Design {
        id: "dunkel",
        name: "Dunkel",
        css: bytes!("designs/dunkel.css"),
        preview: ["#0f141d", "#18202c", "#e8edf5", "#5b9cff"],
    },
    Design {
        id: "bunt",
        name: "Bunt",
        css: bytes!("designs/bunt.css"),
        preview: ["#fff4e8", "#ffffff", "#2b1b3d", "#e4407b"],
    },
];

/// Settings by field key.
pub type Settings = Map<String, Value>;

/// How a line of a list setting is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line {
    /// Just text.
    Text,
    /// "Titel https://…" → `{title, url}`.
    Link,
    /// "JJJJ-MM-TT [HH:MM] Titel" → `{date, time, title}`.
    Date,
    /// "Teil 1 | Teil 2 | …" → a list of exactly that many texts (the first one needed, the last one takes the rest).
    Parts(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Text { max: usize },
    Area { max: usize },
    List { min: usize, max: usize, line_max: usize, line: Line },
    Choice { options: Vec<(String, String)> },
    Switch,
    Date,
    Time,
    Link,
}

/// One setting of a template.
#[derive(Debug, Clone, PartialEq)]
struct Field {
    key: String,
    label: String,
    hint: String,
    required: bool,
    default: Value,
    kind: Kind,
}

/// A template's `template.json`, checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    /// The template's name.
    pub name: String,
    /// What it is for, one sentence.
    pub description: String,
    /// With entries (`server.records`).
    pub records: bool,
    fields: Vec<Field>,
}

fn key_ok(key: &str) -> bool {
    let mut bytes = key.bytes();
    key.len() <= 32
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn chars(text: &str) -> usize {
    text.chars().count()
}

/// A short text of the spec: `min..=max` characters, one line.
fn spec_text(object: &Map<String, Value>, name: &str, min: usize, max: usize) -> Result<String, String> {
    let text = object.get(name).and_then(Value::as_str).unwrap_or_default();
    if chars(text) < min || chars(text) > max || text.chars().any(char::is_control) {
        return Err(format!("{name}: {min}-{max} characters"));
    }
    Ok(text.to_owned())
}

/// A number of the spec in `1..=max` (or `default`).
fn spec_number(
    object: &Map<String, Value>,
    name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, String> {
    match object.get(name) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| format!("{name}: {min}-{max}")),
    }
}

impl Spec {
    /// Reads and checks a `template.json`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let Ok(Value::Object(object)) = parse_strict(text.as_bytes(), 64 * 1024) else {
            return Err("template.json: not a JSON object".into());
        };
        let name = spec_text(&object, "name", 1, 40)?;
        let description = spec_text(&object, "description", 0, 200)?;
        let records = object.get("records").and_then(Value::as_bool).unwrap_or(false);
        let raw_fields = object.get("fields").and_then(Value::as_array).ok_or("fields: a list")?;
        if raw_fields.is_empty() || raw_fields.len() > MAX_FIELDS {
            return Err(format!("fields: 1-{MAX_FIELDS}"));
        }
        let mut keys = HashSet::new();
        let mut fields = Vec::new();
        for raw in raw_fields {
            let field = raw.as_object().ok_or("field: an object")?;
            let key = field.get("key").and_then(Value::as_str).unwrap_or_default().to_owned();
            if !key_ok(&key) || !keys.insert(key.clone()) {
                return Err(format!("field key {key:?}: a-z, 0-9, _ and unique"));
            }
            let kind = match field.get("type").and_then(Value::as_str).unwrap_or_default() {
                "text" => Kind::Text { max: spec_number(field, "max", 80, 1, 200)? },
                "area" => Kind::Area { max: spec_number(field, "max", 1000, 1, 4000)? },
                "list" => {
                    let max = spec_number(field, "max", 10, 1, 50)?;
                    let line = match field.get("line").and_then(Value::as_str).unwrap_or("text") {
                        "text" => Line::Text,
                        "link" => Line::Link,
                        "date" => Line::Date,
                        "parts" => Line::Parts(spec_number(field, "parts", 2, 2, 4)?),
                        other => return Err(format!("{key}: line {other:?}")),
                    };
                    let line_max = spec_number(field, "line_max", 120, 1, 400)?;
                    Kind::List { min: spec_number(field, "min", 0, 0, max)?, max, line_max, line }
                }
                "choice" => {
                    let raw = field.get("options").and_then(Value::as_array).ok_or("options: a list")?;
                    if raw.len() < 2 || raw.len() > 20 {
                        return Err(format!("{key}: 2-20 options"));
                    }
                    let mut options = Vec::new();
                    for option in raw {
                        let option = option.as_object().ok_or("option: an object")?;
                        let value = spec_text(option, "value", 1, 32)?;
                        if !key_ok(&value) || options.iter().any(|(seen, _)| *seen == value) {
                            return Err(format!("{key}: option values a-z, 0-9, _ and unique"));
                        }
                        options.push((value, spec_text(option, "label", 1, 60)?));
                    }
                    Kind::Choice { options }
                }
                "switch" => Kind::Switch,
                "date" => Kind::Date,
                "time" => Kind::Time,
                "link" => Kind::Link,
                other => return Err(format!("{key}: type {other:?}")),
            };
            let mut field = Field {
                label: spec_text(field, "label", 1, 60)?,
                hint: spec_text(field, "hint", 0, 200)?,
                required: field.get("required").and_then(Value::as_bool).unwrap_or(false),
                default: field.get("default").cloned().unwrap_or(Value::Null),
                key,
                kind,
            };
            // The default must be a valid setting itself.
            if !field.default.is_null() {
                let (raw, _) =
                    field.check(Some(&field.default)).map_err(|e| format!("default of {}: {e}", field.key))?;
                field.default = raw;
            }
            fields.push(field);
        }
        Ok(Self { name, description, records, fields })
    }

    /// Checks `input` (raw values from the form; absent ones take the default): the raw settings to save and the
    /// values for `config.json`.
    pub fn check(&self, input: &Map<String, Value>) -> Result<(Settings, Settings), String> {
        if let Some(unknown) = input.keys().find(|key| !self.fields.iter().any(|field| &field.key == *key)) {
            let shown: String = unknown.chars().filter(|c| !c.is_control()).take(32).collect();
            return Err(format!("Unbekannte Einstellung: {shown}"));
        }
        let (mut raw, mut config) = (Map::new(), Map::new());
        for field in &self.fields {
            let given = input.get(&field.key).filter(|value| !value.is_null());
            let (saved, value) = field.check(given.or(Some(&field.default)).filter(|value| !value.is_null()))?;
            raw.insert(field.key.clone(), saved);
            config.insert(field.key.clone(), value);
        }
        Ok((raw, config))
    }

    /// The fields for the form in BridgeControll.
    fn fields_json(&self) -> Vec<Value> {
        self.fields
            .iter()
            .map(|field| {
                let mut out = json!({
                    "key": field.key, "label": field.label, "hint": field.hint, "required": field.required,
                    "default": field.default,
                });
                let (kind, extra) = match &field.kind {
                    Kind::Text { max } => ("text", json!({"max": max})),
                    Kind::Area { max } => ("area", json!({"max": max})),
                    Kind::List { min, max, line_max, line } => {
                        let (line, parts) = match line {
                            Line::Text => ("text", 1),
                            Line::Link => ("link", 1),
                            Line::Date => ("date", 1),
                            Line::Parts(parts) => ("parts", *parts),
                        };
                        ("list", json!({"min": min, "max": max, "line_max": line_max, "line": line, "parts": parts}))
                    }
                    Kind::Choice { options } => (
                        "choice",
                        json!({"options": options.iter().map(|(value, label)| json!({"value": value, "label": label}))
                            .collect::<Vec<_>>()}),
                    ),
                    Kind::Switch => ("switch", json!({})),
                    Kind::Date => ("date", json!({})),
                    Kind::Time => ("time", json!({})),
                    Kind::Link => ("link", json!({})),
                };
                out["type"] = json!(kind);
                if let (Some(out), Value::Object(extra)) = (out.as_object_mut(), extra) {
                    out.extend(extra);
                }
                out
            })
            .collect()
    }
}

/// `JJJJ-MM-TT` (1970-2200), a real day.
pub fn date_ok(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    let [year, month, day] = parts.as_slice() else { return false };
    if year.len() != 4 || month.len() != 2 || day.len() != 2 || !text.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (year.parse::<u32>(), month.parse::<u32>(), day.parse::<u32>()) else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1970..=2200).contains(&year) && (1..=days).contains(&day)
}

/// `HH:MM`.
fn time_ok(text: &str) -> bool {
    let Some((hour, minute)) = text.split_once(':') else { return false };
    hour.len() == 2
        && minute.len() == 2
        && hour.parse::<u32>().is_ok_and(|h| h < 24)
        && minute.parse::<u32>().is_ok_and(|m| m < 60)
        && text.bytes().all(|b| b.is_ascii_digit() || b == b':')
}

/// `https://…`, at most 300 characters, nothing that could break out of an attribute.
pub fn link_ok(text: &str) -> bool {
    text.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && !rest.starts_with('/')
            && chars(text) <= MAX_LINK_CHARS
            && !text.chars().any(|c| c.is_control() || c.is_whitespace() || "<>\"'`\\".contains(c))
    })
}

impl Field {
    /// One value checked: `(raw to save, value for config.json)`; `None` = empty.
    fn check(&self, value: Option<&Value>) -> Result<(Value, Value), String> {
        let label = &self.label;
        let text_of = |value: Option<&Value>| -> Result<String, String> {
            match value {
                None => Ok(String::new()),
                Some(Value::String(text)) => Ok(text.clone()),
                Some(_) => Err(format!("{label}: ein Text")),
            }
        };
        let needed = |empty: bool| -> Result<(), String> {
            if empty && self.required { Err(format!("{label}: bitte ausfüllen")) } else { Ok(()) }
        };
        match &self.kind {
            Kind::Text { max } => {
                let text = text_of(value)?.trim().to_owned();
                if chars(&text) > *max || text.chars().any(char::is_control) {
                    return Err(format!("{label}: höchstens {max} Zeichen, eine Zeile"));
                }
                needed(text.is_empty())?;
                Ok((json!(text), json!(text)))
            }
            Kind::Area { max } => {
                let text = text_of(value)?.replace("\r\n", "\n").replace('\r', "\n").trim().to_owned();
                if chars(&text) > *max
                    || text.lines().count() > MAX_AREA_LINES
                    || text.chars().any(|c| c.is_control() && c != '\n')
                {
                    return Err(format!("{label}: höchstens {max} Zeichen und {MAX_AREA_LINES} Zeilen"));
                }
                needed(text.is_empty())?;
                Ok((json!(text), json!(text)))
            }
            Kind::List { min, max, line_max, line } => {
                let lines: Vec<String> = match value {
                    None => Vec::new(),
                    Some(Value::String(text)) => {
                        if chars(text) > (line_max + 2) * max + 1000 {
                            return Err(format!("{label}: zu lang"));
                        }
                        text.lines().map(|line| line.trim().to_owned()).filter(|line| !line.is_empty()).collect()
                    }
                    Some(Value::Array(items)) if items.len() <= *max * 2 => items
                        .iter()
                        .map(|item| item.as_str().map(|line| line.trim().to_owned()).ok_or(format!("{label}: Zeilen")))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .filter(|line| !line.is_empty())
                        .collect(),
                    Some(_) => return Err(format!("{label}: Zeilen")),
                };
                needed(lines.is_empty())?;
                if lines.len() > *max || (!lines.is_empty() && lines.len() < *min) {
                    return Err(format!("{label}: {min}-{max} Zeilen"));
                }
                let mut values = Vec::new();
                for (index, text) in lines.iter().enumerate() {
                    let nr = index + 1;
                    if chars(text) > *line_max || text.chars().any(char::is_control) {
                        return Err(format!("{label}, Zeile {nr}: höchstens {line_max} Zeichen"));
                    }
                    values.push(match line {
                        Line::Text => json!(text),
                        Line::Link => {
                            let (title, url) = text.rsplit_once(char::is_whitespace).unwrap_or(("", text));
                            if !link_ok(url) {
                                return Err(format!("{label}, Zeile {nr}: am Ende eine Adresse mit https://"));
                            }
                            json!({"title": title.trim(), "url": url})
                        }
                        Line::Date => {
                            let mut words = text.splitn(2, char::is_whitespace);
                            let date = words.next().unwrap_or_default();
                            let rest = words.next().unwrap_or_default().trim();
                            let (time, title) = match rest.split_once(char::is_whitespace) {
                                Some((time, title)) if time_ok(time) => (Some(time), title.trim()),
                                _ if time_ok(rest) => (Some(rest), ""),
                                _ => (None, rest),
                            };
                            if !date_ok(date) || title.is_empty() {
                                return Err(format!(
                                    "{label}, Zeile {nr}: „JJJJ-MM-TT Titel“ (Uhrzeit HH:MM optional)"
                                ));
                            }
                            json!({"date": date, "time": time, "title": title})
                        }
                        Line::Parts(count) => {
                            let mut parts: Vec<String> =
                                text.splitn(*count, '|').map(|part| part.trim().to_owned()).collect();
                            if parts.first().is_none_or(String::is_empty) {
                                return Err(format!("{label}, Zeile {nr}: vorne etwas vor dem ersten „|“"));
                            }
                            parts.resize(*count, String::new());
                            json!(parts)
                        }
                    });
                }
                Ok((json!(lines.join("\n")), json!(values)))
            }
            Kind::Choice { options } => {
                let text = text_of(value)?;
                if text.is_empty() {
                    needed(true)?;
                    return Ok((json!(""), json!("")));
                }
                if !options.iter().any(|(option, _)| *option == text) {
                    return Err(format!("{label}: eine der Möglichkeiten"));
                }
                Ok((json!(text), json!(text)))
            }
            Kind::Switch => match value {
                None => Ok((json!(false), json!(false))),
                Some(Value::Bool(on)) => Ok((json!(on), json!(on))),
                Some(_) => Err(format!("{label}: an oder aus")),
            },
            Kind::Date => {
                let text = text_of(value)?.trim().to_owned();
                if !text.is_empty() && !date_ok(&text) {
                    return Err(format!("{label}: ein Datum JJJJ-MM-TT"));
                }
                needed(text.is_empty())?;
                Ok((json!(text), json!(text)))
            }
            Kind::Time => {
                let text = text_of(value)?.trim().to_owned();
                if !text.is_empty() && !time_ok(&text) {
                    return Err(format!("{label}: eine Uhrzeit HH:MM"));
                }
                needed(text.is_empty())?;
                Ok((json!(text), json!(text)))
            }
            Kind::Link => {
                let text = text_of(value)?.trim().to_owned();
                if !text.is_empty() && !link_ok(&text) {
                    return Err(format!("{label}: eine Adresse mit https://"));
                }
                needed(text.is_empty())?;
                Ok((json!(text), json!(text)))
            }
        }
    }
}

fn embedded(id: &str) -> Option<&'static Embedded> {
    TEMPLATES.iter().find(|template| template.id == id)
}

/// The spec of a built-in template.
pub fn spec(id: &str) -> Option<Spec> {
    embedded(id).and_then(|template| Spec::parse(template.spec).ok())
}

/// `GET /api/templates`: the templates with their fields and the designs.
pub fn list() -> Value {
    let templates: Vec<Value> = TEMPLATES
        .iter()
        .filter_map(|template| {
            let spec = Spec::parse(template.spec).ok()?;
            Some(json!({
                "id": template.id, "name": spec.name, "description": spec.description, "records": spec.records,
                "fields": spec.fields_json(),
            }))
        })
        .collect();
    let designs: Vec<Value> =
        DESIGNS.iter().map(|design| json!({"id": design.id, "name": design.name, "preview": design.preview})).collect();
    json!({"templates": templates, "designs": designs})
}

/// The files of a site from a template: shared files, the template's, `design.css`, `config.json`, maybe
/// `server.records`.
pub fn site_files(template: &str, design: &str, config: &Map<String, Value>) -> Result<Vec<(String, Vec<u8>)>, String> {
    let embedded = embedded(template).ok_or("Diese Vorlage gibt es nicht.")?;
    let spec = Spec::parse(embedded.spec)?;
    let design = DESIGNS.iter().find(|candidate| candidate.id == design).ok_or("Dieses Design gibt es nicht.")?;
    let mut files: Vec<(String, Vec<u8>)> =
        SHARED.iter().chain(embedded.files.iter()).map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec())).collect();
    files.push(("design.css".into(), design.css.to_vec()));
    let config = json!({"template": template, "settings": config});
    files.push(("config.json".into(), serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?));
    if spec.records {
        files.push((bridge_sdk::RECORDS_FILE.into(), b"builtin:records\n".to_vec()));
    }
    Ok(files)
}

fn random_hex() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn saved_path(dir: &Path, app: &Id) -> PathBuf {
    dir.join(TEMPLATES_DIR).join(format!("{}.json", app.as_str()))
}

/// The saved template of an app of this owner node: `{template, design, settings, name}` (settings only of fields
/// the template still has).
pub fn saved(dir: &Path, app: &Id) -> Option<Value> {
    let path = saved_path(dir, app);
    if std::fs::metadata(&path).ok()?.len() > MAX_SAVED_BYTES {
        return None;
    }
    let Ok(Value::Object(mut saved)) = parse_strict(&std::fs::read(&path).ok()?, MAX_SAVED_BYTES as usize) else {
        return None;
    };
    let spec = spec(saved.get("template")?.as_str()?)?;
    if let Some(Value::Object(settings)) = saved.get_mut("settings") {
        settings.retain(|key, _| spec.fields.iter().any(|field| &field.key == key));
    }
    Some(Value::Object(saved))
}

/// Puts the template id (or `null`) on every app key `{id, name}` of the dashboard, and whether it has entries.
pub fn annotate(dir: &Path, app_keys: &mut [Value]) {
    for key in app_keys {
        let template = key["id"]
            .as_str()
            .and_then(|id| Id::parse(id).ok())
            .and_then(|id| saved(dir, &id))
            .and_then(|saved| saved.get("template").and_then(Value::as_str).map(str::to_owned));
        let records = template.as_deref().and_then(spec).is_some_and(|spec| spec.records);
        key["template"] = json!(template);
        key["records"] = json!(records);
    }
}

/// Forgets the saved template of a deleted app (best effort).
pub fn forget(dir: &Path, app: &Id) {
    let _ = std::fs::remove_file(saved_path(dir, app));
}

/// Writes `files` into a new folder below `dir/templates/`.
/// Most leftover build folders removed in one go.
const MAX_SWEPT: usize = 16;

/// Removes a build folder; on Windows a virus scanner may still hold a file a moment, so it tries a few times.
fn remove_build(folder: &Path) {
    for attempt in 0..10 {
        if std::fs::remove_dir_all(folder).is_ok() || !folder.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100 * (attempt + 1)));
    }
    tracing::warn!(folder = %folder.display(), "build folder of a template not removed (tried again next time)");
}

/// A build folder older than this is a leftover (a publish takes far less) - younger ones may be in use.
const LEFTOVER_AGE: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Removes build folders an earlier publish left behind - at least `min_age` old, at most [`MAX_SWEPT`].
fn sweep_builds(dir: &Path, min_age: std::time::Duration) {
    let Ok(entries) = std::fs::read_dir(dir.join(TEMPLATES_DIR)) else { return };
    let old = |entry: &std::fs::DirEntry| {
        entry
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|time| time.elapsed().ok())
            .is_some_and(|age| age >= min_age)
    };
    let leftovers = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("build-"))
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter(old)
        .take(MAX_SWEPT);
    for entry in leftovers {
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

fn build(dir: &Path, files: &[(String, Vec<u8>)]) -> Result<PathBuf, String> {
    sweep_builds(dir, LEFTOVER_AGE);
    let folder = dir.join(TEMPLATES_DIR).join(format!("build-{}", random_hex()));
    std::fs::create_dir_all(&folder).map_err(|e| format!("Ordner für die Vorlage: {e}"))?;
    for (path, bytes) in files {
        if let Err(error) = std::fs::write(folder.join(path), bytes) {
            let _ = std::fs::remove_dir_all(&folder);
            return Err(format!("Vorlage schreiben: {error}"));
        }
    }
    Ok(folder)
}

/// Saves the raw settings (write, then rename).
fn save(dir: &Path, app: &Id, saved: &Value) -> Result<(), String> {
    let path = saved_path(dir, app);
    let temp = path.with_extension("json.new");
    let bytes = serde_json::to_vec_pretty(saved).map_err(|e| e.to_string())?;
    std::fs::write(&temp, bytes).and_then(|()| std::fs::rename(&temp, &path)).map_err(|e| e.to_string())
}

fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or_default()
}

/// `POST /api/nodes/<id>/template-publish` `{"template","settings","design"?,"name"|"app","description"?,
/// "address"?}`: a new website from a template - or, with `app`, a new version with new settings ("Bearbeiten").
pub async fn publish(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let template = text(body, "template").trim();
    let spec = spec(template).ok_or("Diese Vorlage gibt es nicht.")?;
    let input = match body.get("settings") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(settings)) => settings.clone(),
        Some(_) => return Err("Einstellungen: ein Objekt".into()),
    };
    let (raw, config) = spec.check(&input)?;
    let design = match text(body, "design").trim() {
        "" => DESIGNS[0].id,
        design => DESIGNS.iter().find(|candidate| candidate.id == design).ok_or("Dieses Design gibt es nicht.")?.id,
    };
    let mut request = body.clone();
    if text(body, "app").trim().is_empty() && text(body, "name").trim().is_empty() {
        request.insert("name".into(), json!(spec.name));
    }
    let checked = crate::sites::checked_request(app, id, &request).await?;
    let files = site_files(template, design, &config)?;
    let dir = app.node_dir(&entry_of(app, id).await?);
    let (build_dir, files_dir) = (dir.clone(), dir.clone());
    let (folder, info) = tokio::task::spawn_blocking(move || {
        let folder = build(&build_dir, &files)?;
        match crate::sites::scan(&folder, START) {
            Ok(info) => Ok((folder, info)),
            Err(error) => {
                let _ = std::fs::remove_dir_all(&folder);
                Err(error)
            }
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    let problems = info.problems(START);
    let result = if let Some(problem) = problems.into_iter().next() {
        Err(problem)
    } else {
        crate::sites::publish_folder(app, id, checked, &folder, &info, START).await
    };
    let cleanup = folder.clone();
    let _ = tokio::task::spawn_blocking(move || remove_build(&cleanup)).await;
    let mut done = result?;
    let app_id = done["app"].as_str().and_then(|raw| Id::parse(raw).ok()).ok_or("keine App-ID")?;
    let saved = json!({
        "template": template, "design": design, "settings": raw, "name": request.get("name"),
        "saved": crate::now_ms(),
    });
    let saved_error =
        tokio::task::spawn_blocking(move || save(&files_dir, &app_id, &saved)).await.map_err(|e| e.to_string())?.err();
    done["template"] = json!(template);
    done["saved_error"] = json!(saved_error);
    Ok(done)
}

/// `POST /api/nodes/<id>/template-load` `{"app"}`: the saved template of an app of the owner node ("Bearbeiten").
pub async fn load(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    let dir = app.node_dir(&entry);
    let app_id = Id::parse(text(body, "app").trim()).map_err(|_| "keine App-ID".to_owned())?;
    tokio::task::spawn_blocking(move || saved(&dir, &app_id))
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Für diese App ist keine Vorlage gespeichert.".to_owned())
}

/// An error of the node's moderation path in German.
fn moderation_error(error: String) -> String {
    if error.contains("NOT_FOUND") {
        "Diese Website hat auf deinem Owner-Knoten keine Einträge (sie läuft dort nicht oder ohne Einträge).".into()
    } else {
        error
    }
}

/// `POST /api/nodes/<id>/site-entries` `{"app","before"?}`: the newest entries of a website with entries hosted by
/// the owner node (moderation, docs/13 §6).
pub async fn entries(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    let admin = crate::ops::admin_client(app, &entry)?;
    let app_id = Id::parse(text(body, "app").trim()).map_err(|_| "keine App-ID".to_owned())?;
    let before = match body.get("before") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_i64().ok_or("before: eine Zeit")?),
    };
    crate::ops::patient(|| admin.app_entries(&app_id, before)).await.map_err(moderation_error)
}

/// `POST /api/nodes/<id>/site-entry-remove` `{"app","c","id"}`: removes anybody's entry - at every host of the site.
pub async fn remove_entry(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    let admin = crate::ops::admin_client(app, &entry)?;
    let app_id = Id::parse(text(body, "app").trim()).map_err(|_| "keine App-ID".to_owned())?;
    let (collection, entry_id) = (text(body, "c"), text(body, "id"));
    crate::ops::patient(|| admin.app_entry_remove(&app_id, collection, entry_id)).await.map_err(moderation_error)?;
    Ok(json!({"ok": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    /// Every built-in template parses, its defaults are valid and the site has everything the page loads.
    #[test]
    fn built_in_templates_are_complete() -> Result<(), String> {
        assert!(TEMPLATES.len() >= 13);
        let ids: HashSet<&str> = TEMPLATES.iter().map(|template| template.id).collect();
        assert_eq!(ids.len(), TEMPLATES.len(), "unique ids");
        for template in TEMPLATES {
            let spec = Spec::parse(template.spec).map_err(|e| format!("{}: {e}", template.id))?;
            let (_, config) = spec.check(&Map::new()).map_err(|e| format!("{} defaults: {e}", template.id))?;
            for design in DESIGNS {
                let files = site_files(template.id, design.id, &config)?;
                let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
                for needed in ["index.html", "app.js", "bridge.js", "login.js", "base.css", "design.css", "config.json"]
                {
                    assert!(names.contains(&needed), "{}: {needed}", template.id);
                }
                assert_eq!(names.contains(&"server.records"), spec.records, "{}", template.id);
                for name in &names {
                    bridge_core::app::check_path(name).map_err(|e| format!("{name}: {e}"))?;
                }
                let css = String::from_utf8_lossy(design.css);
                for color in design.preview {
                    assert!(css.contains(color), "{}: preview {color}", design.id);
                }
                for variable in
                    ["--bg", "--fg", "--muted", "--accent", "--on-accent", "--card", "--line", "--radius", "--font"]
                {
                    assert!(css.contains(&format!("{variable}:")), "{}: {variable}", design.id);
                }
            }
            // The page never puts a setting in as HTML.
            for (name, bytes) in SHARED.iter().chain(template.files.iter()) {
                let code = String::from_utf8_lossy(bytes);
                for bad in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("] {
                    assert!(!code.contains(bad), "{}/{name}: {bad}", template.id);
                }
            }
        }
        let listed = list();
        assert_eq!(listed["templates"].as_array().map(Vec::len), Some(TEMPLATES.len()));
        assert_eq!(listed["designs"][0]["id"], "hell");
        Ok(())
    }

    #[test]
    fn settings_are_checked() -> Result<(), String> {
        let dates = spec("termine").ok_or("no termine")?;
        let (raw, config) = dates.check(&object(json!({
            "title": "  Treffen  ",
            "text": "Zeile eins\r\nZeile zwei",
            "dates": "2026-12-24 18:30 Bescherung\n\n2027-02-28 Fasching\n",
            "rsvp": false,
        })))?;
        assert_eq!(raw["title"], "Treffen");
        assert_eq!(raw["dates"], "2026-12-24 18:30 Bescherung\n2027-02-28 Fasching");
        assert_eq!(config["text"], "Zeile eins\nZeile zwei");
        assert_eq!(
            config["dates"],
            json!([{"date": "2026-12-24", "time": "18:30", "title": "Bescherung"},
                   {"date": "2027-02-28", "time": null, "title": "Fasching"}])
        );
        assert_eq!(config["rsvp"], false);
        // Absent settings take the default; the raw settings can be checked again (Bearbeiten).
        let (again, _) = dates.check(&raw)?;
        assert_eq!(again, raw);
        let (defaults, _) = dates.check(&Map::new())?;
        assert_eq!(defaults["rsvp"], true);

        let card = spec("visitenkarte").ok_or("no visitenkarte")?;
        let (_, config) = card.check(&object(json!({
            "name": "Paddy", "links": ["Blog https://example.org/a?b=1", "https://example.com"],
        })))?;
        assert_eq!(
            config["links"],
            json!([{"title": "Blog", "url": "https://example.org/a?b=1"}, {"title": "", "url": "https://example.com"}])
        );
        let faq = spec("faq").ok_or("no faq")?;
        let (_, config) =
            faq.check(&object(json!({"questions": "Wann? | Morgen | Rest\nWo?|Hier\nNur eine Frage"})))?;
        assert_eq!(config["questions"], json!([["Wann?", "Morgen | Rest"], ["Wo?", "Hier"], ["Nur eine Frage", ""]]));
        let poll = spec("umfrage").ok_or("no umfrage")?;
        let (_, config) = poll.check(&object(json!({"answers": "Ja\nNein"})))?;
        assert_eq!(config["answers"], json!(["Ja", "Nein"]));
        Ok(())
    }

    /// Attack: whatever a form sends - unknown settings, wrong kinds, overlong text, control characters, links that
    /// are no https links (or try to break out of the attribute), impossible dates.
    #[test]
    fn bad_settings_are_refused() -> Result<(), String> {
        let card = spec("visitenkarte").ok_or("no visitenkarte")?;
        let poll = spec("umfrage").ok_or("no umfrage")?;
        let dates = spec("termine").ok_or("no termine")?;
        let book = spec("gaestebuch").ok_or("no gaestebuch")?;
        let countdown = spec("countdown").ok_or("no countdown")?;
        let faq = spec("faq").ok_or("no faq")?;
        let cases = [
            (&card, json!({"name": "x", "admin": true}), "Unbekannte Einstellung"),
            (&card, json!({"name": ""}), "bitte ausfüllen"),
            (&card, json!({"name": 5}), "ein Text"),
            (&card, json!({"name": "x".repeat(61)}), "höchstens 60"),
            (&card, json!({"name": "a\nb"}), "eine Zeile"),
            (&card, json!({"text": "a\u{0}b"}), "höchstens"),
            (&card, json!({"links": "Böse javascript:alert(1)"}), "https://"),
            (&card, json!({"links": "Böse http://example.org"}), "https://"),
            (&card, json!({"links": "x https://a\"onmouseover=alert(1)"}), "https://"),
            (&card, json!({"links": "x https:///pfad"}), "https://"),
            (&card, json!({"links": {"a": 1}}), "Zeilen"),
            (&card, json!({"links": [1, 2]}), "Zeilen"),
            (&card, json!({"links": "x https://a.b\n".repeat(13)}), "Zeilen"),
            (&poll, json!({"answers": "Nur eine"}), "2-8 Zeilen"),
            (&poll, json!({"answers": ""}), "bitte ausfüllen"),
            (&poll, json!({"answers": "x".repeat(101) + "\nb"}), "höchstens 100"),
            (&dates, json!({"dates": "2026-02-30 Gibt es nicht"}), "JJJJ-MM-TT"),
            (&dates, json!({"dates": "2026-12-24"}), "JJJJ-MM-TT"),
            (&dates, json!({"dates": "24.12.2026 Weihnachten"}), "JJJJ-MM-TT"),
            (&dates, json!({"dates": "2026-12-24 18:00"}), "JJJJ-MM-TT"),
            (&book, json!({"login_only": "ja"}), "an oder aus"),
            (&countdown, json!({"time": "25:00"}), "HH:MM"),
            (&faq, json!({"questions": "| Antwort ohne Frage"}), "vor dem ersten"),
            (&countdown, json!({"date": ""}), "bitte ausfüllen"),
        ];
        for (spec, input, expected) in cases {
            let error = spec.check(&object(input.clone())).err().ok_or(format!("accepted: {input}"))?;
            assert!(error.contains(expected), "{input}: {error}");
        }
        // A huge paste is refused before it is split.
        assert!(card.check(&object(json!({"links": "x".repeat(100_000)}))).is_err());
        Ok(())
    }

    /// Attack: a broken or hostile template.json is refused (only built-in ones exist, but design plugins come).
    #[test]
    fn bad_specs_are_refused() {
        let field = |extra: Value| {
            let mut field = json!({"key": "a", "label": "A", "type": "text"});
            if let (Some(field), Value::Object(extra)) = (field.as_object_mut(), extra) {
                field.extend(extra);
            }
            json!({"name": "T", "fields": [field]}).to_string()
        };
        assert!(Spec::parse(&field(json!({}))).is_ok());
        for bad in [
            field(json!({"key": "A"})),
            field(json!({"type": "html"})),
            field(json!({"max": 0})),
            field(json!({"max": 100_000})),
            field(json!({"default": "x".repeat(81)})),
            field(json!({"type": "choice", "options": [{"value": "a", "label": "A"}]})),
            field(json!({"type": "list", "line": "script"})),
            field(json!({"type": "list", "line": "parts", "parts": 9})),
            field(json!({"type": "list", "min": 5, "max": 2})),
            json!({"name": "T", "fields": []}).to_string(),
            json!({"name": "", "fields": [{"key": "a", "label": "A", "type": "text"}]}).to_string(),
            json!({"name": "T", "fields": [{"key": "a", "label": "A", "type": "text"},
                                           {"key": "a", "label": "B", "type": "text"}]})
            .to_string(),
            "[]".to_owned(),
        ] {
            assert!(Spec::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dates_times_links() {
        for good in ["2026-01-01", "2028-02-29", "2200-12-31", "1970-01-01"] {
            assert!(date_ok(good), "{good}");
        }
        for bad in [
            "2027-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-1-01",
            "20261-01-01",
            "1969-12-31",
            "2026-01-32",
            "+026-01-01",
        ] {
            assert!(!date_ok(bad), "{bad}");
        }
        assert!(time_ok("00:00") && time_ok("23:59") && !time_ok("24:00") && !time_ok("9:00") && !time_ok("12:60"));
        assert!(link_ok("https://example.org/a?b=c#d"));
        for bad in ["http://example.org", "https://", "https://a b", "javascript:alert(1)", "https://a<b", "HTTPS://a"]
        {
            assert!(!link_ok(bad), "{bad}");
        }
    }

    #[test]
    fn saved_settings_and_cleanup() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir.path().join(TEMPLATES_DIR)).map_err(|e| e.to_string())?;
        let key = bridge_core::Identity::generate(&mut OsRng);
        let app = key.id().clone();
        save(
            dir.path(),
            &app,
            &json!({"template": "gaestebuch", "design": "bunt", "settings": {"title": "Hi", "alt": 1}}),
        )?;
        let back = saved(dir.path(), &app).ok_or("not saved")?;
        assert_eq!(back["settings"], json!({"title": "Hi"}), "fields the template no longer has are dropped");
        let mut keys = vec![json!({"id": app.as_str(), "name": "x"}), json!({"id": "kaputt", "name": "y"})];
        annotate(dir.path(), &mut keys);
        assert_eq!((keys[0]["template"].clone(), keys[1]["template"].clone()), (json!("gaestebuch"), Value::Null));
        assert_eq!((keys[0]["records"].clone(), keys[1]["records"].clone()), (json!(true), json!(false)));
        // Attack: an oversized or foreign file is not read.
        std::fs::write(saved_path(dir.path(), &app), vec![b' '; 70 * 1024]).map_err(|e| e.to_string())?;
        assert!(saved(dir.path(), &app).is_none());
        save(dir.path(), &app, &json!({"template": "gibtsnicht", "settings": {}}))?;
        assert!(saved(dir.path(), &app).is_none());
        forget(dir.path(), &app);
        assert!(!saved_path(dir.path(), &app).exists());
        // A build folder holds exactly the files.
        let (_, config) = spec("umfrage").ok_or("no umfrage")?.check(&Map::new())?;
        let files = site_files("umfrage", "dunkel", &config)?;
        let stale = dir.path().join(TEMPLATES_DIR).join("build-alt");
        std::fs::create_dir_all(&stale).map_err(|e| e.to_string())?;
        let folder = build(dir.path(), &files)?;
        assert!(stale.exists(), "a young build folder may be in use - kept");
        sweep_builds(dir.path(), std::time::Duration::ZERO);
        assert!(!stale.exists() && !folder.exists(), "leftovers are swept");
        let folder = build(dir.path(), &files)?;
        let info = crate::sites::scan(&folder, START)?;
        assert_eq!((info.files, info.problems(START)), (files.len(), Vec::<String>::new()));
        let written: Value =
            serde_json::from_slice(&std::fs::read(folder.join("config.json")).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        assert_eq!(written["settings"]["answers"], json!(["Freitag", "Samstag", "Sonntag"]));
        assert!(site_files("gibtsnicht", "hell", &config).is_err());
        assert!(site_files("umfrage", "neon", &config).is_err());
        Ok(())
    }
}
