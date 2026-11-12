//! Login definition v1 parsing and validation (same rules and order as
//! `definition.ts`). Order: object check, `schemaVersion > 1` typed refusal,
//! canonical JSON constraints and the document size bound (enforced while
//! canonicalizing; raw text is bounded before parsing), then the schema
//! (`x-*` keys allowed at every object level, any other unknown key refused,
//! no `null` outside extensions) and the cross-field rules.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::canonical::{canonical_json, safe_integer, sha256};
use crate::limits::{
    COMMAND_MAX_BYTES, DEFINITION_PATH_MAX_BYTES, DESCRIPTION_MAX_CHARS, DISPLAY_NAME_MAX_CHARS,
    DOCUMENT_TEXT_MAX_BYTES, EGRESS_DOMAINS_MAX, ENV_DESCRIPTION_MAX_CHARS, ENV_ENTRIES_MAX,
    ENV_NAME_MAX_BYTES, FILE_PATHS_MAX, ID_MAX_BYTES, INSTALL_NOTES_MAX_CHARS, MAX_BYTES_DEFAULT,
    MAX_BYTES_MAX, MAX_BYTES_MIN, SCHEMA_VERSION,
};
use crate::net::{dns_name_problem, format_problem, header_name_problem, parse_upstream};
use crate::paths::{path_below, path_problem, paths_overlap};

// --- Errors -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionErrorCode {
    Invalid,
    SchemaVersionUnsupported,
    /// The stored document no longer matches its pinned digest.
    Corrupt,
}

impl DefinitionErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "definition.invalid",
            Self::SchemaVersionUnsupported => "definition.schema_version_unsupported",
            Self::Corrupt => "credential.definition_corrupt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {}", code.as_str(), issues.first().map_or("", |i| i.message.as_str()))]
pub struct DefinitionError {
    pub code: DefinitionErrorCode,
    pub issues: Vec<DefinitionIssue>,
}

impl DefinitionError {
    fn invalid(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: DefinitionErrorCode::Invalid,
            issues: vec![DefinitionIssue {
                path: path.into(),
                message: message.into(),
            }],
        }
    }
}

// --- Typed definition ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginMethod {
    DeviceCode,
    Paste,
    Interactive,
    BrowserCallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sharing {
    #[default]
    Exclusive,
    Shareable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rotates {
    Yes,
    No,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Install {
    pub check_command: Option<String>,
    pub command: Option<String>,
    pub needs_root: Option<bool>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub domains: Vec<String>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Login {
    pub command: String,
    pub method: LoginMethod,
    #[serde(default = "default_true")]
    pub done_when_command_exits: bool,
    pub verify_command: Option<String>,
    pub egress: Option<Egress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Proxy {
    pub upstream: String,
    pub header: String,
    pub format: String,
    pub base_url_env: String,
    pub placeholder_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvEntry {
    pub name: String,
    pub description: Option<String>,
    pub required: bool,
    pub proxy: Option<Proxy>,
}

const fn default_max_bytes() -> i64 {
    MAX_BYTES_DEFAULT
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Credentials {
    pub files: Option<Files>,
    pub env: Option<Vec<EnvEntry>>,
    #[serde(default)]
    pub sharing: Sharing,
    #[serde(default)]
    pub rotates: Rotates,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: i64,
}

impl Credentials {
    /// `required ∪ optional`.
    pub fn included_paths(&self) -> impl Iterator<Item = &str> {
        self.files
            .iter()
            .flat_map(|f| f.required.iter().chain(f.optional.iter()))
            .map(String::as_str)
    }

    pub fn excluded_paths(&self) -> impl Iterator<Item = &str> {
        self.files
            .iter()
            .flat_map(|f| f.exclude.iter())
            .map(String::as_str)
    }

    pub fn required_paths(&self) -> impl Iterator<Item = &str> {
        self.files
            .iter()
            .flat_map(|f| f.required.iter())
            .map(String::as_str)
    }

    #[must_use]
    pub fn env_entries(&self) -> &[EnvEntry] {
        self.env.as_deref().unwrap_or_default()
    }

    /// `maxBytes` as a byte count (validated to `1..=4 194 304`).
    #[must_use]
    pub fn max_bytes(&self) -> usize {
        usize::try_from(self.max_bytes).unwrap_or(0)
    }
}

/// A validated definition with defaults applied. `x-*` extensions are part of
/// the stored document (and its digest) but are not represented here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoginDefinition {
    pub schema_version: i64,
    pub id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub install: Option<Install>,
    pub login: Login,
    pub credentials: Credentials,
}

/// Accepted, but wssp cannot run the flow yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionWarning {
    BrowserCallbackUnsupported,
}

impl DefinitionWarning {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserCallbackUnsupported => "login.method.browser_callback_unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDefinition {
    pub definition: LoginDefinition,
    pub warnings: Vec<DefinitionWarning>,
    /// SHA-256 of the bounded canonical JSON the parse produced: the
    /// definition digest, without canonicalizing the document again.
    pub digest: [u8; 32],
}

// --- Parsing -------------------------------------------------------------------

/// `x-` followed by at least one character.
#[must_use]
pub fn is_extension_key(key: &str) -> bool {
    key.len() > 2 && key.starts_with("x-")
}

/// Drops `x-*` keys at every schema object level, refuses `null` outside
/// extensions and rewrites integral numbers as integers so serde sees what
/// JavaScript sees.
fn schema_view(value: &Value, path: &str) -> Result<Value, DefinitionError> {
    match value {
        Value::Null => Err(DefinitionError::invalid(
            path,
            "null is not allowed (omit the field)",
        )),
        Value::Number(n) => safe_integer(n)
            .map(Value::from)
            .ok_or_else(|| DefinitionError::invalid(path, "numbers must be safe integers")),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| schema_view(item, &format!("{path}.{i}")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                if is_extension_key(key) {
                    continue;
                }
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                out.insert(key.clone(), schema_view(item, &child)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// Object check and the typed `schemaVersion > 1` refusal, which precede everything else.
fn precheck(document: &Value) -> Result<(), DefinitionError> {
    let Value::Object(object) = document else {
        return Err(DefinitionError::invalid(
            "",
            "definition must be a JSON object",
        ));
    };
    if let Some(Value::Number(n)) = object.get("schemaVersion")
        && let Some(version) = n.as_f64()
        && version.fract() == 0.0
        && version > SCHEMA_VERSION as f64
    {
        return Err(DefinitionError {
            code: DefinitionErrorCode::SchemaVersionUnsupported,
            issues: vec![DefinitionIssue {
                path: "schemaVersion".into(),
                message: format!("schemaVersion {n} is not supported"),
            }],
        });
    }
    Ok(())
}

/// Schema and cross-field rules, given the document's bounded canonical JSON.
fn validate(document: &Value, canonical: &str) -> Result<ParsedDefinition, DefinitionError> {
    let view = schema_view(document, "")?;
    let definition: LoginDefinition =
        serde_json::from_value(view).map_err(|e| DefinitionError::invalid("", e.to_string()))?;
    let mut issues = Vec::new();
    field_issues(&definition, &mut issues);
    if issues.is_empty() {
        semantic_issues(&definition, &mut issues);
    }
    if !issues.is_empty() {
        return Err(DefinitionError {
            code: DefinitionErrorCode::Invalid,
            issues,
        });
    }
    let mut warnings = Vec::new();
    if definition.login.method == LoginMethod::BrowserCallback {
        warnings.push(DefinitionWarning::BrowserCallbackUnsupported);
    }
    Ok(ParsedDefinition {
        definition,
        warnings,
        digest: sha256(canonical.as_bytes()),
    })
}

/// Validates a login definition document.
pub fn parse_definition(document: &Value) -> Result<ParsedDefinition, DefinitionError> {
    precheck(document)?;
    let canonical =
        canonical_json(document).map_err(|e| DefinitionError::invalid(e.path, e.message))?;
    validate(document, &canonical)
}

/// Parses JSON text of at most [`DOCUMENT_TEXT_MAX_BYTES`] bytes (checked
/// before parsing), then [`parse_definition`]. Unparseable text (including a
/// lone surrogate escape) is `definition.invalid`.
pub fn parse_definition_str(text: &str) -> Result<(Value, ParsedDefinition), DefinitionError> {
    if text.len() > DOCUMENT_TEXT_MAX_BYTES {
        return Err(DefinitionError::invalid(
            "",
            format!("definition text exceeds {DOCUMENT_TEXT_MAX_BYTES} bytes"),
        ));
    }
    let document: Value =
        serde_json::from_str(text).map_err(|e| DefinitionError::invalid("", e.to_string()))?;
    let parsed = parse_definition(&document)?;
    Ok((document, parsed))
}

/// Loads a stored definition for use: the digest is recomputed from the stored
/// document's bounded canonical JSON and must equal the pinned digest before
/// anything derives from it. The same canonical text is then validated.
pub fn load_verified_definition(
    document: &Value,
    expected_digest: &[u8; 32],
) -> Result<ParsedDefinition, DefinitionError> {
    match canonical_json(document) {
        Ok(canonical) if &sha256(canonical.as_bytes()) == expected_digest => {
            precheck(document)?;
            validate(document, &canonical)
        }
        _ => Err(DefinitionError {
            code: DefinitionErrorCode::Corrupt,
            issues: vec![DefinitionIssue {
                path: String::new(),
                message: "stored definition does not match its digest".into(),
            }],
        }),
    }
}

// --- Field rules -----------------------------------------------------------------

struct Issues<'a>(&'a mut Vec<DefinitionIssue>);

impl Issues<'_> {
    fn add(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(DefinitionIssue {
            path: path.into(),
            message: message.into(),
        });
    }
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

fn command_problem(s: &str) -> Option<&'static str> {
    if s.is_empty() {
        Some("must not be empty")
    } else if s.len() > COMMAND_MAX_BYTES {
        Some("is too long")
    } else if s.contains('\0') {
        Some("must not contain NUL")
    } else {
        None
    }
}

/// POSIX name, at most 128 bytes, not `HOME`/`SHELL`/`TERM`/`PATH`/`LD_*`.
#[must_use]
pub fn env_name_problem(name: &str) -> Option<&'static str> {
    let b = name.as_bytes();
    let posix = !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    if !posix {
        return Some("must be a POSIX environment variable name");
    }
    if name.len() > ENV_NAME_MAX_BYTES {
        return Some("is too long");
    }
    if matches!(name, "HOME" | "SHELL" | "TERM" | "PATH") || name.starts_with("LD_") {
        return Some("is reserved");
    }
    None
}

fn id_ok(id: &str) -> bool {
    let b = id.as_bytes();
    let ok = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty() && b.len() <= ID_MAX_BYTES && ok(&b[0]) && b.iter().all(|c| ok(c) || *c == b'-')
}

fn field_issues(def: &LoginDefinition, out: &mut Vec<DefinitionIssue>) {
    let mut issues = Issues(out);
    let mut check = |path: &str, problem: Option<&str>| {
        if let Some(p) = problem {
            issues.add(path, p);
        }
    };
    if def.schema_version != SCHEMA_VERSION {
        check("schemaVersion", Some("must be 1"));
    }
    if !id_ok(&def.id) {
        check("id", Some("must match ^[a-z0-9][a-z0-9-]{0,62}$"));
    }
    let name = &def.display_name;
    if name.is_empty() || chars(name) > DISPLAY_NAME_MAX_CHARS {
        check("displayName", Some("must be 1-80 characters"));
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        check("displayName", Some("must not contain control characters"));
    }
    if def
        .description
        .as_deref()
        .is_some_and(|d| chars(d) > DESCRIPTION_MAX_CHARS)
    {
        check("description", Some("is too long"));
    }
    if let Some(install) = &def.install {
        if let Some(c) = &install.check_command {
            check("install.checkCommand", command_problem(c));
        }
        if let Some(c) = &install.command {
            check("install.command", command_problem(c));
        }
        if install
            .notes
            .as_deref()
            .is_some_and(|n| chars(n) > INSTALL_NOTES_MAX_CHARS)
        {
            check("install.notes", Some("is too long"));
        }
    }
    check("login.command", command_problem(&def.login.command));
    if let Some(c) = &def.login.verify_command {
        check("login.verifyCommand", command_problem(c));
    }
    if let Some(egress) = &def.login.egress {
        if egress.domains.len() > EGRESS_DOMAINS_MAX {
            check("login.egress.domains", Some("has too many domains"));
        }
        for (i, domain) in egress.domains.iter().enumerate() {
            check(
                &format!("login.egress.domains.{i}"),
                dns_name_problem(domain),
            );
        }
    }
    let creds = &def.credentials;
    if let Some(files) = &creds.files {
        for (field, list) in [
            ("required", &files.required),
            ("optional", &files.optional),
            ("exclude", &files.exclude),
        ] {
            if list.len() > FILE_PATHS_MAX {
                check(
                    &format!("credentials.files.{field}"),
                    Some("has too many paths"),
                );
            }
            for (i, path) in list.iter().enumerate() {
                check(
                    &format!("credentials.files.{field}.{i}"),
                    path_problem(path, DEFINITION_PATH_MAX_BYTES),
                );
            }
        }
    }
    let env = creds.env_entries();
    if env.len() > ENV_ENTRIES_MAX {
        check("credentials.env", Some("has too many entries"));
    }
    for (i, entry) in env.iter().enumerate() {
        let at = format!("credentials.env.{i}");
        check(&format!("{at}.name"), env_name_problem(&entry.name));
        if entry
            .description
            .as_deref()
            .is_some_and(|d| chars(d) > ENV_DESCRIPTION_MAX_CHARS)
        {
            check(&format!("{at}.description"), Some("is too long"));
        }
        if let Some(proxy) = &entry.proxy {
            check(
                &format!("{at}.proxy.upstream"),
                parse_upstream(&proxy.upstream).err(),
            );
            check(
                &format!("{at}.proxy.header"),
                header_name_problem(&proxy.header),
            );
            check(&format!("{at}.proxy.format"), format_problem(&proxy.format));
            check(
                &format!("{at}.proxy.baseUrlEnv"),
                env_name_problem(&proxy.base_url_env),
            );
            if let Some(p) = &proxy.placeholder_env {
                check(&format!("{at}.proxy.placeholderEnv"), env_name_problem(p));
            }
        }
    }
    if !(MAX_BYTES_MIN..=MAX_BYTES_MAX).contains(&creds.max_bytes) {
        check("credentials.maxBytes", Some("must be 1-4194304"));
    }
}

/// Cross-field rules (identical to `semanticIssues` in `definition.ts`).
fn semantic_issues(def: &LoginDefinition, out: &mut Vec<DefinitionIssue>) {
    let mut issues = Issues(out);
    let creds = &def.credentials;
    let files = creds.files.clone().unwrap_or_default();
    let total = files.required.len() + files.optional.len() + files.exclude.len();
    if total > FILE_PATHS_MAX {
        issues.add("credentials.files", "too many paths in total");
    }
    let included: Vec<&str> = creds.included_paths().collect();
    for (i, a) in included.iter().enumerate() {
        for b in &included[i + 1..] {
            if paths_overlap(a, b) {
                issues.add("credentials.files", "included paths overlap");
            }
        }
    }
    for (i, path) in files.exclude.iter().enumerate() {
        if !included.iter().any(|dir| path_below(path, dir)) {
            issues.add(
                format!("credentials.files.exclude.{i}"),
                "must lie below an included path",
            );
        }
        for other in &files.exclude[i + 1..] {
            if paths_overlap(path, other) {
                issues.add("credentials.files.exclude", "excluded paths overlap");
            }
        }
    }
    let env = creds.env_entries();
    if included.is_empty() && env.is_empty() {
        issues.add("credentials", "declare at least one file path or env entry");
    }
    let mut names = BTreeSet::new();
    for (i, entry) in env.iter().enumerate() {
        if !names.insert(entry.name.as_str()) {
            issues.add(format!("credentials.env.{i}.name"), "duplicate env name");
        }
    }
    let proxied = env.iter().filter(|e| e.proxy.is_some()).count();
    if proxied > 0 {
        if proxied != env.len() {
            issues.add(
                "credentials.env",
                "a proxied definition must proxy every env entry",
            );
        }
        if total > 0 {
            issues.add(
                "credentials.files",
                "a proxied definition must not declare files",
            );
        }
        let mut taken: BTreeMap<&str, &str> = BTreeMap::new();
        for (i, entry) in env.iter().enumerate() {
            let Some(proxy) = &entry.proxy else { continue };
            let mut claims = vec![(proxy.base_url_env.as_str(), "baseUrlEnv")];
            if let Some(p) = &proxy.placeholder_env {
                claims.push((p.as_str(), "placeholderEnv"));
            }
            for (name, field) in claims {
                let own = field == "placeholderEnv" && name == entry.name;
                if (names.contains(name) && !own) || taken.contains_key(name) {
                    issues.add(
                        format!("credentials.env.{i}.proxy.{field}"),
                        "name is already used",
                    );
                }
                taken.insert(name, field);
            }
        }
    }
    if let Some(egress) = &def.login.egress {
        let unique: BTreeSet<&String> = egress.domains.iter().collect();
        if unique.len() != egress.domains.len() {
            issues.add("login.egress.domains", "duplicate domain");
        }
    }
}
