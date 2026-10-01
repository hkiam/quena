//! Sanitized copies of sessions for sharing (support, vendors) and for mocks: credentials,
//! tokens and — depending on the options — personal data are replaced deterministically,
//! without any model or network access.
//!
//! - Headers are all kept; only the values of sensitive ones are replaced (`Authorization`
//!   and its relatives keep their scheme, the credential gets the same pseudonym it gets in
//!   bodies; cookies keep their names and attributes; integrity headers of changed bodies
//!   are dropped).
//! - Names are classified by one word-based rule for fields, parameters and headers
//!   ([`secret_name`]): `pwd`, `otpCode`, `X-Api-Key` are secrets, `passenger` is not.
//! - URLs: user info, the values of secret parameters, tokens in path segments
//!   (`/reset/<token>`) and, with the `ips` option or own patterns, the host are replaced;
//!   other values, path segments and fragments are scanned. URLs inside text are rewritten
//!   the same way.
//! - Bodies are decoded (Content-Encoding, charset) and scrubbed by their structure: JSON
//!   (own tokenizer, so order, whitespace and number formats stay as written), form fields,
//!   multipart parts, XML/SOAP element and attribute values (also named by a sibling or an
//!   attribute: `{"name": "password", "value": …}`, `<Attribute Name="mail">`), HTML tags,
//!   Server-Sent Events, WebSocket messages (inflated, fragments joined); everything else is
//!   scanned as text (`key=value`, `key: value`, `Bearer …`, `Cookie:` lines …). The result
//!   carries no Content-Encoding and a matching Content-Length.
//! - Replacements are pseudonyms: the same value becomes the same `<email-3>` within one
//!   export. The values are only kept as keyed hashes (random key per [`Sanitizer`]); the
//!   numbers follow the order of appearance and say nothing about the value.
//! - The [`RedactionLog`] counts what was replaced, by category and location, without the
//!   values.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::io::Read;
use std::sync::OnceLock;

use crate::diagnostics::auth_facts::encode_component;
use crate::diagnostics::{UrlRewrite, decode_param, has_scheme, redact_authenticate, rewrite_set_cookie, rewrite_url};
use quena_body::Body;
use quena_model::{Headers, SessionDetail, SessionId, SessionKind};
use regex::Regex;
use serde::{Deserialize, Serialize};

// ------------------------------------------------------------------ options

/// What happens to bodies.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum BodyMode {
    /// Kept (scrubbed).
    #[default]
    Keep,
    /// The first [`SanitizeOptions::truncate_kib`] KiB (scrubbed).
    Truncate,
    /// `<body removed: 12 KB application/json>`.
    Placeholder,
    /// Removed.
    Drop,
}

/// What happens to binary bodies (images, fonts, PDF, archives …) and file uploads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum BinaryMode {
    Keep,
    #[default]
    Placeholder,
}

/// What to replace. `Default` is the `support` preset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct SanitizeOptions {
    /// `support`, `gdpr`, `credentials` or `custom` (informational; the flags decide).
    pub preset: String,
    // --- credentials
    /// `Authorization` / `Proxy-Authorization`: only the scheme and the size stay; the
    /// `*-Authenticate` challenges keep their non-secret parameters.
    pub authorization: bool,
    /// `Cookie` / `Set-Cookie`: names and attributes stay, values are replaced.
    pub cookies: bool,
    /// Headers carrying secrets (`x-api-key`, `*token*`, `*secret*`, `x-csrf*` …).
    pub secret_headers: bool,
    /// URL user info and secret query/fragment parameters.
    pub url_secrets: bool,
    /// Secret fields in bodies (`password`, `client_secret`, `access_token` …) and JWTs
    /// anywhere.
    pub body_secrets: bool,
    // --- personal data
    pub emails: bool,
    /// IBAN (mod 97) and card numbers (Luhn).
    pub payment: bool,
    pub phones: bool,
    /// IP addresses in headers and bodies, and the client/server address of the session.
    pub ips: bool,
    /// Fields named like personal data (`firstName`, `street`, `birthDate`, `telefon` …).
    pub personal_fields: bool,
    /// German tax ID (checksum) and social security number (pattern and checksum).
    pub national_ids: bool,
    /// Process name of the session.
    pub process: bool,
    // --- bodies
    pub bodies: BodyMode,
    pub truncate_kib: u32,
    pub binary: BinaryMode,
    /// `<email-3>` (same value, same name) instead of `<email>`.
    pub pseudonyms: bool,
    // --- own rules (names case-insensitive)
    pub extra_headers: Vec<String>,
    /// Query and form parameter names.
    pub extra_params: Vec<String>,
    /// JSON / XML / multipart field names (also used for form fields).
    pub extra_fields: Vec<String>,
    /// Regular expressions; every match is replaced.
    pub patterns: Vec<String>,
}

impl Default for SanitizeOptions {
    fn default() -> Self {
        SanitizeOptions {
            preset: "support".into(),
            authorization: true,
            cookies: true,
            secret_headers: true,
            url_secrets: true,
            body_secrets: true,
            emails: true,
            payment: true,
            phones: false,
            ips: false,
            personal_fields: false,
            national_ids: false,
            process: false,
            bodies: BodyMode::Keep,
            truncate_kib: 64,
            binary: BinaryMode::Placeholder,
            pseudonyms: true,
            extra_headers: vec![],
            extra_params: vec![],
            extra_fields: vec![],
            patterns: vec![],
        }
    }
}

impl SanitizeOptions {
    /// `support`, `gdpr` (strict), or `credentials` (only credentials and tokens, for mocks).
    pub fn preset(name: &str) -> Option<SanitizeOptions> {
        let base = SanitizeOptions::default();
        Some(match name {
            "support" => base,
            "gdpr" => SanitizeOptions {
                preset: "gdpr".into(),
                phones: true,
                ips: true,
                personal_fields: true,
                national_ids: true,
                process: true,
                bodies: BodyMode::Truncate,
                ..base
            },
            "credentials" => SanitizeOptions { preset: "credentials".into(), emails: false, payment: false, binary: BinaryMode::Keep, ..base },
            _ => return None,
        })
    }

    /// The options for generating mocks from sessions: like `base`, but bodies and binary
    /// bodies are kept whole (a mock response must stay a valid response).
    pub fn for_mocks(base: &SanitizeOptions) -> SanitizeOptions {
        SanitizeOptions { bodies: BodyMode::Keep, binary: BinaryMode::Keep, ..base.clone() }
    }

    /// Strict parse (CLI config files): unknown keys are an error that names them. Accepts
    /// the options object itself or the app's saved wrapper `{"options": {…}, "format": …}`.
    /// The lenient `Deserialize` (settings files, forward compatible) stays as it is.
    pub fn from_json_strict(text: &str) -> Result<SanitizeOptions, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
        let serde_json::Value::Object(map) = v else { return Err("expected a JSON object".into()) };
        let wrapper = map.contains_key("options") && map.keys().all(|k| k == "options" || k == "format");
        let obj = if wrapper {
            match map.get("options") {
                Some(serde_json::Value::Object(o)) => o.clone(),
                _ => return Err("\"options\" must be an object".into()),
            }
        } else {
            map
        };
        let known: Vec<String> = match serde_json::to_value(SanitizeOptions::default()) {
            Ok(serde_json::Value::Object(d)) => d.keys().cloned().collect(),
            _ => vec![],
        };
        let mut unknown: Vec<String> = obj.keys().filter(|k| !known.contains(k)).cloned().collect();
        if !unknown.is_empty() {
            unknown.sort();
            return Err(format!("unknown option(s): {} (known: {})", unknown.join(", "), known.join(", ")));
        }
        let opts: SanitizeOptions = serde_json::from_value(serde_json::Value::Object(obj)).map_err(|e| format!("invalid options: {e}"))?;
        opts.validate()?;
        Ok(opts)
    }

    /// The first invalid pattern, if any.
    pub fn validate(&self) -> Result<(), String> {
        for p in &self.patterns {
            Regex::new(p).map_err(|e| format!("invalid pattern {p:?}: {e}"))?;
        }
        Ok(())
    }
}

/// The sanitized export as remembered in the settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct SanitizeExportSettings {
    pub options: SanitizeOptions,
    /// `saz` or `har`.
    pub format: String,
}

impl Default for SanitizeExportSettings {
    fn default() -> Self {
        SanitizeExportSettings { options: SanitizeOptions::default(), format: "saz".into() }
    }
}

// ------------------------------------------------------------------ log

/// Where a value was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loc {
    Header,
    Url,
    Body,
    Ws,
    /// Session metadata: process, addresses, comments, flags.
    Meta,
}

impl Loc {
    fn as_str(self) -> &'static str {
        match self {
            Loc::Header => "header",
            Loc::Url => "url",
            Loc::Body => "body",
            Loc::Ws => "ws",
            Loc::Meta => "meta",
        }
    }
}

/// What was replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cat {
    Authorization,
    Cookie,
    SecretHeader,
    UrlSecret,
    UserInfo,
    SecretField,
    Jwt,
    Email,
    Iban,
    Card,
    Phone,
    Ip,
    PersonalField,
    TaxId,
    SocialSecurity,
    Process,
    Custom,
    BodyRemoved,
    BodyTruncated,
    BinaryRemoved,
    FileRemoved,
    Undecodable,
}

impl Cat {
    fn as_str(self) -> &'static str {
        match self {
            Cat::Authorization => "authorization",
            Cat::Cookie => "cookie",
            Cat::SecretHeader => "secretHeader",
            Cat::UrlSecret => "urlSecret",
            Cat::UserInfo => "userInfo",
            Cat::SecretField => "secretField",
            Cat::Jwt => "jwt",
            Cat::Email => "email",
            Cat::Iban => "iban",
            Cat::Card => "card",
            Cat::Phone => "phone",
            Cat::Ip => "ip",
            Cat::PersonalField => "personalField",
            Cat::TaxId => "taxId",
            Cat::SocialSecurity => "socialSecurity",
            Cat::Process => "process",
            Cat::Custom => "custom",
            Cat::BodyRemoved => "bodyRemoved",
            Cat::BodyTruncated => "bodyTruncated",
            Cat::BinaryRemoved => "binaryRemoved",
            Cat::FileRemoved => "fileRemoved",
            Cat::Undecodable => "undecodable",
        }
    }
    /// The pseudonym prefix (`<email-3>`).
    fn label(self) -> &'static str {
        match self {
            Cat::Cookie => "cookie",
            Cat::SecretHeader | Cat::UrlSecret | Cat::SecretField => "token",
            Cat::UserInfo => "user",
            Cat::Jwt => "jwt",
            Cat::Email => "email",
            Cat::Iban => "iban",
            Cat::Card => "card",
            Cat::Phone => "phone",
            Cat::Ip => "ip",
            Cat::PersonalField => "personal",
            Cat::TaxId => "tax-id",
            Cat::SocialSecurity => "ssn",
            Cat::Process => "process",
            _ => "redacted",
        }
    }
    /// English description for the text log.
    fn describe(self) -> &'static str {
        match self {
            Cat::Authorization => "Authorization credentials",
            Cat::Cookie => "Cookie values",
            Cat::SecretHeader => "Secret header values",
            Cat::UrlSecret => "Secret URL parameters",
            Cat::UserInfo => "URL user info",
            Cat::SecretField => "Secret fields (passwords, tokens …)",
            Cat::Jwt => "JSON Web Tokens",
            Cat::Email => "E-mail addresses",
            Cat::Iban => "IBANs",
            Cat::Card => "Card numbers",
            Cat::Phone => "Phone numbers",
            Cat::Ip => "IP addresses",
            Cat::PersonalField => "Personal fields (names, addresses …)",
            Cat::TaxId => "Tax IDs",
            Cat::SocialSecurity => "Social security numbers",
            Cat::Process => "Process names",
            Cat::Custom => "Own patterns and names",
            Cat::BodyRemoved => "Bodies removed",
            Cat::BodyTruncated => "Bodies truncated",
            Cat::BinaryRemoved => "Binary bodies replaced",
            Cat::FileRemoved => "Uploaded files replaced",
            Cat::Undecodable => "Undecodable bodies replaced",
        }
    }
}

/// One count of the log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RedactionCount {
    /// `email`, `cookie`, `secretField` … (see the UI texts).
    pub category: String,
    /// `header`, `url`, `body`, `ws` (WebSocket messages) or `meta` (process, addresses,
    /// comments).
    pub location: String,
    pub count: usize,
}

/// What was replaced, without the original values.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RedactionLog {
    pub preset: String,
    /// Sessions processed.
    pub sessions: usize,
    /// Numbers (in the original capture) of the sessions in which something was replaced.
    pub touched: Vec<SessionId>,
    /// Replacements in total.
    pub total: usize,
    pub by_category: BTreeMap<String, usize>,
    pub by_location: BTreeMap<String, usize>,
    pub counts: Vec<RedactionCount>,
    /// Distinct values replaced by a pseudonym.
    pub distinct_values: usize,
    /// JSON numbers replaced by a string placeholder (the JSON stays valid; the type of
    /// these values changes).
    pub numbers_as_strings: usize,
    /// WebSocket messages scrubbed.
    pub ws_messages: usize,
    /// Notes for the reader (English).
    pub notes: Vec<String>,
}

impl RedactionLog {
    fn add(&mut self, cat: Cat, loc: Loc) {
        self.total += 1;
        *self.by_category.entry(cat.as_str().into()).or_default() += 1;
        *self.by_location.entry(loc.as_str().into()).or_default() += 1;
        match self.counts.iter_mut().find(|c| c.category == cat.as_str() && c.location == loc.as_str()) {
            Some(c) => c.count += 1,
            None => self.counts.push(RedactionCount { category: cat.as_str().into(), location: loc.as_str().into(), count: 1 }),
        }
    }

    /// Count for a category (all locations).
    pub fn count(&self, category: &str) -> usize {
        self.by_category.get(category).copied().unwrap_or(0)
    }

    /// Count for a category at a location.
    pub fn count_at(&self, category: &str, location: &str) -> usize {
        self.counts.iter().find(|c| c.category == category && c.location == location).map_or(0, |c| c.count)
    }

    /// One line for `log.comment` of a HAR.
    pub fn summary_line(&self) -> String {
        format!(
            "Sanitized by Quena ({} preset): {} replacement(s) in {} of {} session(s). Automatic detection can miss data; check before sharing.",
            self.preset,
            self.total,
            self.touched.len(),
            self.sessions
        )
    }

    /// The text written as `QUENA-REDACTION.txt`.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("Quena sanitized export\r\n======================\r\n\r\n");
        s.push_str(&format!("Preset: {}\r\nSessions: {}\r\nSessions with replacements: {}\r\nReplacements: {}\r\nDistinct values: {}\r\n\r\n", self.preset, self.sessions, self.touched.len(), self.total, self.distinct_values));
        s.push_str("By category\r\n-----------\r\n");
        let mut cats: Vec<(&String, &usize)> = self.by_category.iter().collect();
        cats.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (k, n) in cats {
            let locs: Vec<String> = self.counts.iter().filter(|c| &c.category == k).map(|c| format!("{} {}", c.location, c.count)).collect();
            let name = ALL_CATS.iter().find(|c| c.as_str() == k).map_or(k.as_str(), |c| c.describe());
            s.push_str(&format!("{name}: {n} ({})\r\n", locs.join(", ")));
        }
        if self.by_category.is_empty() {
            s.push_str("(nothing found)\r\n");
        }
        s.push_str("\r\nBy location\r\n-----------\r\n");
        for (k, n) in &self.by_location {
            s.push_str(&format!("{k}: {n}\r\n"));
        }
        if self.numbers_as_strings > 0 {
            s.push_str(&format!("\r\nJSON numbers replaced by a string placeholder: {}\r\n", self.numbers_as_strings));
        }
        if self.ws_messages > 0 {
            s.push_str(&format!("WebSocket messages scrubbed: {}\r\n", self.ws_messages));
        }
        if !self.touched.is_empty() {
            let ids: Vec<String> = self.touched.iter().map(|i| i.to_string()).collect();
            s.push_str(&format!("\r\nSessions with replacements (numbers in the original capture): {}\r\n", ids.join(", ")));
        }
        for n in &self.notes {
            s.push_str(&format!("\r\nNote: {n}\r\n"));
        }
        s.push_str(
            "\r\nReplaced values are pseudonyms: the same value got the same name (<email-1>) within this export.\r\nThe original values are not stored anywhere. Bodies are decoded (no Content-Encoding).\r\nAutomatic detection can miss data. Check the archive before sharing it.\r\n",
        );
        s
    }
}

const ALL_CATS: &[Cat] = &[
    Cat::Authorization,
    Cat::Cookie,
    Cat::SecretHeader,
    Cat::UrlSecret,
    Cat::UserInfo,
    Cat::SecretField,
    Cat::Jwt,
    Cat::Email,
    Cat::Iban,
    Cat::Card,
    Cat::Phone,
    Cat::Ip,
    Cat::PersonalField,
    Cat::TaxId,
    Cat::SocialSecurity,
    Cat::Process,
    Cat::Custom,
    Cat::BodyRemoved,
    Cat::BodyTruncated,
    Cat::BinaryRemoved,
    Cat::FileRemoved,
    Cat::Undecodable,
];

// ------------------------------------------------------------------ result

/// A sanitized session: headers and URL rewritten, bodies decoded (no Content-Encoding any
/// more, Content-Length matching) and scrubbed.
pub struct Sanitized {
    pub detail: SessionDetail,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

/// Largest decoded body that is scrubbed; larger ones become a placeholder (or, when
/// truncating, only their beginning is scrubbed and kept).
pub const MAX_DECODED: usize = 64 << 20;

/// How a placeholder is written into its context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Enc {
    /// `<email-1>`
    Raw,
    /// `%3Cemail-1%3E` (URLs, form fields)
    Url,
    /// `&lt;email-1&gt;` (HTML)
    Xml,
}

fn encode(s: &str, enc: Enc) -> String {
    match enc {
        Enc::Raw => s.to_string(),
        Enc::Url => encode_component(s),
        Enc::Xml => s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"),
    }
}

/// Context of a value given by its field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Plain,
    Secret(Cat),
    /// A weak secret name (`key`, `code`, `refresh`, `hash`): secret only when the value
    /// looks like a credential ([`credential_value`]; `true` = the looser rule for URL and
    /// form parameters). Numbers and booleans stay.
    Weak(Cat, bool),
    Personal,
}

impl Ctx {
    /// The context of a child: a secret or personal parent wins.
    fn child(self, own: Ctx) -> Ctx {
        match (self, own) {
            (Ctx::Secret(c), _) => Ctx::Secret(c),
            (_, Ctx::Secret(c)) => Ctx::Secret(c),
            (Ctx::Personal, _) | (_, Ctx::Personal) => Ctx::Personal,
            // A weak name judges its own value; it does not make children secret.
            (_, Ctx::Weak(c, l)) => Ctx::Weak(c, l),
            _ => Ctx::Plain,
        }
    }
}

// ------------------------------------------------------------------ sanitizer

#[derive(Clone, Copy)]
struct Flags {
    authorization: bool,
    cookies: bool,
    secret_headers: bool,
    url_secrets: bool,
    body_secrets: bool,
    emails: bool,
    payment: bool,
    phones: bool,
    ips: bool,
    personal_fields: bool,
    national_ids: bool,
    process: bool,
}

/// One export: options, the pseudonym key of this export, and the log.
pub struct Sanitizer {
    pub opts: SanitizeOptions,
    log: RedactionLog,
    key: RandomState,
    pseudonyms: HashMap<(&'static str, u64), usize>,
    next: HashMap<&'static str, usize>,
    patterns: Vec<Regex>,
    extra_headers: Vec<String>,
    extra_params: Vec<String>,
    extra_fields: Vec<String>,
    depth: usize,
    /// Scanning program code (JavaScript, CSS): no bare `name=value` rule.
    code: bool,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Integrity headers (`Digest`, `Content-MD5`, `ETag` …) dropped with changed bodies.
    integrity_dropped: usize,
    /// Fragmented WebSocket messages written as one frame.
    ws_joined: usize,
    name_cache: std::cell::RefCell<HashMap<(u8, String), Ctx>>,
    /// No name rules (`Content-Disposition`: `name="…"` names a field, it is no name).
    no_kv: bool,
}

/// See [`Sanitizer::object_shape`].
struct Shape {
    indirect: Option<Ctx>,
    person: bool,
}

impl Sanitizer {
    pub fn new(opts: SanitizeOptions) -> Sanitizer {
        let mut log = RedactionLog { preset: opts.preset.clone(), ..Default::default() };
        let mut patterns = Vec::new();
        for p in opts.patterns.iter().filter(|p| !p.is_empty()) {
            match Regex::new(p) {
                Ok(r) => patterns.push(r),
                Err(_) => log.notes.push(format!("pattern {p:?} is not a valid regular expression and was ignored")),
            }
        }
        let lower = |v: &[String]| v.iter().map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
        Sanitizer {
            extra_headers: lower(&opts.extra_headers),
            extra_params: lower(&opts.extra_params),
            extra_fields: lower(&opts.extra_fields),
            opts,
            log,
            key: RandomState::new(),
            pseudonyms: HashMap::new(),
            next: HashMap::new(),
            patterns,
            depth: 0,
            code: false,
            cancel: None,
            integrity_dropped: 0,
            ws_joined: 0,
            name_cache: Default::default(),
            no_kv: false,
        }
    }

    /// The on/off options (cheap copy).
    fn flags(&self) -> Flags {
        let o = &self.opts;
        Flags {
            authorization: o.authorization,
            cookies: o.cookies,
            secret_headers: o.secret_headers,
            url_secrets: o.url_secrets,
            body_secrets: o.body_secrets,
            emails: o.emails,
            payment: o.payment,
            phones: o.phones,
            ips: o.ips,
            personal_fields: o.personal_fields,
            national_ids: o.national_ids,
            process: o.process,
        }
    }

    pub fn log(&self) -> &RedactionLog {
        &self.log
    }

    /// The log, consuming the sanitizer.
    pub fn into_log(mut self) -> RedactionLog {
        self.log.distinct_values = self.pseudonyms.len();
        self.log
    }

    pub fn session(&mut self, d: &SessionDetail, req: &Body, resp: &Body) -> Sanitized {
        self.log.sessions += 1;
        let before = self.log.total;
        let mut detail = d.clone();
        detail.request.url = if d.summary.kind == SessionKind::Tunnel {
            // CONNECT target `host:port`.
            self.authority(&d.request.url, Loc::Url)
        } else {
            self.url(&d.request.url, Loc::Url)
        };
        self.headers(&mut detail.request.headers);
        if let Some(r) = detail.response.as_mut() {
            self.headers(&mut r.headers);
        }
        let request = self.body(&mut detail.request.headers, req, Loc::Body);
        let deflate = d.response.as_ref().and_then(|r| r.headers.get("sec-websocket-extensions")).is_some_and(|e| e.to_ascii_lowercase().contains("permessage-deflate"));
        let response = match detail.response.as_mut() {
            Some(r) if d.summary.kind == SessionKind::WebSocket => {
                r.headers.remove("content-encoding");
                self.ws_log(resp, deflate)
            }
            Some(r) => self.body(&mut r.headers, resp, Loc::Body),
            None if d.summary.kind == SessionKind::WebSocket => self.ws_log(resp, deflate),
            None => Vec::new(),
        };
        if self.ws_joined > 0 {
            let note = format!("Fragmented WebSocket messages joined into one frame each: {}", self.ws_joined);
            match self.log.notes.iter_mut().find(|n| n.starts_with("Fragmented WebSocket")) {
                Some(n) => *n = note,
                None => self.log.notes.push(note),
            }
        }
        self.meta(&mut detail);
        if self.log.total > before {
            self.log.touched.push(d.summary.id);
        }
        self.log.distinct_values = self.pseudonyms.len();
        if self.integrity_dropped > 0 {
            let note = format!("Integrity headers of changed bodies removed (Digest, Content-MD5, Repr-Digest, Content-Digest, ETag): {}", self.integrity_dropped);
            match self.log.notes.iter_mut().find(|n| n.starts_with("Integrity headers")) {
                Some(n) => *n = note,
                None => self.log.notes.push(note),
            }
        }
        Sanitized { detail, request, response }
    }

    // -------------------------------------------------------------- placeholders

    /// The replacement of `value` (`<email-3>`, raw), counted in the log.
    fn ph(&mut self, cat: Cat, loc: Loc, value: &str) -> String {
        self.ph_label(cat, cat.label(), loc, value)
    }

    /// [`Self::ph`] counted as `cat`, named with `label`.
    fn ph_label(&mut self, cat: Cat, label: &'static str, loc: Loc, value: &str) -> String {
        self.log.add(cat, loc);
        if !self.opts.pseudonyms {
            return format!("<{label}>");
        }
        let norm: Cow<str> = if cat == Cat::Email { Cow::Owned(value.to_ascii_lowercase()) } else { Cow::Borrowed(value) };
        let h = self.key.hash_one(norm.as_ref());
        let n = match self.pseudonyms.get(&(label, h)) {
            Some(n) => *n,
            None => {
                let c = self.next.entry(label).or_insert(0);
                *c += 1;
                let n = *c;
                self.pseudonyms.insert((label, h), n);
                n
            }
        };
        format!("<{label}-{n}>")
    }

    // -------------------------------------------------------------- names

    fn field_ctx(&self, name: &str) -> Ctx {
        self.cached(0, name, |z, n| z.field_ctx_uncached(n))
    }

    fn field_ctx_uncached(&self, name: &str) -> Ctx {
        let n = name.trim().to_ascii_lowercase();
        if !self.extra_fields.is_empty() && self.extra_fields.contains(&n) {
            return Ctx::Secret(Cat::Custom);
        }
        if self.opts.body_secrets && secret_field(name.trim()) {
            return Ctx::Secret(Cat::SecretField);
        }
        if self.opts.body_secrets && weak_secret_name(name) {
            return Ctx::Weak(Cat::SecretField, false);
        }
        if self.opts.personal_fields && personal_name(&n) {
            return Ctx::Personal;
        }
        Ctx::Plain
    }

    fn param_ctx(&self, name: &str) -> Ctx {
        self.cached(1, name, |z, n| z.param_ctx_uncached(n))
    }

    fn param_ctx_uncached(&self, name: &str) -> Ctx {
        let d = decode_param(name);
        let n = d.trim().to_ascii_lowercase();
        if !self.extra_params.is_empty() && self.extra_params.contains(&n) {
            return Ctx::Secret(Cat::Custom);
        }
        if self.opts.url_secrets && secret_param_name(d.trim()) {
            return Ctx::Secret(Cat::UrlSecret);
        }
        if self.opts.url_secrets && weak_secret_name(&d) {
            return Ctx::Weak(Cat::UrlSecret, true);
        }
        if self.opts.personal_fields && personal_name(&n) {
            return Ctx::Personal;
        }
        Ctx::Plain
    }

    /// Name classification is cached per kind (field, parameter, form field).
    fn cached(&self, kind: u8, name: &str, f: impl Fn(&Self, &str) -> Ctx) -> Ctx {
        if name.len() > 64 {
            return f(self, name);
        }
        if let Some(c) = self.name_cache.borrow().get(&(kind, name.to_string())) {
            return *c;
        }
        let c = f(self, name);
        let mut cache = self.name_cache.borrow_mut();
        if cache.len() > 8192 {
            cache.clear();
        }
        cache.insert((kind, name.to_string()), c);
        c
    }

    /// What the members of a JSON object say about it: a member naming another one
    /// (`{"name": "password", "value": …}`) and whether it describes a person.
    fn object_shape(&self, info: &[(String, Option<String>)], pkey: &str) -> Shape {
        let mut indirect = None;
        for (k, v) in info {
            if is_name_key(k)
                && let Some(v) = v
                && self.names_a_field(k, v)
            {
                indirect = Some(self.field_ctx(v));
            }
        }
        let person = self.opts.personal_fields && (person_word(pkey) || info.iter().any(|(k, _)| person_field(k)));
        Shape { indirect, person }
    }

    /// The context of the member `key` (with string value `v`) of an object of `shape`.
    fn member_ctx(&self, key: &str, v: Option<&str>, shape: &Shape) -> Ctx {
        if let Some(v) = v
            && self.names_a_field(key, v)
        {
            return Ctx::Plain;
        }
        if is_value_key(key)
            && let Some(c) = shape.indirect
        {
            return c;
        }
        let own = self.field_ctx(key);
        if own == Ctx::Personal && ambiguous_personal(key) && !shape.person {
            return Ctx::Plain;
        }
        own
    }

    /// Whether cancellation was requested ([`Self::set_cancel`]).
    fn stopped(&self) -> bool {
        self.cancel.as_ref().is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// A flag that, once set, makes the sanitizer stop early (the session in progress then
    /// gets placeholders instead of its bodies; the caller discards it).
    pub fn set_cancel(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.cancel = Some(flag);
    }

    /// Form fields: parameter names, field names and the body secret rules.
    fn form_ctx(&self, name: &str) -> Ctx {
        self.cached(2, name, |z, n| z.form_ctx_uncached(n))
    }

    fn form_ctx_uncached(&self, name: &str) -> Ctx {
        let d = decode_param(name);
        let n = d.trim().to_ascii_lowercase();
        if (!self.extra_params.is_empty() && self.extra_params.contains(&n)) || (!self.extra_fields.is_empty() && self.extra_fields.contains(&n)) {
            return Ctx::Secret(Cat::Custom);
        }
        if self.opts.body_secrets && secret_param_name(d.trim()) {
            return Ctx::Secret(Cat::SecretField);
        }
        if self.opts.body_secrets && weak_secret_name(&d) {
            return Ctx::Weak(Cat::SecretField, true);
        }
        if self.opts.personal_fields && personal_name(&n) {
            return Ctx::Personal;
        }
        Ctx::Plain
    }

    // -------------------------------------------------------------- values

    /// A value in context `ctx` (decoded text); `None` if unchanged. Placeholders are raw.
    fn value(&mut self, v: &str, ctx: Ctx, loc: Loc) -> Option<String> {
        match ctx {
            _ if v.trim().is_empty() => None,
            Ctx::Secret(cat) => Some(self.ph(cat, loc, v)),
            Ctx::Weak(cat, loose) if credential_value(v, loose) => Some(self.ph(cat, loc, v)),
            Ctx::Weak(..) => self.value(v, Ctx::Plain, loc),
            Ctx::Personal => Some(self.ph(Cat::PersonalField, loc, v)),
            Ctx::Plain => {
                let t = v.trim_start();
                if self.depth < 8 && (t.starts_with('{') || t.starts_with('[')) && t.len() > 1 {
                    self.depth += 1;
                    let r = self.json(v, loc);
                    self.depth -= 1;
                    if let Some(r) = r {
                        return (r != v).then_some(r);
                    }
                }
                if self.depth < 8 && has_scheme(v) && !v.contains(char::is_whitespace) {
                    self.depth += 1;
                    let u = self.url(v, loc);
                    self.depth -= 1;
                    return (u != v).then_some(u);
                }
                match self.scrub(v, loc, Enc::Raw) {
                    Cow::Owned(s) => Some(s),
                    Cow::Borrowed(_) => None,
                }
            }
        }
    }

    /// A JSON number in context `ctx`: `Some(placeholder string)` if it is replaced.
    fn number(&mut self, raw: &str, ctx: Ctx, loc: Loc) -> Option<String> {
        // Numbers of weak names (`"key": 5`, `"code": 200`) stay numbers.
        let ctx = if matches!(ctx, Ctx::Weak(..)) { Ctx::Plain } else { ctx };
        let r = match ctx {
            Ctx::Secret(cat) => Some(self.ph(cat, loc, raw)),
            Ctx::Personal => Some(self.ph(Cat::PersonalField, loc, raw)),
            Ctx::Plain if raw.bytes().all(|b| b.is_ascii_digit()) => {
                if self.opts.payment && card_number(raw) {
                    Some(self.ph(Cat::Card, loc, raw))
                } else if self.opts.national_ids && tax_id(raw) {
                    Some(self.ph(Cat::TaxId, loc, raw))
                } else {
                    None
                }
            }
            Ctx::Plain | Ctx::Weak(..) => None,
        };
        if r.is_some() {
            self.log.numbers_as_strings += 1;
        }
        r
    }

    /// Free text: every detector enabled by the options. Placeholders written per `enc`.
    fn scrub<'a>(&mut self, s: &'a str, loc: Loc, enc: Enc) -> Cow<'a, str> {
        if s.len() < 3 {
            return Cow::Borrowed(s);
        }
        let mut spans = Spans::default();
        let o = self.flags();
        // Own patterns first.
        for i in 0..self.patterns.len() {
            let found: Vec<(usize, usize)> = self.patterns[i].find_iter(s).filter(|m| !m.is_empty()).map(|m| (m.start(), m.end())).collect();
            for (a, b) in found {
                if spans.free(a, b) {
                    let p = self.ph(Cat::Custom, loc, &s[a..b]);
                    spans.add(a, b, encode(&p, enc));
                }
            }
        }
        // Credentials written like headers (`Bearer …`, `Cookie: …`).
        if o.authorization || o.cookies {
            self.credentials_in_text(s, loc, enc, &mut spans);
        }
        // URLs in text are rewritten as URLs (user info, parameters, path tokens, hosts).
        if self.depth < 8 && (s.contains("://") || s.contains("url(") || s.contains("URL(")) {
            self.urls_in_text(s, loc, &mut spans);
        }
        // key=value, key: value, "key": "value", <input name=… value=…>, URL user info.
        if !self.no_kv && (o.body_secrets || o.url_secrets || o.personal_fields || !self.extra_params.is_empty() || !self.extra_fields.is_empty()) {
            self.key_values(s, loc, enc, &mut spans);
        }
        if o.body_secrets && s.contains("eyJ") {
            for m in re(&JWT).find_iter(s) {
                if spans.free(m.start(), m.end()) {
                    let p = self.ph(Cat::Jwt, loc, m.as_str());
                    spans.add(m.start(), m.end(), encode(&p, enc));
                }
            }
        }
        if o.emails && (s.contains('@') || s.contains("%40") || s.contains("&#64;") || s.contains("&#x40;") || s.contains("&commat;")) {
            for m in re(&EMAIL).find_iter(s) {
                let Some((a, b)) = email_at(s, m.start(), m.end()) else { continue };
                if !spans.free(a, b) {
                    continue;
                }
                let norm = s[a..b].replace("%40", "@").replace("&#64;", "@").replace("&#x40;", "@").replace("&commat;", "@");
                let p = self.ph(Cat::Email, loc, &norm);
                spans.add(a, b, encode(&p, enc));
            }
        }
        let numeric = (o.payment || o.phones || o.ips || o.national_ids) && s.bytes().any(|b| b.is_ascii_digit());
        if !numeric {
            return spans.apply(s);
        }
        // Spans that look like numbers but are none of the above.
        let mut protect = Spans::default();
        for (a, (b, _)) in &spans.0 {
            protect.add(*a, *b, String::new());
        }
        for r in [&UUID, &DATE, &TIME] {
            for m in re(r).find_iter(s) {
                if protect.free(m.start(), m.end()) {
                    protect.add(m.start(), m.end(), String::new());
                }
            }
        }
        let mut found: Vec<(usize, usize, Cat, String)> = Vec::new();
        if o.payment {
            // A spaced candidate may run into the next IBAN: go on right after each one found.
            let mut pos = 0;
            while let Some(m) = re(&IBAN).find_at(s, pos) {
                match iban_at(s, m.start(), m.end()) {
                    Some(end) => {
                        found.push((m.start(), end, Cat::Iban, s[m.start()..end].replace(' ', "").to_ascii_uppercase()));
                        pos = end;
                    }
                    None => pos = m.start() + s[m.start()..].chars().next().map_or(1, char::len_utf8),
                }
            }
            for m in re(&CARD).find_iter(s) {
                let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
                if number_boundary(s, m.start(), m.end()) && card_layout(m.as_str()) && card_number(&digits) {
                    found.push((m.start(), m.end(), Cat::Card, digits));
                }
            }
        }
        if o.national_ids {
            for m in re(&TAX_ID).find_iter(s) {
                let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
                if number_boundary(s, m.start(), m.end()) && tax_id(&digits) {
                    found.push((m.start(), m.end(), Cat::TaxId, digits));
                }
            }
            for m in re(&SVNR).find_iter(s) {
                let compact: String = m.as_str().chars().filter(|c| !c.is_whitespace()).collect();
                if social_security(&compact) {
                    found.push((m.start(), m.end(), Cat::SocialSecurity, compact));
                }
            }
        }
        if o.phones {
            for (a, b) in phones(s) {
                let digits: String = s[a..b].chars().filter(char::is_ascii_digit).collect();
                found.push((a, b, Cat::Phone, digits));
            }
        }
        if o.ips {
            for m in re(&IPV4).find_iter(s) {
                if ipv4_at(s, m.start(), m.end()) {
                    found.push((m.start(), m.end(), Cat::Ip, m.as_str().to_string()));
                }
            }
            if s.contains(':') {
                for m in re(&IPV6).find_iter(s) {
                    if ipv6_at(s, m.start(), m.end()) {
                        found.push((m.start(), m.end(), Cat::Ip, m.as_str().to_ascii_lowercase()));
                    }
                }
            }
        }
        for (a, b, cat, v) in found {
            if protect.free(a, b) {
                let p = self.ph(cat, loc, &v);
                protect.add(a, b, String::new());
                spans.add(a, b, encode(&p, enc));
            }
        }
        spans.apply(s)
    }

    /// The placeholder of a credential (`Authorization`, `Bearer …` in text): JWTs as `jwt`,
    /// everything else as `token`, so the same value gets the same name wherever it appears.
    fn credential_ph(&mut self, cat: Cat, loc: Loc, v: &str) -> String {
        let jwt = re(&JWT).find(v).is_some_and(|m| m.start() == 0 && m.end() == v.len());
        self.ph_label(cat, if jwt { "jwt" } else { "token" }, loc, v)
    }

    /// `Bearer …`, `Basic …`, `Negotiate …`, `NTLM …`, `Digest …` credentials and `Cookie:` /
    /// `Set-Cookie:` lines anywhere in text.
    fn credentials_in_text(&mut self, s: &str, loc: Loc, enc: Enc, spans: &mut Spans) {
        if self.opts.authorization {
            for c in caps(re(&AUTH_TEXT), s) {
                let (scheme, cred) = (c.get(1).unwrap(), c.get(2).unwrap());
                let v = cred.as_str();
                let (a, mut b) = (cred.start(), cred.end());
                if scheme.as_str().eq_ignore_ascii_case("digest") {
                    if !v.contains('=') {
                        continue;
                    }
                    // Digest parameters: up to the end of the line.
                    b = s[a..].find(['\r', '\n']).map_or(s.len(), |i| a + i);
                } else if !credential_like(v) {
                    continue;
                }
                if spans.free(a, b) {
                    let p = self.credential_ph(Cat::Authorization, loc, &s[a..b]);
                    spans.add(a, b, encode(&p, enc));
                }
            }
        }
        if self.opts.cookies && (s.contains("ookie") || s.contains("OOKIE")) {
            for c in caps(re(&COOKIE_LINE), s) {
                let (name, value) = (c.get(1).unwrap(), c.get(2).unwrap());
                if !spans.free(value.start(), value.end()) {
                    continue;
                }
                let v = value.as_str().trim_end();
                let new = if name.as_str().len() > 6 {
                    rewrite_set_cookie(v, &mut |x| if x.is_empty() { String::new() } else { self.ph(Cat::Cookie, loc, x) })
                } else {
                    self.cookie_values(v, loc)
                };
                if new != v {
                    spans.add(value.start(), value.start() + v.len(), if enc == Enc::Xml { encode(&new, Enc::Xml) } else { new });
                }
            }
        }
    }

    /// Absolute URLs and CSS `url(…)` in text, rewritten like the request URL.
    fn urls_in_text(&mut self, s: &str, loc: Loc, spans: &mut Spans) {
        let mut found: Vec<(usize, usize)> = Vec::new();
        if s.contains("://") {
            for m in re(&URL_TEXT).find_iter(s) {
                let t = m.as_str().trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '*']);
                found.push((m.start(), m.start() + t.len()));
            }
        }
        if s.contains("url(") || s.contains("URL(") {
            for c in caps(re(&CSS_URL), s) {
                let u = c.get(1).unwrap();
                found.push((u.start(), u.end()));
            }
        }
        for (a, b) in found {
            if b <= a || !spans.free(a, b) {
                continue;
            }
            self.depth += 1;
            let new = self.url(&s[a..b], loc);
            self.depth -= 1;
            if new != s[a..b] {
                spans.add(a, b, new);
            }
        }
    }

    /// Secret / personal values named in free text.
    fn key_values(&mut self, s: &str, loc: Loc, enc: Enc, spans: &mut Spans) {
        if s.contains("://") && s.contains('@') && self.opts.url_secrets {
            for c in caps(re(&USERINFO), s) {
                let u = c.get(1).unwrap();
                if spans.free(u.start(), u.end()) {
                    let p = self.ph(Cat::UserInfo, loc, u.as_str());
                    spans.add(u.start(), u.end(), encode(&p, Enc::Url));
                }
            }
        }
        // HTML: tags are handled by their attributes; no `name=value` rule inside them.
        let tags: Vec<(usize, usize)> = if enc == Enc::Xml && s.contains('<') { re(&TAG).find_iter(s).map(|m| (m.start(), m.end())).collect() } else { Vec::new() };
        if !tags.is_empty() {
            self.html_tags(s, loc, &tags, spans);
        }
        let in_tag = |i: usize| {
            let k = tags.partition_point(|t| t.0 <= i);
            k > 0 && tags[k - 1].1 > i
        };
        if s.contains("\":") || s.contains("\" :") {
            for c in caps(re(&JSON_KV), s) {
                let (name, value) = (c.get(1).unwrap(), c.get(2).unwrap());
                let ctx = self.field_ctx(name.as_str());
                if ctx != Ctx::Plain
                    && spans.free(value.start(), value.end())
                    && !self.names_a_field(name.as_str(), value.as_str())
                    && let Some(p) = self.value(value.as_str(), ctx, loc)
                {
                    spans.add(value.start(), value.end(), encode(&p, enc));
                }
            }
        }
        // `name: value`, `name = "value"`, `'name': 'value'` (YAML, JavaScript, logs, GraphQL
        // arguments): only for secret and personal names.
        if s.contains(':') || s.contains('=') {
            for c in caps(re(&KV2), s) {
                let (name, sep, value) = (c.get(1).unwrap(), c.get(2).unwrap(), c.get(3).unwrap());
                let v = value.as_str();
                let quoted = v.starts_with(['"', '\'']);
                if in_tag(name.start()) || (!quoted && (sep.as_str() == "=" || self.code)) {
                    continue;
                }
                let ctx = self.form_ctx(name.as_str());
                if ctx == Ctx::Plain {
                    continue;
                }
                let (a, b) = if quoted { (value.start() + 1, value.end() - 1) } else { (value.start(), value.start() + v.trim_end().len()) };
                if a >= b || !spans.free(a, b) || self.names_a_field(name.as_str(), &s[a..b]) {
                    continue;
                }
                if let Some(p) = self.value(&s[a..b], ctx, loc) {
                    spans.add(a, b, encode(&p, enc));
                }
            }
        }
        if !self.code && s.contains('=') {
            self.kv_pairs(s, 0, s.len(), loc, enc, spans, &in_tag, 0);
        }
    }

    /// `name=value` pairs in `s[from..to]`; values that are URLs or hold pairs themselves
    /// (`next=/login?password=…`) are looked into.
    #[allow(clippy::too_many_arguments)]
    fn kv_pairs(&mut self, s: &str, from: usize, to: usize, loc: Loc, enc: Enc, spans: &mut Spans, in_tag: &dyn Fn(usize) -> bool, depth: usize) {
        let found: Vec<(usize, usize, usize, usize)> = caps(re(&KV), &s[from..to])
            .into_iter()
            .map(|c| {
                let (n, v) = (c.get(1).unwrap(), c.get(2).unwrap());
                (from + n.start(), from + n.end(), from + v.start(), from + v.end())
            })
            .collect();
        let penc = if enc == Enc::Xml { Enc::Xml } else { Enc::Url };
        for (na, nb, va, vb) in found {
            if in_tag(na) {
                continue;
            }
            let (name, value) = (&s[na..nb], &s[va..vb]);
            let ctx = self.form_ctx(name);
            if ctx != Ctx::Plain {
                if spans.free(va, vb) {
                    let v = decode_param(value);
                    if !self.names_a_field(name, &v)
                        && let Some(p) = self.value(&v, ctx, loc)
                    {
                        // In text the pair is most likely part of a URL or form.
                        spans.add(va, vb, encode(&p, penc));
                    }
                }
                continue;
            }
            if depth >= 3 || !spans.free(va, vb) {
                continue;
            }
            if value.contains('?') || has_scheme(value) {
                self.depth += 1;
                let new = self.url(value, loc);
                self.depth -= 1;
                if new != value {
                    spans.add(va, vb, new);
                }
            } else if value.contains('=') {
                self.kv_pairs(s, va, vb, loc, enc, spans, in_tag, depth + 1);
            } else if value.contains('%') {
                // An encoded URL or pairs (`redirect=https%3A%2F%2F…%3Ftoken%3D…`).
                let v = decode_param(value);
                if (v.contains('=') || has_scheme(&v))
                    && let Some(new) = self.value(&v, Ctx::Plain, loc)
                {
                    spans.add(va, vb, encode_component(&new));
                }
            }
        }
    }

    /// HTML tags: `<input>` / `<meta>` / `<param>` values by their name (`csrf`, a password
    /// field, `csrf-token`), URLs in `href` / `src` / `action` … rewritten as URLs.
    fn html_tags(&mut self, s: &str, loc: Loc, tags: &[(usize, usize)], spans: &mut Spans) {
        for &(ta, tb) in tags {
            let tag = &s[ta..tb];
            let tname: String = tag[1..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ':').collect::<String>().to_ascii_lowercase();
            // (name lower case, value start, value end)
            let attrs: Vec<(String, usize, usize)> = re(&ATTR)
                .captures_iter(tag)
                .map(|c| {
                    let v = c.get(2).unwrap();
                    let q = v.as_str().starts_with(['"', '\'']);
                    let (a, b) = if q { (v.start() + 1, v.end() - 1) } else { (v.start(), v.end()) };
                    (c[1].to_ascii_lowercase(), ta + a, ta + b)
                })
                .collect();
            let get = |n: &str| attrs.iter().find(|a| a.0 == n).map(|a| &s[a.1..a.2]);
            for (an, a, b) in &attrs {
                let (a, b) = (*a, *b);
                let v = &s[a..b];
                let url_attr = matches!(an.as_str(), "href" | "src" | "action" | "formaction" | "poster" | "cite" | "background" | "data" | "ping" | "manifest" | "longdesc" | "codebase" | "data-src" | "data-href" | "data-url");
                if url_attr && (v.contains(['?', '#', '@', ';']) || v.contains("://") || v.contains('/')) && spans.free(a, b) {
                    self.depth += 1;
                    let new = self.url(v, loc);
                    self.depth -= 1;
                    if new != v {
                        spans.add(a, b, new);
                    }
                }
            }
            if !matches!(tname.as_str(), "input" | "meta" | "param" | "textarea" | "option" | "button" | "data") {
                continue;
            }
            // <meta http-equiv="refresh" content="0; url=…">
            if tname == "meta"
                && get("http-equiv").is_some_and(|v| v.eq_ignore_ascii_case("refresh"))
                && let Some(c) = attrs.iter().find(|a| a.0 == "content")
            {
                let v = &s[c.1..c.2];
                let new = self.refresh(v, loc);
                if new != v && spans.free(c.1, c.2) {
                    spans.add(c.1, c.2, encode(&new, Enc::Xml));
                }
                continue;
            }
            let name = get("name").or_else(|| get("property")).or_else(|| get("itemprop")).or_else(|| get("id")).unwrap_or("").to_string();
            let password = get("type").is_some_and(|t| t.eq_ignore_ascii_case("password"));
            let mut ctx = self.form_ctx(&name);
            if password && self.opts.body_secrets {
                ctx = Ctx::Secret(Cat::SecretField);
            }
            if ctx == Ctx::Plain {
                continue;
            }
            for (an, a, b) in &attrs {
                if (an == "value" || an == "content")
                    && spans.free(*a, *b)
                    && let Some(p) = self.value(&s[*a..*b], ctx, loc)
                {
                    spans.add(*a, *b, encode(&p, Enc::Xml));
                }
            }
        }
    }

    /// `Refresh: 0; url=…` (header or `<meta http-equiv>`).
    fn refresh(&mut self, v: &str, loc: Loc) -> String {
        let lower = v.to_ascii_lowercase();
        match lower.find("url=") {
            Some(i) => {
                let u = v[i + 4..].trim_matches(['\'', '"', ' ']);
                let start = v[i + 4..].find(u).map_or(i + 4, |k| i + 4 + k);
                format!("{}{}{}", &v[..start], self.url(u, loc), &v[start + u.len()..])
            }
            None => self.scrub(v, loc, Enc::Raw).into_owned(),
        }
    }

    /// Whether `value` of the field `name` is itself a field name (`"name": "password"`,
    /// `"key": "email"`): the value names another value and is no secret or person.
    fn names_a_field(&self, name: &str, value: &str) -> bool {
        is_name_key(name) && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphabetic() || b"_-. :".contains(&b)) && self.field_ctx(value) != Ctx::Plain
    }

    // -------------------------------------------------------------- URLs

    fn url(&mut self, url: &str, loc: Loc) -> String {
        let mut r = UrlScrub { s: self, loc };
        rewrite_url(url, &mut r)
    }

    // -------------------------------------------------------------- headers

    fn headers(&mut self, h: &mut Headers) {
        let o = self.flags();
        let mut out = Vec::with_capacity(h.0.len());
        for (name, value) in std::mem::take(&mut h.0) {
            let lower = name.to_ascii_lowercase();
            let words = name_words(&lower);
            // `X-Forwarded-Authorization` …, and `X-Basic: Basic …` (a scheme in the value).
            let scheme_value = value.trim_start().split_once(' ').is_some_and(|(s, _)| ["basic", "bearer", "digest", "negotiate", "ntlm"].contains(&s.to_ascii_lowercase().as_str()));
            let authz = (lower.contains("authorization") && !lower.starts_with("access-control-")) || (scheme_value && words.iter().any(|w| matches!(w.as_str(), "bearer" | "basic" | "negotiate" | "auth" | "token")));
            let new = match lower.as_str() {
                "www-authenticate" | "proxy-authenticate" if o.authorization => {
                    let r = redact_authenticate(&value);
                    if r != value {
                        self.log.add(Cat::Authorization, Loc::Header);
                    }
                    r
                }
                _ if authz && o.authorization => self.authorization(&value),
                "cookie" if o.cookies => self.cookie(&value),
                "set-cookie" if o.cookies => rewrite_set_cookie(&value, &mut |v| if v.is_empty() { String::new() } else { self.ph(Cat::Cookie, Loc::Header, v) }),
                "sec-websocket-protocol" if o.secret_headers => self.ws_protocols(&value),
                "location" | "referer" | "content-location" | ":path" | "x-original-url" | "x-rewrite-url" | "origin" | "x-forwarded-uri" | "x-original-uri" | "x-quena-mapped-from" => {
                    self.url(&value, Loc::Header)
                }
                "refresh" => self.refresh(&value, Loc::Header),
                "content-disposition" => {
                    self.no_kv = true;
                    let v = self.scrub(&value, Loc::Header, Enc::Raw).into_owned();
                    self.no_kv = false;
                    v
                }
                "link" => self.link(&value),
                "host" | ":authority" | "x-forwarded-host" | "x-original-host" => self.authority(&value, Loc::Header),
                "content-length" | "content-type" | "content-encoding" | "transfer-encoding" | "date" | ":method" | ":scheme" | ":status" => value,
                _ if !value.trim().is_empty() && self.extra_headers.contains(&lower) => self.ph(Cat::Custom, Loc::Header, value.trim()),
                _ if !value.trim().is_empty() && o.secret_headers && secret_header(&lower) => self.ph(Cat::SecretHeader, Loc::Header, value.trim()),
                _ if !value.trim().is_empty() && o.personal_fields && personal_header(&lower) => self.ph(Cat::PersonalField, Loc::Header, value.trim()),
                _ => self.scrub(&value, Loc::Header, Enc::Raw).into_owned(),
            };
            out.push((name, new));
        }
        h.0 = out;
    }

    /// `Authorization` and its relatives: the scheme stays, the credential becomes a pseudonym
    /// (`Bearer <token-3>`), the same one it gets in bodies and URLs.
    fn authorization(&mut self, v: &str) -> String {
        let v = v.trim();
        if v.is_empty() {
            return String::new();
        }
        let scheme_like = |s: &str| s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') && s.bytes().any(|b| b.is_ascii_alphabetic());
        match v.split_once(|c: char| c.is_ascii_whitespace()) {
            Some((scheme, rest)) if scheme_like(scheme) && !rest.trim().is_empty() => format!("{scheme} {}", self.credential_ph(Cat::Authorization, Loc::Header, rest.trim())),
            None if scheme_like(v) && ["basic", "bearer", "digest", "negotiate", "ntlm", "kerberos", "hoba", "mutual", "hawk", "oauth", "token", "dpop"].contains(&v.to_ascii_lowercase().as_str()) => {
                v.to_string()
            }
            _ => self.credential_ph(Cat::Authorization, Loc::Header, v),
        }
    }

    /// `Sec-WebSocket-Protocol`: protocol names stay; tokens passed as subprotocols (a value
    /// after `access_token`, `base64url.bearer.authorization.k8s.io.…`, long random strings)
    /// are replaced.
    fn ws_protocols(&mut self, v: &str) -> String {
        let mut prev_secret = false;
        v.split(',')
            .map(|t| {
                let tok = t.trim();
                let lead = &t[..t.len() - t.trim_start().len()];
                let lower = tok.to_ascii_lowercase();
                let digits = tok.bytes().any(|b| b.is_ascii_digit());
                let name = secret_name(tok) && !digits;
                let secret = !tok.is_empty() && !name && (prev_secret || lower.contains("bearer") || lower.contains("token") || (tok.len() >= 16 && digits && tok.bytes().any(|b| b.is_ascii_alphabetic())));
                prev_secret = name;
                if secret { format!("{lead}{}", self.credential_ph(Cat::SecretHeader, Loc::Header, tok)) } else { t.to_string() }
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// `Link: <url>; rel=…`: the URLs rewritten.
    fn link(&mut self, v: &str) -> String {
        let mut out = String::with_capacity(v.len());
        let mut rest = v;
        while let Some(a) = rest.find('<') {
            let Some(b) = rest[a..].find('>') else { break };
            out.push_str(&rest[..=a]);
            out.push_str(&self.url(&rest[a + 1..a + b], Loc::Header));
            out.push('>');
            rest = &rest[a + b + 1..];
        }
        out.push_str(rest);
        self.scrub(&out, Loc::Header, Enc::Raw).into_owned()
    }

    /// `host[:port]` (`Host`, `:authority`, a CONNECT target): IP literals (with the `ips`
    /// option) and own patterns are replaced, host names stay.
    fn authority(&mut self, v: &str, loc: Loc) -> String {
        let t = v.trim();
        let (host, port) = if let Some(rest) = t.strip_prefix('[') {
            match rest.split_once(']') {
                Some((h, p)) => (h, p),
                None => (t, ""),
            }
        } else {
            match t.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => (h, &t[h.len()..]),
                _ => (t, ""),
            }
        };
        let new = self.host(host, loc);
        if new == host {
            return v.to_string();
        }
        format!("{new}{port}")
    }

    /// A host name or IP literal (without brackets or port).
    fn host(&mut self, host: &str, loc: Loc) -> String {
        if host.is_empty() || host.starts_with('<') {
            return host.to_string();
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if self.opts.ips {
            let ip = match bare.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(a)) => !a.is_loopback() && !a.is_unspecified() && !a.is_broadcast(),
                Ok(std::net::IpAddr::V6(a)) => !a.is_loopback() && !a.is_unspecified(),
                Err(_) => false,
            };
            if ip {
                return self.ph(Cat::Ip, loc, &bare.to_ascii_lowercase());
            }
        }
        if self.patterns.is_empty() {
            return host.to_string();
        }
        let mut spans = Spans::default();
        for i in 0..self.patterns.len() {
            let found: Vec<(usize, usize)> = self.patterns[i].find_iter(host).filter(|m| !m.is_empty()).map(|m| (m.start(), m.end())).collect();
            for (a, b) in found {
                if spans.free(a, b) {
                    let p = self.ph(Cat::Custom, loc, &host[a..b]);
                    spans.add(a, b, p);
                }
            }
        }
        spans.apply(host).into_owned()
    }

    /// `Cookie`: names kept, values replaced.
    fn cookie(&mut self, v: &str) -> String {
        self.cookie_values(v, Loc::Header)
    }

    fn cookie_values(&mut self, v: &str, loc: Loc) -> String {
        v.split(';')
            .map(|c| {
                let lead = &c[..c.len() - c.trim_start().len()];
                match c.trim().split_once('=') {
                    Some((n, val)) if !val.trim().is_empty() => format!("{lead}{}={}", n.trim(), self.ph(Cat::Cookie, loc, val.trim())),
                    Some(_) => c.to_string(),
                    None if c.trim().is_empty() => c.to_string(),
                    None => format!("{lead}{}", self.ph(Cat::Cookie, loc, c.trim())),
                }
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    // -------------------------------------------------------------- bodies

    /// The new body bytes; `headers` lose Content-Encoding and get a matching Content-Length.
    fn body(&mut self, headers: &mut Headers, body: &Body, loc: Loc) -> Vec<u8> {
        if body.is_empty() {
            headers.remove("content-encoding");
            return Vec::new();
        }
        let ct = headers.get("content-type").unwrap_or("").to_string();
        let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        let encoded = headers.get("content-encoding").map(str::trim).is_some_and(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity"));
        let decoded = decode_cut(headers, body, MAX_DECODED + 1);
        headers.remove("content-encoding");
        let mut changed = encoded;
        let out = match decoded {
            Err(e) => {
                self.log.add(Cat::Undecodable, loc);
                changed = true;
                format!("<body removed: could not be decoded ({e}), {} {}>", size_label(body.len()), label_mime(&mime)).into_bytes()
            }
            Ok((b, cut)) => {
                let out = match self.opts.bodies {
                    BodyMode::Drop => {
                        self.log.add(Cat::BodyRemoved, loc);
                        Vec::new()
                    }
                    BodyMode::Placeholder => {
                        self.log.add(Cat::BodyRemoved, loc);
                        format!("<body removed: {} {}>", size_label(b.len() as u64), label_mime(&mime)).into_bytes()
                    }
                    BodyMode::Keep if b.len() > MAX_DECODED => {
                        self.log.add(Cat::BodyRemoved, loc);
                        format!("<body removed: larger than {} decoded, {}>", size_label(MAX_DECODED as u64), label_mime(&mime)).into_bytes()
                    }
                    BodyMode::Keep => {
                        let mut out = self.content(&b, &ct, headers, loc);
                        if cut {
                            out.extend_from_slice(format!("…<decoding stopped after {} bytes: the data is damaged or cut>", b.len()).as_bytes());
                            self.log.add(Cat::BodyTruncated, loc);
                        }
                        out
                    }
                    BodyMode::Truncate => {
                        let limit = (self.opts.truncate_kib.max(1) as usize) << 10;
                        // Small enough: scrubbed whole (its structure is understood), then cut.
                        // Larger: only a prefix is scrubbed (as text, a margin beyond the cut so
                        // values crossing it are seen whole).
                        let full = b.len() <= limit || b.len() <= TRUNCATE_WHOLE;
                        let mut out = if full {
                            self.content(&b, &ct, headers, loc)
                        } else {
                            let mut end = (limit + TRUNCATE_MARGIN).min(b.len());
                            while end > 0 && end < b.len() && (b[end] & 0xc0) == 0x80 {
                                end -= 1;
                            }
                            self.content(&b[..end], &ct, headers, loc)
                        };
                        if out.len() > limit {
                            let mut end = limit;
                            if std::str::from_utf8(&out).is_ok() {
                                while end > 0 && (out[end] & 0xc0) == 0x80 {
                                    end -= 1;
                                }
                            }
                            out.truncate(end);
                            let total = if b.len() > MAX_DECODED { format!("more than {}", size_label(MAX_DECODED as u64)) } else { size_label(b.len() as u64) };
                            out.extend_from_slice(format!("…<truncated, {total} decoded>").as_bytes());
                            self.log.add(Cat::BodyTruncated, loc);
                        } else if cut {
                            out.extend_from_slice(format!("…<decoding stopped after {} bytes: the data is damaged or cut>", b.len()).as_bytes());
                            self.log.add(Cat::BodyTruncated, loc);
                        }
                        out
                    }
                };
                changed = changed || out != b;
                out
            }
        };
        if self.stopped() {
            return b"<cancelled>".to_vec();
        }
        if changed {
            // Integrity metadata of the original bytes no longer matches.
            for h in INTEGRITY_HEADERS {
                if headers.contains(h) {
                    headers.remove(h);
                    self.integrity_dropped += 1;
                }
            }
        }
        if headers.contains("content-length") {
            headers.set("content-length", out.len().to_string());
        }
        out
    }

    /// Decoded content by its type.
    fn content(&mut self, b: &[u8], ct: &str, headers: &mut Headers, loc: Loc) -> Vec<u8> {
        let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if mime.starts_with("multipart/")
            && let Some(out) = self.multipart(b, ct, loc)
        {
            return out;
        }
        if !is_text(&mime, b) {
            return self.binary(b, &mime, loc, Cat::BinaryRemoved);
        }
        self.text_bytes(b, ct, headers, loc).unwrap_or_else(|| self.binary(b, &mime, loc, Cat::BinaryRemoved))
    }

    /// A binary body or part.
    fn binary(&mut self, b: &[u8], mime: &str, loc: Loc, cat: Cat) -> Vec<u8> {
        match self.opts.binary {
            BinaryMode::Keep => b.to_vec(),
            BinaryMode::Placeholder => {
                self.log.add(cat, loc);
                let what = if cat == Cat::FileRemoved { "file" } else { "binary body" };
                format!("<{what} removed: {} {}>", size_label(b.len() as u64), label_mime(mime)).into_bytes()
            }
        }
    }

    /// Text in any charset → scrubbed UTF-8 (the Content-Type then says `charset=utf-8`);
    /// `None` when the bytes are no text after all (binary data sent as `text/*`). Invalid
    /// UTF-8 without control bytes is read as windows-1252.
    fn text_bytes(&mut self, b: &[u8], ct: &str, headers: &mut Headers, loc: Loc) -> Option<Vec<u8>> {
        let detected = quena_body::charset::detect(Some(ct).filter(|c| !c.is_empty()), &b[..b.len().min(64 << 10)]);
        let name = detected.name().to_ascii_lowercase();
        let wide = name.starts_with("utf-16");
        let control = |t: &str| t.chars().filter(|c| (c.is_control() && !matches!(c, '\n' | '\r' | '\t' | '\u{c}')) || *c == '\u{fffd}').count();
        let text: Cow<str> = if name == "utf-8" {
            match std::str::from_utf8(b) {
                Ok(t) => Cow::Borrowed(t),
                Err(e) if e.error_len().is_none() => Cow::Owned(String::from_utf8_lossy(b).into_owned()),
                Err(_) => {
                    if b.contains(&0) {
                        return None;
                    }
                    let (t, _) = quena_body::charset::decode(b, quena_body::charset::for_label("windows-1252")?);
                    set_charset_utf8(headers);
                    Cow::Owned(t.into_owned())
                }
            }
        } else {
            if !wide && b.contains(&0) {
                return None;
            }
            let (t, _) = quena_body::charset::decode(b, detected.encoding);
            set_charset_utf8(headers);
            Cow::Owned(t.into_owned())
        };
        // Mostly control characters: binary.
        let sample: String = text.chars().take(8192).collect();
        if !sample.is_empty() && control(&sample) * 10 > sample.chars().count() {
            return None;
        }
        Some(self.text(&text, ct, loc).into_bytes())
    }

    /// Text by its type.
    fn text(&mut self, s: &str, ct: &str, loc: Loc) -> String {
        let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        let t = s.trim_start_matches('\u{feff}').trim_start();
        let html = quena_body::charset::is_html(&mime);
        if mime == "application/x-www-form-urlencoded" {
            return self.form(s, loc);
        }
        if mime == "text/event-stream" {
            return self.sse(s, loc);
        }
        if (quena_body::charset::is_json(&mime) || (!html && (t.starts_with('{') || t.starts_with('['))))
            && let Some(out) = self.json(s, loc)
        {
            return out;
        }
        if !html
            && (quena_body::charset::is_xml(&mime) || t.starts_with("<?xml") || (t.starts_with('<') && mime.is_empty()))
            && let Some(out) = self.xml(s, loc)
        {
            return out;
        }
        self.code = mime.contains("javascript") || mime.contains("ecmascript") || mime == "text/css";
        let enc = if html { Enc::Xml } else { Enc::Raw };
        let out = if s.len() <= 4 * TEXT_CHUNK {
            self.scrub(s, loc, enc).into_owned()
        } else {
            // Large text in pieces ending at line breaks: bounded work per step and a chance
            // to stop when the export is cancelled.
            let mut out = String::with_capacity(s.len());
            let mut pos = 0;
            while pos < s.len() {
                let mut end = (pos + TEXT_CHUNK).min(s.len());
                while !s.is_char_boundary(end) {
                    end += 1;
                }
                if end < s.len() {
                    end = s[end..].find('\n').map_or(s.len(), |i| end + i + 1);
                }
                out.push_str(&self.scrub(&s[pos..end], loc, enc));
                pos = end;
                if self.stopped() {
                    break;
                }
            }
            out
        };
        self.code = false;
        out
    }

    fn form(&mut self, s: &str, loc: Loc) -> String {
        s.split('&')
            .map(|p| {
                let (name, value) = match p.split_once('=') {
                    Some(x) => x,
                    None => return self.scrub(p, loc, Enc::Url).into_owned(),
                };
                let ctx = self.form_ctx(name);
                let v = decode_param(value);
                let new_name = match self.scrub(&decode_param(name), loc, Enc::Raw) {
                    Cow::Owned(n) => encode_component(&n),
                    Cow::Borrowed(_) => name.to_string(),
                };
                match self.value(&v, ctx, loc) {
                    Some(new) => format!("{new_name}={}", encode_component(&new)),
                    None => format!("{new_name}={value}"),
                }
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Server-Sent Events: `data:` lines holding JSON keep their structure.
    fn sse(&mut self, s: &str, loc: Loc) -> String {
        let mut out = String::with_capacity(s.len());
        for line in s.split_inclusive('\n') {
            let body = line.trim_end_matches(['\r', '\n']);
            let end = &line[body.len()..];
            if let Some(rest) = body.strip_prefix("data:") {
                let (sp, data) = rest.strip_prefix(' ').map_or(("", rest), |d| (" ", d));
                let t = data.trim_start();
                if (t.starts_with('{') || t.starts_with('['))
                    && let Some(j) = self.json(data, loc)
                {
                    out.push_str(&format!("data:{sp}{j}{end}"));
                    continue;
                }
            }
            out.push_str(&self.scrub(body, loc, Enc::Raw));
            out.push_str(end);
        }
        out
    }

    /// JSON with its formatting kept; `None` if `s` is not valid JSON.
    fn json(&mut self, s: &str, loc: Loc) -> Option<String> {
        let mut p = JsonParser { b: s.as_bytes(), s, i: 0, out: String::with_capacity(s.len() + 16), depth: 0, n: 0 };
        p.ws();
        p.value(self, Ctx::Plain, loc, "").ok()?;
        p.ws();
        (p.i == p.b.len()).then_some(p.out)
    }

    /// XML with element and attribute values scrubbed (everything else as written);
    /// `None` if `s` is not well-formed. An element named by an attribute
    /// (`<Parameter name="password">`, `<Attribute Name="mail">`, `<property name="client_secret"
    /// value="…"/>`) takes the context of that name; wrappers such as `UsernameToken` or
    /// `Assertion` only make their direct text secret, their children are judged by their own
    /// names (`Password`, `Nonce` yes; `Created`, `Type` attributes no).
    fn xml(&mut self, s: &str, loc: Loc) -> Option<String> {
        use quick_xml::events::Event;
        let mut r = quick_xml::Reader::from_str(s);
        // (context of direct text, context passed to children, local name)
        let mut stack: Vec<(Ctx, Ctx, String)> = Vec::new();
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        let mut text: Option<(usize, usize)> = None;
        let mut seen_element = false;
        let mut n = 0usize;
        loop {
            n += 1;
            if n.is_multiple_of(4096) && self.stopped() {
                return None;
            }
            let start = r.buffer_position() as usize;
            let ev = r.read_event().ok()?;
            let end = r.buffer_position() as usize;
            if matches!(ev, Event::Text(_) | Event::GeneralRef(_)) {
                text = Some((text.map_or(start, |t| t.0), end));
                continue;
            }
            if let Some((a, b)) = text.take() {
                let ctx = stack.last().map_or(Ctx::Plain, |e| e.0);
                let raw = &s[a..b];
                match quick_xml::escape::unescape(raw) {
                    Ok(t) => {
                        if let Some(new) = self.value(&t, ctx, loc) {
                            edits.push((a, b, quick_xml::escape::escape(new.as_str()).into_owned()));
                        }
                    }
                    Err(_) => {
                        if let Cow::Owned(new) = self.scrub(raw, loc, Enc::Xml) {
                            edits.push((a, b, new));
                        }
                    }
                }
            }
            match ev {
                Event::Start(e) | Event::Empty(e) => {
                    seen_element = true;
                    let empty = s[start..end].ends_with("/>");
                    let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                    let lname = name.to_ascii_lowercase();
                    let (parent, pname) = stack.last().map_or((Ctx::Plain, String::new()), |e| (e.1, e.2.clone()));
                    // (qualified key, local name, raw value, unescaped value)
                    let mut attrs: Vec<(String, String, String, Option<String>)> = Vec::new();
                    for a in e.attributes().with_checks(false) {
                        let a = a.ok()?;
                        let key = String::from_utf8_lossy(a.key.as_ref()).into_owned();
                        let local = String::from_utf8_lossy(a.key.local_name().as_ref()).into_owned();
                        let raw = String::from_utf8_lossy(&a.value).into_owned();
                        let un = quick_xml::escape::unescape(&raw).ok().map(Cow::into_owned);
                        attrs.push((key, local, raw, un));
                    }
                    let indirect = attrs.iter().find_map(|(k, local, _, v)| {
                        let v = v.as_deref()?;
                        (!k.starts_with("xmlns") && is_name_key(local) && self.names_a_field(local, v)).then(|| self.field_ctx(v))
                    });
                    let mut own = self.field_ctx(&name);
                    if own == Ctx::Personal && ambiguous_personal(&name) && !person_word(&pname) {
                        own = Ctx::Plain;
                    }
                    let mut text_ctx = parent.child(own);
                    let mut child_ctx = if XML_WRAPPERS.contains(&lname.as_str()) { parent } else { text_ctx };
                    if let Some(c) = indirect {
                        text_ctx = text_ctx.child(c);
                        child_ctx = child_ctx.child(c);
                    }
                    let mut changed = false;
                    let mut out_attrs = Vec::with_capacity(attrs.len());
                    for (key, local, raw, un) in attrs {
                        let mut value = raw.clone();
                        if !key.starts_with("xmlns")
                            && let Some(v) = un
                        {
                            // Attributes describe the element (`<Password Type="…">`): the
                            // context of the parent applies, not the element's own.
                            let actx = if is_name_key(&local) && self.names_a_field(&local, &v) {
                                Ctx::Plain
                            } else if is_value_key(&local) && let Some(c) = indirect {
                                parent.child(c)
                            } else {
                                let mut a = self.field_ctx(&local);
                                if a == Ctx::Personal && ambiguous_personal(&local) && !person_word(&name) {
                                    a = Ctx::Plain;
                                }
                                parent.child(a)
                            };
                            if let Some(new) = self.value(&v, actx, loc) {
                                value = quick_xml::escape::escape(new.as_str()).into_owned();
                                changed = true;
                            }
                        }
                        out_attrs.push((key, value));
                    }
                    if changed {
                        let qname = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                        let mut tag = format!("<{qname}");
                        for (k, v) in out_attrs {
                            tag.push_str(&format!(" {k}=\"{}\"", v.replace('"', "&quot;")));
                        }
                        tag.push_str(if empty { "/>" } else { ">" });
                        edits.push((start, end, tag));
                    }
                    if !empty {
                        stack.push((text_ctx, child_ctx, name));
                    }
                }
                Event::End(_) => {
                    stack.pop();
                }
                Event::CData(c) => {
                    let ctx = stack.last().map_or(Ctx::Plain, |e| e.0);
                    let t = String::from_utf8_lossy(&c).into_owned();
                    if let Some(new) = self.value(&t, ctx, loc) {
                        edits.push((start, end, format!("<![CDATA[{}]]>", new.replace("]]>", "]] >"))));
                    }
                }
                Event::Comment(c) => {
                    let t = String::from_utf8_lossy(&c).into_owned();
                    if let Cow::Owned(new) = self.scrub(&t, loc, Enc::Raw) {
                        edits.push((start, end, format!("<!--{}-->", new.replace("--", "- -"))));
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !seen_element || !stack.is_empty() {
            return None;
        }
        let mut out = String::with_capacity(s.len());
        let mut pos = 0;
        for (a, b, new) in edits {
            out.push_str(&s[pos..a]);
            out.push_str(&new);
            pos = b;
        }
        out.push_str(&s[pos..]);
        Some(out)
    }

    /// `multipart/*`: fields scrubbed, file contents per the binary option.
    fn multipart(&mut self, b: &[u8], ct: &str, loc: Loc) -> Option<Vec<u8>> {
        let boundary = ct.split(';').skip(1).find_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim().eq_ignore_ascii_case("boundary").then(|| v.trim().trim_matches('"').to_string())
        })?;
        if boundary.is_empty() || boundary.len() > 200 {
            return None;
        }
        let delim = format!("--{boundary}").into_bytes();
        let mut starts = Vec::new();
        let mut i = 0;
        while let Some(p) = find(&b[i..], &delim) {
            let at = i + p;
            if at == 0 || b[..at].ends_with(b"\n") {
                starts.push(at);
            }
            i = at + delim.len();
        }
        if starts.len() < 2 {
            return None;
        }
        let mut out = Vec::with_capacity(b.len());
        out.extend_from_slice(&b[..starts[0]]);
        for w in starts.windows(2) {
            let (a, next) = (w[0], w[1]);
            let line_end = a + find(&b[a..next], b"\n")? + 1;
            out.extend_from_slice(&b[a..line_end]);
            let part = &b[line_end..next];
            // The part ends with the line break before the next delimiter.
            let content_end = if part.ends_with(b"\r\n") { part.len() - 2 } else if part.ends_with(b"\n") { part.len() - 1 } else { part.len() };
            let (head_len, sep) = match find(part, b"\r\n\r\n") {
                Some(p) => (p, 4),
                None => (find(part, b"\n\n")?, 2),
            };
            if head_len + sep > content_end {
                out.extend_from_slice(part);
                continue;
            }
            let head = String::from_utf8_lossy(&part[..head_len]).into_owned();
            let content = &part[head_len + sep..content_end];
            let mut name = String::new();
            let mut file = false;
            let mut pct = String::new();
            for line in head.split('\n') {
                let Some((k, v)) = line.trim_end_matches('\r').split_once(':') else { continue };
                let lk = k.trim().to_ascii_lowercase();
                if lk == "content-disposition" {
                    name = disposition_param(v, "name").unwrap_or_default();
                    file = disposition_param(v, "filename").is_some() || disposition_param(v, "filename*").is_some();
                } else if lk == "content-type" {
                    pct = v.trim().to_string();
                }
            }
            let pmime = pct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            let ctx = self.form_ctx(&name);
            let mut part_headers = Headers::new();
            if !pct.is_empty() {
                part_headers.push("Content-Type", pct.clone());
            }
            let new_content: Vec<u8> = if file && self.opts.binary == BinaryMode::Placeholder {
                self.binary(content, &pmime, loc, Cat::FileRemoved)
            } else if !is_text(&pmime, content) {
                if file { content.to_vec() } else { self.binary(content, &pmime, loc, Cat::BinaryRemoved) }
            } else if ctx != Ctx::Plain && !file {
                let t = String::from_utf8_lossy(content);
                self.value(&t, ctx, loc).map(String::into_bytes).unwrap_or_else(|| content.to_vec())
            } else {
                match self.text_bytes(content, &pct, &mut part_headers, loc) {
                    Some(t) => t,
                    None if file => content.to_vec(),
                    None => self.binary(content, &pmime, loc, Cat::BinaryRemoved),
                }
            };
            // The part's Content-Type follows a conversion to UTF-8.
            let new_ct = part_headers.get("content-type").map(str::to_string);
            let mut new_head = Vec::new();
            for line in head.split('\n') {
                let line = line.trim_end_matches('\r');
                let Some((k, v)) = line.split_once(':') else {
                    new_head.push(line.to_string());
                    continue;
                };
                if k.trim().eq_ignore_ascii_case("content-type")
                    && let Some(c) = new_ct.as_deref().filter(|c| *c != pct)
                {
                    new_head.push(format!("{k}: {c}"));
                    continue;
                }
                self.no_kv = k.trim().eq_ignore_ascii_case("content-disposition");
                let v = self.scrub(v, loc, Enc::Raw).into_owned();
                self.no_kv = false;
                new_head.push(format!("{k}:{v}"));
            }
            out.extend_from_slice(new_head.join("\r\n").as_bytes());
            out.extend_from_slice(&part[head_len..head_len + sep]);
            out.extend_from_slice(&new_content);
            out.extend_from_slice(&part[content_end..]);
        }
        out.extend_from_slice(&b[*starts.last().unwrap()..]);
        Some(out)
    }

    /// The WebSocket frame log (see `quena-proxy::wsframe`): text messages scrubbed,
    /// binary ones per the binary option. Messages compressed with `permessage-deflate`
    /// (RSV1 in the record, or an invalid text frame of a session that negotiated it) are
    /// inflated with the per-direction context and written uncompressed; fragmented messages
    /// are joined and written as one frame.
    fn ws_log(&mut self, body: &Body, deflate: bool) -> Vec<u8> {
        let mut b = Vec::new();
        let _ = body.stream(0, false).take(MAX_DECODED as u64 * 4).read_to_end(&mut b);
        if b.is_empty() {
            return b;
        }
        if matches!(self.opts.bodies, BodyMode::Drop | BodyMode::Placeholder) {
            self.log.add(Cat::BodyRemoved, Loc::Ws);
            return Vec::new();
        }
        let mut out = Vec::with_capacity(b.len());
        // Inflate contexts per direction; `None` once a message could not be inflated.
        let mut inflate: [Option<flate2::Decompress>; 2] = [Some(flate2::Decompress::new(false)), Some(flate2::Decompress::new(false))];
        // The message being assembled: (record header of its first frame, payload, frames).
        let mut pending: [Option<WsPending>; 2] = [None, None];
        let mut joined = 0usize;
        let mut pos = 0;
        let mut n = 0usize;
        while pos + 16 <= b.len() {
            n += 1;
            if n.is_multiple_of(256) && self.stopped() {
                return b"<cancelled>".to_vec();
            }
            let len = u32::from_le_bytes(b[pos + 12..pos + 16].try_into().unwrap()) as usize;
            let Some(payload) = b.get(pos + 16..pos + 16 + len) else { break };
            let mut head: [u8; 12] = b[pos..pos + 12].try_into().unwrap();
            let (dir, opcode, fin) = (head[0] as usize & 1, head[1], head[2] != 0);
            pos += 16 + len;
            match opcode {
                1 | 2 if !fin => {
                    if let Some(p) = pending[dir].take() {
                        // A new message before the old one ended: write what there was.
                        let msg = self.ws_message(p.0, &p.1, deflate, &mut inflate[dir]);
                        ws_record(&mut out, p.0, &msg);
                    }
                    pending[dir] = Some((head, payload.to_vec(), 1));
                    continue;
                }
                0 => {
                    match pending[dir].as_mut() {
                        Some(p) => {
                            p.1.extend_from_slice(payload);
                            p.2 += 1;
                        }
                        None => {
                            // A continuation without its start (the log began mid-message).
                            head[1] = 2;
                            pending[dir] = Some((head, payload.to_vec(), 1));
                        }
                    }
                    if fin && let Some(p) = pending[dir].take() {
                        if p.2 > 1 {
                            joined += 1;
                        }
                        let msg = self.ws_message(p.0, &p.1, deflate, &mut inflate[dir]);
                        ws_record(&mut out, p.0, &msg);
                    }
                    continue;
                }
                1 | 2 => {
                    let msg = self.ws_message(head, payload, deflate, &mut inflate[dir]);
                    ws_record(&mut out, head, &msg);
                }
                8 if payload.len() > 2 => {
                    let mut v = payload[..2].to_vec();
                    v.extend_from_slice(self.scrub(&String::from_utf8_lossy(&payload[2..]), Loc::Ws, Enc::Raw).as_bytes());
                    ws_record(&mut out, head, &v);
                }
                9 | 0xa if !payload.is_empty() && self.opts.binary == BinaryMode::Placeholder => {
                    self.log.add(Cat::BinaryRemoved, Loc::Ws);
                    ws_record(&mut out, head, format!("<binary message removed: {}>", size_label(payload.len() as u64)).as_bytes());
                }
                _ => ws_record(&mut out, head, payload),
            }
        }
        for dir in 0..2 {
            if let Some(p) = pending[dir].take() {
                let msg = self.ws_message(p.0, &p.1, deflate, &mut inflate[dir]);
                ws_record(&mut out, p.0, &msg);
            }
        }
        if joined > 0 {
            self.ws_joined += joined;
        }
        out
    }

    /// One complete data message (record header of its first frame, payload as logged).
    fn ws_message(&mut self, head: [u8; 12], payload: &[u8], deflate: bool, inflate: &mut Option<flate2::Decompress>) -> Vec<u8> {
        let text = head[1] == 1;
        let rsv1 = head[3] & 0x4 != 0;
        // Old logs have no RSV bits: a text message that is no UTF-8 in a deflate session.
        let compressed = deflate && !payload.is_empty() && (rsv1 || (head[3] == 0 && text && std::str::from_utf8(payload).is_err()));
        let data: Cow<[u8]> = if compressed {
            match inflate.as_mut().and_then(|d| ws_inflate(d, payload)) {
                Some(d) => Cow::Owned(d),
                None => {
                    // The shared context is lost: later messages cannot be inflated either.
                    *inflate = None;
                    self.log.add(Cat::Undecodable, Loc::Ws);
                    return format!("<compressed message removed: {}>", size_label(payload.len() as u64)).into_bytes();
                }
            }
        } else {
            Cow::Borrowed(payload)
        };
        if !text {
            if self.opts.binary == BinaryMode::Placeholder && !data.is_empty() {
                self.log.add(Cat::BinaryRemoved, Loc::Ws);
                return format!("<binary message removed: {}>", size_label(data.len() as u64)).into_bytes();
            }
            return data.into_owned();
        }
        self.log.ws_messages += 1;
        let Ok(t) = std::str::from_utf8(&data) else {
            self.log.add(Cat::Undecodable, Loc::Ws);
            return format!("<text message removed: not UTF-8, {}>", size_label(data.len() as u64)).into_bytes();
        };
        let tt = t.trim_start();
        let json = if tt.starts_with('{') || tt.starts_with('[') { self.json(t, Loc::Ws) } else { None };
        let mut new = json.unwrap_or_else(|| self.scrub(t, Loc::Ws, Enc::Raw).into_owned()).into_bytes();
        let limit = (self.opts.truncate_kib.max(1) as usize) << 10;
        if self.opts.bodies == BodyMode::Truncate && new.len() > limit {
            let mut end = limit;
            while end > 0 && (new[end] & 0xc0) == 0x80 {
                end -= 1;
            }
            new.truncate(end);
            new.extend_from_slice("…<truncated>".as_bytes());
            self.log.add(Cat::BodyTruncated, Loc::Ws);
        }
        new
    }

    // -------------------------------------------------------------- metadata

    fn scrub_in_place(&mut self, s: &mut String) {
        let new = match self.scrub(s, Loc::Meta, Enc::Raw) {
            Cow::Owned(n) => Some(n),
            Cow::Borrowed(_) => None,
        };
        if let Some(n) = new {
            *s = n;
        }
    }

    fn meta(&mut self, d: &mut SessionDetail) {
        let o = self.flags();
        self.scrub_in_place(&mut d.summary.comment);
        self.scrub_in_place(&mut d.summary.custom);
        if let Some(e) = d.error.as_mut() {
            self.scrub_in_place(e);
        }
        if let Some(g) = d.connection.gateway.as_mut() {
            self.scrub_in_place(g);
        }
        if o.process {
            if let Some(p) = d.process.as_mut()
                && !p.name.is_empty()
            {
                p.name = self.ph(Cat::Process, Loc::Meta, &p.name.clone());
                p.pid = 0;
                d.summary.process = p.display();
            } else if !d.summary.process.is_empty() {
                let name = d.summary.process.rsplit_once(':').map_or(d.summary.process.as_str(), |(n, _)| n).to_string();
                d.summary.process = self.ph(Cat::Process, Loc::Meta, &name);
            }
        }
        if o.ips {
            for a in [&mut d.connection.client_addr, &mut d.connection.server_addr].into_iter().flatten() {
                let (ip, port) = split_addr(a);
                if !ip.is_empty() && !ip.starts_with('<') {
                    let p = self.ph(Cat::Ip, Loc::Meta, &ip);
                    *a = match port {
                        Some(port) => format!("{p}:{port}"),
                        None => p,
                    };
                }
            }
            if !d.summary.client_ip.is_empty() && !d.summary.client_ip.starts_with('<') {
                d.summary.client_ip = self.ph(Cat::Ip, Loc::Meta, &d.summary.client_ip.clone());
            }
        }
        let flags = std::mem::take(&mut d.extra_flags);
        for (k, v) in flags {
            let lk = k.to_ascii_lowercase();
            let v = match lk.as_str() {
                "x-clientip" | "x-hostip" | "x-client-ip" | "x-egressip" if o.ips && !v.is_empty() => self.ph(Cat::Ip, Loc::Meta, &v),
                "x-overridehost" | "x-hostheader" | "x-original-host" => self.authority(&v, Loc::Meta),
                "x-quena-mapped-from" | "x-originalurl" | "x-redirecturl" => self.url(&v, Loc::Meta),
                "x-autoauth" | "x-password" | "x-pwd" | "x-credentials" if o.body_secrets && !v.is_empty() => self.ph(Cat::SecretField, Loc::Meta, &v),
                "x-username" | "x-user" | "x-userid" | "x-user-name" if o.personal_fields && !v.is_empty() => self.ph(Cat::PersonalField, Loc::Meta, &v),
                "x-processinfo" | "x-processname" if o.process && !v.is_empty() => {
                    let name = v.rsplit_once(':').map_or(v.as_str(), |(n, _)| n).to_string();
                    self.ph(Cat::Process, Loc::Meta, &name)
                }
                _ => self.scrub(&v, Loc::Meta, Enc::Raw).into_owned(),
            };
            d.extra_flags.push((k, v));
        }
    }
}

/// A data message being assembled: record header of its first frame, payload, frames.
type WsPending = ([u8; 12], Vec<u8>, usize);

/// One frame record (see `quena-proxy::wsframe`), written complete and uncompressed.
fn ws_record(out: &mut Vec<u8>, head: [u8; 12], payload: &[u8]) {
    out.push(head[0]);
    out.push(head[1]);
    out.push(1);
    out.push(0);
    out.extend_from_slice(&head[4..12]);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

/// Inflate one `permessage-deflate` message (RFC 7692: raw deflate, the trailing
/// `00 00 ff ff` removed by the sender) with the direction's context.
fn ws_inflate(d: &mut flate2::Decompress, payload: &[u8]) -> Option<Vec<u8>> {
    let mut input = payload.to_vec();
    input.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut out = Vec::with_capacity(payload.len() * 3 + 64);
    let start_in = d.total_in();
    loop {
        let consumed = (d.total_in() - start_in) as usize;
        if out.len() >= MAX_DECODED {
            return None;
        }
        if out.capacity() - out.len() < 4096 {
            out.reserve(out.capacity().max(4096));
        }
        let (before_in, before_out) = (d.total_in(), d.total_out());
        let st = d.decompress_vec(&input[consumed..], &mut out, flate2::FlushDecompress::Sync).ok()?;
        let done_in = (d.total_in() - start_in) as usize >= input.len();
        if d.total_in() == before_in && d.total_out() == before_out && !done_in {
            return None;
        }
        if matches!(st, flate2::Status::StreamEnd) || (done_in && d.total_out() == before_out) {
            break;
        }
        if done_in && out.len() < out.capacity() {
            break;
        }
    }
    Some(out)
}

/// `ip:port`, `[v6]:port`, `ip` → (ip, port).
fn split_addr(a: &str) -> (String, Option<String>) {
    if let Some(rest) = a.strip_prefix('[')
        && let Some((ip, port)) = rest.split_once("]:")
    {
        return (ip.to_string(), Some(port.to_string()));
    }
    match a.rsplit_once(':') {
        Some((ip, port)) if !ip.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => (ip.to_string(), Some(port.to_string())),
        _ => (a.to_string(), None),
    }
}

/// URL parts through the sanitizer.
struct UrlScrub<'a> {
    s: &'a mut Sanitizer,
    loc: Loc,
}

impl UrlRewrite for UrlScrub<'_> {
    fn userinfo(&mut self, userinfo: &str) -> String {
        if !self.s.opts.url_secrets || userinfo.is_empty() {
            return userinfo.to_string();
        }
        encode_component(&self.s.ph(Cat::UserInfo, self.loc, userinfo))
    }
    fn host(&mut self, host: &str) -> String {
        let new = self.s.host(host, self.loc);
        if new == host { new } else { encode_component(&new) }
    }
    fn path(&mut self, path: &str) -> String {
        let mut prev = String::new();
        path.split('/')
            .map(|seg| {
                // `segment;name=value` (matrix parameters, `;jsessionid=…`).
                let (main, matrix) = match seg.split_once(';') {
                    Some((m, x)) => (m, Some(x)),
                    None => (seg, None),
                };
                let d = decode_param(&main.replace('+', "%2B"));
                let mut out = if self.s.opts.url_secrets && path_token(&prev, &d) {
                    encode_component(&self.s.ph(Cat::UrlSecret, self.loc, &d))
                } else {
                    match self.s.scrub(&d, self.loc, Enc::Raw) {
                        Cow::Owned(n) => encode_component(&n),
                        Cow::Borrowed(_) => main.to_string(),
                    }
                };
                if let Some(x) = matrix {
                    for piece in x.split(';') {
                        out.push(';');
                        out.push_str(&self.param(piece));
                    }
                }
                prev = d.to_ascii_lowercase();
                out
            })
            .collect::<Vec<_>>()
            .join("/")
    }
    fn param(&mut self, piece: &str) -> String {
        let Some((name, value)) = piece.split_once('=') else {
            return match self.s.scrub(&decode_param(piece), self.loc, Enc::Raw) {
                Cow::Owned(n) => encode_component(&n),
                Cow::Borrowed(_) => piece.to_string(),
            };
        };
        let ctx = self.s.param_ctx(name);
        match self.s.value(&decode_param(value), ctx, self.loc) {
            Some(new) => format!("{name}={}", encode_component(&new)),
            None => piece.to_string(),
        }
    }
    fn fragment(&mut self, f: &str) -> String {
        match self.s.scrub(&decode_param(f), self.loc, Enc::Raw) {
            Cow::Owned(n) => encode_component(&n),
            Cow::Borrowed(_) => f.to_string(),
        }
    }
}

/// Whether the path segment `seg` after the segment `prev` (lower case) is a token:
/// `/token/…`, `/api-key/…` (6+ characters with a digit, or 12+), `/reset/…`, `/verify/…`,
/// `/invite/…`, `/magic/…` … (16+ characters mixing letters and digits, or 24+).
fn path_token(prev: &str, seg: &str) -> bool {
    const STRONG: &[&str] = &["token", "tokens", "secret", "secrets", "key", "keys", "apikey", "api-key", "api_key", "password", "passwords", "session", "sessions", "jwt", "otp"];
    const ACTION: &[&str] = &[
        "reset", "verify", "verification", "confirm", "confirmation", "invite", "invites", "invitation", "invitations", "magic", "magic-link", "magiclink", "activate",
        "activation", "unsubscribe", "password-reset", "reset-password", "passwordreset", "recover", "recovery", "sso", "login", "signin", "sign-in", "auth", "share",
        "s", "t", "download-token", "accept",
    ];
    let alnum = seg.bytes().filter(|b| b.is_ascii_alphanumeric()).count();
    let digits = seg.bytes().any(|b| b.is_ascii_digit());
    let letters = seg.bytes().any(|b| b.is_ascii_alphabetic());
    let tokenish = !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~=+".contains(&b)) && !seg.contains("..");
    if !tokenish {
        return false;
    }
    if STRONG.contains(&prev) {
        return (alnum >= 6 && digits && letters) || alnum >= 12;
    }
    ACTION.contains(&prev) && ((alnum >= 16 && digits && letters) || alnum >= 24)
}

// ------------------------------------------------------------------ JSON

/// A JSON tokenizer that copies its input and replaces scalar values.
struct JsonParser<'a> {
    b: &'a [u8],
    s: &'a str,
    i: usize,
    out: String,
    depth: usize,
    /// Values seen (cancellation is checked every few thousand).
    n: usize,
}

impl JsonParser<'_> {
    fn ws(&mut self) {
        let start = self.i;
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
        self.out.push_str(&self.s[start..self.i]);
    }

    fn value(&mut self, z: &mut Sanitizer, ctx: Ctx, loc: Loc, key: &str) -> Result<(), ()> {
        self.depth += 1;
        if self.depth > 512 {
            return Err(());
        }
        self.n += 1;
        if self.n.is_multiple_of(4096) && z.stopped() {
            return Err(());
        }
        let r = match self.b.get(self.i).ok_or(())? {
            b'{' => self.object(z, ctx, loc, key),
            b'[' => self.array(z, ctx, loc, key),
            b'"' => {
                let (a, v) = self.string()?;
                match z.value(&v, ctx, loc) {
                    Some(new) => self.out.push_str(&serde_json::to_string(&new).map_err(|_| ())?),
                    None => self.out.push_str(&self.s[a..self.i]),
                }
                Ok(())
            }
            b'-' | b'0'..=b'9' => {
                let start = self.i;
                while self.i < self.b.len() && matches!(self.b[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    self.i += 1;
                }
                let raw = &self.s[start..self.i];
                let ok = raw.trim_start_matches('-').bytes().next().is_some_and(|b| b.is_ascii_digit());
                if !ok {
                    return Err(());
                }
                match z.number(raw, ctx, loc) {
                    Some(p) => self.out.push_str(&serde_json::to_string(&p).map_err(|_| ())?),
                    None => self.out.push_str(raw),
                }
                Ok(())
            }
            _ => {
                for lit in ["true", "false", "null"] {
                    if self.s[self.i..].starts_with(lit) {
                        self.out.push_str(lit);
                        self.i += lit.len();
                        self.depth -= 1;
                        return Ok(());
                    }
                }
                Err(())
            }
        };
        self.depth -= 1;
        r
    }

    fn object(&mut self, z: &mut Sanitizer, ctx: Ctx, loc: Loc, pkey: &str) -> Result<(), ()> {
        let info = if self.depth < 64 { self.peek_object() } else { Vec::new() };
        let shape = z.object_shape(&info, pkey);
        let mut idx = 0;
        self.out.push('{');
        self.i += 1;
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.out.push('}');
            self.i += 1;
            return Ok(());
        }
        loop {
            if self.b.get(self.i) != Some(&b'"') {
                return Err(());
            }
            let (a, key) = self.string()?;
            // Keys can be personal too (maps keyed by e-mail).
            match z.scrub(&key, loc, Enc::Raw) {
                Cow::Owned(k) => self.out.push_str(&serde_json::to_string(&k).map_err(|_| ())?),
                Cow::Borrowed(_) => self.out.push_str(&self.s[a..self.i]),
            }
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(());
            }
            self.out.push(':');
            self.i += 1;
            self.ws();
            let v = info.get(idx).filter(|m| m.0 == key).and_then(|m| m.1.as_deref());
            idx += 1;
            let own = z.member_ctx(&key, v, &shape);
            let child = ctx.child(own);
            self.value(z, child, loc, &key)?;
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.out.push(',');
                    self.i += 1;
                    self.ws();
                }
                Some(b'}') => {
                    self.out.push('}');
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(()),
            }
        }
    }

    /// The members of the object at `i` (key, string value) without consuming it; empty
    /// when it is not well-formed.
    fn peek_object(&mut self) -> Vec<(String, Option<String>)> {
        let i = self.i;
        let mut out = Vec::new();
        let ok = self.skim_object(&mut out).is_ok();
        self.i = i;
        if ok { out } else { Vec::new() }
    }

    fn skim_object(&mut self, out: &mut Vec<(String, Option<String>)>) -> Result<(), ()> {
        self.i += 1;
        self.skip_ws();
        if self.b.get(self.i) == Some(&b'}') {
            return Ok(());
        }
        loop {
            if self.b.get(self.i) != Some(&b'"') {
                return Err(());
            }
            let (_, key) = self.string()?;
            self.skip_ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(());
            }
            self.i += 1;
            self.skip_ws();
            let v = if self.b.get(self.i) == Some(&b'"') { Some(self.string()?.1) } else { self.skip_value(0)?; None };
            out.push((key, v));
            self.skip_ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                    self.skip_ws();
                }
                Some(b'}') => return Ok(()),
                _ => return Err(()),
            }
        }
    }

    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    /// Skip a value (no output).
    fn skip_value(&mut self, depth: usize) -> Result<(), ()> {
        if depth > 512 {
            return Err(());
        }
        match *self.b.get(self.i).ok_or(())? {
            b'"' => {
                self.string()?;
            }
            open @ (b'{' | b'[') => {
                let close = if open == b'{' { b'}' } else { b']' };
                self.i += 1;
                loop {
                    self.skip_ws();
                    match *self.b.get(self.i).ok_or(())? {
                        c if c == close => {
                            self.i += 1;
                            return Ok(());
                        }
                        b',' | b':' => self.i += 1,
                        _ => self.skip_value(depth + 1)?,
                    }
                }
            }
            _ => {
                let start = self.i;
                while self.i < self.b.len() && !matches!(self.b[self.i], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r' | b':') {
                    self.i += 1;
                }
                if self.i == start {
                    return Err(());
                }
            }
        }
        Ok(())
    }

    fn array(&mut self, z: &mut Sanitizer, ctx: Ctx, loc: Loc, key: &str) -> Result<(), ()> {
        self.out.push('[');
        self.i += 1;
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.out.push(']');
            self.i += 1;
            return Ok(());
        }
        loop {
            self.value(z, ctx, loc, key)?;
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.out.push(',');
                    self.i += 1;
                    self.ws();
                }
                Some(b']') => {
                    self.out.push(']');
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(()),
            }
        }
    }

    /// A string token at `i`: (its start, decoded value); `i` is then after it.
    fn string(&mut self) -> Result<(usize, String), ()> {
        let start = self.i;
        self.i += 1;
        let mut v = String::new();
        let mut run = self.i;
        loop {
            let c = *self.b.get(self.i).ok_or(())?;
            match c {
                b'"' => {
                    v.push_str(&self.s[run..self.i]);
                    self.i += 1;
                    return Ok((start, v));
                }
                b'\\' => {
                    v.push_str(&self.s[run..self.i]);
                    let e = *self.b.get(self.i + 1).ok_or(())?;
                    self.i += 2;
                    match e {
                        b'"' => v.push('"'),
                        b'\\' => v.push('\\'),
                        b'/' => v.push('/'),
                        b'b' => v.push('\u{8}'),
                        b'f' => v.push('\u{c}'),
                        b'n' => v.push('\n'),
                        b'r' => v.push('\r'),
                        b't' => v.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let c = if (0xd800..0xdc00).contains(&hi) && self.s[self.i..].starts_with("\\u") {
                                self.i += 2;
                                let lo = self.hex4()?;
                                char::from_u32(0x10000 + ((hi - 0xd800) << 10) + (lo.wrapping_sub(0xdc00) & 0x3ff))
                            } else {
                                char::from_u32(hi)
                            };
                            v.push(c.unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(()),
                    }
                    run = self.i;
                }
                0..=0x1f => return Err(()),
                _ => self.i += 1,
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ()> {
        let h = self.s.get(self.i..self.i + 4).ok_or(())?;
        self.i += 4;
        u32::from_str_radix(h, 16).map_err(|_| ())
    }
}

// ------------------------------------------------------------------ spans

/// Non-overlapping replacements in a string, ordered by start (lookups are logarithmic, so
/// texts with many findings stay linear).
#[derive(Default, Clone)]
struct Spans(BTreeMap<usize, (usize, String)>);

impl Spans {
    fn free(&self, a: usize, b: usize) -> bool {
        a < b && self.0.range(..b).next_back().is_none_or(|(_, (end, _))| *end <= a)
    }
    fn add(&mut self, a: usize, b: usize, r: String) {
        self.0.insert(a, (b, r));
    }
    fn apply<'a>(self, s: &'a str) -> Cow<'a, str> {
        if self.0.is_empty() {
            return Cow::Borrowed(s);
        }
        let mut out = String::with_capacity(s.len());
        let mut pos = 0;
        for (a, (b, r)) in self.0 {
            out.push_str(&s[pos..a]);
            out.push_str(&r);
            pos = b;
        }
        out.push_str(&s[pos..]);
        Cow::Owned(out)
    }
}

// ------------------------------------------------------------------ names

/// The words of a field, parameter or header name, lower case: split at every character that
/// is no letter or digit, at camelCase humps (`apiKey`, `APIKey`) and between letters and
/// digits (`otp2`).
pub(crate) fn name_words(n: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = n.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if !cur.is_empty() {
            let p = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            let hump = (p.is_lowercase() && c.is_uppercase()) || (p.is_uppercase() && c.is_uppercase() && next_lower);
            let digit = p.is_ascii_digit() != c.is_ascii_digit();
            if hump || digit {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Whether values named `n` (a JSON / XML / form / multipart field, a query parameter, a
/// header) are secrets. One classifier for every place: the name is split into words
/// ([`name_words`]) and the words are matched, so `passenger`, `compass` or `keyboard` are no
/// secrets while `pass`, `pwd`, `otpCode`, `X-Api-Key` or `client_secret` are. Metadata about
/// secrets (`token_type`, `password_length`, `token_endpoint`, `expires_in` …) is not secret.
pub(crate) fn secret_name(n: &str) -> bool {
    let w = name_words(n);
    if w.is_empty() {
        return false;
    }
    let joined = w.concat();
    const EXACT: &[&str] = &[
        "saml", "sig", "nonce", "otp", "totp", "hotp", "auth", "sid", "pin", "cvv", "cvc", "cvv2", "cvn", "tan", "pw", "pwd", "pass", "passwd",
        "passcode", "bearer", "csrf", "xsrf", "mfa", "codeverifier", "codechallenge", "loginhint", "idtokenhint", "privatekey", "authorization", "proxyauthorization",
        "cookie", "setcookie", "jwt", "assertion", "ticket", "credential", "credentials", "apikey", "secret", "signature", "hmac", "authcode", "authkey", "sessionkey",
        "samlresponse", "samlrequest", "samlart", "relaystate", "wresult", "mnemonic", "seedphrase",
    ];
    if EXACT.contains(&joined.as_str()) {
        return true;
    }
    // Metadata about a secret.
    const NOT_LAST: &[&str] = &[
        "type", "types", "count", "length", "len", "size", "enabled", "enable", "required", "expires", "expiry", "expiration", "ttl", "timeout", "policy", "endpoint",
        "endpoints", "uri", "url", "urls", "supported", "methods", "method", "name", "names", "format", "mode", "status", "label", "version", "path", "domain", "header",
        "headers", "field", "fields", "param", "params", "parameter", "parameters", "prefix", "location", "scope", "scopes", "strength", "rules", "at", "in", "kind",
        "visible", "lifetime", "duration", "age", "valid", "validity", "algorithm", "alg", "algs", "provider", "providers", "store", "storage", "file", "dir", "hint",
        "placeholder", "pattern", "description", "title", "text", "message", "error", "errors", "changed", "updated", "created", "used", "set", "mask", "masked", "attempts",
        "retries", "complexity", "min", "max", "minimum", "maximum",
    ];
    const NOT_ANY: &[&str] = &["expires", "expiry", "expiration", "issued", "supported", "endpoint"];
    let last = w.last().map(String::as_str).unwrap_or("");
    if (NOT_LAST.contains(&last) && w.len() > 1) || w.iter().any(|x| NOT_ANY.contains(&x.as_str())) {
        return false;
    }
    const WORDS: &[&str] = &[
        "pwd", "pw", "pass", "passwd", "password", "passwords", "passwort", "kennwort", "passphrase", "passcode", "secret", "secrets", "token", "tokens", "bearer",
        "apikey", "credential", "credentials", "signature", "session", "sessionid", "cookie", "cookies", "csrf", "xsrf", "otp", "totp", "hotp", "mfa", "jwt",
        "assertion", "ticket", "privatekey", "saml", "samlresponse", "samlrequest", "pin", "nonce", "sig", "hmac", "cvv", "cvc", "mnemonic", "accesstoken",
        "refreshtoken", "idtoken", "authtoken", "clientsecret", "jsessionid", "phpsessid", "aspsessionid",
    ];
    if w.iter().any(|x| WORDS.contains(&x.as_str())) {
        return true;
    }
    // Compounds written without separators (`clientsecret`, `x_apikey`, `jsessionid`).
    const PARTS: &[&str] = &[
        "password", "passwd", "passwort", "kennwort", "passphrase", "apikey", "accesskey", "secretkey", "privatekey", "clientsecret", "credential", "csrf", "xsrf",
        "samlresponse", "samlrequest", "sessionid", "sessiontoken", "accesstoken", "refreshtoken", "idtoken", "authtoken", "authcode", "authkey", "bearertoken", "otpcode",
        "mfacode",
    ];
    if PARTS.iter().any(|p| joined.contains(p)) || ["token", "tokens", "secret", "signature"].iter().any(|p| joined.ends_with(p)) {
        return true;
    }
    // Word pairs.
    for pair in w.windows(2) {
        let (a, b) = (pair[0].as_str(), pair[1].as_str());
        let hit = match b {
            "key" | "keys" => matches!(
                a,
                "access" | "secret" | "api" | "auth" | "private" | "session" | "signing" | "sign" | "encryption" | "encrypt" | "master" | "subscription" | "client" | "app"
                    | "consumer" | "shared" | "crypto" | "license" | "ssh" | "gpg" | "pgp" | "hmac" | "aes" | "account" | "storage" | "service" | "recovery" | "secure"
            ),
            "code" | "codes" => matches!(
                a,
                "auth" | "authorization" | "recovery" | "verification" | "verify" | "otp" | "mfa" | "totp" | "sms" | "reset" | "confirmation" | "confirm" | "activation"
                    | "security" | "access" | "backup" | "login" | "device" | "user" | "pairing" | "pin" | "invite" | "invitation" | "secret" | "fa" | "challenge" | "one"
                    | "email" | "phone" | "magic"
            ),
            "answer" | "answers" => matches!(a, "security" | "secret" | "recovery" | "challenge"),
            "phrase" => matches!(a, "pass" | "secret" | "recovery" | "seed"),
            "number" => matches!(a, "pin" | "tan" | "cvv"),
            _ => false,
        };
        if hit {
            return true;
        }
    }
    false
}

/// Names that are secrets only with a value that looks like one (`"key": "title"` is an i18n
/// key, `"key": "sk_live_…"` an API key; `"code": "DE"` or `200`, `?code=` of OAuth).
pub(crate) fn weak_secret_name(n: &str) -> bool {
    matches!(name_words(n).concat().as_str(), "key" | "code" | "refresh" | "hash")
}

/// Whether `v` looks like a credential: no spaces, and long and random enough. Fields need
/// 16+ characters mixing letters and digits or both cases with some variety; parameters
/// (`loose`) 6+ characters with a digit, or upper case with a token character (OAuth codes
/// are often short), but not a plain word, number or language code.
fn credential_value(v: &str, loose: bool) -> bool {
    let v = v.trim();
    if v.is_empty() || v.contains(char::is_whitespace) || v.starts_with('<') {
        return false;
    }
    let letters = v.bytes().any(|b| b.is_ascii_alphabetic());
    let digits = v.bytes().any(|b| b.is_ascii_digit());
    let upper = v.bytes().any(|b| b.is_ascii_uppercase());
    let lower = v.bytes().any(|b| b.is_ascii_lowercase());
    let special = v.bytes().any(|b| b"-_.~+/=".contains(&b));
    let mut distinct: Vec<u8> = v.bytes().collect();
    distinct.sort_unstable();
    distinct.dedup();
    if loose {
        return v.len() >= 6 && letters && (digits || (special && upper)) && distinct.len() >= 5;
    }
    v.len() >= 16 && distinct.len() >= 8 && ((letters && digits) || (upper && lower))
}

/// Body field names whose values are secrets.
fn secret_field(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    secret_name(n) || l.starts_with("x-amz-") || l.starts_with("x-goog-")
}

/// Query / form parameter names whose values are secrets: the field rules plus the short
/// names of OAuth (`state`) and signed URLs (Azure SAS, AWS, GCS).
fn secret_param_name(n: &str) -> bool {
    const EXACT: &[&str] = &["state", "se", "sp", "sv", "sr", "st", "spr", "srt", "ss", "si", "sdd", "skoid", "sktid", "skt", "ske", "sks", "skv", "x-amz-credential"];
    let l = n.trim().to_ascii_lowercase();
    EXACT.contains(&l.as_str()) || secret_field(n.trim())
}

/// Names of personal data fields (lower case, with or without `_`, `-`, `.`).
fn personal_name(n: &str) -> bool {
    let n: String = n.chars().filter(|c| !matches!(c, '_' | '-' | '.' | ' ')).collect();
    const EXACT: &[&str] = &[
        "name", "fullname", "displayname", "username", "nickname", "givenname", "familyname", "surname", "middlename", "maidenname", "address", "address1", "address2",
        "zip", "zipcode", "postalcode", "postcode", "plz", "city", "town", "ort", "wohnort", "dob", "tel", "fax", "mail", "phone", "mobile", "iban", "bic", "ssn",
        "svnr", "rvnr", "taxid", "taxnumber", "steuerid", "steuernummer", "vorname", "nachname", "geburtsname", "hausnummer", "housenumber", "anschrift", "adresse",
        "handy", "telefon", "passport", "passportnumber", "idnumber", "nationalid", "ausweisnummer", "personalausweisnummer", "gender", "geschlecht", "nationality",
        "staatsangehoerigkeit", "staatsangehörigkeit", "religion", "accountnumber", "kontonummer", "cardholder", "cardholdername", "kontoinhaber", "socialsecuritynumber",
        "sozialversicherungsnummer", "nameid", "upn", "lat", "lng", "latitude", "longitude", "geolocation",
    ];
    const PARTS: &[&str] = &[
        "firstname", "lastname", "fullname", "surname", "email", "phone", "mobile", "street", "strasse", "straße", "postalcode", "zipcode", "birth", "geburt", "iban",
        "taxid", "vorname", "nachname", "telefon", "address", "adresse", "anschrift",
    ];
    EXACT.contains(&n.as_str()) || PARTS.iter().any(|p| n.contains(p))
}

/// Header names whose values are secrets (lower case).
fn secret_header(n: &str) -> bool {
    const PARTS: &[&str] = &["token", "secret", "signature", "apikey", "api-key", "api_key", "csrf", "xsrf", "session", "credential", "password", "passwd", "jwt"];
    const NOT: &[&str] = &[
        "sec-websocket-key", "sec-websocket-accept", "sec-websocket-extensions", "sec-websocket-version", "access-control-allow-headers", "access-control-expose-headers",
        "access-control-request-headers", "access-control-allow-credentials", "x-ms-client-principal-name", "x-ms-client-principal-idp",
    ];
    if NOT.contains(&n) {
        return false;
    }
    PARTS.iter().any(|p| n.contains(p))
        || secret_name(n)
        || n.ends_with("-key")
        || n.starts_with("x-auth")
        || n.starts_with("x-ms-client-principal")
        || matches!(n, "x-amz-security-token" | "dpop" | "x-access" | "x-autoauth" | "x-pwd" | "x-pass")
}

/// Header names whose values identify a person (`X-Forwarded-User`, `X-Remote-User`,
/// `X-MS-CLIENT-PRINCIPAL-NAME`, client certificates …); not `User-Agent`.
fn personal_header(n: &str) -> bool {
    let w = name_words(n);
    if w.iter().any(|x| x == "agent") || n.starts_with("sec-ch-") {
        return false;
    }
    let cert = n.contains("client-cert") || n.contains("ssl-client") || n.contains("client-dn") || n.contains("clientcert") || n.contains("client-subject");
    cert || w.iter().any(|x| matches!(x.as_str(), "user" | "username" | "principal" | "email" | "mail" | "upn" | "login")) || personal_name(&w.iter().filter(|x| *x != "x").cloned().collect::<String>())
}

fn disposition_param(v: &str, name: &str) -> Option<String> {
    v.split(';').skip(1).find_map(|p| {
        let (k, val) = p.split_once('=')?;
        k.trim().eq_ignore_ascii_case(name).then(|| val.trim().trim_matches('"').to_string())
    })
}

// ------------------------------------------------------------------ detectors

macro_rules! regexes {
    ($($name:ident = $re:expr;)*) => {
        $(static $name: (OnceLock<Regex>, &str) = (OnceLock::new(), $re);)*
    };
}

regexes! {
    JWT = r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)?";
    EMAIL = r"(?i)[\p{L}\p{N}][\p{L}\p{N}._+'\-]{0,63}(?:@|%40|&#64;|&#x40;|&commat;)(?:[\p{L}\p{N}](?:[\p{L}\p{N}\-]{0,61}[\p{L}\p{N}])?\.)+\p{L}{2,24}";
    IBAN = r"(?i)[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}";
    CARD = r"\b[0-9](?:[ \-]?[0-9]){12,18}\b";
    TAX_ID = r"\b[1-9][0-9](?: ?[0-9]{3}){3}\b";
    SVNR = r"\b[0-9]{2} ?[0-9]{6} ?[A-Z] ?[0-9]{3}\b";
    PHONE = r"(?:\+[1-9]|\(0\)|\(0[1-9][0-9]{0,4}\)|\b0)[0-9 ()\-/]{6,22}[0-9]";
    IPV4 = r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b";
    IPV6 = r"(?i)(?:[0-9a-f]{1,4}:){1,7}(?:(?::[0-9a-f]{1,4}){1,7}|[0-9a-f]{1,4}|:)|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}";
    UUID = r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b";
    DATE = r"\b(?:[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]+)?)?(?:Z|[+\-][0-9]{2}:?[0-9]{2})?)?|[0-9]{1,2}\.[0-9]{1,2}\.(?:19|20)[0-9]{2}|[0-9]{1,2}[/\-][0-9]{1,2}[/\-](?:19|20)?[0-9]{2})\b";
    TIME = r"\b[0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?\b";
    KV = r#"([A-Za-z0-9_.\-\[\]]{1,64})=([^&\s"'<>;,]+)"#;
    JSON_KV = r#""([A-Za-z0-9_\-.$@]{1,64})"\s*:\s*"((?:[^"\\]|\\.)*)""#;
    USERINFO = r"(?i)\b[a-z][a-z0-9+.\-]*://([^/\s@'<>?#]+)@";
    TAG = r#"<[A-Za-z][A-Za-z0-9:\-]*(?:\s[^<>]*)?/?>"#;
    ATTR = r#"([A-Za-z_:][A-Za-z0-9_:.\-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'<>=`]+)"#;
    KV2 = r#"(?:^|[^A-Za-z0-9_\-.$@])["']?([A-Za-z_$@][A-Za-z0-9_.\-$@]{0,63})["']?[ \t]*([:=])[ \t]*("(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)*'|[^\s=,;&<>"'{}()\[\]][^\r\n,;&<>"'{}()\[\]]*)"#;
    AUTH_TEXT = r"(?i)\b(Bearer|Basic|Negotiate|NTLM|Digest)[ \t]+([A-Za-z0-9._~+/=\-]{8,})";
    COOKIE_LINE = r"(?im)^[ \t]*(set-cookie|cookie)[ \t]*:[ \t]*([^\r\n]+)";
    URL_TEXT = r#"(?i)\b(?:https?|wss?|ftps?)://[^\s"'<>()\[\]{}\\^`|]+"#;
    CSS_URL = r#"(?i)\burl\(\s*["']?([^"')\s]+)"#;
}

/// A match of a group (see [`caps`]).
#[derive(Clone, Copy)]
struct Mt<'h> {
    s: &'h str,
    a: usize,
    b: usize,
}

impl<'h> Mt<'h> {
    fn start(&self) -> usize {
        self.a
    }
    fn end(&self) -> usize {
        self.b
    }
    fn as_str(&self) -> &'h str {
        &self.s[self.a..self.b]
    }
}

/// The groups of one match (see [`caps`]).
struct Caps<'h> {
    s: &'h str,
    g: Vec<Option<(usize, usize)>>,
}

impl<'h> Caps<'h> {
    fn get(&self, i: usize) -> Option<Mt<'h>> {
        self.g.get(i).copied().flatten().map(|(a, b)| Mt { s: self.s, a, b })
    }
}

/// Every match of `r` in `s` with its groups: the matches are found with the fast
/// (DFA) engines, the groups resolved on the match alone, so large texts stay fast (group
/// searches over a whole large text use the slow NFA engine).
fn caps<'h>(r: &Regex, s: &'h str) -> Vec<Caps<'h>> {
    let mut out = Vec::new();
    for m in r.find_iter(s) {
        let sub = &s[m.start()..m.end()];
        if let Some(c) = r.captures(sub) {
            let g = (0..c.len()).map(|i| c.get(i).map(|x| (m.start() + x.start(), m.start() + x.end()))).collect();
            out.push(Caps { s, g });
        }
    }
    out
}

fn re(r: &'static (OnceLock<Regex>, &'static str)) -> &'static Regex {
    r.0.get_or_init(|| Regex::new(r.1).expect("sanitize regex"))
}

/// File extensions that look like top-level domains (`logo@2x.png`).
const NOT_TLDS: &[&str] = &["png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "js", "mjs", "css", "map", "json", "html", "htm", "woff", "woff2", "ttf", "otf", "eot", "pdf", "txt", "xml", "mp4", "webm", "mp3", "wasm"];

/// The e-mail address in the candidate `s[a..b]`, if it is one: an escape (`%3D`) before it
/// is no part of it, an apostrophe only between letters (`o'brien`), a file extension after
/// it (`max@firma.de.pdf`) is cut off, `_` counts as a boundary (`invoice_max@firma.de_1.pdf`).
fn email_at(s: &str, a: usize, b: usize) -> Option<(usize, usize)> {
    let mut a = a;
    let bytes = s.as_bytes();
    // `%3Dname%40host`, `mailto%3Aname%40host` (an escape before): no part of it.
    if a > 0 && bytes[a - 1] == b'%' && b - a > 2 && bytes[a].is_ascii_hexdigit() && bytes[a + 1].is_ascii_hexdigit() {
        a += 2;
    }
    let at = ["@", "%40", "&#64;", "&#x40;", "&commat;"].iter().filter_map(|sep| s[a..b].find(sep)).min()? + a;
    // An apostrophe not between two letters starts the address after it.
    let local = &s[a..at];
    let mut start = a;
    for (i, c) in local.char_indices() {
        if c == '\'' {
            let prev = local[..i].chars().next_back();
            let next = local[i + 1..].chars().next();
            if !(prev.is_some_and(char::is_alphabetic) && next.is_some_and(char::is_alphabetic)) {
                start = a + i + 1;
            }
        }
    }
    let a = start;
    if a >= at || !s[a..].chars().next().is_some_and(char::is_alphanumeric) {
        return None;
    }
    let prev = s[..a].chars().next_back();
    let after_escape = a >= 3 && bytes[a - 3] == b'%' && bytes[a - 2].is_ascii_hexdigit() && bytes[a - 1].is_ascii_hexdigit();
    if prev.is_some_and(|c| c.is_alphanumeric()) && !after_escape {
        return None;
    }
    let mut b = b;
    loop {
        let e = &s[a..b];
        let domain = &s[at..b];
        let tld = e.rsplit('.').next().unwrap_or("").to_lowercase();
        if NOT_TLDS.contains(&tld.as_str()) {
            // `john.doe@example.com.txt`: try without the extension.
            let cut = b - tld.len() - 1;
            if s[at..cut].contains('.') {
                b = cut;
                continue;
            }
            return None;
        }
        if !domain.contains('.') {
            return None;
        }
        let next = s[b..].chars().next();
        let after = s[b..].chars().nth(1);
        if next.is_some_and(|c| c.is_alphanumeric() || c == '-') || (next == Some('.') && after.is_some_and(|c| c.is_alphanumeric()) && !NOT_TLDS.iter().any(|t| s[b + 1..].to_lowercase().starts_with(t))) {
            return None;
        }
        return Some((a, b));
    }
}

/// A credential after an authorization scheme in text (`Bearer abc.def`), not a word
/// (`Basic information`): it has a digit or a base64 / token character, or mixed case.
fn credential_like(v: &str) -> bool {
    let digit = v.bytes().any(|b| b.is_ascii_digit());
    let special = v.bytes().any(|b| b"+/=._~-".contains(&b));
    let mixed = v.bytes().any(|b| b.is_ascii_uppercase()) && v.bytes().any(|b| b.is_ascii_lowercase());
    digit || (special && v.len() >= 12) || (mixed && v.len() >= 16)
}

/// Field names that name another value (`{"name": "password", "value": "…"}`).
fn is_name_key(n: &str) -> bool {
    matches!(
        n.to_ascii_lowercase().as_str(),
        "name" | "key" | "field" | "fieldname" | "field_name" | "id" | "attribute" | "attributename" | "attr" | "param" | "parameter" | "paramname" | "property" | "claim" | "claimtype" | "friendlyname" | "label" | "itemprop"
    )
}

/// Personal field names that also name things other than persons (`name` of a product).
fn ambiguous_personal(n: &str) -> bool {
    matches!(name_words(n).concat().as_str(), "name" | "displayname" | "title")
}

/// A field that only a person has (`email`, `firstName`, `phone`, `birthDate` …).
fn person_field(n: &str) -> bool {
    let j = name_words(n).concat();
    ["email", "mail", "firstname", "lastname", "surname", "givenname", "familyname", "fullname", "username", "phone", "mobile", "telefon", "birth", "geburt", "vorname", "nachname", "middlename", "nickname", "gender"]
        .iter()
        .any(|p| j.contains(p))
        || matches!(j.as_str(), "dob" | "ssn" | "upn")
}

/// A key or element name that holds a person (`user`, `customer`, `author` …).
fn person_word(n: &str) -> bool {
    const P: &[&str] = &[
        "user", "users", "customer", "customers", "contact", "contacts", "person", "persons", "people", "author", "authors", "owner", "owners", "member", "members",
        "employee", "employees", "patient", "patients", "profile", "recipient", "recipients", "sender", "buyer", "seller", "guest", "guests", "passenger", "passengers",
        "driver", "student", "teacher", "applicant", "holder", "payer", "payee", "beneficiary", "subscriber", "attendee", "attendees", "participant", "participants",
        "candidate", "account", "me", "reporter", "assignee", "creator", "manager", "friend", "friends", "partner", "kunde", "kunden", "nutzer", "benutzer",
        "mitarbeiter", "ansprechpartner", "absender", "empfaenger", "inhaber", "principal", "subject", "signer", "approver", "reviewer", "requester", "cardholder",
        "accountholder", "billing", "shipping", "identity",
    ];
    name_words(n).iter().any(|w| P.contains(&w.as_str()))
}

/// XML elements (lower case local names) that wrap credentials: their direct text is judged
/// by their name, their children by their own names.
const XML_WRAPPERS: &[&str] = &[
    "usernametoken", "security", "assertion", "encryptedassertion", "signature", "signedinfo", "keyinfo", "securitytokenreference", "requestsecuritytoken",
    "requestsecuritytokenresponse", "requestedsecuritytoken", "attributestatement", "authnstatement", "subject",
];

/// Field names that hold the value named by a sibling [`is_name_key`] field.
fn is_value_key(n: &str) -> bool {
    matches!(n.to_ascii_lowercase().as_str(), "value" | "values" | "val" | "content" | "attributevalue" | "text" | "data" | "default" | "defaultvalue" | "current" | "currentvalue")
}

/// Digits not continued by other digits (also across `.`/`,`, i.e. no decimals).
fn number_boundary(s: &str, a: usize, b: usize) -> bool {
    let bytes = s.as_bytes();
    let prev = a.checked_sub(1).map(|i| bytes[i]);
    let next = bytes.get(b).copied();
    let after = bytes.get(b + 1).copied();
    let before = a.checked_sub(2).map(|i| bytes[i]);
    !(prev.is_some_and(|c| c.is_ascii_digit() || c == b'-' || c == b'_')
        || ((prev == Some(b'.') || prev == Some(b',')) && before.is_some_and(|c| c.is_ascii_digit()))
        || next.is_some_and(|c| c.is_ascii_digit() || c == b'_')
        || ((next == Some(b'.') || next == Some(b',') || next == Some(b'-')) && after.is_some_and(|c| c.is_ascii_digit())))
}

/// A card number as written: no separators, the same separator throughout, or groups of
/// four (`4111 1111-1111 1111`) or the Amex layout 4-6-5.
fn card_layout(m: &str) -> bool {
    let seps: Vec<char> = m.chars().filter(|c| !c.is_ascii_digit()).collect();
    if seps.windows(2).all(|w| w[0] == w[1]) {
        return true;
    }
    let groups: Vec<usize> = m.split([' ', '-']).map(str::len).collect();
    let fours = groups.len() >= 3 && groups[..groups.len() - 1].iter().all(|&g| g == 4) && (1..=4).contains(groups.last().unwrap());
    fours || groups == [4, 6, 5] || groups == [4, 6, 4]
}

/// Luhn checksum.
pub fn luhn(digits: &str) -> bool {
    let mut sum = 0;
    for (i, c) in digits.bytes().rev().enumerate() {
        let mut d = (c - b'0') as u32;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

/// A plausible payment card number: 13–19 digits, a known issuer prefix and the Luhn check.
pub fn card_number(d: &str) -> bool {
    let n = d.len();
    if !(13..=19).contains(&n) || !d.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let p = |k: usize| d[..k].parse::<u32>().unwrap_or(0);
    let issuer = match d.as_bytes()[0] {
        b'4' => matches!(n, 13 | 16 | 19),                                                       // Visa
        b'5' => ((51..=55).contains(&p(2)) && n == 16) || ((p(2) == 50 || (56..=59).contains(&p(2))) && n >= 12), // Mastercard, Maestro
        b'2' => (2221..=2720).contains(&p(4)) && n == 16,                                       // Mastercard
        b'3' => (matches!(p(2), 34 | 37) && n == 15) || (((300..=305).contains(&p(3)) || matches!(p(2), 36 | 38 | 39)) && n == 14) || ((3528..=3589).contains(&p(4)) && n >= 16), // Amex, Diners, JCB
        b'6' => n >= 16,                                                                         // Discover, UnionPay, Maestro
        _ => false,
    };
    issuer && luhn(d) && !d.bytes().all(|b| b == d.as_bytes()[0])
}

/// IBAN check (mod 97) of `s` (spaces allowed).
pub fn iban(s: &str) -> bool {
    let c: String = s.chars().filter(|c| *c != ' ').collect();
    if !(15..=34).contains(&c.len()) || !c.is_ascii() {
        return false;
    }
    let b = c.as_bytes();
    if !b[0].is_ascii_uppercase() || !b[1].is_ascii_uppercase() || !b[2].is_ascii_digit() || !b[3].is_ascii_digit() {
        return false;
    }
    let mut rem: u32 = 0;
    for ch in c[4..].chars().chain(c[..4].chars()) {
        let v = match ch {
            '0'..='9' => ch as u32 - '0' as u32,
            'A'..='Z' => ch as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    rem == 1
}

/// IBAN lengths by country (the common ones; others are accepted in upper case at any length).
const IBAN_LEN: &[(&str, usize)] = &[
    ("AD", 24), ("AE", 23), ("AL", 28), ("AT", 20), ("AZ", 28), ("BA", 20), ("BE", 16), ("BG", 22), ("BH", 22), ("BR", 29), ("CH", 21), ("CR", 22), ("CY", 28),
    ("CZ", 24), ("DE", 22), ("DK", 18), ("DO", 28), ("EE", 20), ("ES", 24), ("FI", 18), ("FO", 18), ("FR", 27), ("GB", 22), ("GE", 22), ("GI", 23), ("GL", 18),
    ("GR", 27), ("GT", 28), ("HR", 21), ("HU", 28), ("IE", 22), ("IL", 23), ("IS", 26), ("IT", 27), ("JO", 30), ("KW", 30), ("KZ", 20), ("LB", 28), ("LI", 21),
    ("LT", 20), ("LU", 20), ("LV", 21), ("MC", 27), ("MD", 24), ("ME", 22), ("MK", 19), ("MR", 27), ("MT", 31), ("MU", 30), ("NL", 18), ("NO", 15), ("PK", 24),
    ("PL", 28), ("PS", 29), ("PT", 25), ("QA", 29), ("RO", 24), ("RS", 22), ("SA", 24), ("SE", 24), ("SI", 19), ("SK", 24), ("SM", 27), ("TN", 24), ("TR", 26),
    ("UA", 29), ("VG", 24), ("XK", 20),
];

/// The end of a valid IBAN starting at `a` (the candidate `s[a..b]` may have run into the
/// next word). Not inside a longer token (`_` counts as a boundary); lower case only for
/// known countries at their length.
fn iban_at(s: &str, a: usize, b: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if a > 0 && bytes[a - 1].is_ascii_alphanumeric() {
        return None;
    }
    let m = &s[a..b];
    let upper = m.to_ascii_uppercase();
    let known = IBAN_LEN.iter().find(|(c, _)| upper.starts_with(c)).map(|(_, n)| *n);
    let boundary = |e: usize| bytes.get(e).is_none_or(|c| !c.is_ascii_alphanumeric());
    // Ends after each character: (end, compact length).
    let mut ends: Vec<(usize, usize)> = Vec::new();
    let mut n = 0;
    for (i, c) in m.char_indices() {
        if c != ' ' {
            n += 1;
            ends.push((a + i + 1, n));
        }
    }
    let cands: Vec<usize> = match known {
        Some(len) => ends.iter().filter(|(_, k)| *k == len).map(|(e, _)| *e).collect(),
        None if m.bytes().all(|c| !c.is_ascii_lowercase()) => ends.iter().rev().filter(|(e, k)| *k >= 15 && (*e == b || bytes[*e] == b' ')).map(|(e, _)| *e).collect(),
        None => Vec::new(),
    };
    // `De89…` or `dE89…` is no IBAN; `DE89 abcd …` (lower case account letters) may be.
    let case_ok = |e: usize| {
        let c = &s[a..e];
        let lower = c.bytes().any(|x| x.is_ascii_lowercase());
        !lower || c[..2].bytes().all(|x| x.is_ascii_lowercase()) || c[..2].bytes().all(|x| x.is_ascii_uppercase())
    };
    cands.into_iter().find(|&e| boundary(e) && case_ok(e) && iban(&s[a..e].to_ascii_uppercase()))
}

/// German tax identification number (11 digits, digit distribution and ISO 7064 check).
pub fn tax_id(d: &str) -> bool {
    if d.len() != 11 || !d.bytes().all(|b| b.is_ascii_digit()) || d.starts_with('0') {
        return false;
    }
    let digits: Vec<u32> = d.bytes().map(|b| (b - b'0') as u32).collect();
    let mut counts = [0u8; 10];
    for &x in &digits[..10] {
        counts[x as usize] += 1;
    }
    let multi: Vec<u8> = counts.iter().copied().filter(|&c| c > 1).collect();
    if multi.len() != 1 || multi[0] > 3 {
        return false;
    }
    let mut product = 10;
    for &x in &digits[..10] {
        let mut sum = (x + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = (11 - product) % 10;
    check == digits[10]
}

/// German social security (pension insurance) number: area, birth date, initial, serial,
/// check digit.
pub fn social_security(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 12 || !b[..8].iter().all(u8::is_ascii_digit) || !b[8].is_ascii_uppercase() || !b[9..].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let num = |i: usize| ((b[i] - b'0') * 10 + (b[i + 1] - b'0')) as u32;
    let (day, month) = (num(2), num(4));
    if !((1..=31).contains(&day) || (51..=81).contains(&day)) || !(1..=12).contains(&month) {
        return false;
    }
    let letter = (b[8] - b'A' + 1) as u32;
    let mut digits: Vec<u32> = b[..8].iter().map(|c| (c - b'0') as u32).collect();
    digits.push(letter / 10);
    digits.push(letter % 10);
    digits.push((b[9] - b'0') as u32);
    digits.push((b[10] - b'0') as u32);
    const W: [u32; 12] = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1];
    let sum: u32 = digits.iter().zip(W).map(|(d, w)| (d * w) / 10 + (d * w) % 10).sum();
    sum % 10 == (b[11] - b'0') as u32
}

/// Phone numbers in `s`. A candidate that is no phone number as a whole (it ran into the
/// next number: `030 1234567 / 0170 1234567`) is tried shorter, at its group boundaries, and
/// the search goes on right after its start.
fn phones(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < s.len() {
        let Some(m) = re(&PHONE).find_at(s, pos) else { break };
        let (a, b) = (m.start(), m.end());
        let mut end = phone_at(s, a, b).then_some(b);
        if end.is_none() {
            let cand = &s[a..b];
            let cuts: Vec<usize> = cand.char_indices().filter(|(i, c)| *i > 0 && matches!(c, ' ' | '/' | '-' | '(') && cand[..*i].ends_with(|x: char| x.is_ascii_digit() || x == ')')).map(|(i, _)| i).collect();
            // Prefer a cut where the rest starts like the next number (`0…`, `+…`, `(…`).
            let next_number = |e: usize| s[e..b].trim_start_matches([' ', '/', '-', ',', ';']).starts_with(['+', '0', '(']);
            end = cuts.iter().rev().map(|i| a + i).find(|&e| next_number(e) && phone_at(s, a, e)).or_else(|| cuts.iter().rev().map(|i| a + i).find(|&e| phone_at(s, a, e)));
        }
        match end {
            Some(e) => {
                out.push((a, e));
                pos = e;
            }
            None => {
                pos = a + s[a..].chars().next().map_or(1, char::len_utf8);
            }
        }
    }
    out
}

/// Whether the phone candidate `s[a..b]` is a phone number: `+` or `00`/`0` prefix with an
/// area code (`(030)` too), 8–15 digits, consistent separators, no date, not inside a longer
/// token.
fn phone_at(s: &str, a: usize, b: usize) -> bool {
    let m = &s[a..b];
    let bytes = s.as_bytes();
    let prev = a.checked_sub(1).map(|i| bytes[i]);
    if prev.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'/' | b'_' | b'+' | b'=' | b':' | b'#')) {
        return false;
    }
    let next = bytes.get(b).copied();
    if next.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'/' | b'(')) || (next == Some(b'.') && bytes.get(b + 1).is_some_and(u8::is_ascii_digit)) {
        return false;
    }
    let digits = m.bytes().filter(u8::is_ascii_digit).count();
    if !(8..=15).contains(&digits) {
        return false;
    }
    if m.contains("  ") || m.contains("--") || m.contains("//") || m.matches('(').count() != m.matches(')').count() || m.matches('(').count() > 1 {
        return false;
    }
    let groups: Vec<&str> = m.split([' ', '-', '/']).filter(|g| !g.is_empty()).collect();
    if groups.len() > 6 {
        return false;
    }
    let separated = groups.len() > 1;
    if let Some(rest) = m.strip_prefix('+') {
        // Country code 1–3 digits, no leading zero.
        return !rest.starts_with('0');
    }
    if m.starts_with("(0)") {
        return true;
    }
    // `(030) 1234567`: the area code in parentheses.
    let core = if m.starts_with("(0") { &m[1..] } else { m };
    if core.starts_with("00") {
        return separated && !core.starts_with("000");
    }
    // National: `0` and an area code (second digit 1-9).
    if core.as_bytes().get(1).is_none_or(|&c| c == b'0' || !c.is_ascii_digit() && c != b'(') && !core.starts_with("0(") {
        return false;
    }
    if !separated {
        return (10..=12).contains(&digits);
    }
    let area = groups[0].trim_matches(['(', ')']);
    if !(2..=6).contains(&area.len()) || !area.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Three short groups (`01 02 2024`) are no phone number.
    !(groups.len() == 3 && groups.iter().all(|g| g.len() <= 4) && digits <= 8)
}

fn ipv4_at(s: &str, a: usize, b: usize) -> bool {
    let bytes = s.as_bytes();
    let prev = a.checked_sub(1).map(|i| bytes[i]);
    let next = bytes.get(b).copied();
    if prev == Some(b'.') || (next == Some(b'.') && bytes.get(b + 1).is_some_and(u8::is_ascii_digit)) {
        return false;
    }
    // A version (`version 1.2.3.4`, `ver. 10.0.0.1`, `v1.2.3.4`), not an address.
    let before = s[..a].trim_end_matches([' ', ':', '=', '.', '/']).to_ascii_lowercase();
    if before.ends_with("version") || before.ends_with("ver") || before.ends_with('v') && !before.ends_with("dev") || before.ends_with("build") || before.ends_with("release") {
        return false;
    }
    !matches!(&s[a..b], "127.0.0.1" | "0.0.0.0" | "255.255.255.255")
}

fn ipv6_at(s: &str, a: usize, b: usize) -> bool {
    let bytes = s.as_bytes();
    let prev = a.checked_sub(1).map(|i| bytes[i]);
    let next = bytes.get(b).copied();
    if prev.is_some_and(|c| c.is_ascii_alphanumeric() || c == b':' || c == b'_') || next.is_some_and(|c| c.is_ascii_alphanumeric() || c == b':' || c == b'_') {
        return false;
    }
    let m = &s[a..b];
    m.matches(':').count() >= 2 && m.parse::<std::net::Ipv6Addr>().is_ok_and(|ip| !ip.is_loopback() && !ip.is_unspecified())
}

// ------------------------------------------------------------------ bodies

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Text by type, or (without a known type) by its bytes.
fn is_text(mime: &str, b: &[u8]) -> bool {
    if mime.is_empty() || mime == "application/octet-stream" || mime == "binary/octet-stream" {
        let p = &b[..b.len().min(8 << 10)];
        return quena_body::charset::utf8_valid_prefix(p) && !p.contains(&0);
    }
    if quena_body::charset::is_textual(Some(mime)) || mime.contains("yaml") || mime.contains("graphql") || mime.contains("toml") {
        return true;
    }
    let binary = mime.starts_with("image/") || mime.starts_with("audio/") || mime.starts_with("video/") || mime.starts_with("font/") || mime.contains("octet-stream") || mime.contains("zip") || mime.contains("pdf") || mime.contains("protobuf") || mime.contains("grpc") || mime.contains("wasm") || mime.contains("msgpack") || mime.contains("compressed") || mime.contains("tar");
    if binary {
        return false;
    }
    // `application/x-…`: by content.
    let p = &b[..b.len().min(8 << 10)];
    quena_body::charset::utf8_valid_prefix(p) && !p.contains(&0)
}

fn size_label(n: u64) -> String {
    if n < 1024 {
        format!("{n} bytes")
    } else if n < 1 << 20 {
        format!("{} KB", n.div_ceil(1024))
    } else {
        format!("{:.1} MB", n as f64 / (1 << 20) as f64)
    }
}

fn label_mime(m: &str) -> &str {
    if m.is_empty() { "without content type" } else { m }
}

/// Content-Type with `charset=utf-8` (the body was converted).
fn set_charset_utf8(h: &mut Headers) {
    let Some(ct) = h.get("content-type").map(str::to_string) else { return };
    let mut parts: Vec<String> = ct.split(';').map(|p| p.trim().to_string()).collect();
    parts.retain(|p| !p.to_ascii_lowercase().starts_with("charset="));
    parts.insert(1.min(parts.len()), "charset=utf-8".into());
    h.set("content-type", parts.join("; "));
}

/// Headers describing the exact bytes of a body (dropped when the body changes).
const INTEGRITY_HEADERS: &[&str] = &["digest", "content-md5", "repr-digest", "content-digest", "etag"];

/// Large text is scanned in pieces of about this size (ending at line breaks).
const TEXT_CHUNK: usize = 256 << 10;

/// Bodies up to this size are scrubbed whole before truncating (their structure is kept).
const TRUNCATE_WHOLE: usize = 1 << 20;
/// When only a prefix is scrubbed, this much more than the kept part.
const TRUNCATE_MARGIN: usize = 64 << 10;

fn short_error(e: &str) -> String {
    if e.len() > 80 { format!("{}…", &e[..e.char_indices().take_while(|(i, _)| *i < 80).last().map_or(0, |(i, c)| i + c.len_utf8())]) } else { e.to_string() }
}

/// The body without its Content-Encoding (at most `limit` bytes) and whether decoding
/// stopped at damaged or cut data (the part decoded so far is returned); an error when the
/// encoding is unknown or nothing could be decoded.
fn decode_cut(headers: &Headers, body: &Body, limit: usize) -> Result<(Vec<u8>, bool), String> {
    match headers.get("content-encoding").map(str::trim).filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity")) {
        Some(ce) => {
            let encs = quena_body::decode::parse_encodings(ce).map_err(|e| short_error(&format!("unknown content encoding {e}")))?;
            let mut reader = quena_body::decode::decoding_reader(Box::new(body.stream(0, false)), &encs);
            let mut out = Vec::new();
            let mut buf = vec![0u8; 64 << 10];
            while out.len() < limit {
                let want = buf.len().min(limit - out.len());
                match reader.read(&mut buf[..want]) {
                    Ok(0) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) if out.is_empty() => return Err(short_error(&e.to_string())),
                    Err(_) => return Ok((out, true)),
                }
            }
            Ok((out, false))
        }
        None => {
            let mut v = Vec::new();
            body.stream(0, false).take(limit as u64).read_to_end(&mut v).map_err(|e| e.to_string())?;
            Ok((v, false))
        }
    }
}

/// The body without its Content-Encoding (at most `limit` bytes); the stored bytes when the
/// encoding is unknown or broken.
pub fn decoded_body(headers: &Headers, body: &Body, limit: usize) -> Vec<u8> {
    decode_cut(headers, body, limit).map(|(b, _)| b).unwrap_or_else(|_| {
        let mut v = Vec::new();
        let _ = body.stream(0, false).take(limit as u64).read_to_end(&mut v);
        v
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_about_secrets_is_not_a_secret() {
        for n in ["token_endpoint", "revocation_endpoint_auth_methods_supported", "token_type", "jwks_uri", "session_url", "id_token_signing_alg_values_supported"] {
            assert!(!secret_field(n), "{n}");
        }
        for n in ["access_token", "client_secret", "password", "refresh_token", "sessionid"] {
            assert!(secret_field(n), "{n}");
        }
    }
    use quena_model::{RequestHead, ResponseHead};

    fn z(preset: &str) -> Sanitizer {
        Sanitizer::new(SanitizeOptions::preset(preset).unwrap())
    }

    fn text(z: &mut Sanitizer, s: &str) -> String {
        z.scrub(s, Loc::Body, Enc::Raw).into_owned()
    }

    fn headers(h: &[(&str, &str)]) -> Headers {
        let mut out = Headers::new();
        for (k, v) in h {
            out.push(*k, *v);
        }
        out
    }

    fn store() -> (tempfile::TempDir, std::sync::Arc<quena_body::BodyStore>) {
        let dir = tempfile::tempdir().unwrap();
        let s = quena_body::BodyStore::open(dir.path(), quena_body::BodyConfig::default()).unwrap();
        (dir, s)
    }

    fn session(url: &str, req_h: &[(&str, &str)], resp_h: &[(&str, &str)]) -> SessionDetail {
        let mut d = SessionDetail::default();
        d.summary.id = 7;
        d.request = RequestHead { method: "POST".into(), url: url.into(), headers: headers(req_h), ..Default::default() };
        d.response = Some(ResponseHead { status: 200, reason: "OK".into(), headers: headers(resp_h), ..Default::default() });
        d
    }

    #[test]
    fn presets() {
        assert_eq!(SanitizeOptions::default(), SanitizeOptions::preset("support").unwrap());
        let g = SanitizeOptions::preset("gdpr").unwrap();
        assert!(g.phones && g.ips && g.personal_fields && g.national_ids && g.process && g.bodies == BodyMode::Truncate);
        let c = SanitizeOptions::preset("credentials").unwrap();
        assert!(c.cookies && c.body_secrets && !c.emails && !c.payment && c.binary == BinaryMode::Keep);
        assert!(SanitizeOptions::preset("x").is_none());
        // Missing fields take the support defaults; camelCase names.
        let o: SanitizeOptions = serde_json::from_str(r#"{"preset":"custom","phones":true,"truncateKib":8}"#).unwrap();
        assert!(o.phones && o.emails && o.truncate_kib == 8);
        assert!(SanitizeOptions { patterns: vec!["(".into()], ..Default::default() }.validate().is_err());
    }

    #[test]
    fn emails() {
        let mut s = z("support");
        assert_eq!(text(&mut s, "mail Max.Muster@example.com, again max.muster@EXAMPLE.com."), "mail <email-1>, again <email-1>.");
        assert_eq!(text(&mut s, "other a_b+c@sub.example.de"), "other <email-2>");
        assert_eq!(text(&mut s, "q=user%40example.org&x=1"), "q=<email-3>&x=1");
        for neg in ["logo@2x.png", "react-dom@18.2.0", "@media screen", "user@localhost", "npm i @scope/pkg@1.0.0", "a@b"] {
            assert_eq!(text(&mut s, neg), neg, "{neg}");
        }
        assert_eq!(s.log().count("email"), 4);
    }

    #[test]
    fn iban_and_cards() {
        let mut s = z("support");
        assert!(iban("DE89370400440532013000") && iban("DE89 3704 0044 0532 0130 00") && iban("GB82WEST12345698765432"));
        assert!(!iban("DE89370400440532013001") && !iban("DE0012"));
        assert_eq!(text(&mut s, "IBAN: DE89 3704 0044 0532 0130 00 EUR"), "IBAN: <iban-1> EUR");
        assert_eq!(text(&mut s, "iban=DE89370400440532013000"), "iban=<iban-1>");
        assert_eq!(text(&mut s, "DE89370400440532013001 stays"), "DE89370400440532013001 stays");
        assert!(card_number("4111111111111111") && card_number("5500005555555559") && card_number("378282246310005"));
        assert!(!card_number("4111111111111112") && !card_number("1234567812345670") && !card_number("4444444444444444"));
        assert_eq!(text(&mut s, "card 4111 1111 1111 1111 exp"), "card <card-1> exp");
        assert_eq!(text(&mut s, "card 4111-1111-1111-1111"), "card <card-1>");
        // Inside longer digit runs, decimals, mixed separators, millisecond timestamps.
        // Groups of four with mixed separators are still a card.
        assert_eq!(text(&mut s, "card 4111 1111-1111 1111"), "card <card-1>");
        for neg in ["41111111111111110", "x14111111111111111", "4111111111111111.5", "4111 11-111111 1111", "ts 1700000000000 and 1712345678901", "id 4111111111111111_2"] {
            assert_eq!(text(&mut s, neg), neg, "{neg}");
        }
    }

    #[test]
    fn phones_ips_and_ids() {
        let mut s = z("gdpr");
        assert_eq!(text(&mut s, "Tel. +49 30 1234567 or 030/1234567 or (0)30 1234568 or 030 1234567"), "Tel. <phone-1> or <phone-2> or <phone-3> or <phone-2>");
        assert_eq!(text(&mut s, "mobile 0171-1234567, intl 0049 171 1234567"), "mobile <phone-4>, intl <phone-5>");
        for neg in [
            "2024-01-15 10:30:00",
            "15.01.2024",
            "01-15-2024",
            "version 1.2.3",
            "id 550e8400-e29b-41d4-a716-446655440000",
            "Chrome/120.0.6099.109",
            "M0 0 1024 768",
            "order 12345678",
            "+0 1234",
            "0000123456789",
            "ts=1700000000000",
        ] {
            assert_eq!(text(&mut s, neg), neg, "{neg}");
        }
        assert_eq!(text(&mut s, "from 203.0.113.7, 2001:db8::7 and fe80::1:2"), "from <ip-1>, <ip-2> and <ip-3>");
        for neg in ["127.0.0.1", "v1.2.3.4", "1.2.3.4.5", "12:30:45", "a::before", "00:1A:2B:3C:4D:5E", "::1"] {
            assert_eq!(text(&mut s, neg), neg, "{neg}");
        }
        assert!(tax_id("65929970489") && tax_id("86095742719"));
        assert!(!tax_id("65929970488") && !tax_id("12345678901") && !tax_id("01234567890"));
        assert_eq!(text(&mut s, "Steuer-ID 65929970489"), "Steuer-ID <tax-id-1>");
        assert!(social_security("65170839J003") && !social_security("65170839J004") && !social_security("65173839J003"));
        assert_eq!(text(&mut s, "SVNR 65 170839 J 003"), "SVNR <ssn-1>");
        // Support keeps phones and IPs.
        let mut s = z("support");
        let t = "Tel. +49 30 1234567 from 203.0.113.7";
        assert_eq!(text(&mut s, t), t);
    }

    #[test]
    fn jwt_and_key_values() {
        let mut s = z("support");
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl";
        assert_eq!(text(&mut s, &format!("token {jwt} end")), "token <jwt-1> end");
        assert_eq!(text(&mut s, "see /cb?code=SECRET-CODE&state=xyz&lang=de"), "see /cb?code=%3Ctoken-1%3E&state=%3Ctoken-2%3E&lang=de");
        assert_eq!(text(&mut s, r#"var cfg = {"apiKey": "SECRET-K", "name": "x"}"#), r#"var cfg = {"apiKey": "<token-3>", "name": "x"}"#);
        let html = r#"<input type="hidden" name="csrf_token" value="SECRET-CSRF"><input type="password" name="pw" value="SECRET-PW">"#;
        let out = s.text(html, "text/html", Loc::Body);
        assert!(!out.contains("SECRET") && out.contains(r#"name="csrf_token" value="&lt;token-"#), "{out}");
        assert_eq!(text(&mut s, "proxy https://bob:SECRET-PW@proxy.test/"), "proxy https://%3Cuser-1%3E@proxy.test/");
        // No `name=value` rules in program code.
        let js = "var code=n.code;";
        assert_eq!(s.text(js, "application/javascript", Loc::Body), js);
    }

    #[test]
    fn urls() {
        let mut s = z("support");
        let u = s.url(
            "https://user:SECRET-PW@login.test/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fapp.test%2Fcb%3Fcode%3DSECRET-INNER&state=SECRET-STATE&login_hint=a%40b.de&scope=openid+email#access_token=SECRET-AT&token_type=Bearer",
            Loc::Url,
        );
        for secret in ["SECRET", "a%40b.de", "a@b.de"] {
            assert!(!u.contains(secret), "{u}");
        }
        assert!(u.starts_with("https://%3Cuser-1%3E@login.test/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fapp.test%2Fcb%3Fcode%3D%253Ctoken-"), "{u}");
        assert!(u.contains("&scope=openid+email#access_token=%3Ctoken-"), "{u}");
        let u = s.url("https://api.test/users/max%40example.com/orders?id=5", Loc::Url);
        assert_eq!(u, "https://api.test/users/%3Cemail-1%3E/orders?id=5");
        // Unchanged URLs stay byte for byte.
        let plain = "https://api.test/a/b?x=1&y=%20z#frag";
        assert_eq!(s.url(plain, Loc::Url), plain);
    }

    #[test]
    fn secret_headers_and_cookies() {
        let mut s = z("support");
        let mut h = headers(&[
            ("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"),
            ("Proxy-Authorization", "Basic dXNlcjpTRUNSRVQ="),
            ("Cookie", "sid=SECRET-SID; theme=dark; flag"),
            ("X-Api-Key", "SECRET-KEY"),
            ("X-CSRF-Token", "SECRET-CSRF"),
            ("Ocp-Apim-Subscription-Key", "SECRET-SUB"),
            ("X-Custom", "contact max@example.com"),
            ("Accept", "application/json"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Referer", "https://app.test/cb?code=SECRET-CODE"),
        ]);
        s.headers(&mut h);
        let all: String = h.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
        assert!(!all.contains("SECRET") && !all.contains("max@") && !all.contains("dXNlcjpT"), "{all}");
        assert_eq!(h.len(), 10, "all headers are kept");
        assert_eq!(h.get("authorization"), Some("Bearer <jwt-1>"));
        assert_eq!(h.get("proxy-authorization"), Some("Basic <token-1>"));
        assert_eq!(h.get("cookie"), Some("sid=<cookie-1>; theme=<cookie-2>; <cookie-3>"));
        assert_eq!(h.get("accept"), Some("application/json"));
        assert_eq!(h.get("sec-websocket-key"), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(h.get("x-api-key").unwrap().starts_with("<token-"));
        let mut r = headers(&[("Set-Cookie", "sid=SECRET-SID; Path=/; HttpOnly"), ("WWW-Authenticate", r#"Digest realm="x", nonce="SECRET-NONCE""#)]);
        s.headers(&mut r);
        // The same cookie value gets the same name in Cookie and Set-Cookie.
        assert_eq!(r.get("set-cookie"), Some("sid=<cookie-1>; Path=/; HttpOnly"));
        assert_eq!(r.get("www-authenticate"), Some(r#"Digest realm="x", nonce"#));
        assert!(s.log().count_at("cookie", "header") >= 4 && s.log().count("authorization") == 3);
        // Own header names.
        let mut s = Sanitizer::new(SanitizeOptions { extra_headers: vec!["X-Tenant".into()], ..Default::default() });
        let mut h = headers(&[("x-tenant", "acme")]);
        s.headers(&mut h);
        assert_eq!(h.get("x-tenant"), Some("<redacted-1>"));
    }

    #[test]
    fn json_keeps_structure_and_formatting() {
        let mut s = z("gdpr");
        let src = "{\n  \"user\": {\"firstName\": \"Max\", \"email\": \"max@example.com\", \"age\": 42},\n  \"password\": \"SECRET-PW\",\n  \"pin\": 123456,\n  \"token_type\": \"Bearer\",\n  \"ok\": true, \"n\": null, \"f\": 1.50e3,\n  \"note\": \"call +49 30 1234567\",\n  \"nested\": \"{\\\"client_secret\\\":\\\"SECRET-CS\\\"}\",\n  \"max@example.com\": [1, 2]\n}";
        let out = s.json(src, Loc::Body).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(!out.contains("SECRET") && !out.contains("Max\"") && !out.contains("max@"), "{out}");
        assert_eq!(v["user"]["firstName"], "<personal-1>");
        assert_eq!(v["user"]["email"], "<personal-2>");
        assert_eq!(v["user"]["age"], 42);
        assert_eq!(v["pin"], "<token-2>");
        assert_eq!(v["token_type"], "Bearer");
        assert_eq!(v["ok"], true);
        assert!(out.contains("\"f\": 1.50e3"), "numbers keep their format: {out}");
        assert_eq!(v["note"], "call <phone-1>");
        assert!(v["nested"].as_str().unwrap().contains("<token-"));
        assert!(v.get("<email-1>").is_some(), "{out}");
        assert!(out.starts_with("{\n  \"user\": {\"firstName\""), "whitespace and order kept: {out}");
        assert_eq!(s.log().numbers_as_strings, 1);
        // Not JSON → None (the caller scans it as text).
        assert!(s.json("{\"a\": 1,}", Loc::Body).is_none());
        assert!(s.json("[1, 2] x", Loc::Body).is_none());
        // Card numbers as JSON numbers become strings.
        let out = s.json(r#"{"cc": 4111111111111111}"#, Loc::Body).unwrap();
        assert_eq!(out, r#"{"cc": "<card-1>"}"#);
    }

    #[test]
    fn form_multipart_xml() {
        let mut s = z("gdpr");
        let f = s.form("grant_type=password&username=max&password=SECRET+PW&client_secret=SECRET-CS&lang=de&note=max%40example.com", Loc::Body);
        assert_eq!(f, "grant_type=password&username=%3Cpersonal-1%3E&password=%3Ctoken-1%3E&client_secret=%3Ctoken-2%3E&lang=de&note=%3Cemail-1%3E");
        let mp = b"--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nSECRET-PW\r\n--XyZ\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nmail max@example.com\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\x00\x01SECRET-BIN\r\n--XyZ--\r\n";
        let out = s.multipart(mp, "multipart/form-data; boundary=XyZ", Loc::Body).unwrap();
        let t = String::from_utf8_lossy(&out);
        assert!(!t.contains("SECRET") && !t.contains("max@"), "{t}");
        assert!(t.starts_with("--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n<token-"), "{t}");
        assert!(t.contains("filename=\"a.png\"") && t.contains("<file removed: 16 bytes image/png>") && t.ends_with("\r\n--XyZ--\r\n"), "{t}");
        assert_eq!(t.matches("--XyZ").count(), 4);
        let xml = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><wsse:Security><wsse:Password Type="x">SECRET-PW</wsse:Password></wsse:Security></soap:Header><soap:Body><Customer email="max@example.com" id="1"><Vorname>Max</Vorname><Note>a &amp; b, 203.0.113.7</Note><![CDATA[mail max@example.com]]></Customer></soap:Body></soap:Envelope>"#;
        let out = s.xml(xml, Loc::Body).unwrap();
        assert!(!out.contains("SECRET") && !out.contains("max@") && !out.contains(">Max<") && !out.contains("203.0.113.7"), "{out}");
        assert!(out.contains("<wsse:Password Type=\"x\">&lt;token-") && out.contains(r#"<Customer email="&lt;personal-"#) && out.contains("<Note>a &amp; b, &lt;ip-1&gt;</Note>"), "{out}");
        assert!(out.contains("<![CDATA[mail <email-1>]]>"), "{out}");
        assert!(quick_xml::Reader::from_str(&out).read_event().is_ok());
        assert!(s.xml("<a><b></a>", Loc::Body).is_none());
    }

    #[test]
    fn pseudonyms_stable_within_and_independent_between_exports() {
        let mut a = z("support");
        assert_eq!(text(&mut a, "x@example.com y@example.com x@example.com"), "<email-1> <email-2> <email-1>");
        let mut b = z("support");
        // The numbers follow the order in this export; nothing ties them to the value.
        assert_eq!(text(&mut b, "y@example.com x@example.com"), "<email-1> <email-2>");
        assert_eq!(a.log().distinct_values, 0, "updated per session");
        let mut c = Sanitizer::new(SanitizeOptions { pseudonyms: false, ..Default::default() });
        assert_eq!(text(&mut c, "x@example.com y@example.com"), "<email> <email>");
        assert_ne!(a.key.hash_one("x@example.com"), b.key.hash_one("x@example.com"));
    }

    #[test]
    fn bodies_are_decoded_and_content_length_fixed() {
        use std::io::Write;
        let (_d, st) = store();
        let json = br#"{"access_token":"SECRET-AT","email":"max@example.com"}"#;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(json).unwrap();
        let gz = gz.finish().unwrap();
        let mut br = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
            w.write_all(json).unwrap();
        }
        for (enc, bytes) in [("gzip", gz), ("br", br)] {
            let len = bytes.len().to_string();
            let d = session("https://api.test/x", &[], &[("Content-Type", "application/json"), ("Content-Encoding", enc), ("Content-Length", &len)]);
            let mut s = z("support");
            let out = s.session(&d, &Body::empty(), &st.store_bytes(&bytes));
            let t = String::from_utf8(out.response.clone()).unwrap();
            assert_eq!(t, r#"{"access_token":"<token-1>","email":"<email-1>"}"#, "{enc}");
            let h = &out.detail.response.as_ref().unwrap().headers;
            assert!(h.get("content-encoding").is_none());
            assert_eq!(h.get("content-length"), Some(t.len().to_string().as_str()));
            assert_eq!(s.log().touched, vec![7]);
        }
        // Undecodable → placeholder.
        let d = session("https://api.test/x", &[], &[("Content-Type", "application/json"), ("Content-Encoding", "gzip")]);
        let out = z("support").session(&d, &Body::empty(), &st.store_bytes(b"not gzip SECRET"));
        assert!(String::from_utf8_lossy(&out.response).starts_with("<body removed: could not be decoded"));
        // Binary placeholder, truncation, drop.
        let d = session("https://api.test/x", &[("Content-Type", "text/plain"), ("Content-Length", "3000")], &[("Content-Type", "image/png")]);
        let mut s = Sanitizer::new(SanitizeOptions { bodies: BodyMode::Truncate, truncate_kib: 1, ..Default::default() });
        let out = s.session(&d, &st.store_bytes(&b"a".repeat(3000)), &st.store_bytes(b"\x89PNG\x00\x00"));
        assert_eq!(out.response, b"<binary body removed: 6 bytes image/png>");
        assert!(out.request.len() < 1100 && out.request.ends_with("…<truncated, 3 KB decoded>".as_bytes()), "{}", String::from_utf8_lossy(&out.request));
        assert_eq!(out.detail.request.headers.get("content-length"), Some(out.request.len().to_string().as_str()));
        let mut s = Sanitizer::new(SanitizeOptions { bodies: BodyMode::Placeholder, ..Default::default() });
        let out = s.session(&d, &st.store_bytes(&b"a".repeat(3000)), &Body::empty());
        assert_eq!(out.request, b"<body removed: 3 KB text/plain>");
        // Latin-1 text becomes UTF-8.
        let d = session("https://api.test/x", &[], &[("Content-Type", "text/plain; charset=iso-8859-1")]);
        let out = z("support").session(&d, &Body::empty(), &st.store_bytes(b"Gr\xfc\xdfe max@example.com"));
        assert_eq!(String::from_utf8(out.response).unwrap(), "Grüße <email-1>");
        assert_eq!(out.detail.response.unwrap().headers.get("content-type"), Some("text/plain; charset=utf-8"));
    }

    #[test]
    fn websocket_messages_and_metadata() {
        let (_d, st) = store();
        let rec = |dir: u8, op: u8, p: &[u8]| {
            let mut r = vec![dir, op, 1, 0];
            r.extend_from_slice(&5i64.to_le_bytes());
            r.extend_from_slice(&(p.len() as u32).to_le_bytes());
            r.extend_from_slice(p);
            r
        };
        let mut log = rec(0, 1, br#"{"type":"auth","token":"SECRET-WS"}"#);
        log.extend(rec(1, 1, b"hello max@example.com"));
        log.extend(rec(1, 2, b"\x00\x01SECRET-BIN"));
        log.extend(rec(1, 9, b""));
        let mut d = session("wss://ws.test/socket?access_token=SECRET-Q", &[], &[]);
        d.summary.kind = SessionKind::WebSocket;
        d.process = Some(quena_model::ProcessInfo { pid: 42, name: "Max Laptop Chrome".into() });
        d.connection.client_addr = Some("203.0.113.7:51000".into());
        d.connection.server_addr = Some("[2001:db8::7]:443".into());
        d.summary.comment = "ask max@example.com".into();
        d.extra_flags = vec![("x-clientip".into(), "203.0.113.7".into())];
        let mut s = z("gdpr");
        let out = s.session(&d, &Body::empty(), &st.store_bytes(&log));
        let t = String::from_utf8_lossy(&out.response).into_owned();
        assert!(!t.contains("SECRET") && !t.contains("max@"), "{t}");
        assert!(t.contains(r#"{"type":"auth","token":"<token-"#) && t.contains("hello <email-1>") && t.contains("<binary message removed: 12 bytes>"));
        // The frame log stays readable: four records with matching lengths.
        let mut pos = 0;
        let mut n = 0;
        while pos + 16 <= out.response.len() {
            pos += 16 + u32::from_le_bytes(out.response[pos + 12..pos + 16].try_into().unwrap()) as usize;
            n += 1;
        }
        assert_eq!((n, pos), (4, out.response.len()));
        assert!(!out.detail.request.url.contains("SECRET"));
        let p = out.detail.process.as_ref().unwrap();
        assert_eq!((p.name.as_str(), p.pid), ("<process-1>", 0));
        assert_eq!(out.detail.connection.client_addr.as_deref(), Some("<ip-1>:51000"));
        assert_eq!(out.detail.connection.server_addr.as_deref(), Some("<ip-2>:443"));
        assert_eq!(out.detail.extra_flags[0].1, "<ip-1>");
        assert_eq!(out.detail.summary.comment, "ask <email-1>");
        assert_eq!(s.log().ws_messages, 2);
        assert!(s.log().count_at("email", "ws") == 1 && s.log().count_at("ip", "meta") >= 2 && s.log().count("process") == 1);
        let text = s.log().to_text();
        assert!(text.contains("E-mail addresses: 2") && text.contains("Sessions with replacements (numbers in the original capture): 7"), "{text}");
    }

    #[test]
    fn name_classifier() {
        assert_eq!(name_words("otpCode"), ["otp", "code"]);
        assert_eq!(name_words("APIKey"), ["api", "key"]);
        assert_eq!(name_words("X-Amz-Security-Token"), ["x", "amz", "security", "token"]);
        assert_eq!(name_words("SAMLResponse"), ["saml", "response"]);
        for n in [
            "pwd", "pass", "passphrase", "pin_code", "pinCode", "otpCode", "mfaCode", "verificationCode", "recoveryCode", "securityAnswer", "bearer", "accessKey",
            "secretAccessKey", "authCode", "csrf", "_csrf", "xsrf-token", "csrfmiddlewaretoken", "SAMLResponse", "SAMLRequest", "client_secret",
            "clientsecret", "api_key", "x-api-key", "access_token", "refresh_token", "id_token", "sessionid", "JSESSIONID", "session_state", "password", "new_password",
            "Passwort", "privateKey", "authenticity_token", "__RequestVerificationToken", "SignatureValue", "Nonce", "user_code", "backup_codes", "seed_phrase",
        ] {
            assert!(secret_name(n), "{n}");
        }
        for n in [
            "passenger", "compass", "keyboard", "keyName", "author", "token_type", "tokenType", "password_length", "token_endpoint", "expires_in", "jwks_uri",
            "revocation_endpoint_auth_methods_supported", "id_token_signing_alg_values_supported", "session_url", "public_key", "monkey", "secretary", "bypass_count",
            "refreshInterval", "sec-websocket-key", "username", "email", "type", "code_challenge_method", "spinner",
        ] {
            assert!(!secret_name(n), "{n}");
        }
        // Weak names: secret only with a credential-like value.
        for n in ["key", "code", "refresh", "hash", "Key"] {
            assert!(weak_secret_name(n) && !secret_name(n), "{n}");
        }
        assert!(!weak_secret_name("keyboard") && !weak_secret_name("zip_code"));
        assert!(credential_value("sk_live_51H8xQ2eZvKYlo2C0aBcD", false) && !credential_value("title", false) && !credential_value("user-settings-panel", false));
        assert!(credential_value("AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", true) && credential_value("SECRET-CODE", true) && credential_value("REFCODE1", true));
        assert!(!credential_value("DE", true) && !credential_value("200", true) && !credential_value("de-DE", true) && !credential_value("Settings", true));
        // Parameters: also the short OAuth and signed-URL names; `token_type=bearer` is none.
        assert!(secret_param_name("state") && secret_param_name("sig") && secret_param_name("X-Amz-Signature"));
        assert!(!secret_param_name("token_type") && !secret_param_name("lang"));
        // Headers.
        for n in ["x-api-key", "x-csrf-token", "x-session", "bearer", "x-auth", "x-ms-client-principal", "x-ms-token-aad-id-token", "ocp-apim-subscription-key", "x-access"] {
            assert!(secret_header(n), "{n}");
        }
        for n in ["sec-websocket-key", "x-request-id", "accept", "x-ms-client-principal-name", "content-security-policy"] {
            assert!(!secret_header(n), "{n}");
        }
        for n in ["x-forwarded-user", "x-remote-user", "x-ms-client-principal-name", "x-auth-request-email", "x-ssl-client-dn", "x-client-cert", "x-ssl-client-cert"] {
            assert!(personal_header(n), "{n}");
        }
        assert!(!personal_header("user-agent") && !personal_header("x-request-id"));
    }

    #[test]
    fn email_detection() {
        for (src, want) in [
            ("max@firma.de.pdf", "<email-1>.pdf"),
            ("filename=\"john.doe@example.com.txt\"", "filename=\"<email-1>.txt\""),
            ("invoice_john.doe@example.com_DE89370400440532013000.pdf", "<email-1>_<iban-1>.pdf"),
            ("o'brien@firma.ie", "<email-1>"),
            ("'max@firma.de'", "'<email-1>'"),
            ("john&#64;example.com and x&#x40;y.de and a&commat;b.org", "<email-1> and <email-2> and <email-3>"),
            ("jürgen.müller@bücher.de", "<email-1>"),
            ("mailto%3Ajohn%40example.com", "mailto%3A<email-1>"),
        ] {
            assert_eq!(text(&mut z("support"), src), want, "{src}");
        }
        let mut s = z("support");
        for neg in ["logo@2x.png", "a@b", "user@localhost", "font@1.2.3"] {
            assert_eq!(text(&mut s, neg), neg);
        }
    }

    #[test]
    fn phone_detection_retries_shorter() {
        let mut s = z("gdpr");
        for (src, want) in [
            ("030 1234567 / 0170 1234567", "<phone-1> / <phone-2>"),
            ("(030) 1234567 und 0170 1234567", "<phone-1> und <phone-2>"),
            ("phone (030) 123-4567", "phone <phone-1>"),
            ("x +1 (555) 123-4567 0049 30 1234567 y", "x <phone-3> <phone-4> y"),
            ("Tel. +49 30 1234 5678 ok", "Tel. <phone-5> ok"),
        ] {
            assert_eq!(text(&mut s, src), want, "{src}");
        }
        for neg in ["version 1.2.3.4", "ver 10.0.0.1", "2024-01-15 10:30:00"] {
            assert_eq!(text(&mut s, neg), neg);
        }
        assert_eq!(text(&mut s, "iban de89 3704 0044 0532 0130 00 and GB82 WEST 1234 5698 7654 32"), "iban <iban-1> and <iban-2>");
    }

    #[test]
    fn key_values_in_text() {
        let mut s = z("support");
        for (src, want) in [
            ("url=https://h.test/?token=T1 x", "url=https://h.test/?token=%3Ctoken-1%3E x"),
            ("next=/login?password=P1", "next=/login?password=%3Ctoken-2%3E"),
            ("secret: C1\nother: ok", "secret: <token-3>\nother: ok"),
            ("password = \"quoted secret\"; 'api_key': 'K1'", "password = \"<token-4>\"; 'api_key': '<token-5>'"),
            ("login(password: \"G1\", user: \"u\")", "login(password: \"<token-6>\", user: \"u\")"),
            ("Authorization: Bearer abc.DEF-123456", "Authorization: Bearer <token-7>"),
            ("Cookie: s=CK1; t=CK2", "Cookie: s=<cookie-1>; t=<cookie-2>"),
            ("token_type=bearer&access_token=A1", "token_type=bearer&access_token=%3Ctoken-8%3E"),
            ("Basic information and Digest authentication", "Basic information and Digest authentication"),
        ] {
            assert_eq!(text(&mut s, src), want, "{src}");
        }
        // Program code: no bare `name=value`, but quoted secrets, JSON pairs and URLs.
        let js = r#"var code=n.code; let password="JSPW"; fetch("https://h.test/x?access_token=JSAT"); x.secret = 'JSS';"#;
        let out = s.text(js, "application/javascript", Loc::Body);
        assert!(out.starts_with("var code=n.code;") && !out.contains("JSPW") && !out.contains("JSAT") && !out.contains("JSS"), "{out}");
        let css = ".a{background:url(/i.png?token=CSST)}";
        assert!(!s.text(css, "text/css", Loc::Body).contains("CSST"));
        let yaml = "password: YP\napi_key: \"YK\"\nname: app\n";
        let out = s.text(yaml, "application/yaml", Loc::Body);
        assert!(out.starts_with("password: <token-") && out.contains("api_key: \"<token-") && out.ends_with("\"\nname: app\n"), "{out}");
        // HTML: unquoted attributes, no `name=value` rule inside tags (no broken markup).
        let html = r#"<form action="/login?sid=FS"><input name=password value=UQ><input type=hidden name=csrf value=CS><meta name="csrf-token" content="MT"><a href="/reset?token=HR&amp;x=1">r</a></form>"#;
        let out = s.text(html, "text/html", Loc::Body);
        for m in ["FS", "UQ", "CS\"", "=CS", "MT", "HR"] {
            assert!(!out.contains(m), "{m}: {out}");
        }
        assert!(out.contains("<input name=password value=&lt;token-") && out.contains("&amp;x=1") && out.matches('<').count() == html.matches('<').count(), "{out}");
    }

    #[test]
    fn name_value_pairs() {
        let mut s = z("gdpr");
        let src = r#"{"fields":[{"name":"password","value":"NV1"},{"key":"email","value":"nv@example.com"},{"Name":"client_secret","Value":"NV3"},{"name":"color","value":"blue"}],"product":{"name":"Widget"},"customer":{"name":"Max Muster","email":"m@x.de"},"schema":{"name":"password","type":"string"},"headers":[{"name":"Accept","value":"json"}]}"#;
        let out = s.json(src, Loc::Body).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(!out.contains("NV1") && !out.contains("nv@") && !out.contains("NV3") && !out.contains("Max Muster"), "{out}");
        assert_eq!(v["fields"][0]["name"], "password");
        assert_eq!(v["fields"][3]["value"], "blue");
        assert_eq!(v["product"]["name"], "Widget");
        assert_eq!(v["schema"]["name"], "password");
        assert_eq!(v["headers"][0]["value"], "json");
        let xml = r#"<r><Attribute Name="mail"><AttributeValue>saml@example.com</AttributeValue></Attribute><Parameter name="password">XP</Parameter><property name="client_secret" value="XC"/><Item name="Widget"/><wsse:UsernameToken xmlns:wsse="w"><wsse:Username>WU</wsse:Username><wsse:Password Type="PasswordText">WP</wsse:Password><wsu:Created xmlns:wsu="u">2024-01-01</wsu:Created></wsse:UsernameToken></r>"#;
        let out = s.xml(xml, Loc::Body).unwrap();
        for m in ["saml@", ">XP<", "\"XC\"", ">WU<", ">WP<"] {
            assert!(!out.contains(m), "{m}: {out}");
        }
        assert!(out.contains(r#"Name="mail""#) && out.contains(r#"<Item name="Widget"/>"#) && out.contains(r#"Type="PasswordText""#) && out.contains("2024-01-01") && out.contains("<wsse:Username>&lt;personal-"), "{out}");
        // Support: the user name is no token.
        let mut s = z("support");
        let out = s.xml(xml, Loc::Body).unwrap();
        assert!(out.contains(">WU<") && !out.contains(">WP<"), "{out}");
    }

    #[test]
    fn hosts_tunnels_and_patterns() {
        let mut s = Sanitizer::new(SanitizeOptions { patterns: vec![r"intranet\.corp\.example".into()], ..SanitizeOptions::preset("gdpr").unwrap() });
        assert_eq!(s.url("https://203.0.113.5:8443/a?x=1", Loc::Url), "https://%3Cip-1%3E:8443/a?x=1");
        assert_eq!(s.url("https://[2001:db8::5]/a", Loc::Url), "https://%3Cip-2%3E/a");
        assert_eq!(s.url("https://app.intranet.corp.example/x", Loc::Url), "https://app.%3Credacted-1%3E/x");
        assert_eq!(s.url("https://api.example.com/x", Loc::Url), "https://api.example.com/x");
        assert_eq!(s.authority("203.0.113.5:443", Loc::Url), "<ip-1>:443");
        let mut h = headers(&[("Host", "203.0.113.5"), (":authority", "api.example.com")]);
        s.headers(&mut h);
        assert_eq!(h.get("host"), Some("<ip-1>"));
        assert_eq!(h.get(":authority"), Some("api.example.com"));
        // Support keeps IP hosts.
        let mut s = z("support");
        assert_eq!(s.url("https://203.0.113.5/a", Loc::Url), "https://203.0.113.5/a");
        // Tokens in path segments.
        assert_eq!(s.url("https://h.test/reset/aB3dE6gH9jK2mN5pQ8rS/confirm", Loc::Url), "https://h.test/reset/%3Ctoken-1%3E/confirm");
        assert_eq!(s.url("https://h.test/token/SECRETPATH1;jsessionid=JS1", Loc::Url), "https://h.test/token/%3Ctoken-2%3E;jsessionid=%3Ctoken-3%3E");
        assert_eq!(s.url("https://h.test/verify/12345/api/token/refresh", Loc::Url), "https://h.test/verify/12345/api/token/refresh");
    }

    #[test]
    fn weak_names_judge_their_values() {
        let mut s = z("support");
        let src = r#"{"items":[{"key":"title","label":"Title"},{"key":5},{"code":"DE"},{"code":200},{"refresh":30},{"key":"sk_live_51H8xQ2eZvKYlo2C0aBcD"},{"credentials":{"key":"k1"}},{"fields":[{"name":"key","value":"x"}]}]}"#;
        let out = s.json(src, Loc::Body).unwrap();
        for keep in [r#""key":"title""#, r#""key":5"#, r#""code":"DE""#, r#""code":200"#, r#""refresh":30"#] {
            assert!(out.contains(keep), "{keep}: {out}");
        }
        assert!(!out.contains("sk_live") && !out.contains("\"k1\""), "{out}");
        assert_eq!(s.log().numbers_as_strings, 0);
        let u = s.url("https://maps.test/api?key=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY&code=DE&lang=de", Loc::Url);
        assert!(!u.contains("AIzaSy") && u.contains("&code=DE&lang=de"), "{u}");
        assert_eq!(s.form("key=title&code=DE", Loc::Body), "key=title&code=DE");
        assert!(!s.form("key=sk_live_51H8xQ2eZvKYlo2C0aBcD", Loc::Body).contains("sk_live"));
    }

    #[test]
    fn strict_options_and_mock_options() {
        let o = SanitizeOptions::from_json_strict(r#"{"preset":"custom","phones":true}"#).unwrap();
        assert!(o.phones);
        let o = SanitizeOptions::from_json_strict(r#"{"options":{"preset":"gdpr","ips":true},"format":"har"}"#).unwrap();
        assert_eq!(o.preset, "gdpr");
        let e = SanitizeOptions::from_json_strict(r#"{"phone":true,"emials":false}"#).unwrap_err();
        assert!(e.contains("emials") && e.contains("phone"), "{e}");
        assert!(SanitizeOptions::from_json_strict(r#"{"patterns":["("]}"#).is_err());
        assert!(SanitizeOptions::from_json_strict("[]").is_err());
        let m = SanitizeOptions::for_mocks(&SanitizeOptions::preset("gdpr").unwrap());
        assert!(m.bodies == BodyMode::Keep && m.binary == BinaryMode::Keep && m.phones);
    }

    #[test]
    fn sse_and_custom_rules() {
        let mut s = Sanitizer::new(SanitizeOptions { patterns: vec![r"ACME-\d+".into()], extra_fields: vec!["tenant".into()], ..Default::default() });
        let out = s.text("event: msg\ndata: {\"tenant\":\"t1\",\"ref\":\"ACME-123\"}\n\ndata: plain max@example.com\n", "text/event-stream", Loc::Body);
        assert_eq!(out, "event: msg\ndata: {\"tenant\":\"<redacted-1>\",\"ref\":\"<redacted-2>\"}\n\ndata: plain <email-1>\n");
        assert_eq!(s.log().count("custom"), 2);
    }
}
