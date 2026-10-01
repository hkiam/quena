//! Sanitized copies of sessions for sharing (support, vendors) and for mocks: credentials,
//! tokens and — depending on the options — personal data are replaced deterministically,
//! without any model or network access.
//!
//! - Headers are all kept; only the values of sensitive ones are replaced (`Authorization`
//!   keeps its scheme and the size, cookies keep their names and attributes).
//! - URLs: user info and the values of secret parameters (the diagnostics rules plus the
//!   OAuth list) are replaced; other values, path segments and fragments are scanned.
//! - Bodies are decoded (Content-Encoding, charset) and scrubbed by their structure: JSON
//!   (own tokenizer, so order, whitespace and number formats stay as written), form fields,
//!   multipart parts, XML/SOAP element and attribute values, Server-Sent Events, WebSocket
//!   messages; everything else is scanned as text. The result carries no Content-Encoding
//!   and a matching Content-Length.
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
use crate::diagnostics::{UrlRewrite, decode_param, has_scheme, redact_authenticate, redact_authorization, rewrite_set_cookie, rewrite_url, secret_param};
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
    Personal,
}

impl Ctx {
    /// The context of a child: a secret or personal parent wins.
    fn child(self, own: Ctx) -> Ctx {
        match (self, own) {
            (Ctx::Secret(c), _) => Ctx::Secret(c),
            (_, Ctx::Secret(c)) => Ctx::Secret(c),
            (Ctx::Personal, _) | (_, Ctx::Personal) => Ctx::Personal,
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
    /// Scanning program code (JavaScript, CSS): no `name=value` rules.
    code: bool,
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
        if d.summary.kind != SessionKind::Tunnel {
            detail.request.url = self.url(&d.request.url, Loc::Url);
        }
        self.headers(&mut detail.request.headers);
        if let Some(r) = detail.response.as_mut() {
            self.headers(&mut r.headers);
        }
        let request = self.body(&mut detail.request.headers, req, Loc::Body);
        let response = match detail.response.as_mut() {
            Some(r) if d.summary.kind == SessionKind::WebSocket => {
                r.headers.remove("content-encoding");
                self.ws_log(resp)
            }
            Some(r) => self.body(&mut r.headers, resp, Loc::Body),
            None if d.summary.kind == SessionKind::WebSocket => self.ws_log(resp),
            None => Vec::new(),
        };
        self.meta(&mut detail);
        if self.log.total > before {
            self.log.touched.push(d.summary.id);
        }
        self.log.distinct_values = self.pseudonyms.len();
        Sanitized { detail, request, response }
    }

    // -------------------------------------------------------------- placeholders

    /// The replacement of `value` (`<email-3>`, raw), counted in the log.
    fn ph(&mut self, cat: Cat, loc: Loc, value: &str) -> String {
        self.log.add(cat, loc);
        let label = cat.label();
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
        let n = name.trim().to_ascii_lowercase();
        if !self.extra_fields.is_empty() && self.extra_fields.contains(&n) {
            return Ctx::Secret(Cat::Custom);
        }
        if self.opts.body_secrets && secret_field(&n) {
            return Ctx::Secret(Cat::SecretField);
        }
        if self.opts.personal_fields && personal_name(&n) {
            return Ctx::Personal;
        }
        Ctx::Plain
    }

    fn param_ctx(&self, name: &str) -> Ctx {
        let n = decode_param(name).trim().to_ascii_lowercase();
        if !self.extra_params.is_empty() && self.extra_params.contains(&n) {
            return Ctx::Secret(Cat::Custom);
        }
        if self.opts.url_secrets && secret_param(&n) {
            return Ctx::Secret(Cat::UrlSecret);
        }
        if self.opts.personal_fields && personal_name(&n) {
            return Ctx::Personal;
        }
        Ctx::Plain
    }

    /// Form fields: parameter names, field names and the body secret rules.
    fn form_ctx(&self, name: &str) -> Ctx {
        let n = decode_param(name).trim().to_ascii_lowercase();
        if (!self.extra_params.is_empty() && self.extra_params.contains(&n)) || (!self.extra_fields.is_empty() && self.extra_fields.contains(&n)) {
            return Ctx::Secret(Cat::Custom);
        }
        if self.opts.body_secrets && (secret_param(&n) || secret_field(&n)) {
            return Ctx::Secret(Cat::SecretField);
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
            Ctx::Plain => None,
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
        // key=value, "key": "value", <input name=… value=…>, URL user info.
        if !self.code && (o.body_secrets || o.url_secrets || o.personal_fields || !self.extra_params.is_empty() || !self.extra_fields.is_empty()) {
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
        if o.emails && (s.contains('@') || s.contains("%40")) {
            for m in re(&EMAIL).find_iter(s) {
                let (mut a, b) = (m.start(), m.end());
                // `%3Dname%40host` (an encoded `=` before): the escape is no part of it.
                if a > 0 && s.as_bytes()[a - 1] == b'%' && s[a..].len() > 2 && s.as_bytes()[a].is_ascii_hexdigit() && s.as_bytes()[a + 1].is_ascii_hexdigit() {
                    a += 2;
                }
                let e = &s[a..b];
                if !email_ok(s, a, b, e) || !spans.free(a, b) {
                    continue;
                }
                let p = self.ph(Cat::Email, loc, &e.replace("%40", "@"));
                spans.add(a, b, encode(&p, enc));
            }
        }
        let numeric = (o.payment || o.phones || o.ips || o.national_ids) && s.bytes().any(|b| b.is_ascii_digit());
        if !numeric {
            return spans.apply(s);
        }
        // Spans that look like numbers but are none of the above.
        let mut protect = spans.clone();
        for r in [&UUID, &DATE, &TIME] {
            for m in re(r).find_iter(s) {
                protect.add(m.start(), m.end(), String::new());
            }
        }
        let mut found: Vec<(usize, usize, Cat, String)> = Vec::new();
        if o.payment {
            for m in re(&IBAN).find_iter(s) {
                if let Some(end) = iban_at(s, m.start(), m.end()) {
                    found.push((m.start(), end, Cat::Iban, s[m.start()..end].replace(' ', "")));
                }
            }
            for m in re(&CARD).find_iter(s) {
                let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
                if number_boundary(s, m.start(), m.end()) && consistent_separators(m.as_str()) && card_number(&digits) {
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
            for m in re(&PHONE).find_iter(s) {
                if phone_at(s, m.start(), m.end()) {
                    let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
                    found.push((m.start(), m.end(), Cat::Phone, digits));
                }
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

    /// Secret / personal values named in free text.
    fn key_values(&mut self, s: &str, loc: Loc, enc: Enc, spans: &mut Spans) {
        if s.contains("://") && s.contains('@') && self.opts.url_secrets {
            for c in re(&USERINFO).captures_iter(s) {
                let u = c.get(1).unwrap();
                if spans.free(u.start(), u.end()) {
                    let p = self.ph(Cat::UserInfo, loc, u.as_str());
                    spans.add(u.start(), u.end(), encode(&p, Enc::Url));
                }
            }
        }
        if s.contains('=') {
            for c in re(&KV).captures_iter(s) {
                let (name, value) = (c.get(1).unwrap(), c.get(2).unwrap());
                let ctx = self.form_ctx(name.as_str());
                if ctx != Ctx::Plain && spans.free(value.start(), value.end()) {
                    let v = decode_param(value.as_str());
                    if let Some(p) = self.value(&v, ctx, loc) {
                        // In text the pair is most likely part of a URL or form.
                        spans.add(value.start(), value.end(), if enc == Enc::Xml { encode(&p, Enc::Xml) } else { encode(&p, Enc::Url) });
                    }
                }
            }
            if s.contains("<input") || s.contains("<INPUT") {
                for tag in re(&INPUT).find_iter(s) {
                    let attrs: Vec<(String, usize, usize)> = re(&ATTR)
                        .captures_iter(tag.as_str())
                        .map(|c| {
                            let v = c.get(2).unwrap();
                            (c[1].to_ascii_lowercase(), tag.start() + v.start() + 1, tag.start() + v.end() - 1)
                        })
                        .collect();
                    let name = attrs.iter().find(|a| a.0 == "name").map(|a| s[a.1..a.2].to_string()).unwrap_or_default();
                    let password = attrs.iter().any(|a| a.0 == "type" && s[a.1..a.2].eq_ignore_ascii_case("password"));
                    let mut ctx = self.form_ctx(&name);
                    if password && self.opts.body_secrets {
                        ctx = Ctx::Secret(Cat::SecretField);
                    }
                    if let Some(v) = attrs.iter().find(|a| a.0 == "value")
                        && ctx != Ctx::Plain
                        && spans.free(v.1, v.2)
                        && let Some(p) = self.value(&s[v.1..v.2], ctx, loc)
                    {
                        spans.add(v.1, v.2, encode(&p, Enc::Xml));
                    }
                }
            }
        }
        if s.contains("\":") || s.contains("\" :") {
            for c in re(&JSON_KV).captures_iter(s) {
                let (name, value) = (c.get(1).unwrap(), c.get(2).unwrap());
                let ctx = self.field_ctx(name.as_str());
                if ctx != Ctx::Plain
                    && spans.free(value.start(), value.end())
                    && let Some(p) = self.value(value.as_str(), ctx, loc)
                {
                    spans.add(value.start(), value.end(), encode(&p, enc));
                }
            }
        }
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
            let new = match lower.as_str() {
                "authorization" | "proxy-authorization" if o.authorization => {
                    let r = redact_authorization(&value);
                    if r != value {
                        self.log.add(Cat::Authorization, Loc::Header);
                    }
                    r
                }
                "www-authenticate" | "proxy-authenticate" if o.authorization => {
                    let r = redact_authenticate(&value);
                    if r != value {
                        self.log.add(Cat::Authorization, Loc::Header);
                    }
                    r
                }
                "cookie" if o.cookies => self.cookie(&value),
                "set-cookie" if o.cookies => rewrite_set_cookie(&value, &mut |v| if v.is_empty() { String::new() } else { self.ph(Cat::Cookie, Loc::Header, v) }),
                "location" | "referer" | "content-location" | ":path" | "x-original-url" | "x-rewrite-url" => {
                    self.url(&value, Loc::Header)
                }
                "content-length" | "content-type" | "content-encoding" | "transfer-encoding" | "date" | "host" | ":authority" | ":method" | ":scheme" | ":status" => value,
                _ if !value.trim().is_empty() && self.extra_headers.contains(&lower) => self.ph(Cat::Custom, Loc::Header, value.trim()),
                _ if !value.trim().is_empty() && o.secret_headers && secret_header(&lower) => self.ph(Cat::SecretHeader, Loc::Header, value.trim()),
                _ => self.scrub(&value, Loc::Header, Enc::Raw).into_owned(),
            };
            out.push((name, new));
        }
        h.0 = out;
    }

    /// `Cookie`: names kept, values replaced.
    fn cookie(&mut self, v: &str) -> String {
        v.split(';')
            .map(|c| {
                let lead = &c[..c.len() - c.trim_start().len()];
                match c.trim().split_once('=') {
                    Some((n, val)) if !val.trim().is_empty() => format!("{lead}{}={}", n.trim(), self.ph(Cat::Cookie, Loc::Header, val.trim())),
                    Some(_) => c.to_string(),
                    None if c.trim().is_empty() => c.to_string(),
                    None => format!("{lead}{}", self.ph(Cat::Cookie, Loc::Header, c.trim())),
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
        let decoded = try_decode(headers, body, MAX_DECODED + 1);
        headers.remove("content-encoding");
        let out = match decoded {
            Err(e) => {
                self.log.add(Cat::Undecodable, loc);
                format!("<body removed: could not be decoded ({e}), {} {}>", size_label(body.len()), label_mime(&mime)).into_bytes()
            }
            Ok(b) => match self.opts.bodies {
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
                mode => {
                    let limit = (self.opts.truncate_kib.max(1) as usize) << 10;
                    let big = b.len() > MAX_DECODED;
                    let b = if big { &b[..MAX_DECODED] } else { &b[..] };
                    let mut out = if big { self.text_bytes(b, &ct, headers, loc) } else { self.content(b, &ct, headers, loc) };
                    if mode == BodyMode::Truncate && out.len() > limit {
                        let mut end = limit;
                        if std::str::from_utf8(&out).is_ok() {
                            while end > 0 && (out[end] & 0xc0) == 0x80 {
                                end -= 1;
                            }
                        }
                        let cut = out.len() - end;
                        out.truncate(end);
                        out.extend_from_slice(format!("…<truncated {cut} bytes>").as_bytes());
                        self.log.add(Cat::BodyTruncated, loc);
                    }
                    out
                }
            },
        };
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
        self.text_bytes(b, ct, headers, loc)
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

    /// Text in any charset → scrubbed UTF-8 (the Content-Type then says `charset=utf-8`).
    fn text_bytes(&mut self, b: &[u8], ct: &str, headers: &mut Headers, loc: Loc) -> Vec<u8> {
        let detected = quena_body::charset::detect(Some(ct).filter(|c| !c.is_empty()), &b[..b.len().min(64 << 10)]);
        let text: Cow<str> = if detected.name().eq_ignore_ascii_case("utf-8") {
            String::from_utf8_lossy(b)
        } else {
            let (t, _) = quena_body::charset::decode(b, detected.encoding);
            set_charset_utf8(headers);
            Cow::Owned(t.into_owned())
        };
        self.text(&text, ct, loc).into_bytes()
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
        let out = self.scrub(s, loc, if html { Enc::Xml } else { Enc::Raw }).into_owned();
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
        let mut p = JsonParser { b: s.as_bytes(), s, i: 0, out: String::with_capacity(s.len() + 16), depth: 0 };
        p.ws();
        p.value(self, Ctx::Plain, loc).ok()?;
        p.ws();
        (p.i == p.b.len()).then_some(p.out)
    }

    /// XML with element and attribute values scrubbed (everything else as written);
    /// `None` if `s` is not well-formed.
    fn xml(&mut self, s: &str, loc: Loc) -> Option<String> {
        use quick_xml::events::Event;
        let mut r = quick_xml::Reader::from_str(s);
        let mut stack: Vec<Ctx> = Vec::new();
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        let mut text: Option<(usize, usize)> = None;
        let mut seen_element = false;
        loop {
            let start = r.buffer_position() as usize;
            let ev = r.read_event().ok()?;
            let end = r.buffer_position() as usize;
            if matches!(ev, Event::Text(_) | Event::GeneralRef(_)) {
                text = Some((text.map_or(start, |t| t.0), end));
                continue;
            }
            if let Some((a, b)) = text.take() {
                let ctx = stack.last().copied().unwrap_or(Ctx::Plain);
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
                    let parent = stack.last().copied().unwrap_or(Ctx::Plain);
                    let ctx = parent.child(self.field_ctx(&name));
                    let mut changed = false;
                    let mut attrs = Vec::new();
                    for a in e.attributes().with_checks(false) {
                        let a = a.ok()?;
                        let key = String::from_utf8_lossy(a.key.as_ref()).into_owned();
                        let local = String::from_utf8_lossy(a.key.local_name().as_ref()).into_owned();
                        let raw = String::from_utf8_lossy(&a.value).into_owned();
                        let mut value = raw.clone();
                        if !key.starts_with("xmlns") {
                            // Attributes describe the element (`<Password Type="…">`): the
                            // context of the parent applies, not the element's own.
                            let actx = parent.child(self.field_ctx(&local));
                            if let Ok(v) = quick_xml::escape::unescape(&raw)
                                && let Some(new) = self.value(&v, actx, loc)
                            {
                                value = quick_xml::escape::escape(new.as_str()).into_owned();
                                changed = true;
                            }
                        }
                        attrs.push((key, value));
                    }
                    if changed {
                        let qname = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                        let mut tag = format!("<{qname}");
                        for (k, v) in attrs {
                            tag.push_str(&format!(" {k}=\"{}\"", v.replace('"', "&quot;")));
                        }
                        tag.push_str(if empty { "/>" } else { ">" });
                        edits.push((start, end, tag));
                    }
                    if !empty {
                        stack.push(ctx);
                    }
                }
                Event::End(_) => {
                    stack.pop();
                }
                Event::CData(c) => {
                    let ctx = stack.last().copied().unwrap_or(Ctx::Plain);
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
            let mut new_head = Vec::new();
            for line in head.split('\n') {
                let line = line.trim_end_matches('\r');
                let Some((k, v)) = line.split_once(':') else {
                    new_head.push(line.to_string());
                    continue;
                };
                let lk = k.trim().to_ascii_lowercase();
                if lk == "content-disposition" {
                    name = disposition_param(v, "name").unwrap_or_default();
                    file = disposition_param(v, "filename").is_some() || disposition_param(v, "filename*").is_some();
                } else if lk == "content-type" {
                    pct = v.trim().to_string();
                }
                new_head.push(format!("{k}:{}", self.scrub(v, loc, Enc::Raw)));
            }
            out.extend_from_slice(new_head.join("\r\n").as_bytes());
            out.extend_from_slice(&part[head_len..head_len + sep]);
            let pmime = pct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            let ctx = self.form_ctx(&name);
            let new_content: Vec<u8> = if file && self.opts.binary == BinaryMode::Placeholder {
                self.binary(content, &pmime, loc, Cat::FileRemoved)
            } else if !is_text(&pmime, content) {
                if file { content.to_vec() } else { self.binary(content, &pmime, loc, Cat::BinaryRemoved) }
            } else if ctx != Ctx::Plain && !file {
                let t = String::from_utf8_lossy(content);
                self.value(&t, ctx, loc).map(String::into_bytes).unwrap_or_else(|| content.to_vec())
            } else {
                let mut dummy = Headers::new();
                self.text_bytes(content, &pct, &mut dummy, loc)
            };
            out.extend_from_slice(&new_content);
            out.extend_from_slice(&part[content_end..]);
        }
        out.extend_from_slice(&b[*starts.last().unwrap()..]);
        Some(out)
    }

    /// The WebSocket frame log (see `quena-proxy::wsframe`): text messages scrubbed,
    /// binary ones per the binary option.
    fn ws_log(&mut self, body: &Body) -> Vec<u8> {
        let mut b = Vec::new();
        let _ = body.stream(0, false).take(MAX_DECODED as u64 * 4).read_to_end(&mut b);
        if b.is_empty() {
            return b;
        }
        if matches!(self.opts.bodies, BodyMode::Drop | BodyMode::Placeholder) {
            self.log.add(Cat::BodyRemoved, Loc::Ws);
            return Vec::new();
        }
        let limit = (self.opts.truncate_kib.max(1) as usize) << 10;
        let mut out = Vec::with_capacity(b.len());
        let mut pos = 0;
        let mut text_message = false;
        while pos + 16 <= b.len() {
            let len = u32::from_le_bytes(b[pos + 12..pos + 16].try_into().unwrap()) as usize;
            let Some(payload) = b.get(pos + 16..pos + 16 + len) else { break };
            let (opcode, fin) = (b[pos + 1], b[pos + 2] != 0);
            let is_text = opcode == 1 || (opcode == 0 && text_message);
            if opcode == 1 || opcode == 2 {
                text_message = opcode == 1 && !fin;
            } else if opcode == 0 && fin {
                text_message = false;
            }
            let mut new: Vec<u8> = if is_text {
                self.log.ws_messages += 1;
                let t = String::from_utf8_lossy(payload);
                let tt = t.trim_start();
                let json = if tt.starts_with('{') || tt.starts_with('[') { self.json(&t, Loc::Ws) } else { None };
                json.unwrap_or_else(|| self.scrub(&t, Loc::Ws, Enc::Raw).into_owned()).into_bytes()
            } else if opcode == 8 && payload.len() > 2 {
                let mut v = payload[..2].to_vec();
                v.extend_from_slice(self.scrub(&String::from_utf8_lossy(&payload[2..]), Loc::Ws, Enc::Raw).as_bytes());
                v
            } else if opcode == 2 || opcode == 0 || ((opcode == 9 || opcode == 0xa) && !payload.is_empty()) {
                if self.opts.binary == BinaryMode::Placeholder && !payload.is_empty() {
                    self.log.add(Cat::BinaryRemoved, Loc::Ws);
                    format!("<binary message removed: {}>", size_label(payload.len() as u64)).into_bytes()
                } else {
                    payload.to_vec()
                }
            } else {
                payload.to_vec()
            };
            if self.opts.bodies == BodyMode::Truncate && new.len() > limit && is_text {
                let mut end = limit;
                while end > 0 && (new[end] & 0xc0) == 0x80 {
                    end -= 1;
                }
                new.truncate(end);
                new.extend_from_slice("…<truncated>".as_bytes());
                self.log.add(Cat::BodyTruncated, Loc::Ws);
            }
            out.extend_from_slice(&b[pos..pos + 12]);
            out.extend_from_slice(&(new.len() as u32).to_le_bytes());
            out.extend_from_slice(&new);
            pos += 16 + len;
        }
        out
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
    fn path(&mut self, path: &str) -> String {
        path.split('/')
            .map(|seg| {
                let d = decode_param(&seg.replace('+', "%2B"));
                match self.s.scrub(&d, self.loc, Enc::Raw) {
                    Cow::Owned(n) => encode_component(&n),
                    Cow::Borrowed(_) => seg.to_string(),
                }
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

// ------------------------------------------------------------------ JSON

/// A JSON tokenizer that copies its input and replaces scalar values.
struct JsonParser<'a> {
    b: &'a [u8],
    s: &'a str,
    i: usize,
    out: String,
    depth: usize,
}

impl JsonParser<'_> {
    fn ws(&mut self) {
        let start = self.i;
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
        self.out.push_str(&self.s[start..self.i]);
    }

    fn value(&mut self, z: &mut Sanitizer, ctx: Ctx, loc: Loc) -> Result<(), ()> {
        self.depth += 1;
        if self.depth > 512 {
            return Err(());
        }
        let r = match self.b.get(self.i).ok_or(())? {
            b'{' => self.object(z, ctx, loc),
            b'[' => self.array(z, ctx, loc),
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

    fn object(&mut self, z: &mut Sanitizer, ctx: Ctx, loc: Loc) -> Result<(), ()> {
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
            let child = ctx.child(z.field_ctx(&key));
            self.value(z, child, loc)?;
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

    fn array(&mut self, z: &mut Sanitizer, ctx: Ctx, loc: Loc) -> Result<(), ()> {
        self.out.push('[');
        self.i += 1;
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.out.push(']');
            self.i += 1;
            return Ok(());
        }
        loop {
            self.value(z, ctx, loc)?;
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

/// Non-overlapping replacements in a string.
#[derive(Default, Clone)]
struct Spans(Vec<(usize, usize, String)>);

impl Spans {
    fn free(&self, a: usize, b: usize) -> bool {
        a < b && !self.0.iter().any(|(x, y, _)| a < *y && *x < b)
    }
    fn add(&mut self, a: usize, b: usize, r: String) {
        self.0.push((a, b, r));
    }
    fn apply<'a>(mut self, s: &'a str) -> Cow<'a, str> {
        if self.0.is_empty() {
            return Cow::Borrowed(s);
        }
        self.0.sort_by_key(|x| x.0);
        let mut out = String::with_capacity(s.len());
        let mut pos = 0;
        for (a, b, r) in self.0 {
            out.push_str(&s[pos..a]);
            out.push_str(&r);
            pos = b;
        }
        out.push_str(&s[pos..]);
        Cow::Owned(out)
    }
}

// ------------------------------------------------------------------ names

/// Body field names whose values are secrets (lower case).
fn secret_field(n: &str) -> bool {
    const EXACT: &[&str] = &["code", "otp", "totp", "nonce", "sig", "auth", "sid", "pin", "cvv", "cvc", "cvv2", "tan", "passcode", "code_verifier", "code_challenge", "login_hint", "authorization", "cookie", "set-cookie", "privatekey", "private_key"];
    const PARTS: &[&str] = &["token", "password", "passwd", "passwort", "kennwort", "secret", "signature", "apikey", "api_key", "api-key", "credential", "jwt", "assertion", "samlresponse", "samlrequest", "ticket", "session"];
    // Metadata about secrets, not secrets: `token_type`, `token_endpoint` (OpenID discovery),
    // `revocation_endpoint_auth_methods_supported`, `session_state_url` … URLs among them are
    // still scrubbed as URLs.
    const NOT: &[&str] = &[
        "type", "count", "length", "size", "enabled", "required", "expires_in", "expiresin", "expiry", "expires_at", "issued_at", "ttl", "timeout", "policy", "hint_type",
        "endpoint", "uri", "url", "supported", "methods",
    ];
    if NOT.iter().any(|x| n.ends_with(x)) {
        return false;
    }
    EXACT.contains(&n) || PARTS.iter().any(|p| n.contains(p)) || n.starts_with("x-amz-") || n.starts_with("x-goog-")
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
        "sozialversicherungsnummer", "lat", "lng", "latitude", "longitude", "geolocation",
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
    const NOT: &[&str] = &["sec-websocket-key", "sec-websocket-accept", "access-control-allow-headers", "access-control-expose-headers", "access-control-request-headers"];
    if NOT.contains(&n) {
        return false;
    }
    PARTS.iter().any(|p| n.contains(p)) || n.ends_with("-key") || n.starts_with("x-auth") || n == "x-amz-security-token" || n == "dpop"
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
    EMAIL = r"(?i)[a-z0-9][a-z0-9._+\-]{0,63}(?:@|%40)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}";
    IBAN = r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}\b";
    CARD = r"\b[0-9](?:[ \-]?[0-9]){12,18}\b";
    TAX_ID = r"\b[1-9][0-9](?: ?[0-9]{3}){3}\b";
    SVNR = r"\b[0-9]{2} ?[0-9]{6} ?[A-Z] ?[0-9]{3}\b";
    PHONE = r"(?:\+[1-9]|\(0\)|\b0)[0-9 ()\-/]{6,22}[0-9]";
    IPV4 = r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b";
    IPV6 = r"(?i)(?:[0-9a-f]{1,4}:){1,7}(?:(?::[0-9a-f]{1,4}){1,7}|[0-9a-f]{1,4}|:)|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}";
    UUID = r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b";
    DATE = r"\b(?:[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]+)?)?(?:Z|[+\-][0-9]{2}:?[0-9]{2})?)?|[0-9]{1,2}\.[0-9]{1,2}\.(?:19|20)[0-9]{2}|[0-9]{1,2}[/\-][0-9]{1,2}[/\-](?:19|20)?[0-9]{2})\b";
    TIME = r"\b[0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?\b";
    KV = r#"([A-Za-z0-9_.\-\[\]]{1,64})=([^&\s"'<>;,]+)"#;
    JSON_KV = r#""([A-Za-z0-9_\-.$@]{1,64})"\s*:\s*"((?:[^"\\]|\\.)*)""#;
    USERINFO = r"(?i)\b[a-z][a-z0-9+.\-]*://([^/\s@'<>?#]+)@";
    INPUT = r"(?i)<input\b[^>]*>";
    ATTR = r#"([A-Za-z\-]+)\s*=\s*("[^"]*"|'[^']*')"#;
}

fn re(r: &'static (OnceLock<Regex>, &'static str)) -> &'static Regex {
    r.0.get_or_init(|| Regex::new(r.1).expect("sanitize regex"))
}

/// File extensions that look like top-level domains (`logo@2x.png`).
const NOT_TLDS: &[&str] = &["png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "js", "mjs", "css", "map", "json", "html", "htm", "woff", "woff2", "ttf", "otf", "eot", "pdf", "txt", "xml", "mp4", "webm", "mp3", "wasm"];

fn email_ok(s: &str, a: usize, b: usize, e: &str) -> bool {
    let tld = e.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if NOT_TLDS.contains(&tld.as_str()) {
        return false;
    }
    let next = s[b..].chars().next();
    let prev = s[..a].chars().next_back();
    !next.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_') && !prev.is_some_and(|c| c.is_alphanumeric())
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

/// All separators in a card number are the same (or none).
fn consistent_separators(m: &str) -> bool {
    let seps: Vec<char> = m.chars().filter(|c| !c.is_ascii_digit()).collect();
    seps.windows(2).all(|w| w[0] == w[1])
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

/// The end of a valid IBAN in `s[a..b]` (a spaced match may have run into the next word).
fn iban_at(s: &str, a: usize, b: usize) -> Option<usize> {
    let m = &s[a..b];
    if iban(m) {
        return Some(b);
    }
    let mut ends: Vec<usize> = m.match_indices(' ').map(|(i, _)| a + i).collect();
    ends.reverse();
    ends.into_iter().find(|&e| iban(&s[a..e]))
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

/// Whether the phone candidate `s[a..b]` is a phone number: `+` or `00`/`0` prefix with an
/// area code, 8–15 digits, consistent separators, no date, not inside a longer token.
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
    if m.starts_with("00") {
        return separated && !m.starts_with("000");
    }
    // National: `0` and an area code (second digit 1-9).
    if m.as_bytes().get(1).is_none_or(|&c| c == b'0' || !c.is_ascii_digit() && c != b'(') && !m.starts_with("0(") {
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
    if quena_body::charset::is_textual(Some(mime)) {
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

/// The body without its Content-Encoding (at most `limit` bytes); an error when the encoding
/// is unknown or the data cannot be decoded at all.
fn try_decode(headers: &Headers, body: &Body, limit: usize) -> Result<Vec<u8>, String> {
    match headers.get("content-encoding").map(str::trim).filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity")) {
        Some(ce) => quena_body::decode::decode_prefix(body, ce, limit, &quena_body::decode::NoProgress).map_err(|e| {
            let e = e.to_string();
            if e.len() > 80 { format!("{}…", &e[..e.char_indices().take_while(|(i, _)| *i < 80).last().map_or(0, |(i, c)| i + c.len_utf8())]) } else { e }
        }),
        None => {
            let mut v = Vec::new();
            body.stream(0, false).take(limit as u64).read_to_end(&mut v).map_err(|e| e.to_string())?;
            Ok(v)
        }
    }
}

/// The body without its Content-Encoding (at most `limit` bytes); the stored bytes when the
/// encoding is unknown or broken.
pub fn decoded_body(headers: &Headers, body: &Body, limit: usize) -> Vec<u8> {
    try_decode(headers, body, limit).unwrap_or_else(|_| {
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
        for neg in ["41111111111111110", "x14111111111111111", "4111111111111111.5", "4111 1111-1111 1111", "ts 1700000000000 and 1712345678901", "id 4111111111111111_2"] {
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
        assert_eq!(h.get("authorization"), Some("Bearer <40 bytes>"));
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
        assert!(out.contains("<wsse:Password Type=\"x\">&lt;token-") && out.contains(r#"<Customer email="&lt;personal-2&gt;" id="1">"#) && out.contains("<Note>a &amp; b, &lt;ip-1&gt;</Note>"), "{out}");
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
        assert!(out.request.len() < 1100 && out.request.ends_with("…<truncated 1976 bytes>".as_bytes()));
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
    fn sse_and_custom_rules() {
        let mut s = Sanitizer::new(SanitizeOptions { patterns: vec![r"ACME-\d+".into()], extra_fields: vec!["tenant".into()], ..Default::default() });
        let out = s.text("event: msg\ndata: {\"tenant\":\"t1\",\"ref\":\"ACME-123\"}\n\ndata: plain max@example.com\n", "text/event-stream", Loc::Body);
        assert_eq!(out, "event: msg\ndata: {\"tenant\":\"<redacted-1>\",\"ref\":\"<redacted-2>\"}\n\ndata: plain <email-1>\n");
        assert_eq!(s.log().count("custom"), 2);
    }
}
