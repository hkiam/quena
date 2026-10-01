//! OAuth 2 / OpenID Connect diagnostics: `OAUTH-*`, `TOKEN-*`, `OIDC-*`.
//!
//! Input: the authentication facts the host extracts (`Session::auth`: JWT claims of bearer
//! tokens, token requests and responses, discovery documents — never secrets), the OAuth
//! parameters of URLs and `Location` headers (`response_type`, `client_id`, `error` … keep
//! their values; `code`, `state`, `nonce`, tokens are redacted) and the `WWW-Authenticate`
//! parameters (`error`, `error_description`, `scope` …). Everything degrades gracefully:
//! HAR imports without bodies still give flows and URL findings from the URLs alone.
//!
//! [`Model`] is built once per run (shared through `Prep`) and holds the OAuth-relevant
//! sessions: authorization requests, token requests, errors, tokens in URLs, bearer
//! requests, discovery/JWKS fetches. The rules read it:
//!
//! * `OAUTH-ERROR` — errors of token/authorize/device endpoints and APIs, per IdP host and
//!   error code, explained from `crate::idp` (AADSTS codes, OAuth codes, Keycloak texts).
//! * `OAUTH-FLOW` — flows per client; implicit, ROPC, code without PKCE, secrets, http
//!   redirect URIs, tokens in the query.
//! * `TOKEN-IN-URL`, `TOKEN-EXPIRED`, `TOKEN-NOTYET`, `TOKEN-AUDIENCE`, `TOKEN-SCOPE`,
//!   `TOKEN-SIZE`, `TOKEN-REFRESH` — problems of the tokens themselves.
//! * `OIDC-LOOP`, `OIDC-SILENT`, `OIDC-DISCOVERY` — sign-in loops, failing silent renewal,
//!   discovery caching and issuer mismatches.
//!
//! Double reporting is avoided: API errors that a `TOKEN-*` rule explains are not repeated
//! by `OAUTH-ERROR`; silent sign-in errors belong to `OIDC-SILENT`; `AUTH-FAIL` leaves 403s
//! with token facts to `TOKEN-SCOPE`; `COOKIE` leaves oversized authentication cookies to
//! `TOKEN-SIZE`; repeated token requests are `TOKEN-REFRESH` only (no longer `AUTH-REPEAT`).
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::request::emit;
use crate::canon;
use crate::idp::{self, Class, Endpoint, Idp, Topic};
use crate::model::{Analyzer, Confidence, Ctx, Finding, JwtClaims, Session, Severity};
use crate::util::{self, FxHashMap, FxHashSet};

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(OAuthErrors),
        Box::new(Flows),
        Box::new(TokenInUrl),
        Box::new(TokenExpired),
        Box::new(TokenNotYet),
        Box::new(TokenAudience),
        Box::new(TokenScope),
        Box::new(TokenSize),
        Box::new(TokenRefresh),
        Box::new(OidcLoop),
        Box::new(OidcSilent),
        Box::new(OidcDiscovery),
    ]
}

// ------------------------------------------------------------------ thresholds

/// Clock difference token checks tolerate (seconds); client libraries commonly allow 0–5
/// minutes, 60 s is a typical default.
pub const LEEWAY_S: i64 = 60;
/// An API that accepts a token expired by more than this does not check `exp` (ASP.NET
/// Core's default `ClockSkew` is 5 minutes).
pub const ACCEPTED_EXPIRED_S: i64 = 300;
/// Tokens valid only this far in the future are critical (Kerberos' default tolerance;
/// beyond it every library rejects them).
pub const NOTYET_CRIT_S: i64 = 300;
/// OAUTH-ERROR: client credential and grant errors on the token endpoint from this count
/// are critical.
pub const ERROR_CRIT_MIN: usize = 3;
/// OIDC-LOOP: authorization requests of one client within [`LOOP_WINDOW_US`] from this count.
pub const LOOP_MIN: usize = 3;
pub const LOOP_WINDOW_US: u64 = 60_000_000;
/// TOKEN-SIZE: an `Authorization` header from this size is a warning (nginx's default
/// `large_client_header_buffers` is 8 KiB per header line) …
pub const TOKEN_WARN_BYTES: u64 = 8 << 10;
/// … and critical from this size (IIS/http.sys `MaxFieldLength` 16 KiB).
pub const TOKEN_CRIT_BYTES: u64 = 16 << 10;
/// TOKEN-SIZE: chunks of one authentication cookie in a request from this count.
pub const COOKIE_CHUNKS_MIN: usize = 3;
/// TOKEN-SIZE: OIDC nonce/correlation cookies in one request from this count (left over
/// from sign-ins that did not complete).
pub const NONCE_COOKIES_MIN: usize = 5;
/// TOKEN-SIZE: the latest `Set-Cookie` values of a host's authentication cookies from
/// this total size.
pub const AUTH_COOKIE_BYTES_WARN: u64 = 8 << 10;
/// TOKEN-REFRESH: a new token for the same client, grant and scope before this share of
/// the previous `expires_in` has passed is early …
pub const REFRESH_EARLY_SHARE: f64 = 0.5;
/// … reported from this many early requests.
pub const REFRESH_EARLY_MIN: usize = 3;
/// TOKEN-REFRESH without `expires_in`: token requests of one client within this window …
pub const REFRESH_WINDOW_US: u64 = 300_000_000;
/// … from this count.
pub const REFRESH_WINDOW_MIN: usize = 3;
/// TOKEN-REFRESH: token requests at least this share of the client's API calls …
pub const REFRESH_PER_CALL_SHARE: f64 = 0.5;
/// … with at least this many token requests: a token per call.
pub const REFRESH_PER_CALL_MIN: usize = 5;
/// OIDC-DISCOVERY: fetches of one document within this window …
pub const DISCOVERY_WINDOW_US: u64 = 300_000_000;
/// … from this count (info) / this count (warning).
pub const DISCOVERY_INFO_MIN: usize = 5;
pub const DISCOVERY_WARN_MIN: usize = 20;
/// OIDC-SILENT: an interactive sign-in this soon after a silent attempt means it failed.
pub const SILENT_FALLBACK_US: u64 = 60_000_000;
/// A redirect target or callback must follow within this time to count as the same step.
const FOLLOW_US: u64 = 10_000_000;

pub const PROFILES: &[&str] = &["auth", "troubleshooting"];
/// Security-relevant flow findings also belong to modernization.
const PROFILES_SECURITY: &[&str] = &["auth", "troubleshooting", "modernization"];

// ------------------------------------------------------------------ URL and header helpers

/// Path of an absolute URL (no allocation; `/` if empty).
fn raw_path(url: &str) -> &str {
    let rest = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
}

/// `scheme://host/path` without query and fragment, lower-case scheme and host.
fn base_url(url: &str) -> String {
    let u = url.split(['?', '#']).next().unwrap_or("");
    match u.find("://") {
        Some(i) => {
            let rest = &u[i + 3..];
            let (auth, path) = rest.find('/').map(|k| (&rest[..k], &rest[k..])).unwrap_or((rest, ""));
            format!("{}://{}{}", u[..i].to_ascii_lowercase(), auth.to_ascii_lowercase(), path.trim_end_matches('/'))
        }
        None => u.trim_end_matches('/').to_string(),
    }
}

/// Host of a URL (lower-case, default port dropped).
fn url_host(url: &str) -> String {
    canon::parse(url).host
}

fn decode_pair(p: &str) -> (String, String) {
    let (k, v) = p.split_once('=').unwrap_or((p, ""));
    let dec = |x: &str| if x.contains('+') { canon::decode(&x.replace('+', " ")) } else { canon::decode(x) };
    (dec(k).to_ascii_lowercase(), dec(v))
}

/// Decoded URL parameters (names lower-case).
type Params = Vec<(String, String)>;

/// Decoded query and fragment parameters (names lower-case).
fn url_params(url: &str) -> (Params, Params) {
    let (before, frag) = url.split_once('#').unwrap_or((url, ""));
    let query = before.split_once('?').map(|(_, q)| q).unwrap_or("");
    let split = |s: &str| s.split('&').filter(|p| !p.is_empty()).map(decode_pair).collect::<Vec<_>>();
    (split(query), split(frag))
}

fn param<'a>(p: &'a [(String, String)], name: &str) -> Option<&'a str> {
    p.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

/// A redacted value (`<n bytes>`).
fn redacted(v: &str) -> bool {
    util::redacted_bytes(v).is_some() && v.trim_start().starts_with('<')
}

/// Value of a parameter that is not redacted.
fn plain<'a>(p: &'a [(String, String)], name: &str) -> Option<&'a str> {
    param(p, name).filter(|v| !redacted(v))
}

/// Cheap pre-check: could this URL carry OAuth parameters?
fn may_carry_oauth(url: &str) -> bool {
    let Some(i) = url.find(['?', '#']) else { return false };
    let q = &url[i..];
    q.contains("response_type") || q.contains("error") || q.contains("_token") || q.contains("client_id")
}

/// Parameters of a `WWW-Authenticate` value: `(scheme, [(name, value)])` per challenge;
/// values unquoted, names lower-case; redacted or missing values are empty.
pub fn challenges(v: &str) -> Vec<(String, Vec<(String, String)>)> {
    const PARAMS: [&str; 10] = ["realm", "error", "error_description", "error_uri", "scope", "authorization_uri", "resource_metadata", "resource", "trusted_issuers", "nonce"];
    // Split at commas outside quotes.
    let mut items = vec![];
    let (mut cur, mut quoted, mut esc) = (String::new(), false, false);
    for c in v.chars() {
        if esc {
            cur.push(c);
            esc = false;
        } else if c == '\\' && quoted {
            esc = true;
        } else if c == '"' {
            quoted = !quoted;
            cur.push(c);
        } else if c == ',' && !quoted {
            items.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    items.push(cur);
    let mut out: Vec<(String, Vec<(String, String)>)> = vec![];
    let unquote = |s: &str| {
        let s = s.trim();
        let s = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(s);
        if redacted(s) { String::new() } else { s.to_string() }
    };
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let eq = item.find('=');
        let sp = item.find(char::is_whitespace);
        // `Scheme rest…` starts a new challenge unless it is a `name=value` pair.
        let (scheme, rest) = match (sp, eq) {
            (Some(s), Some(e)) if s < e => (Some(&item[..s]), item[s..].trim()),
            (Some(s), None) => (Some(&item[..s]), item[s..].trim()),
            (None, None) if !PARAMS.iter().any(|p| item.eq_ignore_ascii_case(p)) || out.is_empty() => (Some(item), ""),
            _ => (None, item),
        };
        if let Some(sc) = scheme {
            out.push((sc.to_string(), vec![]));
        }
        if rest.is_empty() {
            continue;
        }
        let Some(last) = out.last_mut() else { continue };
        match rest.split_once('=') {
            Some((k, val)) => last.1.push((k.trim().to_ascii_lowercase(), unquote(val))),
            // Token68 (redacted) or a bare parameter name of the old redaction format.
            None if PARAMS.iter().any(|p| rest.eq_ignore_ascii_case(p)) => last.1.push((rest.to_ascii_lowercase(), String::new())),
            None => {}
        }
    }
    out
}

/// The Bearer/DPoP challenge of a response: error, description, scope, error_uri.
#[derive(Debug, Clone, Default)]
pub struct Challenge {
    pub error: Option<String>,
    pub description: Option<String>,
    pub scope: Option<String>,
    pub error_uri: Option<String>,
}

pub fn bearer_challenge(s: &Session) -> Option<Challenge> {
    for v in s.resp_headers("www-authenticate") {
        for (scheme, ps) in challenges(v) {
            if !(scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("dpop")) {
                continue;
            }
            let get = |n: &str| ps.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
            return Some(Challenge { error: get("error").map(|e| e.to_ascii_lowercase()), description: get("error_description"), scope: get("scope"), error_uri: get("error_uri") });
        }
    }
    None
}

/// Size of a bearer token sent by the request (Authorization `Bearer`/`DPoP`).
fn bearer_bytes(s: &Session) -> Option<u64> {
    let a = s.req_header("authorization")?;
    let scheme = util::auth_scheme(a);
    if !(scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("dpop")) {
        return None;
    }
    util::redacted_bytes(a)
        .or_else(|| s.auth.as_ref().and_then(|x| x.bearer.as_ref().map(|c| c.size as u64).or(x.opaque_bearer.map(|n| n as u64))))
        .or(Some(a.len().saturating_sub(scheme.len() + 1) as u64))
}

fn claims(s: &Session) -> Option<&JwtClaims> {
    s.auth.as_ref()?.bearer.as_ref()
}

fn start_s(s: &Session) -> i64 {
    (s.started / 1_000_000) as i64
}

/// `a.b.example.com` → `example.com` (same-site comparisons).
fn site(host: &str) -> String {
    let h = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
    if h.parse::<std::net::IpAddr>().is_ok() || h.starts_with('[') {
        return h.to_string();
    }
    let labels: Vec<&str> = h.split('.').filter(|l| !l.is_empty()).collect();
    labels[labels.len().saturating_sub(2)..].join(".").to_ascii_lowercase()
}

fn is_localhost(host: &str) -> bool {
    let h = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
    h.eq_ignore_ascii_case("localhost") || h.starts_with("127.") || h == "[::1]" || h.ends_with(".localhost")
}

// ------------------------------------------------------------------ the model

/// Outcome of an authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Unknown,
    /// Redirected back with a code or tokens.
    Success,
    /// Redirected back with `error=`.
    Error(String),
}

/// An authorization request (`/authorize` with `response_type`), from a session or from
/// a `Location` header pointing to one (when the IdP request itself is not captured).
#[derive(Debug, Clone)]
pub struct Authz {
    /// Session index (the authorize request, or the session whose Location points to it).
    pub i: usize,
    pub at: u64,
    pub via_location: bool,
    pub host: String,
    pub idp: Idp,
    pub client: String,
    /// Space-separated words, sorted (`code`, `code id_token`, `id_token token` …).
    pub response_type: String,
    pub response_mode: Option<String>,
    pub prompt: Option<String>,
    /// `code_challenge_method` (or `plain` when only a challenge is sent).
    pub pkce: Option<String>,
    pub redirect_uri: Option<String>,
    pub outcome: Outcome,
    /// A repeated request within the same sign-in (Entra ID `sso_reload=true`), not a new
    /// attempt.
    pub continuation: bool,
}

impl Authz {
    pub fn silent(&self) -> bool {
        self.prompt.as_deref().is_some_and(|p| p.split_whitespace().any(|w| w == "none")) || self.response_mode.as_deref() == Some("web_message")
    }
    fn has(&self, word: &str) -> bool {
        self.response_type.split_whitespace().any(|w| w == word)
    }
}

/// Where an error was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
    /// JSON error response (token, device, introspection endpoint).
    Json,
    /// `error=` in the Location of a redirect back to the client.
    Redirect,
    /// `error=` in the URL of the callback request.
    Callback,
    /// `WWW-Authenticate: Bearer error=…` of an API.
    Challenge,
}

#[derive(Debug, Clone)]
pub struct ErrEvent {
    pub i: usize,
    pub source: Source,
    pub host: String,
    pub idp: Idp,
    pub kind: Endpoint,
    pub error: String,
    pub description: Option<String>,
    pub codes: Vec<u32>,
    pub uri: Option<String>,
    pub trace: Option<String>,
    pub correlation: Option<String>,
    pub client: Option<String>,
    pub grant: Option<String>,
    pub silent: bool,
    pub subcode: Option<String>,
}

/// A token in a URL.
#[derive(Debug, Clone)]
pub struct UrlToken {
    pub i: usize,
    /// `access_token`, `id_token`, `refresh_token`.
    pub name: String,
    pub place: Place,
    /// Host whose URL carries the token (for a Referer: the host that received it).
    pub host: String,
    /// Host of the URL itself (differs from `host` for a Referer).
    pub url_host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Place {
    Query,
    Fragment,
    LocationQuery,
    LocationFragment,
    Referer,
}

/// Why a TOKEN-* rule explains a 401/403 ([`Model::explained`]).
pub const EXPLAINED_EXPIRED: u8 = 1;
pub const EXPLAINED_NOTYET: u8 = 2;
pub const EXPLAINED_AUDIENCE: u8 = 4;
pub const EXPLAINED_SCOPE: u8 = 8;

/// Authentication cookie size facts of one host (TOKEN-SIZE; COOKIE skips these hosts).
#[derive(Debug, Clone, Default)]
pub struct CookieSize {
    pub host: String,
    /// Most chunks of one cookie in one request, its base name and the session.
    pub chunks: usize,
    pub chunk_name: String,
    /// Most nonce/correlation cookies in one request.
    pub nonces: usize,
    /// Latest Set-Cookie size per authentication cookie name.
    pub set_bytes: BTreeMap<String, u64>,
    pub sessions: Vec<usize>,
    /// 431 / 400 responses to requests with these cookies.
    pub rejected: Vec<usize>,
}

impl CookieSize {
    pub fn set_total(&self) -> u64 {
        self.set_bytes.values().sum()
    }
    pub fn reported(&self) -> bool {
        self.chunks >= COOKIE_CHUNKS_MIN || self.nonces >= NONCE_COOKIES_MIN || self.set_total() >= AUTH_COOKIE_BYTES_WARN
    }
}

/// The OAuth-relevant part of a capture (see the module docs).
#[derive(Default)]
pub struct Model {
    pub authz: Vec<Authz>,
    /// Requests to token / device authorization endpoints.
    pub tokens: Vec<usize>,
    pub errors: Vec<ErrEvent>,
    pub url_tokens: Vec<UrlToken>,
    /// Requests with a bearer token.
    pub bearer: Vec<usize>,
    pub discovery: Vec<usize>,
    pub jwks: Vec<usize>,
    /// Requests to a registered redirect URI (callbacks).
    pub callbacks: Vec<usize>,
    /// Session index → `EXPLAINED_*` bits.
    pub explained: FxHashMap<usize, u8>,
    pub cookies: Vec<CookieSize>,
    /// IdP per host (from endpoints, discovery documents and issuers).
    pub idp_hosts: FxHashMap<String, Idp>,
    /// Median server clock offset (s) of the hosts the rules may ask about.
    pub offsets: FxHashMap<String, f64>,
}

/// The shared model of this run.
pub fn model<'a>(ctx: &'a Ctx) -> &'a Model {
    ctx.prep().oauth.get_or_init(|| Model::build(ctx))
}

fn starts_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

fn contains_ci(s: &str, needle: &str) -> bool {
    s.len() >= needle.len() && s.as_bytes().windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Base name of an authentication cookie and whether this name is one chunk of it:
/// `.AspNetCore.Cookies` / `.AspNetCore.CookiesC1`…, `FedAuth` / `FedAuth1`…, `MSISAuth` /
/// `MSISAuth1`…, `appSession` / `appSession.0`…, `next-auth.session-token.0`…, Keycloak,
/// IdentityServer and OIDC client cookies. `None` for other cookies (runs per Set-Cookie
/// of the capture: no allocation).
fn auth_cookie_base(name: &str) -> Option<(&str, bool)> {
    let aspnet = starts_ci(name, ".aspnetcore.");
    let fed = starts_ci(name, "fedauth") || starts_ci(name, "msisauth");
    let auth_like = aspnet
        || fed
        || starts_ci(name, "appsession")
        || starts_ci(name, "idsrv")
        || starts_ci(name, "oidc")
        || starts_ci(name, "keycloak_")
        || starts_ci(name, "auth_session")
        || starts_ci(name, "msal.")
        || starts_ci(name, ".auth")
        || contains_ci(name, "session-token");
    if !auth_like || is_nonce_cookie(name) || starts_ci(name, ".aspnetcore.antiforgery") {
        return None;
    }
    let digits = name.bytes().rev().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || digits == name.len() {
        return Some((name, false));
    }
    let head = &name[..name.len() - digits];
    if let Some(b) = head.strip_suffix('.') {
        return Some((b, true));
    }
    if aspnet && let Some(b) = head.strip_suffix('C') {
        return Some((b, true));
    }
    if fed {
        return Some((head, true));
    }
    Some((name, false))
}

fn is_nonce_cookie(name: &str) -> bool {
    starts_ci(name, ".aspnetcore.openidconnect.nonce") || starts_ci(name, ".aspnetcore.correlation") || starts_ci(name, "openidconnect.nonce") || starts_ci(name, "oidc.nonce")
}

/// Normalised response_type: words sorted.
fn norm_words(v: &str) -> String {
    let mut w: Vec<String> = v.split([' ', '+', ',']).filter(|x| !x.is_empty()).map(|x| x.to_ascii_lowercase()).collect();
    w.sort();
    w.dedup();
    w.join(" ")
}

/// An authorization request from its URL parameters.
fn authz_from(url: &str, q: &[(String, String)]) -> Option<(String, Authz)> {
    let rt = param(q, "response_type")?;
    let path = raw_path(url);
    let client = param(q, "client_id");
    if client.is_none() && idp::endpoint(path) != Endpoint::Authorize {
        return None;
    }
    let host = url_host(url);
    let idp = idp::detect(&host, path).unwrap_or(Idp::Generic);
    let pkce = plain(q, "code_challenge_method").map(|m| m.to_string()).or_else(|| param(q, "code_challenge").map(|_| "plain".to_string()));
    Some((
        host.clone(),
        Authz {
            i: 0,
            at: 0,
            via_location: false,
            host,
            idp,
            client: client.map(|c| if redacted(c) { "?".to_string() } else { c.to_string() }).unwrap_or_else(|| "?".into()),
            response_type: norm_words(rt),
            response_mode: plain(q, "response_mode").map(|m| m.to_ascii_lowercase()),
            prompt: plain(q, "prompt").map(|m| m.to_ascii_lowercase()),
            pkce,
            redirect_uri: plain(q, "redirect_uri").map(base_url),
            outcome: Outcome::Unknown,
            continuation: param(q, "sso_reload").is_some(),
        },
    ))
}

/// An `error=` in URL parameters that looks like an OAuth error (not some page's own
/// `?error=1`): a known code, or with description / state / AADSTS.
/// `(error, error_description, error_uri, error_subcode)` of a URL.
type UrlError = (String, Option<String>, Option<String>, Option<String>);

fn url_error(ps: &[(String, String)]) -> Option<UrlError> {
    let e = plain(ps, "error")?;
    let desc = plain(ps, "error_description").map(|d| d.to_string());
    let oauthish = idp::oauth_error(e).is_some() || desc.is_some() || param(ps, "state").is_some() || e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') && e.contains('_');
    oauthish.then(|| (e.to_ascii_lowercase(), desc, plain(ps, "error_uri").map(String::from), plain(ps, "error_subcode").map(String::from)))
}

const TOKEN_PARAMS: [&str; 3] = ["access_token", "id_token", "refresh_token"];

impl Model {
    /// Sessions whose error the OAuth rules explain (OAUTH-ERROR, OIDC-SILENT): JSON error
    /// responses of token endpoints and callbacks with `error=`; other rules skip them.
    pub fn error_sessions(&self) -> FxHashSet<usize> {
        self.errors.iter().filter(|e| matches!(e.source, Source::Json | Source::Callback)).map(|e| e.i).collect()
    }
    /// Sessions of interactive sign-ins (OIDC-LOOP): authorization requests, redirects to an
    /// authorization endpoint and callbacks.
    pub fn sign_in_sessions(&self, ctx: &Ctx) -> FxHashSet<usize> {
        let ss = ctx.sessions;
        let mut set: FxHashSet<usize> = self.authz.iter().map(|a| a.i).chain(self.callbacks.iter().copied()).collect();
        for &i in &ctx.prep().http {
            let s = &ss[i];
            if (300..400).contains(&s.status) && s.resp_header("location").is_some_and(|l| idp::endpoint(raw_path(l)) == Endpoint::Authorize) {
                set.insert(i);
            }
        }
        set
    }
    pub fn build(ctx: &Ctx) -> Model {
        let ss = ctx.sessions;
        let p = ctx.prep();
        let mut m = Model::default();
        // Location-derived authorization requests and redirect errors: (url key of the
        // target, time), to drop duplicates of requests that were captured themselves.
        let mut loc_authz: Vec<(String, Authz)> = vec![];
        let mut redirect_targets: Vec<(String, u64)> = vec![];
        let mut callback_errors: Vec<ErrEvent> = vec![];
        let mut cookie_hosts: FxHashMap<u32, CookieSize> = FxHashMap::default();
        // This pass sees every session of the capture: the endpoint kind and the "may carry
        // OAuth parameters" check are computed once per interned endpoint / URL key.
        let kinds: Vec<Endpoint> = p.endpoint_strs.iter().map(|e| idp::endpoint(e)).collect();
        let mut oauth_key: Vec<u8> = vec![0; p.url_key_strs.len()];
        for &i in &p.http {
            let s = &ss[i];
            let host = p.host_of(i);
            let kind = p.endpoint.get(i).and_then(|&e| kinds.get(e as usize)).copied().unwrap_or(Endpoint::Other);
            let auth = s.auth.as_deref();
            let carries = match p.url_key.get(i).and_then(|&k| oauth_key.get_mut(k as usize)) {
                Some(c) => {
                    if *c == 0 {
                        *c = if may_carry_oauth(p.url_key_of(i)) || s.url.contains('#') { 2 } else { 1 };
                    }
                    *c == 2 || (s.url.contains('#') && may_carry_oauth(&s.url))
                }
                None => may_carry_oauth(&s.url),
            };
            let path = if carries || kind != Endpoint::Other || auth.is_some() || s.status >= 300 { raw_path(&s.url) } else { "/" };
            // Authorization requests and errors in the URL.
            if carries {
                let (q, frag) = url_params(&s.url);
                if let Some((h, mut a)) = authz_from(&s.url, &q) {
                    a.i = i;
                    a.at = s.started;
                    if (300..400).contains(&s.status)
                        && let Some(loc) = s.resp_header("location")
                    {
                        let (lq, lf) = url_params(loc);
                        a.outcome = if let Some((e, ..)) = url_error(&lq).or_else(|| url_error(&lf)) {
                            Outcome::Error(e)
                        } else if param(&lq, "code").is_some() || param(&lf, "code").is_some() || TOKEN_PARAMS.iter().any(|t| param(&lf, t).is_some() || param(&lq, t).is_some()) {
                            Outcome::Success
                        } else {
                            Outcome::Unknown
                        };
                    }
                    m.idp_hosts.entry(h).or_insert(a.idp);
                    m.authz.push(a);
                }
                if let Some((error, description, uri, subcode)) = url_error(&q).or_else(|| url_error(&frag)) {
                    callback_errors.push(ErrEvent {
                        i,
                        source: Source::Callback,
                        host: host.to_string(),
                        idp: Idp::Generic,
                        kind: Endpoint::Authorize,
                        codes: description.as_deref().map(idp::aadsts_in).unwrap_or_default(),
                        error,
                        description,
                        uri,
                        trace: None,
                        correlation: None,
                        client: None,
                        grant: None,
                        silent: false,
                        subcode,
                    });
                }
                for (ps, place) in [(&q, Place::Query), (&frag, Place::Fragment)] {
                    for t in TOKEN_PARAMS {
                        if param(ps, t).is_some() {
                            m.url_tokens.push(UrlToken { i, name: t.into(), place, host: host.to_string(), url_host: host.to_string() });
                        }
                    }
                }
            }
            // Redirects: authorization requests, errors and tokens in the Location.
            if (300..400).contains(&s.status)
                && let Some(loc) = s.resp_header("location")
                && may_carry_oauth(loc)
            {
                let target = canon::resolve(&s.url, loc);
                let (lq, lf) = url_params(loc);
                let tkey = canon::url_key(&canon::parse(&target), Some(s.started));
                if let Some((_, mut a)) = authz_from(&target, &lq) {
                    a.i = i;
                    a.at = s.end();
                    a.via_location = true;
                    loc_authz.push((tkey.clone(), a));
                }
                if let Some((error, description, uri, subcode)) = url_error(&lq).or_else(|| url_error(&lf)) {
                    let me = m.authz.last().filter(|a| a.i == i && !a.via_location);
                    m.errors.push(ErrEvent {
                        i,
                        source: Source::Redirect,
                        host: host.to_string(),
                        idp: idp::detect(host, path).unwrap_or(Idp::Generic),
                        kind: Endpoint::Authorize,
                        codes: description.as_deref().map(idp::aadsts_in).unwrap_or_default(),
                        error,
                        description,
                        uri,
                        trace: None,
                        correlation: None,
                        client: me.map(|a| a.client.clone()),
                        grant: None,
                        silent: me.is_some_and(|a| a.silent()),
                        subcode,
                    });
                    redirect_targets.push((tkey, s.end()));
                }
                let th = url_host(&target);
                for (ps, place) in [(&lq, Place::LocationQuery), (&lf, Place::LocationFragment)] {
                    for t in TOKEN_PARAMS {
                        if param(ps, t).is_some() {
                            m.url_tokens.push(UrlToken { i, name: t.into(), place, host: th.clone(), url_host: th.clone() });
                        }
                    }
                }
            }
            // Tokens in the Referer: the URL of the previous page leaked to this host.
            if let Some(r) = s.req_header("referer")
                && r.contains("token")
                && may_carry_oauth(r)
            {
                let (rq, rf) = url_params(r);
                for t in TOKEN_PARAMS {
                    if param(&rq, t).is_some() || param(&rf, t).is_some() {
                        m.url_tokens.push(UrlToken { i, name: t.into(), place: Place::Referer, host: host.to_string(), url_host: url_host(r) });
                    }
                }
            }
            // Endpoints of the IdP.
            let token_like = matches!(kind, Endpoint::Token | Endpoint::Device) && s.method.eq_ignore_ascii_case("POST");
            if token_like || auth.is_some_and(|a| a.oauth_request.is_some()) {
                m.tokens.push(i);
            }
            match kind {
                Endpoint::Discovery => m.discovery.push(i),
                Endpoint::Jwks => m.jwks.push(i),
                _ => {}
            }
            if (token_like || matches!(kind, Endpoint::Discovery | Endpoint::Jwks | Endpoint::Authorize))
                && let Some(d) = idp::detect(host, path)
            {
                let e = m.idp_hosts.entry(host.to_string()).or_insert(d);
                if *e == Idp::Generic {
                    *e = d;
                }
            }
            if let Some(d) = auth.and_then(|a| a.discovery.as_ref()).and_then(|d| d.issuer.as_deref()) {
                let i = idp::from_issuer(d);
                let e = m.idp_hosts.entry(host.to_string()).or_insert(i);
                if *e == Idp::Generic {
                    *e = i;
                }
            }
            // JSON errors of OAuth endpoints.
            if let Some(r) = auth.and_then(|a| a.oauth_response.as_ref())
                && let Some(error) = r.error.as_deref().filter(|e| !e.trim().is_empty())
            {
                let req = auth.and_then(|a| a.oauth_request.as_ref());
                let mut codes = r.error_codes.clone();
                for c in r.error_description.as_deref().map(idp::aadsts_in).unwrap_or_default() {
                    if !codes.contains(&c) {
                        codes.push(c);
                    }
                }
                let detected = idp::detect(host, path);
                let relevant = kind != Endpoint::Other || req.is_some() || detected.is_some() || idp::oauth_error(error).is_some() || !codes.is_empty() || r.trace_id.is_some();
                if relevant {
                    m.errors.push(ErrEvent {
                        i,
                        source: Source::Json,
                        host: host.to_string(),
                        idp: detected.unwrap_or(Idp::Generic),
                        kind: if kind == Endpoint::Other && req.is_some() { Endpoint::Token } else { kind },
                        error: error.trim().to_ascii_lowercase(),
                        description: r.error_description.clone(),
                        codes,
                        uri: r.error_uri.clone(),
                        trace: r.trace_id.clone(),
                        correlation: r.correlation_id.clone(),
                        client: req.and_then(|q| q.client_id.clone()),
                        grant: req.and_then(|q| q.grant_type.clone()),
                        silent: false,
                        subcode: None,
                    });
                }
            }
            // API challenges with an error.
            if matches!(s.status, 400 | 401 | 403)
                && let Some(c) = bearer_challenge(s)
                && let Some(error) = c.error.clone()
            {
                let idp = claims(s).and_then(|c| c.iss.as_deref()).map(idp::from_issuer).unwrap_or(Idp::Generic);
                m.errors.push(ErrEvent {
                    i,
                    source: Source::Challenge,
                    host: host.to_string(),
                    idp,
                    kind: Endpoint::Other,
                    codes: c.description.as_deref().map(idp::aadsts_in).unwrap_or_default(),
                    error,
                    description: c.description,
                    uri: c.error_uri,
                    trace: None,
                    correlation: None,
                    client: claims(s).and_then(|c| c.client.clone()),
                    grant: None,
                    silent: false,
                    subcode: None,
                });
            }
            if bearer_bytes(s).is_some() {
                m.bearer.push(i);
            }
            // Authentication cookies sent (names only): chunks and nonce cookies.
            if let Some(c) = s.req_header("cookie") {
                let mut per_base: Vec<(&str, usize)> = vec![];
                let (mut nonces, mut any) = (0, false);
                for name in c.split(';').map(|x| x.split('=').next().unwrap_or("").trim()).filter(|x| !x.is_empty()) {
                    if is_nonce_cookie(name) {
                        nonces += 1;
                        any = true;
                    } else if let Some((base, chunk)) = auth_cookie_base(name) {
                        any = true;
                        if chunk {
                            match per_base.iter_mut().find(|(b, _)| *b == base) {
                                Some(e) => e.1 += 1,
                                None => per_base.push((base, 1)),
                            }
                        }
                    }
                }
                if any {
                    let e = cookie_hosts.entry(p.host[i]).or_insert_with(|| CookieSize { host: host.to_string(), ..Default::default() });
                    let chunks = per_base.iter().map(|x| x.1).max().unwrap_or(0);
                    if chunks > e.chunks {
                        e.chunks = chunks;
                        e.chunk_name = per_base.iter().max_by_key(|x| x.1).map(|x| x.0.to_string()).unwrap_or_default();
                    }
                    e.nonces = e.nonces.max(nonces);
                    if chunks >= COOKIE_CHUNKS_MIN || nonces >= NONCE_COOKIES_MIN {
                        e.sessions.push(i);
                        if matches!(s.status, 400 | 431) {
                            e.rejected.push(i);
                        }
                    }
                }
            }
        }
        // Sizes of the authentication cookies the hosts set (only hosts whose requests
        // carry authentication cookies: 8 KiB of them cannot be one cookie, so they show up
        // in the Cookie header names).
        if !cookie_hosts.is_empty() {
            for &i in &p.http {
                let Some(e) = cookie_hosts.get_mut(&p.host[i]) else { continue };
                let mut set = false;
                for v in ss[i].resp_headers("set-cookie") {
                    let name = v.split(['=', ';']).next().unwrap_or("").trim();
                    if auth_cookie_base(name).is_some() {
                        let c = util::set_cookie(v);
                        if !c.deletes {
                            set = true;
                            let b = c.bytes.unwrap_or(0) + c.name.len() as u64;
                            e.set_bytes.insert(c.name, b);
                        }
                    }
                }
                if set {
                    e.sessions.push(i);
                }
            }
        }
        // Drop Location-derived requests that were captured themselves.
        let mut seen: HashMap<&str, Vec<u64>> = HashMap::new();
        for a in m.authz.iter() {
            seen.entry(p.url_key_of(a.i)).or_default().push(a.at);
        }
        let mut extra = vec![];
        for (k, a) in loc_authz {
            let captured = seen.get(k.as_str()).is_some_and(|ts| ts.iter().any(|&t| t + 1_000_000 >= a.at && t <= a.at + FOLLOW_US));
            if !captured {
                extra.push(a);
            }
        }
        m.authz.extend(extra);
        m.authz.sort_by_key(|a| (a.at, a.i));
        for a in &m.authz {
            if !a.via_location {
                m.idp_hosts.entry(a.host.clone()).or_insert(a.idp);
            }
        }
        // Callbacks: requests to a redirect URI of an authorization request.
        let redirect_uris: BTreeSet<&str> = m.authz.iter().filter_map(|a| a.redirect_uri.as_deref()).collect();
        if !redirect_uris.is_empty() {
            let hosts: BTreeSet<String> = redirect_uris.iter().map(|u| url_host(u)).collect();
            for &i in &p.http {
                if hosts.contains(p.host_of(i)) && redirect_uris.contains(base_url(&ss[i].url).as_str()) {
                    m.callbacks.push(i);
                }
            }
        }
        // Callback errors: not when the redirect carrying them was captured; client and IdP
        // from the latest authorization request with this redirect URI.
        let mut by_target: HashMap<&str, Vec<u64>> = HashMap::new();
        for (k, t) in &redirect_targets {
            by_target.entry(k.as_str()).or_default().push(*t);
        }
        for mut e in callback_errors {
            let s = &ss[e.i];
            let dup = by_target.get(p.url_key_of(e.i)).is_some_and(|ts| ts.iter().any(|&t| t <= s.started + 1_000_000 && s.started <= t + FOLLOW_US));
            if dup {
                continue;
            }
            let base = base_url(&s.url);
            if let Some(a) = m.authz.iter().rev().find(|a| a.at <= s.started && a.redirect_uri.as_deref() == Some(base.as_str())) {
                e.host = a.host.clone();
                e.idp = a.idp;
                e.client = Some(a.client.clone());
                e.silent = a.silent();
            }
            m.errors.push(e);
        }
        // IdP of errors from the hosts' IdP; trace/correlation stay with the event.
        for e in m.errors.iter_mut() {
            if e.idp == Idp::Generic
                && let Some(&d) = m.idp_hosts.get(&e.host)
            {
                e.idp = d;
            }
        }
        m.errors.sort_by_key(|e| (ss[e.i].started, e.i));
        let mut cookies: Vec<CookieSize> = cookie_hosts.into_values().filter(|c| c.reported()).collect();
        cookies.sort_by(|a, b| a.host.cmp(&b.host));
        m.cookies = cookies;
        m.explain(ctx);
        m.clock_offsets(ctx);
        m
    }

    /// Which 401/403 responses the TOKEN-* rules explain.
    fn explain(&mut self, ctx: &Ctx) {
        let ss = ctx.sessions;
        let p = ctx.prep();
        // Successful bearer requests per host: their audiences/issuers for comparison.
        let mut ok_auds: FxHashMap<u32, BTreeSet<String>> = FxHashMap::default();
        // Entra ID token versions (v1?) of accepted tokens per host.
        let mut ok_v1: FxHashMap<u32, BTreeSet<bool>> = FxHashMap::default();
        for &i in &self.bearer {
            if (200..400).contains(&ss[i].status)
                && let Some(c) = claims(&ss[i])
            {
                ok_auds.entry(p.host[i]).or_default().extend(c.aud.iter().cloned());
                if let Some(v) = entra_v1(c) {
                    ok_v1.entry(p.host[i]).or_default().insert(v);
                }
            }
        }
        for &i in &self.bearer {
            let s = &ss[i];
            let ch = if matches!(s.status, 400 | 401 | 403) { bearer_challenge(s) } else { None };
            let cause = ch.as_ref().and_then(|c| c.description.as_deref()).and_then(idp::resource_cause);
            let mut bits = 0u8;
            if let Some(c) = claims(s) {
                if expired_by(s, c).is_some_and(|d| d > LEEWAY_S) {
                    bits |= EXPLAINED_EXPIRED;
                }
                if early_by(c, start_s(s)).is_some_and(|d| d > LEEWAY_S) {
                    bits |= EXPLAINED_NOTYET;
                }
                if s.status == 401 && bits == 0 {
                    let mismatch = audience_verdict(&c.aud, p.host_of(i)) == Some(false)
                        || ok_auds.get(&p.host[i]).is_some_and(|ok| !ok.is_empty() && !c.aud.is_empty() && c.aud.iter().all(|a| !ok.contains(a)))
                        || entra_v1(c).is_some_and(|v| ok_v1.get(&p.host[i]).is_some_and(|ok| ok.len() == 1 && !ok.contains(&v)));
                    if mismatch || matches!(cause, Some(idp::ResourceCause::Audience | idp::ResourceCause::Issuer)) {
                        bits |= EXPLAINED_AUDIENCE;
                    }
                }
            }
            match cause {
                Some(idp::ResourceCause::Expired) => bits |= EXPLAINED_EXPIRED,
                Some(idp::ResourceCause::NotYetValid) => bits |= EXPLAINED_NOTYET,
                Some(idp::ResourceCause::Audience | idp::ResourceCause::Issuer) if s.status == 401 => bits |= EXPLAINED_AUDIENCE,
                _ => {}
            }
            let insufficient = ch.as_ref().is_some_and(|c| c.error.as_deref() == Some("insufficient_scope"));
            if insufficient || (s.status == 403 && claims(s).is_some()) {
                bits |= EXPLAINED_SCOPE;
            }
            // Only rejected requests are "explained"; expired tokens that were accepted are
            // reported by TOKEN-EXPIRED from the claims directly.
            if bits != 0 && matches!(s.status, 400 | 401 | 403) {
                self.explained.insert(i, bits);
            }
        }
    }

    /// Median server clock offsets of the IdP hosts and of hosts with token time problems.
    fn clock_offsets(&mut self, ctx: &Ctx) {
        let p = ctx.prep();
        let mut wanted: BTreeSet<u32> = BTreeSet::new();
        let ids: FxHashMap<&str, u32> = p.host_strs.iter().enumerate().map(|(k, h)| (h.as_str(), k as u32)).collect();
        for h in self.idp_hosts.keys() {
            if let Some(&k) = ids.get(h.as_str()) {
                wanted.insert(k);
            }
        }
        for &i in &self.bearer {
            let s = &ctx.sessions[i];
            if let Some(c) = claims(s)
                && (expired_by(s, c).is_some_and(|d| d > LEEWAY_S) || early_by(c, start_s(s)).is_some_and(|d| d > LEEWAY_S))
            {
                wanted.insert(p.host[i]);
            }
        }
        if wanted.is_empty() {
            return;
        }
        let mut offs: FxHashMap<u32, Vec<f64>> = FxHashMap::default();
        for &i in &p.http {
            if wanted.contains(&p.host[i])
                && let Some((o, _)) = super::clock::offset_s(&ctx.sessions[i])
            {
                offs.entry(p.host[i]).or_default().push(o);
            }
        }
        for (h, v) in offs {
            self.offsets.insert(p.host_strs[h as usize].clone(), util::percentile(&v, 50.0));
        }
    }

    pub fn explained(&self, i: usize, bit: u8) -> bool {
        self.explained.get(&i).is_some_and(|b| b & bit != 0)
    }

    fn idp_of(&self, host: &str) -> Idp {
        self.idp_hosts.get(host).copied().or_else(|| idp::by_host(host)).unwrap_or(Idp::Generic)
    }
}

/// Entra ID token version: `Some(true)` for v1 (iss sts.windows.net / ver 1.0),
/// `Some(false)` for v2, `None` for other issuers.
fn entra_v1(c: &JwtClaims) -> Option<bool> {
    let iss = c.iss.as_deref()?;
    if idp::is_entra_v1_issuer(iss) || (c.ver.as_deref() == Some("1.0") && idp::from_issuer(iss).is_entra()) {
        Some(true)
    } else if idp::from_issuer(iss).is_entra() {
        Some(false)
    } else {
        None
    }
}

/// Seconds the token had expired at the request start (by this computer's clock).
fn expired_by(s: &Session, c: &JwtClaims) -> Option<i64> {
    Some(start_s(s) - c.exp? as i64)
}

/// Seconds the token's nbf/iat lie after `at_s`.
fn early_by(c: &JwtClaims, at_s: i64) -> Option<i64> {
    let t = c.nbf.into_iter().chain(c.iat).max()? as i64;
    Some(t - at_s)
}

/// Does an audience plausibly name the API on `host`? `Some(true)` plausible,
/// `Some(false)` names another API, `None` cannot tell (GUIDs, custom App ID URIs).
pub fn audience_verdict(aud: &[String], host: &str) -> Option<bool> {
    let host = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host).to_ascii_lowercase();
    let mut wrong = false;
    for a in aud {
        if let Some(h) = idp::ms_resource_host(a) {
            if host == h.trim_start_matches('.') || host.ends_with(h) {
                return Some(true);
            }
            wrong = true;
            continue;
        }
        let lower = a.to_ascii_lowercase();
        let ah = if lower.starts_with("https://") || lower.starts_with("http://") {
            Some(url_host(&lower))
        } else if let Some(rest) = lower.strip_prefix("api://") {
            let h = rest.split('/').next().unwrap_or("");
            (h.contains('.') && !canon::is_guid(h)).then(|| h.to_string())
        } else {
            None
        };
        match ah {
            Some(ah) if !ah.is_empty() => {
                let ah = ah.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h.to_string()).unwrap_or(ah);
                if ah == host || site(&ah) == site(&host) {
                    return Some(true);
                }
                wrong = true;
            }
            _ => return None,
        }
    }
    wrong.then_some(false)
}

// ------------------------------------------------------------------ shared text helpers

fn tr(ctx: &Ctx, en: String, de: String) -> String {
    if ctx.de() { de } else { en }
}

fn pick(ctx: &Ctx, pair: (&'static str, &'static str)) -> &'static str {
    if ctx.de() { pair.1 } else { pair.0 }
}

/// "Where (Keycloak): Clients → …".
fn where_rec(ctx: &Ctx, i: Idp, topic: Topic) -> Option<String> {
    let w = pick(ctx, idp::where_to(i, topic)?);
    Some(tr(ctx, format!("Where ({}): {w}", i.name()), format!("Wo ({}): {w}", i.name())))
}

/// Distinct values, most frequent first, at most `n`: `a (3), b, …`.
fn top_list(ctx: &Ctx, values: impl IntoIterator<Item = String>, n: usize) -> String {
    let mut m: HashMap<String, usize> = HashMap::new();
    for v in values {
        if !v.is_empty() {
            *m.entry(v).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let more = v.len() > n;
    let mut out: Vec<String> = v.into_iter().take(n).map(|(k, c)| if c > 1 { format!("{} ({})", util::short(&k, 120), ctx.fmt_count(c)) } else { util::short(&k, 120) }).collect();
    if more {
        out.push("…".into());
    }
    out.join(", ")
}

fn yes_no(ctx: &Ctx, b: bool) -> &'static str {
    if b { ctx.l("yes", "ja") } else { ctx.l("no", "nein") }
}

fn secs(ctx: &Ctx, s: i64) -> String {
    ctx.fmt_ms(s.unsigned_abs() as f64 * 1000.0)
}

/// Claims table rows of distinct tokens (no personal claims reach the plugin).
fn claims_table(ctx: &Ctx, rows: &[(String, &JwtClaims, i64)]) -> (Vec<String>, Vec<Vec<String>>) {
    let cols = vec![
        ctx.l("Response", "Antwort").to_string(),
        "iss".into(),
        "aud".into(),
        "ver".into(),
        "scp".into(),
        "roles".into(),
        ctx.l("exp (at request)", "exp (beim Request)").to_string(),
        ctx.l("client", "Client").to_string(),
    ];
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for (label, c, start) in rows {
        let key = (label.clone(), c.iss.clone(), c.aud.clone(), c.ver.clone(), c.scopes.clone(), c.roles.clone(), c.client.clone());
        if !seen.insert(key) || out.len() >= 8 {
            continue;
        }
        let exp = c.exp.map(|e| {
            let d = e as i64 - start;
            if d >= 0 { tr(ctx, format!("valid {}", secs(ctx, d)), format!("noch {}", secs(ctx, d))) } else { tr(ctx, format!("expired {} ago", secs(ctx, d)), format!("seit {} abgelaufen", secs(ctx, d))) }
        });
        out.push(vec![
            label.clone(),
            c.iss.clone().unwrap_or_default(),
            c.aud.join(" "),
            c.ver.clone().unwrap_or_default(),
            util::short(&c.scopes.join(" "), 120),
            util::short(&c.roles.join(" "), 120),
            exp.unwrap_or_default(),
            c.client.clone().unwrap_or_default(),
        ]);
    }
    (cols, out)
}

fn clock_hint(ctx: &Ctx, m: &Model, hosts: &[&str]) -> Option<String> {
    let (h, o) = hosts.iter().filter_map(|h| m.offsets.get(*h).map(|o| (*h, *o))).max_by(|a, b| a.1.abs().total_cmp(&b.1.abs()))?;
    (o.abs() >= 30.0).then(|| {
        tr(
            ctx,
            format!("The Date header of {h} differs from this computer's clock by {} {} (see CLOCK-SKEW / CLOCK-LOCAL): token times are judged against a wrong clock.", if o >= 0.0 { "+" } else { "−" }, secs(ctx, o as i64)),
            format!("Der Date-Header von {h} weicht um {}{} von der Uhr dieses Computers ab (siehe CLOCK-SKEW / CLOCK-LOCAL): Token-Zeiten werden gegen eine falsche Uhr geprüft.", if o >= 0.0 { "+" } else { "−" }, secs(ctx, o as i64)),
        )
    })
}

// ------------------------------------------------------------------ OAUTH-ERROR

fn source_label(ctx: &Ctx, s: Source) -> &'static str {
    match s {
        Source::Json => ctx.l("JSON error response", "JSON-Fehlerantwort"),
        Source::Redirect => ctx.l("redirect back to the client (Location)", "Weiterleitung zurück zum Client (Location)"),
        Source::Callback => ctx.l("callback URL", "Callback-URL"),
        Source::Challenge => "WWW-Authenticate",
    }
}

/// OAUTH-ERROR: OAuth/OIDC errors per IdP host and error code, explained.
struct OAuthErrors;

impl Analyzer for OAuthErrors {
    fn id(&self) -> &'static str {
        "OAUTH-ERROR"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let events = m.errors.iter().filter(|e| {
            // Silent sign-in errors: OIDC-SILENT. API errors explained by a TOKEN-* rule: there.
            let silent = e.silent && is_silent_error(&e.error);
            let explained = e.source == Source::Challenge && m.explained.contains_key(&e.i);
            !silent && !explained
        });
        let mut list = vec![];
        for ((host, error, code), v) in util::group_by(events, |e| (e.host.clone(), e.error.clone(), e.codes.first().copied())) {
            let n = v.len();
            let first = v[0];
            let the_idp = v.iter().map(|e| e.idp).find(|i| *i != Idp::Generic).unwrap_or(first.idp);
            let entry = idp::explain(the_idp, &error, first.description.as_deref(), &first.codes);
            let class = entry.map(|e| e.class).unwrap_or(Class::Config);
            let kinds: BTreeSet<Endpoint> = v.iter().map(|e| e.kind).collect();
            let on_token = kinds.contains(&Endpoint::Token);
            let resource = v.iter().all(|e| e.source == Source::Challenge);
            let severity = if class == Class::Normal {
                Severity::Info
            } else if on_token && n >= ERROR_CRIT_MIN && (matches!(class, Class::Credential | Class::Grant) || matches!(error.as_str(), "invalid_client" | "invalid_grant" | "unauthorized_client")) {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let code_txt = code.map(|c| format!(" (AADSTS{c})")).unwrap_or_default();
            let kind_txt = kinds.iter().map(|k| endpoint_label(ctx, *k)).collect::<Vec<_>>().join(", ");
            let title = if resource {
                tr(ctx, format!("API rejects the token ({error}): {}", util::short(&host, 60)), format!("API weist das Token ab ({error}): {}", util::short(&host, 60)))
            } else {
                format!("{}: {error}{code_txt} – {}", the_idp.name(), util::short(&host, 60))
            };
            let obs = if resource {
                tr(
                    ctx,
                    format!("{} response(s) of {host} named the error {error} in WWW-Authenticate.", ctx.fmt_count(n)),
                    format!("{} Response(s) von {host} nannten in WWW-Authenticate den Fehler {error}.", ctx.fmt_count(n)),
                )
            } else {
                tr(
                    ctx,
                    format!("{} {kind_txt} request(s) to {host} ({}) failed with {error}{code_txt}.", ctx.fmt_count(n), the_idp.name()),
                    format!("{} {kind_txt}-Request(s) an {host} ({}) scheiterten mit {error}{code_txt}.", ctx.fmt_count(n), the_idp.name()),
                )
            };
            let mut f = Finding::new("OAUTH-ERROR", &format!("{host}|{error}|{}", code.map(|c| c.to_string()).unwrap_or_default()), severity, title, obs)
                .categories(&["auth", "errors"])
                .tags(&["oauth"])
                .score(util::scale(n as f64, 0.0, 30.0) * 0.6 + if severity == Severity::Critical { 40.0 } else if class == Class::Normal { 0.0 } else { 20.0 })
                .threshold(if ctx.de() {
                    format!("jeder Fehler; kritisch ab {ERROR_CRIT_MIN} Client-/Grant-Fehlern am Token-Endpunkt; Gerätefluss-Abfragen: Hinweis")
                } else {
                    format!("every error; critical from {ERROR_CRIT_MIN} client/grant errors on the token endpoint; device flow polling: info")
                })
                .fact(ctx.l("Identity provider", "Identity Provider"), the_idp.name())
                .fact(ctx.l("Error", "Fehler"), error.clone())
                .fact(ctx.l("Occurrences", "Vorkommen"), ctx.fmt_count(n))
                .fact(ctx.l("Seen in", "Gesehen in"), top_list(ctx, v.iter().map(|e| source_label(ctx, e.source).to_string()), 4))
                .fact(ctx.l("Endpoints", "Endpunkte"), top_list(ctx, v.iter().map(|e| p.endpoint_of(e.i).to_string()), 3))
                .sessions(v.iter().map(|e| ss[e.i].id));
            let codes: BTreeSet<u32> = v.iter().flat_map(|e| e.codes.iter().copied()).collect();
            if !codes.is_empty() {
                f = f.fact(
                    ctx.l("AADSTS codes", "AADSTS-Codes"),
                    codes.iter().take(6).map(|c| idp::aadsts(*c).map(|e| format!("AADSTS{c} {}", e.name)).unwrap_or_else(|| format!("AADSTS{c}"))).collect::<Vec<_>>().join(", "),
                );
            }
            let descs = top_list(ctx, v.iter().filter_map(|e| e.description.clone()), 2);
            if !descs.is_empty() {
                f = f.fact("error_description", descs);
            }
            let subs = top_list(ctx, v.iter().filter_map(|e| e.subcode.clone()), 3);
            if !subs.is_empty() {
                f = f.fact("error_subcode", subs);
            }
            let uris = top_list(ctx, v.iter().filter_map(|e| e.uri.clone()), 2);
            if !uris.is_empty() {
                f = f.fact("error_uri", uris);
            }
            let clients = top_list(ctx, v.iter().filter_map(|e| e.client.clone()), 4);
            if !clients.is_empty() {
                f = f.fact(ctx.l("Clients (client_id)", "Clients (client_id)"), clients);
            }
            let grants = top_list(ctx, v.iter().filter_map(|e| e.grant.clone()), 4);
            if !grants.is_empty() {
                f = f.fact("grant_type", grants);
            }
            let tenants = top_list(ctx, v.iter().filter_map(|e| idp::tenant_or_realm(e.idp, raw_path(&ss[e.i].url))), 3);
            if !tenants.is_empty() && !resource {
                f = f.fact(if the_idp == Idp::Keycloak { "Realm" } else { ctx.l("Tenant", "Mandant") }, tenants);
            }
            // Support identifiers: the IdP's operator finds the request by them.
            let traces: Vec<String> = v.iter().filter_map(|e| e.trace.clone()).collect::<BTreeSet<_>>().into_iter().take(3).collect();
            if !traces.is_empty() {
                f = f.fact(ctx.l("Trace ids (examples)", "Trace-IDs (Beispiele)"), traces.join(", "));
            }
            let corrs: Vec<String> = v.iter().filter_map(|e| e.correlation.clone()).collect::<BTreeSet<_>>().into_iter().take(3).collect();
            if !corrs.is_empty() {
                f = f.fact(ctx.l("Correlation ids (examples)", "Korrelations-IDs (Beispiele)"), corrs.join(", "));
            }
            let statuses = top_list(ctx, v.iter().map(|e| ss[e.i].status.to_string()), 4);
            f = f.fact(ctx.l("HTTP status", "HTTP-Status"), statuses);
            f = match entry {
                Some(e) => {
                    let mut f = f.hypothesis(pick(ctx, e.cause)).recommend(pick(ctx, e.fix));
                    if let Some(w) = e.topic.and_then(|t| where_rec(ctx, the_idp, t)) {
                        f = f.recommend(w);
                    }
                    f
                }
                None => f.confidence(Confidence::Medium).hypothesis(ctx.l(
                    "An error code that is not in the knowledge base of this analyzer; error_description and the IdP's documentation explain it.",
                    "Ein Fehlercode, den die Wissensbasis dieser Analyse nicht kennt; error_description und die Dokumentation des IdP erklären ihn.",
                )),
            };
            if let Some(w) = where_rec(ctx, the_idp, Topic::Logs).filter(|_| !resource && class != Class::Normal) {
                f = f.next_step(w);
            }
            if !traces.is_empty() || !corrs.is_empty() {
                f = f.next_step(ctx.l("Give the trace and correlation ids to the IdP's administrators or support: they identify these requests in the IdP's logs.", "Trace- und Korrelations-IDs an die Administratoren oder den Support des IdP geben: Damit finden sie diese Requests in den Protokollen des IdP."));
            }
            if v.iter().all(|e| e.source == Source::Callback) {
                f = f.confidence(Confidence::Medium);
            }
            if resource {
                f = f.recommend(ctx.l(
                    "Compare the token's claims (aud, iss, scp/roles, exp) with what the API validates; TOKEN-* findings in this report check them where the claims are known.",
                    "Die Claims des Tokens (aud, iss, scp/roles, exp) mit dem vergleichen, was die API prüft; die TOKEN-*-Befunde dieses Berichts tun das, wo die Claims bekannt sind.",
                ));
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

fn endpoint_label(ctx: &Ctx, k: Endpoint) -> &'static str {
    match k {
        Endpoint::Authorize => ctx.l("authorization", "Autorisierungs"),
        Endpoint::Token => ctx.l("token", "Token"),
        Endpoint::Device => ctx.l("device authorization", "Geräteautorisierungs"),
        Endpoint::Discovery => ctx.l("discovery", "Discovery"),
        Endpoint::Jwks => "JWKS",
        Endpoint::Userinfo => "UserInfo",
        Endpoint::Introspect => ctx.l("introspection", "Introspection"),
        Endpoint::Revoke => ctx.l("revocation", "Widerrufs"),
        Endpoint::Logout => ctx.l("logout", "Abmelde"),
        Endpoint::Other => ctx.l("other", "sonstige"),
    }
}

fn is_silent_error(e: &str) -> bool {
    matches!(e, "login_required" | "interaction_required" | "consent_required" | "account_selection_required")
}

// ------------------------------------------------------------------ OAUTH-FLOW

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Flow {
    CodePkce,
    Code,
    Hybrid,
    Implicit,
    ImplicitIdToken,
    Ropc,
    ClientCredentials,
    Refresh,
    DeviceCode,
    JwtBearer,
    TokenExchange,
    Saml2,
    Ciba,
    Other,
}

fn flow_label(ctx: &Ctx, f: Flow) -> &'static str {
    match f {
        Flow::CodePkce => ctx.l("authorization code + PKCE", "Authorization Code + PKCE"),
        Flow::Code => ctx.l("authorization code (no PKCE seen)", "Authorization Code (ohne erkennbares PKCE)"),
        Flow::Hybrid => ctx.l("hybrid (code id_token)", "Hybrid (code id_token)"),
        Flow::Implicit => ctx.l("implicit (tokens in the redirect)", "Implicit (Tokens in der Weiterleitung)"),
        Flow::ImplicitIdToken => ctx.l("implicit, ID token only (sign-in)", "Implicit, nur ID-Token (Anmeldung)"),
        Flow::Ropc => ctx.l("resource owner password (ROPC)", "Resource Owner Password (ROPC)"),
        Flow::ClientCredentials => ctx.l("client credentials", "Client Credentials"),
        Flow::Refresh => ctx.l("refresh token", "Refresh-Token"),
        Flow::DeviceCode => ctx.l("device code", "Gerätecode (Device Code)"),
        Flow::JwtBearer => ctx.l("JWT bearer / on-behalf-of", "JWT Bearer / On-Behalf-Of"),
        Flow::TokenExchange => ctx.l("token exchange (RFC 8693)", "Token Exchange (RFC 8693)"),
        Flow::Saml2 => ctx.l("SAML 2.0 bearer assertion", "SAML-2.0-Bearer-Assertion"),
        Flow::Ciba => ctx.l("CIBA (backchannel)", "CIBA (Backchannel)"),
        Flow::Other => ctx.l("other grant", "anderer Grant"),
    }
}

fn grant_flow(g: &str) -> Flow {
    match g.trim().to_ascii_lowercase().as_str() {
        "authorization_code" => Flow::Code,
        "password" => Flow::Ropc,
        "client_credentials" => Flow::ClientCredentials,
        "refresh_token" => Flow::Refresh,
        "urn:ietf:params:oauth:grant-type:device_code" | "device_code" => Flow::DeviceCode,
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => Flow::JwtBearer,
        "urn:ietf:params:oauth:grant-type:token-exchange" => Flow::TokenExchange,
        "urn:ietf:params:oauth:grant-type:saml2-bearer" | "urn:ietf:params:oauth:grant-type:saml1_1-bearer" => Flow::Saml2,
        "urn:openid:params:grant-type:ciba" => Flow::Ciba,
        _ => Flow::Other,
    }
}

#[derive(Default)]
struct ClientFlows {
    idp: Option<Idp>,
    flows: BTreeMap<Flow, Vec<usize>>,
    pkce_seen: bool,
    authz_no_pkce: Vec<usize>,
    redeem_no_verifier: Vec<usize>,
    public: bool,
    confidential: bool,
    secret_post: Vec<usize>,
    browser_secret: Vec<usize>,
    http_redirect: Vec<(usize, String)>,
    query_tokens: Vec<usize>,
}

/// OAUTH-FLOW: flows per client and the risky ones.
struct Flows;

impl Analyzer for Flows {
    fn id(&self) -> &'static str {
        "OAUTH-FLOW"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES_SECURITY
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let mut clients: BTreeMap<(String, String), ClientFlows> = BTreeMap::new();
        let insecure = |uri: &str| uri.len() >= 7 && uri[..7].eq_ignore_ascii_case("http://") && !is_localhost(&url_host(uri));
        for a in m.authz.iter().filter(|a| !a.continuation) {
            let e = clients.entry((a.host.clone(), a.client.clone())).or_default();
            e.idp = e.idp.or(Some(a.idp));
            let flow = if a.has("code") && (a.has("token") || a.has("id_token")) {
                Flow::Hybrid
            } else if a.has("code") {
                if a.pkce.is_some() { Flow::CodePkce } else { Flow::Code }
            } else if a.has("token") {
                Flow::Implicit
            } else if a.has("id_token") {
                Flow::ImplicitIdToken
            } else {
                Flow::Other
            };
            e.flows.entry(flow).or_default().push(a.i);
            if a.has("code") {
                if a.pkce.is_some() {
                    e.pkce_seen = true;
                } else {
                    e.authz_no_pkce.push(a.i);
                }
            }
            if let Some(u) = a.redirect_uri.as_deref().filter(|u| insecure(u)) {
                e.http_redirect.push((a.i, u.to_string()));
            }
            if a.response_mode.as_deref() == Some("query") && (a.has("token") || a.has("id_token")) {
                e.query_tokens.push(a.i);
            }
        }
        for &i in &m.tokens {
            let s = &ss[i];
            let Some(r) = s.auth.as_ref().and_then(|a| a.oauth_request.as_ref()) else { continue };
            let host = p.host_of(i).to_string();
            let e = clients.entry((host.clone(), r.client_id.clone().unwrap_or_else(|| "?".into()))).or_default();
            e.idp = e.idp.or(Some(m.idp_of(&host)));
            let flow = match r.grant_type.as_deref() {
                Some(g) => grant_flow(g),
                None if idp::endpoint(raw_path(&s.url)) == Endpoint::Device => Flow::DeviceCode,
                None => continue,
            };
            let flow = if flow == Flow::Code {
                if r.has_code_verifier {
                    e.pkce_seen = true;
                    Flow::CodePkce
                } else {
                    e.redeem_no_verifier.push(i);
                    Flow::Code
                }
            } else {
                flow
            };
            if matches!(flow, Flow::Code | Flow::CodePkce) {
                if r.has_client_secret || r.has_client_assertion || r.basic_client_auth {
                    e.confidential = true;
                } else {
                    e.public = true;
                }
            }
            e.flows.entry(flow).or_default().push(i);
            if r.has_client_secret && !r.basic_client_auth {
                e.secret_post.push(i);
            }
            if r.has_client_secret && s.req_header("origin").is_some() {
                e.browser_secret.push(i);
            }
            if let Some(u) = r.redirect_uri.as_deref().filter(|u| insecure(u)) {
                e.http_redirect.push((i, u.to_string()));
            }
        }
        let mut list = vec![];
        for ((host, client), c) in clients {
            let the_idp = c.idp.unwrap_or(Idp::Generic);
            let subject = |kind: &str| format!("{kind}|{host}|{client}");
            let who = tr(ctx, format!("client {client} at {host} ({})", the_idp.name()), format!("Client {client} bei {host} ({})", the_idp.name()));
            let ids = |v: &[usize]| v.iter().map(|&i| ss[i].id).collect::<Vec<_>>();
            // Summary.
            let rows: Vec<Vec<String>> = c.flows.iter().map(|(f, v)| vec![flow_label(ctx, *f).to_string(), ctx.fmt_count(v.len())]).collect();
            let names: Vec<&str> = c.flows.keys().map(|f| flow_label(ctx, *f)).collect();
            list.push(
                Finding::new(
                    "OAUTH-FLOW",
                    &subject("summary"),
                    Severity::Info,
                    tr(ctx, format!("OAuth flows of {who}"), format!("OAuth-Flows von {who}")),
                    tr(ctx, format!("The {who} uses: {}.", names.join(", ")), format!("Der {who} verwendet: {}.", names.join(", "))),
                )
                .categories(&["auth"])
                .tags(&["oauth"])
                .score(10.0)
                .fact(ctx.l("Identity provider", "Identity Provider"), the_idp.name())
                .fact("client_id", client.clone())
                .table(vec![ctx.l("Flow", "Flow").into(), ctx.l("Requests", "Requests").into()], rows)
                .sessions(c.flows.values().flatten().map(|&i| ss[i].id)),
            );
            let flows_where = where_rec(ctx, the_idp, Topic::Flows);
            if let Some(v) = c.flows.get(&Flow::Implicit) {
                let mut f = Finding::new(
                    "OAUTH-FLOW",
                    &subject("implicit"),
                    Severity::Warning,
                    tr(ctx, format!("Implicit flow in use: {client}"), format!("Impliziter Flow in Verwendung: {client}")),
                    tr(
                        ctx,
                        format!("{} authorization request(s) of the {who} ask for tokens directly in the redirect (response_type with token).", ctx.fmt_count(v.len())),
                        format!("{} Autorisierungs-Request(s) des {who} verlangen Tokens direkt in der Weiterleitung (response_type mit token).", ctx.fmt_count(v.len())),
                    ),
                )
                .categories(&["auth", "security"])
                .tags(&["oauth"])
                .score(60.0)
                .threshold("response_type ∋ token")
                .impact(ctx.l(
                    "Access tokens travel in the URL fragment: browser history, scripts and open redirects can read them, and there is no refresh token — the OAuth 2.0 Security Best Current Practice (RFC 9700) deprecates the implicit flow.",
                    "Zugriffstokens reisen im URL-Fragment: Browserverlauf, Skripte und offene Weiterleitungen können sie lesen, und es gibt kein Refresh-Token – die OAuth 2.0 Security Best Current Practice (RFC 9700) rät vom impliziten Flow ab.",
                ))
                .recommend(ctx.l("Switch to authorization code with PKCE (current SDKs such as MSAL.js 2+, oidc-client-ts do this).", "Auf Authorization Code mit PKCE umstellen (aktuelle SDKs wie MSAL.js 2+ und oidc-client-ts tun das)."))
                .sessions(ids(v));
                if let Some(w) = flows_where.clone() {
                    f = f.recommend(w);
                }
                list.push(f);
            }
            if let Some(v) = c.flows.get(&Flow::Ropc) {
                let mut f = Finding::new(
                    "OAUTH-FLOW",
                    &subject("ropc"),
                    Severity::Warning,
                    tr(ctx, format!("Password grant (ROPC) in use: {client}"), format!("Password-Grant (ROPC) in Verwendung: {client}")),
                    tr(
                        ctx,
                        format!("{} token request(s) of the {who} send a user name and password (grant_type=password).", ctx.fmt_count(v.len())),
                        format!("{} Token-Request(s) des {who} senden Benutzername und Passwort (grant_type=password).", ctx.fmt_count(v.len())),
                    ),
                )
                .categories(&["auth", "security"])
                .tags(&["oauth"])
                .score(65.0)
                .threshold("grant_type=password")
                .impact(ctx.l(
                    "The application handles the user's password itself; MFA, Conditional Access, federation and passwordless sign-in do not work, and the grant is deprecated (RFC 9700, OAuth 2.1).",
                    "Die Anwendung verarbeitet das Passwort des Benutzers selbst; MFA, bedingter Zugriff, Föderation und passwortlose Anmeldung funktionieren nicht, und der Grant ist abgekündigt (RFC 9700, OAuth 2.1).",
                ))
                .recommend(ctx.l(
                    "Use authorization code + PKCE for users (device code for input-constrained devices) and client credentials for services.",
                    "Für Benutzer Authorization Code + PKCE verwenden (Gerätecode für Geräte ohne Eingabe), für Dienste Client Credentials.",
                ))
                .sessions(ids(v));
                if let Some(w) = flows_where.clone() {
                    f = f.recommend(w);
                }
                list.push(f);
            }
            if !c.pkce_seen && (!c.authz_no_pkce.is_empty() || !c.redeem_no_verifier.is_empty()) {
                let (severity, conf) = if c.public {
                    (Severity::Warning, Confidence::High)
                } else if c.confidential {
                    (Severity::Info, Confidence::High)
                } else {
                    (Severity::Info, Confidence::Medium)
                };
                let mut v = c.authz_no_pkce.clone();
                v.extend(&c.redeem_no_verifier);
                let mut f = Finding::new(
                    "OAUTH-FLOW",
                    &subject("pkce"),
                    severity,
                    tr(ctx, format!("Authorization code without PKCE: {client}"), format!("Authorization Code ohne PKCE: {client}")),
                    tr(
                        ctx,
                        format!("The {who} uses the authorization code flow without code_challenge / code_verifier ({} request(s)).", ctx.fmt_count(v.len())),
                        format!("Der {who} verwendet den Authorization-Code-Flow ohne code_challenge / code_verifier ({} Request(s)).", ctx.fmt_count(v.len())),
                    ),
                )
                .confidence(conf)
                .categories(&["auth", "security"])
                .tags(&["oauth"])
                .score(if c.public { 55.0 } else { 25.0 })
                .threshold(ctx.l("no code_challenge_method / code_verifier; warning for public clients", "kein code_challenge_method / code_verifier; Warnung bei öffentlichen Clients"))
                .fact(
                    ctx.l("Client type", "Client-Typ"),
                    if c.public {
                        ctx.l("public (token request without client authentication)", "öffentlich (Token-Request ohne Client-Authentifizierung)")
                    } else if c.confidential {
                        ctx.l("confidential (client authentication on the token request)", "vertraulich (Client-Authentifizierung beim Token-Request)")
                    } else {
                        ctx.l("unknown (no token request captured)", "unbekannt (kein Token-Request aufgezeichnet)")
                    },
                )
                .impact(if c.public {
                    ctx.l(
                        "A public client without PKCE: an intercepted authorization code (malicious app with the same redirect scheme, logs, Referer) can be redeemed by an attacker.",
                        "Ein öffentlicher Client ohne PKCE: Ein abgefangener Autorisierungscode (bösartige App mit demselben Redirect-Schema, Logs, Referer) kann von einem Angreifer eingelöst werden.",
                    )
                } else {
                    ctx.l(
                        "PKCE also protects confidential clients against code injection; OAuth 2.1 and RFC 9700 recommend it for every client.",
                        "PKCE schützt auch vertrauliche Clients vor Code-Injection; OAuth 2.1 und RFC 9700 empfehlen es für jeden Client.",
                    )
                })
                .recommend(ctx.l("Send code_challenge with code_challenge_method=S256 and redeem with the code_verifier.", "code_challenge mit code_challenge_method=S256 senden und mit dem code_verifier einlösen."))
                .sessions(ids(&v));
                if let Some(w) = where_rec(ctx, the_idp, Topic::Pkce) {
                    f = f.recommend(w);
                }
                list.push(f);
            }
            if !c.browser_secret.is_empty() {
                let mut f = Finding::new(
                    "OAUTH-FLOW",
                    &subject("browser-secret"),
                    Severity::Warning,
                    tr(ctx, format!("Client secret sent from a browser: {client}"), format!("Client-Secret aus dem Browser gesendet: {client}")),
                    tr(
                        ctx,
                        format!("{} token request(s) of the {who} carry a client_secret and an Origin header – they come from a web page.", ctx.fmt_count(c.browser_secret.len())),
                        format!("{} Token-Request(s) des {who} enthalten ein client_secret und einen Origin-Header – sie kommen von einer Webseite.", ctx.fmt_count(c.browser_secret.len())),
                    ),
                )
                .confidence(Confidence::Medium)
                .categories(&["auth", "security"])
                .tags(&["oauth"])
                .score(75.0)
                .threshold("client_secret + Origin")
                .impact(ctx.l("A secret in browser code is not secret: anyone can read it and act as the application.", "Ein Secret im Browsercode ist nicht geheim: Jeder kann es lesen und sich als die Anwendung ausgeben."))
                .recommend(ctx.l(
                    "Treat the browser app as a public client (authorization code + PKCE, no secret), or move the token exchange to a backend (BFF).",
                    "Die Browser-App als öffentlichen Client behandeln (Authorization Code + PKCE, kein Secret) oder den Token-Austausch in ein Backend verlagern (BFF).",
                ))
                .next_step(ctx.l("Rotate the secret: it has been exposed.", "Das Secret austauschen: Es ist offengelegt."))
                .sessions(ids(&c.browser_secret));
                if let Some(w) = where_rec(ctx, the_idp, Topic::ClientCredentials) {
                    f = f.recommend(w);
                }
                list.push(f);
            } else if !c.secret_post.is_empty() {
                list.push(
                    Finding::new(
                        "OAUTH-FLOW",
                        &subject("secret-post"),
                        Severity::Info,
                        tr(ctx, format!("Client secret in the request body: {client}"), format!("Client-Secret im Request-Body: {client}")),
                        tr(
                            ctx,
                            format!("{} token request(s) of the {who} send client_secret as a form field (client_secret_post).", ctx.fmt_count(c.secret_post.len())),
                            format!("{} Token-Request(s) des {who} senden client_secret als Formularfeld (client_secret_post).", ctx.fmt_count(c.secret_post.len())),
                        ),
                    )
                    .categories(&["auth", "security"])
                    .tags(&["oauth"])
                    .score(15.0)
                    .threshold("client_secret_post")
                    .fact(ctx.l("Identity provider", "Identity Provider"), the_idp.name())
                    .fact("client_id", client.clone())
                    .fact("grant_type", top_list(ctx, c.secret_post.iter().filter_map(|&i| ss[i].auth.as_ref()?.oauth_request.as_ref()?.grant_type.clone()), 3))
                    .fact(ctx.l("Token endpoint", "Token-Endpunkt"), top_list(ctx, c.secret_post.iter().map(|&i| base_url(&ss[i].url)), 2))
                    .impact(ctx.l("Works, but shared secrets leak easily (logs of form bodies, configuration files) and expire.", "Funktioniert, aber geteilte Secrets gelangen leicht nach außen (Protokolle von Formular-Bodys, Konfigurationsdateien) und laufen ab."))
                    .recommend(ctx.l(
                        "Prefer certificate credentials / private_key_jwt or a managed identity; at least client_secret_basic.",
                        "Besser Zertifikate / private_key_jwt oder eine verwaltete Identität verwenden; mindestens client_secret_basic.",
                    ))
                    .sessions(ids(&c.secret_post)),
                );
            }
            if !c.http_redirect.is_empty() {
                let uris = top_list(ctx, c.http_redirect.iter().map(|(_, u)| u.clone()), 3);
                let mut f = Finding::new(
                    "OAUTH-FLOW",
                    &subject("http-redirect"),
                    Severity::Warning,
                    tr(ctx, format!("Redirect URI over plain HTTP: {client}"), format!("Redirect-URI über unverschlüsseltes HTTP: {client}")),
                    tr(ctx, format!("The {who} uses the redirect URI {uris}."), format!("Der {who} verwendet die Redirect-URI {uris}.")),
                )
                .categories(&["auth", "security"])
                .tags(&["oauth"])
                .score(60.0)
                .threshold(ctx.l("http:// except localhost", "http:// außer localhost"))
                .fact("redirect_uri", uris)
                .impact(ctx.l(
                    "The authorization code (or tokens) travel unencrypted; most IdPs reject such URIs, and a mismatch with the registered https URI breaks the sign-in (AADSTS50011, 'Invalid redirect uri').",
                    "Autorisierungscode (oder Tokens) reisen unverschlüsselt; die meisten IdPs lehnen solche URIs ab, und eine Abweichung von der registrierten https-URI bricht die Anmeldung (AADSTS50011, „Invalid redirect uri“).",
                ))
                .hypothesis(ctx.l(
                    "The app runs behind a TLS-terminating proxy and builds the redirect URI from the internal http request (forwarded headers not processed).",
                    "Die App läuft hinter einem TLS-terminierenden Proxy und baut die Redirect-URI aus dem internen http-Request (Forwarded-Header werden nicht ausgewertet).",
                ))
                .recommend(ctx.l(
                    "Use https redirect URIs; behind a proxy honour X-Forwarded-Proto / Forwarded (e.g. ASP.NET Core UseForwardedHeaders).",
                    "https-Redirect-URIs verwenden; hinter einem Proxy X-Forwarded-Proto / Forwarded auswerten (z. B. ASP.NET Core UseForwardedHeaders).",
                ))
                .sessions(c.http_redirect.iter().map(|(i, _)| ss[*i].id));
                if let Some(w) = where_rec(ctx, the_idp, Topic::RedirectUri) {
                    f = f.recommend(w);
                }
                list.push(f);
            }
            if !c.query_tokens.is_empty() {
                list.push(
                    Finding::new(
                        "OAUTH-FLOW",
                        &subject("query-tokens"),
                        Severity::Warning,
                        tr(ctx, format!("Tokens requested in the query string: {client}"), format!("Tokens im Query-String angefordert: {client}")),
                        tr(
                            ctx,
                            format!("{} authorization request(s) of the {who} combine a token response type with response_mode=query.", ctx.fmt_count(c.query_tokens.len())),
                            format!("{} Autorisierungs-Request(s) des {who} kombinieren einen Token-Response-Type mit response_mode=query.", ctx.fmt_count(c.query_tokens.len())),
                        ),
                    )
                    .categories(&["auth", "security"])
                    .tags(&["oauth"])
                    .score(55.0)
                    .threshold("response_mode=query + token/id_token")
                    .impact(ctx.l("Tokens in the query string end up in server and proxy logs and in Referer headers (forbidden by OIDC for token responses).", "Tokens im Query-String landen in Server- und Proxyprotokollen und in Referer-Headern (für Token-Antworten von OIDC verboten)."))
                    .recommend(ctx.l("Use response_type=code, or response_mode=form_post / fragment.", "response_type=code oder response_mode=form_post / fragment verwenden."))
                    .sessions(ids(&c.query_tokens)),
                );
            }
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TOKEN-IN-URL

fn place_label(ctx: &Ctx, p: Place) -> &'static str {
    match p {
        Place::Query => ctx.l("request URL (query)", "Request-URL (Query)"),
        Place::Fragment => ctx.l("request URL (fragment)", "Request-URL (Fragment)"),
        Place::LocationQuery => ctx.l("redirect target (Location, query)", "Weiterleitungsziel (Location, Query)"),
        Place::LocationFragment => ctx.l("redirect target (Location, fragment)", "Weiterleitungsziel (Location, Fragment)"),
        Place::Referer => "Referer",
    }
}

/// TOKEN-IN-URL: tokens as URL parameters (values are redacted; the names are enough).
struct TokenInUrl;

impl Analyzer for TokenInUrl {
    fn id(&self) -> &'static str {
        "TOKEN-IN-URL"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES_SECURITY
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let mut list = vec![];
        for ((host, name, place), v) in util::group_by(m.url_tokens.iter(), |t| (t.host.clone(), t.name.clone(), t.place)) {
            let n = v.len();
            let fragment = matches!(place, Place::Fragment | Place::LocationFragment);
            let cross = place == Place::Referer && v.iter().any(|t| site(&t.url_host) != site(&t.host));
            // SignalR / WebSocket connections pass access_token in the query by design.
            let signalr = place == Place::Query
                && name == "access_token"
                && v.iter().all(|t| {
                    let u = ss[t.i].url.to_ascii_lowercase();
                    ss[t.i].kind == crate::model::Kind::WebSocket || u.contains("/negotiate") || raw_path(&u).ends_with("hub") || u.contains("hub?")
                });
            let severity = if cross {
                Severity::Critical
            } else if signalr || (fragment && name == "id_token") {
                Severity::Info
            } else {
                Severity::Warning
            };
            let label = place_label(ctx, place);
            let mut f = Finding::new(
                "TOKEN-IN-URL",
                &format!("{host}|{name}|{}", format!("{place:?}").to_ascii_lowercase()),
                severity,
                tr(ctx, format!("{name} in the URL: {}", util::short(&host, 60)), format!("{name} in der URL: {}", util::short(&host, 60))),
                if place == Place::Referer {
                    tr(
                        ctx,
                        format!("{} request(s) to {host} carried a Referer whose URL contains {name} (from {}).", ctx.fmt_count(n), top_list(ctx, v.iter().map(|t| t.url_host.clone()), 3)),
                        format!("{} Request(s) an {host} trugen einen Referer, dessen URL {name} enthält (von {}).", ctx.fmt_count(n), top_list(ctx, v.iter().map(|t| t.url_host.clone()), 3)),
                    )
                } else {
                    tr(ctx, format!("{} URL(s) of {host} carry the parameter {name} ({label}).", ctx.fmt_count(n)), format!("{} URL(s) von {host} enthalten den Parameter {name} ({label}).", ctx.fmt_count(n)))
                },
            )
            .categories(&["auth", "security"])
            .tags(&["oauth"])
            .score(if cross { 90.0 } else if severity == Severity::Warning { 60.0 } else { 20.0 } + util::scale(n as f64, 0.0, 100.0) * 0.1)
            .threshold(ctx.l("access_token / id_token / refresh_token as URL parameter", "access_token / id_token / refresh_token als URL-Parameter"))
            .fact(ctx.l("Parameter", "Parameter"), name.clone())
            .fact(ctx.l("Where", "Wo"), label)
            .fact(ctx.l("Occurrences", "Vorkommen"), ctx.fmt_count(n))
            .sessions(v.iter().map(|t| ss[t.i].id));
            f = if fragment {
                f.impact(ctx.l(
                    "The fragment is not sent to servers, but browser history, scripts on the page and open redirects can read the token; it is the implicit flow (see OAUTH-FLOW).",
                    "Das Fragment wird nicht an Server gesendet, aber Browserverlauf, Skripte der Seite und offene Weiterleitungen können das Token lesen; das ist der implizite Flow (siehe OAUTH-FLOW).",
                ))
                .recommend(ctx.l("Use authorization code + PKCE so that tokens never appear in URLs.", "Authorization Code + PKCE verwenden, damit Tokens nie in URLs erscheinen."))
            } else if signalr {
                f.impact(ctx.l(
                    "WebSocket/SignalR connections pass the token in the query because browsers cannot set headers there — by design, but the token lands in server and proxy logs.",
                    "WebSocket-/SignalR-Verbindungen übergeben das Token in der Query, weil Browser dort keine Header setzen können – so vorgesehen, aber das Token landet in Server- und Proxyprotokollen.",
                ))
                .recommend(ctx.l("Keep the query out of access logs for these paths and use short-lived tokens.", "Die Query dieser Pfade aus den Zugriffsprotokollen heraushalten und kurzlebige Tokens verwenden."))
            } else {
                f.impact(ctx.l(
                    "Tokens in URLs leak: server, proxy and CDN logs, browser history, and the Referer header sent to other sites (RFC 6750 discourages URI query tokens).",
                    "Tokens in URLs gelangen nach außen: Server-, Proxy- und CDN-Protokolle, Browserverlauf und der Referer-Header an andere Sites (RFC 6750 rät von Tokens in der URI-Query ab).",
                ))
                .recommend(ctx.l("Send tokens in the Authorization header (or as form_post), never as a URL parameter.", "Tokens im Authorization-Header (oder per form_post) senden, nie als URL-Parameter."))
            };
            if cross {
                f = f
                    .hypothesis(ctx.l("A page whose URL contains the token loads resources from another site; the browser sends that URL as Referer.", "Eine Seite, deren URL das Token enthält, lädt Ressourcen einer anderen Site; der Browser sendet diese URL als Referer."))
                    .recommend(ctx.l("Set Referrer-Policy: no-referrer (or strict-origin) on pages that receive tokens, and remove the token from the URL at once.", "Auf Seiten, die Tokens erhalten, Referrer-Policy: no-referrer (oder strict-origin) setzen und das Token sofort aus der URL entfernen."))
                    .next_step(ctx.l("Treat the token as exposed: revoke it or let it expire, and check which third party received it.", "Das Token als offengelegt behandeln: widerrufen oder ablaufen lassen und prüfen, welcher Dritte es erhalten hat."));
            }
            if name == "refresh_token" {
                f = f.hypothesis(ctx.l("A refresh token in a URL is long-lived: whoever reads it can obtain new access tokens.", "Ein Refresh-Token in einer URL ist langlebig: Wer es liest, kann neue Zugriffstokens beziehen."));
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TOKEN-EXPIRED

/// TOKEN-EXPIRED: bearer tokens sent after their `exp`.
struct TokenExpired;

impl Analyzer for TokenExpired {
    fn id(&self) -> &'static str {
        "TOKEN-EXPIRED"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let expired = m.bearer.iter().copied().filter(|&i| claims(&ss[i]).and_then(|c| expired_by(&ss[i], c)).is_some_and(|d| d > LEEWAY_S) || m.explained(i, EXPLAINED_EXPIRED));
        let mut list = vec![];
        for ((host, client), v) in util::group_by(expired, |&i| (p.host_of(i).to_string(), claims(&ss[i]).and_then(|c| c.client.clone()).unwrap_or_else(|| "?".into()))) {
            let n = v.len();
            let by: Vec<f64> = v.iter().filter_map(|&i| claims(&ss[i]).and_then(|c| expired_by(&ss[i], c))).filter(|d| *d > LEEWAY_S).map(|d| d as f64).collect();
            let rejected = v.iter().filter(|&&i| ss[i].status == 401).count();
            let accepted: Vec<usize> = v.iter().copied().filter(|&i| (200..300).contains(&ss[i].status)).collect();
            let accepted_late: Vec<usize> = accepted.iter().copied().filter(|&i| claims(&ss[i]).and_then(|c| expired_by(&ss[i], c)).is_some_and(|d| d > ACCEPTED_EXPIRED_S)).collect();
            let said_by_api = v.iter().filter(|&&i| bearer_challenge(&ss[i]).and_then(|c| c.description).and_then(|d| idp::resource_cause(&d)) == Some(idp::ResourceCause::Expired)).count();
            let lifetimes: Vec<f64> = v.iter().filter_map(|&i| claims(&ss[i]).and_then(|c| Some(c.exp?.saturating_sub(c.iat?) as f64))).collect();
            let iss = top_list(ctx, v.iter().filter_map(|&i| claims(&ss[i]).and_then(|c| c.iss.clone())), 2);
            // By the server's clock (Date header) — is it this computer's clock instead?
            let offset = m.offsets.get(&host).copied();
            let server_valid = offset.is_some_and(|o| {
                v.iter().all(|&i| claims(&ss[i]).and_then(|c| c.exp).is_some_and(|e| start_s(&ss[i]) as f64 + o - e as f64 <= LEEWAY_S as f64))
            }) && !by.is_empty();
            let mut f = Finding::new(
                "TOKEN-EXPIRED",
                &format!("{host}|{client}"),
                Severity::Warning,
                tr(ctx, format!("Expired tokens sent to {}", util::short(&host, 60)), format!("Abgelaufene Tokens an {} gesendet", util::short(&host, 60))),
                if by.is_empty() {
                    tr(ctx, format!("{} request(s) to {host} were rejected because the token had expired (error_description of the API).", ctx.fmt_count(n)), format!("{} Request(s) an {host} wurden abgewiesen, weil das Token abgelaufen war (error_description der API).", ctx.fmt_count(n)))
                } else {
                    tr(
                        ctx,
                        format!("{} request(s) to {host} carried a token that had expired up to {} before (median {}); {} were rejected with 401.", ctx.fmt_count(n), secs(ctx, util::percentile(&by, 100.0) as i64), secs(ctx, util::percentile(&by, 50.0) as i64), ctx.fmt_count(rejected)),
                        format!("{} Request(s) an {host} trugen ein Token, das bis zu {} zuvor abgelaufen war (Median {}); {} wurden mit 401 abgewiesen.", ctx.fmt_count(n), secs(ctx, util::percentile(&by, 100.0) as i64), secs(ctx, util::percentile(&by, 50.0) as i64), ctx.fmt_count(rejected)),
                    )
                },
            )
            .categories(&["auth", "errors"])
            .tags(&["oauth"])
            .score(util::scale(n as f64, 0.0, 50.0) * 0.6 + 30.0)
            .threshold(tr(ctx, format!("exp more than {} before the request start", secs(ctx, LEEWAY_S)), format!("exp mehr als {} vor dem Request-Start", secs(ctx, LEEWAY_S))))
            .fact(ctx.l("Requests with an expired token", "Requests mit abgelaufenem Token"), ctx.fmt_count(n))
            .fact(ctx.l("Rejected with 401", "Mit 401 abgewiesen"), ctx.fmt_count(rejected))
            .fact(ctx.l("Accepted (2xx)", "Angenommen (2xx)"), ctx.fmt_count(accepted.len()))
            .impact(ctx.l(
                "Each expired token costs a failed request and a retry after refreshing — or, without retry logic, a failed user action.",
                "Jedes abgelaufene Token kostet einen fehlgeschlagenen Request und eine Wiederholung nach der Erneuerung – oder, ohne Wiederholungslogik, eine fehlgeschlagene Benutzeraktion.",
            ))
            .sessions(v.iter().map(|&i| ss[i].id));
            if client != "?" {
                f = f.fact(ctx.l("Client (azp/appid)", "Client (azp/appid)"), client.clone());
            }
            if !iss.is_empty() {
                f = f.fact(ctx.l("Issuer", "Aussteller"), iss);
            }
            if !lifetimes.is_empty() {
                f = f.fact(ctx.l("Token lifetime (exp − iat)", "Token-Laufzeit (exp − iat)"), secs(ctx, util::percentile(&lifetimes, 50.0) as i64));
            }
            if said_by_api > 0 {
                f = f.fact(ctx.l("API says “expired” (WWW-Authenticate)", "API meldet „abgelaufen“ (WWW-Authenticate)"), ctx.fmt_count(said_by_api));
            }
            if server_valid {
                f = f
                    .confidence(Confidence::Medium)
                    .hypothesis(ctx.l(
                        "By the server's clock (Date header) the tokens were still valid: this computer's clock is ahead, so the expiry seen here is an artefact (see CLOCK-LOCAL).",
                        "Nach der Uhr des Servers (Date-Header) waren die Tokens noch gültig: Die Uhr dieses Computers geht vor, die Abläufe hier sind ein Artefakt (siehe CLOCK-LOCAL).",
                    ));
            } else {
                f = f
                    .hypothesis(ctx.l(
                        "The client does not refresh the token before it expires: it caches it longer than expires_in, or reuses it until the API answers 401.",
                        "Der Client erneuert das Token nicht vor Ablauf: Er cacht es länger als expires_in oder verwendet es, bis die API mit 401 antwortet.",
                    ))
                    .hypothesis(ctx.l(
                        "Long-running or suspended processes (background tabs, sleeping devices, batch jobs) resume with an old token.",
                        "Lang laufende oder angehaltene Prozesse (Hintergrund-Tabs, Geräte im Ruhezustand, Batch-Jobs) setzen mit einem alten Token fort.",
                    ));
            }
            if let Some(h) = clock_hint(ctx, m, &[host.as_str()]).filter(|_| !server_valid) {
                f = f.hypothesis(h);
            }
            f = f
                .recommend(ctx.l(
                    "Refresh proactively a few minutes before exp (MSAL and most SDKs do this when the token comes from their cache), and on 401 refresh once and retry.",
                    "Proaktiv einige Minuten vor exp erneuern (MSAL und die meisten SDKs tun das, wenn das Token aus ihrem Cache kommt) und bei 401 einmal erneuern und wiederholen.",
                ))
                .next_step(ctx.l("Compare exp of the token with the request times (authentication facts of the sessions).", "exp des Tokens mit den Request-Zeiten vergleichen (Authentifizierungsfakten der Sessions)."));
            if let Some(w) = where_rec(ctx, claims(&ss[v[0]]).and_then(|c| c.iss.as_deref()).map(idp::from_issuer).unwrap_or(Idp::Generic), Topic::Lifetime) {
                f = f.recommend(w);
            }
            list.push(f);
            if !accepted_late.is_empty() {
                list.push(
                    Finding::new(
                        "TOKEN-EXPIRED",
                        &format!("accepted|{host}"),
                        Severity::Warning,
                        tr(ctx, format!("API accepts expired tokens: {}", util::short(&host, 60)), format!("API akzeptiert abgelaufene Tokens: {}", util::short(&host, 60))),
                        tr(
                            ctx,
                            format!("{} request(s) to {host} succeeded although the token had expired more than {} before.", ctx.fmt_count(accepted_late.len()), secs(ctx, ACCEPTED_EXPIRED_S)),
                            format!("{} Request(s) an {host} waren erfolgreich, obwohl das Token mehr als {} zuvor abgelaufen war.", ctx.fmt_count(accepted_late.len()), secs(ctx, ACCEPTED_EXPIRED_S)),
                        ),
                    )
                    .confidence(if offset.is_some() { Confidence::High } else { Confidence::Medium })
                    .categories(&["auth", "security"])
                    .tags(&["oauth"])
                    .score(70.0)
                    .threshold(tr(ctx, format!("2xx with exp more than {} in the past", secs(ctx, ACCEPTED_EXPIRED_S)), format!("2xx mit exp mehr als {} in der Vergangenheit", secs(ctx, ACCEPTED_EXPIRED_S))))
                    .impact(ctx.l("A stolen token stays usable after its expiry.", "Ein gestohlenes Token bleibt nach Ablauf verwendbar."))
                    .hypothesis(ctx.l(
                        "The API does not validate the token lifetime (ValidateLifetime off, a very large ClockSkew), or its clock is far behind.",
                        "Die API prüft die Laufzeit des Tokens nicht (ValidateLifetime aus, sehr großer ClockSkew), oder ihre Uhr geht weit nach.",
                    ))
                    .recommend(ctx.l("Validate exp/nbf with a small clock skew (≤ 5 minutes) in the API.", "In der API exp/nbf mit kleiner Toleranz (≤ 5 Minuten) prüfen."))
                    .sessions(accepted_late.iter().map(|&i| ss[i].id)),
                );
            }
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TOKEN-NOTYET

/// TOKEN-NOTYET: tokens valid only in the future (nbf/iat ahead of the request).
struct TokenNotYet;

impl Analyzer for TokenNotYet {
    fn id(&self) -> &'static str {
        "TOKEN-NOTYET"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        // (session, issuer, seconds ahead, from a token response?)
        let mut hits: Vec<(usize, String, Option<i64>, bool)> = vec![];
        for &i in &m.bearer {
            let s = &ss[i];
            let ahead = claims(s).and_then(|c| early_by(c, start_s(s))).filter(|d| *d > LEEWAY_S);
            if ahead.is_some() || m.explained(i, EXPLAINED_NOTYET) {
                hits.push((i, claims(s).and_then(|c| c.iss.clone()).unwrap_or_default(), ahead, false));
            }
        }
        for &i in &m.tokens {
            let s = &ss[i];
            let Some(r) = s.auth.as_ref().and_then(|a| a.oauth_response.as_ref()) else { continue };
            let got = (s.end() / 1_000_000) as i64;
            for c in r.access_token.iter().chain(r.id_token.iter()) {
                if let Some(d) = early_by(c, got).filter(|d| *d > LEEWAY_S) {
                    hits.push((i, c.iss.clone().unwrap_or_default(), Some(d), true));
                    break;
                }
            }
        }
        let mut list = vec![];
        for (iss, v) in util::group_by(hits, |h| h.1.clone()) {
            let ahead: Vec<f64> = v.iter().filter_map(|h| h.2).map(|d| d as f64).collect();
            let max = util::percentile(&ahead, 100.0) as i64;
            let n = v.len();
            let rejected = v.iter().filter(|h| ss[h.0].status == 401).count();
            let from_response = v.iter().filter(|h| h.3).count();
            let iss_host = url_host(&iss);
            let api_hosts: BTreeSet<String> = v.iter().filter(|h| !h.3).map(|h| p.host_of(h.0).to_string()).collect();
            let severity = if max >= NOTYET_CRIT_S { Severity::Critical } else { Severity::Warning };
            let shown = if iss.is_empty() { ctx.l("(unknown issuer)", "(unbekannter Aussteller)").to_string() } else { iss.clone() };
            let mut f = Finding::new(
                "TOKEN-NOTYET",
                &iss,
                severity,
                tr(ctx, format!("Tokens not yet valid: {}", util::short(&shown, 70)), format!("Tokens noch nicht gültig: {}", util::short(&shown, 70))),
                if ahead.is_empty() {
                    tr(ctx, format!("{} request(s) were rejected because the token is not yet valid (error_description of the API).", ctx.fmt_count(n)), format!("{} Request(s) wurden abgewiesen, weil das Token noch nicht gültig ist (error_description der API).", ctx.fmt_count(n)))
                } else {
                    tr(
                        ctx,
                        format!("{} token(s) of {shown} carry nbf/iat up to {} after the time this computer saw them.", ctx.fmt_count(n), secs(ctx, max)),
                        format!("{} Token(s) von {shown} tragen nbf/iat bis zu {} nach der Zeit, zu der dieser Computer sie sah.", ctx.fmt_count(n), secs(ctx, max)),
                    )
                },
            )
            .categories(&["auth", "clock"])
            .tags(&["oauth", "clock"])
            .score(util::scale(max as f64, LEEWAY_S as f64, NOTYET_CRIT_S as f64 * 2.0) * 0.7 + util::scale(n as f64, 0.0, 30.0) * 0.3)
            .threshold(tr(
                ctx,
                format!("nbf/iat more than {} ahead; critical from {}", secs(ctx, LEEWAY_S), secs(ctx, NOTYET_CRIT_S)),
                format!("nbf/iat mehr als {} voraus; kritisch ab {}", secs(ctx, LEEWAY_S), secs(ctx, NOTYET_CRIT_S)),
            ))
            .fact(ctx.l("Tokens", "Tokens"), ctx.fmt_count(n))
            .fact(ctx.l("Seen in token responses", "In Token-Antworten gesehen"), ctx.fmt_count(from_response))
            .fact(ctx.l("Rejected with 401", "Mit 401 abgewiesen"), ctx.fmt_count(rejected))
            .impact(ctx.l(
                "APIs and client libraries reject tokens “not yet valid” (IDX10222 and the like) beyond their small tolerance — sign-in or API calls fail until the clocks agree.",
                "APIs und Client-Bibliotheken weisen Tokens jenseits ihrer kleinen Toleranz als „noch nicht gültig“ ab (IDX10222 u. ä.) – Anmeldung oder API-Aufrufe scheitern, bis die Uhren übereinstimmen.",
            ))
            .hypothesis(ctx.l(
                "The identity provider's clock is ahead of the client's/API's clock (or this computer's clock is behind).",
                "Die Uhr des Identity Providers geht gegenüber Client bzw. API vor (oder die Uhr dieses Computers geht nach).",
            ))
            .recommend(ctx.l("Synchronise the clocks of IdP, API hosts and clients (NTP).", "Die Uhren von IdP, API-Hosts und Clients synchronisieren (NTP)."))
            .sessions(v.iter().map(|h| ss[h.0].id));
            if !api_hosts.is_empty() {
                f = f.fact(ctx.l("APIs called with them", "Damit aufgerufene APIs"), api_hosts.iter().take(4).cloned().collect::<Vec<_>>().join(", "));
            }
            let mut hosts: Vec<&str> = vec![iss_host.as_str()];
            hosts.extend(api_hosts.iter().map(String::as_str));
            if let Some(h) = clock_hint(ctx, m, &hosts) {
                f = f.hypothesis(h);
            } else {
                f = f.next_step(ctx.l("Compare with CLOCK-* findings of this report; without Date headers of the IdP the clock offset cannot be measured here.", "Mit den CLOCK-*-Befunden dieses Berichts vergleichen; ohne Date-Header des IdP lässt sich die Abweichung hier nicht messen."));
            }
            if ahead.is_empty() {
                f = f.confidence(Confidence::Medium);
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TOKEN-AUDIENCE

/// TOKEN-AUDIENCE: 401 with a token for another audience or issuer version.
struct TokenAudience;

impl Analyzer for TokenAudience {
    fn id(&self) -> &'static str {
        "TOKEN-AUDIENCE"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let failing = m.bearer.iter().copied().filter(|&i| m.explained(i, EXPLAINED_AUDIENCE));
        let mut list = vec![];
        for (host, v) in util::group_by(failing, |&i| p.host_of(i).to_string()) {
            let n = v.len();
            let ok: Vec<usize> = m.bearer.iter().copied().filter(|&i| p.host_of(i) == host && (200..400).contains(&ss[i].status) && claims(&ss[i]).is_some()).collect();
            let descs: Vec<String> = v.iter().filter_map(|&i| bearer_challenge(&ss[i]).and_then(|c| c.description)).collect();
            let by_api = descs.iter().filter_map(|d| idp::resource_cause(d)).collect::<BTreeSet<_>>();
            let bad: Vec<&JwtClaims> = v.iter().filter_map(|&i| claims(&ss[i])).collect();
            let good: Vec<&JwtClaims> = ok.iter().filter_map(|&i| claims(&ss[i])).collect();
            let auds = top_list(ctx, bad.iter().flat_map(|c| c.aud.iter().cloned()), 3);
            let graph = bad.iter().any(|c| c.aud.iter().any(|a| idp::ms_resource_host(a) == Some("graph.microsoft.com"))) && !host.ends_with("graph.microsoft.com");
            let v1 = |c: &&JwtClaims| entra_v1(c) == Some(true);
            let bad_v1 = bad.iter().any(v1);
            let good_v1 = good.iter().any(v1);
            let version_mismatch = !good.is_empty() && bad.iter().all(v1) != good.iter().all(v1);
            let the_idp = bad.iter().filter_map(|c| c.iss.as_deref()).map(idp::from_issuer).next().unwrap_or(Idp::Generic);
            let mut rows: Vec<(String, &JwtClaims, i64)> = v.iter().filter_map(|&i| claims(&ss[i]).map(|c| (ss[i].status.to_string(), c, start_s(&ss[i])))).collect();
            rows.extend(ok.iter().take(20).filter_map(|&i| claims(&ss[i]).map(|c| (ss[i].status.to_string(), c, start_s(&ss[i])))));
            let (cols, table) = claims_table(ctx, &rows);
            let mut f = Finding::new(
                "TOKEN-AUDIENCE",
                &host,
                Severity::Warning,
                tr(ctx, format!("Token not meant for this API: {}", util::short(&host, 60)), format!("Token nicht für diese API bestimmt: {}", util::short(&host, 60))),
                tr(
                    ctx,
                    format!("{} request(s) to {host} were rejected with 401; their token names the audience {}.", ctx.fmt_count(n), if auds.is_empty() { "?".into() } else { auds.clone() }),
                    format!("{} Request(s) an {host} wurden mit 401 abgewiesen; ihr Token nennt die Audience {}.", ctx.fmt_count(n), if auds.is_empty() { "?".into() } else { auds.clone() }),
                ),
            )
            .confidence(if by_api.iter().any(|c| matches!(c, idp::ResourceCause::Audience | idp::ResourceCause::Issuer)) || graph { Confidence::High } else { Confidence::Medium })
            .categories(&["auth", "errors"])
            .tags(&["oauth"])
            .score(util::scale(n as f64, 0.0, 30.0) * 0.5 + 40.0)
            .threshold(ctx.l("401 with a token whose aud/iss does not match the API", "401 mit einem Token, dessen aud/iss nicht zur API passt"))
            .fact(ctx.l("Rejected requests", "Abgewiesene Requests"), ctx.fmt_count(n))
            .fact(ctx.l("Successful requests with a token", "Erfolgreiche Requests mit Token"), ctx.fmt_count(ok.len()))
            .table(cols, table)
            .impact(ctx.l("Every call with this token fails; refreshing does not help because a new token has the same audience.", "Jeder Aufruf mit diesem Token scheitert; Erneuern hilft nicht, weil ein neues Token dieselbe Audience hat."))
            .sessions(v.iter().map(|&i| ss[i].id));
            if !descs.is_empty() {
                f = f.fact("error_description", top_list(ctx, descs.iter().cloned(), 2));
            }
            if graph {
                f = f.hypothesis(ctx.l(
                    "The token is for Microsoft Graph (aud graph.microsoft.com / 00000003-…): the client requested Graph scopes such as User.Read and sends that token to its own API.",
                    "Das Token ist für Microsoft Graph (aud graph.microsoft.com / 00000003-…): Der Client hat Graph-Scopes wie User.Read angefordert und sendet dieses Token an die eigene API.",
                ));
            }
            if version_mismatch || (bad_v1 && good.is_empty() && the_idp.is_entra()) {
                f = f.hypothesis(if bad_v1 && !good_v1 {
                    ctx.l(
                        "The rejected tokens are Entra ID v1 tokens (iss https://sts.windows.net/<tid>/) while the API validates v2 (iss …/<tid>/v2.0), or the reverse: the API's manifest decides the version (accessTokenAcceptedVersion).",
                        "Die abgewiesenen Tokens sind Entra-ID-v1-Tokens (iss https://sts.windows.net/<tid>/), die API prüft aber v2 (iss …/<tid>/v2.0), oder umgekehrt: Das Manifest der API bestimmt die Version (accessTokenAcceptedVersion).",
                    )
                } else {
                    ctx.l(
                        "Accepted and rejected tokens differ in the Entra ID token version (v1 sts.windows.net vs. v2 …/v2.0): the API accepts only one issuer.",
                        "Angenommene und abgewiesene Tokens unterscheiden sich in der Entra-ID-Token-Version (v1 sts.windows.net vs. v2 …/v2.0): Die API akzeptiert nur einen Aussteller.",
                    )
                });
            }
            if !good.is_empty() {
                let ok_auds = top_list(ctx, good.iter().flat_map(|c| c.aud.iter().cloned()), 3);
                f = f.fact(ctx.l("Audience of accepted tokens", "Audience angenommener Tokens"), ok_auds);
            }
            if by_api.contains(&idp::ResourceCause::Issuer) {
                f = f.hypothesis(ctx.l("The API names the issuer as invalid: wrong tenant/realm/authority configured in the API, or tokens from another IdP.", "Die API nennt den Aussteller ungültig: falscher Mandant/Realm/Authority in der API konfiguriert oder Tokens eines anderen IdP."));
            }
            f = f
                .hypothesis(ctx.l(
                    "This is a hypothesis from the claims: the audience the API expects is configured in the API, which the capture cannot see.",
                    "Das ist eine Hypothese aus den Claims: Welche Audience die API erwartet, ist in der API konfiguriert und in der Aufzeichnung nicht sichtbar.",
                ))
                .recommend(ctx.l(
                    "Request the token for this API (its scope / audience / resource), and configure the API to validate exactly that audience and issuer.",
                    "Das Token für diese API anfordern (deren Scope / Audience / Resource) und die API so konfigurieren, dass sie genau diese Audience und diesen Aussteller prüft.",
                ));
            if let Some(w) = where_rec(ctx, the_idp, Topic::Audience) {
                f = f.recommend(w);
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TOKEN-SCOPE

/// TOKEN-SCOPE: 403 / insufficient_scope: the required scope against the token's.
struct TokenScope;

impl Analyzer for TokenScope {
    fn id(&self) -> &'static str {
        "TOKEN-SCOPE"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let hits = m.bearer.iter().copied().filter(|&i| m.explained(i, EXPLAINED_SCOPE));
        let mut list = vec![];
        for (ep, v) in util::group_by(hits, |&i| p.endpoint_of(i).to_string()) {
            let n = v.len();
            let chs: Vec<Challenge> = v.iter().filter_map(|&i| bearer_challenge(&ss[i])).collect();
            let insufficient = chs.iter().filter(|c| c.error.as_deref() == Some("insufficient_scope")).count();
            let required: BTreeSet<String> = chs.iter().filter_map(|c| c.scope.clone()).flat_map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>()).collect();
            let cl: Vec<&JwtClaims> = v.iter().filter_map(|&i| claims(&ss[i])).collect();
            let have: BTreeSet<String> = cl.iter().flat_map(|c| c.scopes.iter().chain(c.roles.iter()).cloned()).collect();
            let scp = top_list(ctx, cl.iter().flat_map(|c| c.scopes.iter().cloned()), 8);
            let roles = top_list(ctx, cl.iter().flat_map(|c| c.roles.iter().cloned()), 8);
            // The short name of a scope URI (api://x/Orders.Read → Orders.Read).
            let short_name = |s: &str| s.rsplit('/').next().unwrap_or(s).to_string();
            let have_short: BTreeSet<String> = have.iter().map(|s| short_name(s)).collect();
            let missing: Vec<String> = required.iter().filter(|r| !have.contains(*r) && !have_short.contains(&short_name(r))).cloned().collect();
            let app_only = !cl.is_empty() && cl.iter().all(|c| c.scopes.is_empty() && !c.roles.is_empty());
            let delegated = !cl.is_empty() && cl.iter().all(|c| !c.scopes.is_empty());
            let conf = if !required.is_empty() && !cl.is_empty() {
                Confidence::High
            } else if insufficient > 0 {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let the_idp = cl.iter().filter_map(|c| c.iss.as_deref()).map(idp::from_issuer).next().unwrap_or(Idp::Generic);
            let mut f = Finding::new(
                "TOKEN-SCOPE",
                &ep,
                Severity::Warning,
                tr(ctx, format!("Token lacks permission: {}", util::short(&ep, 70)), format!("Token fehlt die Berechtigung: {}", util::short(&ep, 70))),
                if required.is_empty() {
                    tr(ctx, format!("{} request(s) to {ep} were refused (403 / insufficient_scope) although they carried a token.", ctx.fmt_count(n)), format!("{} Request(s) an {ep} wurden verweigert (403 / insufficient_scope), obwohl sie ein Token trugen.", ctx.fmt_count(n)))
                } else {
                    tr(
                        ctx,
                        format!("{} request(s) to {ep} were refused; the API requires the scope {}.", ctx.fmt_count(n), required.iter().cloned().collect::<Vec<_>>().join(" ")),
                        format!("{} Request(s) an {ep} wurden verweigert; die API verlangt den Scope {}.", ctx.fmt_count(n), required.iter().cloned().collect::<Vec<_>>().join(" ")),
                    )
                },
            )
            .confidence(conf)
            .categories(&["auth", "errors"])
            .tags(&["oauth"])
            .score(util::scale(n as f64, 0.0, 30.0) * 0.5 + if conf == Confidence::High { 40.0 } else { 20.0 })
            .threshold(ctx.l("403 with a token, or WWW-Authenticate error=insufficient_scope", "403 mit Token oder WWW-Authenticate error=insufficient_scope"))
            .fact(ctx.l("Refused requests", "Verweigerte Requests"), ctx.fmt_count(n))
            .fact(ctx.l("insufficient_scope", "insufficient_scope"), ctx.fmt_count(insufficient))
            .impact(ctx.l("The action fails although the user (or service) is signed in.", "Die Aktion scheitert, obwohl Benutzer (oder Dienst) angemeldet sind."))
            .sessions(v.iter().map(|&i| ss[i].id));
            if !required.is_empty() {
                f = f.fact(ctx.l("Required scope (WWW-Authenticate)", "Verlangter Scope (WWW-Authenticate)"), required.iter().cloned().collect::<Vec<_>>().join(" "));
            }
            if !scp.is_empty() {
                f = f.fact(ctx.l("Token scopes (scp)", "Scopes des Tokens (scp)"), scp);
            }
            if !roles.is_empty() {
                f = f.fact(ctx.l("Token roles", "Rollen des Tokens"), roles);
            }
            if !missing.is_empty() && !cl.is_empty() {
                f = f.fact(ctx.l("Missing in the token", "Fehlt im Token"), missing.join(" ")).hypothesis(ctx.l(
                    "The token does not contain the required scope/role: it was not requested, not consented, or not assigned.",
                    "Das Token enthält den verlangten Scope bzw. die Rolle nicht: nicht angefordert, nicht zugestimmt oder nicht zugewiesen.",
                ));
            }
            if app_only {
                f = f.hypothesis(ctx.l(
                    "The token is app-only (roles, no scp — client credentials): the API needs an application permission (app role) granted to the client, not a delegated scope.",
                    "Das Token ist app-only (roles, kein scp – Client Credentials): Die API braucht eine Anwendungsberechtigung (App-Rolle) für den Client, keinen delegierten Scope.",
                ));
            } else if delegated && cl.iter().all(|c| c.roles.is_empty()) {
                f = f.hypothesis(ctx.l(
                    "The token is delegated (scp) without roles: if the API checks app roles of the user, assign the user/group to the role.",
                    "Das Token ist delegiert (scp) ohne Rollen: Prüft die API App-Rollen des Benutzers, den Benutzer bzw. die Gruppe der Rolle zuweisen.",
                ));
            }
            if conf == Confidence::Low {
                f = f.hypothesis(ctx.l(
                    "403 can also come from the application's own authorisation (object permissions, tenant, WAF); only error=insufficient_scope proves a scope problem.",
                    "403 kann auch aus der eigenen Autorisierung der Anwendung kommen (Objektrechte, Mandant, WAF); nur error=insufficient_scope belegt ein Scope-Problem.",
                ));
            }
            f = f.recommend(ctx.l("Request the required scope (and grant consent), or assign the app role; then get a new token.", "Den verlangten Scope anfordern (und zustimmen) oder die App-Rolle zuweisen; danach ein neues Token beziehen."));
            if let Some(w) = where_rec(ctx, the_idp, Topic::Consent) {
                f = f.recommend(w);
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TOKEN-SIZE

/// TOKEN-SIZE: large bearer tokens and authentication cookies (header limits).
struct TokenSize;

impl Analyzer for TokenSize {
    fn id(&self) -> &'static str {
        "TOKEN-SIZE"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let limits = ctx.l(
            "Common limits: nginx 8 KiB per header line (large_client_header_buffers), Apache 8 KiB (LimitRequestFieldSize), IIS/http.sys 16 KiB (MaxFieldLength), Kestrel 32 KiB for all headers, many load balancers and WAFs 8–16 KiB.",
            "Übliche Grenzen: nginx 8 KiB pro Headerzeile (large_client_header_buffers), Apache 8 KiB (LimitRequestFieldSize), IIS/http.sys 16 KiB (MaxFieldLength), Kestrel 32 KiB für alle Header, viele Load Balancer und WAFs 8–16 KiB.",
        );
        let mut list = vec![];
        let big = m.bearer.iter().copied().filter(|&i| bearer_bytes(&ss[i]).is_some_and(|b| b >= TOKEN_WARN_BYTES));
        for (host, v) in util::group_by(big, |&i| p.host_of(i).to_string()) {
            let sizes: Vec<f64> = v.iter().filter_map(|&i| bearer_bytes(&ss[i])).map(|b| b as f64).collect();
            let max = util::percentile(&sizes, 100.0);
            let rejected: Vec<usize> = v.iter().copied().filter(|&i| matches!(ss[i].status, 400 | 431)).collect();
            let cl: Vec<&JwtClaims> = v.iter().filter_map(|&i| claims(&ss[i])).collect();
            let groups = cl.iter().filter_map(|c| c.groups).max();
            let roles = cl.iter().map(|c| c.roles.len()).max().unwrap_or(0);
            let overage = cl.iter().any(|c| c.groups_overage);
            let the_idp = cl.iter().filter_map(|c| c.iss.as_deref()).map(idp::from_issuer).next().unwrap_or(Idp::Generic);
            let severity = if !rejected.is_empty() || max >= TOKEN_CRIT_BYTES as f64 { Severity::Critical } else { Severity::Warning };
            let mut f = Finding::new(
                "TOKEN-SIZE",
                &format!("bearer|{host}"),
                severity,
                tr(ctx, format!("Very large bearer tokens: {}", util::short(&host, 60)), format!("Sehr große Bearer-Tokens: {}", util::short(&host, 60))),
                tr(
                    ctx,
                    format!("{} request(s) to {host} carried a bearer token of up to {} (median {}).", ctx.fmt_count(v.len()), ctx.fmt_bytes(max), ctx.fmt_bytes(util::percentile(&sizes, 50.0))),
                    format!("{} Request(s) an {host} trugen ein Bearer-Token von bis zu {} (Median {}).", ctx.fmt_count(v.len()), ctx.fmt_bytes(max), ctx.fmt_bytes(util::percentile(&sizes, 50.0))),
                ),
            )
            .categories(&["auth", "performance"])
            .tags(&["oauth"])
            .score(util::scale(max, TOKEN_WARN_BYTES as f64, 4.0 * TOKEN_CRIT_BYTES as f64))
            .threshold(tr(
                ctx,
                format!("≥ {} (critical from {} or on 400/431)", ctx.fmt_bytes(TOKEN_WARN_BYTES as f64), ctx.fmt_bytes(TOKEN_CRIT_BYTES as f64)),
                format!("≥ {} (kritisch ab {} oder bei 400/431)", ctx.fmt_bytes(TOKEN_WARN_BYTES as f64), ctx.fmt_bytes(TOKEN_CRIT_BYTES as f64)),
            ))
            .fact(ctx.l("Largest token", "Größtes Token"), ctx.fmt_bytes(max))
            .fact(ctx.l("Rejected with 400/431", "Mit 400/431 abgewiesen"), ctx.fmt_count(rejected.len()))
            .impact(limits)
            .sessions(v.iter().map(|&i| ss[i].id));
            if let Some(g) = groups {
                f = f.fact(ctx.l("Groups in the token", "Gruppen im Token"), ctx.fmt_count(g as usize));
            }
            if roles > 0 {
                f = f.fact(ctx.l("Roles in the token", "Rollen im Token"), ctx.fmt_count(roles));
            }
            if overage {
                f = f.fact(ctx.l("Groups overage claim", "Groups-Overage-Claim"), ctx.l("yes", "ja"));
            }
            if groups.is_some_and(|g| g >= 20) || roles >= 50 {
                f = f.hypothesis(ctx.l("Group or role claims inflate the token: every membership travels with every request.", "Gruppen- oder Rollen-Claims blähen das Token auf: Jede Mitgliedschaft reist mit jedem Request."));
            } else {
                f = f.hypothesis(ctx.l("Many claims (groups, roles, custom claims) or an embedded certificate chain make the token large.", "Viele Claims (Gruppen, Rollen, eigene Claims) oder eine eingebettete Zertifikatskette machen das Token groß."));
            }
            f = f.recommend(ctx.l(
                "Emit only the claims the API needs (groups assigned to the application, app roles instead of all groups) or look memberships up on the server.",
                "Nur die Claims ausstellen, die die API braucht (der Anwendung zugewiesene Gruppen, App-Rollen statt aller Gruppen), oder Mitgliedschaften serverseitig nachschlagen.",
            ));
            if let Some(w) = where_rec(ctx, the_idp, Topic::Groups) {
                f = f.recommend(w);
            }
            list.push(f);
        }
        for c in &m.cookies {
            let severity = if !c.rejected.is_empty() { Severity::Critical } else { Severity::Warning };
            let set_total = c.set_total();
            let host = &c.host;
            let mut f = Finding::new(
                "TOKEN-SIZE",
                &format!("cookie|{host}"),
                severity,
                tr(ctx, format!("Large authentication cookies: {}", util::short(host, 60)), format!("Große Anmelde-Cookies: {}", util::short(host, 60))),
                tr(
                    ctx,
                    format!(
                        "Requests to {host} carry up to {} chunks of {}, up to {} nonce/correlation cookies; the authentication cookies set by the host total {}.",
                        ctx.fmt_count(c.chunks),
                        if c.chunk_name.is_empty() { "-" } else { c.chunk_name.as_str() },
                        ctx.fmt_count(c.nonces),
                        ctx.fmt_bytes(set_total as f64)
                    ),
                    format!(
                        "Requests an {host} tragen bis zu {} Teile von {} und bis zu {} Nonce-/Correlation-Cookies; die vom Host gesetzten Anmelde-Cookies umfassen zusammen {}.",
                        ctx.fmt_count(c.chunks),
                        if c.chunk_name.is_empty() { "-" } else { c.chunk_name.as_str() },
                        ctx.fmt_count(c.nonces),
                        ctx.fmt_bytes(set_total as f64)
                    ),
                ),
            )
            .categories(&["auth", "cookies", "performance"])
            .tags(&["oauth"])
            .score(util::scale(set_total as f64, AUTH_COOKIE_BYTES_WARN as f64, 64_000.0).max(util::scale(c.chunks as f64, COOKIE_CHUNKS_MIN as f64, 10.0)).max(util::scale(c.nonces as f64, NONCE_COOKIES_MIN as f64, 30.0)))
            .threshold(tr(
                ctx,
                format!("≥ {COOKIE_CHUNKS_MIN} chunks, ≥ {NONCE_COOKIES_MIN} nonce cookies or ≥ {} of authentication cookies", ctx.fmt_bytes(AUTH_COOKIE_BYTES_WARN as f64)),
                format!("≥ {COOKIE_CHUNKS_MIN} Teile, ≥ {NONCE_COOKIES_MIN} Nonce-Cookies oder ≥ {} Anmelde-Cookies", ctx.fmt_bytes(AUTH_COOKIE_BYTES_WARN as f64)),
            ))
            .fact(ctx.l("Chunks of one cookie (max.)", "Teile eines Cookies (max.)"), ctx.fmt_count(c.chunks))
            .fact(ctx.l("Nonce/correlation cookies (max.)", "Nonce-/Correlation-Cookies (max.)"), ctx.fmt_count(c.nonces))
            .fact(ctx.l("Authentication cookies set", "Gesetzte Anmelde-Cookies"), ctx.fmt_bytes(set_total as f64))
            .fact(ctx.l("Rejected with 400/431", "Mit 400/431 abgewiesen"), ctx.fmt_count(c.rejected.len()))
            .impact(limits)
            .sessions(c.sessions.iter().chain(c.rejected.iter()).map(|&i| ss[i].id));
            if c.chunks >= COOKIE_CHUNKS_MIN || set_total >= AUTH_COOKIE_BYTES_WARN {
                f = f.hypothesis(ctx.l(
                    "The authentication cookie stores the whole identity (all claims, often the tokens too: SaveTokens) and is split into chunks of ~4 KB.",
                    "Das Anmelde-Cookie speichert die ganze Identität (alle Claims, oft auch die Tokens: SaveTokens) und wird in Teile zu ~4 KB zerlegt.",
                ))
                .recommend(ctx.l(
                    "Keep the session on the server (ITicketStore / distributed session store), do not save tokens in the cookie, and drop unneeded claims.",
                    "Die Sitzung auf dem Server halten (ITicketStore / verteilter Sitzungsspeicher), keine Tokens im Cookie speichern und unnötige Claims entfernen.",
                ));
            }
            if c.nonces >= NONCE_COOKIES_MIN {
                f = f
                    .hypothesis(ctx.l(
                        "OpenID Connect nonce/correlation cookies pile up: every sign-in that does not complete (loop, aborted, several tabs) leaves one behind until the header gets too large.",
                        "OpenID-Connect-Nonce-/Correlation-Cookies häufen sich: Jede nicht abgeschlossene Anmeldung (Schleife, Abbruch, mehrere Tabs) hinterlässt eines, bis der Header zu groß wird.",
                    ))
                    .recommend(ctx.l("Fix the incomplete sign-ins (see OIDC-LOOP) and give the nonce cookies a short lifetime.", "Die unvollständigen Anmeldungen beheben (siehe OIDC-LOOP) und den Nonce-Cookies eine kurze Laufzeit geben."));
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TOKEN-REFRESH

/// TOKEN-REFRESH: tokens requested more often than their lifetime requires.
struct TokenRefresh;

impl Analyzer for TokenRefresh {
    fn id(&self) -> &'static str {
        "TOKEN-REFRESH"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["auth", "troubleshooting", "performance"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let req = |i: usize| ss[i].auth.as_ref().and_then(|a| a.oauth_request.as_ref());
        let resp = |i: usize| ss[i].auth.as_ref().and_then(|a| a.oauth_response.as_ref());
        // Device flow polling is by design; failed requests are OAUTH-ERROR's (retries of a
        // failing grant are not a caching problem).
        let token_reqs = m.tokens.iter().copied().filter(|&i| {
            idp::endpoint(raw_path(&ss[i].url)) != Endpoint::Device
                && req(i).and_then(|r| r.grant_type.as_deref()).map(grant_flow) != Some(Flow::DeviceCode)
                && ss[i].status < 400
                && !ss[i].failed()
                && resp(i).is_none_or(|r| r.error.is_none())
        });
        // API calls per token client (for "a token per call").
        let mut calls: HashMap<&str, usize> = HashMap::new();
        for &i in &m.bearer {
            if let Some(c) = claims(&ss[i]).and_then(|c| c.client.as_deref()) {
                *calls.entry(c).or_default() += 1;
            }
        }
        let mut list = vec![];
        for ((host, client), v) in util::group_by(token_reqs, |&i| (p.host_of(i).to_string(), req(i).and_then(|r| r.client_id.clone()).unwrap_or_else(|| "?".into()))) {
            let n = v.len();
            let times: Vec<u64> = v.iter().map(|&i| ss[i].started).collect();
            // Early: a successful token for the same grant and scope while the previous one
            // was still valid for more than half of its lifetime.
            let mut early: Vec<usize> = vec![];
            let mut lifetimes = vec![];
            for (_, w) in util::group_by(v.iter().copied(), |&i| {
                let r = req(i);
                let g = r.and_then(|r| r.grant_type.clone()).unwrap_or_default();
                let g = if matches!(g.as_str(), "refresh_token" | "authorization_code") { "user".to_string() } else { g };
                (g, r.and_then(|r| r.scope.clone()).unwrap_or_default())
            }) {
                let mut prev: Option<(u64, u32)> = None;
                for i in w {
                    let ok = (200..300).contains(&ss[i].status);
                    let exp = resp(i).and_then(|r| r.expires_in).filter(|_| ok);
                    if let (Some((t, e)), true) = (prev, ok)
                        && ((ss[i].started.saturating_sub(t)) as f64) < e as f64 * 1e6 * REFRESH_EARLY_SHARE
                    {
                        early.push(i);
                    }
                    if let Some(e) = exp {
                        lifetimes.push(e as f64);
                        prev = Some((ss[i].started, e));
                    }
                }
            }
            let known_lifetime = !lifetimes.is_empty();
            let api_calls = calls.get(client.as_str()).copied().unwrap_or(0);
            let per_call = client != "?" && n >= REFRESH_PER_CALL_MIN && api_calls > 0 && n as f64 >= api_calls as f64 * REFRESH_PER_CALL_SHARE;
            let peak = util::max_in_window(&times, REFRESH_WINDOW_US);
            let hashes: Vec<u64> = v.iter().filter_map(|&i| ss[i].request_body_hash).collect();
            let identical = {
                let mut c: HashMap<u64, usize> = HashMap::new();
                for h in &hashes {
                    *c.entry(*h).or_default() += 1;
                }
                c.values().copied().max().unwrap_or(0)
            };
            let fallback = !known_lifetime && peak >= REFRESH_WINDOW_MIN;
            if early.len() < REFRESH_EARLY_MIN && !per_call && !fallback {
                continue;
            }
            let severity = if early.len() >= REFRESH_EARLY_MIN || per_call || (fallback && (identical >= REFRESH_WINDOW_MIN || hashes.is_empty())) { Severity::Warning } else { Severity::Info };
            let the_idp = m.idp_of(&host);
            let span_ms = (times.last().unwrap_or(&0) - times.first().unwrap_or(&0)) as f64 / 1000.0;
            let mut f = Finding::new(
                "TOKEN-REFRESH",
                &format!("{host}|{client}"),
                severity,
                tr(ctx, format!("Tokens requested too often: {client} ({})", util::short(&host, 50)), format!("Tokens zu oft angefordert: {client} ({})", util::short(&host, 50))),
                tr(
                    ctx,
                    format!("{} token request(s) of client {client} to {host} ({}) within {}, up to {} within 5 minutes.", ctx.fmt_count(n), the_idp.name(), ctx.fmt_ms(span_ms), ctx.fmt_count(peak)),
                    format!("{} Token-Anforderung(en) von Client {client} an {host} ({}) innerhalb von {}, bis zu {} innerhalb von 5 Minuten.", ctx.fmt_count(n), the_idp.name(), ctx.fmt_ms(span_ms), ctx.fmt_count(peak)),
                ),
            )
            .categories(&["auth", "performance"])
            .tags(&["oauth"])
            .score(util::scale(early.len().max(peak) as f64, REFRESH_EARLY_MIN as f64, 100.0))
            .threshold(tr(
                ctx,
                format!("≥ {REFRESH_EARLY_MIN} tokens before {} of expires_in, token requests ≥ {} of the API calls, or (without expires_in) ≥ {REFRESH_WINDOW_MIN} in 5 min", ctx.fmt_pct(REFRESH_EARLY_SHARE), ctx.fmt_pct(REFRESH_PER_CALL_SHARE)),
                format!("≥ {REFRESH_EARLY_MIN} Tokens vor {} von expires_in, Token-Anforderungen ≥ {} der API-Aufrufe oder (ohne expires_in) ≥ {REFRESH_WINDOW_MIN} in 5 min", ctx.fmt_pct(REFRESH_EARLY_SHARE), ctx.fmt_pct(REFRESH_PER_CALL_SHARE)),
            ))
            .fact(ctx.l("Token requests", "Token-Anforderungen"), ctx.fmt_count(n))
            .fact(ctx.l("Most within 5 minutes", "Höchstens innerhalb von 5 Minuten"), ctx.fmt_count(peak))
            .fact("grant_type", top_list(ctx, v.iter().filter_map(|&i| req(i).and_then(|r| r.grant_type.clone())), 4))
            .impact(ctx.l(
                "Every token request adds latency (often several round trips to the identity provider), load there, and can hit its throttling limits (e.g. Entra ID AADSTS50196 loop detection).",
                "Jede Token-Anforderung kostet Latenz (oft mehrere Roundtrips zum Identity Provider), erzeugt dort Last und kann dessen Drosselung auslösen (z. B. Entra-ID-Schleifenerkennung AADSTS50196).",
            ))
            .recommend(ctx.l(
                "Cache the token per client, resource and scope until shortly before it expires (expires_in) and share the cache between components and instances (one confidential client application instance, a distributed token cache).",
                "Das Token pro Client, Ressource und Scope bis kurz vor Ablauf (expires_in) cachen und den Cache zwischen Komponenten und Instanzen teilen (eine Instanz der Client-Anwendung, verteilter Token-Cache).",
            ))
            .sessions(v.iter().map(|&i| ss[i].id));
            if known_lifetime {
                f = f.fact(ctx.l("Token lifetime (expires_in, median)", "Token-Laufzeit (expires_in, Median)"), secs(ctx, util::percentile(&lifetimes, 50.0) as i64)).fact(
                    tr(ctx, format!("New tokens before {} of the lifetime", ctx.fmt_pct(REFRESH_EARLY_SHARE)), format!("Neue Tokens vor {} der Laufzeit", ctx.fmt_pct(REFRESH_EARLY_SHARE))),
                    ctx.fmt_count(early.len()),
                );
                if early.len() >= REFRESH_EARLY_MIN {
                    f = f.hypothesis(ctx.l(
                        "The previous token was still valid: the client does not cache it (a new client/cache instance per call, cache keyed per request, or the cache is bypassed with force refresh).",
                        "Das vorige Token war noch gültig: Der Client cacht es nicht (neue Client-/Cache-Instanz pro Aufruf, Cache-Schlüssel pro Request oder Umgehung des Caches durch erzwungene Erneuerung).",
                    ));
                }
            } else {
                f = f.confidence(Confidence::Medium);
                if identical >= 2 {
                    f = f.fact(ctx.l("Identical requests (same body)", "Identische Anforderungen (gleicher Body)"), ctx.fmt_count(identical)).hypothesis(ctx.l(
                        "The same token request is repeated: the token is not cached (a new client instance per call, or the cache is bypassed).",
                        "Dieselbe Token-Anforderung wird wiederholt: Das Token wird nicht gecacht (neue Client-Instanz pro Aufruf oder der Cache wird umgangen).",
                    ));
                } else if !hashes.is_empty() {
                    f = f.hypothesis(ctx.l(
                        "The token requests differ (different scopes or refresh tokens); one token per resource may be expected, repeated refreshes are not.",
                        "Die Token-Anforderungen unterscheiden sich (verschiedene Scopes oder Refresh-Tokens); ein Token pro Ressource ist erwartbar, wiederholte Erneuerungen nicht.",
                    ));
                }
            }
            if per_call {
                f = f.fact(ctx.l("API calls with tokens of this client", "API-Aufrufe mit Tokens dieses Clients"), ctx.fmt_count(api_calls)).hypothesis(ctx.l(
                    "A token is fetched for (almost) every API call instead of reusing it.",
                    "Für (fast) jeden API-Aufruf wird ein Token geholt, statt es wiederzuverwenden.",
                ));
            }
            if let Some(w) = where_rec(ctx, the_idp, Topic::Lifetime) {
                f = f.next_step(w);
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ OIDC-LOOP

/// OIDC-LOOP: the same client starts sign-in again and again.
struct OidcLoop;

impl Analyzer for OidcLoop {
    fn id(&self) -> &'static str {
        "OIDC-LOOP"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let mut list = vec![];
        for ((host, client), v) in util::group_by(m.authz.iter().filter(|a| !a.silent() && !a.continuation), |a| (a.host.clone(), a.client.clone())) {
            if v.len() < LOOP_MIN {
                continue;
            }
            // Attempts in any window of LOOP_WINDOW_US holding at least LOOP_MIN of them.
            let mut inloop = vec![false; v.len()];
            let mut lo = 0;
            let mut peak = 0;
            for hi in 0..v.len() {
                while v[hi].at.saturating_sub(v[lo].at) > LOOP_WINDOW_US {
                    lo += 1;
                }
                let k = hi - lo + 1;
                peak = peak.max(k);
                if k >= LOOP_MIN {
                    for x in inloop.iter_mut().take(hi + 1).skip(lo) {
                        *x = true;
                    }
                }
            }
            if peak < LOOP_MIN {
                continue;
            }
            let attempts: Vec<&Authz> = v.iter().zip(&inloop).filter(|(_, b)| **b).map(|(a, _)| *a).collect();
            let (from, to) = (attempts[0].at, attempts.last().map(|a| a.at).unwrap_or(0));
            let uris: BTreeSet<&str> = attempts.iter().filter_map(|a| a.redirect_uri.as_deref()).collect();
            let callbacks: Vec<usize> = m.callbacks.iter().copied().filter(|&i| ss[i].started >= from && ss[i].started <= to + FOLLOW_US && uris.contains(base_url(&ss[i].url).as_str())).collect();
            let the_idp = attempts.iter().map(|a| a.idp).find(|i| *i != Idp::Generic).unwrap_or(Idp::Generic);
            let errors = attempts.iter().filter_map(|a| if let Outcome::Error(e) = &a.outcome { Some(e.clone()) } else { None });
            let errors = top_list(ctx, errors, 3);
            let successes = attempts.iter().filter(|a| a.outcome == Outcome::Success).count();
            // Evidence: cookies the callback sets but the next request does not send back.
            let mut lost: BTreeSet<String> = BTreeSet::new();
            for &c in &callbacks {
                let names: Vec<String> = ss[c].resp_headers("set-cookie").map(util::set_cookie).filter(|x| !x.deletes && !x.name.is_empty()).map(|x| x.name).collect();
                if names.is_empty() {
                    continue;
                }
                let h = p.host[c];
                let until = ss[c].end() + FOLLOW_US;
                if let Some(next) = (c + 1..ss.len()).take_while(|&j| ss[j].started <= until).find(|&j| ss[j].is_http() && p.host[j] == h && ss[j].started >= ss[c].end()) {
                    let sent: BTreeSet<&str> = ss[next].req_header("cookie").into_iter().flat_map(|x| x.split(';')).map(|x| x.split('=').next().unwrap_or("").trim()).collect();
                    lost.extend(names.into_iter().filter(|n| !sent.contains(n.as_str())));
                }
            }
            // Evidence: correlation/nonce cookies that browsers drop or do not send cross-site.
            let mut none_insecure = BTreeSet::new();
            let mut lax_nonce = BTreeSet::new();
            let form_post = attempts.iter().any(|a| a.response_mode.as_deref() == Some("form_post"));
            let app_hosts: BTreeSet<String> = uris.iter().map(|u| url_host(u)).collect();
            let lo = p.http.partition_point(|&i| ss[i].started + FOLLOW_US < from);
            let hi = p.http.partition_point(|&i| ss[i].started <= to + FOLLOW_US);
            for &i in &p.http[lo..hi.max(lo)] {
                let s = &ss[i];
                if !app_hosts.contains(p.host_of(i)) {
                    continue;
                }
                for c in s.resp_headers("set-cookie").map(util::set_cookie).filter(|c| is_nonce_cookie(&c.name) && !c.deletes) {
                    if c.same_site.as_deref() == Some("none") && !c.secure {
                        none_insecure.insert(c.name.clone());
                    } else if form_post && c.same_site.as_deref() != Some("none") {
                        lax_nonce.insert(c.name.clone());
                    }
                }
            }
            let http_uri = uris.iter().any(|u| u.starts_with("http://") && !is_localhost(&url_host(u)));
            let mut rows: Vec<(u64, usize)> = attempts.iter().map(|a| (a.at, a.i)).chain(callbacks.iter().map(|&i| (ss[i].started, i))).collect();
            rows.sort_unstable();
            rows.dedup();
            let table: Vec<Vec<String>> = rows
                .iter()
                .take(15)
                .map(|&(t, i)| vec![format!("+{}", ctx.fmt_ms((t - from) as f64 / 1000.0)), ss[i].status.to_string(), ss[i].method.clone(), util::short(&ss[i].url, 110)])
                .collect();
            let mut f = Finding::new(
                "OIDC-LOOP",
                &format!("{host}|{client}"),
                Severity::Critical,
                tr(ctx, format!("Sign-in loop: {client} ({})", the_idp.name()), format!("Anmeldeschleife: {client} ({})", the_idp.name())),
                tr(
                    ctx,
                    format!("Client {client} sent {} authorization requests to {host}, up to {peak} within {}; {} callback(s) in between.", ctx.fmt_count(attempts.len()), ctx.fmt_ms(LOOP_WINDOW_US as f64 / 1000.0), ctx.fmt_count(callbacks.len())),
                    format!("Client {client} sandte {} Autorisierungs-Requests an {host}, bis zu {peak} innerhalb von {}; dazwischen {} Callback(s).", ctx.fmt_count(attempts.len()), ctx.fmt_ms(LOOP_WINDOW_US as f64 / 1000.0), ctx.fmt_count(callbacks.len())),
                ),
            )
            .categories(&["auth", "errors", "redirects"])
            .tags(&["oauth"])
            .score(util::scale(peak as f64, LOOP_MIN as f64, 20.0) * 0.5 + 50.0)
            .threshold(tr(ctx, format!("≥ {LOOP_MIN} authorization requests of one client within {}", ctx.fmt_ms(LOOP_WINDOW_US as f64 / 1000.0)), format!("≥ {LOOP_MIN} Autorisierungs-Requests eines Clients innerhalb von {}", ctx.fmt_ms(LOOP_WINDOW_US as f64 / 1000.0))))
            .fact(ctx.l("Authorization requests", "Autorisierungs-Requests"), ctx.fmt_count(attempts.len()))
            .fact(ctx.l("Callbacks", "Callbacks"), ctx.fmt_count(callbacks.len()))
            .table(vec![ctx.l("Time", "Zeit").into(), ctx.l("Status", "Status").into(), ctx.l("Method", "Methode").into(), "URL".into()], table)
            .impact(ctx.l(
                "The user never gets into the application (the page flickers between app and IdP); the IdP may throttle the client (Entra ID AADSTS50196) and nonce cookies pile up (TOKEN-SIZE).",
                "Der Benutzer kommt nie in die Anwendung (die Seite springt zwischen App und IdP); der IdP kann den Client drosseln (Entra ID AADSTS50196), und Nonce-Cookies häufen sich (TOKEN-SIZE).",
            ))
            .sessions(rows.iter().map(|&(_, i)| ss[i].id));
            if successes > 0 {
                f = f.fact(ctx.l("Redirected back with a code/token", "Mit Code/Token zurückgeleitet"), ctx.fmt_count(successes));
            }
            if !uris.is_empty() {
                f = f.fact("redirect_uri", uris.iter().take(3).copied().collect::<Vec<_>>().join(", "));
            }
            if !errors.is_empty() {
                f = f.fact(ctx.l("Errors of the IdP", "Fehler des IdP"), errors);
            }
            if !lost.is_empty() {
                f = f.fact(ctx.l("Set by the callback, not sent back", "Vom Callback gesetzt, nicht zurückgesendet"), lost.iter().take(5).cloned().collect::<Vec<_>>().join(", ")).hypothesis(ctx.l(
                    "The authentication cookie set by the callback does not come back with the next request: rejected by the browser (Secure on http, SameSite, Domain/Path, size) — so the app starts the sign-in again.",
                    "Das vom Callback gesetzte Anmelde-Cookie kommt mit dem nächsten Request nicht zurück: vom Browser verworfen (Secure über http, SameSite, Domain/Path, Größe) – also startet die App die Anmeldung erneut.",
                ));
            }
            if !none_insecure.is_empty() {
                f = f.fact(ctx.l("SameSite=None without Secure", "SameSite=None ohne Secure"), none_insecure.iter().take(3).cloned().collect::<Vec<_>>().join(", ")).hypothesis(ctx.l(
                    "The correlation/nonce cookies are SameSite=None without Secure: browsers reject them, the callback cannot be correlated (\"Correlation failed\") and sign-in restarts.",
                    "Die Correlation-/Nonce-Cookies sind SameSite=None ohne Secure: Browser verwerfen sie, der Callback kann nicht zugeordnet werden („Correlation failed“), und die Anmeldung beginnt neu.",
                ));
            }
            if !lax_nonce.is_empty() {
                f = f.hypothesis(ctx.l(
                    "response_mode=form_post is a cross-site POST: correlation/nonce cookies with SameSite=Lax/Strict (or without SameSite) are not sent with it.",
                    "response_mode=form_post ist ein Cross-Site-POST: Correlation-/Nonce-Cookies mit SameSite=Lax/Strict (oder ohne SameSite) werden dabei nicht mitgesendet.",
                ));
            }
            if http_uri {
                f = f.hypothesis(ctx.l(
                    "The redirect URI is http while the site is served over https: Secure cookies set on the callback are dropped, or the IdP rejects the mismatch (forwarded headers behind a proxy).",
                    "Die Redirect-URI ist http, die Site läuft aber über https: Secure-Cookies des Callbacks werden verworfen, oder der IdP lehnt die Abweichung ab (Forwarded-Header hinter einem Proxy).",
                ));
            }
            if m.cookies.iter().any(|c| app_hosts.contains(&c.host)) {
                f = f.hypothesis(ctx.l("The authentication cookies are very large (see TOKEN-SIZE): the browser or a proxy drops them.", "Die Anmelde-Cookies sind sehr groß (siehe TOKEN-SIZE): Browser oder Proxy verwerfen sie."));
            }
            let mut clock_hosts: Vec<&str> = vec![host.as_str()];
            clock_hosts.extend(app_hosts.iter().map(String::as_str));
            if let Some(h) = clock_hint(ctx, m, &clock_hosts) {
                f = f.hypothesis(h).hypothesis(ctx.l("A clock offset makes the app reject the ID token (iat/nbf in the future, exp in the past) and start over.", "Eine Uhrzeitabweichung lässt die App das ID-Token ablehnen (iat/nbf in der Zukunft, exp in der Vergangenheit) und neu beginnen."));
            }
            f = f
                .hypothesis(ctx.l(
                    "Other typical causes: the callback path is not handled by the authentication middleware (CallbackPath vs. redirect_uri), middleware order (authentication after authorization), or the app requires a role the user does not have and treats it as signed out.",
                    "Weitere typische Ursachen: Der Callback-Pfad wird von der Anmelde-Middleware nicht verarbeitet (CallbackPath vs. redirect_uri), Reihenfolge der Middleware (Authentifizierung nach Autorisierung) oder die App verlangt eine Rolle, die der Benutzer nicht hat, und behandelt ihn als abgemeldet.",
                ))
                .recommend(ctx.l(
                    "Follow one cycle in the table: does the callback set the session cookie, and does the next request send it back?",
                    "Einem Zyklus in der Tabelle folgen: Setzt der Callback das Sitzungs-Cookie, und sendet der nächste Request es zurück?",
                ))
                .next_step(ctx.l("Check the application log at the callback for “Correlation failed”, “nonce” or token validation errors.", "Im Anwendungsprotokoll beim Callback nach „Correlation failed“, „nonce“ oder Token-Validierungsfehlern suchen."));
            if let Some(w) = where_rec(ctx, the_idp, Topic::RedirectUri) {
                f = f.recommend(w);
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ OIDC-SILENT

/// OIDC-SILENT: silent sign-in (prompt=none, hidden iframe) that fails.
struct OidcSilent;

impl Analyzer for OidcSilent {
    fn id(&self) -> &'static str {
        "OIDC-SILENT"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let mut list = vec![];
        let by_client = util::group_by(m.authz.iter(), |a| (a.host.clone(), a.client.clone()));
        for ((host, client), v) in by_client {
            let silent: Vec<&Authz> = v.iter().copied().filter(|a| a.silent()).collect();
            if silent.is_empty() {
                continue;
            }
            let interactive: Vec<u64> = v.iter().filter(|a| !a.silent()).map(|a| a.at).collect();
            let mut failed: Vec<usize> = vec![];
            let mut fell_back = 0;
            let mut codes: Vec<String> = vec![];
            for a in &silent {
                match &a.outcome {
                    Outcome::Error(e) => {
                        failed.push(a.i);
                        codes.push(e.clone());
                    }
                    Outcome::Unknown if interactive.iter().any(|&t| t > a.at && t <= a.at + SILENT_FALLBACK_US) => {
                        failed.push(a.i);
                        fell_back += 1;
                    }
                    _ => {}
                }
            }
            // Errors seen only on the callback.
            for e in m.errors.iter().filter(|e| e.silent && e.source == Source::Callback && e.host == host && e.client.as_deref() == Some(client.as_str())) {
                failed.push(e.i);
                codes.push(e.error.clone());
            }
            // AADSTS codes of the silent errors (from the redirect or the callback).
            let aad: BTreeSet<u32> = m.errors.iter().filter(|e| e.silent && e.host == host && e.client.as_deref() == Some(client.as_str())).flat_map(|e| e.codes.iter().copied()).collect();
            let cross_site = silent.iter().any(|a| a.redirect_uri.as_deref().is_some_and(|u| site(&url_host(u)) != site(&a.host)));
            let web_message = silent.iter().any(|a| a.response_mode.as_deref() == Some("web_message"));
            let the_idp = silent[0].idp;
            if failed.is_empty() && !(silent.len() >= 3 && cross_site) {
                continue;
            }
            let severity = if failed.is_empty() { Severity::Info } else { Severity::Warning };
            let mut f = Finding::new(
                "OIDC-SILENT",
                &format!("{host}|{client}"),
                severity,
                if failed.is_empty() {
                    tr(ctx, format!("Silent sign-in through a hidden iframe: {client}"), format!("Stille Anmeldung über ein verstecktes iframe: {client}"))
                } else {
                    tr(ctx, format!("Silent sign-in fails: {client} ({})", the_idp.name()), format!("Stille Anmeldung schlägt fehl: {client} ({})", the_idp.name()))
                },
                tr(
                    ctx,
                    format!("Client {client} made {} silent authorization request(s) (prompt=none / web_message) to {host}; {} failed ({} followed by an interactive sign-in).", ctx.fmt_count(silent.len()), ctx.fmt_count(failed.len()), ctx.fmt_count(fell_back)),
                    format!("Client {client} stellte {} stille Autorisierungs-Request(s) (prompt=none / web_message) an {host}; {} schlugen fehl ({} gefolgt von einer interaktiven Anmeldung).", ctx.fmt_count(silent.len()), ctx.fmt_count(failed.len()), ctx.fmt_count(fell_back)),
                ),
            )
            .confidence(if failed.is_empty() { Confidence::Low } else if codes.is_empty() { Confidence::Medium } else { Confidence::High })
            .categories(&["auth"])
            .tags(&["oauth"])
            .score(util::scale(failed.len() as f64, 0.0, 30.0) * 0.6 + if failed.is_empty() { 5.0 } else { 30.0 })
            .threshold(ctx.l("silent request answered with login_required / interaction_required / consent_required, or followed by an interactive sign-in", "stiller Request mit login_required / interaction_required / consent_required beantwortet oder von einer interaktiven Anmeldung gefolgt"))
            .fact(ctx.l("Silent requests", "Stille Requests"), ctx.fmt_count(silent.len()))
            .fact(ctx.l("Failed", "Fehlgeschlagen"), ctx.fmt_count(failed.len()))
            .fact(ctx.l("IdP on another site than the app", "IdP auf anderer Site als die App"), yes_no(ctx, cross_site))
            .impact(ctx.l(
                "Token renewal falls back to a full-page redirect (lost state, flicker) or the user is signed out; with third-party cookies blocked the hidden-iframe renewal never works.",
                "Die Token-Erneuerung weicht auf eine ganzseitige Weiterleitung aus (verlorener Zustand, Flackern), oder der Benutzer wird abgemeldet; bei blockierten Drittanbieter-Cookies funktioniert die Erneuerung im versteckten iframe nie.",
            ))
            .sessions(silent.iter().map(|a| ss[a.i].id))
            .sessions(failed.iter().map(|&i| ss[i].id));
            if !codes.is_empty() {
                f = f.fact(ctx.l("Errors", "Fehler"), top_list(ctx, codes.iter().cloned(), 4));
            }
            if web_message {
                f = f.fact("response_mode", "web_message");
            }
            if !aad.is_empty() {
                f = f.fact(
                    ctx.l("AADSTS codes", "AADSTS-Codes"),
                    aad.iter().take(4).map(|c| idp::aadsts(*c).map(|e| format!("AADSTS{c} {}", e.name)).unwrap_or_else(|| format!("AADSTS{c}"))).collect::<Vec<_>>().join(", "),
                );
                for e in aad.iter().filter_map(|c| idp::aadsts(*c)).take(2) {
                    f = f.hypothesis(pick(ctx, e.cause));
                }
            }
            let no_session = codes.is_empty() || fell_back > 0 || codes.iter().any(|c| c == "login_required") || aad.contains(&50058);
            if cross_site && no_session {
                f = f.hypothesis(ctx.l(
                    "The IdP's session cookie is a third-party cookie inside the app's iframe: Safari (ITP), Firefox (Total Cookie Protection), Brave and Chrome with third-party cookies blocked do not send it, so the IdP sees no session (login_required).",
                    "Das Sitzungs-Cookie des IdP ist im iframe der App ein Drittanbieter-Cookie: Safari (ITP), Firefox (vollständiger Cookie-Schutz), Brave und Chrome mit blockierten Drittanbieter-Cookies senden es nicht, daher sieht der IdP keine Sitzung (login_required).",
                ));
            } else if no_session {
                f = f.hypothesis(ctx.l("IdP and app share a site, so cookies are first-party: the IdP session itself has probably expired (idle/max lifetime) or MFA/consent is required again.", "IdP und App teilen eine Site, die Cookies sind also First-Party: Vermutlich ist die IdP-Sitzung selbst abgelaufen (Leerlauf/Höchstdauer), oder MFA/Zustimmung ist erneut nötig."));
            }
            if codes.iter().any(|c| c == "interaction_required" || c == "consent_required") {
                f = f.hypothesis(ctx.l("interaction_required / consent_required: MFA, Conditional Access or consent needs the user; silent renewal cannot succeed.", "interaction_required / consent_required: MFA, bedingter Zugriff oder Zustimmung brauchen den Benutzer; stille Erneuerung kann nicht gelingen."));
            }
            f = f
                .recommend(ctx.l(
                    "Renew with refresh tokens (authorization code + PKCE, refresh token rotation) instead of hidden iframes, or move tokens to a backend (BFF pattern) with a first-party session cookie.",
                    "Mit Refresh-Tokens erneuern (Authorization Code + PKCE, Refresh-Token-Rotation) statt mit versteckten iframes, oder die Tokens in ein Backend verlagern (BFF-Muster) mit einem First-Party-Sitzungs-Cookie.",
                ))
                .recommend(ctx.l("Handle login_required / interaction_required by an interactive sign-in at a moment that keeps the user's work.", "login_required / interaction_required mit einer interaktiven Anmeldung zu einem Zeitpunkt behandeln, der die Arbeit des Benutzers erhält."));
            if let Some(w) = where_rec(ctx, the_idp, Topic::SilentRenew) {
                f = f.recommend(w);
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ OIDC-DISCOVERY

/// `https://Host/x/` → `https://host/x`; `{tenantid}` stays a placeholder.
fn norm_issuer(s: &str) -> String {
    let t = s.trim().trim_end_matches('/');
    match t.find("://") {
        Some(i) => {
            let rest = &t[i + 3..];
            let (h, path) = rest.find('/').map(|k| (&rest[..k], &rest[k..])).unwrap_or((rest, ""));
            format!("{}://{}{}", t[..i].to_ascii_lowercase(), h.to_ascii_lowercase(), path)
        }
        None => t.to_string(),
    }
}

/// Issuer `iss` matches the discovery `issuer` (with Entra's `{tenantid}` placeholder).
fn issuer_matches(issuer: &str, iss: &str) -> bool {
    let (a, b) = (norm_issuer(issuer), norm_issuer(iss));
    match a.split_once("{tenantid}") {
        Some((pre, post)) => b.len() >= pre.len() + post.len() && b.starts_with(pre) && b.ends_with(post),
        None => a == b,
    }
}

/// OIDC-DISCOVERY: discovery/JWKS caching and failures, issuer mismatches.
struct OidcDiscovery;

impl Analyzer for OidcDiscovery {
    fn id(&self) -> &'static str {
        "OIDC-DISCOVERY"
    }
    fn profiles(&self) -> &'static [&'static str] {
        PROFILES
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let m = model(ctx);
        let ss = ctx.sessions;
        let p = ctx.prep();
        let mut list = vec![];
        // Fetched again and again.
        for (kind, docs) in [("discovery", &m.discovery), ("jwks", &m.jwks)] {
            for ((key, process), v) in util::group_by(docs.iter().copied(), |&i| (p.url_key_of(i).to_string(), ss[i].process.clone())) {
                let times: Vec<u64> = v.iter().map(|&i| ss[i].started).collect();
                let peak = util::max_in_window(&times, DISCOVERY_WINDOW_US);
                if peak < DISCOVERY_INFO_MIN {
                    continue;
                }
                let host = p.host_of(v[0]).to_string();
                let not_modified = v.iter().filter(|&&i| ss[i].status == 304).count();
                let cc = top_list(ctx, v.iter().filter_map(|&i| ss[i].resp_header("cache-control").map(String::from)), 2);
                let what = if kind == "jwks" { ctx.l("signing keys (JWKS)", "Signaturschlüssel (JWKS)") } else { ctx.l("discovery document", "Discovery-Dokument") };
                let mut f = Finding::new(
                    "OIDC-DISCOVERY",
                    &format!("repeat|{kind}|{key}|{process}"),
                    if peak >= DISCOVERY_WARN_MIN { Severity::Warning } else { Severity::Info },
                    tr(ctx, format!("OIDC {what} fetched repeatedly: {}", util::short(&host, 60)), format!("OIDC-{what} wiederholt abgerufen: {}", util::short(&host, 60))),
                    tr(
                        ctx,
                        format!("Process {process} fetched the {what} of {host} {} times, up to {peak} within 5 minutes.", ctx.fmt_count(v.len())),
                        format!("Prozess {process} rief das {what} von {host} {}-mal ab, bis zu {peak}-mal innerhalb von 5 Minuten.", ctx.fmt_count(v.len())),
                    ),
                )
                .categories(&["auth", "performance", "caching"])
                .tags(&["oauth"])
                .score(util::scale(peak as f64, DISCOVERY_INFO_MIN as f64, 200.0))
                .threshold(tr(ctx, format!("≥ {DISCOVERY_INFO_MIN} in 5 min (warning from {DISCOVERY_WARN_MIN})"), format!("≥ {DISCOVERY_INFO_MIN} in 5 min (Warnung ab {DISCOVERY_WARN_MIN})")))
                .fact(ctx.l("Fetches", "Abrufe"), ctx.fmt_count(v.len()))
                .fact(ctx.l("Most within 5 minutes", "Höchstens innerhalb von 5 Minuten"), ctx.fmt_count(peak))
                .fact("304 Not Modified", ctx.fmt_count(not_modified))
                .impact(ctx.l("Every fetch adds a round trip before a token can be validated or requested, and load on the IdP.", "Jeder Abruf kostet einen Roundtrip, bevor ein Token geprüft oder angefordert werden kann, und Last beim IdP."))
                .hypothesis(ctx.l(
                    "The OIDC metadata is not cached: a new ConfigurationManager / JWKS client / OIDC client per request or per validation.",
                    "Die OIDC-Metadaten werden nicht gecacht: ein neuer ConfigurationManager / JWKS-Client / OIDC-Client pro Request bzw. Validierung.",
                ))
                .recommend(ctx.l(
                    "Keep one metadata/JWKS cache per authority for the process lifetime (default refresh about every 24 h; refetch keys only for an unknown kid).",
                    "Einen Metadaten-/JWKS-Cache pro Authority für die Lebensdauer des Prozesses halten (Aktualisierung etwa alle 24 h; Schlüssel nur bei unbekannter kid neu laden).",
                ))
                .sessions(v.iter().map(|&i| ss[i].id));
                if !cc.is_empty() {
                    f = f.fact("Cache-Control", cc);
                }
                list.push(f);
            }
        }
        // Failing.
        let failing = m.discovery.iter().chain(m.jwks.iter()).copied().filter(|&i| ss[i].status >= 400 || ss[i].failed());
        for (host, v) in util::group_by(failing, |&i| p.host_of(i).to_string()) {
            list.push(
                Finding::new(
                    "OIDC-DISCOVERY",
                    &format!("fail|{host}"),
                    Severity::Warning,
                    tr(ctx, format!("OIDC metadata not available: {}", util::short(&host, 60)), format!("OIDC-Metadaten nicht verfügbar: {}", util::short(&host, 60))),
                    tr(
                        ctx,
                        format!("{} request(s) for the discovery document or the signing keys of {host} failed ({}).", ctx.fmt_count(v.len()), top_list(ctx, v.iter().map(|&i| if ss[i].status > 0 { ss[i].status.to_string() } else { ss[i].error.clone().unwrap_or_default() }), 3)),
                        format!("{} Request(s) nach dem Discovery-Dokument oder den Signaturschlüsseln von {host} scheiterten ({}).", ctx.fmt_count(v.len()), top_list(ctx, v.iter().map(|&i| if ss[i].status > 0 { ss[i].status.to_string() } else { ss[i].error.clone().unwrap_or_default() }), 3)),
                    ),
                )
                .categories(&["auth", "errors"])
                .tags(&["oauth"])
                .score(util::scale(v.len() as f64, 0.0, 20.0) * 0.5 + 40.0)
                .threshold(ctx.l("status ≥ 400 or no response", "Status ≥ 400 oder keine Antwort"))
                .fact("URL", top_list(ctx, v.iter().map(|&i| canon::parse(&ss[i].url).path), 3))
                .impact(ctx.l("Without metadata no sign-in starts and no token can be validated (IDX20803 “Unable to obtain configuration”).", "Ohne Metadaten startet keine Anmeldung, und kein Token kann geprüft werden (IDX20803 „Unable to obtain configuration“)."))
                .hypothesis(ctx.l(
                    "Wrong authority (tenant, realm, path such as /v2.0 or /auth/realms), the IdP is not reachable from this network (proxy, firewall), or it is down.",
                    "Falsche Authority (Mandant, Realm, Pfad wie /v2.0 oder /auth/realms), der IdP ist aus diesem Netz nicht erreichbar (Proxy, Firewall), oder er ist ausgefallen.",
                ))
                .recommend(ctx.l("Open the discovery URL from the affected machine and compare it with the authority configured in the app.", "Die Discovery-URL vom betroffenen Rechner aus öffnen und mit der in der App konfigurierten Authority vergleichen."))
                .sessions(v.iter().map(|&i| ss[i].id)),
            );
        }
        // Issuer mismatches.
        // Per host: discovery issuers, discovery sessions, "URL → issuer" mismatches.
        type Issuers = (BTreeSet<String>, Vec<usize>, BTreeSet<String>);
        let mut issuers: BTreeMap<String, Issuers> = BTreeMap::new();
        for &i in &m.discovery {
            let Some(d) = ss[i].auth.as_ref().and_then(|a| a.discovery.as_ref()) else { continue };
            let Some(iss) = d.issuer.clone() else { continue };
            let e = issuers.entry(p.host_of(i).to_string()).or_default();
            e.0.insert(iss.clone());
            e.1.push(i);
            let authority = ss[i].url.split(['?', '#']).next().unwrap_or("").to_string();
            let authority = authority.trim_end_matches('/');
            let authority = authority.strip_suffix("/.well-known/openid-configuration").unwrap_or(authority);
            if !idp::from_issuer(&iss).is_entra() && !idp::by_host(p.host_of(i)).is_some_and(|x| x.is_entra()) && !issuer_matches(&iss, authority) {
                e.2.insert(format!("{authority} → {iss}"));
            }
        }
        for (host, (doc_iss, docs, authority_mismatch)) in issuers {
            let mut wrong: Vec<(usize, String)> = vec![];
            for &i in &m.tokens {
                if p.host_of(i) != host {
                    continue;
                }
                let Some(r) = ss[i].auth.as_ref().and_then(|a| a.oauth_response.as_ref()) else { continue };
                let toks = r.id_token.iter().chain(r.access_token.iter().filter(|c| !c.aud.iter().any(|a| idp::ms_resource_host(a).is_some())));
                for c in toks {
                    if let Some(iss) = c.iss.as_deref()
                        && !doc_iss.iter().any(|d| issuer_matches(d, iss))
                    {
                        wrong.push((i, iss.to_string()));
                    }
                }
            }
            if wrong.is_empty() && authority_mismatch.is_empty() {
                continue;
            }
            let the_idp = m.idp_of(&host);
            let doc = doc_iss.iter().cloned().collect::<Vec<_>>().join(", ");
            let v1 = wrong.iter().any(|(_, s)| idp::is_entra_v1_issuer(s));
            let mut f = Finding::new(
                "OIDC-DISCOVERY",
                &format!("issuer|{host}"),
                Severity::Warning,
                tr(ctx, format!("Issuer mismatch: {}", util::short(&host, 60)), format!("Aussteller passt nicht: {}", util::short(&host, 60))),
                if wrong.is_empty() {
                    tr(
                        ctx,
                        format!("The discovery document of {host} names the issuer {doc}, which differs from the URL it was fetched from."),
                        format!("Das Discovery-Dokument von {host} nennt den Aussteller {doc}, der von der URL abweicht, unter der es abgerufen wurde."),
                    )
                } else {
                    tr(
                        ctx,
                        format!("Tokens issued by {host} carry iss {}, but its discovery document names {doc}.", top_list(ctx, wrong.iter().map(|(_, s)| s.clone()), 2)),
                        format!("Von {host} ausgestellte Tokens tragen iss {}, das Discovery-Dokument nennt aber {doc}.", top_list(ctx, wrong.iter().map(|(_, s)| s.clone()), 2)),
                    )
                },
            )
            .categories(&["auth", "errors"])
            .tags(&["oauth"])
            .score(50.0)
            .threshold(ctx.l("token iss ≠ discovery issuer, or issuer ≠ discovery URL", "Token-iss ≠ Discovery-Issuer oder Issuer ≠ Discovery-URL"))
            .fact(ctx.l("Issuer (discovery)", "Issuer (Discovery)"), doc)
            .impact(ctx.l(
                "OIDC libraries compare iss with the configured authority's issuer exactly: sign-in fails (IDX10205, “issuer mismatch”) or tokens are rejected by the API.",
                "OIDC-Bibliotheken vergleichen iss exakt mit dem Issuer der konfigurierten Authority: Die Anmeldung scheitert (IDX10205, „issuer mismatch“), oder die API weist Tokens ab.",
            ))
            .sessions(docs.iter().chain(wrong.iter().map(|(i, _)| i)).map(|&i| ss[i].id));
            if !authority_mismatch.is_empty() {
                f = f.fact(ctx.l("Discovery URL → issuer", "Discovery-URL → Issuer"), authority_mismatch.iter().take(2).cloned().collect::<Vec<_>>().join("; ")).hypothesis(ctx.l(
                    "The IdP advertises another host name or scheme than the one clients use (Keycloak behind a proxy: KC_HOSTNAME / frontend URL; X-Forwarded-* not trusted).",
                    "Der IdP gibt einen anderen Hostnamen oder ein anderes Schema an, als die Clients verwenden (Keycloak hinter einem Proxy: KC_HOSTNAME / Frontend-URL; X-Forwarded-* nicht vertraut).",
                ));
            }
            if v1 {
                f = f.hypothesis(ctx.l(
                    "Entra ID issued v1 tokens (sts.windows.net) while the app uses the v2.0 metadata: set accessTokenAcceptedVersion = 2 in the API's manifest, or accept both issuers.",
                    "Entra ID hat v1-Tokens (sts.windows.net) ausgestellt, die App verwendet aber die v2.0-Metadaten: accessTokenAcceptedVersion = 2 im Manifest der API setzen oder beide Aussteller akzeptieren.",
                ));
            } else if !wrong.is_empty() {
                f = f.hypothesis(ctx.l("The app uses another tenant/realm/authority than the one issuing the tokens.", "Die App verwendet einen anderen Mandanten/Realm/eine andere Authority als den Aussteller der Tokens."));
            }
            if let Some(w) = where_rec(ctx, the_idp, Topic::Tenant) {
                f = f.recommend(w);
            }
            list.push(f.recommend(ctx.l("Configure the authority exactly as the issuer the IdP puts into its tokens.", "Die Authority exakt so konfigurieren wie den Issuer, den der IdP in seine Tokens schreibt.")));
        }
        emit(ctx, out, list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn www_authenticate_parameters() {
        let c = challenges(r#"Bearer realm="api", error="invalid_token", error_description="The token expired at '10/01/2026 10:00:00', sorry""#);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, "Bearer");
        let get = |k: &str| c[0].1.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("realm"), Some("api"));
        assert_eq!(get("error"), Some("invalid_token"));
        assert_eq!(get("error_description"), Some("The token expired at '10/01/2026 10:00:00', sorry"));
        // Old redaction format: parameter names only.
        let c = challenges("Bearer realm, error");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].1.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>(), vec![("realm", ""), ("error", "")]);
        // Several challenges, token68.
        let c = challenges(r#"Negotiate <1320 bytes>, Basic realm="x", Bearer error="insufficient_scope", scope="api://x/Orders.Read""#);
        assert_eq!(c.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), vec!["Negotiate", "Basic", "Bearer"]);
        assert_eq!(c[2].1[1], ("scope".to_string(), "api://x/Orders.Read".to_string()));
        assert!(challenges("").is_empty());
        for junk in [",,,", "=", "\"", "Bearer =", "a=b=c, \"x"] {
            let _ = challenges(junk);
        }
    }

    #[test]
    fn audiences() {
        let a = |v: &[&str], h: &str| audience_verdict(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>(), h);
        assert_eq!(a(&["https://graph.microsoft.com"], "api.example.com"), Some(false));
        assert_eq!(a(&["00000003-0000-0000-c000-000000000000"], "graph.microsoft.com"), Some(true));
        assert_eq!(a(&["https://api.example.com/"], "api.example.com"), Some(true));
        assert_eq!(a(&["https://orders.example.com"], "api.example.com:8443"), Some(true), "same site");
        assert_eq!(a(&["https://api.other.org"], "api.example.com"), Some(false));
        assert_eq!(a(&["api://3f2c0e1a-1111-2222-3333-444455556666"], "api.example.com"), None);
        assert_eq!(a(&["my-api"], "api.example.com"), None);
        assert_eq!(a(&[], "api.example.com"), None);
    }

    #[test]
    fn cookie_names() {
        assert_eq!(auth_cookie_base(".AspNetCore.CookiesC1"), Some((".AspNetCore.Cookies", true)));
        assert_eq!(auth_cookie_base(".AspNetCore.Cookies"), Some((".AspNetCore.Cookies", false)));
        assert_eq!(auth_cookie_base("FedAuth1"), Some(("FedAuth", true)));
        assert_eq!(auth_cookie_base("appSession.0"), Some(("appSession", true)));
        assert_eq!(auth_cookie_base("__Secure-next-auth.session-token.1"), Some(("__Secure-next-auth.session-token", true)));
        assert_eq!(auth_cookie_base("c1"), None);
        assert_eq!(auth_cookie_base(".AspNetCore.Correlation.abc"), None);
        assert!(is_nonce_cookie(".AspNetCore.OpenIdConnect.Nonce.CfDJ8"));
    }

    #[test]
    fn issuers_and_urls() {
        assert!(issuer_matches("https://login.microsoftonline.com/{tenantid}/v2.0", "https://login.microsoftonline.com/72f9/v2.0"));
        assert!(!issuer_matches("https://login.microsoftonline.com/{tenantid}/v2.0", "https://sts.windows.net/72f9/"));
        assert!(issuer_matches("https://SSO.example.com/realms/x/", "https://sso.example.com/realms/x"));
        assert_eq!(raw_path("https://h.test/a/b?x=1#f"), "/a/b");
        assert_eq!(raw_path("https://h.test"), "/");
        assert_eq!(base_url("HTTPS://App.Test/cb/?code=1"), "https://app.test/cb");
        let (q, f) = url_params("https://h/cb?error=access_denied&error_description=No+way#access_token=%3C9%20bytes%3E");
        assert_eq!(param(&q, "error_description"), Some("No way"));
        assert!(param(&f, "access_token").is_some() && plain(&f, "access_token").is_none());
        assert_eq!(norm_words("token id_token"), "id_token token");
    }
}
