//! Quena plugin: capture diagnostics ("WebDiag").
//!
//! Turns thousands of sessions into a short list of prioritised findings with evidence.
//! Deterministic: the same capture and options always give the same report. Contract with
//! the host and the UI: `REPORT.md`; data model: `model.rs`; checks: `analyzers/`.
pub mod analyzers;
pub mod canon;
pub mod fmt;
pub mod idp;
pub mod json;
pub mod model;
pub mod net;
pub mod ops;
pub mod prep;
pub mod profiles;
pub mod testkit;
pub mod util;

use json::Value;
use model::{Ctx, Finding, Lang, Metric, Network, Options, Session, Unit};

pub const ID: &str = "io.github.hkiam.webdiag";

// ------------------------------------------------------------------ options

fn num_opt(v: &Value, key: &str, default: f64) -> f64 {
    v.get(key).and_then(|x| x.as_f64()).filter(|x| x.is_finite() && *x >= 0.0).unwrap_or(default)
}

/// Options from JSON (see REPORT.md); invalid or missing values take the defaults.
pub fn parse_options(text: &str) -> Options {
    let d = Options::default();
    let Ok(v) = json::parse(text.as_bytes()) else { return d };
    let networks = match v.get("networks") {
        Some(Value::Arr(a)) if !a.is_empty() => a
            .iter()
            .take(12)
            .enumerate()
            .map(|(i, n)| Network {
                id: n.get("id").and_then(|x| x.as_str()).map(String::from).unwrap_or_else(|| format!("net-{i}")),
                name: n.get("name").and_then(|x| x.as_str()).unwrap_or("?").chars().take(40).collect(),
                rtt_ms: num_opt(n, "rttMs", 0.0),
                mbps: num_opt(n, "mbps", 0.0).max(0.001),
                loss_pct: num_opt(n, "lossPct", 0.0).min(100.0),
            })
            .collect(),
        _ => d.networks.clone(),
    };
    Options {
        profile: v.get("profile").and_then(|x| x.as_str()).map(|p| profiles::get(p).id.to_string()).unwrap_or(d.profile),
        lang: if v.get("lang").and_then(|x| x.as_str()) == Some("de") { Lang::De } else { Lang::En },
        slow_ms: num_opt(&v, "slowMs", d.slow_ms).max(1.0),
        ttfb_ms: num_opt(&v, "ttfbMs", d.ttfb_ms).max(1.0),
        large_request_bytes: num_opt(&v, "largeRequestBytes", d.large_request_bytes as f64).max(1.0) as u64,
        large_response_bytes: num_opt(&v, "largeResponseBytes", d.large_response_bytes as f64).max(1.0) as u64,
        operation_gap_ms: num_opt(&v, "operationGapMs", d.operation_gap_ms).max(10.0),
        networks,
    }
}

// ------------------------------------------------------------------ JSON output

fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}
fn n(v: f64) -> Value {
    if !v.is_finite() {
        return Value::Null;
    }
    if v.fract() == 0.0 && v.abs() < 9.0e15 { Value::Num(format!("{}", v as i64)) } else { Value::Num(format!("{v:.4}")) }
}
fn obj(pairs: Vec<(&str, Value)>) -> Value {
    Value::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn strs(v: &[String]) -> Value {
    Value::Arr(v.iter().map(|x| s(x)).collect())
}

fn metric_json(m: &Metric) -> Value {
    let mut p = vec![("key", s(&m.key)), ("label", s(&m.label)), ("value", n(m.value)), ("unit", s(m.unit.as_str()))];
    if let Some(t) = &m.text {
        p.push(("text", s(t)));
    }
    obj(p)
}

fn finding_json(f: &Finding) -> Value {
    let mut p = vec![
        ("id", s(f.id)),
        ("key", s(&f.key)),
        ("title", s(&f.title)),
        ("severity", s(f.severity.as_str())),
        ("confidence", s(f.confidence.as_str())),
        ("categories", Value::Arr(f.categories.iter().map(|c| s(c)).collect())),
        ("score", n(f.score as f64)),
        ("observation", s(&f.observation)),
        ("impact", s(&f.impact)),
        ("hypotheses", strs(&f.hypotheses)),
        ("recommendations", strs(&f.recommendations)),
        ("nextSteps", strs(&f.next_steps)),
        ("estimate", Value::Bool(f.estimate)),
        ("facts", Value::Arr(f.facts.iter().map(|(l, v)| obj(vec![("label", s(l)), ("value", s(v))])).collect())),
        ("sessions", Value::Arr(f.sessions.iter().map(|id| n(*id as f64)).collect())),
        ("tags", Value::Arr(f.tags.iter().map(|t| s(t)).collect())),
    ];
    if let Some(t) = &f.threshold {
        p.push(("threshold", s(t)));
    }
    if let Some(t) = &f.table {
        p.push(("table", obj(vec![("columns", strs(&t.columns)), ("rows", Value::Arr(t.rows.iter().map(|r| strs(r)).collect()))])));
    }
    if let Some(o) = &f.operation {
        p.push(("operation", s(o)));
    }
    obj(p)
}

// ------------------------------------------------------------------ engine

/// One diagnostic run: sessions are pushed in batches, `finish` builds the report.
pub struct Run {
    opts: Options,
    sessions: Vec<Session>,
    /// At most this many sessions are analysed ([`MAX_SESSIONS`]).
    limit: usize,
    /// Sessions pushed beyond the limit (not analysed).
    dropped: usize,
}

/// More sessions are not analysed (memory/time bound inside the sandbox).
pub const MAX_SESSIONS: usize = 500_000;

impl Run {
    pub fn new(options: &str) -> Run {
        Run { opts: parse_options(options), sessions: vec![], limit: MAX_SESSIONS, dropped: 0 }
    }

    /// A run that analyses at most `limit` sessions (tests; the plugin uses [`MAX_SESSIONS`]).
    pub fn with_limit(mut self, limit: usize) -> Run {
        self.limit = limit;
        self
    }

    pub fn push(&mut self, batch: impl IntoIterator<Item = Session>) {
        for s in batch {
            if self.sessions.len() < self.limit {
                self.sessions.push(s);
            } else {
                self.dropped += 1;
            }
        }
    }

    /// Sessions that were pushed beyond [`MAX_SESSIONS`] and are not analysed.
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    pub fn options(&self) -> &Options {
        &self.opts
    }

    /// Findings, operations and metrics (before JSON).
    pub fn analyse(&mut self) -> (Vec<Finding>, Vec<model::Operation>, Vec<Metric>) {
        self.sessions.sort_by_key(|s| (s.started, s.id));
        let ops = ops::segment(&self.sessions, &self.opts);
        let ctx = Ctx::new(&self.sessions, &ops, &self.opts);
        let profile = self.opts.profile.as_str();
        let mut findings = vec![];
        for a in analyzers::all() {
            if profile == "full" || a.profiles().contains(&profile) {
                a.run(&ctx, &mut findings);
            }
        }
        if self.dropped > 0 {
            findings.push(truncated_finding(&ctx, self.limit, self.dropped));
        }
        findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(b.score.cmp(&a.score)).then(a.key.cmp(&b.key)));
        let mut metrics = capture_metrics(&ctx);
        if self.dropped > 0 {
            let label = ctx.l("Sessions not analysed (limit)", "Nicht analysierte Sessions (Grenze)").to_string();
            metrics.push(Metric { label, ..Metric::new("notAnalysed", "", self.dropped as f64, Unit::Count) });
        }
        (findings, ops, metrics)
    }

    pub fn finish(mut self) -> String {
        let (findings, ops, metrics) = self.analyse();
        let lang = self.opts.lang;
        let l = |en: &'static str, de: &'static str| if lang == Lang::De { de } else { en };
        let count = |sev: model::Severity| findings.iter().filter(|f| f.severity == sev).count() as f64;
        let headline: Vec<String> = findings.iter().filter(|f| f.severity != model::Severity::Info).take(6).map(|f| f.title.clone()).collect();
        let from = self.sessions.first().map(|s| s.started).unwrap_or(0);
        let to = self.sessions.iter().map(|s| s.end()).max().unwrap_or(0);
        let profile = profiles::get(&self.opts.profile);
        let report = obj(vec![
            ("schema", n(1.0)),
            ("tool", obj(vec![("id", s(ID)), ("version", s(env!("CARGO_PKG_VERSION")))])),
            ("profile", obj(vec![("id", s(profile.id)), ("name", s(profiles::pick(profile.name, lang)))])),
            ("lang", s(if lang == Lang::De { "de" } else { "en" })),
            ("range", obj(vec![("from", n(from as f64)), ("to", n(to as f64)), ("sessions", n(self.sessions.len() as f64))])),
            (
                "summary",
                obj(vec![
                    ("critical", n(count(model::Severity::Critical))),
                    ("warning", n(count(model::Severity::Warning))),
                    ("info", n(count(model::Severity::Info))),
                    ("headline", strs(&headline)),
                    (
                        "note",
                        s(l(
                            "Findings are derived from the captured traffic only; statements marked as estimates are modelled, not measured.",
                            "Die Befunde beruhen nur auf dem aufgezeichneten Verkehr; als Schätzung markierte Aussagen sind modelliert, nicht gemessen.",
                        )),
                    ),
                ]),
            ),
            ("metrics", Value::Arr(metrics.iter().map(metric_json).collect())),
            (
                "operations",
                Value::Arr(
                    ops.iter()
                        .map(|o| {
                            obj(vec![
                                ("id", s(&o.id)),
                                ("label", s(&o.label)),
                                ("start", n(o.start as f64)),
                                ("end", n(o.end as f64)),
                                ("sessions", Value::Arr(o.members.iter().map(|&i| n(self.sessions[i].id as f64)).collect())),
                                ("metrics", Value::Arr(o.metrics.iter().map(metric_json).collect())),
                                ("background", Value::Bool(o.background)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("findings", Value::Arr(findings.iter().map(finding_json).collect())),
        ]);
        json::compact(&report)
    }
}

/// SCOPE-LIMIT: the capture had more sessions than the limit ([`MAX_SESSIONS`]); only the
/// first ones (in the order they were pushed) were analysed.
fn truncated_finding(ctx: &Ctx, limit: usize, dropped: usize) -> Finding {
    let analysed = ctx.sessions.len();
    Finding::new(
        "SCOPE-LIMIT",
        "",
        model::Severity::Info,
        if ctx.de() {
            format!("Nur die ersten {} Sessions wurden analysiert", ctx.fmt_count(analysed))
        } else {
            format!("Only the first {} sessions were analysed", ctx.fmt_count(analysed))
        },
        if ctx.de() {
            format!("Die Aufzeichnung enthielt {} Sessions; die Analyse ist auf {} begrenzt, {} wurden nicht berücksichtigt.", ctx.fmt_count(analysed + dropped), ctx.fmt_count(limit), ctx.fmt_count(dropped))
        } else {
            format!("The capture held {} sessions; the analysis is limited to {}, so {} were left out.", ctx.fmt_count(analysed + dropped), ctx.fmt_count(limit), ctx.fmt_count(dropped))
        },
    )
    .categories(&["scope"])
    .score(100.0)
    .threshold(format!("> {}", ctx.fmt_count(limit)))
    .fact(ctx.l("Analysed sessions", "Analysierte Sessions"), ctx.fmt_count(analysed))
    .fact(ctx.l("Sessions not analysed", "Nicht analysierte Sessions"), ctx.fmt_count(dropped))
    .impact(ctx.l(
        "Findings, counts and capture metrics describe only the analysed part; problems in the rest are not reported.",
        "Befunde, Anzahlen und Kennzahlen beschreiben nur den analysierten Teil; Probleme im Rest werden nicht gemeldet.",
    ))
    .recommend(ctx.l(
        "Narrow the analysis to the relevant time range, process or host so that it stays below the limit.",
        "Die Analyse auf den relevanten Zeitraum, Prozess oder Host eingrenzen, damit sie unter der Grenze bleibt.",
    ))
}

/// Key figures of the whole capture (always part of the report).
fn capture_metrics(ctx: &Ctx) -> Vec<Metric> {
    let l = |en: &'static str, de: &'static str| ctx.l(en, de).to_string();
    let http: Vec<&Session> = ctx.http().collect();
    let bytes: u64 = http.iter().map(|s| s.request_bytes + s.response_bytes).sum();
    let errors = http.iter().filter(|s| s.status >= 400 || s.failed()).count();
    let open = http.iter().filter(|s| s.incomplete()).count();
    let p = ctx.prep();
    let mut hosts: Vec<u32> = p.http.iter().map(|&i| p.host[i]).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let from = ctx.sessions.first().map(|s| s.started).unwrap_or(0);
    let to = ctx.sessions.iter().map(|s| s.end()).max().unwrap_or(from);
    let span_ms = (to - from) as f64 / 1000.0;
    let mut m = vec![
        Metric { label: l("HTTP requests", "HTTP-Requests"), ..Metric::new("requests", "", http.len() as f64, Unit::Count) },
        Metric { label: l("Transferred", "Übertragen"), ..Metric::new("bytes", "", bytes as f64, Unit::Bytes) },
        Metric { label: l("Time span", "Zeitraum"), ..Metric::new("span", "", span_ms, Unit::Ms) },
        Metric { label: l("Hosts", "Hosts"), ..Metric::new("hosts", "", hosts.len() as f64, Unit::Count) },
        Metric { label: l("Errors and failures", "Fehler und Abbrüche"), ..Metric::new("errors", "", errors as f64, Unit::Count) },
        Metric { label: l("Operations", "Vorgänge"), ..Metric::new("operations", "", ctx.ops.len() as f64, Unit::Count) },
    ];
    if open > 0 {
        m.push(Metric { label: l("Still open at capture end", "Bei Aufzeichnungsende noch offen"), ..Metric::new("open", "", open as f64, Unit::Count) });
    }
    if span_ms > 0.0 {
        m.push(Metric { label: l("Requests per second", "Requests pro Sekunde"), ..Metric::new("rate", "", http.len() as f64 / (span_ms / 1000.0), Unit::Rate) });
    }
    m
}

/// Profiles and default options for the UI (see REPORT.md).
pub fn describe(lang: &str) -> String {
    let lang = if lang == "de" { Lang::De } else { Lang::En };
    let d = Options { lang, ..Options::default() };
    let l = |en: &'static str, de: &'static str| s(if lang == Lang::De { de } else { en });
    let v = obj(vec![
        ("schema", n(1.0)),
        (
            "profiles",
            Value::Arr(
                profiles::PROFILES
                    .iter()
                    .map(|p| {
                        let mut o = vec![("id", s(p.id)), ("name", s(profiles::pick(p.name, lang))), ("description", s(profiles::pick(p.description, lang)))];
                        if p.id == "full" {
                            o.push(("default", Value::Bool(true)));
                        }
                        obj(o)
                    })
                    .collect(),
            ),
        ),
        (
            "options",
            obj(vec![
                ("profile", s(&d.profile)),
                ("lang", s(if lang == Lang::De { "de" } else { "en" })),
                ("slowMs", n(d.slow_ms)),
                ("ttfbMs", n(d.ttfb_ms)),
                ("largeRequestBytes", n(d.large_request_bytes as f64)),
                ("largeResponseBytes", n(d.large_response_bytes as f64)),
                ("operationGapMs", n(d.operation_gap_ms)),
                (
                    "networks",
                    Value::Arr(
                        d.networks
                            .iter()
                            .map(|x| obj(vec![("id", s(&x.id)), ("name", s(&x.name)), ("rttMs", n(x.rtt_ms)), ("mbps", n(x.mbps)), ("lossPct", n(x.loss_pct))]))
                            .collect(),
                    ),
                ),
            ]),
        ),
        (
            "optionLabels",
            obj(vec![
                ("slowMs", l("Slow request (ms)", "Langsamer Request (ms)")),
                ("ttfbMs", l("High server time, TTFB (ms)", "Hohe Serverzeit, TTFB (ms)")),
                ("largeRequestBytes", l("Large request (bytes)", "Großer Request (Bytes)")),
                ("largeResponseBytes", l("Large response (bytes)", "Große Response (Bytes)")),
                ("operationGapMs", l("Pause that separates operations (ms)", "Pause zwischen Vorgängen (ms)")),
                ("networks", l("Network profiles for estimates", "Netzprofile für Schätzungen")),
            ]),
        ),
    ]);
    json::compact(&v)
}

// ------------------------------------------------------------------ WASM binding

#[cfg(target_arch = "wasm32")]
mod plugin {
    use crate::model::{AuthInfo, JwtClaims, Kind, OAuthRequest, OAuthResponse, OidcDiscovery, Session, TextInfo, Timers};

    wit_bindgen::generate!({ path: "../../wit/plugin.wit", world: "analyzer-plugin" });
    use exports::quena::plugin::analyzer::{
        AuthInfo as WAuthInfo, Guest, GuestRun, Info, JwtClaims as WJwtClaims, Session as WSession, TextInfo as WTextInfo,
    };

    struct WebDiag;

    struct RunState(std::cell::RefCell<Option<crate::Run>>);

    fn text(t: WTextInfo) -> Box<TextInfo> {
        Box::new(TextInfo {
            header_charset: t.header_charset,
            header_resolved: t.header_resolved,
            document_charset: t.document_charset,
            document_resolved: t.document_resolved,
            bom: t.bom,
            effective: t.effective,
            source: t.source,
            unknown_label: t.unknown_label,
            sampled: t.sampled,
            non_ascii: t.non_ascii,
            utf8_valid: t.utf8_valid,
            decode_errors: t.decode_errors,
            replacement_chars: t.replacement_chars,
            double_encoded: t.double_encoded,
            nul_bytes: t.nul_bytes,
            looks_compressed: t.looks_compressed,
        })
    }

    fn claims(c: WJwtClaims) -> JwtClaims {
        JwtClaims {
            alg: c.alg,
            typ: c.typ,
            iss: c.iss,
            aud: c.aud,
            exp: c.exp,
            nbf: c.nbf,
            iat: c.iat,
            client: c.client,
            tenant: c.tenant,
            ver: c.ver,
            scopes: c.scopes,
            roles: c.roles,
            groups: c.groups,
            groups_overage: c.groups_overage,
            size: c.size,
        }
    }

    fn auth(a: WAuthInfo) -> Box<AuthInfo> {
        Box::new(AuthInfo {
            bearer: a.bearer.map(claims),
            opaque_bearer: a.opaque_bearer,
            oauth_request: a.oauth_request.map(|r| OAuthRequest {
                grant_type: r.grant_type,
                client_id: r.client_id,
                scope: r.scope,
                redirect_uri: r.redirect_uri,
                has_code: r.has_code,
                has_code_verifier: r.has_code_verifier,
                has_refresh_token: r.has_refresh_token,
                has_client_secret: r.has_client_secret,
                has_client_assertion: r.has_client_assertion,
                basic_client_auth: r.basic_client_auth,
            }),
            oauth_response: a.oauth_response.map(|r| OAuthResponse {
                error: r.error,
                error_description: r.error_description,
                error_codes: r.error_codes,
                error_uri: r.error_uri,
                trace_id: r.trace_id,
                correlation_id: r.correlation_id,
                token_type: r.token_type,
                expires_in: r.expires_in,
                has_access_token: r.has_access_token,
                has_refresh_token: r.has_refresh_token,
                has_id_token: r.has_id_token,
                scope: r.scope,
                access_token: r.access_token.map(claims),
                id_token: r.id_token.map(claims),
            }),
            discovery: a.discovery.map(|d| OidcDiscovery {
                issuer: d.issuer,
                authorization_endpoint: d.authorization_endpoint,
                token_endpoint: d.token_endpoint,
                jwks_uri: d.jwks_uri,
                end_session_endpoint: d.end_session_endpoint,
            }),
        })
    }

    fn convert(s: WSession) -> Session {
        let t = s.timers;
        Session {
            id: s.id,
            kind: match s.kind.as_str() {
                "tunnel" => Kind::Tunnel,
                "websocket" => Kind::WebSocket,
                _ => Kind::Http,
            },
            started: s.started,
            duration_ms: s.duration_ms,
            method: s.method,
            url: s.url,
            host: s.host,
            version: s.version,
            status: s.status,
            error: s.error,
            request_bytes: s.request_bytes,
            response_bytes: s.response_bytes,
            response_decoded_bytes: s.response_decoded_bytes,
            content_type: s.content_type,
            request_headers: s.request_headers,
            response_headers: s.response_headers,
            timers: Timers {
                client_begin_request: t.client_begin_request,
                client_done_request: t.client_done_request,
                server_connect_start: t.server_connect_start,
                server_connected: t.server_connected,
                server_begin_request: t.server_begin_request,
                server_done_request: t.server_done_request,
                server_got_first_byte: t.server_got_first_byte,
                server_done_response: t.server_done_response,
                client_done_response: t.client_done_response,
                dns_ms: t.dns_ms,
                tcp_connect_ms: t.tcp_connect_ms,
                tls_handshake_ms: t.tls_handshake_ms,
            },
            client_connection: s.client_connection,
            server_connection_reused: s.server_connection_reused,
            tls_version: s.tls_version,
            process: s.process,
            request_body_hash: s.request_body_hash,
            response_body_hash: s.response_body_hash,
            request_text: s.request_text.map(text),
            response_text: s.response_text.map(text),
            request_decoding_error: s.request_decoding_error,
            response_decoding_error: s.response_decoding_error,
            auth: s.auth.map(auth),
        }
    }

    impl Guest for WebDiag {
        type Run = RunState;

        fn get_info() -> Info {
            Info { id: crate::ID.into(), name: "Diagnostics".into(), version: env!("CARGO_PKG_VERSION").into(), title: "Diagnostics".into() }
        }

        fn describe(lang: String) -> String {
            crate::describe(&lang)
        }
    }

    impl GuestRun for RunState {
        fn new(options: String) -> Self {
            RunState(std::cell::RefCell::new(Some(crate::Run::new(&options))))
        }

        fn push(&self, batch: Vec<WSession>) -> Result<(), String> {
            match self.0.borrow_mut().as_mut() {
                Some(r) => {
                    r.push(batch.into_iter().map(convert));
                    Ok(())
                }
                None => Err("run already finished".into()),
            }
        }

        fn finish(&self) -> Result<String, String> {
            self.0.borrow_mut().take().map(|r| r.finish()).ok_or_else(|| "run already finished".into())
        }
    }

    export!(WebDiag);
}
