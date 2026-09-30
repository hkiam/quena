//! Character encoding of text bodies (`ENC-*`).
//!
//! The host examines the first 256 KiB of every decoded textual body (JSON, XML, HTML,
//! `text/*`, form posts …) with the same rules as the display (`quena_body::charset`:
//! BOM > `Content-Type` charset > in-document declaration > default of the type) and passes
//! only facts ([`TextInfo`]): declarations, the effective charset, whether the bytes are
//! valid UTF-8, decode errors, U+FFFD, traces of double encoding, NUL bytes.
//!
//! Every body gets at most one verdict, the most specific one, so that one cause is reported
//! once ([`verdict`]): undecodable Content-Encoding > compressed data as text > binary data
//! as text > unknown label > double encoding > conflicting declarations > JSON not in
//! UTF-8 > declared charset contradicts the bytes > no declaration. Characters already lost
//! (U+FFFD in valid text, `ENC-LOST`) are reported besides. Only non-ASCII bytes make a
//! charset matter: pure ASCII text is never reported as wrongly declared.
//!
//! Aggregation: per endpoint and direction for problems of the data (mismatch, double
//! encoding, lost characters, JSON, binary, decoding), per host and direction for
//! configuration problems (conflicts, unknown labels, missing declarations).
use std::collections::{BTreeMap, HashSet};

use super::request::emit;
use crate::model::{Analyzer, Confidence, Ctx, Finding, Session, Severity, TextInfo};
use crate::util;

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(Charsets), Box::new(Declarations)]
}

/// Bytes the host examines per body (`TEXT_SAMPLE` on the host side): a body with this many
/// sampled bytes was probably longer, so statements about "all bytes" are about the sample.
pub const SAMPLE_BYTES: u64 = 256 << 10;
/// Declared charset contradicted by the bytes with decode errors: critical from this many
/// sessions of an endpoint …
pub const MISMATCH_CRITICAL_SESSIONS: usize = 3;
/// … that are at least this share of its textual bodies.
pub const MISMATCH_CRITICAL_SHARE: f64 = 0.25;
/// Double-encoding traces per endpoint (all sessions) below this are not reported: a single
/// hit can be real text (`„Fuß“` reads like `ß` + `“`).
pub const DOUBLE_MIN_HITS: u32 = 2;
/// From this many traces the double encoding is certain (high confidence).
pub const DOUBLE_HIGH_CONFIDENCE_HITS: u32 = 6;
/// Double encoding is critical from this many sessions (and share) of an endpoint.
pub const DOUBLE_CRITICAL_SESSIONS: usize = 10;
pub const DOUBLE_CRITICAL_SHARE: f64 = 0.25;
/// Lost characters (U+FFFD) are a warning from this many sessions of an endpoint.
pub const LOST_WARN_SESSIONS: usize = 3;
/// Corrupt compressed bodies are critical from this many sessions (and share) of an endpoint.
pub const DECODE_CRITICAL_SESSIONS: usize = 3;
pub const DECODE_CRITICAL_SHARE: f64 = 0.25;

// ------------------------------------------------------------------ classification

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
enum Dir {
    Request,
    Response,
}

impl Dir {
    fn key(self) -> &'static str {
        match self {
            Dir::Request => "request",
            Dir::Response => "response",
        }
    }
}

/// The one verdict of a body (see the module docs for the order).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
enum Verdict {
    /// ENC-DECODE: Content-Encoding data is corrupt.
    DecodeInvalid,
    /// ENC-DECODE: a coding the host (and most clients) cannot decode.
    DecodeUnsupported,
    /// ENC-DECODE: the decoded body is itself compressed (no or one Content-Encoding too few).
    Compressed,
    /// ENC-BINARY: NUL bytes in a text type.
    Binary,
    /// ENC-UNKNOWN: unknown charset label.
    Unknown,
    /// ENC-DOUBLE: UTF-8 decoded as Latin-1 and encoded again.
    Double,
    /// ENC-CONFLICT: BOM, header and document declare different charsets.
    Conflict,
    /// ENC-JSON: JSON not in UTF-8.
    Json,
    /// ENC-MISMATCH: UTF-8 (declared or the JSON/XML default), bytes are not UTF-8.
    NotUtf8,
    /// ENC-MISMATCH: bytes invalid in another declared charset.
    Invalid,
    /// ENC-MISMATCH: single-byte (legacy) charset declared, bytes are UTF-8.
    Utf8AsLegacy,
    /// ENC-MISSING: non-ASCII text without any declaration, for a type without UTF-8 default.
    Missing,
}

impl Verdict {
    fn rule(self) -> &'static str {
        match self {
            Verdict::DecodeInvalid | Verdict::DecodeUnsupported | Verdict::Compressed => "ENC-DECODE",
            Verdict::Binary => "ENC-BINARY",
            Verdict::Unknown => "ENC-UNKNOWN",
            Verdict::Double => "ENC-DOUBLE",
            Verdict::Conflict => "ENC-CONFLICT",
            Verdict::Json => "ENC-JSON",
            Verdict::NotUtf8 | Verdict::Invalid | Verdict::Utf8AsLegacy => "ENC-MISMATCH",
            Verdict::Missing => "ENC-MISSING",
        }
    }
    /// Part of the finding key that tells variants of one rule apart.
    fn variant(self) -> &'static str {
        match self {
            Verdict::DecodeInvalid => "invalid|",
            Verdict::DecodeUnsupported => "unsupported|",
            Verdict::Compressed => "compressed|",
            Verdict::NotUtf8 => "not-utf8|",
            Verdict::Invalid => "invalid|",
            Verdict::Utf8AsLegacy => "utf8|",
            _ => "",
        }
    }
    /// Configuration problems are reported per host, data problems per endpoint.
    fn per_host(self) -> bool {
        matches!(self, Verdict::Conflict | Verdict::Unknown | Verdict::Missing)
    }
}

/// One textual (or undecodable) body.
struct Item<'a> {
    s: &'a Session,
    /// Index in `ctx.sessions`.
    i: usize,
    dir: Dir,
    t: Option<&'a TextInfo>,
    error: Option<&'a str>,
    verdict: Option<Verdict>,
}

fn utf16(name: &str) -> bool {
    name.eq_ignore_ascii_case("UTF-16LE") || name.eq_ignore_ascii_case("UTF-16BE")
}

fn utf8(name: &str) -> bool {
    name.eq_ignore_ascii_case("UTF-8")
}

pub fn is_json(mime: &str) -> bool {
    mime == "application/json" || mime.ends_with("+json") || mime.ends_with("/json")
}

fn is_xml(mime: &str) -> bool {
    mime == "application/xml" || mime == "text/xml" || mime.ends_with("+xml")
}

/// Types whose text has no UTF-8 default, so a missing charset leaves clients guessing:
/// `text/*` (except XML and the always-UTF-8 formats) and form posts.
pub fn needs_charset(mime: &str) -> bool {
    (mime.starts_with("text/") && !is_xml(mime) && !is_json(mime) && !matches!(mime, "text/event-stream" | "text/vtt" | "text/calendar"))
        || mime == "application/x-www-form-urlencoded"
}

/// Declared charsets (BOM, header, document; resolved WHATWG names, UTF-16 byte orders as
/// one family) — two or more distinct ones are a conflict.
fn declarations(t: &TextInfo) -> Vec<&str> {
    let mut v: Vec<&str> = [t.bom.as_deref(), t.header_resolved.as_deref(), t.document_resolved.as_deref()]
        .into_iter()
        .flatten()
        .map(|n| if utf16(n) || n.eq_ignore_ascii_case("UTF-16") { "UTF-16" } else { n })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn verdict(mime: &str, t: Option<&TextInfo>, error: Option<&str>) -> Option<Verdict> {
    if let Some(e) = error {
        return Some(if e.starts_with("unsupported") { Verdict::DecodeUnsupported } else { Verdict::DecodeInvalid });
    }
    let t = t?;
    let eff = t.effective.as_str();
    if t.looks_compressed.is_some() {
        return Some(Verdict::Compressed);
    }
    if t.nul_bytes > 0 && !utf16(eff) {
        return Some(Verdict::Binary);
    }
    if t.unknown_label {
        return Some(Verdict::Unknown);
    }
    if t.decode_errors == 0 && t.double_encoded > 0 && (utf8(eff) || utf16(eff)) {
        return Some(Verdict::Double);
    }
    if declarations(t).len() > 1 {
        return Some(Verdict::Conflict);
    }
    if is_json(mime) && !utf8(eff) {
        return Some(Verdict::Json);
    }
    if t.decode_errors > 0 {
        return Some(if utf8(eff) { Verdict::NotUtf8 } else { Verdict::Invalid });
    }
    if !utf8(eff) && !utf16(eff) && matches!(t.source.as_str(), "header" | "document") && t.utf8_valid && t.non_ascii {
        return Some(Verdict::Utf8AsLegacy);
    }
    if t.non_ascii && t.header_charset.is_none() && t.bom.is_none() && t.document_charset.is_none() && needs_charset(mime) {
        return Some(Verdict::Missing);
    }
    None
}

/// `type/subtype` of a Content-Type, lower-case.
fn mime_of(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// Classification of all bodies, shared by both analyzers (cached in `Prep`).
pub(crate) struct Classified {
    /// Bodies with a verdict or with lost characters: (session index, direction, verdict).
    flagged: Vec<(usize, Dir, Option<Verdict>)>,
    /// Textual (or undecodable) bodies per endpoint id / host id, per direction.
    ep_total: [Vec<u32>; 2],
    host_total: [Vec<u32>; 2],
}

impl Classified {
    fn build(ctx: &Ctx) -> Classified {
        let p = ctx.prep();
        let mut c = Classified { flagged: vec![], ep_total: [vec![0; p.endpoint_strs.len()], vec![0; p.endpoint_strs.len()]], host_total: [vec![0; p.host_strs.len()], vec![0; p.host_strs.len()]] };
        for &i in &p.http {
            let s = &ctx.sessions[i];
            for dir in [Dir::Request, Dir::Response] {
                let (t, error) = body(s, dir);
                if t.is_none() && error.is_none() {
                    continue;
                }
                let v = match dir {
                    Dir::Request => verdict(&mime_of(s.req_header("content-type").unwrap_or("")), t, error),
                    Dir::Response => verdict(p.mime_of(i), t, error),
                };
                for (totals, id) in [(&mut c.ep_total, p.endpoint[i]), (&mut c.host_total, p.host[i])] {
                    if let Some(n) = totals[dir as usize].get_mut(id as usize) {
                        *n += 1;
                    }
                }
                if v.is_some() || t.is_some_and(|t| t.replacement_chars > 0) {
                    c.flagged.push((i, dir, v));
                }
            }
        }
        c
    }
    fn total(&self, ctx: &Ctx, i: usize, dir: Dir, per_host: bool) -> usize {
        let p = ctx.prep();
        let (v, id) = if per_host { (&self.host_total, p.host[i]) } else { (&self.ep_total, p.endpoint[i]) };
        v[dir as usize].get(id as usize).copied().unwrap_or(1) as usize
    }
}

/// Facts and decoding error of one direction.
fn body(s: &Session, dir: Dir) -> (Option<&TextInfo>, Option<&str>) {
    match dir {
        Dir::Request => (s.request_text.as_deref(), s.request_decoding_error.as_deref()),
        Dir::Response => (s.response_text.as_deref(), s.response_decoding_error.as_deref()),
    }
}

fn item<'a>(ctx: &'a Ctx, i: usize, dir: Dir, verdict: Option<Verdict>) -> Item<'a> {
    let s = &ctx.sessions[i];
    let (t, error) = body(s, dir);
    Item { s, i, dir, t, error, verdict }
}

/// Group subject: host or endpoint id of the session (per the verdict's aggregation).
fn subject(ctx: &Ctx, it: &Item, per_host: bool) -> u32 {
    let p = ctx.prep();
    if per_host { p.host[it.i] } else { p.endpoint[it.i] }
}

fn subject_name<'a>(ctx: &'a Ctx, it: &Item, per_host: bool) -> &'a str {
    let p = ctx.prep();
    if per_host { p.host_of(it.i) } else { p.endpoint_of(it.i) }
}

/// Everything a rule needs about one group of bodies.
struct Group<'a, 'b> {
    verdict: Verdict,
    /// Rule id and key variant (`verdict`'s, or ENC-LOST's).
    rule: &'static str,
    variant: &'static str,
    dir: Dir,
    /// Host or endpoint.
    subject: &'a str,
    list: Vec<&'b Item<'a>>,
    /// Textual bodies of the same subject and direction (denominator of shares).
    total: usize,
}

impl Group<'_, '_> {
    fn n(&self) -> usize {
        self.list.len()
    }
    fn share(&self) -> f64 {
        self.n() as f64 / self.total.max(1) as f64
    }
    fn facts(&self) -> impl Iterator<Item = &TextInfo> {
        self.list.iter().filter_map(|it| it.t)
    }
    fn sum(&self, f: impl Fn(&TextInfo) -> u32) -> u64 {
        self.facts().map(|t| f(t) as u64).sum()
    }
    /// Some body filled the whole sample (it was probably longer than what was examined).
    fn sampled_partly(&self) -> bool {
        self.facts().any(|t| t.sampled >= SAMPLE_BYTES)
    }
    fn ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.list.iter().map(|it| it.s.id)
    }
}

/// Values with counts, most frequent first: `ISO-8859-1 (3), latin1 (1)`.
fn top(ctx: &Ctx, values: impl Iterator<Item = String>, n: usize) -> String {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for v in values {
        *m.entry(v).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let more = v.len() > n;
    let mut out: Vec<String> = v.into_iter().take(n).map(|(k, c)| format!("{} ({})", util::short(&k, 60), ctx.fmt_count(c))).collect();
    if more {
        out.push("…".into());
    }
    out.join(", ")
}

/// How a body declares its charset: `header ISO-8859-1, document UTF-8, BOM UTF-8`.
fn declared_as(ctx: &Ctx, t: &TextInfo) -> String {
    let mut v = vec![];
    if let Some(b) = &t.bom {
        v.push(format!("BOM {b}"));
    }
    if let Some(h) = &t.header_charset {
        v.push(format!("{} {h}", ctx.l("header", "Header")));
    }
    if let Some(d) = &t.document_charset {
        v.push(format!("{} {d}", ctx.l("document", "Dokument")));
    }
    if v.is_empty() {
        v.push(format!("{} ({})", ctx.l("none", "keine"), ctx.l("default", "Standard")));
    }
    v.join(", ")
}

fn what<'a>(ctx: &Ctx, dir: Dir) -> &'a str {
    match dir {
        Dir::Request => ctx.l("request bodies", "Request-Bodies"),
        Dir::Response => ctx.l("response bodies", "Response-Bodies"),
    }
}

/// Who produces the body: the client for requests, the server for responses.
fn producer<'a>(ctx: &Ctx, dir: Dir) -> &'a str {
    match dir {
        Dir::Request => ctx.l("the client", "der Client"),
        Dir::Response => ctx.l("the server", "der Server"),
    }
}

fn severity_by(n: usize, share: f64, min: usize, min_share: f64, high: Severity, low: Severity) -> Severity {
    if n >= min && share >= min_share { high } else { low }
}

/// Finding skeleton shared by all rules: key `RULE|direction|variant|subject`, facts about
/// the sample, all sessions.
/// Observations start with "<n> <bodies> <verb> …"; for exactly one body the subject, the
/// verb and possessive pronouns go into the singular ("1 response body declares …").
fn singular(observation: &str) -> String {
    const SUBJECTS: [(&str, &str); 4] = [
        ("1 request bodies", "1 request body"),
        ("1 response bodies", "1 response body"),
        ("1 Request-Bodies", "1 Request-Body"),
        ("1 Response-Bodies", "1 Response-Body"),
    ];
    // (plural, singular) verb forms and pronouns used right after the subject.
    const WORDS: [(&str, &str); 22] = [
        (" deklarieren ", " deklariert "),
        (" sind kein ", " ist kein "),
        (" enthalten ", " enthält "),
        (" nennen ", " nennt "),
        (" beginnen ", " beginnt "),
        (" verwenden ", " verwendet "),
        ("ihre Bytes sind", "seine Bytes sind"),
        ("ihren Zeichensatz", "seinen Zeichensatz"),
        (" declare ", " declares "),
        (" are not valid", " is not valid"),
        (" contain ", " contains "),
        (" name a ", " names a "),
        (" name no ", " names no "),
        (" start ", " starts "),
        (" use a ", " uses a "),
        ("their bytes", "its bytes"),
        ("their charset", "its charset"),
        (" but contain ", " but contains "),
        (" mit Text-Typ beginnen", " mit Text-Typ beginnt"),
        (" with a text type start", " with a text type starts"),
        (" mit Text-Typ (", " mit Text-Typ ("),
        (" with a text type (", " with a text type ("),
    ];
    let Some((plural, one)) = SUBJECTS.iter().find(|(p, _)| observation.starts_with(p)) else { return observation.to_string() };
    let mut s = format!("{one}{}", &observation[plural.len()..]);
    // Only the first sentence (the subject's clause) is changed.
    let end = s.find(". ").map(|i| i + 1).unwrap_or(s.len());
    let (mut head, tail) = (s[..end].to_string(), s[end..].to_string());
    for (p, one) in WORDS {
        if let Some(i) = head.find(p) {
            head.replace_range(i..i + p.len(), one);
        }
    }
    s = head + &tail;
    s
}

fn base(ctx: &Ctx, g: &Group, severity: Severity, title: (&str, &str), observation: String) -> Finding {
    let observation = if g.n() == 1 { singular(&observation) } else { observation };
    let rule = g.rule;
    let key = format!("{}|{}{}", g.dir.key(), g.variant, g.subject);
    let title = format!("{} {}", ctx.l(title.0, title.1), util::short(g.subject, 80));
    let mut f = Finding::new(rule, &key, severity, title, observation)
        .categories(&["encoding", "correctness"])
        .score(util::scale(g.n() as f64, 0.0, 50.0) * 0.6 + g.share() * 40.0)
        .fact(ctx.l("Affected bodies", "Betroffene Bodies"), format!("{} / {}", ctx.fmt_count(g.n()), ctx.fmt_count(g.total)))
        .fact(ctx.l("Direction", "Richtung"), what(ctx, g.dir))
        .sessions(g.ids());
    if g.sampled_partly() {
        f = f.fact(
            ctx.l("Examined", "Untersucht"),
            if ctx.de() { format!("die ersten {} jedes Bodys", ctx.fmt_bytes(SAMPLE_BYTES as f64)) } else { format!("the first {} of each body", ctx.fmt_bytes(SAMPLE_BYTES as f64)) },
        );
    }
    f
}

// ------------------------------------------------------------------ analyzers

/// ENC-MISMATCH, ENC-CONFLICT, ENC-DOUBLE, ENC-LOST, ENC-UNKNOWN, ENC-BINARY, ENC-DECODE.
struct Charsets;

impl Analyzer for Charsets {
    fn id(&self) -> &'static str {
        "ENC-MISMATCH"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        run(ctx, out, &["ENC-MISMATCH", "ENC-CONFLICT", "ENC-DOUBLE", "ENC-LOST", "ENC-UNKNOWN", "ENC-BINARY", "ENC-DECODE"]);
    }
}

/// ENC-JSON, ENC-MISSING: declarations that are missing or not what the format expects.
struct Declarations;

impl Analyzer for Declarations {
    fn id(&self) -> &'static str {
        "ENC-JSON"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        run(ctx, out, &["ENC-JSON", "ENC-MISSING"]);
    }
}

fn run(ctx: &Ctx, out: &mut Vec<Finding>, rules: &[&str]) {
    let c = ctx.prep().encoding.get_or_init(|| Classified::build(ctx));
    if c.flagged.is_empty() {
        return;
    }
    let items: Vec<Item> = c.flagged.iter().map(|&(i, dir, v)| item(ctx, i, dir, v)).collect();
    // Hosts whose responses are UTF-8 declared as a legacy charset: a likely source of
    // double encoding in what clients send back.
    let legacy_hosts: HashSet<u32> = items.iter().filter(|it| it.dir == Dir::Response && it.verdict == Some(Verdict::Utf8AsLegacy)).map(|it| ctx.prep().host[it.i]).collect();

    let mut by_rule: BTreeMap<&'static str, Vec<Finding>> = BTreeMap::new();
    let groups = util::group_by(items.iter().filter(|it| it.verdict.is_some_and(|v| rules.contains(&v.rule()))), |it| {
        let v = it.verdict.unwrap_or(Verdict::Missing);
        (v, it.dir, subject(ctx, it, v.per_host()))
    });
    for ((v, dir, _), list) in groups {
        let total = c.total(ctx, list[0].i, dir, v.per_host()).max(list.len());
        let g = Group { verdict: v, rule: v.rule(), variant: v.variant(), dir, subject: subject_name(ctx, list[0], v.per_host()), list, total };
        let f = match v {
            Verdict::NotUtf8 | Verdict::Invalid | Verdict::Utf8AsLegacy => Some(mismatch(ctx, &g)),
            Verdict::Conflict => Some(conflict(ctx, &g)),
            Verdict::Double => double(ctx, &g, legacy_hosts.contains(&ctx.prep().host[g.list[0].i])),
            Verdict::Json => Some(json(ctx, &g)),
            Verdict::Missing => Some(missing(ctx, &g)),
            Verdict::Unknown => Some(unknown(ctx, &g)),
            Verdict::Binary => Some(binary(ctx, &g)),
            Verdict::DecodeInvalid | Verdict::DecodeUnsupported | Verdict::Compressed => Some(decode(ctx, &g)),
        };
        if let Some(f) = f {
            by_rule.entry(v.rule()).or_default().push(f);
        }
    }
    // ENC-LOST besides the verdicts (not for bodies that are no readable text at all).
    if rules.contains(&"ENC-LOST") {
        let lost = items.iter().filter(|it| {
            !matches!(it.verdict, Some(Verdict::DecodeInvalid | Verdict::DecodeUnsupported | Verdict::Compressed | Verdict::Binary)) && it.t.is_some_and(|t| t.replacement_chars > 0)
        });
        for ((dir, _), list) in util::group_by(lost, |it| (it.dir, subject(ctx, it, false))) {
            let total = c.total(ctx, list[0].i, dir, false).max(list.len());
            let g = Group { verdict: Verdict::Missing, rule: "ENC-LOST", variant: "", dir, subject: subject_name(ctx, list[0], false), list, total };
            by_rule.entry("ENC-LOST").or_default().push(lost_chars(ctx, &g));
        }
    }
    for (_, list) in by_rule {
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ ENC-MISMATCH

fn mismatch(ctx: &Ctx, g: &Group) -> Finding {
    let declared = top(ctx, g.facts().map(|t| declared_as(ctx, t)), 3);
    let errors = g.sum(|t| t.decode_errors);
    let doubles = g.sum(|t| t.double_encoded);
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    match g.verdict {
        Verdict::Utf8AsLegacy => {
            let eff = top(ctx, g.facts().map(|t| t.effective.clone()), 3);
            let mut f = base(
                ctx,
                g,
                Severity::Warning,
                ("UTF-8 text declared as a legacy charset:", "UTF-8-Text als Alt-Zeichensatz deklariert:"),
                if ctx.de() {
                    format!("{n} {dir} deklarieren {eff}, ihre Bytes sind aber gültiges UTF-8 mit Nicht-ASCII-Zeichen.")
                } else {
                    format!("{n} {dir} declare {eff}, but their bytes are valid UTF-8 with non-ASCII characters.")
                },
            )
            .threshold(ctx.l("single-byte/legacy charset declared, bytes valid UTF-8 with bytes ≥ 0x80", "Einzelbyte-/Alt-Zeichensatz deklariert, Bytes gültiges UTF-8 mit Bytes ≥ 0x80"))
            .fact(ctx.l("Declared", "Deklariert"), declared)
            .impact(ctx.l(
                "Clients that honour the declaration show every non-ASCII character as two or three wrong ones: “Grüße” becomes “GrÃ¼ÃŸe”. If such a client stores the text and sends it back as UTF-8, it is double-encoded from then on.",
                "Clients, die sich an die Deklaration halten, zeigen jedes Nicht-ASCII-Zeichen als zwei oder drei falsche an: aus „Grüße“ wird „GrÃ¼ÃŸe“. Speichert ein solcher Client den Text und sendet ihn als UTF-8 zurück, ist er ab dann doppelt kodiert.",
            ))
            .hypothesis(if ctx.de() {
                format!("{} erzeugt UTF-8, die Deklaration (Content-Type bzw. Dokument) stammt aus einer alten Standardeinstellung.", producer(ctx, g.dir))
            } else {
                format!("{} produces UTF-8, but the declaration (Content-Type or document) comes from an old default setting.", producer(ctx, g.dir))
            })
            .recommend(ctx.l("Declare the charset the bytes are in: charset=utf-8 (and the same in the XML declaration / HTML meta).", "Den Zeichensatz deklarieren, in dem die Bytes vorliegen: charset=utf-8 (und ebenso in XML-Deklaration / HTML-Meta)."))
            .next_step(ctx.l("Open a session and switch the text view to UTF-8: if the text then reads correctly, only the label is wrong.", "Eine Session öffnen und die Textansicht auf UTF-8 umstellen: liest sich der Text dann richtig, ist nur die Deklaration falsch."));
            if g.sampled_partly() {
                // Validity of the whole body is only known for the sample.
                f = f.confidence(Confidence::Medium);
            }
            f
        }
        _ => {
            let utf = g.verdict == Verdict::NotUtf8;
            let severity = severity_by(g.n(), g.share(), MISMATCH_CRITICAL_SESSIONS, MISMATCH_CRITICAL_SHARE, Severity::Critical, Severity::Warning);
            let implicit = g.facts().all(|t| t.source == "default");
            let eff = top(ctx, g.facts().map(|t| t.effective.clone()), 3);
            let mut f = base(
                ctx,
                g,
                severity,
                if utf { ("Declared UTF-8, but the bytes are not UTF-8:", "UTF-8 deklariert, die Bytes sind aber kein UTF-8:") } else { ("Bytes invalid in the declared charset:", "Bytes im deklarierten Zeichensatz ungültig:") },
                match (utf, implicit, ctx.de()) {
                    (true, true, true) => format!("{n} {dir} sind kein gültiges UTF-8 ({} fehlerhafte Sequenzen), obwohl der Typ ohne Angabe UTF-8 bedeutet (JSON/XML).", ctx.fmt_count(errors as usize)),
                    (true, true, false) => format!("{n} {dir} are not valid UTF-8 ({} malformed sequences), although the type means UTF-8 without a declaration (JSON/XML).", ctx.fmt_count(errors as usize)),
                    (true, false, true) => format!("{n} {dir} deklarieren UTF-8, enthalten aber {} ungültige UTF-8-Sequenzen.", ctx.fmt_count(errors as usize)),
                    (true, false, false) => format!("{n} {dir} declare UTF-8 but contain {} invalid UTF-8 sequences.", ctx.fmt_count(errors as usize)),
                    (false, _, true) => format!("{n} {dir} enthalten {} Bytefolgen, die in {eff} ungültig sind.", ctx.fmt_count(errors as usize)),
                    (false, _, false) => format!("{n} {dir} contain {} byte sequences that are invalid in {eff}.", ctx.fmt_count(errors as usize)),
                },
            )
            .threshold(if ctx.de() {
                format!("≥ 1 ungültige Sequenz; kritisch ab {} Sessions und {} der Text-Bodies", MISMATCH_CRITICAL_SESSIONS, ctx.fmt_pct(MISMATCH_CRITICAL_SHARE))
            } else {
                format!("≥ 1 invalid sequence; critical from {} sessions and {} of the text bodies", MISMATCH_CRITICAL_SESSIONS, ctx.fmt_pct(MISMATCH_CRITICAL_SHARE))
            })
            .fact(ctx.l("Declared", "Deklariert"), declared)
            .fact(ctx.l("Invalid sequences", "Ungültige Sequenzen"), ctx.fmt_count(errors as usize))
            .impact(ctx.l(
                "Characters get lost: a decoder replaces every invalid sequence with U+FFFD, so “Grüße” sent in ISO-8859-1 but read as UTF-8 becomes “Gr��e”. Strict parsers (many JSON and XML libraries) reject the whole body; once the text is stored again, the original characters cannot be recovered.",
                "Zeichen gehen verloren: ein Decoder ersetzt jede ungültige Sequenz durch U+FFFD, aus „Grüße“, in ISO-8859-1 gesendet und als UTF-8 gelesen, wird „Gr��e“. Strikte Parser (viele JSON- und XML-Bibliotheken) lehnen den ganzen Body ab; wird der Text erneut gespeichert, sind die ursprünglichen Zeichen nicht mehr herstellbar.",
            ))
            .hypothesis(if ctx.de() {
                format!("{} schreibt den Text in einem Alt-Zeichensatz (z. B. windows-1252 aus einer Datenbank, Datei oder String-Konvertierung), deklariert aber UTF-8.", producer(ctx, g.dir))
            } else {
                format!("{} writes the text in a legacy charset (e.g. windows-1252 from a database, file or string conversion) but declares UTF-8.", producer(ctx, g.dir))
            })
            .recommend(ctx.l(
                "Encode the text as UTF-8 where it is serialised (response writer, template, database driver); declare another charset only if the bytes really are in it.",
                "Den Text dort als UTF-8 kodieren, wo er serialisiert wird (Response-Writer, Template, Datenbanktreiber); einen anderen Zeichensatz nur deklarieren, wenn die Bytes wirklich darin vorliegen.",
            ))
            .next_step(ctx.l("Open a session: the text view marks the invalid bytes; try windows-1252 as the display charset to see the intended text.", "Eine Session öffnen: die Textansicht markiert die ungültigen Bytes; mit windows-1252 als Anzeige-Zeichensatz wird der gemeinte Text sichtbar."));
            if doubles > 0 {
                f = f.fact(ctx.l("Traces of double encoding as well", "Außerdem Spuren doppelter Kodierung"), ctx.fmt_count(doubles as usize));
            }
            f
        }
    }
}

// ------------------------------------------------------------------ ENC-CONFLICT

fn conflict(ctx: &Ctx, g: &Group) -> Finding {
    let combos = top(ctx, g.facts().map(|t| declared_as(ctx, t)), 3);
    let winner = top(ctx, g.facts().map(|t| format!("{} ({})", t.effective, t.source)), 3);
    let broken = g.facts().filter(|t| t.decode_errors > 0).count();
    let non_ascii = g.facts().any(|t| t.non_ascii);
    let severity = if broken >= MISMATCH_CRITICAL_SESSIONS && broken as f64 / g.total.max(1) as f64 >= MISMATCH_CRITICAL_SHARE {
        Severity::Critical
    } else if non_ascii {
        Severity::Warning
    } else {
        Severity::Info
    };
    let n = ctx.fmt_count(g.n());
    let dir = what(ctx, g.dir);
    let mut f = base(
        ctx,
        g,
        severity,
        ("Contradicting charset declarations:", "Widersprüchliche Zeichensatz-Angaben:"),
        if ctx.de() {
            format!("{n} {dir} deklarieren ihren Zeichensatz mehrfach und unterschiedlich: {combos}.")
        } else {
            format!("{n} {dir} declare their charset more than once, differently: {combos}.")
        },
    )
    .threshold(ctx.l("BOM, Content-Type charset and in-document declaration name different charsets", "BOM, Content-Type-Charset und Deklaration im Dokument nennen verschiedene Zeichensätze"))
    .fact(ctx.l("Used by browsers", "Von Browsern verwendet"), winner)
    .impact(ctx.l(
        "Browsers and most HTTP clients take the BOM first, then the Content-Type charset, and the in-document declaration (<?xml encoding>, <meta charset>) only when neither is there. XML parsers fed the bytes directly, and every tool that saves the body to a file, use the in-document declaration instead — the same body reads differently depending on the client.",
        "Browser und die meisten HTTP-Clients nehmen zuerst die BOM, dann das Charset im Content-Type, die Deklaration im Dokument (<?xml encoding>, <meta charset>) nur, wenn beides fehlt. XML-Parser, die die Bytes direkt lesen, und jedes Werkzeug, das den Body als Datei speichert, verwenden dagegen die Deklaration im Dokument – derselbe Body liest sich je nach Client verschieden.",
    ))
    .recommend(ctx.l("Make all declarations name the charset the bytes are really in (preferably UTF-8 everywhere), or drop the redundant ones.", "Alle Angaben auf den Zeichensatz bringen, in dem die Bytes wirklich vorliegen (am besten überall UTF-8), oder die überflüssigen entfernen."));
    if broken > 0 {
        f = f
            .fact(ctx.l("Bodies misread with the winning declaration", "Mit der gültigen Angabe falsch gelesen"), ctx.fmt_count(broken))
            .hypothesis(ctx.l("The winning declaration is the wrong one: the bytes contain sequences that are invalid in it.", "Die gültige Angabe ist die falsche: die Bytes enthalten darin ungültige Sequenzen."));
    } else if g.facts().any(|t| t.utf8_valid && t.non_ascii && !utf8(&t.effective)) {
        f = f.hypothesis(ctx.l(
            "The bytes are valid UTF-8, so the UTF-8 declaration is probably right and the other one a leftover default; clients that follow the other one show “GrÃ¼ÃŸe” for “Grüße”.",
            "Die Bytes sind gültiges UTF-8, die UTF-8-Angabe ist also vermutlich richtig und die andere ein übrig gebliebener Standardwert; Clients, die der anderen folgen, zeigen „GrÃ¼ÃŸe“ statt „Grüße“.",
        ));
    }
    if !non_ascii {
        f = ascii_only(ctx, f);
    }
    f
}

/// Pure ASCII today: harmless until the first non-ASCII character.
fn ascii_only(ctx: &Ctx, mut f: Finding) -> Finding {
    f.impact.push(' ');
    f.impact.push_str(ctx.l(
        "The examined bodies contain only ASCII, so nothing is misread yet — the first umlaut or euro sign will be.",
        "Die untersuchten Bodies enthalten nur ASCII, noch wird also nichts falsch gelesen – der erste Umlaut oder das erste Euro-Zeichen schon.",
    ));
    f
}

// ------------------------------------------------------------------ ENC-DOUBLE

fn double(ctx: &Ctx, g: &Group, legacy_responses: bool) -> Option<Finding> {
    let hits = g.sum(|t| t.double_encoded);
    if hits < DOUBLE_MIN_HITS as u64 {
        return None;
    }
    let certain = hits >= DOUBLE_HIGH_CONFIDENCE_HITS as u64;
    let severity = if certain && g.n() >= DOUBLE_CRITICAL_SESSIONS && g.share() >= DOUBLE_CRITICAL_SHARE { Severity::Critical } else { Severity::Warning };
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    let mut f = base(
        ctx,
        g,
        severity,
        ("Double-encoded UTF-8:", "Doppelt kodiertes UTF-8:"),
        if ctx.de() {
            format!("{n} {dir} enthalten {} typische Spuren doppelt kodierten Textes (z. B. „Ã¼“ statt „ü“, „â€““ statt „–“).", ctx.fmt_count(hits as usize))
        } else {
            format!("{n} {dir} contain {} typical traces of double-encoded text (e.g. “Ã¼” for “ü”, “â€“” for “–”).", ctx.fmt_count(hits as usize))
        },
    )
    .confidence(if certain { Confidence::High } else { Confidence::Medium })
    .threshold(if ctx.de() {
        format!("≥ {DOUBLE_MIN_HITS} Spuren je Endpunkt; kritisch ab {DOUBLE_CRITICAL_SESSIONS} Sessions und {} der Text-Bodies", ctx.fmt_pct(DOUBLE_CRITICAL_SHARE))
    } else {
        format!("≥ {DOUBLE_MIN_HITS} traces per endpoint; critical from {DOUBLE_CRITICAL_SESSIONS} sessions and {} of the text bodies", ctx.fmt_pct(DOUBLE_CRITICAL_SHARE))
    })
    .fact(ctx.l("Traces", "Spuren"), ctx.fmt_count(hits as usize))
    .impact(ctx.l(
        "The bytes are valid UTF-8, but the text itself is already wrong: users see “GrÃ¼ÃŸe” instead of “Grüße”, searches and comparisons fail, and every further round trip makes it worse. No client setting can repair it.",
        "Die Bytes sind gültiges UTF-8, aber der Text selbst ist schon falsch: Benutzer sehen „GrÃ¼ÃŸe“ statt „Grüße“, Suche und Vergleiche schlagen fehl, und jeder weitere Durchlauf macht es schlimmer. Keine Client-Einstellung kann das reparieren.",
    ))
    .hypothesis(if ctx.de() {
        format!("UTF-8-Text wurde irgendwo als Latin-1/windows-1252 gelesen und erneut als UTF-8 kodiert – bei {} (Serialisierung), in der Datenbank (Verbindungs- oder Spalten-Zeichensatz) oder schon beim Client, der die Daten erfasst hat.", producer(ctx, g.dir))
    } else {
        format!("UTF-8 text was read as Latin-1/windows-1252 somewhere and encoded as UTF-8 again – in {} (serialisation), in the database (connection or column charset), or at the client that entered the data.", producer(ctx, g.dir))
    })
    .recommend(ctx.l(
        "Fix it at the source: find the step that decodes with Latin-1 (database connection charset, file reads without an encoding, byte/string conversions with the platform default) and make it UTF-8; then repair the stored data once.",
        "An der Quelle beheben: den Schritt finden, der mit Latin-1 dekodiert (Zeichensatz der Datenbankverbindung, Dateilesen ohne Kodierung, Byte-/String-Konvertierung mit Plattform-Standard) und auf UTF-8 umstellen; danach die gespeicherten Daten einmalig reparieren.",
    ))
    .next_step(ctx.l("Compare the same record in the database and in the response to see which step breaks it.", "Denselben Datensatz in der Datenbank und in der Response vergleichen, um den brechenden Schritt zu finden."));
    if !certain {
        f = f.hypothesis(ctx.l("Few traces: some may be real text (e.g. “ß” followed by a closing quote).", "Wenige Spuren: einige können echter Text sein (z. B. „ß“ gefolgt von einem schließenden Anführungszeichen)."));
    }
    if legacy_responses && g.dir == Dir::Request {
        f = f.hypothesis(ctx.l(
            "Responses of this host declare a legacy charset for UTF-8 text (ENC-MISMATCH): clients show it as “GrÃ¼ÃŸe” and send it back like that.",
            "Responses dieses Hosts deklarieren für UTF-8-Text einen Alt-Zeichensatz (ENC-MISMATCH): Clients zeigen ihn als „GrÃ¼ÃŸe“ an und senden ihn so zurück.",
        ));
    }
    Some(f)
}

// ------------------------------------------------------------------ ENC-LOST

fn lost_chars(ctx: &Ctx, g: &Group) -> Finding {
    let chars = g.sum(|t| t.replacement_chars);
    let severity = if g.n() >= LOST_WARN_SESSIONS { Severity::Warning } else { Severity::Info };
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    let mut f = base(
        ctx,
        g,
        severity,
        ("Characters already lost (U+FFFD):", "Bereits verlorene Zeichen (U+FFFD):"),
        if ctx.de() {
            format!("{n} {dir} enthalten {} Ersatzzeichen U+FFFD („�“) als gültigen Text.", ctx.fmt_count(chars as usize))
        } else {
            format!("{n} {dir} contain {} replacement characters U+FFFD (“�”) as valid text.", ctx.fmt_count(chars as usize))
        },
    )
    .confidence(Confidence::Medium)
    .threshold(if ctx.de() { format!("≥ 1 U+FFFD; Warnung ab {LOST_WARN_SESSIONS} Sessions") } else { format!("≥ 1 U+FFFD; warning from {LOST_WARN_SESSIONS} sessions") })
    .fact(ctx.l("Replacement characters", "Ersatzzeichen"), ctx.fmt_count(chars as usize))
    .impact(ctx.l(
        "The characters were lost before this data was sent: an earlier step decoded bytes with the wrong charset and replaced what it could not read. The original text cannot be recovered from this data.",
        "Die Zeichen gingen verloren, bevor diese Daten gesendet wurden: ein früherer Schritt hat Bytes mit dem falschen Zeichensatz dekodiert und ersetzt, was er nicht lesen konnte. Der Originaltext ist aus diesen Daten nicht wiederherstellbar.",
    ))
    .hypothesis(ctx.l("An import, database or upstream service read Latin-1 text as UTF-8 and stored the result.", "Ein Import, die Datenbank oder ein vorgelagerter Dienst hat Latin-1-Text als UTF-8 gelesen und das Ergebnis gespeichert."))
    .recommend(ctx.l("Trace the records back to where they were created or imported and fix the charset there; repair the stored data from the original source.", "Die Datensätze bis zu ihrer Erfassung oder ihrem Import zurückverfolgen und dort den Zeichensatz korrigieren; die gespeicherten Daten aus der Originalquelle reparieren."));
    if g.facts().any(|t| t.decode_errors > 0) {
        f = f.fact(ctx.l("Also invalid sequences (ENC-MISMATCH)", "Außerdem ungültige Sequenzen (ENC-MISMATCH)"), ctx.fmt_count(g.sum(|t| t.decode_errors) as usize));
    }
    f
}

// ------------------------------------------------------------------ ENC-JSON

fn json(ctx: &Ctx, g: &Group) -> Finding {
    let non_ascii = g.facts().any(|t| t.non_ascii);
    let eff = top(ctx, g.facts().map(|t| t.effective.clone()), 3);
    let declared = top(ctx, g.facts().map(|t| declared_as(ctx, t)), 3);
    let utf8_bytes = g.facts().all(|t| t.utf8_valid && !utf16(&t.effective));
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    let mut f = base(
        ctx,
        g,
        if non_ascii { Severity::Warning } else { Severity::Info },
        ("JSON not in UTF-8:", "JSON nicht in UTF-8:"),
        if ctx.de() { format!("{n} JSON-{dir} sind als {eff} deklariert oder kodiert.") } else { format!("{n} JSON {dir} are declared or encoded as {eff}.") },
    )
    .categories(&["encoding", "correctness", "interoperability"])
    .threshold(ctx.l("JSON with an effective charset other than UTF-8", "JSON mit einem anderen effektiven Zeichensatz als UTF-8"))
    .fact(ctx.l("Declared", "Deklariert"), declared)
    .impact(ctx.l(
        "RFC 8259 requires UTF-8 for JSON exchanged between systems and gives the charset parameter no meaning: browsers (fetch, response.json()) and many libraries read UTF-8 regardless, others follow the label — the same response decodes differently per client.",
        "RFC 8259 verlangt UTF-8 für JSON zwischen Systemen und gibt dem Charset-Parameter keine Bedeutung: Browser (fetch, response.json()) und viele Bibliotheken lesen trotzdem UTF-8, andere folgen der Angabe – dieselbe Response wird je nach Client verschieden dekodiert.",
    ))
    .recommend(ctx.l("Send JSON as UTF-8 without a BOM; application/json needs no charset parameter (charset=utf-8 is harmless).", "JSON als UTF-8 ohne BOM senden; application/json braucht keinen Charset-Parameter (charset=utf-8 schadet nicht)."));
    if !non_ascii {
        f = ascii_only(ctx, f);
    } else if utf8_bytes {
        f = f.hypothesis(ctx.l(
            "The bytes are valid UTF-8: only the label is wrong. UTF-8 readers are fine, clients that honour the label show “GrÃ¼ÃŸe” for “Grüße”.",
            "Die Bytes sind gültiges UTF-8: nur die Angabe ist falsch. UTF-8-Leser sind unbetroffen, Clients, die der Angabe folgen, zeigen „GrÃ¼ÃŸe“ statt „Grüße“.",
        ));
    } else {
        f = f.hypothesis(ctx.l(
            "The bytes really are in the declared charset: UTF-8 readers (browsers, most JSON libraries) replace every non-ASCII character with “�” or reject the body.",
            "Die Bytes liegen wirklich im deklarierten Zeichensatz vor: UTF-8-Leser (Browser, die meisten JSON-Bibliotheken) ersetzen jedes Nicht-ASCII-Zeichen durch „�“ oder lehnen den Body ab.",
        ));
    }
    f
}

// ------------------------------------------------------------------ ENC-MISSING

fn missing(ctx: &Ctx, g: &Group) -> Finding {
    let html = g.list.iter().any(|it| it.dir == Dir::Response && ctx.prep().mime_of(it.i) == "text/html");
    let invalid = g.facts().filter(|t| !t.utf8_valid).count();
    let severity = if html || invalid > 0 { Severity::Warning } else { Severity::Info };
    let types = top(
        ctx,
        g.list.iter().map(|it| match it.dir {
            Dir::Response => ctx.prep().mime_of(it.i).to_string(),
            Dir::Request => mime_of(it.s.req_header("content-type").unwrap_or("")),
        }),
        4,
    );
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    let mut f = base(
        ctx,
        g,
        severity,
        ("Text without a charset:", "Text ohne Zeichensatz-Angabe:"),
        if ctx.de() {
            format!("{n} {dir} ({types}) enthalten Nicht-ASCII-Zeichen, nennen aber nirgends einen Zeichensatz (kein Charset im Content-Type, keine BOM, keine Deklaration im Dokument).")
        } else {
            format!("{n} {dir} ({types}) contain non-ASCII characters but name no charset anywhere (no Content-Type charset, no BOM, no in-document declaration).")
        },
    )
    .categories(&["encoding", "interoperability"])
    .threshold(ctx.l(
        "text/* (not XML/JSON) or form data with bytes ≥ 0x80 and no declaration; warning for HTML or bytes that are not UTF-8",
        "text/* (nicht XML/JSON) oder Formulardaten mit Bytes ≥ 0x80 ohne Angabe; Warnung bei HTML oder Bytes, die kein UTF-8 sind",
    ))
    .impact(ctx.l(
        "Every client guesses: browsers fall back to a locale default (windows-1252 in Western Europe) for HTML, many HTTP libraries assume ISO-8859-1 for text/*, others UTF-8. The same body shows “Grüße” in one client and “GrÃ¼ÃŸe” or “Gr�e” in another.",
        "Jeder Client rät: Browser fallen bei HTML auf einen Gebietsschema-Standard zurück (windows-1252 in Westeuropa), viele HTTP-Bibliotheken nehmen für text/* ISO-8859-1 an, andere UTF-8. Derselbe Body zeigt in einem Client „Grüße“, in einem anderen „GrÃ¼ÃŸe“ oder „Gr�e“.",
    ))
    .recommend(ctx.l("Declare the charset: Content-Type: text/…; charset=utf-8 (for HTML also <meta charset=\"utf-8\"> in the first 1024 bytes).", "Den Zeichensatz angeben: Content-Type: text/…; charset=utf-8 (bei HTML zusätzlich <meta charset=\"utf-8\"> in den ersten 1024 Bytes)."));
    if invalid > 0 {
        f = f.fact(ctx.l("Bodies that are not UTF-8", "Bodies, die kein UTF-8 sind"), ctx.fmt_count(invalid)).hypothesis(ctx.l("The bytes are in a legacy charset (probably windows-1252): UTF-8 readers lose the characters.", "Die Bytes liegen in einem Alt-Zeichensatz vor (vermutlich windows-1252): UTF-8-Leser verlieren die Zeichen."));
    } else if g.sampled_partly() {
        f = f.confidence(Confidence::Medium);
    }
    f
}

// ------------------------------------------------------------------ ENC-UNKNOWN

fn unknown(ctx: &Ctx, g: &Group) -> Finding {
    let labels = top(
        ctx,
        g.facts().flat_map(|t| {
            let h = t.header_charset.clone().filter(|_| t.header_resolved.is_none());
            let d = t.document_charset.clone().filter(|_| t.document_resolved.is_none());
            h.into_iter().chain(d)
        }),
        4,
    );
    let used = top(ctx, g.facts().map(|t| t.effective.clone()), 3);
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    base(
        ctx,
        g,
        Severity::Warning,
        ("Unknown charset label:", "Unbekannter Zeichensatz-Name:"),
        if ctx.de() { format!("{n} {dir} nennen einen Zeichensatz, den Browser nicht kennen: {labels}.") } else { format!("{n} {dir} name a charset browsers do not know: {labels}.") },
    )
    .threshold(ctx.l("label not in the WHATWG Encoding Standard", "Name nicht im WHATWG Encoding Standard"))
    .fact(ctx.l("Unknown labels", "Unbekannte Namen"), labels)
    .fact(ctx.l("Used instead", "Stattdessen verwendet"), used)
    .impact(ctx.l(
        "Clients ignore the label and fall back to their own default, or fail (some libraries throw on unknown charsets). Non-ASCII text is then read in whatever charset the client picks.",
        "Clients ignorieren die Angabe und nehmen ihren eigenen Standard oder brechen ab (manche Bibliotheken werfen bei unbekannten Zeichensätzen einen Fehler). Nicht-ASCII-Text wird dann in dem Zeichensatz gelesen, den der Client wählt.",
    ))
    .hypothesis(ctx.l("A typo or a platform-specific name (e.g. “utf8mb4”, “cp1252” variants, “unicode”).", "Ein Tippfehler oder ein plattformspezifischer Name (z. B. „utf8mb4“, Varianten von „cp1252“, „unicode“)."))
    .recommend(ctx.l("Use a standard label, preferably utf-8.", "Einen Standardnamen verwenden, am besten utf-8."))
}

// ------------------------------------------------------------------ ENC-BINARY

fn binary(ctx: &Ctx, g: &Group) -> Finding {
    let nuls = g.sum(|t| t.nul_bytes);
    let types = top(
        ctx,
        g.list.iter().map(|it| match it.dir {
            Dir::Response => ctx.prep().mime_of(it.i).to_string(),
            Dir::Request => mime_of(it.s.req_header("content-type").unwrap_or("")),
        }),
        4,
    );
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    base(
        ctx,
        g,
        Severity::Info,
        ("Binary data declared as text:", "Binärdaten als Text deklariert:"),
        if ctx.de() {
            format!("{n} {dir} mit Text-Typ ({types}) enthalten {} NUL-Bytes.", ctx.fmt_count(nuls as usize))
        } else {
            format!("{n} {dir} with a text type ({types}) contain {} NUL bytes.", ctx.fmt_count(nuls as usize))
        },
    )
    .confidence(Confidence::Medium)
    .threshold(ctx.l("≥ 1 NUL byte outside UTF-16", "≥ 1 NUL-Byte außerhalb von UTF-16"))
    .fact(ctx.l("NUL bytes", "NUL-Bytes"), ctx.fmt_count(nuls as usize))
    .impact(ctx.l(
        "Text does not contain NUL bytes: the body is probably binary (a file, an image, UTF-16/32 without a BOM) with a wrong Content-Type. Clients that treat it as text corrupt it or cut it off at the first NUL.",
        "Text enthält keine NUL-Bytes: der Body ist vermutlich binär (Datei, Bild, UTF-16/32 ohne BOM) mit falschem Content-Type. Clients, die ihn als Text behandeln, verfälschen ihn oder schneiden ihn beim ersten NUL ab.",
    ))
    .recommend(ctx.l("Send the real type (e.g. application/octet-stream, application/pdf) or, for UTF-16 text, a BOM and a charset.", "Den tatsächlichen Typ senden (z. B. application/octet-stream, application/pdf) oder bei UTF-16-Text eine BOM und ein Charset."))
}

// ------------------------------------------------------------------ ENC-DECODE

fn decode(ctx: &Ctx, g: &Group) -> Finding {
    let (n, dir) = (ctx.fmt_count(g.n()), what(ctx, g.dir));
    let coding = |it: &Item| match it.dir {
        Dir::Request => it.s.req_header("content-encoding"),
        Dir::Response => it.s.resp_header("content-encoding"),
    }
    .map(|c| c.trim().to_ascii_lowercase())
    .filter(|c| !c.is_empty() && c != "identity");
    let codings = top(ctx, g.list.iter().filter_map(|it| coding(it)), 3);
    let codings = if codings.is_empty() { ctx.l("none", "keine").to_string() } else { codings };
    let errors = top(ctx, g.list.iter().filter_map(|it| it.error.map(|e| util::short(e, 80))), 2);
    match g.verdict {
        Verdict::Compressed => {
            let magic = top(ctx, g.facts().filter_map(|t| t.looks_compressed.clone()), 3);
            let twice = g.list.iter().any(|it| coding(it).is_some());
            base(
                ctx,
                g,
                Severity::Warning,
                if twice { ("Body compressed twice:", "Body doppelt komprimiert:") } else { ("Compressed body without Content-Encoding:", "Komprimierter Body ohne Content-Encoding:") },
                if ctx.de() {
                    format!("{n} {dir} mit Text-Typ beginnen (nach dem Dekodieren) mit der Signatur komprimierter Daten: {magic}.")
                } else {
                    format!("{n} {dir} with a text type start (after decoding) with the signature of compressed data: {magic}.")
                },
            )
            .categories(&["encoding", "correctness", "payload"])
            .threshold(ctx.l("gzip/zstd/zlib magic bytes at the start of a decoded text body", "gzip-/zstd-/zlib-Signatur am Anfang eines dekodierten Text-Bodys"))
            .fact("Content-Encoding", codings)
            .impact(ctx.l(
                "Clients hand the compressed bytes to the application as text: parsers fail, users see garbage. Browsers do not sniff compression.",
                "Clients geben die komprimierten Bytes als Text an die Anwendung weiter: Parser scheitern, Benutzer sehen Zeichensalat. Browser erkennen Kompression nicht selbst.",
            ))
            .hypothesis(if twice {
                ctx.l("Two layers compress (e.g. the application and a reverse proxy), but only one sets Content-Encoding.", "Zwei Schichten komprimieren (z. B. Anwendung und Reverse-Proxy), aber nur eine setzt Content-Encoding.")
            } else {
                ctx.l("Pre-compressed content (e.g. .gz files) is served without Content-Encoding, or a proxy dropped the header.", "Vorkomprimierte Inhalte (z. B. .gz-Dateien) werden ohne Content-Encoding ausgeliefert, oder ein Proxy hat den Header entfernt.")
            })
            .recommend(ctx.l("Compress once and declare it: Content-Encoding: gzip (or br/zstd) matching the data.", "Einmal komprimieren und es angeben: Content-Encoding: gzip (bzw. br/zstd) passend zu den Daten."))
        }
        _ => {
            let unsupported = g.verdict == Verdict::DecodeUnsupported;
            let severity = if unsupported {
                Severity::Warning
            } else {
                severity_by(g.n(), g.share(), DECODE_CRITICAL_SESSIONS, DECODE_CRITICAL_SHARE, Severity::Critical, Severity::Warning)
            };
            base(
                ctx,
                g,
                severity,
                if unsupported { ("Unsupported Content-Encoding:", "Nicht unterstütztes Content-Encoding:") } else { ("Content-Encoding cannot be decoded:", "Content-Encoding nicht dekodierbar:") },
                if ctx.de() {
                    if unsupported {
                        format!("{n} {dir} verwenden eine Kodierung, die Quena (und die meisten Clients) nicht dekodieren können: {codings}.")
                    } else {
                        format!("{n} {dir} deklarieren Content-Encoding {codings}, die Daten lassen sich aber nicht dekodieren ({errors}).")
                    }
                } else if unsupported {
                    format!("{n} {dir} use a coding that Quena (and most clients) cannot decode: {codings}.")
                } else {
                    format!("{n} {dir} declare Content-Encoding {codings}, but the data cannot be decoded ({errors}).")
                },
            )
            .categories(&["encoding", "errors"])
            .threshold(if unsupported {
                ctx.l("coding other than gzip, deflate, br, zstd, identity", "Kodierung außer gzip, deflate, br, zstd, identity").to_string()
            } else if ctx.de() {
                format!("Dekodierfehler (nicht bei abgeschnitten gespeicherten Bodies); kritisch ab {DECODE_CRITICAL_SESSIONS} Sessions und {} des Endpunkts", ctx.fmt_pct(DECODE_CRITICAL_SHARE))
            } else {
                format!("decoding error (not for bodies stored truncated); critical from {DECODE_CRITICAL_SESSIONS} sessions and {} of the endpoint", ctx.fmt_pct(DECODE_CRITICAL_SHARE))
            })
            .fact("Content-Encoding", codings)
            .fact(ctx.l("Error", "Fehler"), errors)
            .impact(ctx.l(
                "Clients cannot read these bodies: browsers show a content decoding error, libraries throw; the request fails although the status says otherwise.",
                "Clients können diese Bodies nicht lesen: Browser melden einen Dekodierfehler, Bibliotheken werfen eine Ausnahme; der Request scheitert, obwohl der Status anderes sagt.",
            ))
            .hypothesis(if unsupported {
                ctx.l("A non-standard or misspelt coding name, or a coding only one specific client understands.", "Ein nicht standardisierter oder falsch geschriebener Kodierungsname oder eine Kodierung, die nur ein bestimmter Client versteht.")
            } else {
                ctx.l(
                    "The header does not match the data (e.g. Content-Encoding: gzip on uncompressed or differently compressed data), or a proxy changed the body without updating the header.",
                    "Der Header passt nicht zu den Daten (z. B. Content-Encoding: gzip bei unkomprimierten oder anders komprimierten Daten), oder ein Proxy hat den Body geändert, ohne den Header anzupassen.",
                )
            })
            .recommend(ctx.l("Send Content-Encoding only for data compressed exactly that way; check compression middleware and proxies on the path.", "Content-Encoding nur für genau so komprimierte Daten senden; Kompressions-Middleware und Proxys auf dem Weg prüfen."))
        }
    }
}

#[cfg(test)]
mod singular_tests {
    #[test]
    fn one_body_reads_in_the_singular() {
        assert_eq!(super::singular("1 Response-Bodies deklarieren UTF-8, enthalten aber 3 ungültige UTF-8-Sequenzen."), "1 Response-Body deklariert UTF-8, enthält aber 3 ungültige UTF-8-Sequenzen.");
        assert_eq!(super::singular("1 response bodies declare UTF-8 but contain 3 invalid UTF-8 sequences."), "1 response body declares UTF-8 but contains 3 invalid UTF-8 sequences.");
        assert_eq!(super::singular("1 Request-Bodies deklarieren windows-1252, ihre Bytes sind aber gültiges UTF-8."), "1 Request-Body deklariert windows-1252, seine Bytes sind aber gültiges UTF-8.");
        assert_eq!(super::singular("1 response bodies are not valid UTF-8 (2 malformed sequences)."), "1 response body is not valid UTF-8 (2 malformed sequences).");
        // More than one body stays plural; later sentences are not touched.
        assert_eq!(super::singular("12 Response-Bodies enthalten 3 Spuren."), "12 Response-Bodies enthalten 3 Spuren.");
        assert_eq!(super::singular("1 response bodies contain 3 traces. Others contain nothing."), "1 response body contains 3 traces. Others contain nothing.");
    }
}
