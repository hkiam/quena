//! URL canonicalisation: the basis of duplicate, pattern and OData analysis.
//!
//! * `canonical` — the *meaning* of a request: scheme/host lower-case, default port
//!   dropped, query parameters decoded and sorted, cache busters removed, OData system
//!   options normalised (`$filter` whitespace/keyword case, `$select`/`$expand` sorted).
//!   Two requests with the same canonical form are semantic duplicates.
//! * `template` — the *shape*: like `canonical`, but IDs in the path, OData keys and
//!   literals, and ID-like query values replaced by `{}`. The replaced values are returned
//!   as variables. Many requests with one template are an N+1/polling/paging candidate.
//! * `endpoint` — method + host + templated path without query (aggregation key).

/// Percent-decode (`+` stays `+`; invalid escapes are kept), lossy UTF-8.
pub fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = |c: u8| (c as char).to_digit(16);
            if let (Some(a), Some(c)) = (h(b[i + 1]), h(b[i + 2])) {
                out.push((a * 16 + c) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parts of an absolute URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    /// Lower-case, with the port only if it is not the default one.
    pub host: String,
    /// Raw path (not decoded), `/` if empty.
    pub path: String,
    /// Decoded `(name, value)` pairs in the original order (`+` in values → space).
    pub query: Vec<(String, String)>,
}

pub fn parse(url: &str) -> Url {
    let (scheme, rest) = match url.find("://") {
        Some(i) => (url[..i].to_ascii_lowercase(), &url[i + 3..]),
        None => (String::new(), url),
    };
    let rest = rest.split('#').next().unwrap_or("");
    let (auth, pathq) = match rest.find('/') {
        Some(i) if !scheme.is_empty() => (&rest[..i], &rest[i..]),
        _ if !scheme.is_empty() => match rest.find('?') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        },
        _ => ("", rest),
    };
    let auth = auth.rsplit('@').next().unwrap_or("").to_ascii_lowercase();
    let host = match (scheme.as_str(), auth.rsplit_once(':')) {
        ("http", Some((h, "80"))) | ("https", Some((h, "443"))) => h.to_string(),
        _ => auth,
    };
    let (path, q) = match pathq.find('?') {
        Some(i) => (&pathq[..i], &pathq[i + 1..]),
        None => (pathq, ""),
    };
    let query = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(&k.replace('+', " ")), decode(&v.replace('+', " ")))
        })
        .collect();
    Url { scheme, host, path: if path.is_empty() { "/".into() } else { path.to_string() }, query }
}

/// Query parameters that only defeat caches (dropped from `canonical` and `template`).
fn cache_buster(name: &str, value: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let numeric = !value.is_empty() && value.chars().all(|c| c.is_ascii_digit() || c == '.');
    matches!(n.as_str(), "_" | "_t" | "_ts" | "cb" | "cachebuster" | "nocache" | "rnd" | "rand" | "random") && (numeric || value.len() >= 6)
        || (matches!(n.as_str(), "t" | "ts" | "timestamp" | "time") && numeric && value.len() >= 10)
}

fn is_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// GUID with or without braces/dashes.
pub fn is_guid(s: &str) -> bool {
    let s = s.trim_matches(|c| c == '{' || c == '}');
    let p: Vec<&str> = s.split('-').collect();
    (p.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&p).all(|(n, x)| x.len() == *n && is_hex(x))) || (s.len() == 32 && is_hex(s))
}

/// A value that looks like an identifier rather than a fixed name.
pub fn is_id(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    if is_guid(s) {
        return true;
    }
    let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    // Hashes, object ids, long tokens: long and mixed with digits.
    (s.len() >= 12 && is_hex(s) && digits > 0)
        || (s.len() >= 20 && digits >= 2 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

/// Template of one path segment: `42` → `{}`, `Cases(42)` → `Cases({})`, `Cases('a')` → `Cases({})`.
fn segment_template(seg: &str, vars: &mut Vec<(String, String)>, pos: usize) -> String {
    let dec = decode(seg);
    if is_id(&dec) {
        vars.push((format!("path[{pos}]"), dec));
        return "{}".into();
    }
    // OData key predicate: EntitySet(key) or EntitySet(k1=…,k2=…).
    if let (Some(o), true) = (dec.find('('), dec.ends_with(')')) {
        let inner = &dec[o + 1..dec.len() - 1];
        if !inner.is_empty() {
            vars.push((format!("key[{pos}]"), inner.to_string()));
            return format!("{}({{}})", &dec[..o]);
        }
    }
    dec
}

// ------------------------------------------------------------------ OData

const ODATA_OPS: [&str; 18] =
    ["eq", "ne", "gt", "ge", "lt", "le", "and", "or", "not", "has", "in", "add", "sub", "mul", "div", "mod", "asc", "desc"];

/// Tokens of an OData expression: literals, words, punctuation; whitespace dropped.
fn odata_tokens(expr: &str) -> Vec<(bool, String)> {
    // (is_literal, text)
    let c: Vec<char> = expr.chars().collect();
    let mut out: Vec<(bool, String)> = vec![];
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '\'' {
            // 'it''s' — prefixed forms like guid'…' / datetime'…' are joined below.
            let mut s = String::from("'");
            i += 1;
            while i < c.len() {
                if c[i] == '\'' {
                    if i + 1 < c.len() && c[i + 1] == '\'' {
                        s.push_str("''");
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                s.push(c[i]);
                i += 1;
            }
            s.push('\'');
            // guid'…', datetime'…', X'…' (OData v2 typed literals)
            if let Some((false, prev)) = out.last()
                && prev.chars().all(|x: char| x.is_ascii_alphabetic())
                && !ODATA_OPS.contains(&prev.to_ascii_lowercase().as_str())
            {
                let p = out.pop().unwrap().1;
                out.push((true, format!("{p}{s}")));
                continue;
            }
            out.push((true, s));
        } else if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' || ch == '.' || ch == '-' || ch == ':' || ch == '/' {
            let mut s = String::new();
            while i < c.len() && (c[i].is_ascii_alphanumeric() || "_$.-:/+".contains(c[i])) {
                s.push(c[i]);
                i += 1;
            }
            let lit = s.parse::<f64>().is_ok()
                || is_guid(&s)
                || (s.len() >= 10 && s.as_bytes()[..4].iter().all(|b| b.is_ascii_digit()) && s.as_bytes()[4] == b'-') // 2024-01-01…
                || matches!(s.as_str(), "true" | "false" | "null");
            out.push((lit, s));
        } else {
            out.push((false, ch.to_string()));
            i += 1;
        }
    }
    out
}

fn join_tokens(tokens: &[(bool, String)]) -> String {
    let mut s = String::new();
    for (i, (_, t)) in tokens.iter().enumerate() {
        let word = |x: &str| x.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '\'' || c == '$' || c == '_' || c == '{');
        if i > 0 && word(t) && word(&tokens[i - 1].1) {
            s.push(' ');
        }
        s.push_str(t);
    }
    s
}

/// `$filter` with normalised whitespace and operator case.
pub fn odata_filter(expr: &str) -> String {
    let t: Vec<(bool, String)> = odata_tokens(expr)
        .into_iter()
        .map(|(lit, s)| {
            let low = s.to_ascii_lowercase();
            if !lit && ODATA_OPS.contains(&low.as_str()) { (lit, low) } else { (lit, s) }
        })
        .collect();
    join_tokens(&t)
}

/// `$filter` with literals replaced by `{}`; the literals are returned.
pub fn odata_filter_template(expr: &str) -> (String, Vec<String>) {
    let mut vars = vec![];
    let t: Vec<(bool, String)> = odata_tokens(expr)
        .into_iter()
        .map(|(lit, s)| {
            if lit {
                vars.push(s);
                (false, "{}".to_string())
            } else {
                let low = s.to_ascii_lowercase();
                (false, if ODATA_OPS.contains(&low.as_str()) { low } else { s })
            }
        })
        .collect();
    (join_tokens(&t), vars)
}

/// Split at top-level commas (not inside parentheses or quotes).
fn split_list(s: &str) -> Vec<String> {
    let mut out = vec![];
    let (mut depth, mut quote, mut cur) = (0i32, false, String::new());
    for ch in s.chars() {
        match ch {
            '\'' => quote = !quote,
            '(' if !quote => depth += 1,
            ')' if !quote => depth -= 1,
            ',' if !quote && depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Normalised value of an OData system query option (`$filter`, `$select`, …).
pub fn odata_option(name: &str, value: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "$filter" => odata_filter(value),
        "$select" | "$expand" => {
            let mut v: Vec<String> = split_list(value).into_iter().map(|x| x.split_whitespace().collect::<Vec<_>>().join(" ")).collect();
            v.sort();
            v.join(",")
        }
        "$orderby" => split_list(value).into_iter().map(|x| odata_filter(&x)).collect::<Vec<_>>().join(","),
        _ => value.trim().to_string(),
    }
}

/// Is this an OData request? (system query options or an `/odata` path segment)
pub fn is_odata(url: &Url) -> bool {
    url.query.iter().any(|(k, _)| k.starts_with('$'))
        || url.path.to_ascii_lowercase().split('/').any(|s| s == "odata" || s.ends_with(".svc") || s == "$batch")
}

/// The decoded OData system query options (`$filter`, `$top`, …) of a URL.
pub fn odata_options(url: &Url) -> Vec<(String, String)> {
    url.query.iter().filter(|(k, _)| k.starts_with('$')).map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect()
}

// ------------------------------------------------------------------ canonical / template

fn query_string(pairs: &mut [(String, String)]) -> String {
    pairs.sort();
    pairs.iter().map(|(k, v)| if v.is_empty() { k.clone() } else { format!("{k}={v}") }).collect::<Vec<_>>().join("&")
}

/// The meaning of a request (see module docs). Body hash is appended when given.
pub fn canonical(method: &str, url: &str, body_hash: Option<u64>) -> String {
    let u = parse(url);
    let mut q: Vec<(String, String)> = u
        .query
        .iter()
        .filter(|(k, v)| !cache_buster(k, v))
        .map(|(k, v)| if k.starts_with('$') { (k.to_ascii_lowercase(), odata_option(k, v)) } else { (k.clone(), v.clone()) })
        .collect();
    let path: String = u.path.split('/').map(decode).collect::<Vec<_>>().join("/");
    let mut s = format!("{} {}://{}{}", method.to_ascii_uppercase(), u.scheme, u.host, path);
    if !q.is_empty() {
        s.push('?');
        s.push_str(&query_string(&mut q));
    }
    if let Some(h) = body_hash {
        s.push_str(&format!(" #{h:016x}"));
    }
    s
}

/// The shape of a request and the values that were replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub key: String,
    /// `(where, value)`: `path[2]`, `key[3]`, `$filter`, `q:page` …
    pub vars: Vec<(String, String)>,
}

pub fn template(method: &str, url: &str) -> Template {
    let u = parse(url);
    let mut vars = vec![];
    let path: Vec<String> = u.path.split('/').enumerate().map(|(i, s)| segment_template(s, &mut vars, i)).collect();
    let mut q: Vec<(String, String)> = vec![];
    for (k, v) in &u.query {
        if cache_buster(k, v) {
            continue;
        }
        let lk = k.to_ascii_lowercase();
        let val = match lk.as_str() {
            "$filter" => {
                let (t, lits) = odata_filter_template(v);
                vars.extend(lits.into_iter().map(|l| ("$filter".to_string(), l)));
                t
            }
            "$skip" | "$skiptoken" | "page" | "offset" | "start" | "cursor" | "pagetoken" | "skip" => {
                vars.push((format!("q:{lk}"), v.clone()));
                "{}".into()
            }
            _ if k.starts_with('$') => odata_option(k, v),
            _ if is_id(v) => {
                vars.push((format!("q:{k}"), v.clone()));
                "{}".into()
            }
            _ => v.clone(),
        };
        q.push((if k.starts_with('$') { lk } else { k.clone() }, val));
    }
    let mut key = format!("{} {}://{}{}", method.to_ascii_uppercase(), u.scheme, u.host, path.join("/"));
    if !q.is_empty() {
        key.push('?');
        key.push_str(&query_string(&mut q));
    }
    Template { key, vars }
}

/// Method + host + templated path, without query: `GET api.example.com/v1/items/{}`.
pub fn endpoint(method: &str, url: &str) -> String {
    let u = parse(url);
    let mut vars = vec![];
    let path: Vec<String> = u.path.split('/').enumerate().map(|(i, s)| segment_template(s, &mut vars, i)).collect();
    format!("{} {}{}", method.to_ascii_uppercase(), u.host, path.join("/"))
}

// ------------------------------------------------------------------ content types

/// Static resources that should be cacheable.
pub fn is_static(mime: &str, path: &str) -> bool {
    let p = path.split('?').next().unwrap_or("").to_ascii_lowercase();
    mime.starts_with("image/")
        || mime.starts_with("font/")
        || matches!(mime, "text/css" | "application/javascript" | "text/javascript" | "application/font-woff" | "application/x-font-woff")
        || [".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".map"]
            .iter()
            .any(|e| p.ends_with(e))
}

/// Content that compresses well (text-like).
pub fn is_compressible(mime: &str) -> bool {
    mime.starts_with("text/")
        || mime.ends_with("+json")
        || mime.ends_with("+xml")
        || matches!(
            mime,
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-javascript"
                | "application/ecmascript"
                | "application/x-www-form-urlencoded"
                | "image/svg+xml"
                | "application/wasm"
                | "font/ttf"
                | "font/otf"
                | "application/vnd.ms-fontobject"
                | "application/graphql"
        )
}

// ------------------------------------------------------------------ helpers for pattern analysis

/// Is this query parameter a cache buster (dropped by `canonical`)? Public form of the
/// rule used by `canonical` and `template`.
pub fn is_cache_buster(name: &str, value: &str) -> bool {
    cache_buster(name, value)
}

/// Items of an OData list option (`$select`, `$expand`, `$orderby`), split at top-level
/// commas (not inside parentheses or quotes), trimmed.
pub fn odata_list(value: &str) -> Vec<String> {
    split_list(value)
}

/// Shape of an OData `$expand` value: `(depth, items)`. Depth counts nesting through
/// `Nav($expand=…)` options and navigation paths (`A/B`); items counts all navigation
/// properties at all levels. `A,B($expand=C($expand=D))` → `(3, 4)`.
pub fn odata_expand_shape(value: &str) -> (usize, usize) {
    fn walk(v: &str, guard: usize) -> (usize, usize) {
        if guard > 16 {
            return (0, 0);
        }
        let (mut depth, mut items) = (0, 0);
        for item in split_list(v) {
            if item.is_empty() {
                continue;
            }
            let (nav, opts) = match (item.find('('), item.ends_with(')')) {
                (Some(o), true) => (&item[..o], &item[o + 1..item.len() - 1]),
                _ => (item.as_str(), ""),
            };
            let path_depth = nav.split('/').filter(|x| !x.trim().is_empty()).count().max(1);
            items += path_depth;
            // Nested $expand inside the options: `$select=a;$expand=B(…)`.
            let mut inner = (0, 0);
            for o in opts.split(';') {
                let o = o.trim();
                if let Some((k, v)) = o.split_once('=')
                    && k.trim().eq_ignore_ascii_case("$expand")
                {
                    inner = walk(v, guard + 1);
                }
            }
            items += inner.1;
            depth = depth.max(path_depth + inner.0);
        }
        (depth, items)
    }
    walk(value, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url() {
        let u = parse("HTTPS://Api.Example.com:443/v1/items?b=2&a=%C3%A4+x#frag");
        assert_eq!((u.scheme.as_str(), u.host.as_str(), u.path.as_str()), ("https", "api.example.com", "/v1/items"));
        assert_eq!(u.query, vec![("b".into(), "2".into()), ("a".into(), "ä x".into())]);
        assert_eq!(parse("http://h:8080").host, "h:8080");
        assert_eq!(parse("http://h:8080").path, "/");
    }

    #[test]
    fn odata_semantic_duplicates() {
        let a = canonical("GET", "https://h/odata/Documents?$filter=Type eq 'A'&$top=50&$select=Id,Name", None);
        let b = canonical("get", "https://h/odata/Documents?$select=Name, Id&$top=50&$filter=Type%20EQ%20%27A%27", None);
        assert_eq!(a, b);
        let c = canonical("GET", "https://h/odata/Documents?$filter=Type eq 'B'&$top=50&$select=Id,Name", None);
        assert_ne!(a, c);
        // string literal case and spacing inside quotes are meaningful
        assert_ne!(canonical("GET", "https://h/x?$filter=Name eq 'a  b'", None), canonical("GET", "https://h/x?$filter=Name eq 'a b'", None));
    }

    #[test]
    fn cache_busters_do_not_count() {
        assert_eq!(canonical("GET", "https://h/a?x=1&_=1727690000123", None), canonical("GET", "https://h/a?x=1", None));
        assert_ne!(canonical("GET", "https://h/a?page=2", None), canonical("GET", "https://h/a?page=3", None));
        assert_ne!(canonical("POST", "https://h/a", Some(1)), canonical("POST", "https://h/a", Some(2)));
    }

    #[test]
    fn templates() {
        let t = template("GET", "https://h/odata/Documents?$filter=Id eq 1001");
        let u = template("GET", "https://h/odata/Documents?$filter=Id eq 1002");
        assert_eq!(t.key, u.key);
        assert_eq!(t.vars, vec![("$filter".to_string(), "1001".to_string())]);
        assert!(t.key.ends_with("$filter=Id eq {}"), "{}", t.key);
        assert_eq!(template("GET", "https://h/api/users/42/orders").key, template("GET", "https://h/api/users/7/orders").key);
        assert_eq!(template("GET", "https://h/odata/Cases(42)/Documents").key, template("GET", "https://h/odata/Cases(7)/Documents").key);
        assert_eq!(
            template("GET", "https://h/o/Docs?$filter=Owner eq guid'0f8fad5b-d9cb-469f-a165-70867728950e'").vars,
            vec![("$filter".to_string(), "guid'0f8fad5b-d9cb-469f-a165-70867728950e'".to_string())]
        );
        // Names stay: /api/users/me is not an id
        assert_ne!(template("GET", "https://h/api/users/me").key, template("GET", "https://h/api/users/42").key);
        assert_eq!(endpoint("get", "https://h/api/users/42?x=1"), "GET h/api/users/{}");
        let p = template("GET", "https://h/o/Docs?$top=50&$skip=100");
        assert_eq!(p.key, template("GET", "https://h/o/Docs?$skip=150&$top=50").key);
    }

    #[test]
    fn ids() {
        assert!(is_id("1001") && is_id("0f8fad5b-d9cb-469f-a165-70867728950e") && is_id("5f2b8c9e1a3d4f6b7c8d9e0f"));
        assert!(!is_id("orders") && !is_id("v1") && !is_id("me") && !is_id("index.html"));
    }

    #[test]
    fn content_types() {
        assert!(is_static("application/javascript", "/app.js") && is_static("", "/logo.PNG?v=3") && !is_static("application/json", "/api"));
        assert!(is_compressible("application/json") && is_compressible("application/soap+xml") && !is_compressible("image/png"));
    }

    #[test]
    fn pattern_helpers() {
        assert!(is_cache_buster("_", "1727690000123") && !is_cache_buster("page", "2"));
        assert_eq!(odata_list("a, b($select=x,y),c"), vec!["a", "b($select=x,y)", "c"]);
        assert_eq!(odata_expand_shape("A"), (1, 1));
        assert_eq!(odata_expand_shape("A,B($expand=C($expand=D))"), (3, 4));
        assert_eq!(odata_expand_shape("A/B/C"), (3, 3));
        assert_eq!(odata_expand_shape("A($select=x;$expand=B,C)"), (2, 3));
        assert_eq!(odata_expand_shape(""), (0, 0));
        let _ = odata_expand_shape("((((($expand=(((");
    }

    #[test]
    fn never_panics() {
        for s in ["", "%", "%zz", "http://", "https://@/", "?&&=&", "$filter='", "http://h/x?$filter=(((", "http://h/x?$select=a,(b"] {
            let _ = canonical("GET", s, None);
            let _ = template("GET", s);
            let _ = endpoint("GET", s);
            let _ = odata_filter(s);
        }
    }
}

// ------------------------------------------------------------------ reference resolution

/// `.` and `..` segments removed from an absolute path (query kept as is).
fn remove_dots(p: &str) -> String {
    let (path, query) = match p.find('?') {
        Some(i) => (&p[..i], &p[i..]),
        None => (p, ""),
    };
    let mut out: Vec<&str> = vec![];
    let segs: Vec<&str> = path.split('/').skip(1).collect();
    for (i, s) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        match *s {
            "." => {
                if last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if last {
                    out.push("");
                }
            }
            x => out.push(x),
        }
    }
    format!("/{}{}", out.join("/"), query)
}

/// Absolute URL of a `Location` value relative to the request URL (RFC 3986 reference
/// resolution, simplified; the fragment is dropped).
pub fn resolve(base: &str, location: &str) -> String {
    let loc = location.trim();
    let loc = loc.split('#').next().unwrap_or("");
    if let Some(i) = loc.find("://")
        && i > 0
        && loc[..i].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return loc.to_string();
    }
    let Some(i) = base.find("://") else { return loc.to_string() };
    let scheme = &base[..i];
    let rest = base[i + 3..].split('#').next().unwrap_or("");
    let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let path = rest[auth_end..].split('?').next().unwrap_or("");
    let path = if path.is_empty() { "/" } else { path };
    if loc.is_empty() {
        return format!("{scheme}://{rest}");
    }
    if let Some(r) = loc.strip_prefix("//") {
        return format!("{scheme}://{r}");
    }
    if loc.starts_with('/') {
        return format!("{scheme}://{authority}{}", remove_dots(loc));
    }
    if loc.starts_with('?') {
        return format!("{scheme}://{authority}{path}{loc}");
    }
    let dir = &path[..path.rfind('/').map(|i| i + 1).unwrap_or(1).min(path.len())];
    format!("{scheme}://{authority}{}", remove_dots(&format!("{dir}{loc}")))
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    #[test]
    fn resolves_locations() {
        let b = "https://h.test/a/b/c?x=1";
        assert_eq!(resolve(b, "https://o.test/z"), "https://o.test/z");
        assert_eq!(resolve(b, "//o.test/z"), "https://o.test/z");
        assert_eq!(resolve(b, "/z?q=1"), "https://h.test/z?q=1");
        assert_eq!(resolve(b, "d"), "https://h.test/a/b/d");
        assert_eq!(resolve(b, "../d"), "https://h.test/a/d");
        assert_eq!(resolve(b, "./"), "https://h.test/a/b/");
        assert_eq!(resolve(b, "?y=2"), "https://h.test/a/b/c?y=2");
        assert_eq!(resolve(b, ""), "https://h.test/a/b/c?x=1");
        assert_eq!(resolve("http://h.test", "login"), "http://h.test/login");
        assert_eq!(resolve("http://h.test/x", "/../../y"), "http://h.test/y");
        for (x, y) in [("", ""), ("://", "a"), ("http://", "../.."), ("x", "?")] {
            let _ = resolve(x, y);
        }
    }
}
