//! `.http` request collections (JetBrains HTTP Client, VS Code REST Client).
//!
//! ```text
//! @host = https://api.example.com
//!
//! ### List users
//! GET {{host}}/users?page=1
//! Authorization: Bearer {{token}}
//!
//! ### Create
//! # @name create
//! POST {{host}}/users
//! Content-Type: application/json
//!
//! {"name": "{{$uuid}}"}
//! ```
//!
//! Variables come from `@name = value` lines, from the chosen environment of
//! `http-client.env.json` (overridden by `http-client.private.env.json`, with a `$shared`
//! environment as the base), and from the dynamic variables `$uuid`, `$timestamp`,
//! `$isoTimestamp`, `$randomInt [min max]` and `$processEnv NAME`. Response handler scripts
//! (`> {% … %}`) and references to earlier responses are not run; they are reported as
//! warnings or errors.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub const ENV_FILE: &str = "http-client.env.json";
pub const PRIVATE_ENV_FILE: &str = "http-client.private.env.json";

const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "QUERY"];

#[derive(Debug, Clone, PartialEq)]
pub enum BodySource {
    None,
    Text(String),
    /// `< path`, relative to the `.http` file.
    File(String),
}

/// A request as written (variables not yet substituted).
#[derive(Debug, Clone, PartialEq)]
pub struct RawRequest {
    pub name: Option<String>,
    /// 1-based line of the request line.
    pub line: usize,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: BodySource,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HttpFile {
    /// `@name = value`, in file order (values may refer to other variables).
    pub variables: Vec<(String, String)>,
    pub requests: Vec<RawRequest>,
    pub warnings: Vec<String>,
}

/// A request ready to send.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub name: Option<String>,
    pub line: usize,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    None,
    Text(String),
    File(PathBuf),
}

fn is_comment(l: &str) -> bool {
    let t = l.trim_start();
    t.starts_with('#') || t.starts_with("//")
}

/// `# @name x` / `// @name x`
fn name_tag(l: &str) -> Option<String> {
    let t = l.trim_start();
    let t = t.strip_prefix('#').or_else(|| t.strip_prefix("//"))?.trim_start();
    let n = t.strip_prefix("@name")?;
    let n = n.trim_start_matches([' ', '\t', '=']).trim();
    (!n.is_empty()).then(|| n.to_string())
}

/// `@name = value`
fn file_variable(l: &str) -> Option<(String, String)> {
    let t = l.trim().strip_prefix('@')?;
    let (n, v) = t.split_once('=')?;
    let n = n.trim();
    (!n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')).then(|| (n.to_string(), v.trim().to_string()))
}

fn request_line(l: &str) -> Option<(String, String)> {
    let t = l.trim();
    let mut parts = t.split_whitespace();
    let first = parts.next()?;
    if METHODS.contains(&first.to_ascii_uppercase().as_str()) {
        let url = parts.next()?.to_string();
        return Some((first.to_ascii_uppercase(), url));
    }
    // A bare URL means GET.
    (first.starts_with("http://") || first.starts_with("https://") || first.starts_with("{{")).then(|| ("GET".to_string(), first.to_string()))
}

pub fn parse(text: &str) -> HttpFile {
    let mut out = HttpFile::default();
    let lines: Vec<&str> = text.lines().collect();
    // Blocks start at `###` lines.
    let mut blocks: Vec<(Option<String>, usize, usize)> = Vec::new();
    let mut start = 0;
    let mut title: Option<String> = None;
    for (i, l) in lines.iter().enumerate() {
        if let Some(rest) = l.trim_start().strip_prefix("###") {
            blocks.push((title.take(), start, i));
            let t = rest.trim();
            title = (!t.is_empty()).then(|| t.to_string());
            start = i + 1;
        }
    }
    blocks.push((title, start, lines.len()));
    for (title, from, to) in blocks {
        parse_block(&lines[from..to], from, title, &mut out);
    }
    out
}

fn parse_block(lines: &[&str], offset: usize, title: Option<String>, out: &mut HttpFile) {
    let mut name = title;
    let mut i = 0;
    // Before the request line: blank lines, comments, `@name` tags, file variables.
    let (method, mut url, line) = loop {
        let Some(l) = lines.get(i) else { return };
        i += 1;
        if l.trim().is_empty() {
            continue;
        }
        if let Some(n) = name_tag(l) {
            name = Some(n);
            continue;
        }
        if is_comment(l) {
            continue;
        }
        if let Some(v) = file_variable(l) {
            out.variables.push(v);
            continue;
        }
        match request_line(l) {
            Some((m, u)) => break (m, u, offset + i),
            None => {
                out.warnings.push(format!("line {}: not a request line: {}", offset + i, l.trim()));
                return;
            }
        }
    };
    // JetBrains: query parts continued on indented lines.
    while let Some(l) = lines.get(i) {
        let t = l.trim_start();
        if l.starts_with([' ', '\t']) && (t.starts_with('?') || t.starts_with('&')) {
            url.push_str(t.trim_end());
            i += 1;
        } else {
            break;
        }
    }
    let mut headers = Vec::new();
    while let Some(l) = lines.get(i) {
        i += 1;
        if l.trim().is_empty() {
            break;
        }
        if is_comment(l) {
            continue;
        }
        match l.split_once(':') {
            Some((n, v)) if !n.trim().is_empty() && !n.contains(' ') => headers.push((n.trim().to_string(), v.trim().to_string())),
            _ => out.warnings.push(format!("line {}: not a header: {}", offset + i, l.trim())),
        }
    }
    // Body: up to the end of the block, without response handlers and references.
    let mut body_lines: Vec<&str> = Vec::new();
    let mut in_script = false;
    for (k, l) in lines[i.min(lines.len())..].iter().enumerate() {
        let t = l.trim_start();
        if in_script {
            in_script = !t.contains("%}");
            continue;
        }
        if t.starts_with("> {%") {
            out.warnings.push(format!("line {}: response handler scripts are not run", offset + i + k + 1));
            in_script = !t.contains("%}");
            continue;
        }
        if t.starts_with("> ") || t.starts_with(">> ") || t.starts_with("<> ") {
            out.warnings.push(format!("line {}: ignored: {}", offset + i + k + 1, t));
            continue;
        }
        body_lines.push(l);
    }
    while body_lines.last().is_some_and(|l| l.trim().is_empty()) {
        body_lines.pop();
    }
    let body = match body_lines.as_slice() {
        [] => BodySource::None,
        [one] if one.trim_start().starts_with("< ") => BodySource::File(one.trim_start()[2..].trim().to_string()),
        all => BodySource::Text(all.join("\n")),
    };
    out.requests.push(RawRequest { name, line, method, url, headers, body });
}

// ------------------------------------------------------------- environments

fn read_env_file(path: &Path) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
    match std::fs::read(path) {
        Ok(b) => match serde_json::from_slice::<serde_json::Value>(&b) {
            Ok(serde_json::Value::Object(m)) => Ok(Some(m)),
            Ok(_) => Err(format!("{}: expected an object of environments", path.display())),
            Err(e) => Err(format!("{}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn scalar(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Names of the environments next to a `.http` file (`$shared` not included).
pub fn environments(dir: &Path) -> Result<Vec<String>, String> {
    let mut names = std::collections::BTreeSet::new();
    for f in [ENV_FILE, PRIVATE_ENV_FILE] {
        if let Some(m) = read_env_file(&dir.join(f))? {
            names.extend(m.keys().filter(|k| !k.starts_with('$')).cloned());
        }
    }
    Ok(names.into_iter().collect())
}

/// Variables of environment `name` (`$shared` first, the private file last).
pub fn load_environment(dir: &Path, name: Option<&str>) -> Result<HashMap<String, String>, String> {
    let mut vars = HashMap::new();
    let mut found = name.is_none();
    for f in [ENV_FILE, PRIVATE_ENV_FILE] {
        let Some(m) = read_env_file(&dir.join(f))? else { continue };
        for env in std::iter::once("$shared").chain(name) {
            if let Some(serde_json::Value::Object(o)) = m.get(env) {
                found |= Some(env) == name;
                for (k, v) in o {
                    if let Some(s) = scalar(v) {
                        vars.insert(k.clone(), s);
                    }
                }
            }
        }
    }
    if !found {
        let known = environments(dir).unwrap_or_default();
        return Err(format!("no environment '{}' in {ENV_FILE} or {PRIVATE_ENV_FILE} (known: {})", name.unwrap_or(""), if known.is_empty() { "none".into() } else { known.join(", ") }));
    }
    Ok(vars)
}

// ---------------------------------------------------------------- resolving

struct Resolver<'a> {
    file_vars: HashMap<&'a str, &'a str>,
    env: &'a HashMap<String, String>,
}

impl Resolver<'_> {
    fn dynamic(&self, expr: &str) -> Result<Option<String>, String> {
        let mut parts = expr.split_whitespace();
        let Some(head) = parts.next() else { return Ok(None) };
        let now = time::OffsetDateTime::now_utc();
        Ok(Some(match head {
            "$uuid" | "$random.uuid" | "$guid" => uuid_v4(),
            "$timestamp" => now.unix_timestamp().to_string(),
            "$isoTimestamp" => now.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            "$randomInt" | "$random.integer" => {
                let a: i64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                let b: i64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(1000);
                if b <= a {
                    return Err(format!("{{{{{expr}}}}}: max must be above min"));
                }
                rand::random_range(a..b).to_string()
            }
            "$processEnv" => {
                let n = parts.next().ok_or_else(|| "{{$processEnv}} needs a variable name".to_string())?;
                let optional = n.starts_with('%');
                let n = n.trim_start_matches('%');
                match std::env::var(n) {
                    Ok(v) => v,
                    Err(_) if optional => String::new(),
                    Err(_) => return Err(format!("environment variable {n} is not set")),
                }
            }
            h if h.starts_with('$') => return Err(format!("unsupported dynamic variable {{{{{expr}}}}}")),
            _ => return Ok(None),
        }))
    }

    fn lookup(&self, expr: &str, depth: usize) -> Result<String, String> {
        if depth > 16 {
            return Err(format!("variable {{{{{expr}}}}} refers to itself"));
        }
        if let Some(v) = self.dynamic(expr)? {
            return Ok(v);
        }
        if let Some(v) = self.file_vars.get(expr) {
            return self.subst(v, depth + 1);
        }
        if let Some(v) = self.env.get(expr) {
            return self.subst(v, depth + 1);
        }
        if expr.contains(".response.") || expr.starts_with("client.") {
            return Err(format!("{{{{{expr}}}}}: values from earlier responses are not supported"));
        }
        Err(format!("unknown variable {{{{{expr}}}}}"))
    }

    fn subst(&self, s: &str, depth: usize) -> Result<String, String> {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("{{") {
            out.push_str(&rest[..i]);
            let after = &rest[i + 2..];
            let Some(j) = after.find("}}") else {
                out.push_str(&rest[i..]);
                return Ok(out);
            };
            out.push_str(&self.lookup(after[..j].trim(), depth)?);
            rest = &after[j + 2..];
        }
        out.push_str(rest);
        Ok(out)
    }
}

fn uuid_v4() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Substitute the variables of one request. `dir` resolves `< file` bodies.
pub fn resolve(file: &HttpFile, req: &RawRequest, env: &HashMap<String, String>, dir: &Path) -> Result<Request, String> {
    // Later definitions win, as in both clients.
    let file_vars: HashMap<&str, &str> = file.variables.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let r = Resolver { file_vars, env };
    let at = |e: String| format!("line {}: {e}", req.line);
    let url = r.subst(&req.url, 0).map_err(at)?;
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(at(format!("URL must start with http:// or https:// (got {url})")));
    }
    let mut headers = Vec::new();
    for (n, v) in &req.headers {
        headers.push((r.subst(n, 0).map_err(at)?, r.subst(v, 0).map_err(at)?));
    }
    let body = match &req.body {
        BodySource::None => Body::None,
        BodySource::Text(t) => Body::Text(r.subst(t, 0).map_err(at)?),
        BodySource::File(p) => {
            let p = r.subst(p, 0).map_err(at)?;
            let path = dir.join(&p);
            if !path.is_file() {
                return Err(at(format!("body file {} not found", path.display())));
            }
            Body::File(path)
        }
    };
    Ok(Request { name: req.name.clone(), line: req.line, method: req.method.clone(), url, headers, body })
}

// ------------------------------------------------------------------ writing

/// A captured request for [`write`].
#[derive(Debug, Clone)]
pub struct Captured {
    pub comment: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// Text body, or `None` (then `omitted` says why, if there was one).
    pub body: Option<String>,
    pub omitted: Option<String>,
}

/// Headers that belong to the connection, not the request.
const SKIP_HEADERS: &[&str] = &["host", "content-length", "connection", "proxy-connection", "proxy-authorization", "keep-alive", "transfer-encoding", "te", "upgrade"];

/// Write captured requests as a `.http` file. A scheme and host shared by all requests
/// becomes `{{host}}`; bearer tokens and cookies become `{{token}}` / `{{cookie}}`. Returns
/// the file and the environment values (`host` for `http-client.env.json`; `token`,
/// `cookie` for the private file).
pub fn write(reqs: &[Captured]) -> (String, BTreeMap<String, String>, BTreeMap<String, String>) {
    let origin = |u: &str| -> Option<String> {
        let (scheme, rest) = u.split_once("://")?;
        let auth = rest.split(['/', '?', '#']).next()?;
        Some(format!("{scheme}://{auth}"))
    };
    let shared = reqs.first().and_then(|r| origin(&r.url)).filter(|o| reqs.iter().all(|r| origin(&r.url).as_deref() == Some(o.as_str())));
    let mut public = BTreeMap::new();
    let mut private = BTreeMap::new();
    if let Some(o) = &shared {
        public.insert("host".to_string(), o.clone());
    }
    let mut out = String::new();
    for r in reqs {
        out.push_str(&format!("### {}\n", r.comment.replace('\n', " ")));
        let url = match &shared {
            Some(o) => format!("{{{{host}}}}{}", &r.url[o.len()..]),
            None => r.url.clone(),
        };
        out.push_str(&format!("{} {url}\n", r.method));
        for (n, v) in &r.headers {
            let lower = n.to_ascii_lowercase();
            if SKIP_HEADERS.contains(&lower.as_str()) || n.starts_with(':') {
                continue;
            }
            let v = if lower == "authorization" && v.to_ascii_lowercase().starts_with("bearer ") {
                private.entry("token".to_string()).or_insert_with(|| v[7..].trim().to_string());
                if private.get("token").map(String::as_str) == Some(v[7..].trim()) { "Bearer {{token}}".to_string() } else { v.clone() }
            } else if lower == "cookie" {
                private.entry("cookie".to_string()).or_insert_with(|| v.clone());
                if private.get("cookie") == Some(v) { "{{cookie}}".to_string() } else { v.clone() }
            } else {
                v.clone()
            };
            out.push_str(&format!("{n}: {v}\n"));
        }
        if let Some(b) = &r.body {
            out.push('\n');
            out.push_str(b.trim_end_matches('\n'));
            out.push('\n');
        } else if let Some(why) = &r.omitted {
            out.push_str(&format!("# body omitted: {why}\n"));
        }
        out.push('\n');
    }
    (out, public, private)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"@host = https://api.example.com
@base = {{host}}/v1

### List users
GET {{base}}/users
    ?page=1
    &size={{size}}
Accept: application/json
# a comment
Authorization: Bearer {{token}}

### Create
# @name create
POST {{base}}/users HTTP/1.1
Content-Type: application/json

{
  "id": "{{$uuid}}",
  "name": "x"
}

> {%
  client.test("ok", function() {});
%}

###
// @name upload
PUT {{host}}/files
Content-Type: application/json

< ./body.json
"#;

    #[test]
    fn parses_both_dialects() {
        let f = parse(FILE);
        assert_eq!(f.variables, vec![("host".into(), "https://api.example.com".into()), ("base".into(), "{{host}}/v1".into())]);
        assert_eq!(f.requests.len(), 3);
        let r = &f.requests[0];
        assert_eq!((r.name.as_deref(), r.method.as_str(), r.url.as_str()), (Some("List users"), "GET", "{{base}}/users?page=1&size={{size}}"));
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.body, BodySource::None);
        let r = &f.requests[1];
        assert_eq!(r.name.as_deref(), Some("create"));
        assert_eq!(r.body, BodySource::Text("{\n  \"id\": \"{{$uuid}}\",\n  \"name\": \"x\"\n}".into()));
        assert!(f.warnings.iter().any(|w| w.contains("not run")), "{:?}", f.warnings);
        assert_eq!(f.requests[2].name.as_deref(), Some("upload"));
        assert_eq!(f.requests[2].body, BodySource::File("./body.json".into()));
    }

    #[test]
    fn environments_and_variables() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ENV_FILE), r#"{"$shared":{"size":10},"dev":{"size":20,"token":"public"},"prod":{}}"#).unwrap();
        std::fs::write(dir.path().join(PRIVATE_ENV_FILE), r#"{"dev":{"token":"secret"}}"#).unwrap();
        std::fs::write(dir.path().join("body.json"), "{}").unwrap();
        assert_eq!(environments(dir.path()).unwrap(), vec!["dev", "prod"]);
        let env = load_environment(dir.path(), Some("dev")).unwrap();
        assert_eq!((env["size"].as_str(), env["token"].as_str()), ("20", "secret"));
        assert!(load_environment(dir.path(), Some("qa")).unwrap_err().contains("known: dev, prod"));
        let f = parse(FILE);
        let r = resolve(&f, &f.requests[0], &env, dir.path()).unwrap();
        assert_eq!(r.url, "https://api.example.com/v1/users?page=1&size=20");
        assert_eq!(r.headers[1], ("Authorization".into(), "Bearer secret".into()));
        let r = resolve(&f, &f.requests[1], &env, dir.path()).unwrap();
        let Body::Text(t) = r.body else { panic!() };
        let id = serde_json::from_str::<serde_json::Value>(&t).unwrap()["id"].as_str().unwrap().to_string();
        assert_eq!((id.len(), &id[14..15]), (36, "4"));
        assert_eq!(resolve(&f, &f.requests[2], &env, dir.path()).unwrap().body, Body::File(dir.path().join("./body.json")));
        // Without the environment the token is unknown.
        let e = resolve(&f, &f.requests[0], &HashMap::new(), dir.path()).unwrap_err();
        assert!(e.contains("unknown variable {{size}}") && e.starts_with("line 5"), "{e}");
    }

    #[test]
    fn errors() {
        let f = parse("@a = {{b}}\n@b = {{a}}\nGET {{a}}/x\n");
        assert!(resolve(&f, &f.requests[0], &HashMap::new(), Path::new(".")).unwrap_err().contains("refers to itself"));
        let f = parse("GET {{login.response.body.token}}\n");
        assert!(resolve(&f, &f.requests[0], &HashMap::new(), Path::new(".")).unwrap_err().contains("earlier responses"));
        let f = parse("GET /relative\n");
        assert!(resolve(&f, &f.requests[0], &HashMap::new(), Path::new(".")).unwrap_err().contains("http://"));
        let f = parse("hello world\n");
        assert!(f.requests.is_empty() && f.warnings[0].contains("not a request line"));
    }

    #[test]
    fn writes_and_reads_back() {
        let reqs = vec![
            Captured {
                comment: "#1".into(),
                method: "GET".into(),
                url: "https://api.example.com/a?x=1".into(),
                headers: vec![("Host".into(), "api.example.com".into()), ("Authorization".into(), "Bearer abc".into()), ("Accept".into(), "*/*".into())],
                body: None,
                omitted: None,
            },
            Captured {
                comment: "#2".into(),
                method: "POST".into(),
                url: "https://api.example.com/b".into(),
                headers: vec![("Content-Type".into(), "application/json".into()), ("Content-Length".into(), "2".into())],
                body: Some("{}".into()),
                omitted: None,
            },
        ];
        let (text, public, private) = write(&reqs);
        assert_eq!(public["host"], "https://api.example.com");
        assert_eq!(private["token"], "abc");
        assert!(!text.contains("Content-Length") && !text.contains("Host:") && text.contains("Bearer {{token}}"), "{text}");
        let f = parse(&text);
        let env: HashMap<String, String> = public.into_iter().chain(private).collect();
        let r = resolve(&f, &f.requests[0], &env, Path::new(".")).unwrap();
        assert_eq!(r.url, "https://api.example.com/a?x=1");
        assert_eq!(r.headers[0], ("Authorization".into(), "Bearer abc".into()));
        let r = resolve(&f, &f.requests[1], &env, Path::new(".")).unwrap();
        assert_eq!((r.method.as_str(), r.body), ("POST", Body::Text("{}".into())));
    }
}
