//! Recording MCP servers that talk over stdio. A proxy never sees them: `quena-cli mcp-tap
//! --name jira -- npx server` runs the server, passes stdin and stdout through unchanged, pairs
//! the JSON-RPC requests with their responses and appends each exchange as a JSON line to
//! `<data folder>/mcp-tap/<name>-<pid>.jsonl`. The app reads that folder every second and
//! shows the exchanges as sessions (`stdio://jira/tools/call`) while it captures.

use crate::AppCore;
use crate::mcp_traffic;
use quena_model::{Headers, HttpVersion, ProcessInfo, RequestHead, ResponseHead, SessionDetail, SessionState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Folder of the recordings, in the data folder.
pub const TAP_DIR: &str = "mcp-tap";
/// Recordings read completely and not written for this long are removed.
const KEEP_SECS: u64 = 7 * 24 * 3600;
/// Longest line read (a message larger than this is skipped).
const MAX_LINE: usize = 32 << 20;

/// The first line of a recording.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TapHeader {
    pub name: String,
    pub command: String,
    pub pid: u32,
    pub started: i64,
}

/// One exchange: a request (or notification) and its response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TapExchange {
    /// Microseconds since the epoch: request sent, response received.
    pub t0: i64,
    pub t1: i64,
    /// Who sent the request: `client` or `server` (sampling, roots, elicitation).
    pub from: String,
    pub request: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Line {
    Tap(TapHeader),
    Exchange(TapExchange),
}

fn now_us() -> i64 {
    quena_model::now_us()
}

fn id_key(v: &Value) -> Option<String> {
    v.get("id").filter(|i| !i.is_null()).map(|i| i.to_string())
}

/// Pairs messages of both directions and writes the exchanges.
struct Pairing {
    /// Requests waiting for their response, by (sender, id).
    pending: HashMap<(String, String), (i64, Value)>,
    out: Box<dyn Write + Send>,
}

impl Pairing {
    fn write(&mut self, l: &Line) {
        if let Ok(mut s) = serde_json::to_string(l) {
            s.push('\n');
            let _ = self.out.write_all(s.as_bytes());
            let _ = self.out.flush();
        }
    }

    /// A line `from` sent (`client` or `server`).
    fn message(&mut self, from: &str, line: &[u8]) {
        let Ok(v) = serde_json::from_slice::<Value>(line) else { return };
        let items = match v {
            Value::Array(a) => a,
            v => vec![v],
        };
        for m in items {
            let t = now_us();
            let has_method = m.get("method").is_some();
            match (has_method, id_key(&m)) {
                (true, Some(id)) => {
                    self.pending.insert((from.to_string(), id), (t, m));
                }
                (true, None) => self.write(&Line::Exchange(TapExchange { t0: t, t1: t, from: from.into(), request: m, response: None })),
                (false, Some(id)) => {
                    // A response answers a request of the other side.
                    let other = if from == "client" { "server" } else { "client" };
                    if let Some((t0, req)) = self.pending.remove(&(other.to_string(), id)) {
                        self.write(&Line::Exchange(TapExchange { t0, t1: t, from: other.into(), request: req, response: Some(m) }));
                    }
                }
                (false, None) => {}
            }
        }
    }
}

/// Copy lines from `from` to `to`, handing each to `seen`. Ends at end of input.
fn pump(from: impl Read, mut to: impl Write, mut seen: impl FnMut(&[u8])) {
    let mut r = BufReader::new(from);
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if to.write_all(&line).and_then(|_| to.flush()).is_err() {
                    break;
                }
                if line.len() <= MAX_LINE {
                    seen(line.trim_ascii());
                }
            }
        }
    }
}

/// Run `command` with `args` as an MCP server between our stdin/stdout and record its
/// exchanges under `data/mcp-tap`. Returns the server's exit code.
pub fn run(data: &Path, name: &str, command: &str, args: &[String], child_slot: &Mutex<Option<std::process::Child>>) -> anyhow::Result<i32> {
    let dir = data.join(TAP_DIR);
    std::fs::create_dir_all(&dir)?;
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let path = dir.join(format!("{safe}-{}.jsonl", std::process::id()));
    let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    let mut child = std::process::Command::new(command).args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit()).spawn().map_err(|e| anyhow::anyhow!("{command}: {e}"))?;
    let (child_in, child_out) = (child.stdin.take().expect("piped"), child.stdout.take().expect("piped"));
    let pairing = Arc::new(Mutex::new(Pairing { pending: HashMap::new(), out: Box::new(file) }));
    let cmdline = std::iter::once(command.to_string()).chain(args.iter().cloned()).collect::<Vec<_>>().join(" ");
    pairing.lock().unwrap().write(&Line::Tap(TapHeader { name: name.into(), command: cmdline, pid: child.id(), started: now_us() }));
    *child_slot.lock().unwrap() = Some(child);
    let p = pairing.clone();
    // Client → server; at the end of our input the server's input closes too.
    let up = std::thread::spawn(move || pump(std::io::stdin(), child_in, |l| p.lock().unwrap().message("client", l)));
    let p = pairing.clone();
    pump(child_out, std::io::stdout(), |l| p.lock().unwrap().message("server", l));
    drop(up);
    let status = child_slot.lock().unwrap().take().map(|mut c| c.wait());
    Ok(match status {
        Some(Ok(s)) => s.code().unwrap_or(1),
        _ => 1,
    })
}

/// What the app has read of the recordings.
#[derive(Default)]
pub struct TapState {
    files: HashMap<PathBuf, Reading>,
}

struct Reading {
    offset: u64,
    header: Option<TapHeader>,
}

/// Where the read position of a recording is kept (it survives a restart of the app).
fn mark_path(p: &Path) -> PathBuf {
    p.with_extension("jsonl.read")
}

impl AppCore {
    /// Read new exchanges of stdio MCP servers recorded by `quena-cli mcp-tap` (called every
    /// second). They become sessions while capturing; otherwise they are skipped.
    pub fn mcp_tap_tick(&self) {
        let dir = self.paths.data.join(TAP_DIR);
        let Ok(entries) = std::fs::read_dir(&dir) else { return };
        let capturing = self.engine().is_some_and(|e| e.status().capturing);
        let mut st = self.mcp_taps.lock();
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            let reading = st.files.entry(path.clone()).or_insert_with(|| Reading { offset: std::fs::read_to_string(mark_path(&path)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0), header: None });
            if meta.len() > reading.offset {
                let before = reading.offset;
                self.tap_read(&path, reading, capturing);
                if reading.offset != before {
                    let _ = std::fs::write(mark_path(&path), reading.offset.to_string());
                }
            } else if meta.len() == reading.offset && meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age.as_secs() > KEEP_SECS) {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(mark_path(&path));
                st.files.remove(&path);
            }
        }
    }

    fn tap_read(&self, path: &Path, reading: &mut Reading, capturing: bool) {
        let Ok(mut f) = std::fs::File::open(path) else { return };
        if f.seek(SeekFrom::Start(reading.offset)).is_err() {
            return;
        }
        let mut r = BufReader::new(f);
        let mut line = Vec::new();
        loop {
            line.clear();
            let Ok(n) = r.read_until(b'\n', &mut line) else { break };
            // Only complete lines (the writer may be in the middle of one).
            if n == 0 || line.last() != Some(&b'\n') {
                break;
            }
            reading.offset += n as u64;
            match serde_json::from_slice::<Line>(line.trim_ascii()) {
                Ok(Line::Tap(h)) => reading.header = Some(h),
                Ok(Line::Exchange(x)) if capturing => {
                    if reading.header.is_none() {
                        reading.header = first_header(path);
                    }
                    self.tap_insert(reading.header.as_ref(), path, x);
                }
                _ => {}
            }
        }
    }

    fn tap_insert(&self, header: Option<&TapHeader>, path: &Path, x: TapExchange) {
        let name = header.map(|h| h.name.clone()).unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("stdio").to_string());
        let method = x.request.get("method").and_then(|m| m.as_str()).unwrap_or("message");
        let side = if x.from == "server" { "server/" } else { "" };
        let host: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c.to_ascii_lowercase() } else { '-' }).collect();
        let mut json = Headers::default();
        json.push("Content-Type", "application/json");
        let mut d = SessionDetail::default();
        d.request = RequestHead { method: "POST".into(), url: format!("stdio://{host}/{side}{method}"), version: HttpVersion::Http11, headers: json.clone() };
        d.response = Some(ResponseHead { status: if x.response.is_some() { 200 } else { 202 }, reason: String::new(), version: HttpVersion::Http11, headers: json });
        d.summary.state = SessionState::Done;
        d.timers.client_begin_request = Some(x.t0);
        d.timers.client_done_response = Some(x.t1.max(x.t0));
        if let Some(h) = header {
            let exe = h.command.split_whitespace().next().unwrap_or("").rsplit(['/', '\\']).next().unwrap_or("").to_string();
            d.process = Some(ProcessInfo { pid: h.pid, name: exe });
        }
        let cap = self.capture();
        let req = cap.bodies.store_bytes(x.request.to_string().as_bytes());
        let resp = cap.bodies.store_bytes(x.response.as_ref().map(|r| r.to_string()).unwrap_or_default().as_bytes());
        let req_text = x.request.to_string();
        let resp_text = x.response.as_ref().map(|r| r.to_string()).unwrap_or_default();
        if let Some(ex) = mcp_traffic::decode(&d.request.url, &d.request.headers, req_text.as_bytes(), d.response.as_ref().map(|r| &r.headers), resp_text.as_bytes()) {
            let label = if side.is_empty() { ex.label.clone() } else { format!("server: {}", ex.label) };
            d.extra_flags.push((mcp_traffic::MCP_FLAG.into(), label));
            d.extra_flags.push((mcp_traffic::MCP_SERVER_FLAG.into(), ex.server.map(|s| s.0).filter(|n| !n.is_empty()).unwrap_or(name)));
        }
        cap.insert(d, req, resp);
    }
}

/// The header of a recording (its first line).
fn first_header(path: &Path) -> Option<TapHeader> {
    let f = std::fs::File::open(path).ok()?;
    let mut line = String::new();
    BufReader::new(f).take(1 << 20).read_line(&mut line).ok()?;
    match serde_json::from_str::<Line>(line.trim()).ok()? {
        Line::Tap(h) => Some(h),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn requests_pair_with_their_responses() {
        let buf = Buf::default();
        let mut p = Pairing { pending: HashMap::new(), out: Box::new(buf.clone()) };
        p.message("client", br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        p.message("client", br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        // The server asks the client (sampling) before it answers.
        p.message("server", br#"{"jsonrpc":"2.0","id":1,"method":"roots/list"}"#);
        p.message("client", br#"{"jsonrpc":"2.0","id":1,"result":{"roots":[]}}"#);
        p.message("server", br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#);
        p.message("server", b"not json");
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<Line> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let ex: Vec<&TapExchange> = lines.iter().filter_map(|l| if let Line::Exchange(x) = l { Some(x) } else { None }).collect();
        assert_eq!(ex.len(), 3);
        assert_eq!((ex[0].from.as_str(), ex[0].response.is_none()), ("client", true), "the notification");
        assert_eq!((ex[1].from.as_str(), ex[1].request["method"].as_str()), ("server", Some("roots/list")));
        assert_eq!((ex[2].from.as_str(), ex[2].request["method"].as_str()), ("client", Some("tools/list")));
    }

    #[test]
    fn pump_passes_everything_through() {
        let input = b"{\"a\":1}\npartial".to_vec();
        let out = Buf::default();
        let mut seen = vec![];
        pump(&input[..], out.clone(), |l| seen.push(l.to_vec()));
        assert_eq!(*out.0.lock().unwrap(), input);
        assert_eq!(seen, vec![b"{\"a\":1}".to_vec(), b"partial".to_vec()]);
    }
}
