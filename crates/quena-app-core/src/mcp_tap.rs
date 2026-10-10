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
/// Longest line recorded (a larger message is passed on but not recorded).
const MAX_LINE: usize = 32 << 20;
/// Bytes of recordings the app reads per second (the rest follows in the next seconds).
const READ_BUDGET: u64 = 4 << 20;
/// Requests waiting for an answer that are kept (the oldest are written without one).
const MAX_PENDING: usize = 10_000;
/// Largest recording file: past it, exchanges are no longer written (the server runs on).
const MAX_FILE: u64 = 1 << 30;

/// The first line of a recording.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TapHeader {
    pub name: String,
    pub command: String,
    /// The program run (`npx`, `C:\\Program Files\\nodejs\\npx.cmd`).
    #[serde(default)]
    pub program: String,
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
    /// The recording (opened again when it was removed, e.g. after a week without exchanges),
    /// and its first line.
    path: Option<PathBuf>,
    header: Option<TapHeader>,
    /// Size of the recording (at its start, then as written).
    size: u64,
}

impl Pairing {
    fn write(&mut self, l: &Line) {
        if let Some(p) = &self.path
            && !p.exists()
            && let Ok(f) = open_recording(p)
        {
            self.out = Box::new(f);
            self.size = 0;
            if let Some(h) = self.header.clone() {
                self.write_line(&Line::Tap(h));
            }
        }
        self.write_line(l);
    }

    fn write_line(&mut self, l: &Line) {
        if let Ok(mut s) = serde_json::to_string(l) {
            s.push('\n');
            if self.size.saturating_add(s.len() as u64) > MAX_FILE {
                if self.size <= MAX_FILE {
                    eprintln!("quena mcp-tap: the recording reached {} MB, further exchanges are not recorded", MAX_FILE >> 20);
                    self.size = MAX_FILE + 1;
                }
                return;
            }
            self.size += s.len() as u64;
            let _ = self.out.write_all(s.as_bytes());
            let _ = self.out.flush();
        }
    }

    /// Requests still without an answer (the server ended, or they were cancelled).
    fn flush_pending(&mut self, keep: usize) {
        if self.pending.len() <= keep {
            return;
        }
        let mut all: Vec<((String, String), (i64, Value))> = self.pending.drain().collect();
        all.sort_by_key(|(_, (t, _))| *t);
        let rest = all.split_off(all.len().saturating_sub(keep));
        for ((from, _), (t0, req)) in all {
            self.write(&Line::Exchange(TapExchange { t0, t1: now_us(), from, request: req, response: None }));
        }
        self.pending.extend(rest);
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
                    if self.pending.len() > MAX_PENDING {
                        self.flush_pending(MAX_PENDING / 2);
                    }
                }
                (true, None) => {
                    // A cancelled request is written without its answer.
                    if m.get("method").and_then(|x| x.as_str()) == Some("notifications/cancelled")
                        && let Some(id) = m.get("params").and_then(|p| p.get("requestId")).filter(|i| !i.is_null()).map(|i| i.to_string())
                        && let Some((t0, req)) = self.pending.remove(&(from.to_string(), id))
                    {
                        self.write(&Line::Exchange(TapExchange { t0, t1: t, from: from.into(), request: req, response: None }));
                    }
                    self.write(&Line::Exchange(TapExchange { t0: t, t1: t, from: from.into(), request: m, response: None }));
                }
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
/// Everything is passed on as it comes; a line longer than [`MAX_LINE`] is not kept (nor seen).
fn pump(from: impl Read, mut to: impl Write, mut seen: impl FnMut(&[u8])) {
    let mut r = BufReader::new(from);
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = match r.fill_buf() {
            Ok([]) | Err(_) => break,
            Ok(c) => c,
        };
        let (part, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (&chunk[..=i], true),
            None => (chunk, false),
        };
        if to.write_all(part).and_then(|_| if done { to.flush() } else { Ok(()) }).is_err() {
            break;
        }
        if !too_long {
            if line.len() + part.len() > MAX_LINE + 1 {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(part);
            }
        }
        let n = part.len();
        r.consume(n);
        if done {
            if !too_long {
                seen(line.trim_ascii());
            }
            line.clear();
            too_long = false;
        }
    }
    let _ = to.flush();
    if !too_long && !line.is_empty() {
        seen(line.trim_ascii());
    }
}

/// Open a recording for appending (only for the user on Unix: it holds tool results).
fn open_recording(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
}

fn make_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// The program to start and the arguments before the user's: on Windows, a command without
/// extension is looked up with PATHEXT, and `.cmd`/`.bat` files (npx, uvx shims) run through
/// cmd.exe, which `Command` does not do by itself.
fn program(command: &str) -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        let p = Path::new(command);
        let found = if p.extension().is_some() || p.components().count() > 1 {
            Some(p.to_path_buf())
        } else {
            let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
            std::env::var_os("PATH").and_then(|path| std::env::split_paths(&path).flat_map(|d| exts.split(';').filter(|e| !e.is_empty()).map(move |e| d.join(format!("{command}{e}")))).find(|c| c.is_file()))
        };
        if let Some(f) = found {
            let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
            if ext == "cmd" || ext == "bat" {
                return ("cmd.exe".into(), vec!["/d".into(), "/s".into(), "/c".into(), f.display().to_string()]);
            }
            return (f.display().to_string(), vec![]);
        }
    }
    (command.to_string(), vec![])
}

/// Run `command` with `args` as an MCP server between our stdin/stdout and record its
/// exchanges under `data/mcp-tap`. Recording never stops the server: when the folder cannot be
/// written, it runs without. `pid` gets the server's process id (to pass signals on). Returns
/// the server's exit code (128 + signal when a signal ended it).
pub fn run(data: &Path, name: &str, command: &str, args: &[String], pid: &std::sync::atomic::AtomicU32) -> anyhow::Result<i32> {
    let dir = data.join(TAP_DIR);
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let path = dir.join(format!("{safe}-{}.jsonl", std::process::id()));
    let file = match make_dir(&dir).and_then(|_| open_recording(&path)) {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!("quena-cli mcp-tap: not recording, {} cannot be written: {e}", path.display());
            None
        }
    };
    let (prog, mut pre) = program(command);
    pre.extend(args.iter().cloned());
    let mut child = std::process::Command::new(&prog).args(&pre).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit()).spawn().map_err(|e| anyhow::anyhow!("{command}: {e}"))?;
    pid.store(child.id(), std::sync::atomic::Ordering::SeqCst);
    let (child_in, child_out) = (child.stdin.take().expect("piped"), child.stdout.take().expect("piped"));
    let recording = file.is_some();
    let header = TapHeader { name: name.into(), command: std::iter::once(command.to_string()).chain(args.iter().cloned()).collect::<Vec<_>>().join(" "), program: command.to_string(), pid: child.id(), started: now_us() };
    let pairing = Arc::new(Mutex::new(Pairing { pending: HashMap::new(), out: file.map(|f| Box::new(f) as Box<dyn Write + Send>).unwrap_or_else(|| Box::new(std::io::sink())), path: recording.then(|| path.clone()), header: Some(header.clone()), size: std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) }));
    if recording {
        pairing.lock().unwrap().write(&Line::Tap(header));
    }
    let p = pairing.clone();
    // Client → server; at the end of our input the server's input closes too.
    let up = std::thread::spawn(move || pump(std::io::stdin(), child_in, |l| if recording { p.lock().unwrap().message("client", l) }));
    let p = pairing.clone();
    pump(child_out, std::io::stdout(), |l| if recording { p.lock().unwrap().message("server", l) });
    drop(up);
    let status = child.wait();
    if recording {
        pairing.lock().unwrap().flush_pending(0);
    }
    Ok(match status {
        Ok(s) => exit_code(&s),
        Err(_) => 1,
    })
}

fn exit_code(s: &std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    if let Some(sig) = std::os::unix::process::ExitStatusExt::signal(s) {
        return 128 + sig;
    }
    s.code().unwrap_or(1)
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

fn save_mark(p: &Path, offset: u64) {
    let (mark, tmp) = (mark_path(p), p.with_extension("jsonl.read.tmp"));
    if std::fs::write(&tmp, offset.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, &mark);
    }
}

impl AppCore {
    /// Read new exchanges of stdio MCP servers recorded by `quena-cli mcp-tap` (called every
    /// second). They become sessions while capturing; otherwise they are skipped.
    pub fn mcp_tap_tick(&self) {
        // Exchanges are kept in the files until Quena captures (then they show).
        if !self.engine().is_some_and(|e| e.status().capturing) {
            return;
        }
        let dir = self.paths.data.join(TAP_DIR);
        let Ok(entries) = std::fs::read_dir(&dir) else { return };
        let mut st = self.mcp_taps.lock();
        let mut budget = READ_BUDGET;
        let mut marks = Vec::new();
        for e in entries.flatten() {
            let path = e.path();
            let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
            // A read position whose recording is gone.
            if ext == "read" && !path.with_extension("").exists() {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if ext != "jsonl" {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            let reading = st.files.entry(path.clone()).or_insert_with(|| Reading { offset: std::fs::read_to_string(mark_path(&path)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0), header: None });
            // Shorter than what was read: another file of that name.
            if meta.len() < reading.offset {
                *reading = Reading { offset: 0, header: None };
            }
            if meta.len() > reading.offset && budget > 0 {
                let before = reading.offset;
                budget = budget.saturating_sub(self.tap_read(&path, reading, budget));
                if reading.offset != before {
                    save_mark(&path, reading.offset);
                }
            } else if meta.len() == reading.offset && meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age.as_secs() > KEEP_SECS) {
                marks.push(path);
            }
        }
        for path in marks {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(mark_path(&path));
            st.files.remove(&path);
        }
        st.files.retain(|p, _| p.exists());
    }

    /// Read complete lines of a recording up to `budget` bytes; returns the bytes read.
    fn tap_read(&self, path: &Path, reading: &mut Reading, budget: u64) -> u64 {
        let Ok(mut f) = std::fs::File::open(path) else { return 0 };
        if f.seek(SeekFrom::Start(reading.offset)).is_err() {
            return 0;
        }
        let mut r = BufReader::new(f);
        let mut line = Vec::new();
        let mut read = 0u64;
        let mut skipping = false;
        while read < budget {
            line.clear();
            let Ok(n) = (&mut r).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line) else { break };
            let complete = line.last() == Some(&b'\n');
            // A line too long to keep: passed over up to its end.
            if n > MAX_LINE || (skipping && n > 0) {
                reading.offset += n as u64;
                read += n as u64;
                skipping = !complete;
                continue;
            }
            // Only complete lines (the writer may be in the middle of one).
            if n == 0 || !complete {
                break;
            }
            reading.offset += n as u64;
            read += n as u64;
            match serde_json::from_slice::<Line>(line.trim_ascii()) {
                Ok(Line::Tap(h)) => reading.header = Some(h),
                Ok(Line::Exchange(x)) => {
                    if reading.header.is_none() {
                        reading.header = first_header(path);
                    }
                    self.tap_insert(reading.header.as_ref(), path, x);
                }
                _ => {}
            }
        }
        read
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
        // Times from another process's file: never before the epoch, never ending before the start.
        let t0 = x.t0.max(0);
        d.timers.client_begin_request = Some(t0);
        d.timers.client_done_response = Some(x.t1.max(t0));
        if let Some(h) = header {
            let prog = if h.program.is_empty() { h.command.split_whitespace().next().unwrap_or("") } else { h.program.as_str() };
            let exe = prog.rsplit(['/', '\\']).next().unwrap_or("").to_string();
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
            // The name it was given (what the client calls it), for every exchange alike.
            d.extra_flags.push((mcp_traffic::MCP_SERVER_FLAG.into(), name));
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
        let mut p = Pairing { pending: HashMap::new(), out: Box::new(buf.clone()), path: None, header: None, size: 0 };
        p.message("client", br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        p.message("client", br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        // The server asks the client (sampling) before it answers.
        p.message("server", br#"{"jsonrpc":"2.0","id":1,"method":"roots/list"}"#);
        p.message("client", br#"{"jsonrpc":"2.0","id":1,"result":{"roots":[]}}"#);
        p.message("server", br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#);
        p.message("server", b"not json");
        // A request never answered is written when the tap ends.
        p.message("client", br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"slow"}}"#);
        p.flush_pending(0);
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<Line> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let ex: Vec<&TapExchange> = lines.iter().filter_map(|l| if let Line::Exchange(x) = l { Some(x) } else { None }).collect();
        assert_eq!(ex.len(), 4);
        assert!(ex[3].response.is_none() && ex[3].request["id"] == 9);
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
