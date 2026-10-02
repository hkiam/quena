//! `quena-cli`: Quena's diagnostics without a window, for CI pipelines.
//!
//! `quena-cli diagnose capture.har --baseline main.json --fail-on critical` imports the
//! captures into a temporary store, runs the diagnostics analyzer (the same plugin and the same
//! redaction as the app), compares the report with a baseline and exits with 1 when the
//! quality gate fails. Nothing touches the system proxy, the keychain or the app's data.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use quena_app_core::diagnostics::DiagFilter;
use quena_app_core::{AppCore, Paths, WaitError};
use quena_report::gate::{self, GateConfig, GateResult};
use quena_report::{Comparison, Lang, MdOptions, Report, Severity};
use serde_json::{Map, Value};

const ANALYZER: &str = "io.github.hkiam.webdiag";

/// Exit codes (documented in `--help` and the manual).
const EXIT_GATE: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_ANALYSIS: u8 = 3;
/// Interrupted (Ctrl-C, SIGTERM), as shells report SIGINT.
const EXIT_INTERRUPTED: i32 = 130;

/// The engine's temporary data directory, removed when the run is interrupted.
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

#[derive(Parser)]
#[command(
    name = "quena-cli",
    version,
    about = "Quena diagnostics for CI: analyse HAR/SAZ captures, compare with a baseline, fail the build on regressions."
)]
#[command(
    after_help = "Exit codes: 0 gate passed, 1 gate failed, 2 usage or input error, 3 analysis error.\n\
Reports contain URLs and host names (tokens, cookie values and secret URL parameters are removed before the analysis); check them before you publish them."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyse captures and apply the quality gate.
    Diagnose(Diagnose),
    /// Compare two saved JSON reports (no new analysis) and apply the quality gate.
    Compare(CompareArgs),
    /// Write a sanitized copy of captures for sharing (support, vendors): credentials,
    /// tokens and, with `--preset gdpr`, personal data are replaced.
    Sanitize(SanitizeArgs),
    /// Turn captures into mocks: a WireMock folder/ZIP or a Quena mock package.
    Mock(MockArgs),
    /// `.http` request collections (JetBrains HTTP Client, VS Code REST Client).
    Http {
        #[command(subcommand)]
        command: HttpCommand,
    },
    /// List the analysis profiles and options of the analyzer.
    Profiles {
        #[arg(long, default_value = "en")]
        lang: String,
        #[command(flatten)]
        plugins: PluginArgs,
    },
}

#[derive(Args)]
struct Diagnose {
    /// Captures to analyse together (.har, .saz).
    #[arg(required = true, value_name = "CAPTURE")]
    files: Vec<PathBuf>,
    /// Analysis profile: full, performance, troubleshooting, auth, resilience, modernization.
    #[arg(long)]
    profile: Option<String>,
    /// Language of the report texts (en, de).
    #[arg(long)]
    lang: Option<String>,
    /// Analyzer option, e.g. `--set slowMs=1500` (repeatable; values are JSON or text;
    /// language and profile are set with --lang and --profile).
    #[arg(long = "set", value_name = "KEY=VALUE")]
    set: Vec<String>,
    /// Only sessions to these hosts (`api.example.com`, `*.example.com`; repeatable).
    #[arg(long = "host", value_name = "PATTERN")]
    hosts: Vec<String>,
    /// Only sessions of these processes (SAZ captures; repeatable).
    #[arg(long = "process", value_name = "NAME")]
    processes: Vec<String>,
    #[command(flatten)]
    gate: GateArgs,
    #[command(flatten)]
    out: OutArgs,
    #[command(flatten)]
    plugins: PluginArgs,
    /// Give up when the whole run (loading the plugins, all imports and the analysis) takes
    /// longer than this many seconds; exit code 3.
    #[arg(long, value_name = "SECONDS", default_value_t = 600)]
    timeout: u64,
}

#[derive(Args)]
struct SanitizeArgs {
    /// Captures to sanitize together (.har, .saz).
    #[arg(required = true, value_name = "CAPTURE")]
    files: Vec<PathBuf>,
    /// The sanitized archive (.saz or .har).
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    output: PathBuf,
    /// support (credentials, tokens, e-mail, payment data), gdpr (also phone numbers, IP
    /// addresses, personal fields, national ids, process names; bodies truncated) or
    /// credentials (only credentials and tokens).
    #[arg(long, default_value = "support")]
    preset: String,
    /// Sanitize options (JSON: the options object, or the app's saved `{"options": …,
    /// "format": …}`); replaces --preset. Unknown keys are an error (exit 2).
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Also write the redaction log (`.json` or text).
    #[arg(long, value_name = "PATH")]
    log: Option<PathBuf>,
    /// No progress messages on stderr (errors only).
    #[arg(short, long)]
    quiet: bool,
    /// Give up when the whole run (imports, sanitizing, writing) takes longer than this many
    /// seconds; exit code 3.
    #[arg(long, default_value_t = 600)]
    timeout: u64,
}

#[derive(Subcommand)]
enum HttpCommand {
    /// Send the requests of a .http file one after the other and print status and time.
    /// Exit code 1 when a request fails or answers with a status of 400 or above.
    Run(HttpRunArgs),
    /// Write the requests of captures (.har, .saz) as a .http file (with
    /// http-client.env.json / http-client.private.env.json next to it).
    FromHar(HttpFromArgs),
}

#[derive(Args)]
struct HttpRunArgs {
    /// The .http file.
    file: PathBuf,
    /// Environment from http-client.env.json (and http-client.private.env.json) next to it.
    #[arg(long)]
    env: Option<String>,
    /// Only these requests (`# @name` / `### title`, or `line:N`; repeatable).
    #[arg(long = "name", value_name = "NAME")]
    names: Vec<String>,
    /// Also save the requests with their responses (.har or .saz).
    #[arg(long, value_name = "PATH")]
    save: Option<PathBuf>,
    /// Wait at most this many seconds for each response.
    #[arg(long, value_name = "SECONDS", default_value_t = 30)]
    timeout: u64,
}

#[derive(Args)]
struct HttpFromArgs {
    /// Captures (.har, .saz).
    #[arg(required = true, value_name = "CAPTURE")]
    files: Vec<PathBuf>,
    /// The .http file to write.
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    output: PathBuf,
    /// Replace an existing file.
    #[arg(long)]
    overwrite: bool,
}

#[derive(Args)]
struct MockArgs {
    /// Captures to turn into mocks (.har, .saz).
    #[arg(required = true, value_name = "CAPTURE")]
    files: Vec<PathBuf>,
    /// WireMock mappings and __files: a folder (its old mappings and __files are replaced),
    /// or a `.zip`.
    #[arg(long, value_name = "PATH", required_unless_present = "package")]
    wiremock: Option<PathBuf>,
    /// Quena mock package (must end in `.quena-mocks`), for Mock Rules → Import package.
    #[arg(long, value_name = "PATH")]
    package: Option<PathBuf>,
    /// Mock options (JSON: hosts, includeStatic, query, ignoreParams, repeats, matchBody,
    /// latency, includePreflight, includeErrors, sanitize, keepSetCookie; `sanitize` is a
    /// preset name, null or full sanitize options); flags win. Unknown keys are an error.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Only these hosts (repeatable; subdomains included).
    #[arg(long = "host", value_name = "HOST")]
    hosts: Vec<String>,
    /// Several recordings of a request answer in recorded order (default: the last one wins).
    #[arg(long)]
    sequence: bool,
    /// Match the query string exactly (default: cache busters and utm_* are ignored).
    #[arg(long)]
    exact_query: bool,
    /// Include scripts, styles, images and fonts.
    #[arg(long)]
    include_static: bool,
    /// Answer after the recorded time to first byte.
    #[arg(long)]
    latency: bool,
    /// Sanitize preset for the mocks: credentials (the default: credentials and tokens),
    /// support, gdpr, or `none` (as recorded).
    #[arg(long, value_name = "PRESET")]
    sanitize: Option<String>,
    /// No progress messages on stderr (errors only).
    #[arg(short, long)]
    quiet: bool,
    /// Give up when the whole run (imports, building and writing the mocks) takes longer
    /// than this many seconds; exit code 3.
    #[arg(long, default_value_t = 600)]
    timeout: u64,
}

#[derive(Args)]
struct CompareArgs {
    /// The baseline report (JSON).
    before: PathBuf,
    /// The new report (JSON).
    after: PathBuf,
    /// Language of the frame texts (en, de); defaults to the language of the new report
    /// (en when it is neither).
    #[arg(long)]
    lang: Option<String>,
    #[command(flatten)]
    gate: GateArgs,
    #[command(flatten)]
    out: OutArgs,
}

#[derive(Args)]
struct GateArgs {
    /// Baseline report (JSON from an earlier run): only new or worse findings break the gate.
    #[arg(long, value_name = "REPORT")]
    baseline: Option<PathBuf>,
    /// Fail on findings of this severity or worse.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
    /// With a baseline, findings already in it break the gate too.
    #[arg(long, overrides_with = "no_fail_on_existing")]
    fail_on_existing: bool,
    /// Only new or worsened findings break the gate, even when the settings file says
    /// `failOnExisting: true`.
    #[arg(long, overrides_with = "fail_on_existing")]
    no_fail_on_existing: bool,
    /// Metric budget, e.g. `requests=+10%` (against the baseline) or `errors=0` (repeatable).
    #[arg(long = "budget", value_name = "METRIC=LIMIT")]
    budgets: Vec<String>,
    /// Never fail on a rule (`OAUTH-FLOW`) or a finding key (repeatable).
    #[arg(long = "ignore", value_name = "RULE|KEY")]
    ignore: Vec<String>,
    /// Settings file (JSON): failOn, failOnExisting, budgets, ignore, and for `diagnose`
    /// profile, lang, options, hosts, processes (`compare` ignores those, so one file serves
    /// both). Command line arguments win.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Args)]
struct OutArgs {
    /// Output format on stdout (default md; none for nothing).
    #[arg(long, value_enum)]
    format: Option<Format>,
    /// Also write a format to a file, e.g. `-o junit=junit.xml -o json=report.json` (repeatable).
    #[arg(short = 'o', long = "output", value_name = "FORMAT=PATH")]
    outputs: Vec<String>,
    /// No summary on stderr.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
struct PluginArgs {
    /// Folder with the plugins; only this folder is searched (default: QUENA_PLUGIN_DIR, then
    /// next to the program).
    #[arg(long, value_name = "DIR")]
    plugins: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Critical,
    Warning,
    Info,
    None,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum Format {
    Json,
    Md,
    Junit,
    Github,
    /// Nothing on stdout (with `-o` files).
    None,
}

impl Format {
    fn parse(s: &str) -> Result<Format> {
        match Format::from_str(s, true) {
            Ok(Format::None) | Err(_) => {
                Err(anyhow!("unknown format {s:?} (json, md, junit, github)"))
            }
            Ok(f) => Ok(f),
        }
    }
}

/// An error of the user's input (exit 2) rather than of the analysis (exit 3).
#[derive(Debug)]
struct Usage(String);

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Usage {}

fn usage(msg: impl Into<String>) -> anyhow::Error {
    Usage(msg.into()).into()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Interrupted (a cancelled CI job): remove the temporary store, which can hold a copy of
    // the captured traffic. Best effort; without a handler the OS would just kill us.
    let _ = ctrlc::set_handler(|| {
        if let Some(d) = DATA_DIR.get() {
            let _ = std::fs::remove_dir_all(d);
        }
        std::process::exit(EXIT_INTERRUPTED);
    });
    let r = match cli.command {
        Command::Diagnose(a) => diagnose(a),
        Command::Compare(a) => compare(a),
        Command::Sanitize(a) => sanitize(a).map(|_| true),
        Command::Mock(a) => mock(a).map(|_| true),
        Command::Http { command: HttpCommand::Run(a) } => http_run(a),
        Command::Http { command: HttpCommand::FromHar(a) } => http_from(a).map(|_| true),
        Command::Profiles { lang, plugins } => profiles(&lang, &plugins).map(|_| true),
    };
    match r {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_GATE),
        Err(e) => {
            eprintln!("quena-cli: {e:#}");
            ExitCode::from(if e.downcast_ref::<Usage>().is_some() {
                EXIT_USAGE
            } else {
                EXIT_ANALYSIS
            })
        }
    }
}

// ------------------------------------------------------------------ settings file

/// The settings file split into the gate part and the analysis part.
#[derive(Default)]
struct Settings {
    gate: GateConfig,
    profile: Option<String>,
    lang: Option<String>,
    options: Map<String, Value>,
    hosts: Vec<String>,
    processes: Vec<String>,
}

fn read_settings(path: Option<&Path>, analysis: bool) -> Result<Settings> {
    let Some(path) = path else {
        return Ok(Settings {
            gate: default_gate(),
            ..Default::default()
        });
    };
    let text =
        std::fs::read_to_string(path).map_err(|e| usage(format!("{}: {e}", path.display())))?;
    let mut v: Map<String, Value> =
        serde_json::from_str(&text).map_err(|e| usage(format!("{}: {e}", path.display())))?;
    let mut s = Settings::default();
    if !analysis {
        // `compare` runs no analysis: the same settings file as for `diagnose` works.
        for k in ["profile", "lang", "options", "hosts", "processes"] {
            v.remove(k);
        }
    } else {
        let text_of = |v: Option<Value>, k: &str| -> Result<Option<String>> {
            match v {
                None => Ok(None),
                Some(Value::String(s)) => Ok(Some(s)),
                Some(_) => Err(usage(format!("{}: {k} must be a string", path.display()))),
            }
        };
        let list_of = |v: Option<Value>, k: &str| -> Result<Vec<String>> {
            match v {
                None => Ok(vec![]),
                Some(Value::Array(a)) => a
                    .into_iter()
                    .map(|x| {
                        x.as_str().map(String::from).ok_or_else(|| {
                            usage(format!("{}: {k} must be a list of strings", path.display()))
                        })
                    })
                    .collect(),
                Some(_) => Err(usage(format!(
                    "{}: {k} must be a list of strings",
                    path.display()
                ))),
            }
        };
        s.profile = text_of(v.remove("profile"), "profile")?;
        s.lang = text_of(v.remove("lang"), "lang")?;
        s.hosts = list_of(v.remove("hosts"), "hosts")?;
        s.processes = list_of(v.remove("processes"), "processes")?;
        s.options = match v.remove("options") {
            None => Map::new(),
            Some(Value::Object(o)) => o,
            Some(_) => {
                return Err(usage(format!(
                    "{}: options must be an object",
                    path.display()
                )));
            }
        };
    }
    // Without `failOn` the file keeps the default of the command line (critical).
    let fail_on_given = v.contains_key("failOn");
    s.gate = GateConfig::from_json(&Value::Object(v).to_string())
        .map_err(|e| usage(format!("{}: {e}", path.display())))?;
    if !fail_on_given {
        s.gate.fail_on = default_gate().fail_on;
    }
    Ok(s)
}

/// The gate: the settings file, then the command line.
fn gate_config(args: &GateArgs, mut cfg: GateConfig) -> Result<GateConfig> {
    match args.fail_on {
        Some(FailOn::None) => cfg.fail_on = None,
        Some(FailOn::Critical) => cfg.fail_on = Some(Severity::Critical),
        Some(FailOn::Warning) => cfg.fail_on = Some(Severity::Warning),
        Some(FailOn::Info) => cfg.fail_on = Some(Severity::Info),
        None => {}
    }
    if args.fail_on_existing {
        cfg.fail_on_existing = true;
    } else if args.no_fail_on_existing {
        cfg.fail_on_existing = false;
    }
    for b in &args.budgets {
        cfg.budgets
            .push(gate::parse_budget(b).map_err(|e| usage(format!("--budget {b}: {e}")))?);
    }
    cfg.ignore.extend(args.ignore.iter().cloned());
    Ok(cfg)
}

/// Unless told otherwise the gate fails on critical findings.
fn default_gate() -> GateConfig {
    GateConfig {
        fail_on: Some(Severity::Critical),
        ..Default::default()
    }
}

fn read_report(path: &Path) -> Result<(Value, Report)> {
    let text =
        std::fs::read_to_string(path).map_err(|e| usage(format!("{}: {e}", path.display())))?;
    quena_report::parse(&text).map_err(|e| usage(format!("{}: {e}", path.display())))
}

fn lang_of(s: Option<&str>) -> Result<Lang> {
    match s.unwrap_or("en") {
        "en" => Ok(Lang::En),
        "de" => Ok(Lang::De),
        other => Err(usage(format!("unknown language {other:?} (en, de)"))),
    }
}

/// The frame language for a report's own `lang` (`de`, `de-DE`, …): never an error.
fn lang_of_report(s: &str) -> Lang {
    let primary = s.split(['-', '_']).next().unwrap_or("");
    if primary.eq_ignore_ascii_case("de") {
        Lang::De
    } else {
        Lang::En
    }
}

// ------------------------------------------------------------------ commands

fn diagnose(a: Diagnose) -> Result<bool> {
    // One deadline for the whole run.
    let deadline = Deadline::after(a.timeout);
    let settings = read_settings(a.gate.config.as_deref(), true)?;
    let gate_cfg = gate_config(&a.gate, settings.gate)?;
    let baseline = a.gate.baseline.as_deref().map(read_report).transpose()?;
    let outputs = outputs(&a.out)?;
    let mut seen = std::collections::HashSet::new();
    for f in &a.files {
        if !f.is_file() {
            return Err(usage(format!("{}: no such file", f.display())));
        }
        let canonical = f
            .canonicalize()
            .map_err(|e| usage(format!("{}: {e}", f.display())))?;
        if !seen.insert(canonical) {
            return Err(usage(format!("capture given twice: {}", f.display())));
        }
    }
    let lang = a
        .lang
        .clone()
        .or(settings.lang)
        .unwrap_or_else(|| "en".into());
    let frame_lang = lang_of(Some(&lang))?;
    let mut options = settings.options;
    if let Some(p) = a.profile.clone().or(settings.profile) {
        options.insert("profile".into(), Value::String(p));
    }
    options.insert("lang".into(), Value::String(lang));
    for kv in &a.set {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| usage(format!("--set {kv}: expected KEY=VALUE")))?;
        let k = k.trim();
        if k == "lang" || k == "profile" {
            return Err(usage(format!("--set {kv}: use --{k}")));
        }
        options.insert(
            k.into(),
            serde_json::from_str(v).unwrap_or_else(|_| Value::String(v.into())),
        );
    }
    let filter = DiagFilter {
        hosts: if a.hosts.is_empty() {
            settings.hosts
        } else {
            a.hosts.clone()
        },
        processes: if a.processes.is_empty() {
            settings.processes
        } else {
            a.processes.clone()
        },
    };

    let engine = Engine::start(a.plugins.plugins.as_deref())?;
    for f in &a.files {
        progress(a.out.quiet, &format!("importing {}", f.display()));
        engine.import(f, &deadline)?;
    }
    progress(a.out.quiet, "analysing");
    let text = engine.analyse(&Value::Object(options).to_string(), filter, &deadline)?;
    drop(engine);
    let (raw, report) = quena_report::parse(&text).map_err(|e| anyhow!("analyzer report: {e}"))?;
    gate::check_budgets(&report, &gate_cfg).map_err(usage)?;
    finish(
        &raw,
        &report,
        baseline.as_ref(),
        &gate_cfg,
        frame_lang,
        &outputs,
        a.out.quiet,
    )
}

/// Existing, distinct capture files (input errors otherwise).
fn check_captures(files: &[PathBuf]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for f in files {
        if !f.is_file() {
            return Err(usage(format!("{}: no such file", f.display())));
        }
        let canonical = f.canonicalize().map_err(|e| usage(format!("{}: {e}", f.display())))?;
        if !seen.insert(canonical) {
            return Err(usage(format!("capture given twice: {}", f.display())));
        }
    }
    Ok(())
}

/// Import the captures into a store of their own; all sessions in recorded order.
fn load_captures(files: &[PathBuf], quiet: bool, deadline: &Deadline) -> Result<(Engine, Vec<u64>)> {
    let engine = Engine::bare()?;
    for f in files {
        progress(quiet, &format!("importing {}", f.display()));
        engine.import(f, deadline)?;
    }
    let ids = engine.core.capture().index.find(|_| true);
    if ids.is_empty() {
        return Err(usage("the captures hold no sessions"));
    }
    Ok((engine, ids))
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| usage(format!("{}: {e}", path.display())))
}

/// Mock options from a config file, strictly: unknown keys are an error that names them.
/// `sanitize` is a preset name, null, or full sanitize options (also strict).
fn mock_options(text: &str) -> std::result::Result<quena_app_core::mockgen::MockOptions, String> {
    use quena_app_core::mockgen::MockOptions;
    use quena_app_core::sanitize::SanitizeOptions;
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(mut map) = v else {
        return Err("expected a JSON object".into());
    };
    let known: Vec<String> = match serde_json::to_value(MockOptions::default()) {
        Ok(Value::Object(d)) => d.keys().cloned().collect(),
        _ => vec![],
    };
    let mut unknown: Vec<&String> = map.keys().filter(|k| !known.contains(k)).collect();
    if !unknown.is_empty() {
        unknown.sort();
        let unknown: Vec<&str> = unknown.iter().map(|s| s.as_str()).collect();
        return Err(format!("unknown option(s): {} (known: {})", unknown.join(", "), known.join(", ")));
    }
    let sanitize = match map.remove("sanitize") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(name)) if name == "none" => Some(None),
        Some(Value::String(name)) => Some(Some(
            SanitizeOptions::preset(&name).ok_or_else(|| format!("sanitize: unknown preset {name:?} (credentials, support, gdpr or none)"))?,
        )),
        Some(o @ Value::Object(_)) => Some(Some(SanitizeOptions::from_json_strict(&o.to_string()).map_err(|e| format!("sanitize: {e}"))?)),
        Some(_) => return Err("sanitize: a preset name, null or an object".into()),
    };
    let mut opts: MockOptions = serde_json::from_value(Value::Object(map)).map_err(|e| format!("invalid options: {e}"))?;
    if let Some(s) = sanitize {
        opts.sanitize = s;
    }
    Ok(opts)
}

/// Where a path points: the canonical file, or for one that does not exist yet the
/// canonical folder plus the file name.
fn path_key(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    match (parent.canonicalize(), p.file_name()) {
        (Ok(d), Some(n)) => d.join(n),
        _ => p.to_path_buf(),
    }
}

/// No output may overwrite an input or another output; nor may a WireMock folder hold an
/// input in the parts that are replaced (`mappings`, `__files`).
fn check_outputs(inputs: &[PathBuf], outputs: &[(&str, &PathBuf)], wiremock_dir: Option<&Path>) -> Result<()> {
    let ins: Vec<(PathBuf, &PathBuf)> = inputs.iter().map(|p| (path_key(p), p)).collect();
    let mut seen: Vec<(PathBuf, &str)> = Vec::new();
    for (flag, p) in outputs {
        let k = path_key(p);
        if let Some((_, i)) = ins.iter().find(|(c, _)| *c == k) {
            return Err(usage(format!("{flag} {}: is the capture {}", p.display(), i.display())));
        }
        if let Some((_, other)) = seen.iter().find(|(c, _)| *c == k) {
            return Err(usage(format!("{flag} {}: the same file as {other}", p.display())));
        }
        seen.push((k, flag));
    }
    if let Some(dir) = wiremock_dir {
        let d = path_key(dir);
        for (c, i) in &ins {
            if c.starts_with(d.join("mappings")) || c.starts_with(d.join("__files")) {
                return Err(usage(format!("--wiremock {}: would replace the capture {}", dir.display(), i.display())));
            }
        }
        for (c, flag) in &seen {
            if *flag != "--wiremock" && (c.starts_with(d.join("mappings")) || c.starts_with(d.join("__files"))) {
                return Err(usage(format!("--wiremock {}: would replace the {flag} output", dir.display())));
            }
        }
    }
    Ok(())
}

fn sanitize(a: SanitizeArgs) -> Result<()> {
    use quena_app_core::archive::{ArchiveFormat, sanitized_export};
    use quena_app_core::sanitize::SanitizeOptions;
    let deadline = Deadline::after(a.timeout);
    let opts: SanitizeOptions = match &a.config {
        Some(p) => SanitizeOptions::from_json_strict(&read_text(p)?).map_err(|e| usage(format!("{}: {e}", p.display())))?,
        None => SanitizeOptions::preset(&a.preset).ok_or_else(|| usage(format!("--preset {}: use support, gdpr or credentials", a.preset)))?,
    };
    opts.validate().map_err(usage)?;
    let format = match a.output.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("saz") => ArchiveFormat::Saz,
        Some("har") => ArchiveFormat::Har,
        _ => return Err(usage(format!("-o {}: the output is a .saz or .har file", a.output.display()))),
    };
    check_captures(&a.files)?;
    for p in std::iter::once(&a.output).chain(a.log.as_ref()) {
        check_writable(p).map_err(usage)?;
    }
    let mut outs = vec![("-o", &a.output)];
    outs.extend(a.log.iter().map(|p| ("--log", p)));
    check_outputs(&a.files, &outs, None)?;
    let (engine, ids) = load_captures(&a.files, a.quiet, &deadline)?;
    progress(a.quiet, "sanitizing");
    let tmp = engine._data.path().join("sanitize-tmp");
    let body_cfg = engine.core.settings().bodies.to_config();
    let existed = a.output.exists();
    let r = sanitized_export(&engine.core.capture(), &ids, &a.output, format, opts, &tmp, body_cfg, &DeadlineProgress(&deadline));
    let log = match r {
        Ok(log) => log,
        Err(e) => {
            // A half-written archive is no use; one that was there before is left alone.
            if !existed {
                let _ = std::fs::remove_file(&a.output);
            }
            return Err(deadline.explain(e, "sanitizing"));
        }
    };
    if let Some(p) = &a.log {
        let text = if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("json")) { serde_json::to_string_pretty(&log)? } else { log.to_text() };
        std::fs::write(p, text).with_context(|| p.display().to_string())?;
    }
    if !a.quiet {
        eprintln!("quena-cli: {} → {}: {}", ids.len(), a.output.display(), log.summary_line());
    }
    Ok(())
}

/// Run a .http file through a headless proxy engine (no listener, the system proxy is not
/// touched). `Ok(false)`: a request failed.
fn http_run(a: HttpRunArgs) -> Result<bool> {
    if !a.file.is_file() {
        return Err(usage(format!("{}: no such file", a.file.display())));
    }
    let engine = Engine::bare()?;
    let core = engine.core.clone();
    let proxy = quena_app_core::engine::ProxyEngine::new(&core)?;
    core.set_proxy_engine(proxy);
    let results = core
        .run_http_file(
            &a.file,
            a.env.as_deref(),
            &a.names,
            Duration::from_secs(a.timeout),
            &quena_formats::http_file::Access { process_env: true, root: None },
        )
        .map_err(|e| usage(format!("{e:#}")))?;
    let mut ok = true;
    let mut out = std::io::stdout().lock();
    for r in &results {
        let name = r.name.as_deref().map(|n| format!("  ({n})")).unwrap_or_default();
        let time = r.duration_ms.map(|d| format!("{d} ms")).unwrap_or_default();
        let failed = r.error.is_some() || r.pending || r.status.is_none_or(|s| s >= 400);
        ok &= !failed;
        let status = match (r.status, r.pending) {
            (Some(s), _) => s.to_string(),
            (None, true) => "…".into(),
            (None, false) => "ERR".into(),
        };
        writeln!(out, "{status:>4} {time:>8}  {} {}{name}", r.method, r.url)?;
        if let Some(e) = &r.error {
            writeln!(out, "             {e}")?;
        } else if r.pending {
            writeln!(out, "             no response within {} s", a.timeout)?;
        }
    }
    if let Some(path) = &a.save {
        let ids: Vec<_> = results.iter().filter_map(|r| r.session).collect();
        let job = core.export_archive(ids, path.clone(), None).map_err(|e| usage(format!("{}: {e}", path.display())))?;
        match engine.wait(job, &Deadline::after(600), &path.display().to_string()) {
            Ok(()) => {}
            Err(JobError::Failed(e)) => bail!(e),
            Err(JobError::Wait(e)) => return Err(e),
        }
    }
    core.shutdown();
    Ok(ok)
}

fn http_from(a: HttpFromArgs) -> Result<()> {
    check_outputs(&a.files, &[("--output", &a.output)], None)?;
    let engine = Engine::bare()?;
    let deadline = Deadline::after(600);
    for f in &a.files {
        engine.import(f, &deadline)?;
    }
    let mut ids = engine.core.capture().index.find_all(|_| true);
    ids.sort_unstable();
    let w = engine
        .core
        .sessions_to_http(&ids, &a.output, a.overwrite, false)
        .map_err(|e| usage(format!("{e:#}")))?;
    eprintln!("{} request(s) written to {}", w.requests, w.path);
    for f in &w.env_files {
        eprintln!("environment \"captured\" in {f}");
    }
    Ok(())
}

fn mock(a: MockArgs) -> Result<()> {
    use quena_app_core::mockgen::{self, MockOptions, QueryMatch, Repeats};
    use quena_app_core::sanitize::SanitizeOptions;
    let deadline = Deadline::after(a.timeout);
    let mut opts: MockOptions = match &a.config {
        Some(p) => mock_options(&read_text(p)?).map_err(|e| usage(format!("{}: {e}", p.display())))?,
        None => MockOptions::default(),
    };
    if !a.hosts.is_empty() {
        opts.hosts = a.hosts.clone();
    }
    if a.sequence {
        opts.repeats = Repeats::Sequence;
    }
    if a.exact_query {
        opts.query = QueryMatch::Exact;
    }
    opts.include_static |= a.include_static;
    opts.latency |= a.latency;
    match a.sanitize.as_deref() {
        None => {}
        Some("none") => opts.sanitize = None,
        Some(p) => opts.sanitize = Some(SanitizeOptions::preset(p).ok_or_else(|| usage(format!("--sanitize {p}: use credentials, support, gdpr or none")))?),
    }
    check_captures(&a.files)?;
    if let Some(p) = &a.package {
        if !p.extension().is_some_and(|e| e.eq_ignore_ascii_case("quena-mocks")) {
            return Err(usage(format!("--package {}: a mock package ends in .quena-mocks", p.display())));
        }
        check_writable(p).map_err(|e| usage(format!("--package {}: {e}", p.display())))?;
    }
    let mut wiremock_dir = None;
    if let Some(p) = &a.wiremock {
        if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip")) {
            check_writable(p).map_err(|e| usage(format!("--wiremock {}: {e}", p.display())))?;
        } else {
            // A folder: it may exist already (its mappings and __files are replaced), its
            // parent must; an existing file is not a folder.
            if p.exists() && !p.is_dir() {
                return Err(usage(format!("--wiremock {}: is a file, not a folder (use a folder or a .zip)", p.display())));
            }
            let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
            if !parent.is_dir() {
                return Err(usage(format!("--wiremock {}: no such folder: {}", p.display(), parent.display())));
            }
            wiremock_dir = Some(p.as_path());
        }
    }
    let mut outs = Vec::new();
    outs.extend(a.wiremock.iter().map(|p| ("--wiremock", p)));
    outs.extend(a.package.iter().map(|p| ("--package", p)));
    check_outputs(&a.files, &outs, wiremock_dir)?;
    let (engine, ids) = load_captures(&a.files, a.quiet, &deadline)?;
    progress(a.quiet, "building mocks");
    let set = mockgen::generate(&engine.core.capture(), &ids, &opts, true, &DeadlineProgress(&deadline)).map_err(|e| deadline.explain(e, "building mocks"))?;
    if deadline.passed() {
        return Err(deadline.explain(anyhow!("cancelled"), "building mocks"));
    }
    if let Some(p) = &a.wiremock {
        mockgen::write_wiremock(&set, p)?;
    }
    if let Some(p) = &a.package {
        mockgen::write_package(&set, p, &opts)?;
    }
    if !a.quiet {
        let preview = mockgen::MockPreview::of(&set);
        eprintln!(
            "quena-cli: {} session(s) → {} mock(s), {} sequence(s), {} skipped",
            ids.len(),
            preview.mappings,
            set.sequences(),
            set.skipped.len()
        );
    }
    Ok(())
}

fn compare(a: CompareArgs) -> Result<bool> {
    let settings = read_settings(a.gate.config.as_deref(), false)?;
    let gate_cfg = gate_config(&a.gate, settings.gate)?;
    if a.gate.baseline.is_some() {
        return Err(usage(
            "compare takes the baseline as its first argument, not --baseline",
        ));
    }
    let outputs = outputs(&a.out)?;
    let before = read_report(&a.before)?;
    let (raw, after) = read_report(&a.after)?;
    let lang = match a.lang.as_deref() {
        Some(l) => lang_of(Some(l))?,
        None => lang_of_report(&after.lang),
    };
    gate::check_budgets(&after, &gate_cfg).map_err(usage)?;
    finish(
        &raw,
        &after,
        Some(&before),
        &gate_cfg,
        lang,
        &outputs,
        a.out.quiet,
    )
}

fn profiles(lang: &str, plugins: &PluginArgs) -> Result<()> {
    let engine = Engine::start(plugins.plugins.as_deref())?;
    let d: Value = serde_json::from_str(&engine.core.diag_describe(engine.analyzer, lang)?)?;
    let mut out = std::io::stdout().lock();
    for p in d["profiles"].as_array().into_iter().flatten() {
        writeln!(
            out,
            "{:<16} {}  {}",
            p["id"].as_str().unwrap_or(""),
            p["name"].as_str().unwrap_or(""),
            p["description"].as_str().unwrap_or("")
        )?;
    }
    writeln!(out, "\noptions (--set KEY=VALUE): {}", d["options"])?;
    Ok(())
}

/// Compare, apply the gate, write the outputs; `Ok(passed)`.
fn finish(
    raw: &Value,
    report: &Report,
    baseline: Option<&(Value, Report)>,
    cfg: &GateConfig,
    lang: Lang,
    outputs: &[(Format, Option<PathBuf>)],
    quiet: bool,
) -> Result<bool> {
    let cmp: Option<Comparison> = baseline.map(|(_, b)| quena_report::compare(b, report));
    let result = gate::evaluate(
        report,
        baseline.map(|(_, b)| b).zip(cmp.as_ref()),
        cfg,
        lang,
    );
    // Files first: a failing write must not leave a verdict half on stdout.
    for (format, path) in outputs {
        if let Some(p) = path {
            let text = render(*format, raw, report, cmp.as_ref(), &result, lang);
            std::fs::write(p, text).map_err(|e| usage(format!("{}: {e}", p.display())))?;
        }
    }
    for (format, path) in outputs {
        if path.is_none() {
            let text = render(*format, raw, report, cmp.as_ref(), &result, lang);
            let mut out = std::io::stdout().lock();
            out.write_all(text.as_bytes())
                .and_then(|_| out.flush())
                .context("stdout")?;
        }
    }
    if !quiet {
        eprintln!("{}", summary(report, cmp.as_ref(), &result));
    }
    Ok(result.passed)
}

fn render(
    format: Format,
    raw: &Value,
    report: &Report,
    cmp: Option<&Comparison>,
    gate: &GateResult,
    lang: Lang,
) -> String {
    match format {
        Format::Json => quena_report::to_json(raw, cmp, Some(gate)),
        Format::Md => {
            quena_report::to_markdown(report, cmp, Some(gate), lang, &MdOptions::default())
        }
        Format::Junit => quena_report::to_junit(report, gate, lang),
        Format::Github => quena_report::to_github(report, gate),
        Format::None => String::new(),
    }
}

/// One line for the CI log: counts, what is new, and the verdict.
fn summary(r: &Report, cmp: Option<&Comparison>, g: &GateResult) -> String {
    let mut s = format!(
        "quena-cli: {} critical, {} warning, {} info",
        r.summary.critical, r.summary.warning, r.summary.info
    );
    if let Some(c) = cmp {
        s.push_str(&format!(
            " · vs. baseline: {} new, {} resolved, {} changed",
            c.added.len(),
            c.resolved.len(),
            c.changed.len()
        ));
    }
    s.push_str(if g.passed {
        " → gate passed"
    } else {
        " → gate FAILED"
    });
    for reason in &g.reasons {
        s.push_str("\n  - ");
        s.push_str(reason);
    }
    // The findings that break the gate, most severe first (the report's order).
    const SHOWN: usize = 10;
    let failing: Vec<&quena_report::Finding> = r
        .findings
        .iter()
        .enumerate()
        .filter(|(i, _)| g.is_failing_at(*i))
        .map(|(_, f)| f)
        .collect();
    for f in failing.iter().take(SHOWN) {
        s.push_str(&format!(
            "\n  ✖ [{}] {} ({})",
            f.severity.as_str(),
            f.title,
            f.id
        ));
    }
    if failing.len() > SHOWN {
        s.push_str(&format!("\n  … {} more", failing.len() - SHOWN));
    }
    s
}

/// `--format` goes to stdout (md unless `none`), each `-o FORMAT=PATH` to its file.
fn outputs(o: &OutArgs) -> Result<Vec<(Format, Option<PathBuf>)>> {
    let mut v = vec![];
    for spec in &o.outputs {
        let (f, p) = spec
            .split_once('=')
            .ok_or_else(|| usage(format!("-o {spec}: expected FORMAT=PATH")))?;
        let format = Format::parse(f).map_err(|e| usage(e.to_string()))?;
        let path = PathBuf::from(p);
        check_writable(&path).map_err(|e| usage(format!("-o {spec}: {e}")))?;
        v.push((format, Some(path)));
    }
    match o.format.unwrap_or(Format::Md) {
        Format::None => {}
        f => v.insert(0, (f, None)),
    }
    Ok(v)
}

/// Fail before the (long) analysis rather than after it: the folder must exist and take a
/// new file, an existing file must be writable.
fn check_writable(path: &Path) -> std::result::Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("the path is empty".into());
    }
    if path.is_dir() {
        return Err("is a folder".into());
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if !dir.is_dir() {
        return Err(format!("no such folder: {}", dir.display()));
    }
    if path.exists() {
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
    } else {
        tempfile::NamedTempFile::new_in(dir)
            .map_err(|e| format!("cannot write to {}: {e}", dir.display()))?;
    }
    Ok(())
}

fn progress(quiet: bool, msg: &str) {
    if !quiet {
        eprintln!("quena-cli: {msg}");
    }
}

// ------------------------------------------------------------------ the engine

/// The end of the run (`--timeout`); `None` when too far in the future to represent.
struct Deadline {
    at: Option<Instant>,
    secs: u64,
}

impl Deadline {
    fn after(secs: u64) -> Deadline {
        Deadline {
            at: Instant::now().checked_add(Duration::from_secs(secs)),
            secs,
        }
    }

    fn passed(&self) -> bool {
        self.at.is_some_and(|at| Instant::now() >= at)
    }

    /// An error of work that was cancelled by the deadline: the timeout (exit 3).
    fn explain(&self, e: anyhow::Error, what: &str) -> anyhow::Error {
        if self.passed() {
            anyhow!("{what}: no result within --timeout {} s", self.secs)
        } else {
            e
        }
    }

    /// Time left (`Duration::MAX`: no deadline).
    fn remaining(&self) -> Duration {
        self.at.map_or(Duration::MAX, |at| {
            at.saturating_duration_since(Instant::now())
        })
    }
}

/// Progress of work done in this process (sanitizing, building mocks): cancelled when the
/// deadline has passed.
struct DeadlineProgress<'a>(&'a Deadline);

impl quena_formats::Progress for DeadlineProgress<'_> {
    fn cancelled(&self) -> bool {
        self.0.passed()
    }
}

/// Why a job did not finish as wanted.
enum JobError {
    /// The job ended with an error (its text).
    Failed(String),
    /// No result in time, or the job vanished.
    Wait(anyhow::Error),
}

/// Quena's core on a throw-away data directory: no proxy, no ticker, no instance lock.
struct Engine {
    core: Arc<AppCore>,
    analyzer: u16,
    _data: tempfile::TempDir,
}

impl Engine {
    /// The core without plugins (sanitizing and mocks need none).
    fn bare() -> Result<Engine> {
        let data = tempfile::Builder::new()
            .prefix("quena-cli-")
            .tempdir()
            .context("temporary directory")?;
        let _ = DATA_DIR.set(data.path().to_path_buf());
        std::fs::write(
            data.path().join("settings.json"),
            r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#,
        )?;
        let mut paths = Paths::at(data.path().to_path_buf());
        if let Some(cache) = cache_dir() {
            paths.plugin_cache = cache;
        }
        let core = AppCore::new(paths, quena_app_core::logbuf::LogBuffer::new(100))?;
        Ok(Engine {
            core,
            analyzer: 0,
            _data: data,
        })
    }

    /// The core with the plugins and the diagnostics analyzer.
    fn start(plugins: Option<&Path>) -> Result<Engine> {
        let mut engine = Engine::bare()?;
        let core = engine.core.clone();
        let data = engine._data.path().to_path_buf();
        match plugins {
            // An explicit folder is the only one searched (not even QUENA_PLUGIN_DIR).
            Some(d) if d.is_dir() => core.init_plugins_from(vec![d.to_path_buf()])?,
            Some(d) => return Err(usage(format!("--plugins {}: no such folder", d.display()))),
            None => {
                let found = plugin_dir();
                if found.is_none() && std::env::var_os("QUENA_PLUGIN_DIR").is_none() {
                    return Err(usage(format!(
                        "no plugins folder found (looked in {}); use --plugins or QUENA_PLUGIN_DIR",
                        join_paths(&plugin_candidates())
                    )));
                }
                core.init_plugins(found)?;
            }
        }
        // The searched folders, without the throw-away user plugin folder.
        let searched: Vec<PathBuf> = core
            .plugin_search_dirs()
            .into_iter()
            .filter(|d| !d.starts_with(&data))
            .collect();
        let info = core
            .plugins()
            .into_iter()
            .find(|p| p.id == ANALYZER)
            .ok_or_else(|| {
                usage(format!(
                    "the diagnostics plugin ({ANALYZER}) is missing in {}",
                    join_paths(&searched)
                ))
            })?;
        if let Some(e) = &info.error {
            bail!(
                "the diagnostics plugin ({ANALYZER}) in {} failed to load: {e}",
                info.path
            );
        }
        let analyzer = core
            .diag_analyzers()
            .into_iter()
            .find(|a| a.id == ANALYZER)
            .ok_or_else(|| anyhow!("the diagnostics plugin ({ANALYZER}) is not available"))?
            .index;
        engine.analyzer = analyzer;
        Ok(engine)
    }

    fn wait(&self, job: u64, deadline: &Deadline, what: &str) -> Result<(), JobError> {
        let info = self
            .core
            .jobs
            .wait(job, deadline.remaining())
            .map_err(|e| {
                JobError::Wait(match e {
                    WaitError::Timeout => {
                        anyhow!("{what}: no result within --timeout {} s", deadline.secs)
                    }
                    WaitError::UnknownJob => anyhow!("{what}: the job disappeared"),
                })
            })?;
        match info.status {
            quena_app_core::JobStatus::Done => Ok(()),
            status => Err(JobError::Failed(format!(
                "{what}: {}",
                info.error.unwrap_or_else(|| format!("{status:?}"))
            ))),
        }
    }

    /// Unknown, unreadable or broken captures are input errors (2), a timeout is not (3).
    fn import(&self, file: &Path, deadline: &Deadline) -> Result<()> {
        let job = self
            .core
            .import_archive(file.to_path_buf())
            .map_err(|e| usage(format!("{}: {e}", file.display())))?;
        match self.wait(job, deadline, &file.display().to_string()) {
            Ok(()) => {}
            Err(JobError::Failed(e)) => return Err(usage(e)),
            Err(JobError::Wait(e)) => return Err(e),
        }
        self.core.capture().index.tick();
        Ok(())
    }

    /// An empty scope is an input error (2); anything else going wrong is an analysis error (3).
    fn analyse(&self, options: &str, filter: DiagFilter, deadline: &Deadline) -> Result<String> {
        let job = self
            .core
            .diag_run(self.analyzer, options.to_string(), None, filter)
            .map_err(|e| {
                let text = format!("{e:#}");
                if text.contains("no sessions in the chosen scope") {
                    usage(format!(
                        "{text} (check the captures and --host / --process)"
                    ))
                } else {
                    anyhow!("analysis: {text}")
                }
            })?;
        match self.wait(job, deadline, "analysis") {
            Ok(()) => {}
            Err(JobError::Failed(e)) => bail!(e),
            Err(JobError::Wait(e)) => return Err(e),
        }
        Ok(self
            .core
            .diag_report()
            .ok_or_else(|| anyhow!("the analyzer returned no report"))?
            .to_string())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.core.shutdown();
    }
}

fn join_paths(dirs: &[PathBuf]) -> String {
    if dirs.is_empty() {
        return "(no folder)".into();
    }
    dirs.iter()
        .map(|d| d.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Compiled plugins survive between runs (compiling the analyzer takes seconds). The cache
/// holds machine code that is loaded as is: it must only be writable by trusted users, so
/// its folders get the usual permissions (no world-writable shared cache).
fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("QUENA_CACHE_DIR")
        .map(|d| PathBuf::from(d).join("plugin-cache"))
        .or_else(|| dirs::cache_dir().map(|d| d.join("quena").join("plugin-cache")))
}

/// Where the plugins may be: `plugins/` next to the program, in a macOS bundle's resources,
/// in an FHS layout; debug builds first try the build output of the checkout (release builds
/// never do, so a packaged archive must be self-contained).
fn plugin_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![];
    if cfg!(debug_assertions) {
        // Development builds: the freshly built plugins, not a copy the app's dev build left
        // in target/debug/plugins.
        candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist"));
    }
    if let Some(exe) = std::env::current_exe()
        .ok()
        .and_then(|e| e.canonicalize().ok())
        && let Some(dir) = exe.parent()
    {
        candidates.extend([
            dir.join("plugins"),
            dir.join("../Resources/plugins"),
            dir.join("../lib/quena/plugins"),
        ]);
    }
    candidates
}

/// The first candidate with the diagnostics plugin (`QUENA_PLUGIN_DIR` is searched before it
/// by the core in any case).
fn plugin_dir() -> Option<PathBuf> {
    plugin_candidates()
        .into_iter()
        .find(|d| d.join("webdiag").is_dir())
}
