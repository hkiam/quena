//! `quena-cli`: Quena's diagnostics without a window, for CI pipelines.
//!
//! `quena-cli diagnose capture.har --baseline main.json --fail-on critical` imports the
//! captures into a temporary store, runs the diagnostics analyzer (the same plugin and the same
//! redaction as the app), compares the report with a baseline and exits with 1 when the
//! quality gate fails. Nothing touches the system proxy, the keychain or the app's data.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use quena_app_core::diagnostics::DiagFilter;
use quena_app_core::{AppCore, Paths};
use quena_report::gate::{self, GateConfig, GateResult};
use quena_report::{Comparison, Lang, MdOptions, Report, Severity};
use serde_json::{Map, Value};

const ANALYZER: &str = "io.github.hkiam.webdiag";

/// Exit codes (documented in `--help` and the manual).
const EXIT_GATE: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_ANALYSIS: u8 = 3;

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
    /// Analyzer option, e.g. `--set slowMs=1500` (repeatable; values are JSON or text).
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
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 600)]
    timeout: u64,
}

#[derive(Args)]
struct CompareArgs {
    /// The baseline report (JSON).
    before: PathBuf,
    /// The new report (JSON).
    after: PathBuf,
    /// Language of the frame texts (en, de); defaults to the report's language.
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
    #[arg(long)]
    fail_on_existing: bool,
    /// Metric budget, e.g. `requests=+10%` (against the baseline) or `errors=0` (repeatable).
    #[arg(long = "budget", value_name = "METRIC=LIMIT")]
    budgets: Vec<String>,
    /// Never fail on a rule (`OAUTH-FLOW`) or a finding key (repeatable).
    #[arg(long = "ignore", value_name = "RULE|KEY")]
    ignore: Vec<String>,
    /// Settings file (JSON): failOn, failOnExisting, budgets, ignore, and for `diagnose`
    /// profile, lang, options, hosts, processes. Command line arguments win.
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
    /// Folder with the plugins (default: next to the program).
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
    let r = match cli.command {
        Command::Diagnose(a) => diagnose(a),
        Command::Compare(a) => compare(a),
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
    if analysis {
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
    cfg.fail_on_existing |= args.fail_on_existing;
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

// ------------------------------------------------------------------ commands

fn diagnose(a: Diagnose) -> Result<bool> {
    let settings = read_settings(a.gate.config.as_deref(), true)?;
    let gate_cfg = gate_config(&a.gate, settings.gate)?;
    let baseline = a.gate.baseline.as_deref().map(read_report).transpose()?;
    let outputs = outputs(&a.out)?;
    for f in &a.files {
        if !f.is_file() {
            return Err(usage(format!("{}: no such file", f.display())));
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
        options.insert(
            k.trim().into(),
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
    let timeout = Duration::from_secs(a.timeout);
    for f in &a.files {
        progress(a.out.quiet, &format!("importing {}", f.display()));
        engine.import(f, timeout)?;
    }
    progress(a.out.quiet, "analysing");
    let text = engine.analyse(&Value::Object(options).to_string(), filter, timeout)?;
    drop(engine);
    let (raw, report) = quena_report::parse(&text).map_err(|e| anyhow!("analyzer report: {e}"))?;
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

fn compare(a: CompareArgs) -> Result<bool> {
    let settings = read_settings(a.gate.config.as_deref(), false)?;
    let gate_cfg = gate_config(&a.gate, settings.gate)?;
    if a.gate.baseline.is_some() {
        return Err(usage(
            "compare takes the baseline as its first argument, not --baseline",
        ));
    }
    let before = read_report(&a.before)?;
    let (raw, after) = read_report(&a.after)?;
    let lang = lang_of(
        a.lang
            .as_deref()
            .or(Some(after.lang.as_str()).filter(|l| !l.is_empty())),
    )?;
    let outputs = outputs(&a.out)?;
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
    for (format, path) in outputs {
        let text = render(*format, raw, report, cmp.as_ref(), &result, lang);
        match path {
            Some(p) => std::fs::write(p, text).with_context(|| format!("{}", p.display()))?,
            None => std::io::stdout().lock().write_all(text.as_bytes())?,
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
    let failing: Vec<&quena_report::Finding> =
        r.findings.iter().filter(|f| g.is_failing(f)).collect();
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
        v.push((
            Format::parse(f).map_err(|e| usage(e.to_string()))?,
            Some(PathBuf::from(p)),
        ));
    }
    match o.format.unwrap_or(Format::Md) {
        Format::None => {}
        f => v.insert(0, (f, None)),
    }
    Ok(v)
}

fn progress(quiet: bool, msg: &str) {
    if !quiet {
        eprintln!("quena-cli: {msg}");
    }
}

// ------------------------------------------------------------------ the engine

/// Quena's core on a throw-away data directory: no proxy, no ticker, no instance lock.
struct Engine {
    core: Arc<AppCore>,
    analyzer: u16,
    _data: tempfile::TempDir,
}

impl Engine {
    fn start(plugins: Option<&Path>) -> Result<Engine> {
        let data = tempfile::Builder::new()
            .prefix("quena-cli-")
            .tempdir()
            .context("temporary directory")?;
        std::fs::write(
            data.path().join("settings.json"),
            r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#,
        )?;
        let mut paths = Paths::at(data.path().to_path_buf());
        if let Some(cache) = cache_dir() {
            paths.plugin_cache = cache;
        }
        let core = AppCore::new(paths, quena_app_core::logbuf::LogBuffer::new(100))?;
        let dir = match plugins {
            Some(d) if d.is_dir() => d.to_path_buf(),
            Some(d) => return Err(usage(format!("--plugins {}: no such folder", d.display()))),
            None => plugin_dir().ok_or_else(|| usage("no plugins folder found next to the program (use --plugins or QUENA_PLUGIN_DIR)"))?,
        };
        core.init_plugins(Some(dir.clone()))?;
        let analyzer = core
            .diag_analyzers()
            .into_iter()
            .find(|a| a.id == ANALYZER)
            .ok_or_else(|| {
                usage(format!(
                    "the diagnostics plugin ({ANALYZER}) is missing in {}",
                    dir.display()
                ))
            })?
            .index;
        Ok(Engine {
            core,
            analyzer,
            _data: data,
        })
    }

    fn wait(&self, job: u64, timeout: Duration, what: &str) -> Result<()> {
        let info = self
            .core
            .jobs
            .wait(job, timeout)
            .ok_or_else(|| anyhow!("{what}: no result within {} s", timeout.as_secs()))?;
        match info.status {
            quena_app_core::JobStatus::Done => Ok(()),
            _ => bail!(
                "{what}: {}",
                info.error.unwrap_or_else(|| format!("{:?}", info.status))
            ),
        }
    }

    fn import(&self, file: &Path, timeout: Duration) -> Result<()> {
        let job = self
            .core
            .import_archive(file.to_path_buf())
            .map_err(|e| usage(format!("{}: {e}", file.display())))?;
        self.wait(job, timeout, &file.display().to_string())
            .map_err(|e| usage(e.to_string()))?;
        self.core.capture().index.tick();
        Ok(())
    }

    fn analyse(&self, options: &str, filter: DiagFilter, timeout: Duration) -> Result<String> {
        let job = self
            .core
            .diag_run(self.analyzer, options.to_string(), None, filter)
            .map_err(|e| usage(e.to_string()))?;
        self.wait(job, timeout, "analysis")?;
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

/// Compiled plugins survive between runs (compiling the analyzer takes seconds).
fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("QUENA_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::cache_dir().map(|d| d.join("quena")))
        .map(|d| d.join("plugin-cache"))
}

/// `plugins/` next to the program, in a macOS bundle's resources, or the build output of a
/// checkout (`QUENA_PLUGIN_DIR` is added by the core in any case).
fn plugin_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let dir = exe.parent()?;
    let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    let mut candidates = vec![
        dir.join("plugins"),
        dir.join("../Resources/plugins"),
        dir.join("../lib/quena/plugins"),
    ];
    // Development builds: the freshly built plugins, not a copy the app's dev build left in
    // target/debug/plugins.
    if cfg!(debug_assertions) {
        candidates.insert(0, checkout);
    } else {
        candidates.push(checkout);
    }
    candidates
        .into_iter()
        .find(|d| d.join("webdiag").is_dir())
        .or_else(|| std::env::var_os("QUENA_PLUGIN_DIR").map(PathBuf::from))
}
