//! IPC commands. All commands are `async` so they never run on the main
//! (UI) thread; blocking work is moved to the blocking pool (R2/R7).

use crate::Core;
use quena_app_core::dto::*;
use quena_app_core::settings::Settings;
use quena_app_core::stats::Statistics;
use quena_app_core::{JobInfo, logbuf::LogEntry, mock};
use quena_body::Variant;
use quena_index::{RowWindow, Sort};
use quena_model::{MarkColor, SessionId};
use quena_query::FilterSettings;
use serde::Serialize;
use tauri::State;

type R<T> = Result<T, String>;

fn e<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
    tokio::task::spawn_blocking(f).await.map_err(e)?
}

#[tauri::command]
async fn status(core: State<'_, Core>) -> R<StatusDto> {
    Ok(core.status())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    data_dir: String,
    capture_dir: String,
    platform: &'static str,
}

#[tauri::command]
async fn app_info(core: State<'_, Core>) -> R<AppInfo> {
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        data_dir: core.paths.data.display().to_string(),
        capture_dir: core.capture().dir.display().to_string(),
        platform: std::env::consts::OS,
    })
}

#[tauri::command]
async fn rows(core: State<'_, Core>, start: usize, count: usize) -> R<RowWindow> {
    Ok(core.rows(start, count))
}

#[tauri::command]
async fn view_ids(core: State<'_, Core>, start: usize, count: usize) -> R<Vec<SessionId>> {
    Ok(core.view_ids(start, count))
}

#[tauri::command]
async fn position_of(core: State<'_, Core>, id: SessionId) -> R<Option<usize>> {
    Ok(core.position_of(id))
}

#[tauri::command]
async fn set_sort(core: State<'_, Core>, sort: Sort) -> R<()> {
    core.set_sort(sort);
    Ok(())
}

#[tauri::command]
async fn set_group(core: State<'_, Core>, group: quena_index::GroupBy) -> R<()> {
    core.set_group(group);
    Ok(())
}

#[tauri::command]
async fn toggle_group(core: State<'_, Core>, id: SessionId) -> R<Option<bool>> {
    Ok(core.toggle_group(id))
}

#[tauri::command]
async fn collapse_groups(core: State<'_, Core>, collapse: bool) -> R<()> {
    core.collapse_groups(collapse);
    Ok(())
}

#[tauri::command]
async fn group_ids(core: State<'_, Core>, id: SessionId) -> R<Vec<SessionId>> {
    Ok(core.group_ids(id))
}

#[tauri::command]
async fn get_filters(core: State<'_, Core>) -> R<FilterSettings> {
    Ok(core.filters())
}

#[tauri::command]
async fn set_filters(core: State<'_, Core>, filters: FilterSettings) -> R<()> {
    core.set_filters(filters).map_err(e)
}

#[tauri::command]
async fn quickexec(core: State<'_, Core>, input: String) -> R<QuickExecResult> {
    let core = core.inner().clone();
    blocking(move || Ok(core.quickexec(&input))).await
}

#[tauri::command]
async fn remove(core: State<'_, Core>, ids: Vec<SessionId>) -> R<()> {
    let core = core.inner().clone();
    blocking(move || {
        core.remove(ids);
        Ok(())
    })
    .await
}

#[tauri::command]
async fn remove_all(core: State<'_, Core>) -> R<()> {
    let core = core.inner().clone();
    blocking(move || {
        core.remove_all();
        Ok(())
    })
    .await
}

#[tauri::command]
async fn remove_except(core: State<'_, Core>, ids: Vec<SessionId>) -> R<()> {
    let core = core.inner().clone();
    blocking(move || {
        core.remove_except(ids);
        Ok(())
    })
    .await
}

#[tauri::command]
async fn remove_where(core: State<'_, Core>, expr: String) -> R<usize> {
    let core = core.inner().clone();
    blocking(move || core.remove_where(&expr).map_err(e)).await
}

#[tauri::command]
async fn summaries(core: State<'_, Core>, ids: Vec<SessionId>) -> R<Vec<quena_model::SessionSummary>> {
    Ok(core.summaries(&ids))
}

#[tauri::command]
async fn timers(core: State<'_, Core>, ids: Vec<SessionId>) -> R<Vec<quena_app_core::SessionTimers>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.timers(&ids))).await
}

/// Several tree levels (hosts and every open node) in one pass over the view.
#[tauri::command]
async fn structure(core: State<'_, Core>, levels: Vec<quena_app_core::structure::LevelQuery>) -> R<Vec<quena_app_core::structure::TreeLevel>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.structure_levels(&levels))).await
}

/// Sessions of a node; `exact` for the "(this path)" node (that path only, nothing below).
#[tauri::command]
async fn structure_ids(core: State<'_, Core>, host: String, path: String, exact: Option<bool>) -> R<Vec<SessionId>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.structure_ids(&host, &path, exact.unwrap_or(false)))).await
}

/// The navigator's groups of the sessions the filters let through.
#[tauri::command]
async fn nav_groups(core: State<'_, Core>, by: quena_index::GroupBy) -> R<quena_app_core::navigator::NavGroups> {
    let core = core.inner().clone();
    blocking(move || Ok(core.nav_groups(by))).await
}

/// The sessions of a group or structure node (the filters applied).
#[tauri::command]
async fn nav_ids(core: State<'_, Core>, scope: quena_app_core::navigator::NavScope) -> R<Vec<SessionId>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.nav_ids(&scope))).await
}

/// Narrow the list to a group or structure node (`null`: no narrowing).
#[tauri::command]
async fn set_scope(core: State<'_, Core>, scope: Option<quena_app_core::navigator::NavScope>) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.set_scope(scope).map_err(e)).await
}

/// Language of the UI: the saved preference resolved to "en" or "de".
#[tauri::command]
async fn ui_language(core: State<'_, Core>) -> R<String> {
    Ok(crate::i18n::resolve(&crate::i18n::saved_pref(&core.settings().ui)).to_string())
}

/// Switch the native menu to the language of a preference ("system", "en", "de").
#[tauri::command]
async fn set_language(app: tauri::AppHandle, pref: String) -> R<String> {
    let lang = crate::i18n::resolve(&pref);
    crate::i18n::set(lang);
    let m = crate::menu::build(&app).map_err(e)?;
    app.set_menu(m).map_err(e)?;
    Ok(lang.to_string())
}

#[tauri::command]
async fn mark(core: State<'_, Core>, ids: Vec<SessionId>, color: Option<MarkColor>) -> R<()> {
    let core = core.inner().clone();
    blocking(move || {
        core.mark(ids, color);
        Ok(())
    })
    .await
}

#[tauri::command]
async fn comment(core: State<'_, Core>, ids: Vec<SessionId>, text: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || {
        core.comment(ids, text);
        Ok(())
    })
    .await
}

#[tauri::command]
async fn detail(core: State<'_, Core>, id: SessionId) -> R<Option<DetailDto>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.detail(id))).await
}

#[tauri::command]
async fn body_open(core: State<'_, Core>, id: SessionId, part: Part, variant: Variant) -> R<BodyView> {
    let core = core.inner().clone();
    blocking(move || core.body_open(id, part, variant).map_err(e)).await
}

#[tauri::command]
async fn body_lines(core: State<'_, Core>, id: SessionId, part: Part, variant: Variant, start: u64, count: usize, charset: Option<String>) -> R<LinesDto> {
    let core = core.inner().clone();
    blocking(move || core.body_lines(id, part, variant, start, count, charset.as_deref()).map_err(e)).await
}

#[tauri::command]
async fn body_search(core: State<'_, Core>, id: SessionId, part: Part, variant: Variant, needle: String, ignore_case: bool, charset: Option<String>) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.body_search(id, part, variant, needle, ignore_case, charset.as_deref()).map_err(e)).await
}

#[tauri::command]
async fn search_result(core: State<'_, Core>, job: u64) -> R<Option<SearchResult>> {
    Ok(core.search_result(job))
}

#[tauri::command]
async fn save_body(core: State<'_, Core>, id: SessionId, part: Part, variant: Variant, path: String) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.save_body(id, part, variant, path.into()).map_err(e)).await
}

#[tauri::command]
async fn find_sessions(core: State<'_, Core>, options: quena_app_core::find::FindOptions) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.find_sessions(options).map_err(e)).await
}

#[tauri::command]
async fn find_result(core: State<'_, Core>, job: u64) -> R<Option<quena_app_core::find::FindResult>> {
    Ok(core.find_result(job))
}

#[tauri::command]
async fn statistics(core: State<'_, Core>, ids: Vec<SessionId>) -> R<Statistics> {
    let core = core.inner().clone();
    blocking(move || Ok(core.statistics(ids))).await
}

#[tauri::command]
async fn jobs(core: State<'_, Core>) -> R<Vec<JobInfo>> {
    Ok(core.jobs.list())
}

#[tauri::command]
async fn cancel_job(core: State<'_, Core>, id: u64) -> R<bool> {
    Ok(core.cancel_job(id))
}

#[tauri::command]
async fn settings_get(core: State<'_, Core>) -> R<Settings> {
    Ok(core.settings())
}

#[tauri::command]
async fn settings_set(core: State<'_, Core>, mcp: State<'_, Mcp>, settings: Settings) -> R<()> {
    let core = core.inner().clone();
    let mcp = mcp.inner().clone();
    let old_scripting = core.settings().scripting_enabled;
    let new_scripting = settings.scripting_enabled;
    let cc = core.clone();
    blocking(move || cc.update_settings(settings).map_err(e)).await?;
    if new_scripting != old_scripting {
        if let Some(r) = core.rules.clone() {
            let _ = r.set_script_enabled(new_scripting).await;
        }
    }
    blocking(move || {
        mcp.apply(&core);
        Ok(())
    })
    .await
}

type Mcp = std::sync::Arc<quena_mcp::McpService>;

#[tauri::command]
async fn mcp_status(mcp: State<'_, Mcp>) -> R<quena_mcp::McpStatus> {
    Ok(mcp.status())
}

/// A new token for the settings dialog (saved with the settings).
#[tauri::command]
async fn mcp_new_token() -> R<String> {
    Ok(quena_mcp::generate_token())
}

#[tauri::command]
async fn save_ui_prefs(core: State<'_, Core>, prefs: serde_json::Value) -> R<()> {
    core.save_ui_prefs(prefs).map_err(e)
}

#[tauri::command]
async fn log_since(core: State<'_, Core>, seq: u64) -> R<Vec<LogEntry>> {
    Ok(core.log.since(seq))
}

#[tauri::command]
async fn log_clear(core: State<'_, Core>) -> R<()> {
    core.log.clear();
    Ok(())
}

#[tauri::command]
async fn mock_start(core: State<'_, Core>, rate: u32, total: u64) -> R<()> {
    mock::start(core.inner(), rate, total);
    Ok(())
}

#[tauri::command]
async fn mock_stop(core: State<'_, Core>) -> R<()> {
    mock::stop(core.inner());
    Ok(())
}

#[tauri::command]
async fn mock_big(core: State<'_, Core>, scale: u64) -> R<()> {
    mock::big_bodies(core.inner(), scale);
    Ok(())
}

#[tauri::command]
async fn toggle_capture(core: State<'_, Core>) -> R<bool> {
    let core = core.inner().clone();
    blocking(move || core.toggle_capture().map_err(e)).await
}

#[tauri::command]
async fn recoverable(core: State<'_, Core>) -> R<Vec<quena_store_dto::Recoverable>> {
    Ok(core
        .recoverable_captures()
        .into_iter()
        .map(|c| quena_store_dto::Recoverable { dir: c.dir.display().to_string(), sessions: c.sessions, modified: c.modified })
        .collect())
}

#[tauri::command]
async fn recover(core: State<'_, Core>, dir: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.recover_capture(dir.into()).map_err(e)).await
}

#[tauri::command]
async fn discard_all(core: State<'_, Core>) -> R<usize> {
    let core = core.inner().clone();
    blocking(move || Ok(core.discard_all_captures())).await
}

#[tauri::command]
async fn discard(core: State<'_, Core>, dir: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.discard_capture(dir.into()).map_err(e)).await
}

type Engine = std::sync::Arc<quena_app_core::engine::ProxyEngine>;
use quena_app_core::engine::{CaInfo, DeviceInfo};

#[tauri::command]
async fn ca_info(engine: State<'_, Engine>) -> R<CaInfo> {
    let e = engine.inner().clone();
    blocking(move || Ok(e.ca_info())).await
}

/// Windows: trust the root certificate for all users (or remove it from there).
#[tauri::command]
async fn ca_machine(engine: State<'_, Engine>, trust: bool) -> R<CaInfo> {
    let e = engine.inner().clone();
    blocking(move || e.ca_machine(trust).map_err(|x| x.to_string())).await
}

#[tauri::command]
async fn ca_trust(engine: State<'_, Engine>) -> R<CaInfo> {
    let e = engine.inner().clone();
    blocking(move || e.ca_trust().map_err(|x| x.to_string())).await
}

#[tauri::command]
async fn ca_remove(engine: State<'_, Engine>) -> R<CaInfo> {
    let e = engine.inner().clone();
    blocking(move || e.ca_remove().map_err(|x| x.to_string())).await
}

#[tauri::command]
async fn ca_regenerate(engine: State<'_, Engine>) -> R<CaInfo> {
    let e = engine.inner().clone();
    blocking(move || e.ca_regenerate().map_err(|x| x.to_string())).await
}

#[tauri::command]
async fn ca_export(engine: State<'_, Engine>, path: String, format: quena_app_core::engine::CaExportFormat, password: Option<String>) -> R<()> {
    let e = engine.inner().clone();
    blocking(move || e.ca_export(path.into(), format, password.as_deref().unwrap_or("")).map_err(|x| x.to_string())).await
}

/// Replace the root CA by an existing one (PEM pair or .p12).
#[tauri::command]
async fn ca_import(engine: State<'_, Engine>, source: quena_app_core::engine::CaImport) -> R<CaInfo> {
    let e = engine.inner().clone();
    blocking(move || e.ca_import(&source).map_err(|x| x.to_string())).await
}

#[tauri::command]
async fn device_info(core: State<'_, Core>, engine: State<'_, Engine>) -> R<DeviceInfo> {
    Ok(engine.device_info(core.inner()))
}

/// Stop the running replays (requests in flight finish).
#[tauri::command]
fn replay_stop(core: State<'_, Core>) {
    core.replay_stop();
}

#[tauri::command]
async fn replay(core: State<'_, Core>, ids: Vec<SessionId>, options: quena_app_core::compose::ReplayOptions) -> R<usize> {
    let core = core.inner().clone();
    blocking(move || core.replay(ids, options).map_err(e)).await
}

#[tauri::command]
async fn compose(core: State<'_, Core>, request: quena_app_core::compose::ComposeRequest) -> R<SessionId> {
    let core = core.inner().clone();
    blocking(move || core.compose(request).map_err(e)).await
}

#[tauri::command]
async fn parse_raw_request(raw: String) -> R<quena_app_core::compose::ParsedRequest> {
    quena_app_core::compose::parse_raw_request(&raw).map_err(e)
}

#[tauri::command]
async fn parse_curl(cmd: String) -> R<quena_app_core::compose::ParsedRequest> {
    quena_app_core::compose::parse_curl(&cmd).map_err(e)
}

#[tauri::command]
async fn export_archive(core: State<'_, Core>, ids: Vec<SessionId>, path: String, password: Option<String>) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.export_archive_protected(ids, path.into(), None, password).map_err(e)).await
}

#[tauri::command]
async fn import_archive(core: State<'_, Core>, path: String, password: Option<String>) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.import_archive_protected(path.into(), password).map_err(e)).await
}

/// A dropped archive that waited for its password.
#[tauri::command]
async fn import_dropped(core: State<'_, Core>, id: String, name: String, password: String) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.import_dropped(&id, &name, &password).map_err(e)).await
}

/// AutoSave now (also when nothing changed); the archive's path.
#[tauri::command]
async fn autosave_now(core: State<'_, Core>) -> R<Option<String>> {
    let core = core.inner().clone();
    blocking(move || core.autosave_now(true).map(|p| p.map(|p| p.display().to_string())).map_err(e)).await
}

#[tauri::command]
async fn autosave_reveal(core: State<'_, Core>) -> R<()> {
    let dir = core.autosave_dir();
    std::fs::create_dir_all(&dir).map_err(|x| x.to_string())?;
    quena_platform::open(&dir.display().to_string()).map_err(e)
}

#[tauri::command]
async fn llm_cache_status(core: State<'_, Core>) -> R<quena_app_core::llm_cache::CacheStatus> {
    let core = core.inner().clone();
    blocking(move || core.llm_cache_status().map_err(e)).await
}

#[tauri::command]
async fn llm_cache_advice(core: State<'_, Core>) -> R<Vec<quena_app_core::llm_cache::CacheAdvice>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm_cache_advice())).await
}

/// Whether session `id` is cached; with `on`, cache or forget it first.
#[tauri::command]
async fn llm_cache_set(core: State<'_, Core>, id: u64, on: Option<bool>) -> R<bool> {
    let core = core.inner().clone();
    blocking(move || {
        if let Some(on) = on {
            core.llm_cache_set(id, on).map_err(e)?;
        }
        Ok(core.llm_cached(id))
    })
    .await
}

#[tauri::command]
async fn llm_cache_auto(core: State<'_, Core>, on: bool) -> R<quena_app_core::llm_cache::CacheStatus> {
    let core = core.inner().clone();
    blocking(move || core.llm_cache_set_auto(on).map_err(e)).await
}

#[tauri::command]
async fn llm_cache_remove(core: State<'_, Core>, key: Option<String>) -> R<quena_app_core::llm_cache::CacheStatus> {
    let core = core.inner().clone();
    blocking(move || match key {
        Some(k) => core.llm_cache_remove(&k).map_err(e),
        None => core.llm_cache_clear().map_err(e),
    })
    .await
}

/// Sessions each filter would show (counters of saved filters); an error text where one does
/// not compile.
#[tauri::command]
async fn count_filters(core: State<'_, Core>, list: Vec<quena_query::FilterSettings>) -> R<Vec<Result<usize, String>>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.count_filters(list))).await
}

/// Add Quena's MCP server to an agent's configuration.
#[tauri::command]
async fn mcp_setup_client(core: State<'_, Core>, client: quena_app_core::mcp_setup::McpClient) -> R<String> {
    let core = core.inner().clone();
    blocking(move || core.mcp_setup_client(client).map_err(e)).await
}

/// Write the agent skill; returns its path.
#[tauri::command]
async fn mcp_install_skill(core: State<'_, Core>, target: quena_app_core::mcp_setup::SkillTarget) -> R<String> {
    let core = core.inner().clone();
    blocking(move || core.mcp_install_skill(target).map(|p| p.display().to_string()).map_err(e)).await
}

#[tauri::command]
async fn llm_prices_info(core: State<'_, Core>) -> R<quena_app_core::llm::LlmPricesInfo> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm_prices_info())).await
}

/// Fetch LiteLLM's price list (on request only: it leaves the machine).
#[tauri::command]
async fn llm_prices_update(core: State<'_, Core>) -> R<quena_app_core::llm::LlmPricesInfo> {
    let core = core.inner().clone();
    blocking(move || core.llm_prices_update().map_err(e)).await
}

#[tauri::command]
async fn llm_prices_forget(core: State<'_, Core>) -> R<quena_app_core::llm::LlmPricesInfo> {
    let core = core.inner().clone();
    blocking(move || core.llm_prices_forget().map_err(e)).await
}

/// Open `llm-prices.json` (created with an example first when there is none).
#[tauri::command]
async fn llm_prices_open(core: State<'_, Core>) -> R<()> {
    let path = std::path::PathBuf::from(core.llm_prices_info().path);
    if !path.exists() {
        let example = "{\n  \"my-model\": { \"input\": 1.0, \"output\": 2.0, \"cacheRead\": 0.1, \"cacheWrite\": 1.25 }\n}\n";
        std::fs::write(&path, example).map_err(|x| x.to_string())?;
    }
    quena_platform::open(&path.display().to_string()).map_err(e)
}

/// A packet capture again, with a TLS key log; `replace`: the sessions of its first import,
/// with the session numbering they belong to (event `pcap-import`).
#[tauri::command]
async fn import_capture(core: State<'_, Core>, path: String, name: Option<String>, keylog: String, replace: Vec<SessionId>, numbering: u64) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.import_capture(path.into(), name, vec![keylog.into()], replace, Some(numbering)).map_err(e)).await
}

/// Sanitized export (SAZ/HAR by `format` or the extension); the event `export-sanitized`
/// carries the redaction log when the job is done.
#[tauri::command]
async fn export_sanitized(
    core: State<'_, Core>,
    ids: Vec<SessionId>,
    path: String,
    format: Option<quena_app_core::archive::ArchiveFormat>,
    options: quena_app_core::sanitize::SanitizeOptions,
) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.export_sanitized(ids, path.into(), format, options).map_err(e)).await
}

/// The presets of the sanitized export (`support`, `gdpr`), for the dialog.
#[tauri::command]
async fn sanitize_presets() -> R<Vec<quena_app_core::sanitize::SanitizeOptions>> {
    Ok(["support", "gdpr"].iter().filter_map(|p| quena_app_core::sanitize::SanitizeOptions::preset(p)).collect())
}

/// Check sanitize options before the save dialog (an invalid pattern names itself).
#[tauri::command]
async fn sanitize_validate(options: quena_app_core::sanitize::SanitizeOptions) -> R<()> {
    options.validate()
}

/// Show a file in the file manager.
#[tauri::command]
async fn reveal_path(path: String) -> R<()> {
    quena_platform::reveal(std::path::Path::new(&path)).map_err(e)
}

/// The entries of the system's hosts file, as host remapping entries (not saved).
#[tauri::command]
async fn hosts_file_import() -> R<Vec<quena_app_core::settings::HostRemapEntry>> {
    blocking(|| {
        let path = quena_platform::hosts_file_path();
        let text = std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        Ok(quena_app_core::settings::parse_hosts_file(&text))
    })
    .await
}

/// Browsers that can be started with Quena as proxy.
#[tauri::command]
async fn browsers_list(core: State<'_, Core>) -> R<Vec<quena_app_core::launch::BrowserInfo>> {
    let c = core.inner().clone();
    blocking(move || Ok(c.browsers())).await
}

/// Start a browser with its own profile and Quena as proxy (starts capturing if needed).
#[tauri::command]
async fn launch_browser(core: State<'_, Core>, kind: String, url: Option<String>) -> R<String> {
    let c = core.inner().clone();
    blocking(move || c.launch_browser(&kind, url.as_deref().filter(|u| !u.trim().is_empty())).map(|b| b.name).map_err(e)).await
}

/// Open a terminal whose tools use Quena (starts capturing if needed).
#[tauri::command]
async fn open_terminal(core: State<'_, Core>) -> R<()> {
    let c = core.inner().clone();
    blocking(move || c.open_terminal().map_err(e)).await
}

/// One chunk of a file dropped onto the window (raw body; name, offset etc. in headers).
#[tauri::command]
async fn drop_chunk(core: State<'_, Core>, request: tauri::ipc::Request<'_>) -> R<Option<u64>> {
    let h = |k: &str| request.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let id = h("quena-drop-id");
    let name = percent_encoding::percent_decode_str(&h("quena-drop-name")).decode_utf8_lossy().into_owned();
    let offset: u64 = h("quena-drop-offset").parse().map_err(|_| "invalid drop offset".to_string())?;
    let last = h("quena-drop-last") == "1";
    let data = match request.body() {
        tauri::ipc::InvokeBody::Raw(b) => b.clone(),
        _ => return Err("expected raw bytes".into()),
    };
    let core = core.inner().clone();
    blocking(move || core.drop_chunk(&id, &name, offset, &data, last).map_err(e)).await
}

#[tauri::command]
async fn write_text_file(path: String, text: String) -> R<()> {
    blocking(move || std::fs::write(path, text).map_err(e)).await
}

/// Largest text file [`read_text_file`] loads (a saved diagnostics report for comparison).
const MAX_TEXT_FILE: u64 = 64 << 20;

/// Load a saved diagnostics report: a regular `.json` file of at most [`MAX_TEXT_FILE`].
#[tauri::command]
async fn read_text_file(path: String) -> R<String> {
    blocking(move || read_report_file(&path)).await
}

fn read_report_file(path: &str) -> R<String> {
    use std::io::Read;
    let p = std::path::Path::new(path);
    if !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("json")) {
        return Err(format!("{path}: not a .json file"));
    }
    // Checked before opening: opening a FIFO for reading would block.
    if !std::fs::metadata(p).map_err(e)?.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    let f = std::fs::File::open(p).map_err(e)?;
    let meta = f.metadata().map_err(e)?;
    if !meta.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    if meta.len() > MAX_TEXT_FILE {
        return Err(format!("{path}: file is larger than {} MB", MAX_TEXT_FILE >> 20));
    }
    let mut s = String::new();
    // `take` also bounds a file that grows while it is read.
    f.take(MAX_TEXT_FILE + 1).read_to_string(&mut s).map_err(e)?;
    if s.len() as u64 > MAX_TEXT_FILE {
        return Err(format!("{path}: file is larger than {} MB", MAX_TEXT_FILE >> 20));
    }
    Ok(s)
}

#[tauri::command]
async fn diag_analyzers(core: State<'_, Core>) -> R<Vec<quena_app_core::diagnostics::DiagAnalyzer>> {
    Ok(core.diag_analyzers())
}

#[tauri::command]
async fn diag_describe(core: State<'_, Core>, index: u16, lang: String) -> R<String> {
    let core = core.inner().clone();
    blocking(move || core.diag_describe(index, &lang).map_err(e)).await
}

/// Plugin loading has finished (it runs in the background after start).
#[tauri::command]
async fn plugins_ready(core: State<'_, Core>) -> R<bool> {
    Ok(core.plugins_ready())
}

#[tauri::command]
async fn diag_scope_options(core: State<'_, Core>) -> R<quena_app_core::diagnostics::DiagScopeOptions> {
    let core = core.inner().clone();
    blocking(move || Ok(core.diag_scope_options())).await
}

#[tauri::command]
async fn diag_run(core: State<'_, Core>, index: u16, options: String, ids: Option<Vec<SessionId>>, filter: Option<quena_app_core::diagnostics::DiagFilter>) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.diag_run(index, options, ids, filter.unwrap_or_default()).map_err(e)).await
}

#[tauri::command]
async fn diag_report(core: State<'_, Core>) -> R<Option<String>> {
    Ok(core.diag_report().map(|r| (*r).clone()))
}

use quena_app_core::rules::{AutoResponderState, BreakpointState, PausedInfo, Resume};

fn rules(core: &Core) -> R<std::sync::Arc<quena_app_core::rules::Rules>> {
    core.rules.clone().ok_or_else(|| "rules unavailable".to_string())
}

#[tauri::command]
async fn ar_get(core: State<'_, Core>) -> R<AutoResponderState> {
    Ok(rules(core.inner())?.autoresponder())
}

#[tauri::command]
async fn ar_set(core: State<'_, Core>, state: AutoResponderState) -> R<()> {
    rules(core.inner())?.set_autoresponder(state, true).map_err(e)
}

#[tauri::command]
async fn rw_get(core: State<'_, Core>) -> R<quena_app_core::rewrite::RewriteState> {
    Ok(rules(core.inner())?.rewrite.state())
}

#[tauri::command]
async fn rw_set(core: State<'_, Core>, state: quena_app_core::rewrite::RewriteState) -> R<quena_app_core::rewrite::RewriteState> {
    rules(core.inner())?.rewrite.set(state).map_err(e)
}

/// Save one rewrite rule (new: `id` 0, appended) without replacing the others.
#[tauri::command]
async fn rw_update(core: State<'_, Core>, rule: quena_app_core::rewrite::RewriteRule) -> R<quena_app_core::rewrite::RewriteState> {
    let c = core.inner().clone();
    blocking(move || c.rewrite_update(rule).map_err(e)).await
}

/// Try a rewrite rule on a captured session (before / after), without traffic.
#[tauri::command]
async fn rw_preview(core: State<'_, Core>, rule: quena_app_core::rewrite::RewriteRule, id: SessionId) -> R<quena_app_core::rewrite::RewritePreview> {
    let c = core.inner().clone();
    blocking(move || c.rewrite_preview(rule, id).map_err(e)).await
}

/// Apply rewrite rules to captured sessions (changed copies; the originals stay).
#[tauri::command]
async fn rw_apply(core: State<'_, Core>, ids: Vec<SessionId>, rule_ids: Option<Vec<u64>>, group: Option<String>) -> R<quena_app_core::rewrite::RewriteApplied> {
    let c = core.inner().clone();
    blocking(move || c.rewrite_apply(&ids, rule_ids.as_deref(), group.as_deref()).map_err(e)).await
}

#[tauri::command]
async fn ar_add_sessions(core: State<'_, Core>, ids: Vec<SessionId>, exact: bool) -> R<usize> {
    let r = rules(core.inner())?;
    blocking(move || r.add_rules_from_sessions(&ids, exact).map_err(e)).await
}

#[tauri::command]
async fn ar_import_farx(core: State<'_, Core>, path: String) -> R<AutoResponderState> {
    let r = rules(core.inner())?;
    blocking(move || {
        let xml = std::fs::read_to_string(&path).map_err(e)?;
        let mut incoming = quena_app_core::rules::import_farx(&xml).map_err(e)?;
        let mut cur = r.autoresponder();
        cur.rules.append(&mut incoming.rules);
        cur.enabled = cur.enabled || incoming.enabled;
        r.set_autoresponder(cur, true).map_err(e)?;
        Ok(r.autoresponder())
    })
    .await
}

#[tauri::command]
async fn library_list(core: State<'_, Core>) -> R<Vec<quena_app_core::library::LibraryEntry>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.library_list())).await
}

/// Save sessions (empty: all) into the library; returns the new archive's path in it.
#[tauri::command]
async fn library_save(core: State<'_, Core>, ids: Vec<SessionId>, folder: String, name: String, password: Option<String>) -> R<String> {
    let core = core.inner().clone();
    blocking(move || core.library_save(ids, &folder, &name, password.filter(|p| !p.is_empty())).map(|(_, rel)| rel).map_err(e)).await
}

#[tauri::command]
async fn library_add(core: State<'_, Core>, ids: Vec<SessionId>, path: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.library_add(ids, &path).map(|_| ()).map_err(e)).await
}

#[tauri::command]
async fn library_mkdir(core: State<'_, Core>, path: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.library_mkdir(&path).map_err(e)).await
}

#[tauri::command]
async fn library_rename(core: State<'_, Core>, path: String, name: String) -> R<String> {
    let core = core.inner().clone();
    blocking(move || core.library_rename(&path, &name).map_err(e)).await
}

#[tauri::command]
async fn library_delete(core: State<'_, Core>, path: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.library_delete(&path).map_err(e)).await
}

/// The absolute path of an archive in the library (to load it).
#[tauri::command]
fn library_file(core: State<'_, Core>, path: String) -> R<String> {
    core.library_path(&path).map(|p| p.display().to_string()).map_err(e)
}

#[tauri::command]
async fn library_reveal(core: State<'_, Core>) -> R<()> {
    let dir = core.library_dir();
    std::fs::create_dir_all(&dir).map_err(|x| x.to_string())?;
    quena_platform::open(&dir.display().to_string()).map_err(e)
}

/// Rewrite rules (of `group`, if given) to a JSON file; returns how many.
#[tauri::command]
async fn rw_export(core: State<'_, Core>, path: String, group: Option<String>) -> R<usize> {
    let core = core.inner().clone();
    blocking(move || core.rewrite_export(std::path::Path::new(&path), group.as_deref()).map_err(e)).await
}

/// Add the rewrite rules of a file; returns the new state.
#[tauri::command]
async fn rw_import(core: State<'_, Core>, path: String) -> R<quena_app_core::rewrite::RewriteState> {
    let core = core.inner().clone();
    blocking(move || core.rewrite_import(std::path::Path::new(&path)).map(|(s, _)| s).map_err(e)).await
}

#[tauri::command]
async fn ar_export_farx(core: State<'_, Core>, path: String) -> R<()> {
    let r = rules(core.inner())?;
    std::fs::write(path, quena_app_core::rules::export_farx(&r.autoresponder())).map_err(e)
}

// ------------------------------------------------------------------ mocks from sessions

use quena_app_core::mockgen::{MockOptions, MockPackage, MockPreview};

#[tauri::command]
async fn mock_preview(core: State<'_, Core>, ids: Vec<SessionId>, opts: MockOptions) -> R<MockPreview> {
    let core = core.inner().clone();
    blocking(move || core.mock_preview(ids, opts).map_err(e)).await
}

#[tauri::command]
async fn mock_export_wiremock(core: State<'_, Core>, ids: Vec<SessionId>, path: String, opts: MockOptions) -> R<u64> {
    core.mock_export_wiremock(ids, path.into(), opts).map_err(e)
}

#[tauri::command]
async fn mock_export_package(core: State<'_, Core>, ids: Vec<SessionId>, path: String, opts: MockOptions) -> R<u64> {
    core.mock_export_package(ids, path.into(), opts).map_err(e)
}

#[tauri::command]
async fn mock_apply(core: State<'_, Core>, ids: Vec<SessionId>, opts: MockOptions, name: String) -> R<u64> {
    core.mock_apply(ids, opts, name).map_err(e)
}

#[tauri::command]
async fn mock_import_package(core: State<'_, Core>, path: String, replace: bool) -> R<MockPackage> {
    let core = core.inner().clone();
    blocking(move || core.mock_import_package(path.into(), replace).map_err(e)).await
}

/// A package dropped onto the Mock Rules tab (raw bytes; name and mode in headers).
#[tauri::command]
async fn mock_import_package_data(core: State<'_, Core>, request: tauri::ipc::Request<'_>) -> R<MockPackage> {
    let h = |k: &str| request.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let name = percent_encoding::percent_decode_str(&h("quena-mock-name")).decode_utf8_lossy().into_owned();
    let replace = h("quena-mock-replace") == "1";
    let tauri::ipc::InvokeBody::Raw(data) = request.body() else {
        return Err("expected raw bytes".into());
    };
    // The body is borrowed from the request: work on it in place (no copy of a package that
    // can be hundreds of MB), off the async workers' queue.
    tokio::task::block_in_place(|| core.mock_import_package_bytes(&name, data, replace).map_err(e))
}

#[tauri::command]
async fn mock_remove_package(core: State<'_, Core>, name: String) -> R<usize> {
    let core = core.inner().clone();
    blocking(move || core.mock_remove_package(&name).map_err(e)).await
}

/// Sequences of a package start again with their first response; the number of rules reset.
#[tauri::command]
async fn mock_reset_sequences(core: State<'_, Core>, name: String) -> R<usize> {
    let core = core.inner().clone();
    blocking(move || core.mock_reset_sequences(&name).map_err(e)).await
}

#[tauri::command]
async fn mock_packages(core: State<'_, Core>) -> R<Vec<MockPackage>> {
    Ok(core.mock_packages())
}

#[tauri::command]
async fn bp_get(core: State<'_, Core>) -> R<BreakpointState> {
    Ok(rules(core.inner())?.breakpoints())
}

#[tauri::command]
async fn bp_set(core: State<'_, Core>, state: BreakpointState) -> R<()> {
    rules(core.inner())?.set_breakpoints(state);
    Ok(())
}

#[tauri::command]
async fn bp_paused(core: State<'_, Core>) -> R<Vec<PausedInfo>> {
    Ok(rules(core.inner())?.paused())
}

#[tauri::command]
async fn bp_resume(core: State<'_, Core>, id: SessionId, resume: Resume) -> R<()> {
    rules(core.inner())?.resume(id, resume).map_err(e)
}

#[tauri::command]
async fn bp_go(core: State<'_, Core>) -> R<usize> {
    Ok(rules(core.inner())?.go_all())
}

#[tauri::command]
async fn plugins_list(core: State<'_, Core>) -> R<Vec<quena_plugin_host::PluginInfo>> {
    Ok(core.plugins())
}

#[tauri::command]
async fn plugin_set_enabled(core: State<'_, Core>, id: String, enabled: bool) -> R<()> {
    core.plugin_set_enabled(&id, enabled).map_err(e)
}

#[tauri::command]
async fn plugins_rescan(core: State<'_, Core>) -> R<Vec<quena_plugin_host::PluginInfo>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.plugins_rescan())).await
}

#[tauri::command]
async fn plugins_inspect_header(core: State<'_, Core>, name: String, value: String) -> R<Vec<quena_plugin_host::HeaderInspection>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.plugin_inspect_header(&name, &value))).await
}

#[tauri::command]
async fn plugins_reveal(core: State<'_, Core>) -> R<()> {
    let d = core.plugin_dir();
    let _ = std::fs::create_dir_all(&d);
    quena_platform::open(&d.display().to_string()).map_err(e)
}

#[tauri::command]
async fn auth_set_credential(core: State<'_, Core>, host: String, user: String, domain: String, password: Option<String>) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.auth_set_credential(host, user, domain, password).map_err(e)).await
}

#[tauri::command]
async fn auth_remove_credential(core: State<'_, Core>, host: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.auth_remove_credential(host).map_err(e)).await
}

#[tauri::command]
async fn ws_frames(core: State<'_, Core>, id: SessionId, start: u64, count: usize) -> R<quena_app_core::ws::WsMessages> {
    let core = core.inner().clone();
    blocking(move || Ok(core.ws_frames(id, start, count))).await
}

#[tauri::command]
async fn save_body_range(core: State<'_, Core>, id: SessionId, part: Part, offset: u64, len: u64, path: String) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.save_body_range(id, part, offset, len, path.into()).map_err(e)).await
}

#[tauri::command]
async fn grpc(core: State<'_, Core>, id: SessionId, part: Part, type_name: Option<String>) -> R<Option<quena_app_core::grpc::Grpc>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.grpc(id, part, type_name.as_deref()))).await
}

/// The Composer's collections.
#[tauri::command]
async fn collections_list(core: State<'_, Core>) -> R<Vec<quena_app_core::collections::CollectionInfo>> {
    let core = core.inner().clone();
    blocking(move || core.collections_list().map_err(e)).await
}

#[tauri::command]
async fn collection_read(core: State<'_, Core>, name: String) -> R<quena_app_core::collections::Collection> {
    let core = core.inner().clone();
    blocking(move || core.collection_read(&name).map_err(e)).await
}

#[tauri::command]
async fn collection_save(core: State<'_, Core>, collection: quena_app_core::collections::Collection) -> R<quena_app_core::collections::CollectionInfo> {
    let core = core.inner().clone();
    blocking(move || core.collection_save(&collection).map_err(e)).await
}

#[tauri::command]
async fn collection_rename(core: State<'_, Core>, from: String, to: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.collection_rename(&from, &to).map_err(e)).await
}

#[tauri::command]
async fn collection_delete(core: State<'_, Core>, name: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.collection_delete(&name).map_err(e)).await
}

/// Copy a `.http` file into the collections; returns its name there.
#[tauri::command]
async fn collection_import(core: State<'_, Core>, path: String) -> R<String> {
    let core = core.inner().clone();
    blocking(move || core.collection_import(std::path::Path::new(&path)).map_err(e)).await
}

/// Send a request as edited in the Composer, with the variables of a collection.
#[tauri::command]
async fn collection_send(core: State<'_, Core>, name: Option<String>, request: quena_app_core::collections::CollectionRequest, env: Option<String>) -> R<quena_app_core::collections::HttpRunResult> {
    let core = core.inner().clone();
    blocking(move || core.collection_send(name.as_deref(), &request, env.as_deref().filter(|e| !e.is_empty())).map_err(e)).await
}

/// Run requests of a collection one after the other (all, or those named).
#[tauri::command]
async fn collection_run(core: State<'_, Core>, name: String, names: Vec<String>, env: Option<String>) -> R<Vec<quena_app_core::collections::HttpRunResult>> {
    let core = core.inner().clone();
    blocking(move || core.collection_run(&name, &names, env.as_deref().filter(|e| !e.is_empty()), std::time::Duration::from_secs(30)).map_err(e)).await
}

/// Open the collections folder in the file manager.
#[tauri::command]
async fn collections_reveal(core: State<'_, Core>) -> R<()> {
    let dir = core.collections_dir();
    std::fs::create_dir_all(&dir).map_err(|x| x.to_string())?;
    quena_platform::open(&dir.display().to_string()).map_err(e)
}

/// A session as an LLM API call (`None`: it is not one).
#[tauri::command]
async fn llm_call(core: State<'_, Core>, id: SessionId) -> R<Option<quena_app_core::llm::LlmCall>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm(id))).await
}

/// The conversations (agent runs) of the LLM calls in the capture.
#[tauri::command]
async fn llm_conversations(core: State<'_, Core>) -> R<Vec<quena_app_core::agent::ConvSummary>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm_conversations())).await
}

/// A conversation with its turns, hints and the context of its last request.
#[tauri::command]
async fn llm_conversation(core: State<'_, Core>, key: String) -> R<Option<quena_app_core::agent::ConvDetail>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm_conversation(&key))).await
}

/// An LLM call in its conversation: context breakdown, change from the turn before, cache.
#[tauri::command]
async fn llm_context(core: State<'_, Core>, id: SessionId) -> R<Option<quena_app_core::agent::CallContext>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm_context(id))).await
}

/// Send an LLM call again with changes (prompt playground); the new session.
#[tauri::command]
async fn llm_variant(core: State<'_, Core>, id: SessionId, variant: quena_app_core::playground::Variant) -> R<SessionId> {
    let core = core.inner().clone();
    blocking(move || core.llm_variant(id, variant).map_err(e)).await
}

/// Two conversations side by side.
#[tauri::command]
async fn llm_compare(core: State<'_, Core>, a: String, b: String) -> R<Option<quena_app_core::agent::ConvCompare>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm_compare(&a, &b))).await
}

/// Put a conversation's answered turns into the agent cache (frozen for replays).
#[tauri::command]
async fn llm_freeze(core: State<'_, Core>, key: String) -> R<quena_app_core::agent::Frozen> {
    let core = core.inner().clone();
    blocking(move || core.llm_freeze(&key).map_err(e)).await
}

/// Changes when LLM calls or MCP exchanges were added (cheap; for the Agents panel).
#[tauri::command]
async fn agent_stamp(core: State<'_, Core>) -> R<u64> {
    Ok(core.agent_stamp())
}

/// Write a conversation as Markdown, JSON lines or OpenTelemetry spans.
#[tauri::command]
async fn llm_export(core: State<'_, Core>, key: String, format: String, path: String) -> R<usize> {
    let core = core.inner().clone();
    blocking(move || core.llm_export(&key, &format, std::path::Path::new(&path)).map_err(e)).await
}

/// Start an AI agent in a terminal that uses Quena.
#[tauri::command]
async fn start_agent(core: State<'_, Core>, command: String) -> R<()> {
    let core = core.inner().clone();
    blocking(move || core.start_agent(&command).map_err(e)).await
}

/// A session as an MCP exchange (`None`: it is not one).
#[tauri::command]
async fn mcp_exchange(core: State<'_, Core>, id: SessionId) -> R<Option<quena_app_core::mcp_traffic::McpExchange>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.mcp_exchange(id))).await
}

/// The way of an MCP tool call: the LLM call that asked for it, the one that carries its result.
#[tauri::command]
async fn mcp_trail(core: State<'_, Core>, id: SessionId) -> R<Option<quena_app_core::tool_report::ToolTrail>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.mcp_trail(id))).await
}

/// The MCP exchanges that ran the tool calls of an LLM call's answer.
#[tauri::command]
async fn llm_tool_trails(core: State<'_, Core>, id: SessionId) -> R<Vec<quena_app_core::tool_report::ToolTrail>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.llm_tool_trails(id))).await
}

/// Tools and skills across the agent runs of the capture.
#[tauri::command]
async fn tool_report(core: State<'_, Core>) -> R<quena_app_core::tool_report::ToolReport> {
    let core = core.inner().clone();
    blocking(move || Ok(core.tool_report())).await
}

/// Socket.IO packets of a long-polling body (`None`: not Socket.IO polling).
#[tauri::command]
async fn socketio_polling(core: State<'_, Core>, id: SessionId, part: Part) -> R<Option<Vec<quena_app_core::socketio::SioPacket>>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.socketio_polling(id, part))).await
}

/// The sides one can compare (live, each archive in the list).
#[tauri::command]
async fn compare_sources(core: State<'_, Core>) -> R<Vec<quena_app_core::capdiff::SourceInfo>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.compare_sources())).await
}

/// Compare two captures in the list.
#[tauri::command]
async fn compare_captures(
    core: State<'_, Core>,
    a: quena_app_core::capdiff::Source,
    b: quena_app_core::capdiff::Source,
    options: Option<quena_app_core::capdiff::CompareOptions>,
) -> R<quena_app_core::capdiff::CaptureDiff> {
    let core = core.inner().clone();
    blocking(move || core.compare_captures_with(&a, &b, &options.unwrap_or_default()).map_err(e)).await
}

/// A MessagePack body as a tree (`None`: not MessagePack).
#[tauri::command]
async fn msgpack(core: State<'_, Core>, id: SessionId, part: Part) -> R<Option<quena_app_core::msgpack::Msgpack>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.msgpack(id, part))).await
}

/// The protobuf schemas and whether they compile.
#[tauri::command]
async fn protobuf_status(core: State<'_, Core>) -> R<quena_app_core::protobuf::SchemaStatus> {
    let core = core.inner().clone();
    blocking(move || Ok(core.protobuf_status())).await
}

/// Fetch a gRPC session's schema from its server (server reflection).
#[tauri::command]
async fn grpc_reflect(core: State<'_, Core>, id: SessionId) -> R<quena_app_core::protobuf::Reflected> {
    let core = core.inner().clone();
    blocking(move || core.grpc_reflect(id).map_err(e)).await
}

#[tauri::command]
async fn multipart(core: State<'_, Core>, id: SessionId, part: Part) -> R<Option<quena_app_core::multipart::Multipart>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.multipart(id, part))).await
}

mod quena_store_dto {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Recoverable {
        pub dir: String,
        pub sessions: u64,
        pub modified: Option<i64>,
    }
}

// ---------------------------------------------------------------- Scripting (M14)

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScriptState {
    source: String,
    enabled: bool,
    loaded: bool,
    error: Option<String>,
    types: String,
    menus: Vec<String>,
    column_title: Option<String>,
}

fn script_state(r: &std::sync::Arc<quena_app_core::rules::Rules>) -> ScriptState {
    let eng = r.script_engine();
    ScriptState {
        source: r.script_source(),
        enabled: r.script_enabled(),
        loaded: eng.is_loaded(),
        error: eng.last_error(),
        types: quena_script::TYPES_DTS.to_string(),
        menus: r.script_menus(),
        column_title: r.script_column_title(),
    }
}

#[tauri::command]
async fn script_get(core: State<'_, Core>) -> R<ScriptState> {
    Ok(script_state(&rules(core.inner())?))
}

#[tauri::command]
async fn script_set(core: State<'_, Core>, source: String) -> R<ScriptState> {
    let r = rules(core.inner())?;
    // A compile error is not a command failure: it is surfaced in `error` so the
    // editor can show it. The source is still saved.
    let _ = r.set_script(source).await;
    Ok(script_state(&r))
}

#[tauri::command]
async fn script_set_enabled(core: State<'_, Core>, enabled: bool) -> R<ScriptState> {
    let core = core.inner().clone();
    let r = rules(&core)?;
    let _ = r.set_script_enabled(enabled).await;
    let mut s = core.settings();
    s.scripting_enabled = enabled;
    core.update_settings(s).map_err(e)?;
    Ok(script_state(&r))
}

#[tauri::command]
async fn script_logs(core: State<'_, Core>) -> R<Vec<quena_script::LogLine>> {
    Ok(rules(core.inner())?.script_engine().logs())
}

#[tauri::command]
async fn script_clear_logs(core: State<'_, Core>) -> R<()> {
    rules(core.inner())?.script_engine().clear_logs();
    Ok(())
}

#[tauri::command]
async fn script_menus(core: State<'_, Core>) -> R<Vec<String>> {
    Ok(rules(core.inner())?.script_menus())
}

#[tauri::command]
async fn script_run_menu(core: State<'_, Core>, index: usize, ids: Vec<SessionId>) -> R<usize> {
    rules(core.inner())?.run_script_menu(index, &ids).await.map_err(e)
}

/// Archives passed to the app (file association, command line, macOS "Open With") that
/// the UI has not loaded yet.
pub struct OpenFiles(pub parking_lot::Mutex<Vec<String>>);

/// Hand pending archives to the UI once (it imports them after booting).
#[tauri::command]
fn take_open_files(files: State<'_, OpenFiles>) -> Vec<String> {
    std::mem::take(&mut *files.0.lock())
}

pub fn handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        status,
        mcp_status,
        mcp_new_token,
        set_group,
        toggle_group,
        collapse_groups,
        group_ids,
        rw_get,
        rw_set,
        app_info,
        rows,
        view_ids,
        position_of,
        set_sort,
        get_filters,
        set_filters,
        quickexec,
        remove,
        remove_all,
        remove_except,
        remove_where,
        summaries,
        mark,
        comment,
        detail,
        body_open,
        body_lines,
        body_search,
        search_result,
        save_body,
        statistics,
        find_sessions,
        find_result,
        jobs,
        cancel_job,
        settings_get,
        settings_set,
        save_ui_prefs,
        log_since,
        log_clear,
        mock_start,
        mock_stop,
        mock_big,
        toggle_capture,
        recoverable,
        recover,
        discard,
        discard_all,
        auth_set_credential,
        auth_remove_credential,
        ws_frames,
        multipart,
        save_body_range,
        grpc,
        ca_info,
        ca_trust,
        ca_machine,
        ca_remove,
        ca_regenerate,
        ca_export,
        ca_import,
        device_info,
        replay,
        compose,
        parse_raw_request,
        parse_curl,
        export_archive,
        import_archive,
        import_capture,
        export_sanitized,
        sanitize_presets,
        sanitize_validate,
        reveal_path,
        browsers_list,
        msgpack,
        compare_sources,
        compare_captures,
        socketio_polling,
        llm_call,
        llm_conversations,
        llm_conversation,
        llm_context,
        mcp_exchange,
        start_agent,
        agent_stamp,
        llm_export,
        llm_variant,
        llm_compare,
        llm_freeze,
        mcp_trail,
        llm_tool_trails,
        tool_report,
        collections_list,
        import_dropped,
        autosave_now,
        llm_prices_info,
        mcp_setup_client,
        replay_stop,
        count_filters,
        llm_cache_status,
        llm_cache_advice,
        llm_cache_set,
        llm_cache_auto,
        llm_cache_remove,
        mcp_install_skill,
        llm_prices_update,
        llm_prices_forget,
        llm_prices_open,
        autosave_reveal,
        collection_read,
        collection_save,
        collection_rename,
        collection_delete,
        collection_import,
        collection_run,
        collection_send,
        collections_reveal,
        protobuf_status,
        grpc_reflect,
        rw_update,
        rw_preview,
        rw_apply,
        hosts_file_import,
        launch_browser,
        open_terminal,
        timers,
        ui_language,
        set_language,
        structure,
        structure_ids,
        nav_groups,
        nav_ids,
        set_scope,
        drop_chunk,
        take_open_files,
        write_text_file,
        read_text_file,
        diag_analyzers,
        diag_describe,
        diag_run,
        diag_scope_options,
        plugins_ready,
        diag_report,
        ar_get,
        ar_set,
        ar_add_sessions,
        ar_import_farx,
        rw_export,
        library_list,
        library_save,
        library_add,
        library_mkdir,
        library_rename,
        library_delete,
        library_file,
        library_reveal,
        rw_import,
        ar_export_farx,
        mock_preview,
        mock_export_wiremock,
        mock_export_package,
        mock_apply,
        mock_import_package,
        mock_import_package_data,
        mock_remove_package,
        mock_packages,
        mock_reset_sequences,
        bp_get,
        bp_set,
        bp_paused,
        bp_resume,
        bp_go,
        plugins_list,
        plugin_set_enabled,
        plugins_rescan,
        plugins_inspect_header,
        plugins_reveal,
        script_get,
        script_set,
        script_set_enabled,
        script_logs,
        script_clear_logs,
        script_menus,
        script_run_menu,
    ]
}

#[cfg(test)]
mod read_report_file_tests {
    use super::read_report_file;

    #[test]
    fn only_regular_json_files_are_read() {
        let dir = std::env::temp_dir().join(format!("quena-read-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("report.JSON");
        std::fs::write(&ok, "{}").unwrap();
        assert_eq!(read_report_file(ok.to_str().unwrap()).unwrap(), "{}");
        let txt = dir.join("notes.txt");
        std::fs::write(&txt, "x").unwrap();
        assert!(read_report_file(txt.to_str().unwrap()).unwrap_err().contains("not a .json file"));
        // A directory named like a report is no file.
        let d = dir.join("dir.json");
        std::fs::create_dir_all(&d).unwrap();
        assert!(read_report_file(d.to_str().unwrap()).unwrap_err().contains("not a regular file"));
        // A FIFO is refused instead of blocking the reader.
        #[cfg(unix)]
        {
            let fifo = dir.join("fifo.json");
            let _ = std::fs::remove_file(&fifo);
            if std::process::Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success()) {
                assert!(read_report_file(fifo.to_str().unwrap()).unwrap_err().contains("not a regular file"));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
