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

#[tauri::command]
async fn structure(core: State<'_, Core>, host: Option<String>, prefix: String) -> R<quena_app_core::structure::TreeLevel> {
    let core = core.inner().clone();
    blocking(move || Ok(core.structure(host.as_deref(), &prefix))).await
}

#[tauri::command]
async fn structure_ids(core: State<'_, Core>, host: String, path: String) -> R<Vec<SessionId>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.structure_ids(&host, &path))).await
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
async fn body_lines(core: State<'_, Core>, id: SessionId, part: Part, variant: Variant, start: u64, count: usize) -> R<LinesDto> {
    let core = core.inner().clone();
    blocking(move || core.body_lines(id, part, variant, start, count).map_err(e)).await
}

#[tauri::command]
async fn body_search(core: State<'_, Core>, id: SessionId, part: Part, variant: Variant, needle: String, ignore_case: bool) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.body_search(id, part, variant, needle, ignore_case).map_err(e)).await
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
async fn settings_set(core: State<'_, Core>, settings: Settings) -> R<()> {
    let core = core.inner().clone();
    let old_scripting = core.settings().scripting_enabled;
    let new_scripting = settings.scripting_enabled;
    let cc = core.clone();
    blocking(move || cc.update_settings(settings).map_err(e)).await?;
    if new_scripting != old_scripting {
        if let Some(r) = core.rules.clone() {
            let _ = r.set_script_enabled(new_scripting).await;
        }
    }
    Ok(())
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
async fn ca_export(engine: State<'_, Engine>, path: String, der: bool) -> R<()> {
    let e = engine.inner().clone();
    blocking(move || e.ca_export(path.into(), der).map_err(|x| x.to_string())).await
}

#[tauri::command]
async fn device_info(core: State<'_, Core>, engine: State<'_, Engine>) -> R<DeviceInfo> {
    Ok(engine.device_info(core.inner()))
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
async fn export_archive(core: State<'_, Core>, ids: Vec<SessionId>, path: String) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.export_archive(ids, path.into(), None).map_err(e)).await
}

#[tauri::command]
async fn import_archive(core: State<'_, Core>, path: String) -> R<u64> {
    let core = core.inner().clone();
    blocking(move || core.import_archive(path.into()).map_err(e)).await
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
async fn ar_export_farx(core: State<'_, Core>, path: String) -> R<()> {
    let r = rules(core.inner())?;
    std::fs::write(path, quena_app_core::rules::export_farx(&r.autoresponder())).map_err(e)
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
async fn grpc(core: State<'_, Core>, id: SessionId, part: Part) -> R<Option<quena_app_core::grpc::Grpc>> {
    let core = core.inner().clone();
    blocking(move || Ok(core.grpc(id, part))).await
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
        ca_remove,
        ca_regenerate,
        ca_export,
        device_info,
        replay,
        compose,
        parse_raw_request,
        parse_curl,
        export_archive,
        import_archive,
        timers,
        structure,
        structure_ids,
        drop_chunk,
        take_open_files,
        write_text_file,
        ar_get,
        ar_set,
        ar_add_sessions,
        ar_import_farx,
        ar_export_farx,
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
