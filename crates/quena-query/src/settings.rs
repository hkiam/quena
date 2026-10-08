use crate::{glob_match, host_without_port, is_browser};
use quena_model::{SessionKind, SessionSummary};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum HostMode {
    #[default]
    NoFilter,
    ShowOnly,
    Hide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ProcessMode {
    #[default]
    All,
    Browsers,
    NonBrowsers,
    Remote,
}

/// State of the Filters tab.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct FilterSettings {
    pub enabled: bool,
    // Hosts
    pub host_mode: HostMode,
    /// Patterns separated by `;`, `,` or whitespace; `*` wildcards allowed.
    pub hosts: String,
    // Client process
    pub process_mode: ProcessMode,
    /// Show only traffic from these processes (`;` separated, substring match).
    pub process_only: String,
    pub hide_processes: String,
    // Request headers / URL
    pub url_show_only: String,
    pub url_hide: String,
    pub hide_connects: bool,
    // Response status
    pub hide_success: bool,
    pub hide_non_success: bool,
    pub hide_auth: bool,
    pub hide_redirects: bool,
    pub hide_not_modified: bool,
    // Response type and size
    pub hide_images: bool,
    pub hide_css: bool,
    pub hide_scripts: bool,
    pub hide_fonts: bool,
    pub content_type_show_only: String,
    pub content_type_hide: String,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub min_duration_ms: Option<u64>,
    /// Advanced expression (expression language), ANDed.
    pub expression: String,
}

fn split_list(s: &str) -> Vec<String> {
    s.split([';', ',', '\n', ' ', '\t'])
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    s: FilterSettings,
    hosts: Vec<String>,
    process_only: Vec<String>,
    hide_processes: Vec<String>,
    url_show: Vec<String>,
    url_hide: Vec<String>,
    ct_show: Vec<String>,
    ct_hide: Vec<String>,
}

impl Compiled {
    pub(crate) fn new(s: &FilterSettings) -> Self {
        Compiled {
            s: s.clone(),
            hosts: split_list(&s.hosts),
            process_only: split_list(&s.process_only),
            hide_processes: split_list(&s.hide_processes),
            url_show: split_list(&s.url_show_only),
            url_hide: split_list(&s.url_hide),
            ct_show: split_list(&s.content_type_show_only),
            ct_hide: split_list(&s.content_type_hide),
        }
    }

    pub(crate) fn matches(&self, r: &SessionSummary) -> bool {
        let s = &self.s;
        let tunnel = r.kind == SessionKind::Tunnel;
        if s.hide_connects && tunnel {
            return false;
        }
        // Hosts
        if s.host_mode != HostMode::NoFilter && !self.hosts.is_empty() {
            let host = if tunnel { host_without_port(&r.url) } else { host_without_port(&r.host) };
            let hit = self.hosts.iter().any(|p| glob_match(p, host));
            if (s.host_mode == HostMode::ShowOnly) != hit {
                return false;
            }
        }
        // Process
        let proc_lc = r.process.to_lowercase();
        match s.process_mode {
            ProcessMode::All => {}
            ProcessMode::Browsers if !is_browser(&r.process) => return false,
            ProcessMode::NonBrowsers if is_browser(&r.process) => return false,
            ProcessMode::Remote if !proc_lc.starts_with("remote:") => return false,
            _ => {}
        }
        if !self.process_only.is_empty() && !self.process_only.iter().any(|p| proc_lc.contains(p.as_str())) {
            return false;
        }
        if self.hide_processes.iter().any(|p| proc_lc.contains(p.as_str())) {
            return false;
        }
        // URL
        let url_lc = r.full_url().to_lowercase();
        if !self.url_show.is_empty() && !self.url_show.iter().any(|p| url_lc.contains(p.as_str())) {
            return false;
        }
        if self.url_hide.iter().any(|p| url_lc.contains(p.as_str())) {
            return false;
        }
        // Status – only applies once a response exists.
        if r.status != 0 {
            let st = r.status;
            if s.hide_success && (200..300).contains(&st) {
                return false;
            }
            if s.hide_non_success && !(200..300).contains(&st) {
                return false;
            }
            if s.hide_auth && (st == 401 || st == 407) {
                return false;
            }
            if s.hide_redirects && (300..400).contains(&st) && st != 304 {
                return false;
            }
            if s.hide_not_modified && st == 304 {
                return false;
            }
        }
        // Content type
        let ct = r.content_type.to_lowercase();
        if !ct.is_empty() {
            if s.hide_images && ct.starts_with("image/") {
                return false;
            }
            if s.hide_css && ct.contains("css") {
                return false;
            }
            if s.hide_scripts && (ct.contains("javascript") || ct.contains("ecmascript")) {
                return false;
            }
            if s.hide_fonts && (ct.starts_with("font/") || ct.contains("font-") || ct.contains("woff")) {
                return false;
            }
            if self.ct_hide.iter().any(|p| ct.contains(p.as_str())) {
                return false;
            }
        }
        if !self.ct_show.is_empty() && r.status != 0 && !self.ct_show.iter().any(|p| ct.contains(p.as_str())) {
            return false;
        }
        // Size and duration (only once known)
        if r.state.is_final() {
            if let Some(min) = s.min_size {
                if r.response_body_len < min {
                    return false;
                }
            }
            if let Some(max) = s.max_size {
                if r.response_body_len > max {
                    return false;
                }
            }
            if let (Some(min), Some(d)) = (s.min_duration_ms, r.duration_ms) {
                if (d as u64) < min {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Filter;

    fn row(host: &str, status: u16, ct: &str) -> SessionSummary {
        SessionSummary {
            host: host.into(),
            url: "/x".into(),
            status,
            content_type: ct.into(),
            protocol: "HTTPS".into(),
            ..Default::default()
        }
    }

    #[test]
    fn hosts_and_types() {
        let f = Filter::compile(&FilterSettings {
            enabled: true,
            host_mode: HostMode::ShowOnly,
            hosts: "*.company.de; localhost".into(),
            hide_images: true,
            ..Default::default()
        })
        .unwrap();
        assert!(f.matches(&row("api.company.de:443", 200, "application/json")));
        assert!(!f.matches(&row("api.company.de", 200, "image/png")));
        assert!(!f.matches(&row("example.com", 200, "text/html")));
        assert!(f.matches(&row("localhost:8080", 200, "")));
    }

    #[test]
    fn disabled_matches_all() {
        let f = Filter::compile(&FilterSettings { enabled: false, hide_images: true, ..Default::default() }).unwrap();
        assert!(f.matches(&row("a", 200, "image/png")));
    }
}
