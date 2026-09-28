use crate::{PlatformError, Result, SystemProxy};
use piper_model::ProcessInfo;
use std::path::Path;

pub fn system_proxy() -> Result<SystemProxy> {
    Ok(SystemProxy::default())
}
pub fn set_system_proxy(_port: u16, _bypass: &[String], _backup: &Path) -> Result<()> {
    Err(PlatformError::Unsupported)
}
pub fn restore_system_proxy(_backup: &Path) -> Result<bool> {
    Ok(false)
}
pub fn install_root_ca(_cert: &Path) -> Result<()> {
    Err(PlatformError::Unsupported)
}
pub fn remove_root_ca(_cert: &Path, _sha1: &str) -> Result<()> {
    Err(PlatformError::Unsupported)
}
pub fn is_root_ca_trusted(_cert: &Path) -> bool {
    false
}
pub fn open(_target: &str) -> Result<()> {
    Err(PlatformError::Unsupported)
}
pub fn reveal(_path: &Path) -> Result<()> {
    Err(PlatformError::Unsupported)
}
pub fn local_addresses() -> Vec<(String, String)> {
    vec![]
}

#[derive(Default)]
pub struct ProcessLookup;
impl ProcessLookup {
    pub fn new() -> Self {
        ProcessLookup
    }
    pub fn lookup(&self, _client_port: u16, _proxy_port: u16) -> Option<ProcessInfo> {
        None
    }
}
