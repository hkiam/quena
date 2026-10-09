//! Archive formats. All readers and writers stream bodies – archives with
//! multi-GB bodies neither need the RAM nor a temporary copy.

pub mod curl;
pub mod har;
pub mod http_file;
pub mod pcap;
pub mod raw;
pub mod saz;
mod time_fmt;

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("cancelled")]
    Cancelled,
    /// The archive is encrypted and no password was given.
    #[error("the archive is protected with a password")]
    PasswordRequired,
    #[error("wrong password")]
    WrongPassword,
}

pub type Result<T> = std::result::Result<T, FormatError>;

/// Progress reporting / cancellation for long imports and exports.
pub trait Progress {
    fn cancelled(&self) -> bool {
        false
    }
    fn progress(&self, _done: u64, _total: u64) {}
}

pub struct NoProgress;
impl Progress for NoProgress {}
