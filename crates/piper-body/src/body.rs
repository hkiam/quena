use crate::store::BodyStore;
use crate::{BodyError, Result};
use parking_lot::RwLock;
use piper_model::BodyRef;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

#[derive(Debug, Default)]
struct State {
    inline: Vec<u8>,
    /// Bytes written to the blob file (0 if no file).
    file_len: u64,
    has_file: bool,
    wire_len: u64,
    truncated: bool,
    complete: bool,
}

#[derive(Debug)]
struct Inner {
    id: u64,
    path: PathBuf,
    state: RwLock<State>,
    /// Lazily opened read handle.
    reader: RwLock<Option<Arc<File>>>,
}

/// A stored (possibly still growing) body. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Body(Arc<Inner>);

impl Body {
    pub(crate) fn new(id: u64, path: PathBuf) -> Body {
        Body(Arc::new(Inner { id, path, state: RwLock::new(State::default()), reader: RwLock::new(None) }))
    }

    pub fn empty() -> Body {
        let b = Body::new(0, PathBuf::new());
        b.0.state.write().complete = true;
        b
    }

    pub(crate) fn from_ref(r: &BodyRef, path: PathBuf) -> Body {
        match r {
            BodyRef::Empty => Body::empty(),
            BodyRef::Inline { id, data, wire_len, truncated } => {
                let b = Body::new(*id, path);
                {
                    let mut s = b.0.state.write();
                    s.inline = data.clone();
                    s.wire_len = *wire_len;
                    s.truncated = *truncated;
                    s.complete = true;
                }
                b
            }
            BodyRef::Blob { id, len, wire_len, truncated, complete } => {
                let b = Body::new(*id, path);
                {
                    let mut s = b.0.state.write();
                    s.has_file = true;
                    s.file_len = *len;
                    s.wire_len = *wire_len;
                    s.truncated = *truncated;
                    // A blob that was not complete when persisted will never grow again.
                    let _ = complete;
                    s.complete = true;
                }
                b
            }
        }
    }

    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// Stored length (readable bytes).
    pub fn len(&self) -> u64 {
        let s = self.0.state.read();
        if s.has_file { s.file_len } else { s.inline.len() as u64 }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn wire_len(&self) -> u64 {
        self.0.state.read().wire_len
    }

    pub fn is_complete(&self) -> bool {
        self.0.state.read().complete
    }

    pub fn is_truncated(&self) -> bool {
        self.0.state.read().truncated
    }

    pub fn path(&self) -> Option<PathBuf> {
        let s = self.0.state.read();
        s.has_file.then(|| self.0.path.clone())
    }

    pub fn to_ref(&self) -> BodyRef {
        let s = self.0.state.read();
        if self.0.id == 0 && !s.has_file && s.inline.is_empty() && s.wire_len == 0 {
            return BodyRef::Empty;
        }
        if s.has_file {
            BodyRef::Blob {
                id: self.0.id,
                len: s.file_len,
                wire_len: s.wire_len,
                truncated: s.truncated,
                complete: s.complete,
            }
        } else if s.inline.is_empty() && s.wire_len == 0 {
            BodyRef::Empty
        } else {
            BodyRef::Inline { id: self.0.id, data: s.inline.clone(), wire_len: s.wire_len, truncated: s.truncated }
        }
    }

    /// Read up to `buf.len()` bytes at `offset`. Returns bytes read (0 at current end).
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let (has_file, file_len) = {
            let s = self.0.state.read();
            if !s.has_file {
                let len = s.inline.len() as u64;
                if offset >= len {
                    return Ok(0);
                }
                let start = offset as usize;
                let n = buf.len().min(s.inline.len() - start);
                buf[..n].copy_from_slice(&s.inline[start..start + n]);
                return Ok(n);
            }
            (s.has_file, s.file_len)
        };
        debug_assert!(has_file);
        if offset >= file_len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(file_len - offset) as usize;
        let file = self.file_handle()?;
        read_exact_at(&file, &mut buf[..want], offset)?;
        Ok(want)
    }

    /// Read a range into a new vector (clamped to the current length).
    pub fn read_range(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let avail = self.len().saturating_sub(offset);
        let mut v = vec![0u8; (len as u64).min(avail) as usize];
        let mut done = 0;
        while done < v.len() {
            let n = self.read_at(offset + done as u64, &mut v[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        v.truncate(done);
        Ok(v)
    }

    /// Sequential reader starting at `offset`. With `follow`, the reader waits
    /// for more data until the body is complete (for streaming derivations).
    pub fn file_handle(&self) -> io::Result<Arc<File>> {
        if let Some(f) = self.0.reader.read().as_ref() {
            return Ok(f.clone());
        }
        let f = Arc::new(File::open(&self.0.path)?);
        *self.0.reader.write() = Some(f.clone());
        Ok(f)
    }

    pub fn stream(&self, offset: u64, follow: bool) -> BodyReader {
        BodyReader { body: self.clone(), pos: offset, follow, cancel: None }
    }

    /// Delete the backing file (session removal).
    pub(crate) fn delete_file(&self) {
        *self.0.reader.write() = None;
        if self.0.state.read().has_file {
            let _ = std::fs::remove_file(&self.0.path);
        }
    }
}

fn read_exact_at(f: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = f.read_at(buf, offset)?;
        #[cfg(windows)]
        let n = f.seek_read(buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "blob shorter than expected"));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// Sequential reader over a [`Body`].
pub struct BodyReader {
    body: Body,
    pos: u64,
    follow: bool,
    cancel: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

impl BodyReader {
    pub fn with_cancel(mut self, f: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.cancel = Some(f);
        self
    }
    pub fn position(&self) -> u64 {
        self.pos
    }
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.body.read_at(self.pos, buf)?;
            if n > 0 {
                self.pos += n as u64;
                return Ok(n);
            }
            if !self.follow || self.body.is_complete() {
                // Re-check once: data may have arrived between read and completion check.
                let n = self.body.read_at(self.pos, buf)?;
                self.pos += n as u64;
                return Ok(n);
            }
            if let Some(c) = &self.cancel {
                if c() {
                    return Err(crate::cancelled_io());
                }
            }
            std::thread::sleep(Duration::from_millis(15));
        }
    }
}

/// Writer for a body that is being received. Owned by exactly one producer.
pub struct BodyWriter {
    body: Body,
    store: Arc<BodyStore>,
    file: Option<File>,
    inline_limit: usize,
    max_len: u64,
}

impl BodyWriter {
    pub(crate) fn new(body: Body, store: Arc<BodyStore>, inline_limit: usize, max_len: u64) -> Self {
        BodyWriter { body, store, file: None, inline_limit, max_len }
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Append a chunk. Bytes beyond the recording limit are counted but not stored.
    pub fn write(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let stored = self.body.len();
        let room = self.max_len.saturating_sub(stored);
        let keep = (chunk.len() as u64).min(room) as usize;
        {
            let mut s = self.body.0.state.write();
            s.wire_len += chunk.len() as u64;
            if keep < chunk.len() {
                s.truncated = true;
            }
        }
        if keep == 0 {
            return Ok(());
        }
        let data = &chunk[..keep];
        if self.file.is_none() {
            let inline_len = self.body.0.state.read().inline.len();
            if inline_len + data.len() <= self.inline_limit {
                self.body.0.state.write().inline.extend_from_slice(data);
                return Ok(());
            }
            self.spill()?;
        }
        if !self.store.reserve(data.len() as u64) {
            self.body.0.state.write().truncated = true;
            return Ok(());
        }
        let f = self.file.as_mut().expect("spilled");
        f.write_all(data)?;
        self.body.0.state.write().file_len += data.len() as u64;
        Ok(())
    }

    /// Account for bytes that passed the wire but could not be recorded.
    pub fn add_dropped(&mut self, n: u64) {
        if n > 0 {
            let mut s = self.body.0.state.write();
            s.wire_len += n;
            s.truncated = true;
        }
    }

    fn spill(&mut self) -> Result<()> {
        let path = &self.body.0.path;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = File::create(path)?;
        let mut s = self.body.0.state.write();
        let inline = std::mem::take(&mut s.inline);
        f.write_all(&inline)?;
        s.file_len = inline.len() as u64;
        s.has_file = true;
        drop(s);
        self.store.reserve(inline.len() as u64);
        self.file = Some(f);
        Ok(())
    }

    /// Mark as complete. Returns the body.
    pub fn finish(mut self) -> Body {
        if let Some(f) = self.file.take() {
            let _ = f.sync_data().map_err(|e| tracing::debug!("sync: {e}"));
        }
        self.body.0.state.write().complete = true;
        self.body.clone()
    }

    /// Mark as complete but aborted (connection dropped); data stays readable.
    pub fn abort(self) -> Body {
        self.finish()
    }
}

impl Drop for BodyWriter {
    fn drop(&mut self) {
        self.body.0.state.write().complete = true;
    }
}

impl Write for BodyWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        BodyWriter::write(self, buf).map_err(|e| match e {
            BodyError::Io(e) => e,
            other => io::Error::other(other.to_string()),
        })?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
