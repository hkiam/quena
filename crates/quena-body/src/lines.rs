//! Line splitting and a sampled line index for huge text bodies.
//!
//! A "line" ends after `\n` or after [`MAX_LINE`] bytes (virtual wrap at a
//! UTF-8 boundary), so a 500 MB single-line JSON document becomes ~128k
//! displayable lines instead of one giant DOM node.

use crate::body::Body;
use crate::decode::Progress;
use crate::{BodyError, Result};
use parking_lot::RwLock;
use serde::Serialize;
use std::io::Read;

pub const MAX_LINE: usize = 4096;
/// Every STRIDE-th line start is sampled.
pub const STRIDE: u64 = 1024;

/// Incremental line splitter. Feed consecutive buffers; get line-start offsets.
#[derive(Debug, Default, Clone)]
pub struct LineSplitter {
    line_len: usize,
    pos: u64,
}

impl LineSplitter {
    pub fn at(pos: u64) -> Self {
        LineSplitter { line_len: 0, pos }
    }

    /// Calls `on_start(offset)` for every new line start found in `buf`.
    /// Returning `false` from the callback stops early; the function then
    /// returns the number of bytes consumed.
    pub fn feed(&mut self, buf: &[u8], mut on_start: impl FnMut(u64) -> bool) -> usize {
        let mut i = 0;
        while i < buf.len() {
            let room = MAX_LINE - self.line_len;
            let window = room.min(buf.len() - i);
            if let Some(nl) = memchr::memchr(b'\n', &buf[i..i + window]) {
                i += nl + 1;
                self.pos += (nl + 1) as u64;
                self.line_len = 0;
                if !on_start(self.pos) {
                    return i;
                }
                continue;
            }
            i += window;
            self.pos += window as u64;
            self.line_len += window;
            if self.line_len >= MAX_LINE {
                // Wrap before the next non-continuation byte.
                while i < buf.len() && (buf[i] & 0xC0) == 0x80 {
                    i += 1;
                    self.pos += 1;
                }
                if i < buf.len() {
                    if buf[i] == b'\n' {
                        // Newline right at the wrap point: let it end the line normally.
                        self.line_len = MAX_LINE - 1;
                        continue;
                    }
                    self.line_len = 0;
                    if !on_start(self.pos) {
                        return i;
                    }
                } else {
                    // Buffer ended at the wrap point; decide on the next buffer.
                    self.line_len = MAX_LINE;
                    return i;
                }
            }
        }
        i
    }

    /// Handle the pending wrap when a new buffer starts exactly at the wrap point.
    fn pre_feed(&mut self, buf: &[u8], on_start: &mut impl FnMut(u64) -> bool) -> (usize, bool) {
        if self.line_len < MAX_LINE {
            return (0, true);
        }
        let mut i = 0;
        while i < buf.len() && (buf[i] & 0xC0) == 0x80 {
            i += 1;
            self.pos += 1;
        }
        if i == buf.len() {
            return (i, true);
        }
        if buf[i] == b'\n' {
            self.line_len = MAX_LINE - 1;
            return (i, true);
        }
        self.line_len = 0;
        (i, on_start(self.pos))
    }

    pub fn feed_all(&mut self, buf: &[u8], mut on_start: impl FnMut(u64) -> bool) -> usize {
        let (skip, cont) = self.pre_feed(buf, &mut on_start);
        if !cont {
            return skip;
        }
        skip + self.feed(&buf[skip..], on_start)
    }
}

#[derive(Debug, Default)]
struct IndexState {
    samples: Vec<u64>,
    /// Number of line starts found (line 0 at offset 0 counts).
    lines: u64,
    last_start: u64,
    scanned: u64,
    done: bool,
    error: Option<String>,
}

/// Sampled line index. Built progressively; readable while building.
#[derive(Debug, Default)]
pub struct LineIndex {
    st: RwLock<IndexState>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LineIndexInfo {
    pub lines: u64,
    pub scanned: u64,
    pub done: bool,
    pub error: Option<String>,
}

impl LineIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn info(&self) -> LineIndexInfo {
        let s = self.st.read();
        LineIndexInfo { lines: s.lines, scanned: s.scanned, done: s.done, error: s.error.clone() }
    }

    /// Build the index for `body` (follows a growing body until complete).
    pub fn build(&self, body: &Body, p: &dyn Progress) -> Result<()> {
        {
            let mut s = self.st.write();
            *s = IndexState::default();
            s.samples.push(0);
        }
        let mut reader = body.stream(0, true);
        let mut splitter = LineSplitter::default();
        let mut buf = vec![0u8; 1 << 20];
        let mut local_samples: Vec<u64> = Vec::new();
        let mut lines: u64 = 1;
        let mut last_start: u64 = 0;
        let mut first = true;
        loop {
            if p.cancelled() {
                return Err(BodyError::Cancelled);
            }
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if crate::is_cancelled(&e) => return Err(BodyError::Cancelled),
                Err(e) => {
                    self.st.write().error = Some(e.to_string());
                    return Err(e.into());
                }
            };
            if first && n == 0 {
                lines = 0;
            }
            first = false;
            splitter.feed_all(&buf[..n], |off| {
                if lines % STRIDE == 0 {
                    local_samples.push(off);
                }
                lines += 1;
                last_start = off;
                true
            });
            let mut s = self.st.write();
            s.samples.append(&mut local_samples);
            s.lines = lines;
            s.last_start = last_start;
            s.scanned = reader.position();
            drop(s);
            p.progress(reader.position(), body.len().max(reader.position()));
        }
        let len = body.len();
        let mut s = self.st.write();
        if len == 0 {
            s.lines = 0;
            s.samples.clear();
        } else if s.last_start == len && s.lines > 1 {
            // Trailing newline does not start another line.
            s.lines -= 1;
            if (s.lines) % STRIDE == 0 && s.samples.last() == Some(&len) {
                s.samples.pop();
            }
        }
        s.scanned = len;
        s.done = true;
        Ok(())
    }

    /// Read `count` lines starting at `start` (lossy UTF-8, trailing `\r\n` stripped).
    pub fn read_lines(&self, body: &Body, start: u64, count: usize) -> Result<Vec<String>> {
        let (offset, first_line) = {
            let s = self.st.read();
            if s.samples.is_empty() {
                return Ok(vec![]);
            }
            let idx = ((start / STRIDE) as usize).min(s.samples.len() - 1);
            (s.samples[idx], idx as u64 * STRIDE)
        };
        let mut skip = start - first_line;
        let mut out = Vec::with_capacity(count);
        let mut cur: Vec<u8> = Vec::new();
        let mut splitter = LineSplitter::at(offset);
        let mut pos = offset;
        let mut buf = vec![0u8; 256 * 1024];
        let total = body.len();
        while out.len() < count && pos < total {
            let n = body.read_at(pos, &mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            let mut last = 0usize;
            let chunk_start = pos;
            splitter.feed_all(chunk, |off| {
                let end = (off - chunk_start) as usize;
                if skip > 0 {
                    skip -= 1;
                } else {
                    cur.extend_from_slice(&chunk[last..end]);
                    out.push(finish_line(std::mem::take(&mut cur)));
                }
                last = end;
                out.len() < count
            });
            if out.len() >= count {
                break;
            }
            if skip == 0 {
                cur.extend_from_slice(&chunk[last..]);
            }
            pos += n as u64;
        }
        if out.len() < count && !cur.is_empty() && skip == 0 {
            out.push(finish_line(cur));
        }
        Ok(out)
    }

    /// Line number containing byte `offset` (only exact once the index is done).
    pub fn line_of_offset(&self, body: &Body, offset: u64) -> Result<u64> {
        let (sample_off, sample_line) = {
            let s = self.st.read();
            if s.samples.is_empty() {
                return Ok(0);
            }
            let idx = match s.samples.binary_search(&offset) {
                Ok(i) => i,
                Err(i) => i.saturating_sub(1),
            };
            (s.samples[idx], idx as u64 * STRIDE)
        };
        let mut line = sample_line;
        let mut splitter = LineSplitter::at(sample_off);
        let mut pos = sample_off;
        let mut buf = vec![0u8; 256 * 1024];
        while pos <= offset {
            let n = body.read_at(pos, &mut buf)?;
            if n == 0 {
                break;
            }
            let mut stop = false;
            splitter.feed_all(&buf[..n], |off| {
                if off > offset {
                    stop = true;
                    return false;
                }
                line += 1;
                true
            });
            if stop {
                break;
            }
            pos += n as u64;
        }
        Ok(line)
    }
}

fn finish_line(mut v: Vec<u8>) -> String {
    if v.last() == Some(&b'\n') {
        v.pop();
        if v.last() == Some(&b'\r') {
            v.pop();
        }
    }
    String::from_utf8(v).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::NoProgress;
    use crate::store::{BodyConfig, BodyStore};

    fn body_of(data: &[u8]) -> (tempfile::TempDir, Body) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BodyConfig { inline_limit: 16, ..Default::default() };
        let store = BodyStore::open(dir.path(), cfg).unwrap();
        let b = store.store_bytes(data);
        (dir, b)
    }

    #[test]
    fn index_and_read() {
        let mut data = String::new();
        for i in 0..5000 {
            data.push_str(&format!("line {i}\n"));
        }
        let (_d, b) = body_of(data.as_bytes());
        let idx = LineIndex::new();
        idx.build(&b, &NoProgress).unwrap();
        assert_eq!(idx.info().lines, 5000);
        let l = idx.read_lines(&b, 2047, 3).unwrap();
        assert_eq!(l, vec!["line 2047", "line 2048", "line 2049"]);
        let l = idx.read_lines(&b, 4998, 10).unwrap();
        assert_eq!(l, vec!["line 4998", "line 4999"]);
        let off = data.find("line 3000\n").unwrap() as u64 + 2;
        assert_eq!(idx.line_of_offset(&b, off).unwrap(), 3000);
    }

    #[test]
    fn long_lines_wrap() {
        let data = vec![b'a'; MAX_LINE * 3 + 10];
        let (_d, b) = body_of(&data);
        let idx = LineIndex::new();
        idx.build(&b, &NoProgress).unwrap();
        assert_eq!(idx.info().lines, 4);
        let l = idx.read_lines(&b, 0, 10).unwrap();
        assert_eq!(l.len(), 4);
        assert_eq!(l[0].len(), MAX_LINE);
        assert_eq!(l[3].len(), 10);
    }

    #[test]
    fn wrap_respects_utf8() {
        let mut data = vec![b'a'; MAX_LINE - 1];
        data.extend_from_slice("€€".as_bytes());
        let (_d, b) = body_of(&data);
        let idx = LineIndex::new();
        idx.build(&b, &NoProgress).unwrap();
        let l = idx.read_lines(&b, 0, 10).unwrap();
        assert_eq!(l.len(), 2);
        assert!(l[0].ends_with('€'));
        assert_eq!(l[1], "€");
    }

    #[test]
    fn splitter_chunk_independent() {
        let mut data = Vec::new();
        for i in 0..300 {
            data.extend(std::iter::repeat_n(b'x', (i * 37) % 9000));
            data.push(b'\n');
        }
        let mut whole = Vec::new();
        LineSplitter::default().feed_all(&data, |o| {
            whole.push(o);
            true
        });
        for chunk in [1usize, 7, 4096, 4097, 10000] {
            let mut s = LineSplitter::default();
            let mut got = Vec::new();
            for c in data.chunks(chunk) {
                s.feed_all(c, |o| {
                    got.push(o);
                    true
                });
            }
            assert_eq!(got, whole, "chunk {chunk}");
        }
    }
}
