//! Port for transparently redirected traffic: the firewall (iptables/nftables on Linux, pf
//! on macOS, a router) sends connections that were meant for other hosts here, and the
//! clients need no proxy settings at all.
//!
//! The target is the connection's original destination where the system tells it (Linux:
//! `SO_ORIGINAL_DST`), otherwise the TLS server name (SNI, port 443) or, for plain HTTP, the
//! `Host` header. Connections are handled like CONNECT tunnels: HTTPS is decrypted when
//! decryption is on, plain HTTP is recorded, anything else is passed through.

use crate::conn::{Prefixed, TunnelKind, begin_tunnel, run_tunnel, serve_h1};
use crate::forward::ConnCtx;
use crate::util::join_host_port;
use quena_model::Headers;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// A client without a known original destination must say something within this time.
const FIRST_BYTES_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest TLS record (ClientHello) read to find the server name.
const MAX_RECORD: usize = 5 + 16 * 1024;

/// Serve one redirected connection.
pub(crate) async fn serve(ctx: Arc<ConnCtx>, mut s: TcpStream) {
    let local = s.local_addr().ok();
    // Not redirected (the client called this port itself) or pointing back at Quena: no
    // original destination to use.
    let orig = original_dst(&s).filter(|a| Some(*a) != local && !crate::connector::is_self_addr(a));
    if let Some(o) = orig {
        let host = o.ip().to_canonical().to_string();
        let mut h = Headers::new();
        h.push("Quena-Original-Destination", o.to_string());
        let (live, process) = begin_tunnel(&ctx, &join_host_port(&host, o.port()), h).await;
        run_tunnel(ctx, live, process, s, host, o.port(), TunnelKind::Transparent).await;
        return;
    }
    // The name inside: TLS server name, or the Host header of plain HTTP.
    let mut buf = Vec::new();
    let first = tokio::time::timeout(FIRST_BYTES_TIMEOUT, async {
        let mut b = [0u8; 1];
        if s.read(&mut b).await.ok()? == 0 {
            return None;
        }
        buf.push(b[0]);
        Some(b[0])
    })
    .await;
    let Ok(Some(first)) = first else { return };
    if first == 0x16 {
        let read = tokio::time::timeout(FIRST_BYTES_TIMEOUT, read_record(&mut s, &mut buf)).await;
        let sni = match read {
            Ok(Ok(())) => client_hello_sni(&buf),
            _ => None,
        };
        let Some(host) = sni else {
            tracing::warn!(target: "quena::proxy", "transparent: TLS from {} without a server name (SNI) and no original destination; closed", ctx.client_addr);
            return;
        };
        let (live, process) = begin_tunnel(&ctx, &join_host_port(&host, 443), Headers::new()).await;
        run_tunnel(ctx, live, process, Prefixed::new(buf, s), host, 443, TunnelKind::Transparent).await;
    } else if first.is_ascii_uppercase() {
        // Plain HTTP: the Host header names the target (origin-form request).
        serve_h1(ctx, Prefixed::new(buf, s)).await;
    } else {
        tracing::warn!(target: "quena::proxy", "transparent: {} sent neither TLS nor HTTP and the original destination is unknown; closed", ctx.client_addr);
    }
}

/// Read the rest of the first TLS record into `buf` (which holds its first byte).
async fn read_record(s: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut chunk = [0u8; 4096];
    loop {
        let want = if buf.len() >= 5 { (5 + u16::from_be_bytes([buf[3], buf[4]]) as usize).min(MAX_RECORD) } else { 5 };
        if buf.len() >= want {
            return Ok(());
        }
        let take = (want - buf.len()).min(chunk.len());
        let n = s.read(&mut chunk[..take]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The server name (SNI) of a TLS ClientHello record.
pub(crate) fn client_hello_sni(rec: &[u8]) -> Option<String> {
    let mut r = Reader { b: rec, p: 0 };
    if r.u8()? != 0x16 {
        return None;
    }
    r.skip(4)?; // version, record length
    if r.u8()? != 1 {
        return None; // not a ClientHello
    }
    r.skip(3 + 2 + 32)?; // length, client version, random
    let sid = r.u8()? as usize;
    r.skip(sid)?;
    let cs = r.u16()? as usize;
    r.skip(cs)?;
    let comp = r.u8()? as usize;
    r.skip(comp)?;
    let ext_len = r.u16()? as usize;
    let end = (r.p + ext_len).min(rec.len());
    while r.p + 4 <= end {
        let typ = r.u16()?;
        let len = r.u16()? as usize;
        if typ != 0 {
            r.skip(len)?;
            continue;
        }
        let list_end = r.p + r.u16()? as usize;
        while r.p + 3 <= list_end {
            let kind = r.u8()?;
            let n = r.u16()? as usize;
            let name = r.take(n)?;
            if kind == 0 {
                let name = std::str::from_utf8(name).ok()?.trim_end_matches('.').to_ascii_lowercase();
                return (!name.is_empty()).then_some(name);
            }
        }
        return None;
    }
    None
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n)?;
        self.p += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// The destination a connection had before the firewall redirected it (Linux netfilter).
#[cfg(target_os = "linux")]
fn original_dst(s: &TcpStream) -> Option<SocketAddr> {
    use std::os::fd::AsRawFd;
    const SOL_IP: i32 = 0;
    const SOL_IPV6: i32 = 41;
    const SO_ORIGINAL_DST: i32 = 80;
    unsafe extern "C" {
        fn getsockopt(socket: i32, level: i32, name: i32, value: *mut std::ffi::c_void, option_len: *mut u32) -> i32;
    }
    let fd = s.as_raw_fd();
    for level in [SOL_IP, SOL_IPV6] {
        let mut buf = [0u8; 128];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` is valid for `len` bytes; the kernel writes at most `len` bytes.
        let r = unsafe { getsockopt(fd, level, SO_ORIGINAL_DST, buf.as_mut_ptr().cast(), &mut len) };
        if r != 0 {
            continue;
        }
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        match family {
            2 if len >= 8 => return Some(SocketAddr::from(([buf[4], buf[5], buf[6], buf[7]], port))),
            10 if len >= 24 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&buf[8..24]);
                return Some(SocketAddr::from((std::net::Ipv6Addr::from(a), port)));
            }
            _ => {}
        }
    }
    None
}

/// Other systems do not tell the original destination to an unprivileged process: the
/// server name or Host header decides.
#[cfg(not(target_os = "linux"))]
fn original_dst(_: &TcpStream) -> Option<SocketAddr> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ClientHello with the given extensions.
    fn hello(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // compression: null
        let mut ext = Vec::new();
        for (t, d) in exts {
            ext.extend_from_slice(&t.to_be_bytes());
            ext.extend_from_slice(&(d.len() as u16).to_be_bytes());
            ext.extend_from_slice(d);
        }
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn sni(name: &str) -> (u16, Vec<u8>) {
        let mut d = Vec::new();
        d.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        d.push(0);
        d.extend_from_slice(&(name.len() as u16).to_be_bytes());
        d.extend_from_slice(name.as_bytes());
        (0, d)
    }

    #[test]
    fn server_name_is_found_among_other_extensions() {
        let rec = hello(&[(0x002b, vec![2, 3, 4]), sni("API.Example.com."), (0x0010, vec![0, 3, 2, b'h', b'2'])]);
        assert_eq!(client_hello_sni(&rec).as_deref(), Some("api.example.com"));
        assert_eq!(client_hello_sni(&hello(&[(0x002b, vec![2, 3, 4])])), None);
        // Truncated or not a handshake: no name, no panic.
        assert_eq!(client_hello_sni(&rec[..20]), None);
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n"), None);
        for n in 0..rec.len() {
            let _ = client_hello_sni(&rec[..n]);
        }
    }
}
