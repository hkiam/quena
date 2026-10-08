//! SOCKS port: SOCKS5 (RFC 1928; a user name and password, RFC 1929, are accepted and not
//! checked) and SOCKS4/4a. Only CONNECT: the client names a target, and the connection is
//! handled like a CONNECT tunnel — HTTPS is decrypted when decryption is on, plain HTTP is
//! recorded as sessions, anything else is passed through.

use crate::conn::{TunnelKind, begin_tunnel, run_tunnel};
use crate::forward::ConnCtx;
use crate::util::join_host_port;
use quena_model::Headers;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// The whole handshake must be done within this time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V4,
    V5,
}

/// Serve one client connection on the SOCKS port.
pub(crate) async fn serve(ctx: Arc<ConnCtx>, mut s: TcpStream) {
    let (host, port, version) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut s)).await {
        Ok(Ok(Some(t))) => t,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            tracing::debug!(target: "quena::proxy", "SOCKS handshake with {}: {e}", ctx.client_addr);
            return;
        }
        Err(_) => {
            tracing::debug!(target: "quena::proxy", "SOCKS handshake with {} timed out", ctx.client_addr);
            return;
        }
    };
    let target = join_host_port(&host, port);
    let mut headers = Headers::new();
    headers.push("Quena-Socks-Version", if version == Version::V5 { "5" } else { "4" });
    let (live, process) = begin_tunnel(&ctx, &target, headers).await;
    // Success right away; the target is connected when the client speaks (like CONNECT).
    let reply: &[u8] = match version {
        Version::V5 => &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        Version::V4 => &[0, 0x5a, 0, 0, 0, 0, 0, 0],
    };
    if s.write_all(reply).await.is_err() {
        live.update(|d| {
            d.summary.state = quena_model::SessionState::Aborted;
            d.error = Some("the SOCKS client closed the connection".into());
        });
        live.finish();
        return;
    }
    run_tunnel(ctx, live, process, s, host, port, TunnelKind::Socks).await;
}

/// Negotiate and read the request. `Ok(None)`: refused (the client got the reason).
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> std::io::Result<Option<(String, u16, Version)>> {
    match s.read_u8().await? {
        5 => socks5(s).await,
        4 => socks4(s).await,
        v => Err(std::io::Error::other(format!("not a SOCKS client (first byte {v:#04x})"))),
    }
}

async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> std::io::Result<Option<(String, u16, Version)>> {
    let n = s.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    if methods.contains(&0) {
        s.write_all(&[5, 0]).await?;
    } else if methods.contains(&2) {
        // User name and password: accepted whatever they are (Quena is no gatekeeper here;
        // the port's remote allowlist is).
        s.write_all(&[5, 2]).await?;
        let _ver = s.read_u8().await?;
        let ulen = s.read_u8().await? as usize;
        let mut skip = vec![0u8; ulen];
        s.read_exact(&mut skip).await?;
        let plen = s.read_u8().await? as usize;
        let mut skip = vec![0u8; plen];
        s.read_exact(&mut skip).await?;
        s.write_all(&[1, 0]).await?;
    } else {
        s.write_all(&[5, 0xff]).await?;
        return Ok(None);
    }
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    let [ver, cmd, _, atyp] = head;
    if ver != 5 {
        return Err(std::io::Error::other(format!("bad SOCKS5 request version {ver}")));
    }
    let host = match atyp {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let len = s.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            s.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| std::io::Error::other("SOCKS5 host name is not UTF-8"))?
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => {
            // Address type not supported.
            s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(None);
        }
    };
    let port = s.read_u16().await?;
    if cmd != 1 {
        // Only CONNECT (no BIND, no UDP ASSOCIATE): command not supported.
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(None);
    }
    Ok(Some((host, port, Version::V5)))
}

async fn socks4<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> std::io::Result<Option<(String, u16, Version)>> {
    let cmd = s.read_u8().await?;
    let port = s.read_u16().await?;
    let mut ip = [0u8; 4];
    s.read_exact(&mut ip).await?;
    let _user = read_cstr(s).await?;
    // SOCKS4a: 0.0.0.x (x ≠ 0) means "the host name follows".
    let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 { read_cstr(s).await? } else { Ipv4Addr::from(ip).to_string() };
    if cmd != 1 {
        s.write_all(&[0, 0x5b, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(None);
    }
    Ok(Some((host, port, Version::V4)))
}

/// A NUL-terminated string of at most 255 bytes.
async fn read_cstr<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<String> {
    let mut out = Vec::new();
    loop {
        match s.read_u8().await? {
            0 => break,
            b if out.len() < 255 => out.push(b),
            _ => return Err(std::io::Error::other("SOCKS4 field too long")),
        }
    }
    String::from_utf8(out).map_err(|_| std::io::Error::other("SOCKS4 field is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(input: &[u8]) -> (std::io::Result<Option<(String, u16, Version)>>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(input).await.unwrap();
        let r = handshake(&mut server).await;
        drop(server);
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        (r, out)
    }

    #[tokio::test]
    async fn socks5_domain_and_ip() {
        let mut req = vec![5, 1, 0, 5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        let (r, out) = run(&req).await;
        assert_eq!(r.unwrap(), Some(("example.com".into(), 443, Version::V5)));
        assert_eq!(out, [5, 0]);
        let (r, _) = run(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 7, 0, 80]).await;
        assert_eq!(r.unwrap(), Some(("10.0.0.7".into(), 80, Version::V5)));
        let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0x1f, 0x90]);
        assert_eq!(run(&v6).await.0.unwrap(), Some(("::1".into(), 8080, Version::V5)));
    }

    #[tokio::test]
    async fn socks5_password_is_accepted() {
        let (r, out) = run(&[5, 1, 2, 1, 1, b'u', 1, b'p', 5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await;
        assert_eq!(r.unwrap(), Some(("127.0.0.1".into(), 80, Version::V5)));
        assert_eq!(out, [5, 2, 1, 0]);
    }

    #[tokio::test]
    async fn socks5_refusals() {
        // No acceptable method.
        let (r, out) = run(&[5, 1, 0x80]).await;
        assert_eq!(r.unwrap(), None);
        assert_eq!(out, [5, 0xff]);
        // UDP ASSOCIATE is not supported.
        let (r, out) = run(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        assert_eq!(r.unwrap(), None);
        assert_eq!(&out[2..4], &[5, 7]);
        // Not SOCKS at all.
        assert!(run(b"GET / HTTP/1.1\r\n\r\n").await.0.is_err());
    }

    #[tokio::test]
    async fn socks4_and_4a() {
        let (r, _) = run(&[4, 1, 0, 80, 93, 184, 216, 34, b'u', 0]).await;
        assert_eq!(r.unwrap(), Some(("93.184.216.34".into(), 80, Version::V4)));
        let mut a = vec![4, 1, 1, 187, 0, 0, 0, 1, 0];
        a.extend_from_slice(b"example.org\0");
        assert_eq!(run(&a).await.0.unwrap(), Some(("example.org".into(), 443, Version::V4)));
    }
}
