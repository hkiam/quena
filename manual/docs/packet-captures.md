# Packet captures

A packet capture shows traffic that never passed Quena: recorded with `tcpdump` on a server
or in a container, with Wireshark on a colleague's machine, or from an app that ignores the
system proxy or pins its certificates. Quena reads `.pcap` and `.pcapng` files, puts the TCP
connections back together and turns the HTTP in them into ordinary sessions — with the
inspectors, filters, Diagnostics, mocks and exports that work on captured traffic. HTTPS is
decrypted when the TLS secrets of the connections are available (see
[Decrypting HTTPS](#decrypting-https)).

## Record a capture

| Where | How |
|---|---|
| macOS | `sudo tcpdump -i all -w trace.pcapng port 80 or port 443` — `all` records every interface, loopback and VPN tunnels included, through the packet tap (written as pcapng) |
| Linux | `sudo tcpdump -i any -w trace.pcap port 80 or port 443` |
| Windows | Wireshark or `dumpcap`; or the built-in `pktmon start --capture`, `pktmon stop`, then `pktmon etl2pcap PktMon.etl --out trace.pcapng` |
| Wireshark | *File → Save As…* as pcapng (keeps embedded TLS secrets) or pcap |
| Servers, containers | `tcpdump -w` on the host or inside the container, then copy the file |

Record whole packets: current `tcpdump` versions do by default; with a small snapshot length
(`-s 128`) bodies are cut, and Quena says so in the affected sessions.

## Load it

- *File → Import Sessions → Packet Capture (pcap, pcapng)…*
- *File → Load Archive…* (`Ctrl/⌘ O`); the dialog shows archives and captures together.
- **Drag and drop** `.pcap`, `.pcapng` or `.cap` files onto the window.
- **Open With → Quena** in the Finder for `.pcap` and `.pcapng` (macOS registers Quena as
  an alternative viewer, so Wireshark stays the default).
- The command palette: *Import packet capture (pcap, pcapng)*.
- On the command line: `quena-cli` takes captures wherever it takes HAR and SAZ files (see
  [Command line](#command-line)).

Like loading an archive, importing a capture stops capturing and, when the list is not
empty, asks whether its sessions go or stay ([details](archives.md#loading)). The import
runs as a background job with its progress in the status bar and can be cancelled. The new
sessions are added to the list in the order of their requests and marked *imported*. A summary goes to the log, for example: *packet capture trace.pcap:
48 211 packet(s), 312 TCP connection(s), 1 204 session(s): 290 TLS connection(s) decrypted,
6 connection(s) not HTTP*. A capture with no HTTP at all is reported as an error that says
what it found instead.

Both file formats are read in all their variants: pcap with micro- or nanosecond
timestamps in either byte order, and pcapng with several interfaces and timestamp
resolutions. A file cut off in the middle (a recording that was killed) is read up to the
cut; a damaged block stops reading there, and what came before is kept. Compressed files
(`.pcap.gz`) have to be unpacked first.

## What becomes a session

| Traffic in the capture | In Quena |
|---|---|
| HTTP/1.0 and HTTP/1.1 | One session per request and response: keep-alive and pipelined requests, chunked bodies, `100 Continue` (skipped, like `103 Early Hints`), `HEAD`, `204` and `304` without a body, responses that end with the connection; any method, also requests in absolute form to a proxy |
| WebSocket | One WebSocket session after the `101` upgrade, its messages (unmasked) in the WebSocket inspector |
| HTTP/2 | One session per stream, also server pushes; in cleartext (h2c with prior knowledge or after `Upgrade: h2c`, gRPC) and inside decrypted TLS; trailers are added to the headers, a reset stream says so in its error |
| HTTPS | Decrypted: the sessions inside, as above, marked *decrypted*. Without secrets: one tunnel session `CONNECT host:443` |
| `CONNECT` through a proxy | The tunnel session, plus the sessions inside it (HTTPS decrypted when possible, or plain HTTP) |
| Other TCP traffic (databases, SMTP, …), UDP (DNS, QUIC/HTTP/3) | Skipped; counted in the summary |

### What each session shows

- **Addresses**: client and server address with port (*Properties*), the *Client IP*
  column, and the connection number — group the list *by connection* to see keep-alive
  connections and HTTP/2 streams together. Later requests on a connection are marked as
  reusing it; HTTP/2 sessions show their stream id.
- **Timings** from the packet times, as seen where the capture was taken: TCP connect
  (SYN to SYN/ACK) on the first request of a connection, TLS handshake (ClientHello to the
  first application data) for decrypted connections, request start and end, the response's
  first byte, headers and end. The [Timeline](analyze.md) and Diagnostics use them.
- **Bodies** as they were sent: chunked transfer coding removed, `Content-Encoding` (gzip,
  brotli, zstd) kept, so the inspectors decode them as usual. The limits of *Settings →
  Bodies & Storage* apply.
- **Tunnels** (TLS without secrets): the server name (SNI) as target, ALPN, TLS version
  and cipher suite under *Properties*, and the bytes in both directions (↑ ↓ in the
  *Custom* column). When a connection cannot be decrypted for another reason than missing
  secrets, *Properties* says why.

## Decrypting HTTPS

TLS keeps its keys secret, but many clients write them to a **key log** (the NSS
`SSLKEYLOGFILE` format) when asked to. Record the key log together with the capture:

```bash
export SSLKEYLOGFILE=~/trace.keys        # read by the programs started from this shell
sudo tcpdump -i any -w ~/trace.pcap port 443       # macOS: -i all
```

| Client | How it writes a key log |
|---|---|
| Chrome, Edge, Firefox | the `SSLKEYLOGFILE` environment variable (start the browser from that shell) |
| curl | `SSLKEYLOGFILE` (builds with OpenSSL, BoringSSL or wolfSSL, such as Homebrew's curl on macOS) |
| Node.js | `node --tls-keylog=trace.keys app.js` |
| Python | `ssl.SSLContext.keylog_filename`; `urllib3` and `requests` honour `SSLKEYLOGFILE` |
| Go | `tls.Config{KeyLogWriter: f}` |
| OpenSSL tools | `openssl s_client -keylogfile trace.keys` |

### Where Quena takes the secrets from

All of these are combined; every connection uses the secrets logged for it:

1. **The capture itself.** pcapng files can carry the secrets (a *Decryption Secrets
   Block*); Wireshark's `editcap` adds them:
   `editcap --inject-secrets tls,trace.keys trace.pcapng with-keys.pcapng`. Such a file is
   self-contained — the easiest way to hand a decryptable capture to someone.
2. **A key log next to the capture**, found by its name: `trace.pcap.keys`, `trace.keys`,
   `trace.keylog`, `sslkeylog.log` or `sslkeys.log` in the same folder.
3. ***Settings → HTTPS → Packet captures***: a key log used for every import, like
   Wireshark's *(Pre)-Master-Secret log filename* — handy when `SSLKEYLOGFILE` always points
   to the same file.
4. **After the import.** When connections stayed encrypted, the status bar says how many
   (*trace.pcap: 3 TLS connections could not be decrypted (no secrets in the key log)*) and
   offers ***Choose key log file…***. The capture is loaded again with that key log, and
   the new sessions replace those of the first import (unless the list was cleared with
   *Remove All* since; then they are added). This also works for dropped files:
   Quena keeps their temporary copy until it is restarted, for an hour at most.
5. **`quena-cli --tls-keylog trace.keys`** (repeatable).

### What is decrypted

| | |
|---|---|
| TLS 1.3 | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`; key updates are followed |
| TLS 1.2 | AES-GCM and ChaCha20-Poly1305 suites (ECDHE, DHE, RSA and PSK key exchange), and AES-CBC suites with SHA-1, SHA-256 or SHA-384 MACs, with or without encrypt-then-MAC |
| Not decrypted | SSL 3.0, TLS 1.0 and 1.1, drafts of TLS 1.3, TLS 1.3 early data (0-RTT), AES-CCM and other rare suites, a renegotiation inside a connection, DTLS and QUIC |

A connection that is not decrypted stays a tunnel session, with the reason under
*Properties* when it is not just missing secrets. Inside a decrypted connection, a gap in
the capture ends decryption: the sessions after it say so in their error.

!!! warning "Key logs are secrets"
    Anyone with the key log can read the recorded traffic, including passwords and tokens.
    Quena reads key logs only locally and does not store them in sessions or archives — but
    a pcapng with embedded secrets carries them. Delete key logs after use, and share
    captures with the [sanitized export](archives.md#sanitized-export-for-sharing) instead
    of the original file.

## Missing and damaged data

Captures are rarely perfect. Quena keeps as much as can be read correctly and says where
something is missing:

- **Packets out of order or sent twice** are put in order; retransmissions and overlaps
  are dropped.
- **Lost packets.** When the other side acknowledged bytes the capture does not have,
  they are known to be lost. The affected message ends there and says how many bytes are
  missing (*12 bytes of the response body are missing in the capture*); a whole lost
  response or request is noted as well, so the requests and responses after it still pair
  up correctly. An HTTP/2 connection cannot be followed after a gap (its header
  compression is lost); its open streams say so.
- **Packets cut by the snapshot length** are counted, and the bodies they belonged to are
  marked as incomplete.
- **Recording started mid-connection**: Quena picks up at the next complete request or
  response. A response whose request was not recorded is skipped (counted in the summary);
  a WebSocket or other upgrade whose request is missing is kept with a note.
- **IP fragments** (rare for TCP) are skipped and counted.

The summary in the log lists all of it: places where packets are missing, responses
without their request, connections that are not HTTP, IP fragments, packets cut short,
packets of an unsupported link type, a file cut off or damaged.

## Supported captures

IPv4 and IPv6 over Ethernet (also with VLAN tags), Linux "any" (cooked capture SLL and
SLL2), raw IP, BSD loopback (macOS `lo0`) and the macOS packet tap (`tcpdump -i any`, VPN
interfaces). Captures of other link types — Wi-Fi in monitor mode (radiotap), USB,
Bluetooth — are reported as unsupported.

## Command line

`quena-cli` reads captures like HAR and SAZ files — for Diagnostics in CI, sanitised copies,
mocks and `.http` collections:

```bash
quena-cli diagnose trace.pcapng --fail-on critical
quena-cli diagnose trace.pcap --tls-keylog trace.keys
quena-cli sanitize trace.pcap --tls-keylog trace.keys -o shared.har --preset gdpr
quena-cli http from-har trace.pcap -o requests.http
```

Key logs next to the capture and secrets embedded in pcapng files are used there as well.
See [Diagnostics in CI](ci.md).
