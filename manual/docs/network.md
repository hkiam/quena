# Client certificates and throttling

## Client certificates (mTLS)

Some servers require the client to present a certificate. Quena can present one for you
when it connects to such a server.

1. Open **Capture → HTTPS Settings…** → *Client certificates (mTLS)*.
2. Click **Add client certificate**.
3. Enter a **host pattern** (e.g. `*.corp.example`), then choose the **certificate** and the
   **key** as PEM files (`.pem`, `.crt`, `.cer`, `.key`). Certificate and key may be in the
   same file; the key is optional in that case.

The certificate is presented to matching upstream hosts. `✕` removes an entry. HTTPS
decryption must be on for the host, since Quena makes the TLS connection to the server
itself.

## Bandwidth and latency simulation

To see how an application behaves on a slow network, set in
*Settings → Connections → Bandwidth simulation*:

| Option | Meaning |
|---|---|
| *Throttle (kbit/s)* | bandwidth cap, `0` = unlimited |
| *Added latency (ms)* | extra delay before each response, `0` = none |

For individual URLs, use [Mock Rules](change-replay.md#latency) with a latency or a
`*delay:` action instead.
