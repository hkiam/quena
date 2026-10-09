# HTTPS and devices

Without decryption, HTTPS connections appear in the list as **tunnels** (CONNECT) with the
target host, but their content is not visible. To see inside, Quena acts as a
man-in-the-middle with certificates it issues on the fly from its own root certificate.

## Enable HTTPS decryption

1. Open **Capture → HTTPS Settings…**.
2. Enable **Decrypt HTTPS traffic**. The root certificate is created now if it does not
   exist yet.
3. Click **Trust root certificate…**. The status changes to *trusted by* your operating
   system.

The certificate and its private key are generated on your machine and stored in Quena's
data directory with owner-only permissions. The key leaves the computer only if you export
it yourself (*Export with key (.p12)…*). Instead of Quena's own certificate you can also
[use an existing CA](#use-an-existing-ca), e.g. your company's.

| Platform | Where *Trust* adds the certificate |
|---|---|
| macOS | Keychain |
| Windows | the current user's certificate store |
| Linux | Chrome's and Firefox's certificate databases (NSS, via `certutil`) and — after asking for your password (`pkexec`) — the system store used by curl and other tools |

!!! warning
    Only trust the root certificate on machines you use for debugging, and remove it when
    you are done: **Remove from trust store** in the same dialog.

### Root certificate actions

| Button | Effect |
|---|---|
| *Trust root certificate…* / *Re-trust* | Add the certificate to the trust store. |
| *Remove from trust store* | Remove it again. |
| *Export…* | Save it as `.crt`/`.pem` (PEM) or `.cer`/`.der` (DER), e.g. for Java or another machine. |
| *Export with key (.p12)…* | Save certificate, chain and private key as a password-protected PKCS#12 file — to use the same CA on a second machine or in [`quena-cli --ca-p12`](reverse-proxy.md). Whoever has the file and the password can read the HTTPS traffic of every device that trusts the certificate. |
| *Import CA…* | [Use an existing CA](#use-an-existing-ca) instead. |
| *Regenerate* | Create a new root certificate. Remove the current one from the trust store first. |

The dialog also shows the certificate's name, validity, SHA-256 fingerprint and file path.

## Use an existing CA

Many companies already run a CA for TLS inspection that every company machine trusts. With
it, Quena's certificates are accepted without trusting anything new — on managed devices,
in containers and in test environments that have the company CA built in.

*Capture → HTTPS Settings… → Import CA…* takes either

- a **PKCS#12 file** (`.p12`, `.pfx`) with its password — also older files with 3DES/RC2
  encryption, as Windows and OpenSSL write them; or
- a **certificate and its private key** as PEM files. The key must not be encrypted
  (`PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`). The certificate file may contain
  the chain up to the root as well.

Quena checks that the certificate is a CA allowed to sign certificates (`CA:TRUE`,
`keyCertSign`), that the key belongs to it and that it is valid now. RSA, ECDSA (P-256,
P-384) and Ed25519 keys work. An **intermediate CA** is fine: the certificates above it are
sent along with every certificate Quena issues, so clients that trust the root accept them.

The previous CA's files stay in the data directory as `quena-root-ca.*.bak-<time>`.
*Regenerate* switches back to a CA of Quena's own.

Headless: `quena-cli reverse --ca-p12 company-ca.p12` with the password in
`QUENA_CA_PASSWORD`.

## Expiring server certificates

Sessions to servers whose certificate expires within 30 days get the flag `x-quena-cert`
(*expires on 2026-11-02 (in 24 days)*); with *Ignore server certificate errors* an
already expired certificate is flagged too (*expired on …*). The number of days is set in
*Capture → HTTPS Settings… → Warn about server certificates expiring within (days)*; `0`
switches the warning off.

- The column **Cert. until** (right-click the column headers) shows the end of validity and
  sorts by it.
- The filter `certdays < 30` lists sessions to servers whose certificate expires within 30
  days (`certdays == 0`: expired or expires within a day).
- *Properties* shows the server certificate's subject, issuer and validity.

Without *Ignore server certificate errors*, an expired server certificate makes the TLS
handshake fail; the session's error says so.

## Choose what is decrypted

In *Capture → HTTPS Settings…* (and *Settings → HTTPS*):

| Option | Meaning |
|---|---|
| *Decrypt traffic from* | *all processes*, *browsers only*, *non-browsers only* or *remote clients only*. |
| *Skip decryption for* | Hosts that stay tunnels, `;`-separated with wildcards, e.g. `*.bank.example; login.live.com`. |
| *Ignore server certificate errors (unsafe)* | Accept invalid server certificates. *Settings → HTTPS* also offers *Ignore certificate errors for* a list of hosts only. |
| *Enable HTTP/2* | Offer HTTP/2 to clients and servers. *Settings → HTTPS → Downgrade to HTTP/1.1 for* lists hosts that should stay on HTTP/1.1. |

Applications that pin certificates, or that bring their own trust store, reject Quena's
certificate. Put their hosts into *Skip decryption for*. To see their HTTPS anyway, record
it as a [packet capture](packet-captures.md) with a TLS key log (`SSLKEYLOGFILE`), if the
application can write one.

## Phones, tablets and VMs

**Capture → Connect Device…** is an assistant for iOS, Android and other devices:

1. Click **Allow remote computers to connect** if remote connections are still off.
2. Pick the network **interface**; the dialog shows the proxy server address and port.
3. Choose the device type and follow the steps. For iOS and Android they are:

=== "iPhone / iPad"

    1. *Settings → Wi-Fi → (i)* of your network → *Configure Proxy → Manual*: enter the
       server and port shown.
    2. Scan the QR code (or open the address in Safari) and download the `.mobileconfig`
       profile.
    3. *Settings → General → VPN & Device Management*: install the Quena profile.
    4. *Settings → General → About → Certificate Trust Settings*: enable full trust for
       “Quena Root CA”.

=== "Android"

    1. *Settings → Network → Wi-Fi →* your network *→ Advanced → Proxy: Manual*: enter the
       host and port shown.
    2. Open the address shown and download the certificate (`.cer`).
    3. *Settings → Security → Encryption & credentials → Install a certificate →
       CA certificate*.

    Since Android 7, apps trust user-installed CAs only if their network security
    configuration allows it. Browsers do; many apps do not.

=== "Other / VM"

    1. Configure the HTTP and HTTPS proxy as the address and port shown.
    2. Download the root certificate from the address shown and add it to the system
       trust store.

The QR code contains `http://<address>:<port>/`, the landing page described below. At the
bottom, the dialog checks the setup as you go: whether Quena is listening, when the first
connection from the device arrives, and whether its HTTPS traffic is decrypted.

### The landing page `http://quena.cert`

Any client that uses Quena as its proxy can open **`http://quena.cert`** (or
`http://<your-ip>:8866/`). The page offers the root certificate in the formats devices
need, with short instructions:

| Link | For |
|---|---|
| `.mobileconfig` profile | iOS, iPadOS, macOS |
| `.cer` (DER) | Android, Windows |
| `.crt` (PEM) | Linux, Firefox, Java … |

It also shows the certificate's SHA-256 fingerprint, so you can compare it with the one in
*HTTPS Settings*.
