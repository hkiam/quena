# Automatic authentication

Intranet servers and corporate proxies often ask for Windows-style authentication. With
**automatic authentication**, Quena answers `401` (server) and `407` (upstream proxy)
challenges itself with your credentials, so tools that cannot authenticate — or that you
don't want to configure — still get through, and you don't log in on every request.

It is **off by default**.

## Turn it on

- *Capture → Enable Automatic Authentication* toggles it quickly.
- *Settings → Authentication* has all options:

| Option | Meaning |
|---|---|
| *Enable Automatic Authentication* | master switch |
| *Only for hosts* | restrict to these hosts, `;`-separated with wildcards, e.g. `*.corp.example.com; sharepoint.corp`. Empty means all hosts. |
| *Also authenticate to the upstream proxy (407)* | answer challenges of the corporate proxy Quena forwards to |
| *Use current OS identity for SSO (Kerberos) when available* | single sign-on with your logged-in identity |
| *Scheme order* | preferred order of schemes, default `negotiate;ntlm;basic` |

## Schemes and single sign-on

| Scheme | macOS | Windows | Linux |
|---|---|---|---|
| Negotiate / Kerberos | SSO with a Kerberos ticket | SSO via SSPI | SSO via GSSAPI with a ticket from `kinit` (needs the Kerberos library) |
| NTLM (NTLMv2) | with stored credentials | SSO via SSPI | with stored credentials |
| Basic | with stored credentials | with stored credentials | with stored credentials |

When the server offers several schemes, Quena picks the first in *Scheme order*. If the
server rejects one (e.g. Negotiate is advertised but only NTLM works), Quena falls back to
the next offered scheme. On Linux without the Kerberos library, Quena falls back to NTLM.

Kerberos needs a host name: for IP addresses and `localhost` Quena skips Negotiate and uses
the next scheme. A step of the Kerberos library (GSSAPI, SSPI) that does not answer within
5 seconds — typically a ticket for a domain whose KDC cannot be reached, e.g. over a VPN
without a route to it — is abandoned; Quena falls back to the next scheme and does not try
that scheme for the host again for 10 minutes. The log says so (`quena::auth`).

## Credentials

Kerberos SSO needs no stored credentials. For NTLM and Basic, add them under
*Settings → Authentication → Credentials*:

1. Enter the **host or realm** (`*` for a default), an optional **domain**, the **user**
   and the **password** (leave the password blank to use SSO for that host).
2. Click **Add / update**.

Passwords go to the operating system's secure store — Keychain on macOS, Credential Manager
on Windows, Secret Service (GNOME Keyring, KWallet) on Linux — never into the settings file.
The list shows only host, user and whether a password is stored; *Remove* deletes an entry.
Without a keyring on Linux, passwords last until Quena quits.

## What you see

- The handshake happens transparently; the client receives the final, authenticated
  response.
- The Auth view of the request and response shows the tokens, decoded by the bundled
  *Kerberos / NTLM* plugin — see [Inspect → Auth view](inspect.md#auth-view).

## Safety

- An authenticated upstream connection is **pinned to one client connection** and never
  shared, so one client can never use another one's identity.
- `Authorization` and `Proxy-Authorization` headers are redacted in logs.
- A handshake that does not succeed after a few rounds returns the original `401`/`407`
  to the client.
