# Plugins

Plugins add decoders and inspectors to Quena. They are **WebAssembly components**
(WASI Preview 2) and run sandboxed: no file-system, network or environment access, with
memory and time limits. They stream their input and output, so they are safe to run on
untrusted, huge payloads.

## Kinds of plugins

| Kind | What it does | Where it shows up |
|---|---|---|
| **Decoder** | turns a body of certain content types (or file extensions) into text, XML or JSON | as an extra view in the request or response card, named by the plugin |
| **Header inspector** | explains the value of certain headers | in the *Auth* view (and wherever the header is recognised) |

## Bundled plugins

| Plugin | Kind | Handles |
|---|---|---|
| **Fast Infoset** | decoder | `application/fastinfoset`, `application/soap+fastinfoset`, `application/x-fastinfoset` (`.fi`, `.finf`): binary XML decoded to XML. The SOAP and Atom/OData views work on its output. |
| **Kerberos / NTLM** | header inspector | `Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, `Proxy-Authenticate`: SPNEGO, Kerberos AP-REQ/AP-REP/KRB-ERROR and NTLM Type 1–3 tokens; flags Negotiate that fell back to NTLM. |
| **JWT** | header inspector | JSON Web Tokens in authorization headers (Bearer, DPoP), `Cookie`, `Set-Cookie` and common token headers: header, claims, dates and expiry. Signatures are not verified. |
| **GraphQL** | decoder | `application/graphql` and GraphQL JSON requests and responses: the operation with the query pretty-printed, errors first in responses. |

## Managing plugins

**Tools → Plugins…** lists the installed plugins with name, ID, version, status and what they
apply to (content types, or headers for header inspectors).

- The checkbox enables or disables a plugin.
- **Rescan** looks for new or changed plugins.
- **Open plugin folder** opens the folder for your own plugins.

## Installing a plugin

1. Click **Open plugin folder** (the `plugins` folder in the
   [data directory](settings.md#data-directory)).
2. Copy the plugin's folder into it — a folder with a `plugin.toml` and the `.wasm` file.
3. Click **Rescan**.

A `plugin.toml` looks like this:

```toml
id = "io.github.hkiam.fast-infoset"
name = "Fast Infoset"
version = "0.1.1"
api_version = "1"
wasm = "fast_infoset.wasm"
description = "Decodes Fast Infoset (binary XML, e.g. SOAP/FI) into XML."

[decoder]
mime_types = ["application/fastinfoset", "application/soap+fastinfoset", "application/x-fastinfoset"]
extensions = ["fi", "finf"]
```

A header inspector has a `[header_inspector]` section with `headers = [ … ]` instead.

Quena looks for plugins in the user plugin folder and in the bundled plugins (in the app's
resources, or in a `plugins` folder next to the executable of a portable installation).
Compiled plugins are cached in `plugin-cache` in the data directory, so later starts are
fast.

## Writing plugins

The plugin API is defined in
[`wit/plugin.wit`](https://github.com/hkiam/quena/blob/main/wit/plugin.wit). The bundled
plugins in [`plugins/`](https://github.com/hkiam/quena/tree/main/plugins) are complete
examples; `./plugins/build.sh` builds them (needs the Rust target `wasm32-wasip2`). The
plugin API may still change while Quena is at version `0.x`.
