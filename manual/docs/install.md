# Install and first start

## Download

Download the package for your platform from the
[Releases](https://github.com/hkiam/quena/releases) page.

| Platform | Packages |
|---|---|
| macOS | `.dmg` — one universal app for Apple Silicon and Intel |
| Windows | installer (`.exe` or `.msi`), or the **portable ZIP** |
| Linux | `.deb` (Debian, Ubuntu), `.rpm` (Fedora, openSUSE), AppImage — for x86_64 and arm64 |

### Packages are not signed yet

The packages are not signed with a paid certificate or notarized yet, so the operating
system asks you to confirm the first start:

- **macOS:** after the first launch attempt, open *System Settings → Privacy & Security*
  and choose *Open Anyway*.
- **Windows:** SmartScreen may warn about an unknown publisher — choose
  *More info → Run anyway*.

### Windows portable (no installation)

Unzip `Quena_<version>_x64-portable.zip` anywhere — a USB stick, a network share,
`C:\Tools` — and start `Quena.exe`. No installation and no admin rights are needed.

Everything Quena stores stays in the `quena-data` folder next to `Quena.exe`: settings,
captured sessions, mock rules, the rules script, the root certificate and the web view's own
data. The folder must therefore be **writable**; from a write-protected stick or a read-only
share Quena says so on start and quits (copy the folder elsewhere first). Only what you
actually use touches the machine:

- *Act as system proxy* points the current user's Windows proxy to Quena and restores it
  when Quena quits (or at the next start after a crash).
- *Trust root certificate* adds Quena's certificate to the current user's certificate
  store. Remove it again under *Capture → HTTPS Settings…* before you leave a machine.
- Passwords saved for automatic authentication go to the Windows Credential Manager of
  the current user; they do not travel with the folder.

The portable edition needs the Microsoft Edge WebView2 Runtime, which Windows 11 and
current Windows 10 include. See [Portable mode](settings.md#portable-mode) for how the
mode is switched on.

### Linux: optional helper tools

On Linux, Quena uses these tools when they are installed (the `.deb` and `.rpm` packages
recommend them):

| Tool | Package | Used for |
|---|---|---|
| `certutil` | libnss3-tools / nss-tools | trusting the root certificate in Chrome and Firefox |
| `pkexec` | polkit | adding the root certificate to the system store (curl, wget, most CLI tools) |
| `secret-tool` | libsecret-tools | saving passwords in GNOME Keyring or KWallet |
| Kerberos library | libgssapi-krb5 | Kerberos single sign-on |

Without a keyring, saved passwords last until Quena quits. Without the Kerberos library,
automatic authentication falls back to NTLM.

## First start

1. **Start Quena.** It opens in the **Quena** layout: session list on the left, request
    above response on the right. *Settings → General → Layout* switches to **Classic**
    (dense list with more columns), and *View → Request Beside Response* puts request and
    response side by side.

2. **Traffic appears.** Quena starts capturing right away and — with
   *Act as system proxy while capturing* (on by default) — registers itself as the system
   proxy. The previous proxy is kept as the upstream and restored when Quena quits. The
   capture switch in the toolbar shows *Capturing*; the status bar shows the listening
   address and a *system proxy* tag.

3. **Browse.** Sessions appear live in the list. Select one to inspect it.

4. **HTTPS content.** Without decryption, HTTPS shows up as tunnels only. Open
   *Capture → HTTPS Settings…*, enable *Decrypt HTTPS traffic* and click
   **Trust root certificate…** — see [HTTPS and devices](https.md).

5. **Command-line tools** work as well, pointed at the proxy explicitly:

    ```bash
    curl -x http://127.0.0.1:8866 https://example.com
    ```

!!! tip "Quick orientation"
    - `F12` starts and stops capturing.
    - `Ctrl/⌘ K` opens the command palette with every command.
    - `Alt Q` jumps to the command field — type `help` there for the syntax.

## Main window

- **Toolbar** — capture switch; Replay, Remove and Resume buttons; stream, decode and
  keep-sessions toggles; process filter; the **command field**; Find, Save, Comment,
  Text Tools and Settings.
- **Session list** — one row per request. See [Session list](sessions.md).
- **Navigator** (optional, left; ▯ in the toolbar or `Ctrl/⌘ Alt N`) — the sessions'
  groups or host/path structure; a click narrows the list. See
  [Session list](sessions.md#navigator).
- **Right pane** — tabs *Inspect*, *Composer*, *Mock Rules*, *Filters*, *Timeline*,
  *Diagnostics*, *Statistics* and *Log*. A dot on *Filters* or *Mock Rules* tells you they
  are active.
- **Status bar** — proxy address and state (*system proxy*, *HTTPS decrypt*), the process
  scope (click to change), the number of visible/total sessions (with a *filtered* tag),
  active breakpoints and paused sessions, *Mock Rules* when active, running background
  jobs, and the disk space used by the capture.

`Ctrl/⌘ +`, `Ctrl/⌘ -` and `Ctrl/⌘ 0` zoom the whole window.

## Build from source

Requirements: [Rust](https://rustup.rs) 1.95+, [Node.js](https://nodejs.org) 20.19+ (or
22.12+), and the [Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your
platform.

```bash
git clone https://github.com/hkiam/quena.git
cd quena
npm ci --prefix app/ui

# Bundled plugins (optional), built as WebAssembly components
rustup target add wasm32-wasip2
./plugins/build.sh

# Run in development mode …
npm exec --prefix app/ui -- tauri dev
# … or build an installable bundle
npm exec --prefix app/ui -- tauri build
```
