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

The packages are not signed with a paid certificate or notarised yet, so the operating
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

### Software bill of materials (SBOM)

Every release lists what Quena is built from as a [CycloneDX](https://cyclonedx.org) SBOM
(JSON): the Rust crates, the npm packages of the user interface and the bundled plugins,
with versions, licences and package URLs. Import it into Dependency-Track, or scan it with
Grype or Trivy, to check a version against known vulnerabilities.

| Where | File |
|---|---|
| Releases page | `quena-<version>-<platform>.cdx.json` (app), `quena-cli-<version>-<platform>.cdx.json` |
| macOS | `Quena.app/Contents/Resources/sbom.cdx.json` |
| Windows | `sbom.cdx.json` next to `Quena.exe` (installed and portable) |
| Linux | `/usr/lib/Quena/sbom.cdx.json` (`.deb`, `.rpm`), inside the AppImage |
| quena-cli | `sbom.cdx.json` in the archive, `/opt/quena-cli/sbom.cdx.json` in the Docker image |

Each SBOM describes one platform: only the crates built for it are listed. The Docker image
also carries an SBOM attestation of the whole image, Debian packages included:
`docker buildx imagetools inspect ghcr.io/hkiam/quena-cli:<version> --format '{{ json .SBOM }}'`.

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
  *Diagnostics*, *Statistics*, *Agents* (see [Agent conversations](agents.md)) and *Log*.
  A dot on *Filters* or *Mock Rules* tells you they are active.
- **Status bar** — proxy address and state (*system proxy*, *HTTPS decrypt*), the process
  scope (click to change), the number of visible/total sessions (with a *filtered* tag),
  active breakpoints and paused sessions, *Mock Rules* when active, running background
  jobs, and the disk space used by the capture.

`Ctrl/⌘ +`, `Ctrl/⌘ -` and `Ctrl/⌘ 0` zoom the whole window.

## quena-cli

`quena-cli` is Quena without a window, a separate download for the command line. It runs
the [diagnostics in CI](ci.md) (`diagnose`, `compare`), compares captures (`diff`),
sanitises them (`sanitize`), turns them into mocks (`mock`), runs `.http` collections
(`http`), records traffic as a [reverse, SOCKS or transparent proxy](reverse-proxy.md#without-a-window-quena-cli-reverse)
(`reverse`), and records [MCP servers that talk over stdio](mcp-traffic.md#servers-that-talk-over-stdio)
for the app (`mcp-tap`). `quena-cli --help` lists the commands.

### Download

| Where | What |
|---|---|
| [Releases](https://github.com/hkiam/quena/releases) | `quena-cli-<version>-macos-universal.tar.gz`, `quena-cli-<version>-windows-x64.zip`, `quena-cli-<version>-linux-x64.tar.gz`, `quena-cli-<version>-linux-arm64.tar.gz` |
| Docker | `ghcr.io/hkiam/quena-cli:<version>` (or `:latest`, the newest release that is not a prerelease), for linux/amd64 and linux/arm64; the entry point is `quena-cli` |
| GitHub Actions | `hkiam/quena/diagnose@<version>` downloads it for you — see [Diagnostics in CI](ci.md#quick-start) |

Unpack the archive and **keep the `plugins` folder next to the program**: the diagnostics
plugin lives there. The packages are not signed yet: on macOS, if the program is refused
after a download in the browser, remove the quarantine flag with
`xattr -dr com.apple.quarantine quena-cli-<version>-macos-universal`.

### Put it on the PATH

So that `quena-cli` works in any terminal, put its folder on the `PATH`, or link the
program into a folder that is on it:

=== "macOS / Linux"

    ```bash
    sudo mv quena-cli-<version>-<platform> /opt/quena-cli
    sudo ln -s /opt/quena-cli/quena-cli /usr/local/bin/quena-cli
    quena-cli --version
    ```

=== "Windows"

    Unpack to `C:\Tools\quena-cli`, then add that folder to the `Path` of your user
    (*Settings → System → About → Advanced system settings → Environment Variables*), or in
    PowerShell:

    ```powershell
    [Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Tools\quena-cli", "User")
    ```

    Open a new terminal afterwards.

### In MCP client configurations

Desktop apps and IDEs that start MCP servers (Claude Desktop, VS Code, Cursor …) often do
not see the `PATH` of your shell. Give the **full path** to the program in their
configuration, e.g. `/opt/quena-cli/quena-cli` or `C:\Tools\quena-cli\quena-cli.exe`, not just
`quena-cli`.

### Data folder

`quena-cli mcp-tap` writes its recordings into the `mcp-tap` folder of Quena's
[data directory](settings.md#data-directory), where the app picks them up. It finds the same
folder as the app when the app uses its normal location. Pass `--data-dir` when the app
does not:

- the app runs in [portable mode](settings.md#portable-mode) — then
  `--data-dir <app folder>/quena-data` (a `quena-cli` placed next to `Quena.exe`, beside
  `quena-data`, finds the folder by itself);
- the app was started with `QUENA_DATA_DIR` set, but the MCP client that starts `quena-cli`
  does not have it — then `--data-dir` with that folder.

```bash
quena-cli mcp-tap --name jira --data-dir /path/to/quena-data -- npx -y jira-mcp
```

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
