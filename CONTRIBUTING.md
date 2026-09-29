# Contributing to Quena

Thank you for your interest in Quena! Bug reports, documentation, inspectors, plugins and
platform work are all very welcome.

## Before you start

- **Bugs:** search the [issues](https://github.com/hkiam/quena/issues) first, then open one with
  steps to reproduce, your platform and Quena version. A small `.saz` or `.har` file that shows
  the problem helps a lot — please remove secrets (cookies, tokens) before sharing it.
- **Features:** open an issue or a discussion first for anything bigger than a small fix, so we
  can agree on the approach before you invest time.
- **Security issues:** never in public — see [SECURITY.md](SECURITY.md).

## Development setup

```bash
npm ci --prefix app/ui
rustup target add wasm32-wasip2 && ./plugins/build.sh   # bundled plugins
npm exec --prefix app/ui -- tauri dev                     # run the app
npm exec --prefix app/ui -- tauri build -- --profile local  # optimized exe without the slow release LTO
```

Requirements: Rust 1.95+, Node.js 20.19+ (or 22.12+) and the
[Tauri 2 prerequisites](https://tauri.app/start/prerequisites/) for your platform.

On Linux (Debian/Ubuntu) the system packages are:

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev \
  libxdo-dev patchelf libnss3-tools libsecret-tools
```

`tools/linux/Dockerfile` builds the same environment as the CI job, e.g. to test Linux from a Mac:

```bash
docker build -t quena-linux tools/linux
docker run --rm -v "$PWD":/src -v quena-target:/src/target -w /src quena-linux \
  cargo test --workspace --exclude quena-app
# Desktop integration (GNOME proxy settings, NSS trust) against a real session bus:
docker run --rm -e HOME=/tmp/h -v "$PWD":/src -v quena-target:/src/target -w /src quena-linux \
  dbus-run-session -- cargo test -p quena-platform -- --ignored
```

> **Tip:** while developing, point Quena at a throw-away data directory and keep it off the
> system proxy, so a rebuild never changes your machine's network settings:
>
> ```bash
> mkdir -p /tmp/quena-dev
> echo '{"proxy":{"actAsSystemProxy":false}}' > /tmp/quena-dev/settings.json
> QUENA_DATA_DIR=/tmp/quena-dev npm exec --prefix app/ui -- tauri dev
> ```
>
> Then test with `curl -x http://127.0.0.1:8866 …` (add `--cacert /tmp/quena-dev/quena-root-ca.pem`
> for HTTPS) instead of trusting the certificate system-wide.

## Checks

Please make sure these pass before opening a pull request (CI runs the tests, the UI build and
the license check on macOS and Windows):

```bash
cargo test --workspace --exclude quena-app
cargo clippy --workspace
cargo fmt --all
npm run build --prefix app/ui          # TypeScript typecheck + production build
npm test --prefix app/ui               # UI unit tests (Vitest)
```

## Design principles

Changes are reviewed against the two core principles described in the README and
[`PLAN.md`](PLAN.md):

1. **Bodies can be huge.** Never read a whole body into memory, IPC, React state or the DOM.
   Use streaming or windowed (`offset`, `len`) access and keep memory O(1) in body size.
2. **The UI never waits.** Keep work off the UI thread and off the proxy's forwarding path;
   anything that can take time is a cancellable job.

Also keep in mind:

- **Familiar workflows matter.** Shortcuts, file formats and workflows stay familiar for people
  coming from other debugging proxies; visual design and wording are Quena's own.
- **Secure defaults.** Decryption, remote access and automatic authentication stay opt-in;
  secrets go to the OS secure store, never into settings or logs.
- **Permissive licenses only.** New dependencies must be MIT, Apache-2.0, BSD, ISC, Zlib or
  similar (checked by `cargo deny check licenses`).

## Pull requests

- Keep PRs focused; one topic per PR.
- Add or update tests for behaviour changes.
- Match the style of the surrounding code (comments, naming, idioms).
- Describe *what* changed and *why*; screenshots help for UI changes.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license of this project.
