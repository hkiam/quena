#!/bin/bash
# Run the UI end-to-end tests against a built app through tauri-driver.
#   Linux:   app/e2e/run.sh target/ci/quena        (WebKitWebDriver; needs xvfb-run and
#            dbus-run-session, CI wraps it in both)
#   Windows: EDGEDRIVER=path/to/msedgedriver.exe app/e2e/run.sh target/ci/quena.exe
#            (Git Bash; msedgedriver must match the installed WebView2 runtime)
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
QUENA_APP="$(realpath "${1:?path to the quena binary}")"
# Isolated data directory: never the user's settings, never the system proxy.
QUENA_DATA_DIR="$(mktemp -d)"
driver_args=()
if command -v cygpath >/dev/null; then
  # Windows: the app, node and tauri-driver need native paths.
  QUENA_APP="$(cygpath -w "$QUENA_APP")"
  QUENA_DATA_DIR="$(cygpath -w "$QUENA_DATA_DIR")"
fi
[ -n "${EDGEDRIVER:-}" ] && driver_args+=(--native-driver "$EDGEDRIVER")
export QUENA_APP QUENA_DATA_DIR
settings() {
  # Each suite starts clean: the previous app was killed by the driver, which Quena rightly
  # treats as a crash (it would offer to recover that capture).
  find "$QUENA_DATA_DIR" -mindepth 1 -maxdepth 1 ! -name tauri-driver.log -exec rm -rf {} +
  echo '{"proxy":{"actAsSystemProxy":false,"port":0},"ui":{"layout":{"preset":"quena","stacked":false,"language":"'"$1"'"}}}' > "$QUENA_DATA_DIR/settings.json"
}
settings en
export WEBKIT_DISABLE_DMABUF_RENDERER=1 NO_AT_BRIDGE=1
tauri-driver --port 4444 "${driver_args[@]}" > "$QUENA_DATA_DIR/tauri-driver.log" 2>&1 &
driver=$!
trap 'kill $driver 2>/dev/null; rm -rf "$QUENA_DATA_DIR"' EXIT
for _ in $(seq 1 50); do curl -s http://127.0.0.1:4444/status >/dev/null && break; sleep 0.2; done
if [ -n "${QUENA_SHOTS:-}" ]; then
  # Screenshots for README and manual only (docs/screenshots).
  node --test --test-reporter=spec "$here/screenshots.mjs"
  exit
fi
node --test --test-reporter=spec "$here/app.test.mjs"
# Mocks from sessions: dialog → Mock Rules → the proxy answers from the package.
settings en
node --test --test-reporter=spec "$here/mocks.test.mjs"
# Reverse proxy: an entry from the dialog forwards to its target and records.
settings en
node --test --test-reporter=spec "$here/reverse.test.mjs"
# Rewrite rules: editor with preview, live change, applied to a captured session.
settings en
node --test --test-reporter=spec "$here/rewrite.test.mjs"
# Sanitized export: GDPR preset → HAR without marker values → opened again.
settings en
node --test --test-reporter=spec "$here/sanitize.test.mjs"
# Diagnostics with the real analyzer plugin.
settings en
node --test --test-reporter=spec "$here/diagnostics.test.mjs"
# Bodies in many character encodings.
settings en
node --test --test-reporter=spec "$here/encoding.test.mjs"
# The German UI: longer texts must not break the layout.
settings de
node --test --test-reporter=spec "$here/german.test.mjs"
