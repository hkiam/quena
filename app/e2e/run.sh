#!/bin/bash
# Run the UI end-to-end tests against a built app (Linux: tauri-driver + WebKitWebDriver).
#   app/e2e/run.sh target/ci/quena
# Needs a display (xvfb-run) and a session bus (dbus-run-session); CI wraps it in both.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
export QUENA_APP="$(realpath "${1:?path to the quena binary}")"
# Isolated data directory: never the user's settings, never the system proxy.
export QUENA_DATA_DIR="$(mktemp -d)"
echo '{"proxy":{"actAsSystemProxy":false,"port":0},"ui":{"layout":{"preset":"quena","presetChosen":true,"stacked":false}}}' > "$QUENA_DATA_DIR/settings.json"
export WEBKIT_DISABLE_DMABUF_RENDERER=1 NO_AT_BRIDGE=1
tauri-driver --port 4444 > "$QUENA_DATA_DIR/tauri-driver.log" 2>&1 &
driver=$!
trap 'kill $driver 2>/dev/null; rm -rf "$QUENA_DATA_DIR"' EXIT
for _ in $(seq 1 50); do curl -s http://127.0.0.1:4444/status >/dev/null && break; sleep 0.2; done
node --test --test-reporter=spec "$here/app.test.mjs"
