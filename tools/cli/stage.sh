#!/bin/bash
# Stage the quena-cli archive folder: the program, the bundled plugins, license files.
#   tools/cli/stage.sh <quena-cli binary> <platform> [out dir]
# e.g. tools/cli/stage.sh target/release/quena-cli linux-x64 → target/cli/quena-cli-0.1.2-linux-x64/
set -eu
cd "$(dirname "$0")/../.."
bin="${1:?quena-cli binary}"
platform="${2:?platform, e.g. linux-x64}"
out="${3:-target/cli}"
version=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"(.*)".*/\1/')
dir="$out/quena-cli-$version-$platform"
rm -rf "$dir"
mkdir -p "$dir/plugins"
cp "$bin" "$dir/"
# The plugins the app bundles (tauri.conf.json resources), not the test plugins.
for p in $(sed -n 's#.*"\.\./\.\./plugins/dist/\([a-z0-9-]*\)".*#\1#p' app/src-tauri/tauri.conf.json); do
  cp -R "plugins/dist/$p" "$dir/plugins/$p"
done
[ -f "$dir/plugins/webdiag/webdiag.wasm" ] || { echo "plugins/dist/webdiag missing: run plugins/build.sh" >&2; exit 1; }
cp LICENSE NOTICE "$dir/"
cat > "$dir/README.txt" <<TXT
quena-cli $version: Quena's diagnostics for CI pipelines.

  quena-cli diagnose capture.har --fail-on critical
  quena-cli diagnose capture.har --baseline main.json --budget requests=+10% -o junit=junit.xml
  quena-cli --help

Keep the plugins folder next to the program.
Manual: https://hkiam.github.io/quena/ci/
TXT
echo "$dir"
