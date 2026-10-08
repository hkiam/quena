#!/bin/bash
# Generate the CycloneDX SBOMs (JSON, spec 1.5) of the app and of quena-cli for one platform.
#   tools/sbom/generate.sh <platform> [<rust target>...]
# e.g. tools/sbom/generate.sh macos-universal aarch64-apple-darwin x86_64-apple-darwin
#      → target/sbom/quena-0.1.7-macos-universal.cdx.json, target/sbom/quena-cli-0.1.7-macos-universal.cdx.json
# Without a target: the host's. Several targets add up (the macOS universal build).
# The app: quena-app, the npm packages the UI bundles (no dev dependencies) and the bundled
# plugins; quena-cli: the program and the same plugins. Build-only crates are left out.
# Needs cargo-cyclonedx (cargo install cargo-cyclonedx --locked), npx and python3.
set -eu
platform="${1:?platform, e.g. linux-x64}"
shift
cd "$(dirname "$0")/../.."
version=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"(.*)".*/\1/')
out=target/sbom
parts="$out/parts/$platform"
part=quena-sbom-part   # cargo-cyclonedx writes <crate dir>/$part.json for every crate
cyclonedx_npm="@cyclonedx/cyclonedx-npm@6.0.1"
python=python3
command -v python3 > /dev/null && python3 -c '' 2> /dev/null || python=python   # Windows runners

cleanup() { rm -f crates/*/"$part.json" app/src-tauri/"$part.json" plugins/*/"$part.json"; }
trap cleanup EXIT
rm -rf "$parts"
mkdir -p "$parts"

cdx() { cargo cyclonedx -q --format json --spec-version 1.5 --no-build-deps --override-filename "$part" "$@"; }

# The Rust programs, once per target.
[ $# -gt 0 ] || set -- ""
for t in "$@"; do
  cdx ${t:+--target "$t"}
  suffix=${t:-host}
  mv "app/src-tauri/$part.json" "$parts/quena-app-$suffix.json"
  mv "crates/quena-cli/$part.json" "$parts/quena-cli-$suffix.json"
  cleanup
done

# The plugins the app bundles (tauri.conf.json resources), as in tools/cli/stage.sh.
plugin_args=()
# shellcheck disable=SC2013 # plugin names are single words
for p in $(sed -n 's#.*"\.\./\.\./plugins/dist/\([a-z0-9-]*\)".*#\1#p' app/src-tauri/tauri.conf.json); do
  cdx --manifest-path "plugins/$p/Cargo.toml" --target wasm32-wasip2
  mv "plugins/$p/$part.json" "$parts/plugin-$p.json"
  plugin_args+=(--plugin "$parts/plugin-$p.json")
done
[ ${#plugin_args[@]} -gt 0 ] || { echo "no bundled plugins found in tauri.conf.json" >&2; exit 1; }

# The UI: the npm packages in the bundle, from the lock file (no node_modules needed).
(cd app/ui && npx --yes "$cyclonedx_npm" --omit dev --package-lock-only --spec-version 1.5 \
  --output-reproducible --output-format JSON --output-file "../../$parts/quena-ui.json")

app_parts=("$parts"/quena-app-*.json)
cli_parts=("$parts"/quena-cli-*.json)
"$python" -I tools/sbom/merge.py -o "$out/quena-$version-$platform.cdx.json" \
  --name quena --version "$version" --platform "$platform" \
  --description "Quena desktop app: HTTP(S) debugging proxy and traffic workbench" \
  "${app_parts[@]}" "$parts/quena-ui.json" "${plugin_args[@]}"
"$python" -I tools/sbom/merge.py -o "$out/quena-cli-$version-$platform.cdx.json" \
  --name quena-cli --version "$version" --platform "$platform" \
  --description "quena-cli: diagnostics of HAR/SAZ captures for CI pipelines" \
  "${cli_parts[@]}" "${plugin_args[@]}"
echo "$out/quena-$version-$platform.cdx.json"
echo "$out/quena-cli-$version-$platform.cdx.json"
