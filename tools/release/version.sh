#!/bin/sh
# Show, check or set the Piper version in every place it is declared.
#
#   tools/release/version.sh            print the versions found (non-zero exit if they differ)
#   tools/release/version.sh 0.0.2      set them all to 0.0.2
set -e
cd "$(dirname "$0")/../.."
FILES_TOML="Cargo.toml plugins/fast-infoset/Cargo.toml plugins/fast-infoset/plugin.toml"
FILES_JSON="app/src-tauri/tauri.conf.json app/ui/package.json"

if [ -n "$1" ]; then
  echo "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo "not a semver version: $1" >&2; exit 2; }
  # First match only: the package version, not dependency versions.
  for f in $FILES_TOML; do perl -0pi -e "s/^version = \"[^\"]*\"/version = \"$1\"/m" "$f"; done
  for f in $FILES_JSON; do perl -0pi -e "s/\"version\": \"[^\"]*\"/\"version\": \"$1\"/" "$f"; done
  (cd app/ui && npm install --package-lock-only --ignore-scripts >/dev/null)
fi

found=""
for f in $FILES_TOML; do v=$(grep -m1 -E '^version = ' "$f" | sed -E 's/.*"(.*)".*/\1/'); echo "$v  $f"; found="$found $v"; done
for f in $FILES_JSON app/ui/package-lock.json; do v=$(grep -m1 '"version"' "$f" | sed -E 's/.*"version": "([^"]*)".*/\1/'); echo "$v  $f"; found="$found $v"; done
n=$(echo $found | tr ' ' '\n' | sort -u | wc -l | tr -d ' ')
[ "$n" = 1 ] || { echo "version mismatch" >&2; exit 1; }
