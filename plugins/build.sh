#!/bin/sh
# Build all plugins as WASM components and stage them in plugins/dist/<name>/.
set -e
# rustup toolchain with the wasm32-wasip2 target (override with QUENA_WASM_TOOLCHAIN).
TC="${QUENA_WASM_TOOLCHAIN:-stable}"
cd "$(dirname "$0")"
for p in */; do
  p=${p%/}
  [ -f "$p/Cargo.toml" ] || continue
  (cd "$p" && RUSTC="$(rustup which --toolchain "$TC" rustc)" "$(rustup which --toolchain "$TC" cargo)" build --quiet --release --target wasm32-wasip2)
  crate=$(grep '^name' "$p/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' | tr - _)
  mkdir -p "dist/$p"
  cp "$p/target/wasm32-wasip2/release/$crate.wasm" "dist/$p/"
  cp "$p/plugin.toml" "dist/$p/"
  echo "built $p ($(wc -c < "dist/$p/$crate.wasm") bytes)"
done
