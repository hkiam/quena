# Linux build/test environment for Quena (same packages as the CI job).
#   docker build -t quena-linux tools/linux
#   docker run --rm -v "$PWD":/src -w /src quena-linux cargo test --workspace --exclude quena-app
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates git pkg-config file \
      libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev patchelf \
      libnss3-tools libsecret-tools libkrb5-3 libgssapi-krb5-2 krb5-user \
      dbus dbus-x11 gsettings-desktop-schemas dconf-cli xvfb xauth fonts-dejavu imagemagick x11-apps \
      rpm xz-utils webkit2gtk-driver xdotool \
 && rm -rf /var/lib/apt/lists/*
# Node 22 (Ubuntu's Node 18 is too old for Vite 8).
RUN arch=$(dpkg --print-architecture | sed 's/amd64/x64/') \
 && curl -fsSL https://nodejs.org/dist/v22.20.0/node-v22.20.0-linux-$arch.tar.xz | tar -xJ -C /usr/local --strip-components=1
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.96.0 \
 && rustup target add wasm32-wasip2 \
 && cargo install tauri-driver --locked \
 && chmod -R a+w $RUSTUP_HOME $CARGO_HOME
