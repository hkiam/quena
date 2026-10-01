# quena-cli for CI systems without the GitHub Action (GitLab CI, Jenkins, Azure Pipelines …).
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/hkiam/quena-cli \
#     diagnose capture.har --fail-on critical
# --user makes the reports belong to you; any uid works (no home directory needed).
# Built from the release archives: the build context holds quena-cli-<version>-linux-x64/
# and quena-cli-<version>-linux-arm64/ (see .github/workflows/docker.yml).
FROM debian:bookworm-slim
ARG TARGETARCH
ARG VERSION
LABEL org.opencontainers.image.title="quena-cli" \
      org.opencontainers.image.description="Quena diagnostics for CI: analyse HAR/SAZ captures, compare with a baseline, fail the build on regressions" \
      org.opencontainers.image.source="https://github.com/hkiam/quena" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY quena-cli-${VERSION}-linux-${TARGETARCH}/ /opt/quena-cli/
RUN ln -s /opt/quena-cli/quena-cli /usr/local/bin/quena-cli \
 && useradd --create-home --uid 1000 quena \
 && mkdir -p /work /tmp/quena-cache && chown quena /work && chmod 1777 /tmp/quena-cache
USER quena
# Compiled plugins are cached in /tmp/quena-cache/plugin-cache, inside the container: mount a
# volume there to keep them between runs (-v quena-cache:/tmp/quena-cache). The folder is
# writable for every user of the container (and a new volume Docker fills from it): share
# such a volume only between trusted jobs, the cache holds machine code.
ENV QUENA_CACHE_DIR=/tmp/quena-cache
WORKDIR /work
ENTRYPOINT ["quena-cli"]
CMD ["--help"]
