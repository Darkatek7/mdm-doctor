# syntax=docker/dockerfile:1.7
ARG WEB_BUILD_STAGE=web-build
FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=secret,id=corporate_ca,required=false,mode=0444 \
    if [ -s /run/secrets/corporate_ca ]; then \
      NODE_EXTRA_CA_CERTS=/run/secrets/corporate_ca npm ci --prefer-offline --ignore-scripts; \
    else \
      npm ci --prefer-offline --ignore-scripts; \
    fi
COPY web/ ./
COPY openapi.json /src/openapi.json
RUN npm run types:generate && npm run typecheck && npm run test && npm run build

FROM ${WEB_BUILD_STAGE} AS selected-web-build

FROM --platform=$BUILDPLATFORM rust:1.97-bookworm AS rust-build
ARG BUILDARCH
ARG TARGETARCH
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml backend/Cargo.toml
COPY backend/ backend/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=secret,id=corporate_ca,required=false,mode=0444 \
    case "$TARGETARCH" in \
      amd64) rust_target=x86_64-unknown-linux-gnu; cross_package=gcc-x86-64-linux-gnu; cross_cc=x86_64-linux-gnu-gcc ;; \
      arm64) rust_target=aarch64-unknown-linux-gnu; cross_package=gcc-aarch64-linux-gnu; cross_cc=aarch64-linux-gnu-gcc ;; \
      *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 64 ;; \
    esac && \
    if [ "$BUILDARCH" = "$TARGETARCH" ]; then \
      target_cc=cc; \
    else \
      sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && \
      if [ -s /run/secrets/corporate_ca ]; then \
        apt_ca="-o Acquire::https::CaInfo=/run/secrets/corporate_ca"; \
      else \
        apt_ca=; \
      fi && \
      apt-get $apt_ca update && \
      apt-get $apt_ca install --yes --no-install-recommends "$cross_package" && \
      target_cc="$cross_cc"; \
    fi && \
    rustup target add "$rust_target" && \
    if [ "$TARGETARCH" = amd64 ]; then \
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$target_cc" \
        CC_x86_64_unknown_linux_gnu="$target_cc"; \
    else \
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$target_cc" \
        CC_aarch64_unknown_linux_gnu="$target_cc"; \
    fi && \
    if [ -s /run/secrets/corporate_ca ]; then \
      export CARGO_HTTP_CAINFO=/run/secrets/corporate_ca SSL_CERT_FILE=/run/secrets/corporate_ca; \
    fi && \
    cargo build --locked --release --bin mdm-doctor --target "$rust_target" && \
    cp "target/$rust_target/release/mdm-doctor" /mdm-doctor

FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.title="MDM Doctor" \
      org.opencontainers.image.description="Transient Microsoft Intune and MDM diagnostics workbench" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/Darkatek7/mdm-doctor"
RUN groupadd --gid 10001 mdm-doctor && \
    useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mdm-doctor && \
    mkdir -p /app/static /run/mdm-doctor && \
    chown -R 10001:10001 /run/mdm-doctor
COPY --from=rust-build --chown=0:0 /mdm-doctor /usr/local/bin/mdm-doctor
COPY --from=selected-web-build --chown=0:0 /src/web/dist/ /app/static/
USER 10001:10001
ENV BIND_ADDRESS=0.0.0.0 PORT=8080 WORKSPACE_PATH=/run/mdm-doctor STATIC_DIR=/app/static
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mdm-doctor"]
CMD ["serve"]
