# MDM Doctor

MDM Doctor is a self-hosted, evidence-first workbench for Microsoft Intune and
Windows MDM diagnostic bundles. It reconstructs provisioning sessions,
application attempts, enrollment state, ESP tracking, and collection coverage
without accounts, case history, telemetry, or durable diagnostic storage.

The container is built and tested for both `linux/amd64` (x64) and
`linux/arm64`. The native builder cross-compiles Rust for the requested target,
Docker selects the matching Debian runtime, and the compiled React interface
is architecture-independent.

The application is designed for localhost, VPN, or a protected internal
network. It has deliberately **no authentication layer** and must never be
published directly to the public internet.

## Run with Docker Compose

The recommended host has at least 12 GiB available memory, 8 GiB available for
tmpfs, and encrypted swap or swap disabled.

Published releases are available as one multi-architecture image for x64 and
ARM64:

```sh
docker pull ghcr.io/darkatek7/mdm-doctor:latest
MDM_DOCTOR_IMAGE=ghcr.io/darkatek7/mdm-doctor:latest \
  docker compose up -d --no-build
```

For reproducible deployments, replace `latest` with a version tag or immutable
digest shown on the GitHub package page.

```sh
cp .env.example .env
docker compose up -d --build
```

If an enterprise TLS-inspection root is required only during dependency
download, pass a PEM bundle as a BuildKit secret; it is not copied into an
image layer:

```sh
docker build --secret id=corporate_ca,src=/absolute/corporate-ca.pem \
  -t mdm-doctor:local .
docker compose up -d --no-build
```

For a network that redirects npm downloads to an authentication portal, an
administrator may supply a locally built and tested UI stage containing
`/src/web/dist`, then select that image with `WEB_BUILD_STAGE`. This is intended
only for controlled offline builds; the standard connected build always runs
`npm ci`, type checks, privacy tests, and the production UI build in its own
stage. BuildKit secrets are never copied into an image layer.

Do not disable npm or Cargo TLS verification.

Open `http://127.0.0.1:8080`. Compose publishes loopback only by default. Set
`BIND_ADDRESS=0.0.0.0` only on a trusted LAN or VPN after applying host firewall
rules. Stop the service with `docker compose down`; graceful shutdown purges all
active jobs, while tmpfs disappearance provides a second cleanup boundary.

The optional TLS proxy uses administrator-provided certificates:

```sh
TLS_CERTIFICATE_PATH=/absolute/server.crt \
TLS_PRIVATE_KEY_PATH=/absolute/server.key \
docker compose -f compose.yaml -f compose.tls.yaml up -d --build
```

Review the source-IP restriction example in `deploy/nginx/nginx.conf` before
trusted-LAN use. The TLS override does not make public exposure safe.

## Local development

Requirements are Rust 1.88 or later and Node.js 24 or later.

```sh
cargo test --workspace --all-features --locked
cargo run --release --locked --example scale_benchmark
cd web
npm ci --ignore-scripts
npm run types:generate
npm run typecheck
npm run test
npm run build
cd ..
WORKSPACE_PATH="$(mktemp -d)" STATIC_DIR="$PWD/web/dist" cargo run -- serve
```

Analyze an already extracted folder without modifying it:

```sh
WORKSPACE_PATH="$(mktemp -d)" STATIC_DIR="$PWD/web/dist" \
  cargo run -- serve --import-folder /absolute/path/to/extracted-bundle
```

Only regular files are copied into the transient workspace. Links and special
files are rejected. The one-time capability is delivered only to the UI that
claims the local import.

## Privacy and lifecycle

- Uploads, extracted objects, SQLite/FTS indexes, previews, and report inputs
  exist only in `/run/mdm-doctor/<random-server-id>` on tmpfs.
- The browser keeps at most two 256-bit capability handles in React memory.
  Handles are never placed in URLs, bodies, cookies, browser storage, logs, or
  UI text. Refreshing the page loses access by design.
- Delete, cancellation, fatal analysis errors, timeouts, TTL expiry, export
  failure, and graceful shutdown purge the whole capability-scoped directory.
- Uploaded HTML is never rendered. Raw evidence requires an explicit reveal;
  unredacted exports require confirmation.
- Access logs, application logs, telemetry, crash uploads, persistent metrics,
  cookies, audit history, user data, and backups do not exist.

The default rule pack is `2026.08`. See [ARCHITECTURE.md](ARCHITECTURE.md) and
[SECURITY.md](SECURITY.md) for trust boundaries and operational controls.

## License

Apache-2.0. Dependency licensing and clean-room provenance are documented in
[LICENSES.md](LICENSES.md).
