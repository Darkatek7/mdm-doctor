# Third-party licenses and provenance

MDM Doctor is a clean-room implementation of the diagnostic concepts described
in its product brief. No source code from CMTrace Open, Analyze-MDMDiagReport,
the Intune M365 Log Dashboard, Endpoint Diagnostics Hub, or proprietary
Microsoft Store software is copied into this repository.

Rust dependencies are resolved by `Cargo.lock`; JavaScript dependencies are
resolved by `web/package-lock.json`. Their exact package names, versions,
repositories, and declared licenses are checked with `cargo deny` and the
frontend license script during CI. Permitted licenses are recorded in
`deny.toml`.

The allowlist includes permissive Apache, MIT, BSD, ISC, Unicode, Zlib,
bzip2, and CC0 terms plus MPL-2.0 for file-level-copyleft HTML parser
dependencies. No MPL-covered source is modified or copied into MDM Doctor.

No RustSec advisory is ignored; every RustSec advisory that matches a
dependency fails CI.

The application source is licensed under Apache-2.0. Direct runtime libraries
used for parsing and serving include Axum (MIT), Tokio (MIT), `evtx` (MIT),
`cab` (MIT), `zip` (MIT), `rusqlite` (MIT), and `printpdf` (MIT). Required
copyright and license files remain available through their source packages and
the generated dependency notices in release artifacts.

No real diagnostic bundle or derived sample content is redistributed.
