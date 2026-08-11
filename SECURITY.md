# Security and deployment policy

MDM Doctor processes hostile archives containing highly sensitive endpoint
diagnostics. Run it only on an administrator-controlled localhost, VPN, or
segmented internal network. The no-login design is a privacy boundary, not a
public authentication mechanism.

## Required controls

- Keep the default loopback publication unless a trusted-LAN exception is
  deliberate. Apply a host firewall and preferably the TLS/source-IP proxy.
- Keep the root filesystem read-only, all capabilities dropped,
  `no-new-privileges`, core dumps disabled, and `/run/mdm-doctor` on tmpfs.
- Provision at least 12 GiB container memory for the default 8 GiB tmpfs; use
  encrypted swap or disable swap to avoid diagnostic remnants on disk.
- Do not add host volumes for the workspace, upload, indexes, exports, or logs.
- Do not enable reverse-proxy buffering, access logging, crash collection,
  telemetry, or persistent metrics.
- Do not place capability headers in tickets, screenshots, shell history,
  browser storage, URLs, or monitoring systems.

## Archive boundary

Every member path is canonicalized and validated before any file is created.
Extraction is manual and subject to per-file, total-size, compression-ratio,
file-count, and nesting limits. Absolute, drive, UNC, traversal, encoded or
mixed separator, normalized collision, link, device, socket, and FIFO entries
are rejected. Objects use hashes for storage names; database paths are resolved
against the capability directory before reads.

High-ratio ETL is the only non-extraction path: because ETL has no enabled Linux
parser, such a member remains quarantined inside its parent archive. Its bounded
compressed bytes are hashed for provenance, it cannot be previewed or downloaded
as a materialized artifact, and its declared size still participates in global
admission limits. All supported source types remain subject to the 100:1
per-entry extraction limit.

## Reporting vulnerabilities

Do not attach real diagnostic archives, capability handles, or endpoint
identifiers to a public issue. Report a minimal synthetic reproducer privately
to the deployment owner. Immediately purge any active affected job and rotate
TLS material if exposure is suspected.
