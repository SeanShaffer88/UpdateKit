# UpdateKit

Self-update behind one clean C ABI. DLL #14 in the Windows DLL Collection.

UpdateKit gives a Windows app the trustworthy half of auto-updating:
ask a static JSON manifest whether a newer version exists, download
the package with progress reporting, and **verify its SHA-256 before
the download counts as successful** — a package that fails
verification is deleted, never left on disk looking usable. Applying
the staged package (swapping a running executable, restarting) stays
the app's own choreography in v0.1.

Zero Rust dependencies: the version comparator, JSON parser, SHA-256,
and WinHTTP bindings are all in-tree.

## ABI (`include/updatekit.h`, prefix `uk_`)

| Function | Purpose |
|---|---|
| `uk_check_update(current_version, manifest_url)` | Fetch + evaluate a manifest → result JSON (below), or null on failure. |
| `uk_download(url, dest, expected_sha256, progress, ctx)` | Stream to disk, hashing as it goes; verifies the hash when one is given. `UK_OK` on success. |
| `uk_download_json(...)` | Same, returning `{"path","bytes","sha256"}` JSON. |
| `uk_verify_file(path, expected_sha256)` | Verify an on-disk file: `UK_OK` or `UK_ERR_CORRUPT` (7). |
| `uk_compare_versions(a, b, &out)` | -1/0/1 comparison (rules below). |
| `uk_version*`, `uk_last_error*`, `uk_free_string` | Version info, thread-local errors, string disposal. |

The progress callback receives `(downloaded, total)` after each chunk
(total 0 when the server sends no Content-Length, so the app can show
% + ETA when a total exists) and aborts the download by returning
non-zero.

## The manifest

A static JSON file you host anywhere — a web host, a release asset, an
intranet server:

```json
{
  "version": "1.4.0",
  "package_url": "https://example.com/releases/App-1.4.0.zip",
  "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  "size": 12345678,
  "mandatory": false,
  "notes": "Fixes the thing.",
  "min_version": "1.0.0"
}
```

`version`, and (when a package is offered) `package_url` + `sha256`,
are required — UpdateKit **refuses manifests that offer a package
without a hash**. `min_version` makes the update mandatory for anyone
below it. `uk_check_update` answers:

```json
{"update_available":true,"current_version":"1.3.9","latest_version":"1.4.0",
 "mandatory":false,"package_url":"…","sha256":"…","size":12345678,"notes":"…"}
```

## Version comparison

Dotted numeric with optional pre-release suffix: `1.2` == `1.2.0`,
`1.10` > `1.9`, `1.2.0-beta` < `1.2.0`, suffixes compare by semver's
piecewise rules. Invalid strings are rejected, not guessed at.

## Transport & security posture

- WinHTTP (Windows' own stack): system proxy settings honored,
  10s/30s timeouts, redirects followed **except** https→http
  downgrades, which are refused.
- Manifests are capped at 1 MiB; HTTP 404 maps to `UK_ERR_NOT_FOUND`;
  TLS/transport failures surface the WinHTTP error code in the
  message.
- Verification is not optional when a hash exists: downloads verify
  inline, and a mismatch deletes the file and returns
  `UK_ERR_CORRUPT`.

## Verification

- 18 unit tests cover SHA-256 (the FIPS vectors, incl. the
  million-'a' digest), the JSON parser, version rules, manifest
  validation (unverifiable manifests rejected), URL parsing, the FFI
  contract, and file verification incl. tamper detection.
- Gate (WinDevKit `tools/gate.sh`): fmt, clippy on host **and**
  `x86_64-pc-windows-msvc`, full suite — green.
- **Unverified:** the WinHTTP pipeline itself has not run yet. CI's
  labeled e2e step serves a manifest + package from a local HTTP
  server on `windows-latest` and runs check → verified download →
  tamper rejection through the real transport; that run is the
  Windows gate. On non-Windows builds the transport reports
  `UK_ERR_NOT_SUPPORTED` while all pure logic keeps working.

## v0.1 limits

- Check + download + verify only; no apply/restart helper yet.
- One package per manifest (no per-channel/per-arch selection).
- No code-signing check beyond the manifest hash — serve manifests
  over HTTPS (the hash only proves the package matches the manifest).
- No delta updates, no resume of interrupted downloads.

See `ROADMAP.md` for what's next.

## License

MIT © 2026 Sean Shaffer.
