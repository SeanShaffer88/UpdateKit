# Update trust and input contract — October 21–22, 2026

A matching SHA-256 proves that a package matches the supplied digest. **It does not authenticate the publisher when the digest and package are controlled by the same attacker.** A manifest with a package URL still requires a digest. The raw download API permits a null digest for explicit transport-only use; consumers must pass a trusted digest before treating a package as verified. UpdateKit stages files; it does not install or execute them.

## Transport and freshness

Remote URLs now require HTTPS. Plain HTTP is accepted only for exact `localhost`/`127.0.0.1` fixtures, with redirects disabled. Credentials, whitespace/control characters, fragments, backslashes, ambiguous authority and port zero are refused. HTTPS requests explicitly set WinHTTP's no-HTTPS-to-HTTP redirect policy and stop if setting that option fails. HTTPS redirects can change hosts; application allowlists and publisher trust are still the host's responsibility. Normal Windows certificate validation remains enabled; no TLS/security bypass was introduced.

The caller must control the manifest origin, validate the release channel and architecture, and decide whether signed metadata or detached package signatures are required. Persistent high-watermark versions, expiry, key rotation and replay protection are **not implemented** by this stateless library. Older/equal offered versions never produce update_available or mandatory=true against the supplied installed version, but replay of an obsolete version still newer than the installed build requires application policy. A checksum and HTTPS do not replace that policy.

## Bounded input and file behavior

JSON is limited to 1 MiB and 64 nested value levels. Duplicate keys and malformed/non-finite numbers are rejected. Package URLs are validated while parsing the manifest. WinHTTP reads allocate at most 64 KiB per chunk. Destination files must be new: existing files and final-path links are not truncated. Cancellation and hash mismatch attempt to remove only this newly created output; cleanup failure is explicitly reported with its path instead of falsely claiming deletion. Parent-directory races, disk durability and a total download-byte/time budget require caller/environment controls; manifest size is advisory metadata, not an enforced package length.

These refusals are intentional behavior changes under the existing ABI. Applications previously using remote cleartext HTTP or overwriting destinations must use HTTPS and a fresh staging filename. Release panic strategy is unwind so the FFI guard can contain unwinding panics; invalid pointers and process aborts remain outside the contract.

## Evidence and limits

Windows 11 Home build 26300 x64: 21 Debug and 21 Release tests passed (the opt-in transport test is listed as ignored in those suites). The transport test was then explicitly run with UK_E2E=1 and passed through real WinHTTP against a loopback server: update check, download, digest verification, tamper rejection, existing-destination preservation and callback cancellation/partial cleanup. Strict host/Windows lint/check and Release DLL build passed. Tests cover excessive nesting, duplicate keys, malformed numbers, URL policy and downgrade/replay comparisons.

The fixture uses local HTTP, not a TLS server. A real TLS redirect downgrade/certificate-error matrix, forced cleanup-denial test, coverage-guided fuzzing, sanitizer instrumentation and a complete security audit were not performed. Source policy is anchored to [Microsoft's WinHTTP redirect-option documentation](https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags#winhttp_option_redirect_policy). Never label this library an authenticated automatic updater without the application's trust and freshness controls.
