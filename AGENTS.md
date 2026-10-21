# UpdateKit — agent notes

- Zero Rust dependencies is a design rule. SHA-256 (src/sha256.rs),
  the JSON parser (src/json.rs), and the WinHTTP bindings
  (src/platform.rs) are hand-written on purpose; correctness anchors
  are the FIPS SHA-256 vectors and the parser/version test suites —
  keep those tests intact when refactoring.
- Security invariants, do not weaken:
  - A manifest offering package_url without sha256 is REJECTED.
  - A download whose hash mismatches is DELETED and returns
    ERR_CORRUPT (7); never leave a failed package on disk.
  - Redirects never downgrade https → http (WinHTTP redirect policy
    is set on every request).
  - Manifest size cap 1 MiB.
- ERR_CORRUPT = 7 is a deliberate local extension of the shared 0–6
  codes (ArchiveKit precedent); header and lib.rs must stay in sync.
- The WinHTTP code cannot be exercised on this Linux host: the e2e
  (tests/e2e.rs, local HTTP server, UK_E2E=1) runs only on Windows CI
  and is the transport's real gate. Do not claim download behavior is
  verified from the host gate — the gate proves the logic around the
  transport, CI proves the transport.
- Gate: WinDevKit tools/gate.sh (fmt + clippy BOTH targets + full
  tests). Hand-declared externs carry #[link(name = "...")] — winhttp
  and kernel32 here; LNK2019 only shows in CI's real link.
- Progress-callback contract: total may be 0 (no Content-Length);
  callback returning non-zero aborts and deletes the partial file.
  ETA is the caller's math, not ours.
