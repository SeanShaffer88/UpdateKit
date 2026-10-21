//! UpdateKit — self-update behind one clean C ABI.
//!
//! The pipeline an app runs at startup (or on demand):
//!   1. `check_update` — GET a static JSON manifest, compare versions,
//!      get back everything needed to decide (see manifest.rs for the
//!      format). Nothing is downloaded yet.
//!   2. `download` — stream the package to disk over WinHTTP, hashing
//!      as it goes, with progress callbacks; the SHA-256 from the
//!      manifest is verified before the call succeeds, and a bad
//!      package is deleted rather than left on disk.
//!   3. The app applies the staged package however it likes (this is
//!      deliberately where UpdateKit stops in v0.1 — replacing a
//!      running executable is the app's own choreography).
//!
//! Pure logic (JSON, versions, SHA-256, URL parsing) is platform-free
//! and unit-tested; only the transport in `platform` is Windows-only.

pub mod ffi;
pub mod json;
pub mod manifest;
pub mod platform;
pub mod sha256;
pub mod version;

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

// Error codes (mirror include/updatekit.h).
pub const UK_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;
/// Local extension (same pattern as ArchiveKit): the downloaded or
/// on-disk bytes do not match the expected SHA-256.
pub const ERR_CORRUPT: i32 = 7;

/// The crate-wide result: failures carry a stable code + message,
/// rendered at the FFI boundary into the thread-local last error.
pub type CResult<T> = Result<T, (i32, String)>;

/// Manifests are small; anything bigger is not a manifest.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Fetch + evaluate the manifest at `manifest_url` for an app running
/// `current_version`. Returns the check-result JSON (see manifest.rs).
pub fn check_update(current_version: &str, manifest_url: &str) -> CResult<String> {
    version::parse_version(current_version)
        .map_err(|e| (ERR_INVALID_ARG, format!("current version invalid: {e}")))?;
    platform::parse_url(manifest_url)?;
    let bytes = platform::fetch_bytes(manifest_url, MAX_MANIFEST_BYTES)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| (ERR_INVALID_ARG, "manifest is not valid UTF-8".to_string()))?;
    let m = manifest::parse_manifest(&text)?;
    manifest::check_result_json(current_version, &m)
}

/// Verify a file on disk against an expected SHA-256 hex digest.
/// Returns the actual digest on success; ERR_CORRUPT on mismatch.
pub fn verify_file(path: &str, expected_sha256: &str) -> CResult<String> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err((
            ERR_INVALID_ARG,
            "expected SHA-256 must be 64 hex characters".into(),
        ));
    }
    let mut file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            (ERR_NOT_FOUND, format!("file not found: '{path}'"))
        } else {
            (ERR_PLATFORM, format!("cannot open '{path}': {e}"))
        }
    })?;
    let mut hasher = sha256::Sha256::new();
    let mut buf = [0u8; 65536];
    use std::io::Read;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| (ERR_PLATFORM, format!("cannot read '{path}': {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = sha256::hex(&hasher.finalize());
    if digest.eq_ignore_ascii_case(expected_sha256) {
        Ok(digest)
    } else {
        Err((
            ERR_CORRUPT,
            format!(
                "SHA-256 mismatch for '{path}': expected {}, got {}",
                expected_sha256.to_lowercase(),
                digest
            ),
        ))
    }
}

/// Escape a string for inclusion inside JSON double quotes.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_json() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn verify_file_roundtrip_and_tamper() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("uk-verify-{}.bin", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        let path = p.to_str().unwrap();
        // sha256("abc") — standard vector.
        let good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(verify_file(path, good).unwrap(), good);
        let (code, _) = verify_file(path, &"0".repeat(64)).unwrap_err();
        assert_eq!(code, ERR_CORRUPT);
        let (code, _) = verify_file(path, "not-hex").unwrap_err();
        assert_eq!(code, ERR_INVALID_ARG);
        let _ = std::fs::remove_file(&p);
        let (code, _) = verify_file("Z:/definitely/not/here.bin", good).unwrap_err();
        assert_eq!(code, ERR_NOT_FOUND);
    }
}
