//! Platform layer: HTTP(S) transport via WinHTTP on Windows.
//! On non-Windows targets the transport reports ERR_NOT_SUPPORTED so
//! the pure logic (manifest, versions, hashing) and the FFI contract
//! stay testable anywhere; the download pipeline itself is then
//! exercised end-to-end by CI on windows-latest.
//!
//! Every extern block carries #[link(name = "...")] — without it the
//! build fails at LINK time with LNK2019, which check/clippy cannot
//! catch; CI's real build can.

use crate::{CResult, ERR_NOT_SUPPORTED};

pub fn not_supported<T>(what: &str) -> CResult<T> {
    Err((
        ERR_NOT_SUPPORTED,
        format!("{what} is only available on Windows (WinHTTP transport)"),
    ))
}

/// A parsed http(s) URL. Parsing lives here (not in the WinHTTP code)
/// so it is identical on every platform and unit-tested. IPv6 literal
/// hosts are not supported in v0.1.
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub path: String, // path + query, always starts with '/'
}

pub fn parse_url(url: &str) -> CResult<Url> {
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) || url.contains(['\\', '#', '@']) {
        return Err((
            crate::ERR_INVALID_ARG,
            "URL contains forbidden whitespace, credentials, fragment or backslash".into(),
        ));
    }
    let (secure, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err((
            crate::ERR_INVALID_ARG,
            format!("URL must start with http:// or https://: '{url}'"),
        ));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('[') {
        return Err((
            crate::ERR_INVALID_ARG,
            format!("URL has no valid host: '{url}'"),
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            if h.is_empty() || p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err((crate::ERR_INVALID_ARG, format!("bad port in URL: '{url}'")));
            }
            let port: u16 = p
                .parse()
                .map_err(|_| (crate::ERR_INVALID_ARG, format!("bad port in URL: '{url}'")))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    if port == 0 || host.contains(['?', ':']) {
        return Err((crate::ERR_INVALID_ARG, "invalid URL authority".into()));
    }
    if !secure && !matches!(host.as_str(), "localhost" | "127.0.0.1") {
        return Err((
            crate::ERR_INVALID_ARG,
            "remote update URLs require HTTPS; plain HTTP is limited to loopback tests".into(),
        ));
    }
    Ok(Url {
        secure,
        host,
        port,
        path: if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_string()
        },
    })
}

#[cfg(windows)]
pub use win::download_to_file;
#[cfg(windows)]
pub use win::fetch_bytes;
#[cfg(not(windows))]
pub fn fetch_bytes(_url: &str, _max_bytes: usize) -> CResult<Vec<u8>> {
    not_supported("update checks")
}
#[cfg(not(windows))]
pub fn download_to_file(
    _url: &str,
    _dest_path: &str,
    _expected_sha256: Option<&str>,
    _progress: &mut dyn FnMut(u64, u64) -> bool,
) -> CResult<(u64, String)> {
    not_supported("downloads")
}

#[cfg(windows)]
mod win {
    use super::parse_url;
    use crate::sha256::{hex, Sha256};
    use crate::{CResult, ERR_CORRUPT, ERR_NOT_FOUND, ERR_PLATFORM};
    use std::ffi::c_void;
    use std::io::Write;

    type HInternet = *mut c_void;

    #[link(name = "winhttp")]
    extern "system" {
        fn WinHttpOpen(
            agent: *const u16,
            access_type: u32,
            proxy_name: *const u16,
            proxy_bypass: *const u16,
            flags: u32,
        ) -> HInternet;
        fn WinHttpSetTimeouts(
            h: HInternet,
            resolve: i32,
            connect: i32,
            send: i32,
            recv: i32,
        ) -> i32;
        fn WinHttpConnect(h: HInternet, server: *const u16, port: u16, reserved: u32) -> HInternet;
        fn WinHttpOpenRequest(
            connect: HInternet,
            verb: *const u16,
            object: *const u16,
            version: *const u16,
            referrer: *const u16,
            accept_types: *const *const u16,
            flags: u32,
        ) -> HInternet;
        fn WinHttpSetOption(h: HInternet, option: u32, buffer: *const c_void, len: u32) -> i32;
        fn WinHttpSendRequest(
            h: HInternet,
            headers: *const u16,
            headers_len: u32,
            optional: *const c_void,
            optional_len: u32,
            total_len: u32,
            context: usize,
        ) -> i32;
        fn WinHttpReceiveResponse(h: HInternet, reserved: *mut c_void) -> i32;
        fn WinHttpQueryHeaders(
            h: HInternet,
            info_level: u32,
            name: *const u16,
            buffer: *mut c_void,
            len: *mut u32,
            index: *mut u32,
        ) -> i32;
        fn WinHttpQueryDataAvailable(h: HInternet, bytes: *mut u32) -> i32;
        fn WinHttpReadData(h: HInternet, buffer: *mut c_void, want: u32, got: *mut u32) -> i32;
        fn WinHttpCloseHandle(h: HInternet) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
    }

    const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
    const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
    const WINHTTP_OPTION_REDIRECT_POLICY: u32 = 88;
    const WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP: u32 = 2;
    const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    const WINHTTP_QUERY_CONTENT_LENGTH: u32 = 5;
    const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_err(what: &str) -> (i32, String) {
        let code = unsafe { GetLastError() };
        (
            ERR_PLATFORM,
            format!("{what} failed (WinHTTP error {code})"),
        )
    }

    struct Session {
        session: HInternet,
        connect: HInternet,
        request: HInternet,
    }

    impl Drop for Session {
        fn drop(&mut self) {
            unsafe {
                if !self.request.is_null() {
                    WinHttpCloseHandle(self.request);
                }
                if !self.connect.is_null() {
                    WinHttpCloseHandle(self.connect);
                }
                if !self.session.is_null() {
                    WinHttpCloseHandle(self.session);
                }
            }
        }
    }

    fn open_get(url: &str) -> CResult<(Session, u32, u64)> {
        let u = parse_url(url)?;
        let agent = wide("UpdateKit/0.1");
        let session = unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if session.is_null() {
            return Err(last_err("WinHttpOpen"));
        }
        let mut s = Session {
            session,
            connect: std::ptr::null_mut(),
            request: std::ptr::null_mut(),
        };
        unsafe {
            WinHttpSetTimeouts(session, 10_000, 10_000, 30_000, 30_000);
        }
        let host = wide(&u.host);
        s.connect = unsafe { WinHttpConnect(session, host.as_ptr(), u.port, 0) };
        if s.connect.is_null() {
            return Err(last_err("WinHttpConnect"));
        }
        let verb = wide("GET");
        let path = wide(&u.path);
        s.request = unsafe {
            WinHttpOpenRequest(
                s.connect,
                verb.as_ptr(),
                path.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                if u.secure { WINHTTP_FLAG_SECURE } else { 0 },
            )
        };
        if s.request.is_null() {
            return Err(last_err("WinHttpOpenRequest"));
        }
        // Follow redirects (release downloads redirect to storage),
        // but never let an https URL downgrade to http.
        // Loopback HTTP is only for test fixtures and must never redirect remotely.
        let policy: u32 = if u.secure {
            WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP
        } else {
            0
        };
        let configured = unsafe {
            WinHttpSetOption(
                s.request,
                WINHTTP_OPTION_REDIRECT_POLICY,
                &policy as *const u32 as *const c_void,
                4,
            )
        };
        if configured == 0 {
            return Err(last_err("WinHttpSetOption redirect policy"));
        }
        if unsafe { WinHttpSendRequest(s.request, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) }
            == 0
        {
            return Err(last_err("WinHttpSendRequest"));
        }
        if unsafe { WinHttpReceiveResponse(s.request, std::ptr::null_mut()) } == 0 {
            return Err(last_err("WinHttpReceiveResponse"));
        }
        let mut status: u32 = 0;
        let mut len: u32 = 4;
        if unsafe {
            WinHttpQueryHeaders(
                s.request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                std::ptr::null(),
                &mut status as *mut u32 as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_err("WinHttpQueryHeaders(status)"));
        }
        let mut total: u32 = 0;
        let mut len2: u32 = 4;
        let has_total = unsafe {
            WinHttpQueryHeaders(
                s.request,
                WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                std::ptr::null(),
                &mut total as *mut u32 as *mut c_void,
                &mut len2,
                std::ptr::null_mut(),
            )
        } != 0;
        Ok((s, status, if has_total { total as u64 } else { 0 }))
    }

    fn check_status(status: u32, url: &str) -> CResult<()> {
        match status {
            200..=299 => Ok(()),
            404 => Err((ERR_NOT_FOUND, format!("HTTP 404 for '{url}'"))),
            _ => Err((ERR_PLATFORM, format!("HTTP {status} for '{url}'"))),
        }
    }

    fn read_chunk(req: HInternet) -> CResult<Option<Vec<u8>>> {
        let mut avail: u32 = 0;
        if unsafe { WinHttpQueryDataAvailable(req, &mut avail) } == 0 {
            return Err(last_err("WinHttpQueryDataAvailable"));
        }
        if avail == 0 {
            return Ok(None);
        }
        let avail = avail.min(64 * 1024);
        let mut buf = vec![0u8; avail as usize];
        let mut got: u32 = 0;
        if unsafe { WinHttpReadData(req, buf.as_mut_ptr() as *mut c_void, avail, &mut got) } == 0 {
            return Err(last_err("WinHttpReadData"));
        }
        buf.truncate(got as usize);
        Ok(Some(buf))
    }

    pub fn fetch_bytes(url: &str, max_bytes: usize) -> CResult<Vec<u8>> {
        let (s, status, _total) = open_get(url)?;
        check_status(status, url)?;
        let mut out = Vec::new();
        while let Some(chunk) = read_chunk(s.request)? {
            if out.len() + chunk.len() > max_bytes {
                return Err((
                    ERR_PLATFORM,
                    format!("response exceeds {max_bytes} bytes: '{url}'"),
                ));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Stream `url` to `dest_path`, hashing as we go. Returns
    /// (bytes_written, sha256_hex). On a hash mismatch the partial
    /// file is deleted and ERR_CORRUPT is returned — a bad package
    /// must never sit on disk looking usable. `progress` is called
    /// after each chunk with (downloaded, total_or_0); returning
    /// false aborts (file deleted, ERR_PLATFORM "aborted by caller").
    pub fn download_to_file(
        url: &str,
        dest_path: &str,
        expected_sha256: Option<&str>,
        progress: &mut dyn FnMut(u64, u64) -> bool,
    ) -> CResult<(u64, String)> {
        let (s, status, total) = open_get(url)?;
        check_status(status, url)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest_path)
            .map_err(|e| (ERR_PLATFORM, format!("cannot create '{dest_path}': {e}")))?;
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        let result = (|| -> CResult<()> {
            while let Some(chunk) = read_chunk(s.request)? {
                file.write_all(&chunk)
                    .map_err(|e| (ERR_PLATFORM, format!("write to '{dest_path}': {e}")))?;
                hasher.update(&chunk);
                written += chunk.len() as u64;
                if !progress(written, total) {
                    return Err((ERR_PLATFORM, "download aborted by caller".into()));
                }
            }
            Ok(())
        })();
        drop(file);
        if let Err(e) = result {
            return Err(cleanup_error(dest_path, e));
        }
        let digest = hex(&hasher.finalize());
        if let Some(expected) = expected_sha256 {
            if !digest.eq_ignore_ascii_case(expected) {
                return Err(cleanup_error(
                    dest_path,
                    (
                        ERR_CORRUPT,
                        format!(
                            "SHA-256 mismatch for '{url}': expected {}, got {}",
                            expected.to_lowercase(),
                            digest
                        ),
                    ),
                ));
            }
        }
        Ok((written, digest))
    }

    fn cleanup_error(path: &str, mut error: (i32, String)) -> (i32, String) {
        if let Err(cleanup) = std::fs::remove_file(path) {
            if cleanup.kind() != std::io::ErrorKind::NotFound {
                error.1.push_str(&format!(
                    "; incomplete/unverified file could not be removed at '{path}': {cleanup}"
                ));
            }
        }
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("https://example.com/a/b.zip?x=1").unwrap();
        assert!(u.secure);
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/a/b.zip?x=1");

        let u = parse_url("http://localhost:8080/manifest.json").unwrap();
        assert!(!u.secure);
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/manifest.json");

        let u = parse_url("https://example.com").unwrap();
        assert_eq!(u.path, "/");

        assert!(parse_url("ftp://x/y").is_err());
        assert!(parse_url("https://").is_err());
        assert!(parse_url("https://host:notaport/x").is_err());
        assert!(parse_url("https://host:/x").is_err());
        assert!(parse_url("https://[::1]/x").is_err());
    }
}
