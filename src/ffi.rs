//! C ABI surface — everything declared in include/updatekit.h.
//! Conventions (house standard):
//! - `*mut c_char` results are caller-owned; free with `uk_free_string`.
//! - Failures return null / an ERR_* code + a thread-local last-error message.
//! - Nothing unwinds across the FFI boundary (catch_unwind everywhere;
//!   release profile also sets panic = "abort").

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{
    check_update, json_escape, verify_file, ERR_INTERNAL, ERR_INVALID_ARG, UK_OK, VERSION_MAJOR,
    VERSION_MINOR, VERSION_PATCH,
};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((0, CString::new("").unwrap()));
}

pub fn set_error(code: i32, msg: &str) {
    // Messages must never contain NUL (they cross into C strings);
    // replace instead of failing the whole error report.
    let cleaned: String = msg
        .chars()
        .map(|c| if c == '\0' { ' ' } else { c })
        .collect();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(cleaned).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(UK_OK, "");
}

fn guard<T, F: FnOnce() -> T>(f: F) -> Result<T, (i32, String)> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => Ok(v),
        Err(_) => Err((ERR_INTERNAL, "internal panic caught at FFI boundary".into())),
    }
}

fn req_str(p: *const c_char, name: &str) -> Result<String, (i32, String)> {
    if p.is_null() {
        return Err((ERR_INVALID_ARG, format!("{name} must not be null")));
    }
    let s = unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| (ERR_INVALID_ARG, format!("{name} must be valid UTF-8")))?;
    if s.is_empty() {
        return Err((ERR_INVALID_ARG, format!("{name} must not be empty")));
    }
    Ok(s.to_string())
}

fn opt_str(p: *const c_char) -> Result<Option<String>, (i32, String)> {
    if p.is_null() {
        return Ok(None);
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().map_err(|_| {
        (
            ERR_INVALID_ARG,
            "string argument must be valid UTF-8".to_string(),
        )
    })?;
    Ok(Some(s.to_string()))
}

fn out_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            set_error(ERR_INTERNAL, "result contained a NUL byte");
            std::ptr::null_mut()
        }
    }
}

/// Progress callback for uk_download / uk_download_json.
/// Called after each chunk with bytes downloaded so far and the
/// total size (0 when the server sent no Content-Length). Return 0
/// to continue, non-zero to abort the download.
pub type UkProgressFn = extern "C" fn(ctx: *mut c_void, downloaded: u64, total: u64) -> c_int;

#[no_mangle]
pub extern "C" fn uk_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.1.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn uk_version_major() -> c_int {
    VERSION_MAJOR as c_int
}

#[no_mangle]
pub extern "C" fn uk_version_minor() -> c_int {
    VERSION_MINOR as c_int
}

#[no_mangle]
pub extern "C" fn uk_version_patch() -> c_int {
    VERSION_PATCH as c_int
}

#[no_mangle]
pub extern "C" fn uk_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn uk_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0) as c_int
}

/// # Safety (caller contract): `p` is null or a string this library
/// returned and has not been freed yet. Documented in the header.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn uk_free_string(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

/// Compare two version strings. On UK_OK, *out_result is -1, 0 or 1
/// (a < b, a == b, a > b) per the rules in version.rs / the README.
/// out_result is null-checked before the single write.
/// # Safety (caller contract): out_result points to writable memory.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn uk_compare_versions(
    a: *const c_char,
    b: *const c_char,
    out_result: *mut c_int,
) -> c_int {
    let run = guard(|| {
        if out_result.is_null() {
            return Err((ERR_INVALID_ARG, "out_result must not be null".into()));
        }
        let a = req_str(a, "a")?;
        let b = req_str(b, "b")?;
        let va = crate::version::parse_version(&a)
            .map_err(|e| (ERR_INVALID_ARG, format!("version a invalid: {e}")))?;
        let vb = crate::version::parse_version(&b)
            .map_err(|e| (ERR_INVALID_ARG, format!("version b invalid: {e}")))?;
        let ord = crate::version::compare_versions(&va, &vb);
        unsafe {
            *out_result = ord as c_int;
        }
        Ok(())
    });
    finish(run)
}

/// Fetch the manifest at `manifest_url`, evaluate it for
/// `current_version`, and return the result JSON (caller-owned), or
/// null on failure. See the README for the manifest format and the
/// result schema.
#[no_mangle]
pub extern "C" fn uk_check_update(
    current_version: *const c_char,
    manifest_url: *const c_char,
) -> *mut c_char {
    let run = guard(|| {
        let cur = req_str(current_version, "current_version")?;
        let url = req_str(manifest_url, "manifest_url")?;
        check_update(&cur, &url)
    });
    match run {
        Ok(Ok(json)) => {
            clear_error();
            out_string(json)
        }
        Ok(Err((code, msg))) => {
            set_error(code, &msg);
            std::ptr::null_mut()
        }
        Err((code, msg)) => {
            set_error(code, &msg);
            std::ptr::null_mut()
        }
    }
}

fn do_download(
    url: *const c_char,
    dest_path: *const c_char,
    expected_sha256: *const c_char,
    progress: Option<UkProgressFn>,
    ctx: *mut c_void,
) -> Result<(u64, String), (i32, String)> {
    let url = req_str(url, "url")?;
    let dest = req_str(dest_path, "dest_path")?;
    let expected = opt_str(expected_sha256)?;
    if let Some(h) = &expected {
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err((
                ERR_INVALID_ARG,
                "expected_sha256 must be 64 hex characters".into(),
            ));
        }
    }
    crate::platform::parse_url(&url)?;
    let mut cb = |downloaded: u64, total: u64| -> bool {
        match progress {
            Some(f) => f(ctx, downloaded, total) == 0,
            None => true,
        }
    };
    crate::platform::download_to_file(&url, &dest, expected.as_deref(), &mut cb)
}

/// Download `url` to `dest_path`, verifying `expected_sha256` when
/// non-null. Returns UK_OK on success (file on disk, hash verified);
/// on failure the error code + message are set and any partial/bad
/// file is removed.
#[no_mangle]
pub extern "C" fn uk_download(
    url: *const c_char,
    dest_path: *const c_char,
    expected_sha256: *const c_char,
    progress: Option<UkProgressFn>,
    ctx: *mut c_void,
) -> c_int {
    let run = guard(|| do_download(url, dest_path, expected_sha256, progress, ctx).map(|_| ()));
    finish(run)
}

/// Like uk_download, but returns a caller-owned JSON result:
/// {"path":"…","bytes":N,"sha256":"…"} — or null on failure.
#[no_mangle]
pub extern "C" fn uk_download_json(
    url: *const c_char,
    dest_path: *const c_char,
    expected_sha256: *const c_char,
    progress: Option<UkProgressFn>,
    ctx: *mut c_void,
) -> *mut c_char {
    let run = guard(|| do_download(url, dest_path, expected_sha256, progress, ctx));
    match run {
        Ok(Ok((bytes, digest))) => {
            clear_error();
            let dest = opt_str(dest_path).unwrap_or(None).unwrap_or_default();
            out_string(format!(
                "{{\"path\":\"{}\",\"bytes\":{},\"sha256\":\"{}\"}}",
                json_escape(&dest),
                bytes,
                digest
            ))
        }
        Ok(Err((code, msg))) | Err((code, msg)) => {
            set_error(code, &msg);
            std::ptr::null_mut()
        }
    }
}

/// Verify the file at `path` against an expected SHA-256 hex digest.
/// UK_OK when it matches; UK_ERR_CORRUPT (7) when it does not.
#[no_mangle]
pub extern "C" fn uk_verify_file(path: *const c_char, expected_sha256: *const c_char) -> c_int {
    let run = guard(|| {
        let path = req_str(path, "path")?;
        let expected = req_str(expected_sha256, "expected_sha256")?;
        verify_file(&path, &expected).map(|_| ())
    });
    finish(run)
}

fn finish(run: Result<Result<(), (i32, String)>, (i32, String)>) -> c_int {
    match run {
        Ok(Ok(())) => {
            clear_error();
            UK_OK
        }
        Ok(Err((code, msg))) | Err((code, msg)) => {
            set_error(code, &msg);
            code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn compare_versions_ffi() {
        let mut out: c_int = 99;
        assert_eq!(
            uk_compare_versions(cs("1.10").as_ptr(), cs("1.9").as_ptr(), &mut out),
            UK_OK
        );
        assert_eq!(out, 1);
        assert_eq!(
            uk_compare_versions(cs("1.2").as_ptr(), cs("1.2.0").as_ptr(), &mut out),
            UK_OK
        );
        assert_eq!(out, 0);
        assert_eq!(
            uk_compare_versions(cs("bad").as_ptr(), cs("1.0").as_ptr(), &mut out),
            ERR_INVALID_ARG
        );
        assert_eq!(uk_last_error_code(), ERR_INVALID_ARG);
        assert_eq!(
            uk_compare_versions(std::ptr::null(), cs("1.0").as_ptr(), &mut out),
            ERR_INVALID_ARG
        );
    }

    #[test]
    fn verify_file_ffi() {
        let p = std::env::temp_dir().join(format!("uk-ffi-{}.bin", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        let path = cs(p.to_str().unwrap());
        let good = cs("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(uk_verify_file(path.as_ptr(), good.as_ptr()), UK_OK);
        let bad = cs(&"f".repeat(64));
        assert_eq!(
            uk_verify_file(path.as_ptr(), bad.as_ptr()),
            crate::ERR_CORRUPT
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn network_calls_are_not_supported_off_windows() {
        #[cfg(not(windows))]
        {
            let j = uk_check_update(
                cs("1.0.0").as_ptr(),
                cs("https://example.com/m.json").as_ptr(),
            );
            assert!(j.is_null());
            assert_eq!(uk_last_error_code(), crate::ERR_NOT_SUPPORTED);
            assert_eq!(
                uk_download(
                    cs("https://example.com/f.zip").as_ptr(),
                    cs("out.zip").as_ptr(),
                    std::ptr::null(),
                    None,
                    std::ptr::null_mut()
                ),
                crate::ERR_NOT_SUPPORTED
            );
        }
    }
}
