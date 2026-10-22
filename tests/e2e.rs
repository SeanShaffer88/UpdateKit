//! End-to-end proof (Windows only): a tiny std-only HTTP server on
//! 127.0.0.1 serves a manifest + package; the real FFI then runs the
//! full pipeline — check → download (hash-verified) → tamper
//! rejection → on-disk verify — through the actual WinHTTP transport.
//! Ignored by default; CI runs it with UK_E2E=1.
//! On non-Windows this test does nothing (transport is Windows-only).

#![cfg(windows)]

use std::ffi::CString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::raw::{c_char, c_int, c_void};

use updatekit::ffi::{uk_check_update, uk_download, uk_last_error_code, uk_verify_file};
use updatekit::sha256::sha256_hex;
use updatekit::{ERR_CORRUPT, ERR_NOT_FOUND, UK_OK};

const PKG: &[u8] = b"PK\x03\x04 fake UpdateKit e2e package bytes 0123456789abcdef";

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string result");
    let s = unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned();
    updatekit::ffi::uk_free_string(p);
    s
}

static PROGRESS_CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static LAST_DOWNLOADED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
extern "C" fn progress(_ctx: *mut c_void, downloaded: u64, _total: u64) -> c_int {
    use std::sync::atomic::Ordering;
    PROGRESS_CALLS.fetch_add(1, Ordering::SeqCst);
    LAST_DOWNLOADED.store(downloaded, Ordering::SeqCst);
    0
}

fn serve_once(listener: &TcpListener, pkg_hash: &str) {
    // Serve until killed: manifest + package routes, 404 otherwise.
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
        let (status, ctype, body): (&str, &str, Vec<u8>) = if path == "/manifest.json" {
            let manifest = format!(
                "{{\"version\":\"9.9.9\",\"package_url\":\"http://127.0.0.1:{}/pkg.bin\",\"sha256\":\"{}\",\"size\":{},\"notes\":\"e2e\"}}",
                listener.local_addr().unwrap().port(),
                pkg_hash,
                PKG.len()
            );
            ("200 OK", "application/json", manifest.into_bytes())
        } else if path == "/pkg.bin" {
            ("200 OK", "application/octet-stream", PKG.to_vec())
        } else {
            ("404 Not Found", "text/plain", b"nope".to_vec())
        };
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    }
}

#[test]
#[ignore = "needs the WinHTTP transport: UK_E2E=1 on Windows"]
fn full_update_pipeline() {
    if std::env::var("UK_E2E").ok().as_deref() != Some("1") {
        eprintln!("UK_E2E not set — skipping");
        return;
    }
    let pkg_hash = sha256_hex(PKG);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hash_for_server = pkg_hash.clone();
    std::thread::spawn(move || serve_once(&listener, &hash_for_server));

    let base = format!("http://127.0.0.1:{port}");
    let manifest_url = format!("{base}/manifest.json");

    // 1. Check: 9.9.9 is newer than 1.0.0.
    let j = take(uk_check_update(
        cs("1.0.0").as_ptr(),
        cs(&manifest_url).as_ptr(),
    ));
    println!("check result: {j}");
    assert!(j.contains("\"update_available\":true"), "{j}");
    assert!(j.contains("\"latest_version\":\"9.9.9\""), "{j}");
    assert!(j.contains(&pkg_hash), "{j}");
    // And not newer than itself.
    let j2 = take(uk_check_update(
        cs("9.9.9").as_ptr(),
        cs(&manifest_url).as_ptr(),
    ));
    assert!(j2.contains("\"update_available\":false"), "{j2}");

    // 2. Missing manifest → NOT_FOUND.
    let missing = uk_check_update(
        cs("1.0.0").as_ptr(),
        cs(&format!("{base}/nope.json")).as_ptr(),
    );
    assert!(missing.is_null());
    assert_eq!(uk_last_error_code(), ERR_NOT_FOUND);

    // 3. Download with the correct hash + progress callback.
    let dir = std::env::temp_dir().join(format!("uk-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("pkg.bin");
    let rc = uk_download(
        cs(&format!("{base}/pkg.bin")).as_ptr(),
        cs(dest.to_str().unwrap()).as_ptr(),
        cs(&pkg_hash).as_ptr(),
        Some(progress),
        std::ptr::null_mut(),
    );
    assert_eq!(rc, UK_OK, "download failed with code {rc}");
    assert_eq!(std::fs::read(&dest).unwrap(), PKG);
    {
        use std::sync::atomic::Ordering;
        assert!(
            PROGRESS_CALLS.load(Ordering::SeqCst) >= 1,
            "progress callback never fired"
        );
        assert_eq!(LAST_DOWNLOADED.load(Ordering::SeqCst), PKG.len() as u64);
    }

    // 4. Verify on disk.
    assert_eq!(
        uk_verify_file(cs(dest.to_str().unwrap()).as_ptr(), cs(&pkg_hash).as_ptr()),
        UK_OK
    );
    let wrong = "0".repeat(64);
    assert_eq!(
        uk_verify_file(cs(dest.to_str().unwrap()).as_ptr(), cs(&wrong).as_ptr()),
        ERR_CORRUPT
    );

    // Existing files are refused before writes and preserved on both failure and success paths.
    let rc = uk_download(
        cs(&format!("{base}/pkg.bin")).as_ptr(),
        cs(dest.to_str().unwrap()).as_ptr(),
        cs(&pkg_hash).as_ptr(),
        None,
        std::ptr::null_mut(),
    );
    assert_ne!(rc, UK_OK);
    assert_eq!(std::fs::read(&dest).unwrap(), PKG);
    extern "C" fn cancel(_: *mut c_void, _: u64, _: u64) -> c_int {
        1
    }
    let cancelled = dir.join("cancelled.bin");
    let rc = uk_download(
        cs(&format!("{base}/pkg.bin")).as_ptr(),
        cs(cancelled.to_str().unwrap()).as_ptr(),
        cs(&pkg_hash).as_ptr(),
        Some(cancel),
        std::ptr::null_mut(),
    );
    assert_ne!(rc, UK_OK);
    assert!(!cancelled.exists());

    // 5. Download with a wrong expected hash → CORRUPT, file removed.
    let dest2 = dir.join("pkg2.bin");
    let rc = uk_download(
        cs(&format!("{base}/pkg.bin")).as_ptr(),
        cs(dest2.to_str().unwrap()).as_ptr(),
        cs(&wrong).as_ptr(),
        None,
        std::ptr::null_mut(),
    );
    assert_eq!(rc, ERR_CORRUPT);
    assert!(!dest2.exists(), "a hash-mismatched package must be deleted");

    let _ = std::fs::remove_dir_all(&dir);
}
