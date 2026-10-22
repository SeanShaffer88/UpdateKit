//! The update manifest: a static JSON document the app host serves
//! from anywhere (a web host, a GitHub release, an intranet share).
//! UpdateKit fetches it, compares `version` against the running app,
//! and reports everything the app needs to decide and download.
//!
//! ```json
//! {
//!   "version": "1.4.0",                       // required
//!   "package_url": "https://…/App-1.4.0.zip", // required when an update exists
//!   "sha256": "…64 hex chars…",               // required with package_url
//!   "size": 12345678,                          // optional, bytes
//!   "mandatory": false,                        // optional
//!   "notes": "What changed…",                  // optional, free text
//!   "min_version": "1.0.0"                     // optional: below this, update is mandatory
//! }
//! ```

use crate::version::{compare_versions, parse_version};
use crate::{json_escape, CResult, ERR_INVALID_ARG};

#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub version: String,
    pub package_url: Option<String>,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub mandatory: bool,
    pub notes: String,
    pub min_version: Option<String>,
}

pub fn parse_manifest(text: &str) -> CResult<Manifest> {
    let v = crate::json::parse(text)
        .map_err(|e| (ERR_INVALID_ARG, format!("manifest is not valid JSON: {e}")))?;
    let version = v
        .get("version")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or((ERR_INVALID_ARG, "manifest has no 'version' string".into()))?
        .to_string();
    parse_version(&version)
        .map_err(|e| (ERR_INVALID_ARG, format!("manifest version invalid: {e}")))?;
    let package_url = v
        .get("package_url")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let sha256 = v
        .get("sha256")
        .and_then(|x| x.as_str())
        .map(|s| s.to_lowercase());
    if let Some(url) = &package_url {
        crate::platform::parse_url(url)?;
    }
    if let Some(h) = &sha256 {
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err((
                ERR_INVALID_ARG,
                "manifest 'sha256' must be 64 hex characters".into(),
            ));
        }
    }
    if package_url.is_some() && sha256.is_none() {
        return Err((
            ERR_INVALID_ARG,
            "manifest has 'package_url' but no 'sha256' — refusing unverifiable packages".into(),
        ));
    }
    let min_version = v
        .get("min_version")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    if let Some(mv) = &min_version {
        parse_version(mv).map_err(|e| {
            (
                ERR_INVALID_ARG,
                format!("manifest min_version invalid: {e}"),
            )
        })?;
    }
    Ok(Manifest {
        version,
        package_url,
        sha256,
        size: v.get("size").and_then(|x| x.as_u64()),
        mandatory: v
            .get("mandatory")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        notes: v
            .get("notes")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        min_version,
    })
}

/// Evaluate a manifest against the running version and render the
/// result JSON the FFI returns. An update whose package fields are
/// missing is reported as available=false with an internal-consistency
/// note rather than treated as a downloadable update.
pub fn check_result_json(current: &str, m: &Manifest) -> CResult<String> {
    let cur = parse_version(current)
        .map_err(|e| (ERR_INVALID_ARG, format!("current version invalid: {e}")))?;
    let latest = parse_version(&m.version).map_err(|e| (ERR_INVALID_ARG, e))?;
    let newer = compare_versions(&latest, &cur) == std::cmp::Ordering::Greater;
    let below_min = match &m.min_version {
        Some(mv) => {
            compare_versions(&cur, &parse_version(mv).map_err(|e| (ERR_INVALID_ARG, e))?)
                == std::cmp::Ordering::Less
        }
        None => false,
    };
    let complete = m.package_url.is_some() && m.sha256.is_some();
    let available = newer && complete;
    let mandatory = available && (m.mandatory || below_min);
    Ok(format!(
        "{{\"update_available\":{},\"current_version\":\"{}\",\"latest_version\":\"{}\",\"mandatory\":{},\"package_url\":{},\"sha256\":{},\"size\":{},\"notes\":\"{}\"}}",
        available,
        json_escape(current),
        json_escape(&m.version),
        mandatory,
        m.package_url
            .as_ref()
            .map(|u| format!("\"{}\"", json_escape(u)))
            .unwrap_or_else(|| "null".into()),
        m.sha256
            .as_ref()
            .map(|h| format!("\"{h}\""))
            .unwrap_or_else(|| "null".into()),
        m.size.map(|s| s.to_string()).unwrap_or_else(|| "null".into()),
        json_escape(&m.notes),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
        "version": "1.4.0",
        "package_url": "https://example.test/app-1.4.0.zip",
        "sha256": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        "size": 42,
        "notes": "Fixes the thing."
    }"#;

    #[test]
    fn newer_version_is_an_update() {
        let m = parse_manifest(MANIFEST).unwrap();
        let j = check_result_json("1.3.9", &m).unwrap();
        assert!(j.contains("\"update_available\":true"), "{j}");
        assert!(j.contains("\"mandatory\":false"), "{j}");
        // Hash normalized to lowercase.
        assert!(j.contains("ba7816bf8f01cfea"), "{j}");
    }

    #[test]
    fn same_or_older_is_not_an_update() {
        let m = parse_manifest(MANIFEST).unwrap();
        assert!(check_result_json("1.4.0", &m)
            .unwrap()
            .contains("\"update_available\":false"));
        assert!(check_result_json("2.0.0", &m)
            .unwrap()
            .contains("\"update_available\":false"));
    }

    #[test]
    fn min_version_forces_mandatory() {
        let m = parse_manifest(
            r#"{"version":"1.4.0","package_url":"https://x/y.zip","sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","min_version":"1.2.0"}"#,
        )
        .unwrap();
        assert!(check_result_json("1.1.0", &m)
            .unwrap()
            .contains("\"mandatory\":true"));
        assert!(check_result_json("1.3.0", &m)
            .unwrap()
            .contains("\"mandatory\":false"));
    }

    #[test]
    fn unverifiable_manifests_are_rejected() {
        // package_url without sha256
        assert!(parse_manifest(r#"{"version":"1.0.0","package_url":"https://x/y.zip"}"#).is_err());
        // malformed hash
        assert!(parse_manifest(
            r#"{"version":"1.0.0","package_url":"https://x/y.zip","sha256":"xyz"}"#
        )
        .is_err());
        // no version at all
        assert!(parse_manifest(r#"{"package_url":"https://x/y.zip"}"#).is_err());
    }
}
