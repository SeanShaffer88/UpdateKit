//! Dotted-numeric version comparison with an optional pre-release
//! suffix: `MAJOR[.MINOR[.PATCH[.BUILD]]][-prerelease]`.
//!
//! Rules (documented in the README — manifests and apps must agree):
//! missing components are 0 (`1.2` == `1.2.0`); numeric components
//! compare numerically (`1.10` > `1.9`); a version WITH a pre-release
//! suffix sorts BEFORE the same version without one (`1.2.0-beta` <
//! `1.2.0`); two suffixes compare dot-piece by dot-piece, numeric
//! pieces numerically, numeric < alphanumeric, fewer pieces < more
//! when all shared pieces are equal (semver's rules).

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub nums: Vec<u64>,
    pub pre: Vec<String>,
}

pub fn parse_version(s: &str) -> Result<Version, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("version string is empty".into());
    }
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let mut nums = Vec::new();
    for part in core.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("invalid version component '{part}' in '{s}'"));
        }
        nums.push(
            part.parse::<u64>()
                .map_err(|_| format!("version component too large in '{s}'"))?,
        );
    }
    if nums.is_empty() {
        return Err(format!("invalid version '{s}'"));
    }
    let pre_parts: Vec<String> = match pre {
        Some(p) => {
            if p.is_empty() {
                return Err(format!("empty pre-release suffix in '{s}'"));
            }
            p.split('.').map(|x| x.to_string()).collect()
        }
        None => Vec::new(),
    };
    Ok(Version {
        nums,
        pre: pre_parts,
    })
}

pub fn compare_versions(a: &Version, b: &Version) -> Ordering {
    let n = a.nums.len().max(b.nums.len());
    for i in 0..n {
        let x = a.nums.get(i).copied().unwrap_or(0);
        let y = b.nums.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    // Release > pre-release of the same version.
    match (a.pre.is_empty(), b.pre.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for i in 0..a.pre.len().max(b.pre.len()) {
                let (x, y) = match (a.pre.get(i), b.pre.get(i)) {
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(x), Some(y)) => (x, y),
                    (None, None) => break,
                };
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(xn), Ok(yn)) => xn.cmp(&yn),
                    (Ok(_), Err(_)) => Ordering::Less, // numeric < alphanumeric
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            Ordering::Equal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        compare_versions(&parse_version(a).unwrap(), &parse_version(b).unwrap())
    }

    #[test]
    fn numeric_components() {
        assert_eq!(cmp("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(cmp("1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(cmp("2.0", "1.999"), Ordering::Greater);
        assert_eq!(cmp("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(cmp("0.9", "1.0"), Ordering::Less);
    }

    #[test]
    fn prerelease_rules() {
        assert_eq!(cmp("1.2.0-beta", "1.2.0"), Ordering::Less);
        assert_eq!(cmp("1.2.0-alpha", "1.2.0-beta"), Ordering::Less);
        assert_eq!(cmp("1.2.0-alpha.1", "1.2.0-alpha.beta"), Ordering::Less);
        assert_eq!(cmp("1.2.0-alpha", "1.2.0-alpha.1"), Ordering::Less);
        assert_eq!(cmp("1.2.0-rc.2", "1.2.0-rc.10"), Ordering::Less);
    }

    #[test]
    fn rejects_bad_versions() {
        for bad in ["", "1..2", "1.x", "v1.2", "1.2-", ".", "1."] {
            assert!(parse_version(bad).is_err(), "should reject: {bad:?}");
        }
    }
}
