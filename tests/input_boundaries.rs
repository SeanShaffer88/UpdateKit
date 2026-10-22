use updatekit::{json, manifest, platform};
#[test]
fn deep_ambiguous_and_non_json_numbers_are_rejected() {
    assert!(json::parse(&("[".repeat(10000) + &"]".repeat(10000))).is_err());
    assert!(json::parse(r#"{"version":"1","version":"9"}"#).is_err());
    for s in ["01", "1.", "1e", "1e999", "-01", "+1", ".5"] {
        assert!(json::parse(s).is_err(), "{s}");
    }
    assert!(json::parse(&" ".repeat(1024 * 1024 + 1)).is_err());
}
#[test]
fn url_policy_has_no_ambiguous_authority_or_remote_cleartext() {
    for url in [
        "http://example.com/a",
        "https://user@host/a",
        "https://host/a\r\nX: y",
        "https://host:0/a",
        "https://host/a#fragment",
        "https://host\\evil/a",
    ] {
        assert!(platform::parse_url(url).is_err(), "{url}");
    }
    assert_eq!(
        platform::parse_url("https://example.com?x=1").unwrap().path,
        "/?x=1"
    );
    assert!(platform::parse_url("http://127.0.0.1:8080/test").is_ok());
}
#[test]
fn rollback_and_replayed_versions_never_offer_an_update() {
    for version in ["0.9.0", "1.0.0"] {
        let m=manifest::parse_manifest(&format!(r#"{{"version":"{version}","package_url":"https://example.com/a","sha256":"{}","mandatory":true}}"#,"0".repeat(64))).unwrap();
        let result = manifest::check_result_json("1.0.0", &m).unwrap();
        assert!(result.contains("\"update_available\":false"));
        assert!(result.contains("\"mandatory\":false"));
    }
}
