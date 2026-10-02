use super::*;

#[test]
fn missing_policy_file_is_treated_as_empty_policy() {
    let path = Path::new("/nonexistent/dep-cooldown.toml");
    let policy = load_policy_file(path).expect("a missing file is not an error");
    assert_eq!(policy, policy::PolicyFile::default());
}

#[test]
fn present_policy_file_is_parsed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dep-cooldown.toml");
    std::fs::write(&path, "cooldown_days = 9\n").expect("write fixture");
    let policy = load_policy_file(&path).expect("valid file parses");
    assert_eq!(policy.cooldown_days, Some(9));
}

#[test]
fn malformed_policy_file_is_a_load_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dep-cooldown.toml");
    std::fs::write(&path, "cooldown_days = \"not a number\"\n").expect("write fixture");
    assert!(load_policy_file(&path).is_err());
}
