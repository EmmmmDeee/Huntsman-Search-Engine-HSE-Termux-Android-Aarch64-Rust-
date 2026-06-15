use super::is_linkedin_profile;

#[test]
fn detects_profile_html() {
    assert!(is_linkedin_profile(
        r#"<meta property="og:type" content="profile" />"#
    ));
}

#[test]
fn rejects_login_wall() {
    assert!(!is_linkedin_profile(
        "<html><body>Sign in to LinkedIn</body></html>"
    ));
}
