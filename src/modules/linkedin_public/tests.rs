use super::{LinkedinPublic, is_linkedin_profile};
use crate::core::module::Module;
use crate::core::scan::{Target, TargetKind};

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

#[test]
fn accepts_fullname_and_organisation() {
    let m = LinkedinPublic;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}
