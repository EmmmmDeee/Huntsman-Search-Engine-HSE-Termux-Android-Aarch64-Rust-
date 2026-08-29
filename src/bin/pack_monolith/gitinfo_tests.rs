use super::*;

#[test]
fn sanitize_remote_strips_scheme_credentials_proxy_and_git_suffix() {
    assert_eq!(
        sanitize_remote("https://github.com/EmmmmDeee/Huntsman-Search-Engine.git"),
        "github.com/EmmmmDeee/Huntsman-Search-Engine"
    );
    assert_eq!(
        sanitize_remote("git@github.com:owner/repo.git"),
        "github.com:owner/repo"
    );
    assert_eq!(
        sanitize_remote("https://local_proxy@127.0.0.1:1234/git/EmmmmDeee/repo.git"),
        "EmmmmDeee/repo"
    );
    assert_eq!(sanitize_remote(""), "(unknown)");
    // No scheme, no credentials, no .git suffix: passed through unchanged.
    assert_eq!(
        sanitize_remote("github.com/owner/repo"),
        "github.com/owner/repo"
    );
}
