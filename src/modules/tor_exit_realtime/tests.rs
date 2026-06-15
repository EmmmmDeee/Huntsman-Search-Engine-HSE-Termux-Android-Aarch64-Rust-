use super::is_tor_exit;

#[test]
fn detects_exit_node() {
    let list = "# Tor exit list\n1.2.3.4\n5.6.7.8\n";
    assert!(is_tor_exit("1.2.3.4", list));
    assert!(is_tor_exit("5.6.7.8", list));
}

#[test]
fn misses_non_exit() {
    let list = "1.2.3.4\n5.6.7.8\n";
    assert!(!is_tor_exit("9.10.11.12", list));
}

#[test]
fn skips_comment_lines() {
    let list = "# 9.9.9.9\n1.1.1.1\n";
    assert!(!is_tor_exit("9.9.9.9", list));
}
