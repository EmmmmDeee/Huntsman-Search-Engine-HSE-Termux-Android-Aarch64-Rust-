use super::*;

#[test]
fn classify_splits_by_presence_of_a_non_blank_domain() {
    assert_eq!(StealerRowKind::classify(Some("example.com")), StealerRowKind::Password);
    assert_eq!(StealerRowKind::classify(Some("   ")), StealerRowKind::Combo);
    assert_eq!(StealerRowKind::classify(None), StealerRowKind::Combo);
}

#[test]
fn db_str_round_trips_through_both_kinds() {
    assert_eq!(StealerRowKind::from_db_str(StealerRowKind::Password.as_db_str()), StealerRowKind::Password);
    assert_eq!(StealerRowKind::from_db_str(StealerRowKind::Combo.as_db_str()), StealerRowKind::Combo);
}

#[test]
fn from_db_str_defaults_unrecognised_values_to_combo_not_a_fabricated_password_row() {
    assert_eq!(StealerRowKind::from_db_str("garbage"), StealerRowKind::Combo);
    assert_eq!(StealerRowKind::from_db_str(""), StealerRowKind::Combo);
}

#[test]
fn is_empty_true_only_when_both_login_and_password_are_absent() {
    let base = StealerRow {
        log_id: Some("abc123".into()),
        domain: Some("example.com".into()),
        login: None,
        password: None,
        pwned_at: None,
        kind: StealerRowKind::Password,
    };
    assert!(base.is_empty());

    let mut with_login = base.clone();
    with_login.login = Some("alice".into());
    assert!(!with_login.is_empty());

    let mut with_password = base.clone();
    with_password.password = Some("hunter2".into());
    assert!(!with_password.is_empty());
}
