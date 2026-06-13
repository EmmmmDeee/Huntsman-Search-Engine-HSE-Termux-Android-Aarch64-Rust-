use super::*;

    #[test]
    fn accepts_email_and_username() {
        let m = PwnedPasswords;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(PwnedPasswords.name(), "pwned_passwords");
        assert_eq!(PwnedPasswords.priority(), 115);
        assert_eq!(PwnedPasswords.max_timeout_ms(), 10_000);
        // Network-reaching (api.pwnedpasswords.com) → not passive.
        assert!(!PwnedPasswords.is_passive());
    }

    #[test]
    fn sha1_hash_format() {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(b"password");
        let hash = hex::encode(h.finalize()).to_uppercase();
        assert_eq!(hash.len(), 40);
        assert_eq!(&hash[..5], "5BAA6");
    }
