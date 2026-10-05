use super::*;
    use crate::core::scan::TargetKind;

    // ── parse_target_kind ───────────────────────────────────────────────────

    #[test]
    fn parse_email() {
        assert_eq!(parse_target_kind("email").expect("should succeed"), TargetKind::Email);
        assert_eq!(parse_target_kind("EMAIL").expect("should succeed"), TargetKind::Email);
        assert_eq!(parse_target_kind(" Email ").expect("should succeed"), TargetKind::Email);
    }

    #[test]
    fn parse_username() {
        assert_eq!(parse_target_kind("username").expect("should succeed"), TargetKind::Username);
    }

    #[test]
    fn parse_phone() {
        assert_eq!(parse_target_kind("phone").expect("should succeed"), TargetKind::Phone);
    }

    #[test]
    fn parse_name_aliases() {
        assert_eq!(parse_target_kind("name").expect("should succeed"), TargetKind::FullName);
        assert_eq!(parse_target_kind("fullname").expect("should succeed"), TargetKind::FullName);
    }

    #[test]
    fn parse_ip_aliases() {
        assert_eq!(parse_target_kind("ip").expect("should succeed"), TargetKind::IpAddress);
        assert_eq!(
            parse_target_kind("ipaddress").expect("should succeed"),
            TargetKind::IpAddress
        );
    }

    #[test]
    fn parse_domain() {
        assert_eq!(parse_target_kind("domain").expect("should succeed"), TargetKind::Domain);
    }

    #[test]
    fn parse_asn() {
        assert_eq!(parse_target_kind("asn").expect("should succeed"), TargetKind::Asn);
    }

    #[test]
    fn parse_coords_aliases() {
        assert_eq!(
            parse_target_kind("coords").expect("should succeed"),
            TargetKind::Coordinates
        );
        assert_eq!(
            parse_target_kind("coordinates").expect("should succeed"),
            TargetKind::Coordinates
        );
    }

    #[test]
    fn parse_address() {
        assert_eq!(parse_target_kind("address").expect("should succeed"), TargetKind::Address);
    }

    #[test]
    fn parse_unknown_kind_is_err() {
        assert!(parse_target_kind("foobar").is_err());
        assert!(parse_target_kind("").is_err());
    }

    #[test]
    fn every_seed_kind_canonical_form_round_trips() {
        // Total invariant: the canonical string the system emits for EVERY seed
        // kind (`canonical_str` — also serde/API/entity `kind`) must parse back to
        // that exact kind via the CLI parser. Regression: `full_name`/`ip_address`
        // did not (only `fullname`/`ipaddress` were accepted), so a copied
        // canonical kind failed on the CLI. Driven over the complete kind list so
        // a newly-added kind that forgets the alias fails here.
        for &kind in crate::core::dependency::ALL_TARGET_KINDS {
            let canon = kind.canonical_str();
            assert_eq!(
                parse_target_kind(canon).ok(),
                Some(kind),
                "canonical form {canon:?} must round-trip through parse_target_kind"
            );
        }
    }

    // ── split_csv ───────────────────────────────────────────────────────────

    #[test]
    fn split_csv_none_stays_none() {
        assert!(split_csv(None).is_none());
    }

    #[test]
    fn split_csv_single_entry() {
        let r = split_csv(Some("dns_resolver".into())).expect("should succeed");
        assert_eq!(r, vec!["dns_resolver"]);
    }

    #[test]
    fn split_csv_multiple_entries() {
        let r = split_csv(Some("a, b ,c".into())).expect("should succeed");
        assert_eq!(r, vec!["a", "b", "c"]);
    }

    #[test]
    fn split_csv_empty_string() {
        let r = split_csv(Some(String::new())).expect("should succeed");
        assert_eq!(r, vec![""]);
    }

    // ── cost_label ──────────────────────────────────────────────────────────

    #[test]
    fn cost_labels() {
        assert_eq!(
            crate::app::export::cost_label(crate::core::ModuleCost::Free),
            "free"
        );
        assert_eq!(
            crate::app::export::cost_label(crate::core::ModuleCost::KeyGated),
            "key-gated"
        );
        assert_eq!(
            crate::app::export::cost_label(crate::core::ModuleCost::Paid),
            "paid"
        );
    }

    // ── truncate ────────────────────────────────────────────────────────────

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string_adds_ellipsis() {
        let r = truncate("hello world", 5);
        assert!(r.contains('…'));
        assert_eq!(r.chars().count(), 5);
    }

    #[test]
    fn truncate_unicode() {
        let r = truncate("café latte", 5);
        assert_eq!(r.chars().count(), 5);
        assert!(r.ends_with('…'));
    }

    // ── resolve_seed ────────────────────────────────────────────────────────

    #[test]
    fn resolve_seed_prefers_explicit_cli_value() {
        let got = resolve_seed(Some("alice".to_string()), Some("default".to_string())).expect("should succeed");
        assert_eq!(got, "alice");
    }

    #[test]
    fn resolve_seed_falls_back_to_default_when_value_absent() {
        let got = resolve_seed(None, Some("default".to_string())).expect("should succeed");
        assert_eq!(got, "default");
    }

    #[test]
    fn resolve_seed_blank_cli_value_falls_back_to_default() {
        // `-v "  "` is treated as absent, not as a blank target.
        let got = resolve_seed(Some("   ".to_string()), Some("default".to_string())).expect("should succeed");
        assert_eq!(got, "default");
    }

    #[test]
    fn resolve_seed_trims_explicit_value() {
        let got = resolve_seed(Some("  bob  ".to_string()), None).expect("should succeed");
        assert_eq!(got, "bob");
    }

    #[test]
    fn resolve_seed_errors_when_nothing_set() {
        let err = resolve_seed(None, None).expect_err("should be an error").to_string();
        assert!(err.contains("--value"), "{err}");
        assert!(err.contains("HUNTSMAN_DEFAULT_SEED"), "{err}");
    }

    // ── resolve_scan_id ─────────────────────────────────────────────────────

    #[test]
    fn resolve_scan_id_recovers_incomplete_scans() {
        use crate::core::scan::{Scan, ScanStatus, Target};
        use crate::storage::Store;

        let store = Store::open(":memory:").expect("should succeed");
        let target = Target { kind: TargetKind::Email, value: "test@example.com".to_string() };
        let mut scan = Scan::new("abc123", target);
        scan.status = ScanStatus::Running;
        store.upsert_scan(&scan).expect("should succeed");

        // An interrupted (non-complete) scan's checkpointed data must be
        // RECOVERABLE — resolve returns Ok so export/audit can read its partial
        // entities, never discarding collected findings (warning goes to stderr).
        assert_eq!(
            crate::app::runtime::resolve_scan_id(&store, "abc123").expect("should succeed"),
            "abc123"
        );
        // A genuinely-absent scan still errors loudly.
        assert!(crate::app::runtime::resolve_scan_id(&store, "no-such-scan").is_err());
    }

    #[test]
    fn config_set_rejects_an_unknown_toggle_key_instead_of_persisting_it() {
        // `hse config module.shodann off` used to print "○ off" and persist a
        // key nothing reads — a silent no-op the operator took as "disabled".
        // The same validator the web toggle endpoint uses now rejects it, and
        // the command exits non-zero without touching settings.json.
        let err = crate::cli::config::cmd_config(
            Some("module.no_such_module_xyz".to_string()),
            Some("off".to_string()),
        )
        .expect_err("an unknown toggle key must be an error");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown toggle key") && msg.contains("module.no_such_module_xyz"),
            "{msg}"
        );
        // An unset key resolves to the caller's default; had `off` been
        // persisted, this would read back `false`.
        assert!(
            crate::util::settings::get_bool("module.no_such_module_xyz", true),
            "nothing may have been persisted for the rejected key"
        );
    }

    // ── bsi profile aliasing (shared with `hse assurance --profile`) ─────────

    #[test]
    fn bsi_profile_railway_aliases_cloud() {
        use crate::core::assurance::Profile;
        // The directive names `hse bsi profile railway`; a Railway/container
        // deployment is exactly the cloud-hosted profile under which C5 applies.
        assert_eq!(super::assurance::parse_profile("railway").unwrap(), Profile::Cloud);
        assert_eq!(super::assurance::parse_profile("RAILWAY").unwrap(), Profile::Cloud);
        // Canonical names still resolve; a bare word matches its profile.
        assert_eq!(super::assurance::parse_profile("cloud").unwrap(), Profile::Cloud);
        assert_eq!(super::assurance::parse_profile("android").unwrap(), Profile::Android);
        assert_eq!(
            super::assurance::parse_profile("hse-bsi-web").unwrap(),
            Profile::Web
        );
        // An unknown profile is a clean error, never a silent default.
        assert!(super::assurance::parse_profile("nope").is_err());
    }

    // ── `hse import --input-format` ─────────────────────────────────────────

    /// REQ-SCANNAME-001: `hse scan --name` and `hse live --name` parse into
    /// their commands, so a scan run from a terminal can be named as one
    /// queued from the console can.
    #[test]
    fn scan_and_live_take_a_name() {
        use super::command::{Cli, Command};
        use clap::Parser;
        let scan = Cli::try_parse_from(["hse", "scan", "-v", "a@b.com", "--name", "Q3 audit"])
            .expect("scan --name");
        match scan.command {
            Command::Scan { name, .. } => assert_eq!(name.as_deref(), Some("Q3 audit")),
            _ => panic!("parsed a different subcommand"),
        }
        let live = Cli::try_parse_from(["hse", "live", "-v", "a@b.com", "--name", "Q3 audit"])
            .expect("live --name");
        match live.command {
            Command::Live { name, .. } => assert_eq!(name.as_deref(), Some("Q3 audit")),
            _ => panic!("parsed a different subcommand"),
        }
        match Cli::try_parse_from(["hse", "scan", "-v", "a@b.com"])
            .expect("no --name")
            .command
        {
            Command::Scan { name, .. } => assert_eq!(name, None),
            _ => panic!("parsed a different subcommand"),
        }
    }

    /// REQ-CLI-HINTS-001: the hint printed after a scan is stored outside `hse
    /// scan` (an import, an ingest or an investigate run) is a command that
    /// reads that scan back, all of it. It named a list command `hse` does not
    /// have.
    #[test]
    fn the_stored_scan_hint_reads_that_scan_back() {
        use super::command::{Cli, Command};
        use clap::Parser;
        let hint = crate::app::persist::view_command("import-dossier-1790249205");
        let parsed = Cli::try_parse_from(hint.split_whitespace())
            .unwrap_or_else(|e| panic!("`{hint}` is not a command hse has: {e}"));
        match parsed.command {
            Command::Export {
                scan_id, format, ..
            } => {
                assert_eq!(scan_id, "import-dossier-1790249205", "{hint}");
                assert_eq!(format, "full", "the export that shows everything: {hint}");
            }
            _ => panic!("`{hint}` must export the scan it names"),
        }
    }

    /// Every help page, the root's and every subcommand's, hidden and nested
    /// ones included, with its path from `hse`.
    fn help_pages() -> Vec<(String, String)> {
        use clap::CommandFactory;
        fn walk(cmd: &mut clap::Command, path: String, out: &mut Vec<(String, String)>) {
            out.push((path.clone(), cmd.render_long_help().to_string()));
            for sub in cmd.get_subcommands_mut() {
                let sub_path = format!("{path} {}", sub.get_name());
                walk(sub, sub_path, out);
            }
        }
        let mut all = Vec::new();
        walk(&mut super::command::Cli::command(), "hse".to_string(), &mut all);
        all
    }

    /// Whether the command line `words` (after `hse`) names a real command and
    /// passes only arguments it takes. Each word that names a subcommand, or
    /// an alias of one, descends; `hse help …` must name subcommands only.
    /// After that, every `--flag` or `-f` must be one of that command's
    /// arguments (or `--help`/`-h`), a flag that takes a value takes the next
    /// word, and any other word, a placeholder such as `<id>` included, is a
    /// positional argument, which only a command that has one may take.
    /// Square brackets marking an optional part (`[--yes]`) are read through.
    fn names_a_real_command(words: &[&str]) -> std::result::Result<(), String> {
        use clap::CommandFactory;
        let root = super::command::Cli::command();
        if let Some((&"help", path)) = words.split_first() {
            let mut cmd = &root;
            for word in path {
                cmd = cmd
                    .find_subcommand(word)
                    .ok_or_else(|| format!("`hse help`: no command `{word}`"))?;
            }
            return Ok(());
        }
        let mut cmd = &root;
        let mut rest = words;
        while let Some((first, tail)) = rest.split_first() {
            match cmd.find_subcommand(first) {
                Some(sub) => {
                    cmd = sub;
                    rest = tail;
                }
                None => break,
            }
        }
        if std::ptr::eq(cmd, &root) {
            return Err(format!("no command `{}`", words.first().unwrap_or(&"")));
        }
        let takes_positionals = cmd.get_positionals().next().is_some();
        // A command that is only a group of subcommands takes no bare word, so
        // one that is not a subcommand is a misspelt one (`hse keys lsit`).
        if let Some(word) = rest.first().filter(|w| !w.starts_with(['-', '<', '[']))
            && cmd.has_subcommands()
            && !takes_positionals
        {
            return Err(format!("`{}` has no subcommand `{word}`", cmd.get_name()));
        }
        let mut value_due = false;
        for raw in rest {
            let word = raw.trim_start_matches('[').trim_end_matches(']');
            if value_due {
                value_due = false;
                continue;
            }
            let (flag, attached) = match word.split_once('=') {
                Some((flag, _)) => (flag, true),
                None => (word, false),
            };
            let arg = if let Some(long) = flag.strip_prefix("--") {
                if long == "help" {
                    continue;
                }
                cmd.get_arguments().find(|a| {
                    a.get_long() == Some(long)
                        || a.get_all_aliases().is_some_and(|al| al.contains(&long))
                })
            } else if let Some(short) = flag.strip_prefix('-').filter(|s| s.chars().count() == 1) {
                let c = short.chars().next().unwrap_or('-');
                if c == 'h' {
                    continue;
                }
                cmd.get_arguments().find(|a| {
                    a.get_short() == Some(c)
                        || a.get_all_short_aliases().is_some_and(|al| al.contains(&c))
                })
            } else if takes_positionals {
                continue;
            } else {
                return Err(format!("`{}` takes no argument `{word}`", cmd.get_name()));
            };
            let Some(arg) = arg else {
                return Err(format!("`{}` has no `{flag}`", cmd.get_name()));
            };
            value_due = arg.get_action().takes_values() && !attached;
        }
        Ok(())
    }

    /// REQ-CLI-HINTS-001: every `hse …` command a help page quotes is one `hse`
    /// has, with flags it takes. `hse ingest --help` and `hse investigate
    /// --help` named a list command, and `hse query --help` a search command;
    /// neither exists. Every page is checked, hidden and nested ones included,
    /// and each quoted command is followed through its subcommands to its flags.
    #[test]
    fn every_command_the_help_names_exists() {
        let all = help_pages();
        assert!(
            all.len() > 40,
            "the whole command tree, not {} pages",
            all.len()
        );

        let mut named = 0;
        let mut wrong = Vec::new();
        for (page, text) in &all {
            // A help line wraps wherever it likes, so read the words, not lines.
            let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
            for (at, quoted) in flat.match_indices("`hse ") {
                let span = flat[at + quoted.len()..]
                    .split('`')
                    .next()
                    .unwrap_or_default();
                let words: Vec<&str> = span.split_whitespace().collect();
                if !words
                    .first()
                    .is_some_and(|w| w.starts_with(|c: char| c.is_ascii_lowercase()))
                {
                    continue;
                }
                named += 1;
                if let Err(why) = names_a_real_command(&words) {
                    wrong.push(format!("{page}: `hse {span}`: {why}"));
                }
            }
        }
        assert!(named > 10, "the help names commands; found only {named}");
        assert!(
            wrong.is_empty(),
            "help names commands or flags hse does not have:\n{}",
            wrong.join("\n")
        );

        // The lock itself: a phantom command, a phantom flag, a phantom nested
        // subcommand, a positional id that `export` does not take and a
        // `--version` below the root are each refused; real ones pass.
        assert!(names_a_real_command(&["list"]).is_err());
        assert!(names_a_real_command(&["export", "--scan", "<id>"]).is_err());
        assert!(names_a_real_command(&["keys", "lsit"]).is_err());
        assert!(names_a_real_command(&["export", "<id>", "-f", "full"]).is_err());
        assert!(names_a_real_command(&["scan", "--version"]).is_err());
        assert!(names_a_real_command(&["help", "lsit"]).is_err());
        assert!(names_a_real_command(&["export", "-s", "<id>", "-f", "full"]).is_ok());
        assert!(names_a_real_command(&["export", "--format=full"]).is_ok());
        assert!(names_a_real_command(&["cells", "import", "--country", "AU"]).is_ok());
        assert!(names_a_real_command(&["cells", "clear", "[--yes]"]).is_ok());
        assert!(names_a_real_command(&["help", "keys", "set"]).is_ok());
    }

    /// REQ-CLI-HINTS-001: the `--auto-scan` help quotes the command the hint
    /// prints, so the two cannot drift apart.
    #[test]
    fn the_auto_scan_help_quotes_the_stored_scan_hint() {
        let hint = crate::app::persist::view_command("<id>");
        let pages = help_pages();
        for want in ["hse ingest", "hse investigate"] {
            let (page, text) = pages
                .iter()
                .find(|(p, _)| p == want)
                .unwrap_or_else(|| panic!("no help page `{want}`"));
            let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                flat.contains(&format!("`{hint}`")),
                "{page} --help must quote `{hint}`"
            );
        }
    }

    /// The flag parses straight into the shared `app::import::ImportFormat`
    /// (a clap `ValueEnum`), case-insensitively, and rejects an unknown name at
    /// parse time — so `cmd_import` can never receive a spelling the web
    /// upload's `?format=` would not also accept.
    #[test]
    fn import_input_format_flag_parses_into_the_shared_enum() {
        use super::command::{Cli, Command};
        use crate::app::import::ImportFormat;
        use clap::Parser;
        let parsed = |extra: &[&str]| {
            let mut argv = vec!["hse", "import", "dump.txt"];
            argv.extend_from_slice(extra);
            Cli::try_parse_from(argv)
        };
        match parsed(&[]).expect("no flag").command {
            Command::Import { input_format, .. } => assert_eq!(input_format, None),
            _ => panic!("parsed a different subcommand"),
        }
        match parsed(&["--input-format", "Combolist"])
            .expect("case-insensitive")
            .command
        {
            Command::Import { input_format, .. } => {
                assert_eq!(input_format, Some(ImportFormat::Combolist));
            }
            _ => panic!("parsed a different subcommand"),
        }
        let msg = match parsed(&["--input-format", "bogus"]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("unknown names must fail at parse time"),
        };
        assert!(
            msg.contains("bogus") && msg.contains("sql-dump"),
            "clap must name the typo and the accepted values: {msg}"
        );
    }

    // ── color_severity ───────────────────────────────────────────────────

    /// Pins the exact ANSI sequence per [`Severity`] tier. A prior version
    /// took the already `Display`-rendered (uppercase) label and matched it
    /// against lowercase string literals ("critical", "high", "medium"), so
    /// none of the three coloured arms ever fired — every row in `hse scan`'s
    /// correlation table rendered dim regardless of actual severity. Falsified
    /// by reverting `color_severity` to take `&str` and re-deriving the label
    /// via `format!("{:<10}", severity)` before matching `.trim()` against
    /// lowercase: this test fails on that shape (every arm below except `Low`
    /// gets the dim `\x1b[2m` code instead of its own) and passes once the
    /// match is driven directly off the `Severity` enum.
    #[test]
    fn color_severity_each_tier_gets_its_own_colour() {
        let padded = |s: &str| format!("{s:<10}");
        assert_eq!(
            color_severity(Severity::Critical, true),
            format!("\x1b[1;31m{}\x1b[0m", padded("CRITICAL"))
        );
        assert_eq!(
            color_severity(Severity::High, true),
            format!("\x1b[31m{}\x1b[0m", padded("HIGH"))
        );
        assert_eq!(
            color_severity(Severity::Medium, true),
            format!("\x1b[33m{}\x1b[0m", padded("MEDIUM"))
        );
        assert_eq!(
            color_severity(Severity::Low, true),
            format!("\x1b[2m{}\x1b[0m", padded("LOW"))
        );
    }

    #[test]
    fn color_severity_color_false_is_the_plain_padded_label_no_ansi() {
        for (sev, label) in [
            (Severity::Critical, "CRITICAL"),
            (Severity::High, "HIGH"),
            (Severity::Medium, "MEDIUM"),
            (Severity::Low, "LOW"),
        ] {
            let out = color_severity(sev, false);
            assert_eq!(out, format!("{label:<10}"));
            assert!(!out.contains('\u{1b}'), "no ANSI escape when color is disabled: {out:?}");
        }
    }
