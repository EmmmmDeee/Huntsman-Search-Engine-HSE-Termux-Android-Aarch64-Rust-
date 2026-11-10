use super::*;

#[test]
fn no_key_makes_no_request_and_reports_not_configured() {
    let ExposureRun::Printed { report, text } = run(Sources::default(), "Ada@Example.com", 7)
    else {
        panic!("expected a printed report");
    };
    let legs: Vec<_> = report
        .outcomes
        .iter()
        .map(|o| (o.module.as_str(), o.kind))
        .collect();
    assert_eq!(
        legs,
        [
            (SOURCE, SourceOutcomeKind::NotConfigured),
            (STOLEN_TAX_SOURCE, SourceOutcomeKind::NotConfigured),
            (OATHNET_SOURCE, SourceOutcomeKind::NotConfigured),
            (DEHASHED_SOURCE, SourceOutcomeKind::NotConfigured),
            (BREACHDIRECTORY_SOURCE, SourceOutcomeKind::NotConfigured)
        ],
        "every keyed leg is reported, in breach_hybrid order"
    );
    assert_eq!(report.entities.len(), 1);
    assert!(!report.entities[0].tags.iter().any(|t| t == tags::BREACH));
    assert_eq!(report.incidents, None, "no answer is not a zero");
    assert!(
        text.ends_with("\nincidents=none\noathnet_breaches=none\ndehashed_breaches=none\n"),
        "{text}"
    );

    // The HIBP leg names the free self-service route; stolen.tax, which has none, does not.
    let detail = |module: &str| {
        report
            .outcomes
            .iter()
            .find(|o| o.module == module)
            .and_then(|o| o.detail.clone())
            .unwrap_or_default()
    };
    assert!(
        detail(SOURCE).contains("https://haveibeenpwned.com/"),
        "{}",
        detail(SOURCE)
    );
    assert!(
        !detail(STOLEN_TAX_SOURCE).contains("haveibeenpwned"),
        "{}",
        detail(STOLEN_TAX_SOURCE)
    );
}

#[test]
fn the_help_describes_what_the_report_prints() {
    // A keyless leg's row, as the no-key test above sees it.
    let keyless = format!("reports {}.", SourceOutcomeKind::NotConfigured.as_str());
    assert!(EXPOSURE_HELP.contains(&keyless), "{EXPOSURE_HELP}");
    // Every OathNet column and row render_oathnet writes, values included.
    let rows = render_oathnet(Some(&[oathnet::Breach {
        dbname: "acme_forum".into(),
        records: 1,
        values: [(
            "phone_number".to_owned(),
            ["+15555550100".to_owned()].into(),
        )]
        .into(),
        ..oathnet::Breach::default()
    }]));
    assert!(
        rows.contains("\ttitle=") && rows.contains("oathnet_value\t"),
        "{rows}"
    );
    // What the decoder holds back and how far it reads, as `oathnet` defines them.
    let [pass, pwd, hash, salt] = oathnet::CREDENTIAL_MARKERS;
    for named in [
        "oathnet_breach row per breach database: records, title,".to_owned(),
        "one oathnet_value row (field=value) per distinct non-credential value".to_owned(),
        format!("(at most {}, each named", oathnet::MAX_FIELDS),
        format!("within {} bytes", oathnet::MAX_FIELD_BYTES),
        format!("(at most {} per field;", oathnet::MAX_VALUES_PER_FIELD),
        format!("a value over {} bytes", oathnet::MAX_VALUE_BYTES),
        format!("A field whose name holds {pass}, {pwd}, {hash} or {salt} in any case"),
        format!(
            "a {pass} beginning {} does not count",
            oathnet::NOT_A_CREDENTIAL
        ),
        "neither its value nor a list or object holding such a field".to_owned(),
        "such a field whose words name one holds a value, as a field or inside a list or \
             object, even if the field's name is left out"
            .to_owned(),
        match oathnet::PASSWORD_WORDS {
            [first @ .., last] => format!("a word beginning {} or {last}", first.join(", ")),
        },
        match oathnet::PASSWORD_NAMES {
            [first @ .., last] => format!("a word {} or {last}", first.join(", ")),
        },
        "never a field that describes one (pwdLastSet, password_changed_at)".to_owned(),
    ] {
        assert!(EXPOSURE_HELP.contains(&named), "{named:?}: {EXPOSURE_HELP}");
    }
    assert!(
        !EXPOSURE_HELP.contains("No record value other than"),
        "OathNet values are printed: {EXPOSURE_HELP}"
    );
}

#[test]
fn each_hibp_breach_is_evidence_on_the_one_email_entity() {
    let (text, report, urls) = run_with(&serde_json::json!([
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
         "PwnCount": 152_445_165, "DataClasses": ["Email addresses", "Passwords"],
         "IsVerified": true, "IsStealerLog": false},
        {"Name": "Logs", "DataClasses": ["Email addresses"], "IsStealerLog": true}
    ]));
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(urls[0].contains("/breachedaccount/"), "{urls:?}");
    assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::Success);
    assert_eq!(report.outcomes[0].found, Some(2));
    assert_eq!(report.entities.len(), 1, "merged by uid: {text}");
    let entity = &report.entities[0];
    assert!(entity.tags.iter().any(|t| t == tags::BREACH));
    assert!(entity.tags.iter().any(|t| t == tags::STEALER_LOG));
    let breaches: Vec<_> = entity
        .evidence
        .iter()
        .filter_map(|e| e.attributes.get("breach_name"))
        .collect();
    assert_eq!(breaches.len(), 2, "{breaches:?}");
}

#[test]
fn a_selector_that_is_neither_an_address_nor_a_username_fails() {
    for bad in ["not an email", "ada@", "", "ünï"] {
        assert!(
            matches!(run(Sources::default(), bad, 7), ExposureRun::Failed(_)),
            "{bad:?} accepted"
        );
    }
}

#[test]
fn an_address_is_never_read_as_a_handle() {
    assert_eq!(
        canonical_selector(" Ada@Example.com ").as_deref(),
        Some("ada@example.com")
    );
    assert_eq!(canonical_selector("@Ada_99").as_deref(), Some("ada_99"));
}

fn oathnet_only<'a>(transport: &'a (dyn Transport + Sync), keys: &'a Keys) -> Sources<'a> {
    Sources {
        oathnet: Some((transport, keys)),
        ..Sources::default()
    }
}

fn oathnet_keys() -> Keys {
    Keys::parse(&format!(
        "{}=on-test-key-0123456789abcdef\n",
        oathnet::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"))
}

#[test]
fn a_configured_keyed_leg_reaches_every_selector_it_can_search() {
    let transport = Counting::default();
    let keys = oathnet_keys();
    assert!(
        !Sources::default().reach("ada@example.com"),
        "no key, no leg"
    );
    let sources = oathnet_only(&transport, &keys);
    assert!(sources.reach("ada@example.com"));
    assert!(sources.reach("@Ada_99"), "OathNet searches a username too");
    assert!(!sources.reach("two words"), "not a selector");
}

/// Counts requests and answers each with a 404, so a test can prove a leg sent nothing.
#[derive(Default)]
struct Counting(std::sync::Mutex<usize>);

impl Transport for Counting {
    fn send(
        &self,
        _: &crate::http::Request,
    ) -> Result<crate::http::Response, crate::http::TransportFailure> {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        Ok(crate::http::Response {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
            truncated: false,
        })
    }
}

#[test]
fn dehashed_searches_an_address_and_never_a_username() {
    let counting = std::sync::Arc::new(Counting::default());
    let secret = crate::keys::Secret::new("dh-test-key-0123456789".to_owned())
        .unwrap_or_else(|e| panic!("fixture secret: {e}"));
    let client = DehashedClient::new(counting.clone(), secret);
    let sources = Sources {
        dehashed: Some(&client),
        ..Sources::default()
    };
    assert!(sources.reach("ada@example.com"));
    assert!(
        !sources.reach("@Ada_99"),
        "DeHashed alone cannot search a username"
    );
    let ExposureRun::Printed { report, .. } = run(sources, "@Ada_99", 7) else {
        panic!("expected a printed report");
    };
    assert_eq!(
        *counting
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        0
    );
    assert!(
        report.outcomes.iter().all(|o| o.module != DEHASHED_SOURCE),
        "a username lookup records no DeHashed leg: {:?}",
        report.outcomes
    );
    assert_eq!(report.dehashed, None);
}

#[test]
fn an_email_lookup_folds_in_the_keyed_legs_under_one_report() {
    // Gravatar, Duolingo and keys.openpgp.org each find nothing.
    let reply = |status: u16, body: &str| {
        Ok(crate::http::Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        })
    };
    let email_sources = crate::test_support::ScriptedTransport::new(vec![
        reply(404, ""),
        reply(200, r#"{"users":[]}"#),
        reply(404, "No key found"),
    ]);
    let crate::email_cli::EmailRun::Printed { report: email, .. } =
        crate::email_cli::run(&email_sources, "ada@example.com", 7)
    else {
        panic!("expected an email report");
    };
    let body = serde_json::json!({"success": true, "data": {
        "items": [{"email": "ada@example.com", "password": "hunter2", "dbname": "acme_forum"}],
        "meta": {"total": 1, "has_more": false}
    }});
    let transport = FakeHibp {
        body: body.to_string(),
        urls: std::sync::Mutex::default(),
    };
    let keys = oathnet_keys();
    let ExposureRun::Printed { report, .. } =
        run(oathnet_only(&transport, &keys), "ada@example.com", 7)
    else {
        panic!("expected an exposure report");
    };
    let (mut entities, mut outcomes) = (email.entities, email.outcomes);
    let before = outcomes.len();
    let text = match fold_into(&mut entities, &mut outcomes, report) {
        Ok(text) => text,
        Err(m) => panic!("fold failed: {m}"),
    };
    let legs: Vec<&str> = outcomes[before..]
        .iter()
        .map(|o| o.module.as_str())
        .collect();
    assert_eq!(
        legs,
        [SOURCE, STOLEN_TAX_SOURCE, OATHNET_SOURCE, DEHASHED_SOURCE]
    );
    assert_eq!(text.matches("entities=").count(), 1, "{text}");
    assert!(text.contains("oathnet_breaches=1"), "{text}");
    assert!(text.contains("dehashed_breaches=none"), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
    let seeds = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.raw_value == "ada@example.com")
        .count();
    assert_eq!(seeds, 1, "the seed both lookups emit is merged");
    assert!(
        entities
            .iter()
            .any(|e| e.raw_value == "ada@example.com" && e.tags.iter().any(|t| t == tags::BREACH)),
        "{text}"
    );
}

#[test]
fn an_unavailable_exposure_line_cannot_forge_a_row() {
    assert_eq!(
        unavailable_line("refused\nentities=9"),
        "exposure=unavailable reason=refused\\nentities=9\n"
    );
}

#[test]
fn a_username_skips_hibp_and_searches_oathnet_by_username() {
    let body = serde_json::json!({"success": true, "data": {
        "items": [
            {"email": "ada@example.com", "username": "Ada_99", "password_hash": "deadbeef",
             "dbname": "acme_forum"},
            {"email": "a.l@example.org", "username": "ada_99", "dbname": "acme_forum"}
        ],
        "meta": {"total": 2, "has_more": false}
    }});
    let transport = FakeHibp {
        body: body.to_string(),
        urls: std::sync::Mutex::default(),
    };
    let keys = Keys::parse(&format!(
        "{}=on-test-key-0123456789abcdef\n",
        oathnet::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"));
    let sources = Sources {
        oathnet: Some((&transport, &keys)),
        ..Sources::default()
    };
    let ExposureRun::Printed { text, report } = run(sources, "@Ada_99", 7) else {
        panic!("expected a printed report");
    };
    let urls = transport
        .urls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(urls[0].contains("username%5B%5D=ada_99"), "{urls:?}");

    let legs: Vec<&str> = report.outcomes.iter().map(|o| o.module.as_str()).collect();
    assert_eq!(
        legs,
        [STOLEN_TAX_SOURCE, OATHNET_SOURCE],
        "HIBP is email-only"
    );

    let seed = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.raw_value == "ada_99")
        .unwrap_or_else(|| panic!("no username seed: {text}"));
    assert!(seed.tags.iter().any(|t| t == tags::BREACH), "{text}");
    assert!(
        seed.tags.iter().any(|t| t == tags::PASSWORD_AT_RISK),
        "{text}"
    );
    let emails: Vec<&str> = report
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.raw_value.as_str())
        .collect();
    assert_eq!(emails, ["a.l@example.org", "ada@example.com"], "{text}");
    assert_eq!(
        report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Username)
            .count(),
        1,
        "the seed's own spelling in a record is not a second username: {text}"
    );
    assert!(!text.contains("deadbeef"), "{text}");
}

#[test]
fn oathnet_breaches_surface_values_but_not_cleartext_credentials() {
    let body = serde_json::json!({"success": true, "data": {
        "items": [
            {"email": "ada@example.com", "username": "ada99", "password": "hunter2-secret",
             "dbname": "linkedin_2012", "indexed_at": "2026-04-18T12:00:00Z"},
            {"email": "ada@example.com", "phone_number": "+15555550100",
             "dbname": "acme_forum"}
        ],
        "meta": {"total": 7, "has_more": true},
        "dbname_info": {"linkedin_2012": {"Title": "LinkedIn", "BreachDate": "2012-05-05"}}
    }});
    let transport = FakeHibp {
        body: body.to_string(),
        urls: std::sync::Mutex::default(),
    };
    let keys = Keys::parse(&format!(
        "{}=on-test-key-0123456789abcdef\n",
        oathnet::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"));
    let sources = Sources {
        oathnet: Some((&transport, &keys)),
        ..Sources::default()
    };
    let ExposureRun::Printed { text, report } = run(sources, "Ada@Example.com", 7) else {
        panic!("expected a printed report");
    };

    let urls = transport
        .urls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(
        urls[0].contains("email%5B%5D=ada%40example.com"),
        "{urls:?}"
    );

    let outcome = report
        .outcomes
        .iter()
        .find(|o| o.module == OATHNET_SOURCE)
        .unwrap_or_else(|| panic!("no oathnet outcome: {text}"));
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(outcome.found, Some(2));
    let detail = outcome.detail.clone().unwrap_or_default();
    assert!(detail.contains("first 2 of 7"), "{detail}");

    let email = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .unwrap_or_else(|| panic!("no email entity: {text}"));
    assert!(email.tags.iter().any(|t| t == tags::BREACH));
    assert!(email.tags.iter().any(|t| t == tags::PASSWORD_AT_RISK));
    let datasets: Vec<_> = email
        .evidence
        .iter()
        .filter(|e| e.provenance.source == OATHNET_SOURCE)
        .filter_map(|e| e.attributes.get("dbname"))
        .collect();
    assert_eq!(datasets.len(), 2, "{datasets:?}");
    assert!(
        report
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "ada99"),
        "{text}"
    );

    assert!(text.contains("\noathnet_breaches=2\n"), "{text}");
    assert!(
        text.contains(
            "oathnet_breach\tlinkedin_2012\trecords=1\ttitle=LinkedIn\tbreach_date=2012-05-05\t\
                 first_indexed=2026-04-18T12:00:00Z\tlast_indexed=2026-04-18T12:00:00Z\t\
                 password_exposed=true\tfields=email,password,username\n"
        ),
        "{text}"
    );
    // Non-credential record values are surfaced, not reduced to field names: the phone number
    // a record held appears as its own row.
    assert!(
        text.contains("oathnet_value\tacme_forum\tphone_number=+15555550100\n"),
        "{text}"
    );
    // A cleartext credential is never emitted: the password is reported as exposed (the
    // `password_exposed=true` and `fields=…,password,…` above), but its value appears nowhere.
    assert!(
        !text.contains("oathnet_value\tlinkedin_2012\tpassword="),
        "the cleartext password value must not be emitted: {text}"
    );
    assert!(
        !text.contains("hunter2-secret"),
        "the cleartext password value must not be emitted: {text}"
    );
    let saved = serde_json::to_string(&report.entities).unwrap_or_default();
    for value in ["+15555550100", "ada99"] {
        assert!(
            saved.contains(value),
            "{value} missing from entities: {saved}"
        );
    }
    assert!(
        !saved.contains("hunter2-secret"),
        "the cleartext password value must not reach the entities: {saved}"
    );
}

/// Every non-credential value the `DeHashed` records hold is shown, as `OathNet`'s section shows it,
/// and kept as evidence on the queried address.
fn dehashed_values_are_shown_and_kept(text: &str, email: &Entity) {
    for row in [
        "dehashed_value\tLinkedIn\tname=Ada Example\n",
        "dehashed_value\tLinkedIn\tphone=+15555550100\n",
        "dehashed_value\tLinkedIn\temail=alt@example.com\n",
        "dehashed_value\tLinkedIn\tusername=ada99\n",
    ] {
        assert!(text.contains(row), "{row:?} missing: {text}");
    }
    let linkedin = email
        .evidence
        .iter()
        .find(|e| e.attributes.get("database_name").map(String::as_str) == Some("LinkedIn"))
        .unwrap_or_else(|| panic!("no LinkedIn evidence: {text}"));
    assert_eq!(
        linkedin.attributes.get("value_name").map(String::as_str),
        Some("Ada Example")
    );
    assert_eq!(
        linkedin.attributes.get("value_phone").map(String::as_str),
        Some("+15555550100")
    );
}

#[test]
fn dehashed_breaches_show_every_value_on_the_email_but_never_a_credential() {
    let body = serde_json::json!({
        "entries": [
            {"database_name": "LinkedIn", "email": ["ada@example.com"],
             "username": ["ada99"], "password": "hunter2-secret", "name": ["Ada Example"]},
            {"database_name": "LinkedIn", "email": ["ada@example.com", "alt@example.com"],
             "hashed_password": "deadbeef-hash", "phone": "+15555550100"},
            {"database_name": "AcmeForum", "email": ["ada@example.com"]}
        ],
        "total": 5
    });
    let transport = std::sync::Arc::new(FakeHibp {
        body: body.to_string(),
        urls: std::sync::Mutex::default(),
    });
    let secret = crate::keys::Secret::new("dh-test-key-0123456789abcdef".to_owned())
        .unwrap_or_else(|e| panic!("fixture secret: {e}"));
    // Local pacing off so the test never waits on the shared limiter.
    let client = DehashedClient::with_limiter(
        transport.clone(),
        secret,
        crate::hibp::rate_limit::RateLimiter::per_minute(0),
    );
    let sources = Sources {
        dehashed: Some(&client),
        ..Sources::default()
    };
    let ExposureRun::Printed { text, report } = run(sources, "Ada@Example.com", 7) else {
        panic!("expected a printed report");
    };

    let urls = transport
        .urls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(urls[0].ends_with("/v2/search"), "{urls:?}");

    let outcome = report
        .outcomes
        .iter()
        .find(|o| o.module == DEHASHED_SOURCE)
        .unwrap_or_else(|| panic!("no dehashed outcome: {text}"));
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(outcome.found, Some(2));
    let detail = outcome.detail.clone().unwrap_or_default();
    assert!(detail.contains("first 3 of 5"), "{detail}");

    let email = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "ada@example.com")
        .unwrap_or_else(|| panic!("no email entity: {text}"));
    assert!(email.tags.iter().any(|t| t == tags::BREACH));
    assert!(email.tags.iter().any(|t| t == tags::PASSWORD_AT_RISK));
    let datasets: Vec<_> = email
        .evidence
        .iter()
        .filter(|e| e.provenance.source == DEHASHED_SOURCE)
        .filter_map(|e| e.attributes.get("database_name"))
        .collect();
    assert_eq!(datasets.len(), 2, "one evidence per database: {datasets:?}");
    assert!(
        report
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Username && e.value == "ada99"),
        "{text}"
    );

    assert!(text.contains("\ndehashed_breaches=2\n"), "{text}");
    assert!(
        text.contains(
            "dehashed_breach\tAcmeForum\trecords=1\tpassword_exposed=false\tfields=email\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "dehashed_breach\tLinkedIn\trecords=2\tpassword_exposed=true\t\
             fields=email,hashed_password,name,password,phone,username\n"
        ),
        "{text}"
    );
    dehashed_values_are_shown_and_kept(&text, email);
    let saved = serde_json::to_string(&report.entities).unwrap_or_default();
    // A failure names which credential leaked, never the value or the output that holds it, so a
    // failing run cannot copy it into CI's logs.
    for (withheld, value) in [("password", "hunter2-secret"), ("hash", "deadbeef-hash")] {
        assert!(
            !text.contains(value),
            "the {withheld} leaked into the printed text"
        );
        assert!(
            !saved.contains(value),
            "the {withheld} leaked into the saved entities"
        );
    }
}

/// Answers every request with one 200 JSON body and records each requested URL.
struct FakeHibp {
    body: String,
    urls: std::sync::Mutex<Vec<String>>,
}

impl Transport for FakeHibp {
    fn send(
        &self,
        request: &crate::http::Request,
    ) -> Result<crate::http::Response, crate::http::TransportFailure> {
        self.urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.url.clone());
        Ok(crate::test_support::json_ok(&self.body))
    }
}

/// Gives stolen.tax's `snusbase` path no response and answers every other request with one
/// 200 JSON body.
struct SnusbaseDown(&'static str);

impl Transport for SnusbaseDown {
    fn send(
        &self,
        request: &crate::http::Request,
    ) -> Result<crate::http::Response, crate::http::TransportFailure> {
        if request.url.ends_with("path=snusbase") {
            return Err(crate::http::TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "no route".into(),
                blocked: false,
            });
        }
        Ok(crate::test_support::json_ok(self.0))
    }
}

/// A stolen.tax row that restates the searched handle and names no breach mints nothing,
/// but its row says stolen.tax matched, beside the partial note when a path failed.
#[test]
fn a_stolen_tax_row_that_names_no_breach_is_noted_on_its_row() {
    let body = r#"{"success":true,"data":{"breach_data":[{"username":"ada_99"}]}}"#;
    let keys = Keys::parse(&format!(
        "{}=st-test-key-0123456789abcdef\n",
        stolen_tax::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"));
    let row = |transport: &(dyn Transport + Sync)| {
        let sources = Sources {
            stolen_tax: Some((transport, &keys)),
            ..Sources::default()
        };
        let ExposureRun::Printed { report, .. } = run(sources, "ada.99", 7) else {
            panic!("expected a printed report");
        };
        report
            .outcomes
            .into_iter()
            .find(|o| o.module == STOLEN_TAX_SOURCE)
            .unwrap_or_else(|| panic!("no stolen.tax row"))
    };

    let every_path = FakeHibp {
        body: body.into(),
        urls: std::sync::Mutex::default(),
    };
    let answered = row(&every_path);
    assert_eq!(
        (answered.kind, answered.found, answered.detail.as_deref()),
        (
            SourceOutcomeKind::Inconclusive,
            Some(0),
            Some("1 row(s) name no breach or stealer host")
        )
    );

    let partial = row(&SnusbaseDown(body));
    assert_eq!(partial.kind, SourceOutcomeKind::Inconclusive);
    let detail = partial.detail.unwrap_or_default();
    assert!(
        detail.starts_with(
            "partial: 0 retrieved — stopped by the stolen.tax `snusbase` path(s) failing"
        ) && detail.ends_with("; 1 row(s) name no breach or stealer host"),
        "{detail}"
    );
}

/// A stolen.tax path the egress refuses before sending now makes the exposure lookup a refusal
/// (exit 77) naming it, where before it printed an empty report and exited 0 because only a
/// transport failure, through the old `network` side channel, could stop the lookup.
#[test]
fn a_refused_stolen_tax_path_is_a_refusal() {
    let keys = Keys::parse(&format!(
        "{}=st-test-key-0123456789abcdef\n",
        stolen_tax::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"));
    let refusing = crate::test_support::Refusing;
    let sources = Sources {
        stolen_tax: Some((&refusing, &keys)),
        ..Sources::default()
    };
    let ExposureRun::Network(why) = run(sources, "ada.99", 7) else {
        panic!("expected a network refusal");
    };
    assert!(why.contains(STOLEN_TAX_SOURCE), "{why}");
}

/// A stolen.tax lookup whose every path got no response is no usable response (exit 69)
/// naming it, never a refusal and never a report. Before, the leg mapped every path failure
/// to `Inconclusive`, so the lookup printed an empty report and exited 0 with the transport
/// failure surviving only as text; now the row keeps the kind the fetch saw.
#[test]
fn a_silent_stolen_tax_path_is_no_response_not_inconclusive() {
    let keys = Keys::parse(&format!(
        "{}=st-test-key-0123456789abcdef\n",
        stolen_tax::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"));
    let silent = crate::test_support::Silent;
    let sources = Sources {
        stolen_tax: Some((&silent, &keys)),
        ..Sources::default()
    };
    let ExposureRun::Failed(why) = run(sources, "ada.99", 7) else {
        panic!("expected no usable response");
    };
    // The refusal holds the queried handle, so a failure says what it lacks, not what it says.
    assert!(
        why.contains(STOLEN_TAX_SOURCE),
        "the refusal does not name {STOLEN_TAX_SOURCE}"
    );
    assert!(
        why.contains("no response (DnsFailure)"),
        "the refusal does not say there was no response"
    );
}

/// A stolen.tax source that answered every path with an error was reached, so the lookup
/// prints its row (exit 0) with the status's kind, not a transport failure and never a
/// refusal.
#[test]
fn a_failing_stolen_tax_path_is_reached_with_the_status_kind() {
    let keys = Keys::parse(&format!(
        "{}=st-test-key-0123456789abcdef\n",
        stolen_tax::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"));
    let failing = crate::test_support::Failing;
    let sources = Sources {
        stolen_tax: Some((&failing, &keys)),
        ..Sources::default()
    };
    let ExposureRun::Printed { report, .. } = run(sources, "ada.99", 7) else {
        panic!("expected a printed report");
    };
    let Some(row) = report
        .outcomes
        .iter()
        .find(|row| row.module == STOLEN_TAX_SOURCE)
    else {
        panic!("expected a stolen_tax row, got {:?}", report.outcomes);
    };
    assert_eq!(row.kind, SourceOutcomeKind::Upstream5xx);
    assert!(!row.kind.is_transport_failure());
    assert_eq!(
        row.detail.as_deref(),
        Some("stolen_tax: `snusbase` path failed: HTTP 500 (Upstream5xx)")
    );
}

/// Runs `exposure` for one fixed address against a fake HIBP that answers `breaches`, with
/// local pacing off so the tests never wait on the shared limiter.
fn run_with(breaches: &serde_json::Value) -> (String, Report, Vec<String>) {
    let transport = std::sync::Arc::new(FakeHibp {
        body: breaches.to_string(),
        urls: std::sync::Mutex::default(),
    });
    let Some(key) = crate::hibp::key::ApiKey::new("0123456789abcdef0123456789abcdef") else {
        panic!("the fixture key is a valid HIBP key");
    };
    let client = HibpClient::with_config(
        transport.clone(),
        crate::hibp::client::Auth::ApiKey(key),
        crate::hibp::client::HibpConfig::default(),
        std::sync::Arc::new(crate::hibp::rate_limit::RateLimiter::per_minute(0)),
    );
    let sources = Sources {
        hibp: Some(&client),
        ..Sources::default()
    };
    let ExposureRun::Printed { text, report } = run(sources, "ada@example.com", 7) else {
        panic!("expected a printed report");
    };
    let urls = transport
        .urls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    (text, report, urls)
}

/// The attribute `key` of the HIBP evidence for breach `name`.
fn breach_attr<'a>(report: &'a Report, name: &str, key: &str) -> Option<&'a str> {
    report
        .entities
        .iter()
        .flat_map(|entity| &entity.evidence)
        .find(|evidence| evidence.attributes.get("breach_name").map(String::as_str) == Some(name))
        .and_then(|evidence| evidence.attributes.get(key))
        .map(String::as_str)
}

/// Nested tags, the common entities, one link twice (once with a fragment and mixed-case
/// host), and a `javascript:`, a relative and a `mailto:` link.
const ADOBE_DESCRIPTION: &str = "<p>In October 2013, <b>153 <i>million</i></b> Adobe \
        accounts were <a href=\"https://KrebsOnSecurity.com/2013/10/adobe-breach/#top\" \
        target=\"_blank\" rel=\"noopener\">breached</a> &amp; each held an ID, email \
        &lt;address&gt;, &quot;encrypted&quot; password and a hint&#39;s text. Hints \
        <a href='https://www.troyhunt.com/adobe-credentials-and-serious/'>disclosed&nbsp;much\
        </a>&#x2014;see <a href=\"https://krebsonsecurity.com/2013/10/adobe-breach/\">the \
        report</a> again, <a href=\"javascript:alert(1)\">this</a>, <a href=\"/breach/Adobe\">\
        that</a> and <a href=\"mailto:x@example.com\">mail</a>.</p>";

const ADOBE_SUMMARY: &str = "In October 2013, 153 million Adobe accounts were breached & \
        each held an ID, email <address>, \"encrypted\" password and a hint's text. Hints \
        disclosed much\u{2014}see the report again, this, that and mail.";

const ADOBE_REFERENCES: [&str; 2] = [
    "https://krebsonsecurity.com/2013/10/adobe-breach/",
    "https://www.troyhunt.com/adobe-credentials-and-serious/",
];

#[test]
fn each_incident_shows_its_summary_and_the_links_its_source_gives() {
    let (text, report, _) = run_with(&serde_json::json!([{
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-12-04T00:00:00Z",
        "ModifiedDate": "2022-05-15T23:52:49Z",
        "PwnCount": 152_445_165,
        "Description": ADOBE_DESCRIPTION,
        "Attribution": "Data provided by a researcher",
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "IsVerified": true,
        "IsFabricated": false,
        "IsSensitive": false,
        "IsRetired": false,
        "IsSpamList": false,
        "IsMalware": false,
        "IsStealerLog": false
    }]));

    assert!(text.contains("\nincidents=1\n"), "{text}");
    assert!(
        text.contains(
            "\nincident\tAdobe\ttitle=Adobe\tbreach_date=2013-10-04\t\
                 added=2013-12-04T00:00:00Z\tdomain=adobe.com\taccounts=152445165\t\
                 verified=true\tflags=none\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(&format!("\nsummary\tAdobe\t{ADOBE_SUMMARY}\n")),
        "{text}"
    );
    let references: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("reference\tAdobe\t"))
        .collect();
    assert_eq!(references, ADOBE_REFERENCES, "{text}");
    assert!(
        text.contains("\nattribution\tAdobe\tData provided by a researcher\n"),
        "{text}"
    );

    assert_eq!(
        breach_attr(&report, "Adobe", "breach_summary"),
        Some(ADOBE_SUMMARY)
    );
    assert_eq!(
        breach_attr(&report, "Adobe", "breach_references"),
        Some(ADOBE_REFERENCES.join(" ").as_str())
    );
    for (key, value) in [
        ("breach_added_date", "2013-12-04T00:00:00Z"),
        ("breach_modified_date", "2022-05-15T23:52:49Z"),
        ("breach_attribution", "Data provided by a researcher"),
        ("breach_fabricated", "false"),
        ("breach_sensitive", "false"),
        ("breach_retired", "false"),
        ("breach_spam_list", "false"),
        ("breach_malware", "false"),
        ("breach_stealer_log", "false"),
    ] {
        assert_eq!(breach_attr(&report, "Adobe", key), Some(value), "{key}");
    }
    assert_eq!(
        breach_attr(&report, "Adobe", "breach_subscription_free"),
        None,
        "a flag the source does not send is not invented"
    );
}

/// The incidents section: from `incidents=` up to the `OathNet` section that follows it.
fn incidents_section(text: &str) -> &str {
    let Some(start) = text.find("\nincidents=") else {
        panic!("no incidents section: {text}");
    };
    let Some(end) = text.find("\noathnet_breaches=") else {
        panic!("no oathnet section: {text}");
    };
    &text[start + 1..=end]
}

#[test]
fn a_fabricated_or_spam_list_incident_is_unmistakable() {
    let (text, report, _) = run_with(&serde_json::json!([
        {"Name": "Genuine", "Description": "<p>A real breach.</p>", "IsVerified": true,
         "IsFabricated": false, "IsSpamList": false},
        {"Name": "Fake", "Domain": "fake.example", "Description": "<p>Not real.</p>",
         "IsVerified": false, "IsFabricated": true, "IsSpamList": false},
        {"Name": "Spammy", "Description": "<p>A list.</p>", "IsVerified": true,
         "IsFabricated": false, "IsSpamList": true}
    ]));
    let section = incidents_section(&text);
    let fabricated = caution(FABRICATED).unwrap_or_default();
    let spam_list = caution(SPAM_LIST).unwrap_or_default();
    assert!(!fabricated.is_empty() && !spam_list.is_empty());
    assert_eq!(
        section,
        format!(
            "incidents=3\n\
                 incident\tFake\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
                 domain=fake.example\taccounts=unknown\tverified=false\tflags=fabricated\n\
                 caution\tFake\t{fabricated}\n\
                 summary\tFake\tNot real.\n\
                 incident\tGenuine\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
                 domain=unknown\taccounts=unknown\tverified=true\tflags=none\n\
                 summary\tGenuine\tA real breach.\n\
                 incident\tSpammy\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
                 domain=unknown\taccounts=unknown\tverified=true\tflags=spam-list\n\
                 caution\tSpammy\t{spam_list}\n\
                 summary\tSpammy\tA list.\n"
        ),
        "the domain is shown as a domain, never as a guessed link"
    );

    assert_eq!(
        breach_attr(&report, "Fake", "breach_fabricated"),
        Some("true")
    );
    assert_eq!(
        breach_attr(&report, "Spammy", "breach_spam_list"),
        Some("true")
    );
    assert_eq!(
        breach_attr(&report, "Genuine", "breach_fabricated"),
        Some("false")
    );
    let summaries: Vec<&str> = report
        .entities
        .iter()
        .flat_map(|entity| &entity.evidence)
        .map(|evidence| evidence.summary.as_str())
        .collect();
    for expected in [
        "Address listed in HIBP breach Fake, which the source flags as fabricated",
        "Address listed in HIBP breach Spammy, which the source flags as spam-list",
        "Address listed in HIBP breach Genuine",
    ] {
        assert!(summaries.contains(&expected), "{summaries:?}");
    }
    let Some(entity) = report
        .entities
        .iter()
        .find(|e| e.tags.iter().any(|t| t == tags::BREACH))
    else {
        panic!("no breach entity: {text}");
    };
    for tag in [tags::FABRICATED_BREACH, tags::SPAM_LIST] {
        assert!(
            entity.tags.iter().any(|t| t == tag),
            "{tag}: {:?}",
            entity.tags
        );
    }
    assert!(
        text.contains("seed,breach,fabricated-breach,spam-list"),
        "the tags reach the entity row: {text}"
    );
}

#[test]
fn an_over_long_description_is_cut_on_a_character_boundary() {
    // Twelve characters, three of them more than one byte, 1,200 in all.
    let long = "Z\u{fc}rich \u{2013} \u{6771}\u{4eac} ".repeat(100);
    let (text, report, _) = run_with(&serde_json::json!([
        {"Name": "Long", "Description": format!("<p>{long}</p>")}
    ]));
    let Some(summary) = breach_attr(&report, "Long", "breach_summary") else {
        panic!("no summary: {text}");
    };
    assert_eq!(summary.chars().count(), MAX_SUMMARY_CHARS, "{summary}");
    let Some(kept) = summary.strip_suffix(ELLIPSIS) else {
        panic!("a cut summary ends with an ellipsis: {summary}");
    };
    assert!(
        long.starts_with(kept),
        "the summary is a prefix of the text"
    );
    assert!(
        kept.ends_with('\u{4eac}'),
        "the cut follows a 3-byte character"
    );
    assert!(
        text.contains(&format!("\nsummary\tLong\t{summary}\n")),
        "{text}"
    );
}

#[test]
fn control_characters_from_the_source_are_escaped_in_the_output() {
    let (text, report, _) = run_with(&serde_json::json!([{
        "Name": "Evil\u{1b}[2J",
        "Title": "Title\nforged\trow",
        "Domain": "evil.example\u{1b}]0;owned\u{7}",
        "Description": "<p>Clear\u{1b}[2J screen &#x1b;[31mred\u{7f} nul\u{0} \
            bidi\u{202e}txt <a href=\"https://evil.example/\u{1b}[1m\">x</a> \
            <a href=\"https://evil.example/ok\">ok</a></p>",
        "Attribution": "Credit\u{1b}[5m",
        "DataClasses": ["Email\u{1b}[0m addresses"]
    }]));
    let section = incidents_section(&text);
    assert!(
        crate::test_support::unexpected_controls(&text, &['\n', '\t']).is_empty(),
        "a control character other than the report's own separators: {text:?}"
    );
    let kinds = [
        "incident",
        "caution",
        "summary",
        "data_classes",
        "attribution",
        "reference",
    ];
    for line in section.lines().skip(1) {
        assert!(
            kinds
                .iter()
                .any(|kind| line.starts_with(&format!("{kind}\t"))),
            "text inside a value became a row of its own: {line:?}"
        );
        assert!(!line.contains('\u{202e}'), "{line:?}");
    }
    let incident_row = section.lines().nth(1).unwrap_or_default();
    assert_eq!(incident_row.matches('\t').count(), 8, "{incident_row:?}");
    for escaped in [
        "incident\tEvil\\u{1b}[2J\ttitle=Title\\nforged\\trow\t",
        "domain=evil.example\\u{1b}]0;owned\\u{7}\t",
        "summary\tEvil\\u{1b}[2J\tClear\\u{1b}[2J screen \\u{1b}[31mred\\u{7f} nul\\u{0} \
             bidi\\u{202e}txt x ok\n",
        "attribution\tEvil\\u{1b}[2J\tCredit\\u{1b}[5m\n",
        "data_classes\tEvil\\u{1b}[2J\tEmail\\u{1b}[0m addresses\n",
        "reference\tEvil\\u{1b}[2J\thttps://evil.example/ok\n",
    ] {
        assert!(section.contains(escaped), "{escaped:?} in {section:?}");
    }
    assert_eq!(
        section.matches("\nreference\t").count(),
        1,
        "a link holding a control character is dropped: {section:?}"
    );
    assert_eq!(
        breach_attr(&report, "Evil\u{1b}[2J", "breach_summary"),
        Some("Clear\u{1b}[2J screen \u{1b}[31mred\u{7f} nul\u{0} bidi\u{202e}txt x ok"),
        "the evidence keeps the source's text; only the printed report escapes it"
    );
}

#[test]
fn no_breaches_prints_a_zero_count_and_nothing_else() {
    let (text, report, urls) = run_with(&serde_json::json!([]));
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert_eq!(report.outcomes[0].kind, SourceOutcomeKind::ValidZero);
    assert_eq!(report.incidents, Some(Vec::new()));
    assert_eq!(incidents_section(&text), "incidents=0\n", "{text}");
}

#[test]
fn the_incidents_are_in_name_order_whatever_order_the_source_uses() {
    let breaches = [
        serde_json::json!({"Name": "Zeta", "Title": "Z", "Description": "<p>z</p>"}),
        serde_json::json!({"Name": "Alpha", "Title": "First Alpha"}),
        serde_json::json!({"Name": "Mid", "Description": "<a href=\"https://m.example/\">m</a>"}),
        serde_json::json!({"Name": "Alpha", "Title": "Second Alpha"}),
    ];
    let (forward, report, _) = run_with(&serde_json::Value::from(breaches.to_vec()));
    let names: Vec<&str> = report
        .incidents
        .iter()
        .flatten()
        .map(|incident| incident.name.as_str())
        .collect();
    assert_eq!(names, ["Alpha", "Mid", "Zeta"], "sorted, one per name");
    let section = incidents_section(&forward);
    assert!(
        section.contains("\tAlpha\ttitle=First Alpha\t"),
        "{section}"
    );
    assert!(!section.contains("Second Alpha"), "{section}");

    let mut rotated = breaches.to_vec();
    rotated.rotate_left(2);
    let (again, _, _) = run_with(&serde_json::Value::from(rotated));
    // Rotating moves the second Alpha record ahead of the first, so its title is kept instead.
    assert_eq!(
        incidents_section(&again).replace("Second Alpha", "First Alpha"),
        section,
        "the same incidents print the same section"
    );
    let (repeat, _, _) = run_with(&serde_json::Value::from(breaches.to_vec()));
    assert_eq!(repeat, forward, "the whole report is deterministic");
}

/// The HIBP evidence summaries in `report`, in order.
fn hibp_summaries(report: &Report) -> Vec<&str> {
    report
        .entities
        .iter()
        .flat_map(|entity| &entity.evidence)
        .filter(|evidence| evidence.attributes.contains_key("breach_name"))
        .map(|evidence| evidence.summary.as_str())
        .collect()
}

#[test]
fn a_repeated_breach_name_cannot_hide_a_flag_from_the_text() {
    // HIBP documents Name as unique, so only a malformed or hostile answer repeats one. The
    // later record carries the flags; whichever record comes first, the text, the evidence and
    // the tags must all show them, and must agree on the count. A descriptive field comes from
    // the first record that gives it: the domain, which only the flagged record gives, too.
    let genuine = serde_json::json!({
        "Name": "Alpha", "Title": "Genuine record", "BreachDate": "2020-01-01",
        "Description": "<a href=\"https://one.example/\">one</a>",
        "DataClasses": ["Email addresses"], "IsVerified": true,
        "IsFabricated": false, "IsSpamList": false
    });
    let flagged = serde_json::json!({
        "Name": "Alpha", "Title": "Fabricated record", "Domain": "alpha.example",
        "Description": "<a href=\"https://two.example/\">two</a> \
                        <a href=\"https://one.example/\">one</a>",
        "DataClasses": ["Passwords", "Email addresses"], "IsVerified": false,
        "IsFabricated": true, "IsSpamList": true, "IsMalware": true
    });
    let other = serde_json::json!({"Name": "Beta", "IsFabricated": false});
    let fabricated = caution(FABRICATED).unwrap_or_default();
    let spam_list = caution(SPAM_LIST).unwrap_or_default();
    assert!(!fabricated.is_empty() && !spam_list.is_empty());
    let expected_section = format!(
        "incidents=2\n\
             incident\tAlpha\ttitle=Genuine record\tbreach_date=2020-01-01\tadded=unknown\t\
             domain=alpha.example\taccounts=unknown\tverified=false\t\
             flags=fabricated,spam-list,malware\n\
             caution\tAlpha\t{fabricated}\n\
             caution\tAlpha\t{spam_list}\n\
             summary\tAlpha\tone\n\
             data_classes\tAlpha\tEmail addresses\n\
             reference\tAlpha\thttps://one.example\n\
             incident\tBeta\ttitle=unknown\tbreach_date=unknown\tadded=unknown\t\
             domain=unknown\taccounts=unknown\tverified=unknown\tflags=none\n"
    );

    for (order, breaches) in [
        ("flagged second", [&genuine, &flagged, &other]),
        ("flagged first", [&flagged, &other, &genuine]),
    ] {
        let breaches: Vec<serde_json::Value> = breaches.into_iter().cloned().collect();
        let (text, report, _) = run_with(&serde_json::Value::from(breaches));
        let section = incidents_section(&text);
        if order == "flagged second" {
            assert_eq!(section, expected_section, "{order}");
        }
        for row in [
            "flags=fabricated,spam-list,malware\n",
            &format!("\ncaution\tAlpha\t{fabricated}\n"),
            &format!("\ncaution\tAlpha\t{spam_list}\n"),
            "verified=false\t",
        ] {
            assert!(section.contains(row), "{order}: {row:?} in {section}");
        }
        assert!(section.starts_with("incidents=2\n"), "{order}: {section}");
        assert!(
            text.contains("\nhibp_account\tsuccess\tfound=2\t"),
            "{order}: the outcome counts the incidents the section prints: {text}"
        );
        let detail = report.outcomes[0].detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("3 records") && detail.contains("2 breach names"),
            "{order}: the merge is on record: {detail:?}"
        );

        assert_eq!(
            hibp_summaries(&report),
            [
                "Address listed in HIBP breach Alpha, which the source flags as fabricated \
                     and spam-list",
                "Address listed in HIBP breach Beta",
            ],
            "{order}: one evidence per breach name, in name order"
        );
        for (key, value) in [
            ("breach_fabricated", "true"),
            ("breach_spam_list", "true"),
            ("breach_malware", "true"),
            ("breach_verified", "false"),
            ("breach_domain", "alpha.example"),
        ] {
            assert_eq!(
                breach_attr(&report, "Alpha", key),
                Some(value),
                "{order}: {key}"
            );
        }
        let Some(entity) = report
            .entities
            .iter()
            .find(|e| e.tags.iter().any(|t| t == tags::BREACH))
        else {
            panic!("{order}: no breach entity: {text}");
        };
        for tag in [tags::FABRICATED_BREACH, tags::SPAM_LIST] {
            assert!(entity.tags.iter().any(|t| t == tag), "{order}: {tag}");
        }
    }
}

/// A record of breach `Alpha` with the title, `verified` value and status flags given.
fn alpha(title: &str, verified: Option<bool>, status: &[(&'static str, bool)]) -> Incident {
    Incident {
        name: "Alpha".to_owned(),
        title: Some(title.to_owned()),
        verified,
        status: status
            .iter()
            .map(|&(label, set)| StatusFlag { label, set })
            .collect(),
        ..Incident::default()
    }
}

#[test]
fn merging_records_keeps_every_caution_whatever_their_order() {
    let plain = alpha(
        "first",
        Some(true),
        &[(FABRICATED, false), ("retired", false)],
    );
    let flagged = alpha(
        "second",
        None,
        &[("sensitive", false), (SPAM_LIST, true), (FABRICATED, true)],
    );
    let unverified = alpha("third", Some(false), &[]);
    let other = Incident {
        name: "Beta".to_owned(),
        ..Incident::default()
    };
    let expected_status: Vec<StatusFlag> = [
        (FABRICATED, true),
        (SPAM_LIST, true),
        ("sensitive", false),
        ("retired", false),
    ]
    .into_iter()
    .map(|(label, set)| StatusFlag { label, set })
    .collect();

    for records in [
        [&plain, &flagged, &unverified, &other],
        [&other, &flagged, &unverified, &plain],
        [&unverified, &other, &plain, &flagged],
    ] {
        let records: Vec<Incident> = records.into_iter().cloned().collect();
        let first_title = records
            .iter()
            .find(|record| record.name == "Alpha")
            .and_then(|record| record.title.clone());
        let merged = merge_incidents(records);
        let names: Vec<&str> = merged.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["Alpha", "Beta"]);
        let alpha = &merged[0];
        assert_eq!(alpha.title, first_title, "the first record's title is kept");
        assert_eq!(
            alpha.status, expected_status,
            "any true wins, a flag no record sends stays absent, in the fixed order"
        );
        assert_eq!(
            alpha.verified,
            Some(false),
            "verified only if no record denies it"
        );
        assert_eq!(merged[1].status, [], "{:?}", merged[1]);
    }
}

#[test]
fn merging_records_fills_only_the_fields_the_first_record_lacks() {
    let mut only_true = alpha("a", Some(true), &[]);
    only_true.absorb(alpha("b", None, &[]));
    assert_eq!(only_true.verified, Some(true));
    assert_eq!(only_true.title.as_deref(), Some("a"));
    let mut unknown = alpha("a", None, &[]);
    unknown.absorb(alpha("b", None, &[]));
    assert_eq!(unknown.verified, None);

    let mut gaps = Incident {
        name: "Alpha".to_owned(),
        ..Incident::default()
    };
    gaps.absorb(Incident {
        name: "Alpha".to_owned(),
        domain: Some("alpha.example".to_owned()),
        data_classes: vec!["Passwords".to_owned()],
        references: vec!["https://alpha.example/news".to_owned()],
        ..Incident::default()
    });
    assert_eq!(gaps.domain.as_deref(), Some("alpha.example"));
    assert_eq!(gaps.data_classes, ["Passwords"]);
    assert_eq!(gaps.references, ["https://alpha.example/news"]);
    gaps.absorb(Incident {
        name: "Alpha".to_owned(),
        domain: Some("later.example".to_owned()),
        data_classes: vec!["Usernames".to_owned()],
        references: vec!["https://later.example/".to_owned()],
        ..Incident::default()
    });
    assert_eq!(gaps.domain.as_deref(), Some("alpha.example"));
    assert_eq!(gaps.data_classes, ["Passwords"]);
    assert_eq!(gaps.references, ["https://alpha.example/news"]);
}

#[test]
fn a_saved_report_with_incidents_reloads_with_verify() {
    let (_, report, _) = run_with(&serde_json::json!([
        {"Name": "Adobe", "Description": ADOBE_DESCRIPTION, "IsFabricated": true}
    ]));
    let dir = std::env::temp_dir().join(format!(
        "huntsman-exposure-incidents-save-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(err) = std::fs::create_dir_all(&dir) {
        panic!("temporary directory: {err}");
    }
    let path = dir.join("exposure.json");
    let saved = crate::lookup_save::save(
        &path,
        &report.entities,
        &report.outcomes,
        crate::lookup_save::EXPOSURE_POLICY,
    );
    let loaded = crate::ledger::load_chain(&path);
    let _ = std::fs::remove_dir_all(&dir);
    let (Ok(saved), Ok(loaded)) = (saved, loaded) else {
        panic!("the exposure ledger must save and reload");
    };
    assert_eq!(loaded, saved);
    let evidence: usize = report
        .entities
        .iter()
        .map(|entity| entity.evidence.len())
        .sum();
    assert_eq!(
        saved.len(),
        report.outcomes.len() + report.entities.len() + evidence
    );
}

#[test]
fn html_to_text_reads_malformed_markup_without_panicking() {
    for (html, expected) in [
        ("Hello <b world", Some("Hello <b world")),
        (
            "<a title=\"1 > 0\" href='x>y'>link</a> text",
            Some("link text"),
        ),
        (
            "<a title=\"never closed>x</a> <b>y</b>",
            Some("<a title=\"never closed>x</a> <b>y</b>"),
        ),
        ("a < b > c", Some("a < b > c")),
        ("<<<>>>", Some("<<<>>>")),
        ("x<", Some("x<")),
        ("</", Some("</")),
        ("<!-- never closed", None),
        ("a<!-- hidden -->b", Some("ab")),
        ("a<!-- x > y -->b", Some("ab")),
        ("<!DOCTYPE html><?xml x?>text", Some("text")),
        ("<p>one</p><p>two<br/>three</p>", Some("one two three")),
        ("in<b>line</b>d", Some("inlined")),
        (
            "Before<script>alert('<p>')</script>After",
            Some("BeforeAfter"),
        ),
        ("Before<STYLE>p{}</style >After", Some("BeforeAfter")),
        ("Before<script>never closed", Some("Before")),
        ("&amp;lt;b&amp;gt;", Some("&lt;b&gt;")),
        (
            "&#39;&apos;&quot;&gt;&lt;&amp;&nbsp;&#x41;&#65;&bogus; &#xD800;",
            Some("''\"><& AA&bogus; &#xD800;"),
        ),
        ("  \t\n <p> </p> &nbsp; ", None),
        ("", None),
        ("<a href=\"x\">", None),
    ] {
        assert_eq!(html_to_text(html, 100).as_deref(), expected, "{html:?}");
    }
    assert_eq!(html_to_text("text", 0), None);
}

#[test]
fn html_to_text_bounds_its_output_on_a_character_boundary() {
    assert_eq!(
        html_to_text("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", 3).as_deref(),
        Some("\u{e9}\u{e9}\u{2026}")
    );
    assert_eq!(
        html_to_text("\u{e9}\u{e9}\u{e9}", 3).as_deref(),
        Some("\u{e9}\u{e9}\u{e9}"),
        "text that fits is not cut"
    );
    assert_eq!(
        html_to_text("ab cd", 4).as_deref(),
        Some("ab\u{2026}"),
        "no space is left before the ellipsis"
    );
    assert_eq!(html_to_text("abc", 1).as_deref(), Some("\u{2026}"));
}

#[test]
fn malformed_markup_takes_linear_time() {
    // Each of these makes a naive reader rescan the rest of the input at every `<`.
    for html in [
        "<a".repeat(50_000),
        "<!--".repeat(50_000),
        "<script>".repeat(50_000),
        "<a href=\"".repeat(50_000),
        format!("{}>", "<".repeat(50_000)),
    ] {
        let started = std::time::Instant::now();
        let text = html_to_text(&html, MAX_SUMMARY_CHARS);
        let links = reference_links(&html, MAX_REFERENCE_LINKS);
        assert!(links.is_empty(), "{links:?}");
        assert!(
            text.as_deref()
                .is_none_or(|t| t.chars().count() <= MAX_SUMMARY_CHARS),
            "{text:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{} bytes took {:?}",
            html.len(),
            started.elapsed()
        );
    }
}

#[test]
fn reference_links_keep_only_the_http_links_the_source_wrote() {
    for (html, expected) in [
        ("<a href=\"\">empty</a>", &[][..]),
        ("<a href=>empty</a><a href>bare</a><a>none</a>", &[]),
        (
            "<a href=https://example.com/unquoted>u</a>",
            &["https://example.com/unquoted"][..],
        ),
        ("<a href=\"https://example.com/open", &[]),
        ("<a href=\"https://example.com/never-quoted>x</a>", &[]),
        (
            "<a href='https://example.com/x' href=\"https://other.example/\">",
            &["https://example.com/x"],
        ),
        (
            "<A title=\"a > b\" HREF = \"https://Example.COM/y?utm_source=z&amp;b=2#frag\">",
            &["https://example.com/y?b=2"],
        ),
        (
            "<a href=\"javascript:alert(1)\">j</a><a href=\" JavaScript:x\">j</a>\
                 <a href=\"data:text/html,x\">d</a><a href=\"mailto:a@example.com\">m</a>\
                 <a href=\"/relative\">r</a><a href=\"relative.html\">r</a>\
                 <a href=\"//proto-relative.example/x\">p</a><a href=\"ftp://x.example/\">f</a>",
            &[],
        ),
        ("<a href=\"https://example.com/a b\">space</a>", &[]),
        ("<a href=\"https://user@example.com/\">userinfo</a>", &[]),
        (
            "<abbr href=\"https://example.com/\">x</abbr><link href=\"https://example.com/\">",
            &[],
        ),
        ("</a href=\"https://example.com/\">", &[]),
        ("< a href=\"https://example.com/\">", &[]),
        ("<a href=\"https://example.com/\"", &[]),
        ("<!-- <a href=\"https://hidden.example/\">h</a> -->", &[]),
        ("<script><a href=\"https://hidden.example/\"></script>", &[]),
        (
            "<a href=\"https://example.com/\">1</a><a href=\"HTTPS://EXAMPLE.COM:443\">2</a>",
            &["https://example.com"],
        ),
    ] {
        assert_eq!(
            reference_links(html, MAX_REFERENCE_LINKS),
            expected,
            "{html:?}"
        );
    }
    let too_long = format!(
        "<a href=\"https://example.com/{}\">",
        "x".repeat(MAX_REFERENCE_BYTES)
    );
    assert!(reference_links(&too_long, MAX_REFERENCE_LINKS).is_empty());
}

#[test]
fn reference_links_are_capped_in_first_seen_order() {
    let anchors: Vec<String> = (0..20)
        .map(|n| format!("<a href=\"https://example.com/{n}\">{n}</a>"))
        .collect();
    let links = reference_links(&anchors.concat(), MAX_REFERENCE_LINKS);
    let expected: Vec<String> = (0..MAX_REFERENCE_LINKS)
        .map(|n| format!("https://example.com/{n}"))
        .collect();
    assert_eq!(links, expected);
}

#[test]
fn hibp_errors_keep_their_cause() {
    assert_eq!(
        outcome_kind(&HibpError::Unauthorized("x".into())),
        SourceOutcomeKind::AuthRejected
    );
    assert_eq!(
        outcome_kind(&HibpError::Decode("x".into())),
        SourceOutcomeKind::SchemaDrift
    );
    let no_response = HibpError::Transport {
        message: "request failed".into(),
        kind: SourceOutcomeKind::TlsFailure,
    };
    assert_eq!(outcome_kind(&no_response), SourceOutcomeKind::TlsFailure);
    assert_eq!(
        outcome_kind(&HibpError::NotAnAnswer(SourceOutcomeKind::BotWaf)),
        SourceOutcomeKind::BotWaf
    );
    let statuses = [
        (HibpError::BadRequest("x".into()), Some(400)),
        (HibpError::Unauthorized("x".into()), Some(401)),
        (HibpError::Forbidden("x".into()), Some(403)),
        (HibpError::RateLimited { retry_after: None }, Some(429)),
        (
            HibpError::Server {
                status: 503,
                body: String::new(),
            },
            Some(503),
        ),
        (
            HibpError::UnexpectedStatus {
                status: 418,
                body: String::new(),
            },
            Some(418),
        ),
        (no_response, None),
        (HibpError::Decode("x".into()), None),
        (HibpError::MissingKey, None),
    ];
    for (error, status) in statuses {
        assert_eq!(error.http_status(), status, "{error:?}");
    }
}

/// Answers every request with one fixed result, so a client can be asked more than once.
struct Answers(Result<crate::http::Response, crate::http::TransportFailure>);

impl Transport for Answers {
    fn send(
        &self,
        _: &crate::http::Request,
    ) -> Result<crate::http::Response, crate::http::TransportFailure> {
        self.0.clone()
    }
}

/// A keyed HIBP client over [`Answers`], with local pacing off.
fn hibp_answering(
    answer: Result<crate::http::Response, crate::http::TransportFailure>,
) -> HibpClient {
    let Some(key) = crate::hibp::key::ApiKey::new("0123456789abcdef0123456789abcdef") else {
        panic!("the fixture key is a valid HIBP key");
    };
    HibpClient::with_config(
        std::sync::Arc::new(Answers(answer)),
        crate::hibp::client::Auth::ApiKey(key),
        crate::hibp::client::HibpConfig::default(),
        std::sync::Arc::new(crate::hibp::rate_limit::RateLimiter::per_minute(0)),
    )
}

/// A `DeHashed` client over [`Answers`], with local pacing off.
fn dehashed_answering(
    answer: Result<crate::http::Response, crate::http::TransportFailure>,
) -> DehashedClient {
    let secret = crate::keys::Secret::new("dh-test-key-0123456789".to_owned())
        .unwrap_or_else(|e| panic!("fixture secret: {e}"));
    DehashedClient::with_limiter(
        std::sync::Arc::new(Answers(answer)),
        secret,
        crate::hibp::rate_limit::RateLimiter::per_minute(0),
    )
}

/// A response with `status`, `headers` and no body.
fn status_only(status: u16, headers: &[(&str, &str)]) -> crate::http::Response {
    crate::http::Response {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).into(), (*value).into()))
            .collect(),
        body: Vec::new(),
        truncated: false,
    }
}

/// A Cloudflare interstitial served with 200 in place of the API's answer.
const CHALLENGE: &str = "<html><title>Just a moment...</title>\
        <script src=\"https://challenges.cloudflare.com/x\"></script></html>";

#[test]
fn a_keyed_leg_without_a_response_keeps_the_cause_the_fetch_saw() {
    for kind in [
        SourceOutcomeKind::DnsFailure,
        SourceOutcomeKind::TlsFailure,
        SourceOutcomeKind::TtfbTimeout,
    ] {
        // A real no-response (the request was attempted, so `blocked` is false): the leg's row
        // keeps the cause the fetch saw, which `SourceReach` reads as a no-response (exit 69).
        let failure = || {
            Err(crate::http::TransportFailure {
                kind,
                detail: "ada@example.com".into(),
                blocked: false,
            })
        };
        let hibp = hibp_leg(
            &hibp_answering(failure()),
            "ada@example.com",
            "scan-1",
            7,
            &mut Report::default(),
        );
        assert_eq!(hibp.kind, kind, "{hibp:?}");
        let dehashed = dehashed_leg(
            &dehashed_answering(failure()),
            "ada@example.com",
            "scan-1",
            7,
            &mut Report::default(),
        );
        assert_eq!(dehashed.kind, kind, "{dehashed:?}");
    }
}

#[test]
fn a_blocked_keyed_leg_is_refused_before_sending() {
    // The egress policy refused the request before it was sent (`blocked` is true): the leg's
    // row is `RefusedBeforeSending`, which `SourceReach` reads as a refusal (exit 77), never a
    // reached-but-silent transport failure.
    let blocked = || {
        Err(crate::http::TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "ada@example.com".into(),
            blocked: true,
        })
    };
    let hibp = hibp_leg(
        &hibp_answering(blocked()),
        "ada@example.com",
        "scan-1",
        7,
        &mut Report::default(),
    );
    assert_eq!(
        hibp.kind,
        SourceOutcomeKind::RefusedBeforeSending,
        "{hibp:?}"
    );
    assert!(!hibp.kind.is_transport_failure(), "{hibp:?}");
    let dehashed = dehashed_leg(
        &dehashed_answering(blocked()),
        "ada@example.com",
        "scan-1",
        7,
        &mut Report::default(),
    );
    assert_eq!(
        dehashed.kind,
        SourceOutcomeKind::RefusedBeforeSending,
        "{dehashed:?}"
    );
    assert!(!dehashed.kind.is_transport_failure(), "{dehashed:?}");
}

#[test]
fn a_challenge_page_is_a_wall_on_a_keyed_leg_not_a_network_failure() {
    let page = || Ok(crate::test_support::html_ok(CHALLENGE));
    let hibp = hibp_leg(
        &hibp_answering(page()),
        "ada@example.com",
        "scan-1",
        7,
        &mut Report::default(),
    );
    assert_eq!(hibp.kind, SourceOutcomeKind::BotWaf, "{hibp:?}");
    let dehashed = dehashed_leg(
        &dehashed_answering(page()),
        "ada@example.com",
        "scan-1",
        7,
        &mut Report::default(),
    );
    assert_eq!(dehashed.kind, SourceOutcomeKind::BotWaf, "{dehashed:?}");
}

#[test]
fn a_hibp_rate_limit_records_its_status_and_pause() {
    // Longer than the client waits for, so it gives up at once; a pause past the hour every
    // other leg's fetch allows is recorded at that bound.
    for (sent, recorded) in [("120", 120), ("999999", 3600)] {
        let limited = status_only(429, &[("retry-after", sent)]);
        let outcome = hibp_leg(
            &hibp_answering(Ok(limited)),
            "ada@example.com",
            "scan-1",
            7,
            &mut Report::default(),
        );
        assert_eq!(
            (outcome.kind, outcome.http_status, outcome.retry_after_secs),
            (SourceOutcomeKind::RateLimited, Some(429), Some(recorded)),
            "{sent}: {outcome:?}"
        );
    }
}

#[test]
fn a_dehashed_failure_reads_the_same_on_the_exposure_leg_and_in_the_collector_receipt() {
    let answers = [
        Ok(status_only(400, &[])),
        Ok(status_only(401, &[])),
        Ok(status_only(403, &[])),
        Ok(status_only(429, &[("retry-after", "42")])),
        Ok(status_only(429, &[])),
        Ok(status_only(503, &[])),
        Ok(status_only(418, &[])),
        Ok(status_only(302, &[])),
        Ok(crate::test_support::html_ok(CHALLENGE)),
        Ok(crate::test_support::json_ok(r#"{"results": "x"}"#)),
        Err(crate::http::TransportFailure {
            kind: SourceOutcomeKind::DnsFailure,
            detail: "ada@example.com".into(),
            blocked: false,
        }),
    ];
    let selector = Entity::new(EntityKind::Email, "ada@example.com", 1.0, "scan-1");
    for answer in answers {
        let client = dehashed_answering(answer.clone());
        // Each path on its own breaker: after a 429 or a failure a paced source pauses, so the
        // second path would otherwise read the pause, not the answer.
        let leg = crate::test_support::on_fresh_breakers(|| {
            dehashed_leg(
                &client,
                "ada@example.com",
                "scan-1",
                7,
                &mut Report::default(),
            )
        });
        let batch = crate::test_support::on_fresh_breakers(|| {
            dehashed::collect(
                &client,
                &selector,
                dehashed::Purpose::OwnAccount,
                &crate::collector::CollectionLimits::default(),
                7,
            )
            .unwrap_or_else(|e| panic!("{answer:?}: {e:?}"))
        });
        assert!(!leg.kind.is_accepted(), "{answer:?} gave {leg:?}");
        assert_eq!(leg, batch.receipts[0].outcome, "{answer:?}");
    }
}

/// Every leg's first request waits here until all the legs have sent one, or five seconds
/// pass, then is answered 404. Legs that run one after another never meet: the first waits
/// out the five seconds alone.
struct Meeting {
    inside: std::sync::Mutex<usize>,
    arrived: std::sync::Condvar,
    want: usize,
    together: std::sync::Mutex<Vec<bool>>,
}

/// One leg's transport into a [`Meeting`].
struct Attendee {
    meeting: std::sync::Arc<Meeting>,
    sent: std::sync::Mutex<bool>,
}

impl Transport for Attendee {
    fn send(
        &self,
        _: &crate::http::Request,
    ) -> Result<crate::http::Response, crate::http::TransportFailure> {
        use std::sync::PoisonError;
        let first = !std::mem::replace(
            &mut *self.sent.lock().unwrap_or_else(PoisonError::into_inner),
            true,
        );
        if first {
            let meeting = &self.meeting;
            let mut inside = meeting
                .inside
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *inside += 1;
            meeting.arrived.notify_all();
            let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while *inside < meeting.want && std::time::Instant::now() < until {
                let left = until.saturating_duration_since(std::time::Instant::now());
                inside = meeting
                    .arrived
                    .wait_timeout(inside, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            let met = *inside >= meeting.want;
            drop(inside);
            meeting
                .together
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(met);
        }
        Ok(crate::http::Response {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
            truncated: false,
        })
    }
}

#[test]
fn the_keyed_legs_run_at_the_same_time_and_report_in_their_order() {
    let meeting = std::sync::Arc::new(Meeting {
        inside: std::sync::Mutex::new(0),
        arrived: std::sync::Condvar::new(),
        want: 4,
        together: std::sync::Mutex::default(),
    });
    let attendee = || Attendee {
        meeting: meeting.clone(),
        sent: std::sync::Mutex::new(false),
    };
    let Some(key) = crate::hibp::key::ApiKey::new("0123456789abcdef0123456789abcdef") else {
        panic!("the fixture key is a valid HIBP key");
    };
    let hibp = HibpClient::with_config(
        std::sync::Arc::new(attendee()),
        crate::hibp::client::Auth::ApiKey(key),
        crate::hibp::client::HibpConfig::default(),
        std::sync::Arc::new(crate::hibp::rate_limit::RateLimiter::per_minute(0)),
    );
    let secret = crate::keys::Secret::new("dh-test-key-0123456789".to_owned())
        .unwrap_or_else(|e| panic!("fixture secret: {e}"));
    let dehashed = DehashedClient::new(std::sync::Arc::new(attendee()), secret);
    let (stolen_tax, oathnet) = (attendee(), attendee());
    let keys = Keys::parse(&format!(
        "{}=st-test-key-0123456789abcdef\n{}=on-test-key-0123456789abcdef\n",
        stolen_tax::KEY_SLOT,
        oathnet::KEY_SLOT
    ))
    .unwrap_or_else(|e| panic!("fixture keys: {e}"));
    let sources = Sources {
        hibp: Some(&hibp),
        stolen_tax: Some((&stolen_tax, &keys)),
        oathnet: Some((&oathnet, &keys)),
        dehashed: Some(&dehashed),
        ..Sources::default()
    };
    let started = std::time::Instant::now();
    let ExposureRun::Printed { report, .. } = run(sources, "ada@example.com", 7) else {
        panic!("expected a printed report");
    };
    let together = meeting
        .together
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        together,
        vec![true; 4],
        "each leg's first request found the other three in flight"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "no leg waited for another"
    );
    let legs: Vec<&str> = report.outcomes.iter().map(|o| o.module.as_str()).collect();
    assert_eq!(
        legs,
        [SOURCE, STOLEN_TAX_SOURCE, OATHNET_SOURCE, DEHASHED_SOURCE],
        "the outcomes fold in the legs' order"
    );
}
