//! Parser for a leaked breach **SQL dump** — one or more `INSERT INTO
//! \`table\` (\`col1\`, \`col2\`, ...) VALUES (v1, v2, ...), (v3, v4, ...);`
//! statements, the shape a `mysqldump`-style export of a compromised user
//! table takes. Shared helpers (`ImportStats`, persistence, `push_*`
//! extractors) live in `super` and are reached via `use super::*`.
//!
//! Column semantics are read ONLY from the `INSERT`'s own explicit column
//! list — never guessed from position, and never recovered from a separate
//! `CREATE TABLE` statement elsewhere in the dump. A `CREATE TABLE`'s column
//! order can differ from an `INSERT`'s (a dump tool may reorder, or the two
//! statements may describe different tool versions of the "same" table), so
//! trusting it would risk silently mis-attributing a value to the wrong
//! field — a `phone` value read as a `password`. An `INSERT` with no explicit
//! column list is therefore quarantined rather than guessed at (RULE.md: no
//! fabricated findings).
//!
//! String values are unescaped supporting BOTH common dump dialects: a
//! backslash-escaped byte (`\n`, `\t`, `\r`, `\0`, `\'`, `\\`, ...) — the
//! `mysqldump` default — and a doubled quote (`''`) — the standard-SQL
//! escape `pg_dump` and others use. Both are recognised unconditionally, so
//! the parser never needs to guess which dialect produced a given dump.

use super::*;

use crate::core::confidence;
use crate::core::entity::{Entity, EntityKind, Evidence};
use regex::Regex;
use std::sync::OnceLock;

/// The byte spans of `body` that lie inside a single-quoted SQL string literal.
///
/// A statement-header regex match whose start falls inside one of these spans is
/// NOT a real statement: it is `INSERT INTO ... VALUES` text sitting in a column
/// VALUE — a leaked bio, a stored message, a logged query — and using it as a
/// statement boundary truncates the enclosing statement mid-string, so the tuple
/// parser hits an unterminated string and quarantines the rest of the table.
/// That is silent breach-data loss on the exact path this parser exists to fix
/// (reproduced: an `INSERT INTO t (c) VALUES (1)` substring in one `bio` value
/// dropped every row in a `mysqldump --extended-insert` table).
///
/// Scans the whole body once, tracking string state with the SAME two escape
/// dialects [`parse_value_tuple`] honours — mysqldump's `\'` backslash and
/// standard SQL's `''` doubled quote — so detection and parsing agree on where
/// strings are.
fn string_literal_spans(body: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut chars = body.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '\'' {
            continue;
        }
        let mut end = body.len();
        while let Some((j, d)) = chars.next() {
            match d {
                // A backslash escapes the next char (mysqldump dialect): skip it,
                // so an escaped quote never closes the string.
                '\\' => {
                    chars.next();
                }
                // A doubled quote is an escaped quote (standard-SQL dialect): the
                // pair stays inside the string.
                '\'' if chars.peek().is_some_and(|&(_, e)| e == '\'') => {
                    chars.next();
                }
                // A lone quote closes the string (end is the byte AFTER it).
                '\'' => {
                    end = j + 1;
                    break;
                }
                _ => {}
            }
        }
        spans.push((i, end));
    }
    spans
}

/// The `INSERT INTO <table> (<columns>) VALUES` header, case-insensitive.
/// Captures the table name (group 1, informational only — used as the
/// provenance/database-name label, never for column semantics) and the raw
/// column-list text (group 2). Matched once per statement via `captures_iter`;
/// each match's end is where that statement's `(v1, v2, ...), ...` tuples
/// begin.
fn insert_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)insert\s+into\s+[`"\[]?([\w.]+)[`"\]]?\s*\(([^()]*)\)\s*values\s*"#)
            .expect("constant sql insert-header regex")
    })
}

/// Detect a SQL-dump export by its content: at least one real
/// `INSERT INTO ... (...) VALUES` statement header. This shape is
/// distinctive enough (unlike a raw combolist's bare colon-delimited lines)
/// that a single match is sufficient evidence — real prose essentially never
/// contains this exact structural pattern.
pub(crate) fn looks_like_sql_dump(body: &str) -> bool {
    insert_header_re().is_match(body)
}

/// Skip ASCII/Unicode whitespace on a char-by-char SQL scanner.
fn skip_ws(chars: &mut std::iter::Peekable<std::str::Chars>) {
    while chars.next_if(|c| c.is_whitespace()).is_some() {}
}

/// Parse one `(v1, v2, ...)` value tuple, `chars` positioned at the opening
/// `(`. Returns `None` (a malformed/truncated tuple — unterminated string or
/// missing closing paren) rather than a partial result, so the caller always
/// either has a complete row or quarantines it whole.
fn parse_value_tuple(
    chars: &mut std::iter::Peekable<std::str::Chars>,
) -> Option<Vec<Option<String>>> {
    if chars.next() != Some('(') {
        return None;
    }
    let mut values = Vec::new();
    loop {
        skip_ws(chars);
        match chars.peek() {
            Some('\'') => {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next()? {
                        '\\' => {
                            let escaped = chars.next()?;
                            s.push(match escaped {
                                'n' => '\n',
                                't' => '\t',
                                'r' => '\r',
                                '0' => '\0',
                                other => other,
                            });
                        }
                        '\'' if chars.peek() == Some(&'\'') => {
                            chars.next();
                            s.push('\'');
                        }
                        '\'' => break,
                        c => s.push(c),
                    }
                }
                values.push(Some(s));
            }
            Some(_) => {
                let mut tok = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ',' || c == ')' {
                        break;
                    }
                    tok.push(c);
                    chars.next();
                }
                let trimmed = tok.trim();
                values.push(
                    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null") {
                        None
                    } else {
                        Some(trimmed.to_string())
                    },
                );
            }
            None => return None,
        }
        skip_ws(chars);
        match chars.next() {
            Some(',') => continue,
            Some(')') => break,
            _ => return None,
        }
    }
    Some(values)
}

/// Parse every `(...)`-tuple row following one statement's `VALUES` keyword,
/// `region` being the dump text from right after that keyword up to (but not
/// including) the next statement's header — or the end of the dump. Returns
/// the well-formed rows and a count of malformed ones (a tuple that failed to
/// close cleanly): the whole rest of a statement is quarantined together
/// once a tuple breaks, since there is no safe resync point inside a
/// corrupted value list.
fn parse_row_tuples(region: &str) -> (Vec<Vec<Option<String>>>, usize) {
    let mut rows = Vec::new();
    let mut chars = region.chars().peekable();
    loop {
        skip_ws(&mut chars);
        if chars.peek() != Some(&'(') {
            break;
        }
        match parse_value_tuple(&mut chars) {
            Some(vals) => rows.push(vals),
            None => return (rows, 1),
        }
        skip_ws(&mut chars);
        match chars.peek() {
            Some(',') => {
                chars.next();
            }
            _ => break,
        }
    }
    (rows, 0)
}

/// Split a raw `col1, \`col2\`, "col3"` column-list into trimmed, sigil-stripped
/// names, dropping any empty entry (a trailing comma).
fn parse_column_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|c| {
            c.trim()
                .trim_matches(|ch: char| matches!(ch, '`' | '"' | '[' | ']'))
                .to_string()
        })
        .filter(|c| !c.is_empty())
        .collect()
}

/// Parse a SQL-dump export into entities + stats, following the exact same
/// column-name-based field mapping, confidence levels and evidence shape as
/// the DeHashed CSV parser (`csv::parse_dehashed_csv`) — this is structurally
/// the same "one row = one leaked record" breach table, just SQL-encoded, so
/// it shares that authority's design rather than inventing a second one.
pub(super) fn parse_sql_dump(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen = std::collections::HashSet::new();

    let header_re = insert_header_re();
    // Only headers OUTSIDE a string literal are real statement boundaries; a
    // match inside a quoted value must never split a statement (see
    // `string_literal_spans`). Filtering here means the region below spans the
    // whole real statement, and the string-aware tuple parser handles any
    // `INSERT ... VALUES` text that lives inside a value.
    let string_spans = string_literal_spans(body);
    let in_string = |off: usize| string_spans.iter().any(|&(s, e)| s <= off && off < e);
    let matches: Vec<_> = header_re
        .captures_iter(body)
        .filter(|caps| {
            !in_string(
                caps.get(0)
                    .expect("capture 0 is always the whole match")
                    .start(),
            )
        })
        .collect();
    for (i, caps) in matches.iter().enumerate() {
        let whole = caps.get(0).expect("capture 0 is always the whole match");
        let table = caps.get(1).map_or("sql-dump", |m| m.as_str());
        let Some(cols_raw) = caps.get(2) else {
            stats.malformed_lines += 1;
            continue;
        };
        let columns = parse_column_list(cols_raw.as_str());
        if columns.is_empty() {
            stats.malformed_lines += 1;
            continue;
        }

        let region_end = matches.get(i + 1).map_or(body.len(), |next| {
            next.get(0)
                .expect("capture 0 is always the whole match")
                .start()
        });
        let region = &body[whole.end()..region_end];
        let (rows, malformed_tuples) = parse_row_tuples(region);
        stats.malformed_lines += malformed_tuples;

        let email_i = find_column(&columns, &["email", "e_mail", "email_address", "mail"]);
        let user_i = find_column(
            &columns,
            &["username", "user", "login", "user_name", "handle"],
        );
        let name_i = find_column(
            &columns,
            &["name", "full_name", "fullname", "display_name", "realname"],
        );
        let pass_i = find_column(&columns, &["password", "pass", "passwd", "pwd"]);
        let hashed_idxs: Vec<usize> = columns
            .iter()
            .enumerate()
            .filter(|(_, c)| column_matches(c, &["password_hash", "hashed_password", "hash"]))
            .map(|(i, _)| i)
            .collect();
        let phone_i = find_column(
            &columns,
            &["phone", "mobile", "telephone", "phone_number", "tel"],
        );
        let addr_i = find_column(&columns, &["address", "street_address", "home_address"]);
        let ip_i = find_column(&columns, &["ip", "ip_address", "last_ip", "reg_ip"]);

        for row in &rows {
            if row.len() != columns.len() {
                stats.malformed_lines += 1;
                continue;
            }
            let get = |idx: Option<usize>| -> Option<&str> {
                idx.and_then(|i| row.get(i))
                    .and_then(|v| v.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            };

            let email = get(email_i).map(str::to_ascii_lowercase);
            let label = email
                .as_deref()
                .or_else(|| get(name_i))
                .or_else(|| get(user_i))
                .unwrap_or("breach record");

            let mut ev = Evidence::new(
                "import:sql_dump",
                format!("SQL-dump breach record ({table}) — {label}"),
            )
            .with_attr("database_name", table)
            .with_attr("source", "sql-dump");
            for (lbl, v) in [
                ("email", email.as_deref()),
                ("username", get(user_i)),
                ("name", get(name_i)),
                ("phone", get(phone_i)),
                ("address", get(addr_i)),
                ("ip", get(ip_i)),
            ] {
                if let Some(v) = v {
                    ev = ev.with_attr(lbl, v);
                }
            }

            let mut push = |mut e: Entity, tag: &str| {
                e.tag("import");
                e.tag("sql-dump");
                e.tag("breach");
                e.tag(tag);
                e.add_evidence(ev.clone());
                entities.push(e);
            };

            if let Some(em) = &email
                && em.contains('@')
                && !crate::core::validation::is_fragment_value(&EntityKind::Email, em)
                && seen.insert(format!("em:{em}"))
            {
                push(
                    Entity::new(EntityKind::Email, em, confidence::ATTRIBUTED, sid),
                    "breach",
                );
                stats.emails += 1;
            }
            match get(user_i).map(|un| (un, identity_column_kind(un))) {
                // The login column holds the account's email (no separate email
                // column, or an empty one): it must reach the graph as the Email
                // it is, deduplicated against the email column via the same key.
                Some((un, Some(EntityKind::Email))) => {
                    let em = un.to_ascii_lowercase();
                    if !crate::core::validation::is_fragment_value(&EntityKind::Email, &em)
                        && seen.insert(format!("em:{em}"))
                    {
                        push(
                            Entity::new(EntityKind::Email, &em, confidence::ATTRIBUTED, sid),
                            "breach",
                        );
                        stats.emails += 1;
                    }
                }
                Some((un, Some(EntityKind::Username)))
                    if seen.insert(format!("un:{}", un.to_lowercase())) =>
                {
                    push(
                        Entity::new(EntityKind::Username, un, confidence::MEDIUM_PLUS, sid),
                        "breach",
                    );
                    stats.usernames += 1;
                }
                _ => {}
            }
            if let Some(nm) = get(name_i)
                && nm.split_whitespace().count() >= 2
                && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, nm)
                && seen.insert(format!("pn:{}", nm.to_lowercase()))
            {
                push(
                    Entity::new(EntityKind::Person, nm, confidence::NOTABLE, sid),
                    "breach",
                );
                stats.persons += 1;
            }
            if let Some(pw) = get(pass_i)
                && pw.chars().count() >= 4
            {
                if seen.insert(format!("cr:{pw}")) {
                    stats.credentials += 1;
                }
                push(
                    Entity::new(EntityKind::Credential, pw, confidence::MEDIUM_SOLID, sid),
                    "plaintext-credential",
                );
            }
            for hi in &hashed_idxs {
                if let Some(h) = get(Some(*hi))
                    && h.len() >= 8
                {
                    if seen.insert(format!("cr:{h}")) {
                        stats.credentials += 1;
                    }
                    push(
                        Entity::new(EntityKind::Credential, h, confidence::MEDIUM_PLUS, sid),
                        "password-hash",
                    );
                }
            }
            if let Some(ph) = get(phone_i).and_then(crate::core::validation::to_e164_au)
                && seen.insert(format!("ph:{ph}"))
            {
                push(
                    Entity::new(EntityKind::Phone, &ph, confidence::NOTABLE, sid),
                    "breach",
                );
                stats.phones += 1;
            }
            if let Some(addr) = get(addr_i)
                && crate::core::validation::is_specific_residence(addr)
                && seen.insert(format!("ad:{}", addr.to_ascii_lowercase()))
            {
                push(
                    Entity::new(EntityKind::Address, addr, confidence::MEDIUM_SOLID, sid),
                    "breach",
                );
                stats.addresses += 1;
            }
            if let Some(ip) = get(ip_i)
                && !crate::core::validation::is_bogus_ip(ip)
                && ip.parse::<std::net::IpAddr>().is_ok()
                && seen.insert(format!("ip:{ip}"))
            {
                push(
                    Entity::new(EntityKind::IpAddress, ip, confidence::MEDIUM, sid),
                    "breach",
                );
                stats.ips += 1;
            }

            stats.breach_records += 1;
        }
    }

    push_macs(body, sid, "sql_dump", &mut entities);
    push_crypto(body, sid, "sql_dump", &mut entities);
    push_api_keys(body, sid, "sql_dump", &mut entities);
    push_ibans(body, sid, "sql_dump", &mut entities);
    (entities, stats)
}

pub(super) async fn cmd_import_sql_dump(body: &str, output: &str) -> Result<()> {
    run_import(
        "Importing SQL-dump breach export...",
        "sql-dump",
        output,
        |sid| {
            let (entities, stats) = parse_sql_dump(body, sid);
            ParsedImport::new(entities, stats)
        },
    )
    .await
}
