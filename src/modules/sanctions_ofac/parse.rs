//! Pure parsing for OFAC's SDN.CSV "legacy flat file" format: no header row,
//! selectively-quoted fields (only string-content fields are quoted; numeric
//! and placeholder fields are bare), `""` as the in-field quote escape, and
//! `-0- ` (note the trailing space) as OFAC's own null/absent-field
//! placeholder. Column order and the `-0- ` placeholder verified directly
//! against a live pull of the real file (fetched during this module's design,
//! not assumed from documentation): 12 columns, always present even when
//! empty —
//! `ent_num,SDN_Name,SDN_Type,Program,Title,Call_Sign,Vess_type,Tonnage,GRT,Vess_flag,Vess_owner,Remarks`.
//!
//! Real sample rows observed (2026-07-09 pull):
//! ```text
//! 2674,"ABBAS, Abu","individual","SDGT","Director of ...",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"DOB 10 Dec 1948; ..."
//! 4238,"MAR AZUL","vessel","CUBA",-0- ,"CL2192","Tug",-0- ,"212","Cuba","Samir de Navegacion S.A.",-0-
//! 36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0-
//! ```
//! `SDN_Type` is blank/`-0- ` for organisations (there is no literal
//! "entity"/"organisation" tag in the data) — the third sample row above is a
//! company, not a person, despite its empty `SDN_Type`.

/// One parsed SDN record. Only the columns this module maps to entities are
/// kept as owned fields; `Vess_type`/vessel-only columns are read only to
/// classify [`SdnKind::Vessel`]/[`SdnKind::Aircraft`] and are then discarded.
/// Which of OFAC's two lists a row came from. They carry the same CSV schema
/// and are screened together, but they are not the same designation: an SDN
/// entry is a full-blocking designation, a Consolidated (non-SDN) entry is a
/// sectoral / FSE / NS-ISA / PLC / … sanction that is NOT full blocking. Every
/// finding names its list, so a consolidated-list row can never be reported
/// as an SDN match (which is what happened when the two lists were merged into
/// one unlabelled set — `docs/PROVIDER_SWEEP_BACKLOG.md` #35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OfacList {
    /// `SDN.CSV` — the Specially Designated Nationals list (full blocking).
    Sdn,
    /// `CONS_PRIM.CSV` — the Consolidated (non-SDN) sanctions list.
    Consolidated,
}

impl OfacList {
    /// The register name stamped on every finding's evidence.
    pub(super) fn register(self) -> &'static str {
        match self {
            Self::Sdn => "OFAC Specially Designated Nationals (SDN) List",
            Self::Consolidated => "OFAC Consolidated (non-SDN) Sanctions List",
        }
    }

    /// Short label for summaries (`OFAC SDN list match: …`).
    pub(super) fn short(self) -> &'static str {
        match self {
            Self::Sdn => "SDN",
            Self::Consolidated => "Consolidated (non-SDN)",
        }
    }

    /// The per-list tag beside the shared `sanctions` / `ofac` tags.
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Sdn => "ofac-sdn",
            Self::Consolidated => "ofac-consolidated",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct SdnRecord {
    pub(super) ent_num: u64,
    /// The OFAC list this row was read from — see [`OfacList`].
    pub(super) list: OfacList,
    pub(super) name: String,
    pub(super) kind: SdnKind,
    pub(super) program: String,
    /// The `Title` column (role/position, e.g. "Director of ..."). Carries
    /// misattribution-relevant identity data — see `T2.107` — so it is kept
    /// and surfaced as evidence rather than discarded like the vessel-only
    /// columns.
    pub(super) title: String,
    pub(super) remarks: String,
}

/// What kind of subject one SDN row names. A blank `SDN_Type` field is the
/// organisation bucket in practice (verified against live data — there is no
/// literal "entity"/"organisation" string in the file); `Vessel`/`Aircraft`
/// name the physical asset itself, not a person or company, so they map to
/// neither `EntityKind::Person` nor `EntityKind::Organisation` and are simply
/// not emitted as entities (no matching `EntityKind` exists for either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SdnKind {
    Individual,
    Organisation,
    Vessel,
    Aircraft,
}

impl SdnKind {
    fn from_field(field: &str) -> Self {
        match field {
            s if s.eq_ignore_ascii_case("individual") => Self::Individual,
            s if s.eq_ignore_ascii_case("vessel") => Self::Vessel,
            s if s.eq_ignore_ascii_case("aircraft") => Self::Aircraft,
            _ => Self::Organisation,
        }
    }
}

/// True if a raw CSV field is OFAC's null placeholder — bare `-0-`, or with
/// the trailing space the real file emits (`-0- `), after trimming
/// surrounding whitespace either way — or genuinely empty.
fn is_absent(field: &str) -> bool {
    let t = field.trim();
    t.is_empty() || t == "-0-"
}

/// Split one CSV line into its raw fields. A small hand-rolled quote-aware
/// state machine rather than a full CSV parser dependency: this format's
/// quoting is simple (only some fields are quoted; `""` escapes a literal
/// quote inside a quoted field) and fully exercised by the tests below
/// against real sample rows, so a minimal, auditable implementation is
/// preferable to a new dependency for one well-defined format.
pub(super) fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                // `""` inside a quoted field is an escaped literal quote.
                cur.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

/// Parse the whole SDN.CSV body into records, skipping any row that doesn't
/// have the expected 12 fields or whose `ent_num`/name aren't usable — total,
/// never panics: a truncated download or a format drift degrades to fewer
/// records, never a crash.
pub(super) fn parse_sdn_csv(body: &str, list: OfacList) -> Vec<SdnRecord> {
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| parse_sdn_line(line, list))
        .collect()
}

fn parse_sdn_line(line: &str, list: OfacList) -> Option<SdnRecord> {
    let fields = split_csv_line(line);
    if fields.len() < 12 {
        return None;
    }
    let ent_num: u64 = fields[0].trim().parse().ok()?;
    let name = fields[1].trim();
    if name.is_empty() {
        return None;
    }
    let kind = SdnKind::from_field(fields[2].trim());
    let program = fields[3].trim();
    let title = fields[4].trim();
    let remarks = fields[11].trim();
    Some(SdnRecord {
        ent_num,
        list,
        name: name.to_string(),
        kind,
        program: if is_absent(program) {
            String::new()
        } else {
            program.to_string()
        },
        title: if is_absent(title) {
            String::new()
        } else {
            title.to_string()
        },
        remarks: if is_absent(remarks) {
            String::new()
        } else {
            remarks.to_string()
        },
    })
}

/// Reorder OFAC's `"LAST, First Middle"` individual-name convention to
/// `"First Middle Last"` and title-case it — the same transform
/// `asic_persons::humanise_name` applies to its own register's
/// surname-first names, reimplemented here rather than shared across module
/// boundaries (each module owns its parsing helpers in this codebase).
pub(super) fn humanise_name(s: &str) -> String {
    let reordered = match s.split_once(',') {
        Some((surname, first)) => format!("{} {}", first.trim(), surname.trim()),
        None => s.trim().to_string(),
    };
    crate::util::str_util::title_case(&reordered.to_ascii_lowercase())
}

/// Case-insensitive alphanumeric tokens of at least 3 characters. Stricter
/// than the AU registers' 2-character floor (`asic_banned_orgs::name_tokens`)
/// — OFAC's pool is global and dominated by common transliterated names, so a
/// shorter token would collide far more often than in a national register.
pub(super) fn name_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True if every one of `tokens` appears in `record_name` as a whole word
/// (case-insensitive). Whole-word, not substring — a raw `.contains()` check
/// let a token land inside an unrelated word of a DIFFERENT sanctioned
/// entity's name (e.g. `"ali"` inside `"KHALID"`, where there is no
/// separator to carve "ali" out as its own token), which for a sanctions
/// screen means falsely associating an innocent person sharing a common name
/// with an entry for someone else entirely. Same precision gate
/// `acnc_charities`/`gleif_lei` use for their own full-text search results.
pub(super) fn record_name_matches(record_name: &str, tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }
    crate::util::str_util::whole_word_token_match(record_name, &tokens.join(" "))
}

#[cfg(test)]
mod tests {
    include!("parse_tests.rs");
}
