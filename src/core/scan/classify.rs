//! Domain and identity classification: mega-/infra-domain matching (so a scan
//! doesn't burn rounds mapping a platform's own estate), identity normalisation
//! and overlap (tying an alias back to the subject), and the wrong-identity-pivot
//! gate. Pure matching over strings + the curated INFRA/MEGA domain lists.

/// Dampening factor for domain targets. Mega-domains (top internet
/// properties that appear in nearly every search result) get a 0.15×
/// penalty so they expand after target-specific entities.
///
/// Calibrated from JLM scan: facebook.com (corr=337), reddit.com (111),
/// whitepages.com (83) are noise. Target-specific domains like
/// welcometothejungle.com (corr=262) are valuable but indistinguishable
/// by corroboration alone, so we blocklist by known mega-domain.
/// True if `domain` is — or is a subdomain of — a known mega-domain (a top
/// internet property that shows up in nearly every SERP). Used both to dampen
/// such a domain's expansion weight and (in the engine) to skip expanding one
/// that was only *incidentally* discovered, so a person/profile scan doesn't
/// burn rounds mapping a platform's own DNS/mail infrastructure.
/// Strip a leading `www.` ASCII-case-insensitively without allocating. Safe
/// on any input: the match can only succeed if the first 4 bytes are
/// literally the ASCII characters `w`/`W`, `w`/`W`, `w`/`W`, `.` (a
/// multi-byte UTF-8 continuation byte can never satisfy that comparison), so
/// the returned slice always starts on a real character boundary.
fn strip_www_ci(d: &str) -> &str {
    let b = d.as_bytes();
    if b.len() >= 4 && b[..4].eq_ignore_ascii_case(b"www.") {
        &d[4..]
    } else {
        d
    }
}

/// Registrable-suffix match: `d == m` or `d` ends with `.m` (www-stripped),
/// matched ASCII-case-insensitively against the raw value — zero allocation
/// (every `list` entry — MEGA_DOMAINS, INFRA_PROVIDER_ROOTS, INFRA_HOST_ONLY —
/// is lowercase ASCII, so
/// this is equivalent to the old lowercase-then-compare approach). The
/// suffix comparison runs on byte slices, not `&str`, so it never needs a
/// char-boundary check regardless of where it cuts.
fn matches_domain_suffix(domain: &str, list: &[&str]) -> bool {
    let d = strip_www_ci(domain.trim()).as_bytes();
    list.iter().any(|m| {
        let mb = m.as_bytes();
        d.eq_ignore_ascii_case(mb)
            || (d.len() > mb.len()
                && d[d.len() - mb.len() - 1] == b'.'
                && d[d.len() - mb.len()..].eq_ignore_ascii_case(mb))
    })
}

pub(crate) fn is_mega_domain(domain: &str) -> bool {
    matches_domain_suffix(domain, MEGA_DOMAINS)
}

/// Shared third-party infrastructure (managed DNS, registrar control-plane, CDN
/// apexes, ESP/transactional mail) that surfaces via NS/MX/SOA/reverse lookups
/// but is incidental to any subject — `ns10.dnsmadeeasy.com`,
/// `cns1.secureserver.net`, `u123.sendgrid.net`, `ns-664.awsdns-19.net`, … map
/// the provider's estate, not the target, so they are never worth deep-expanding.
/// ASCII-case-insensitive substring containment. `core` reaches `util` only
/// through the allow-list of pure leaf items in the
/// `core_does_not_import_util_directly` architecture guard, so this doesn't
/// reach for `util::str_util::find_ascii_ci`'s NEON scan —
/// the domain strings here are a handful of bytes, never a scraped body, so a
/// SIMD prefilter would buy nothing a plain scan doesn't already give.
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.len() >= needle.len()
        && (0..=haystack.len() - needle.len())
            .any(|i| haystack[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

pub(crate) fn is_infra_domain(domain: &str) -> bool {
    let d = strip_www_ci(domain.trim());
    // AWS Route 53 nameservers — ns-N.awsdns-NN.{com,net,org,co.uk} — whose root
    // varies with the shard number, so a plain suffix list can't catch them.
    // Both checks are ASCII-case-insensitive, matching the old
    // lowercase-then-`contains`/`starts_with` behaviour, without allocating.
    let db = d.as_bytes();
    if contains_ascii_ci(db, b".awsdns-")
        || (db.len() >= 7 && db[..7].eq_ignore_ascii_case(b"awsdns-"))
    {
        return true;
    }
    // The shared provider roots (one authority with `is_infrastructure_email`)
    // plus the hostname-only estate below.
    matches_domain_suffix(domain, crate::util::domains::INFRA_PROVIDER_ROOTS)
        || matches_domain_suffix(domain, INFRA_HOST_ONLY)
}

/// Either a mega/social platform or shared infrastructure — the haystack a lead
/// sits in, not a lead itself. The engine skips these as incidental (non-seed)
/// expansion targets so a scan doesn't map a provider's whole estate.
pub(crate) fn is_noncentral_domain(domain: &str) -> bool {
    is_mega_domain(domain) || is_infra_domain(domain)
}

/// Identity fingerprint of a name / handle / email-local: lowercase ASCII
/// alphanumerics only (an email's local part is taken before `@`). Used to tie a
/// discovered alias back to the subject without a dictionary name-split.
pub(crate) fn identity_norm(s: &str) -> String {
    let local = crate::core::validation::email_local(s);
    local
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Minimum shared-substring length for two identities to be considered the same
/// person. 4 ties real aliases to the subject (`matt`↔`jordanavery`,
/// `becky`↔`avery`) while rejecting unrelated handles (`arizonambb`).
pub(crate) const IDENTITY_OVERLAP_MIN: usize = 4;

/// True if two identity strings share a common substring of at least
/// [`IDENTITY_OVERLAP_MIN`] characters — a cheap, dictionary-free way to decide
/// whether a discovered Username/Person plausibly belongs to the subject. Inputs
/// are normalised via [`identity_norm`]. Short identities (< MIN) must match
/// exactly. O(n·m) over the two short strings — negligible for handles/names.
pub(crate) fn identity_overlaps(a: &str, b: &str) -> bool {
    let (a, b) = (identity_norm(a), identity_norm(b));
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a.len() < IDENTITY_OVERLAP_MIN || b.len() < IDENTITY_OVERLAP_MIN {
        return a == b;
    }
    // Longest-common-substring ≥ MIN via a rolling DP row.
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let mut prev = vec![0usize; bb.len() + 1];
    let mut cur = vec![0usize; bb.len() + 1];
    for &ca in ab {
        for (j, &cb) in bb.iter().enumerate() {
            cur[j + 1] = if ca == cb { prev[j] + 1 } else { 0 };
            if cur[j + 1] >= IDENTITY_OVERLAP_MIN {
                return true;
            }
        }
        std::mem::swap(&mut prev, &mut cur);
        cur.iter_mut().for_each(|v| *v = 0);
    }
    false
}

/// Decide whether a discovered identity entity is a *wrong-identity* pivot —
/// one that should be recorded but not expanded, because pivoting on it would
/// pull a stranger's footprint into the scan.
///
/// An entity is gated only when ALL of these hold:
///   * it is a `Username` or `Person` (the kinds that fan out into a whole
///     online footprint when searched);
///   * it is below the Verified confidence tier (`c_effective < 0.75`) — a
///     verified identity has earned its expansion;
///   * it is single-source (`source_count <= 1`) — corroboration by a second
///     independent module is itself evidence the alias is real;
///   * its handle/name shares no [`IDENTITY_OVERLAP_MIN`]-char overlap with ANY
///     of the subject's confirmed identities (`subject_identities`).
///
/// Kept as a pure function (separate from the engine loop) so the decision is
/// unit-testable in isolation and the operator override (`expand_all_identities`)
/// is the only thing layered on top of it.
pub(crate) fn is_wrong_identity_pivot(
    kind: &crate::core::entity::EntityKind,
    c_effective: f64,
    source_count: u32,
    value: &str,
    subject_identities: &[String],
) -> bool {
    use crate::core::entity::{Classification, EntityKind};
    matches!(kind, EntityKind::Username | EntityKind::Person)
        && c_effective < Classification::VERIFIED_MIN
        && source_count <= 1
        && !subject_identities
            .iter()
            .any(|s| identity_overlaps(s, value))
}

/// Honorifics dropped from the front of a person name and post-nominals dropped
/// from its end before the given/surname positions are read. Lowercase, compared
/// after `.` is stripped, so `"Mr."`, `"MR"` and `"mr"` all fold to `"mr"`.
const NAME_AFFIXES: &[&str] = &[
    "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "rev", "sir", "dame", "hon", "lady", "lord",
    "jr", "jnr", "sr", "snr", "ii", "iii", "iv", "oam", "am", "ao", "ac", "obe", "mbe", "cbe",
    "phd", "esq",
];

/// Fold a name-bearing string to the one reading every person-name comparison
/// in this file uses: Latin and Vietnamese diacritics to their base ASCII letter
/// through the shared fold ([`crate::util::str_util::fold_ascii_lower`], the
/// same one `name_intel` permutes names with), combining marks (NFD input)
/// dropped, and everything the fold has no ASCII answer for — a separator, a
/// Cyrillic or CJK letter — kept, lowercased, rather than deleted.
///
/// Without it a handle and a name were read in two alphabets: a handle is ASCII
/// (`nguyenvanan`, `jose.garcia`) while the name kept `"nguyễn"`/`"josé"`, so
/// [`handle_names_person`] judged every ASCII handle of an accented name "does
/// not spell it" and [`person_names_compatible`] judged `"Nguyễn Văn An"` and
/// `"Nguyen Van An"` two different people — vetoing ownership and co-reference
/// for exactly the names of HSE's primary jurisdiction (REQ-IDENTITY-GATE-003).
/// The fold is applied per character, never to the whole string, because
/// `fold_ascii_lower` deletes what it cannot fold: a Cyrillic name must stay a
/// Cyrillic name, not become an empty mononym. Pure; deterministic; idempotent.
pub(crate) fn fold_name_text(s: &str) -> String {
    let combining = |c: &char| ('\u{300}'..='\u{36F}').contains(c);
    let mut out = String::with_capacity(s.len());
    let mut buf = [0u8; 4];
    for c in s.chars().filter(|c| !combining(c)) {
        let folded = crate::util::str_util::fold_ascii_lower(c.encode_utf8(&mut buf));
        if folded.is_empty() {
            out.extend(c.to_lowercase().filter(|l| !combining(l)));
        } else {
            out.push_str(&folded);
        }
    }
    out
}

/// A person name read into its positions by [`person_name_parts`].
struct NameParts {
    /// The first name token (`"mary-jane"` keeps its internal `-`).
    given: String,
    /// The tokens between the given name and the surname, in order — the
    /// subject's own middle names, which a slug or a handle may spell out.
    middles: Vec<String>,
    /// The last name token (`"symes-thorpe"`, `"o'neill"`).
    surname: String,
}

/// A person name as [`NameParts`] — the first and last name tokens (and the
/// middle tokens between them) after honorifics, post-nominals and a
/// parenthesised note (`"(swimmer)"`) are removed and a `"Surname, Given"`
/// register reversal is reordered. Tokens are read through [`fold_name_text`]
/// (so `"Nguyễn"` is `"nguyen"`) and kept alphabetic (an internal `-`/`'` is
/// kept, so `O'Neill` and `Symes-Thorpe` survive as one token). `None` when
/// fewer than two tokens remain: a mononym carries no given/surname structure to
/// compare, so the caller must not treat it as proof of a different person.
fn person_name_parts(name: &str) -> Option<NameParts> {
    let mut depth = 0u32;
    let unparenthesised: String = name
        .chars()
        .filter(|&c| match c {
            '(' => {
                depth += 1;
                false
            }
            ')' => {
                depth = depth.saturating_sub(1);
                false
            }
            _ => depth == 0,
        })
        .collect();
    let reordered = match unparenthesised.split_once(',') {
        Some((head, tail)) if head.split_whitespace().count() == 1 && !tail.contains(',') => {
            format!("{tail} {head}")
        }
        _ => unparenthesised,
    };
    let mut tokens: Vec<String> = fold_name_text(&reordered)
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|t| {
            t.trim_matches(|c: char| !c.is_alphabetic())
                .chars()
                .filter(|c| c.is_alphabetic() || matches!(c, '-' | '\''))
                .collect::<String>()
        })
        .filter(|t| !t.is_empty())
        .collect();
    while tokens
        .first()
        .is_some_and(|t| NAME_AFFIXES.contains(&t.as_str()))
    {
        tokens.remove(0);
    }
    while tokens.len() > 2
        && tokens
            .last()
            .is_some_and(|t| NAME_AFFIXES.contains(&t.as_str()))
    {
        tokens.pop();
    }
    if tokens.len() < 2 {
        return None;
    }
    let surname = tokens.pop()?;
    let middles = tokens.split_off(1);
    Some(NameParts {
        given: tokens.pop()?,
        middles,
        surname,
    })
}

/// The surname of a person name as [`person_name_parts`] reads it — honorifics,
/// post-nominals and a `(note)` removed, a `"Surname, Given"` reversal reordered —
/// lowercased and diacritic-folded ([`fold_name_text`]: `"Nguyễn"` is
/// `"nguyen"`). `None` for a mononym. The one surname reading for every caller
/// that holds a scan's `FullName`, so `"Dr Ian Thorpe OAM"` is a Thorpe, not an
/// "OAM" (the last whitespace token); a caller comparing it against raw text
/// folds that text through [`fold_name_text`] too.
pub(crate) fn person_surname(name: &str) -> Option<String> {
    person_name_parts(name).map(|parts| parts.surname)
}

/// Two given names that can denote one person: equal, or one is a bare initial
/// of the other (`"i"` ↔ `"ian"`). Nicknames (`Bob` ↔ `Robert`) are deliberately
/// NOT folded — no dictionary is complete, and a miss here only withholds an
/// automatic pivot (`--expand-all-identities` restores it), whereas a false
/// fold would pivot on a stranger.
fn given_names_compatible(a: &str, b: &str) -> bool {
    let initial_of = |short: &str, long: &str| {
        short.chars().count() == 1 && long.chars().next() == short.chars().next()
    };
    a == b || initial_of(a, b) || initial_of(b, a)
}

/// True when two person names can denote the same individual: the same surname
/// and compatible given names (see [`given_names_compatible`]), read in either
/// token order so a surname-first register row (`"THORPE IAN"`) still matches.
/// Both names are read diacritic-folded ([`fold_name_text`]), so an accented
/// record and its unaccented spelling (`"Nguyễn Văn An"` ↔ `"Nguyen Van An"`)
/// are one person, not two. `None` when either name lacks a given/surname
/// structure (a mononym) — unknown, never "different".
pub(crate) fn person_names_compatible(a: &str, b: &str) -> Option<bool> {
    let (a, b) = (person_name_parts(a)?, person_name_parts(b)?);
    let (ga, sa, gb, sb) = (a.given, a.surname, b.given, b.surname);
    Some(
        (sa == sb && given_names_compatible(&ga, &gb))
            || (ga == sb && given_names_compatible(&sa, &gb)),
    )
}

/// Whether an Email local part or a Username `handle` spells the person `name` —
/// the identifier-side sibling of [`person_names_compatible`], sharing its name
/// parser so a handle and a name record are judged by one reading of the name.
///
/// [`identity_overlaps`] cannot make this call for a person: any ≥4-character
/// run satisfies it, and the surname alone always is one. A real "Ian Thorpe"
/// scan bound `carolthorpe70`, `megthorpeart`, `aidan_thorpe` (`"anthorpe"`)
/// and `tharleschorpe` (`"horpe"`) to the subject as his own identifiers, and
/// co-reference scored `damianthorpe` a 0.62 name-token match because
/// `"ian"` and `"thorpe"` are both substrings of it (REQ-IDENTITY-GATE-002).
///
/// The handle (an email's local part only) is read as its lowercase
/// alphabetic runs — digits and every separator split — and the runs are then
/// concatenated from a run START, so a match can never begin inside a word
/// (`dam|ianthorpe` is not `ian thorpe`) while `ian.thorpe`, `ian_thorpe` and
/// `ianthorpe` read alike. Name and handle are both read diacritic-folded
/// ([`fold_name_text`]), so the ASCII handles of an accented name
/// (`nguyenvanan` for `"Nguyễn Văn An"`, `jose.garcia` for `"José García"`) are
/// read in the name's own alphabet (REQ-IDENTITY-GATE-003). With `g` the given
/// name, `s` the surname (an internal `-`/`'` dropped, so `o.neill` matches
/// `O'Neill`) and `gi`/`si` their initials, `Some(true)` iff the text read from
/// some run start is:
///   * `g s…` — the full given name then the surname, anything after it
///     (`ianthorpe`, `ian.thorpe`, `ianthorpeofficial`, `ianthorpe26`);
///   * `g x s…` — the same across one middle initial (`ianjthorpe`,
///     `ian_j_thorpe`);
///   * `g m s…` — the same across the subject's OWN middle name(s), written
///     together or singly, with or without separators (`ianjamesthorpe` and
///     `ian.james.thorpe` for "Ian James Thorpe");
///   * `g M s…` — across one foreign middle name that is a whole run of its
///     own, `g` a whole run before it and no `-` between it and the surname
///     (`ian.james.thorpe` for "Ian Thorpe"): the handle's separators stand
///     where a name's spaces do, the same whitespace rule
///     [`text_names_person`] applies, and a `-` there reads as the
///     double-barrelled `james-thorpe` instead (REQ-IDENTITY-GATE-003);
///   * `gi s`, `s g`, `s gi` or `g si` — each ENDING at a run boundary, since
///     a bare initial is too short to trust inside a longer word (`ithorpe`,
///     `kdiegmann`, `thorpe_ian`, `thorpe_i` and `haigenb` match;
///     `thorpe_ivan` does not).
///
/// `Some(false)` otherwise — the surname alone or beside another given name
/// (`thorpe`, `jack_thorpe`, `thorpedo_m`), however many characters it
/// shares. `None` when `name` is a mononym, which has no given/surname
/// structure to test; the caller keeps its own check. Known conservative
/// losses, matching this codebase's default of a missed link over a false one:
/// a handle built from a nickname (`bobsmith` for Robert Smith), with a prefix
/// (`realianthorpe`), or with a foreign middle name run into its neighbours
/// (`ianjamesthorpe` when the subject's name does not carry "James") is not
/// recognised. Pure; deterministic; no dictionary.
pub(crate) fn handle_names_person(name: &str, handle: &str) -> Option<bool> {
    let parts = person_name_parts(name)?;
    // `person_name_parts` has already folded and lowercased every token.
    let letters = |s: &str| -> String { s.chars().filter(|c| c.is_alphabetic()).collect() };
    let (g, s) = (letters(&parts.given), letters(&parts.surname));
    let (Some(gi), Some(si)) = (g.chars().next(), s.chars().next()) else {
        return None;
    };
    let (gi, si) = (gi.to_string(), si.to_string());
    // The subject's own middle names as a handle writes them: all of them run
    // together (`johnpaulgeorge`), then each one alone. Insertion-ordered.
    let mut own_middles: Vec<String> = Vec::new();
    let all_middles: String = parts.middles.iter().map(|m| letters(m)).collect();
    for m in std::iter::once(all_middles).chain(parts.middles.iter().map(|m| letters(m))) {
        if !m.is_empty() && !own_middles.contains(&m) {
            own_middles.push(m);
        }
    }
    // Alphabetic runs of the folded local part, each with the separator text
    // (digits included) that precedes it.
    let mut runs: Vec<(String, String)> = Vec::new();
    let (mut run, mut sep) = (String::new(), String::new());
    for c in fold_name_text(crate::core::validation::email_local(handle)).chars() {
        if c.is_alphabetic() {
            run.push(c);
        } else {
            if !run.is_empty() {
                runs.push((std::mem::take(&mut run), std::mem::take(&mut sep)));
            }
            sep.push(c);
        }
    }
    if !run.is_empty() {
        runs.push((run, sep));
    }
    let named = (0..runs.len()).any(|start| {
        // The runs from `start` joined, and the byte offsets where a run ends.
        let mut joined = String::new();
        let mut ends = Vec::new();
        for (r, _) in &runs[start..] {
            joined.push_str(r);
            ends.push(joined.len());
        }
        let open_ended = |form: &str| joined.starts_with(form);
        let bounded = |form: &str| joined.starts_with(form) && ends.contains(&form.len());
        let across_initial = joined.strip_prefix(g.as_str()).is_some_and(|rest| {
            let mut cs = rest.chars();
            cs.next().is_some() && cs.as_str().starts_with(s.as_str())
        });
        let across_own_middle = own_middles
            .iter()
            .any(|m| open_ended(&format!("{g}{m}{s}")));
        let across_foreign_middle_run = runs[start].0 == g
            && runs
                .get(start + 1)
                .is_some_and(|(m, _)| m.chars().count() >= 2)
            && runs
                .get(start + 2)
                .is_some_and(|(_, sep)| !sep.contains('-'))
            && ends
                .get(1)
                .is_some_and(|&at| joined[at..].starts_with(s.as_str()));
        open_ended(&format!("{g}{s}"))
            || across_initial
            || across_own_middle
            || across_foreign_middle_run
            || bounded(&format!("{gi}{s}"))
            || bounded(&format!("{s}{g}"))
            || bounded(&format!("{s}{gi}"))
            || bounded(&format!("{g}{si}"))
    });
    Some(named)
}

/// Whether free `text` (a search result's title + snippet + URL, or a bare URL
/// path) NAMES the person `subject` — the search-admission sibling of
/// [`person_names_compatible`], sharing its name parser so a result and a
/// discovered `Person` are judged by one reading of the subject's name.
///
/// `Some(true)` iff the subject's surname occurs as a whole token run with a
/// compatible given name (see [`given_names_compatible`]) beside it:
///   * directly before it — `"ian thorpe"`, `"i thorpe"`, the slug
///     `ian-thorpe-4b080523`;
///   * two before it across one middle name or initial — `"ian j thorpe"`,
///     `"Ian James Thorpe"`. A FOREIGN middle name must be space-separated from
///     the surname: `"Ian Symes-Thorpe"` is a double-barrelled surname, a
///     different person to [`person_names_compatible`] as well;
///   * the subject's OWN name run before it, whatever separates its tokens —
///     the full given name and the middle name(s) the subject's name carries
///     (`/in/ian-james-thorpe-1234` for "Ian James Thorpe"), or every part of a
///     multi-part given name (`/in/mary-jane-smith` for "Mary-Jane Smith"). A
///     URL path has only `-` separators, so without this the subject's own
///     slug failed the whitespace rule above and was not minted
///     (REQ-SEARCH-012). Tokens the subject's name does not carry still need
///     the whitespace, so `ian-symes-thorpe` stays a Symes-Thorpe;
///   * directly after it in surname-first order — `"THORPE IAN"`, `"Thorpe,
///     Ian"` — and there only the FULL given name, since a bare initial after a
///     surname is as often the pronoun (`"Mark Thorpe I think"`).
///
/// `Some(false)` otherwise: the surname alone, or only beside an incompatible
/// given name (`"bill thorpe"`, `"JAMIE THORPE PLUMBING"`), does not name "Ian
/// Thorpe" — a surname is shared by every relative and namesake, and a live "Ian
/// Thorpe" scan minted a Spokeo `Bill-Thorpe` page, a plumbing company and their
/// contact details as the subject's own on exactly that reading
/// (REQ-SEARCH-008). `None` when `subject` is a mononym, which carries no
/// given/surname structure to test — the caller keeps its own single-term check.
///
/// Tokens are the lowercase alphanumeric runs of `text` read diacritic-folded
/// ([`fold_name_text`], so `nguyen-van-an` names "Nguyễn Văn An"), so `-`, `_`,
/// `/`, `.`, `,` and whitespace all separate and a URL slug tokenises like prose; a
/// hyphenated or apostrophised name part (`Symes-Thorpe`, `O'Neill`) is matched
/// as its run of sub-tokens. Pure; deterministic.
pub(crate) fn text_names_person(text: &str, subject: &str) -> Option<bool> {
    let parts = person_name_parts(subject)?;
    // Lowercase alphanumeric runs, each with the separator text before it.
    let tokenise = |s: &str| -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut sep = String::new();
        let mut tok = String::new();
        for c in s.chars() {
            if c.is_alphanumeric() {
                // `char::to_lowercase` per char, as `person_name_parts` does.
                tok.extend(c.to_lowercase());
            } else {
                if !tok.is_empty() {
                    out.push((std::mem::take(&mut tok), std::mem::take(&mut sep)));
                }
                sep.push(c);
            }
        }
        if !tok.is_empty() {
            out.push((tok, sep));
        }
        out
    };
    let words = |s: &str| -> Vec<String> { tokenise(s).into_iter().map(|(t, _)| t).collect() };
    let surname_toks = words(&parts.surname);
    let given_toks = words(&parts.given);
    let middle_toks: Vec<String> = parts.middles.iter().flat_map(|m| words(m)).collect();
    // A multi-part given name (`Mary-Jane`) is compared on its first part — the
    // part a register, a slug or an initial preserves.
    let given = given_toks.first()?.clone();
    if surname_toks.is_empty() {
        return None;
    }
    // The subject's own name as it can stand before the surname, separators
    // aside: every given-name part then every middle name, every given-name
    // part alone, the first given-name part then every middle name. Only runs
    // of two or more tokens — one token is `direct_before`'s case.
    // Insertion-ordered, so the result never depends on iteration order.
    let mut own_runs: Vec<Vec<String>> = Vec::new();
    for run in [
        [given_toks.as_slice(), middle_toks.as_slice()].concat(),
        given_toks.clone(),
        [std::slice::from_ref(&given), middle_toks.as_slice()].concat(),
    ] {
        if run.len() >= 2 && !own_runs.contains(&run) {
            own_runs.push(run);
        }
    }
    let toks = tokenise(&fold_name_text(text));
    let k = surname_toks.len();
    let tok = |j: usize| toks[j].0.as_str();
    let compatible = |t: &str| given_names_compatible(t, &given);
    let named = (0..toks.len().saturating_sub(k - 1))
        .filter(|&i| {
            toks[i..i + k]
                .iter()
                .map(|(t, _)| t)
                .eq(surname_toks.iter())
        })
        .any(|i| {
            let direct_before = i >= 1 && compatible(tok(i - 1));
            let across_middle = i >= 2 && compatible(tok(i - 2)) && {
                let middle = tok(i - 1);
                let initial = middle.chars().count() == 1;
                middle.chars().all(char::is_alphabetic)
                    && (initial || toks[i].1.chars().any(char::is_whitespace))
            };
            let own_name_before = own_runs.iter().any(|run| {
                i >= run.len() && toks[i - run.len()..i].iter().map(|(t, _)| t).eq(run.iter())
            });
            let surname_first = toks.get(i + k).is_some_and(|(t, _)| *t == given);
            direct_before || across_middle || own_name_before || surname_first
        });
    Some(named)
}

/// Decide whether a discovered `Person` is a *different, named individual* from
/// the scan's subject — one whose expansion would run a whole identity sweep
/// (name permutations → handle/email guesses → breach and profile probes) on a
/// stranger.
///
/// [`is_wrong_identity_pivot`] cannot make this call for people. It asks whether
/// a candidate shares any [`IDENTITY_OVERLAP_MIN`]-char run with the subject, and
/// every relative or namesake sharing the surname does (`"meganthorpe"` ⊃
/// `"thorpe"`), as does a near-surname (`"ianthorley"` ⊃ `"ianthor"`). Its
/// corroboration escape is wrong for people too: two registers agreeing that
/// "Megan Thorpe" exists is evidence she exists, not that she is Ian Thorpe. A
/// real name scan of "Ian Thorpe" pivoted "Ian Thorley", "Aidan Thorpe", "Megan
/// Thorpe", "Wendy Thorpe" and the facility "Ian Thorpe Aquatic Centre", minted
/// ~200 speculative mailboxes and handles for them, and surfaced breach
/// credentials belonging to strangers (REQ-IDENTITY-GATE-001).
///
/// A `Person` is gated here when the subject's own name is known
/// (`subject_names` — the `FullName` seed) and the candidate's name is
/// structurally incompatible with every one of them
/// ([`person_names_compatible`] is `Some(false)`), whatever its confidence or
/// source count. A mononym, or a scan with no named subject, returns `false` and
/// falls through to [`is_wrong_identity_pivot`] unchanged. Only
/// `--expand-all-identities` overrides it — the operator's explicit request to
/// chase relatives.
pub(crate) fn is_other_named_person(
    kind: &crate::core::entity::EntityKind,
    value: &str,
    subject_names: &[String],
) -> bool {
    matches!(kind, crate::core::entity::EntityKind::Person)
        && !subject_names.is_empty()
        && subject_names
            .iter()
            .all(|s| person_names_compatible(s, value) == Some(false))
}

pub(super) fn domain_expansion_factor(domain: &str) -> f64 {
    if is_noncentral_domain(domain) {
        0.15
    } else {
        1.0
    }
}

/// Hostname-only additions to `util::domains::INFRA_PROVIDER_ROOTS` (see
/// [`is_infra_domain`]): managed-DNS and nameserver estates, CDN edge apexes,
/// ESP sending domains, hosted-mail security gateways and the cloud hosts'
/// platform domains — names that surface in NS/MX/SOA/reverse lookups and are
/// applied by the hostname classifier only. Suffix-matched. A root that should
/// ALSO gate role mailboxes (`abuse@…`) belongs in the shared roots instead;
/// `core::scan::tests` locks the three tables pairwise disjoint.
pub(crate) const INFRA_HOST_ONLY: &[&str] = &[
    // Managed DNS & nameserver infrastructure
    "dnsmadeeasy.com",
    "nsone.net",
    "ultradns.net",
    "akam.net",
    "akamaiedge.net",
    "akamai.net",
    "edgekey.net",
    "edgesuite.net",
    "azure-dns.com", // Azure DNS nameservers (ns1-NN.azure-dns.*)
    "azure-dns.net",
    "azure-dns.org",
    "azure-dns.info",
    "googledomains.com", // Google Cloud DNS nameservers (ns-cloud-*.googledomains.com)
    "cloudns.net",       // ClouDNS managed DNS
    "dnsimple.com",      // DNSimple managed DNS
    // Registrar / hosting control-plane hostnames (the registrars' corporate
    // roots — secureserver.net, domaincontrol.com, name.com, namecheap.com,
    // gandi.net — are shared roots, since their role mailboxes surface too)
    "registrar-servers.com",
    "jomax.net", // GoDaddy registrar/abuse mail domain (dns@jomax.net)
    "epik.com",  // Epik registrar / nameserver provider
    // CDN apex roots (edge IPs are gated by validation::is_cdn_edge_ip)
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "azureedge.net",   // Azure CDN edge
    "edgecastcdn.net", // Edgecast / Verizon Media CDN
    "llnwd.net",       // Limelight Networks CDN
    // CDN / cloud provider platform domains — never the subject's own
    // infrastructure, so expanding them floods the graph with the provider's
    // estate (the providers' corporate roots are shared roots).
    "cloudflare.net",
    "cloudflare-dns.com",
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    "1e100.net",
    "azurewebsites.net",
    "windows.net",
    "cloudapp.net",         // Azure cloud-service / VM endpoints
    "elasticbeanstalk.com", // AWS Elastic Beanstalk app hosting
    // ESP / transactional mail sending domains
    "mandrillapp.com",
    "sparkpostmail.com",
    "amazonses.com",
    "mcsv.net",
    "mcdlv.net",
    "rsgsv.net",
    "list-manage.com", // Mailchimp campaign / click-tracking
    "mailchimp.com",
    "postmarkapp.com", // Postmark transactional mail
    "mailjet.com",
    // Hosted-mail security gateways
    "mimecast.com",
    "pphosted.com",
    "messagelabs.com",
    "protection.outlook.com", // Microsoft 365 Exchange Online Protection MX
    "barracudanetworks.com",  // Barracuda mail security
    "emailsrvr.com",          // Rackspace hosted email infra
];

const MEGA_DOMAINS: &[&str] = &[
    // Major platforms & social media
    "amazon.com",
    "amazon.com.au",
    "apple.com",
    "discord.com",
    "facebook.com",
    "fansly.com",
    "github.com",
    "google.com",
    "google.com.au",
    "instagram.com",
    "linkedin.com",
    "microsoft.com",
    "netflix.com",
    "onlyfans.com",
    "patreon.com",
    "pinterest.com",
    "quora.com",
    "reddit.com",
    "soundcloud.com",
    "spotify.com",
    "stackoverflow.com",
    "steamcommunity.com",
    "tiktok.com",
    "tumblr.com",
    "twitch.tv",
    "twitter.com",
    "vimeo.com",
    "whatsapp.com",
    "wikipedia.org",
    "x.com",
    "yahoo.com",
    "youtube.com",
    // Search engines & AI
    "bing.com",
    "chatgpt.com",
    "duckduckgo.com",
    "openai.com",
    // Content platforms & blogs
    "blogspot.com",
    "medium.com",
    "telegram.org",
    "wordpress.com",
    // News & media
    "bbc.co.uk",
    "bbc.com",
    "businessinsider.com",
    "cnn.com",
    "forbes.com",
    "nytimes.com",
    "reuters.com",
    "techcrunch.com",
    "theguardian.com",
    "washingtonpost.com",
    // Commerce & entertainment
    "aliexpress.com",
    "ebay.com",
    "ebay.com.au",
    "imdb.com",
    "pornhub.com",
    "xhamster.com",
    "xvideos.com",
    // CDN / infrastructure
    "akamai.com",
    "cloudflare.com",
    "fastly.com",
    // People-search / OSINT aggregators (they scrape and republish each other, so
    // a person scan hits many at once as stranger co-occurrence noise).
    "advancedbackgroundchecks.com",
    "anywho.com",
    "australialookup.com",
    "beenverified.com",
    "checkpeople.com",
    "clustrmaps.com",
    "cyberbackgroundchecks.com",
    "fastbackgroundcheck.com",
    "fastpeoplesearch.com",
    "idcrawl.com",
    "instantcheckmate.com",
    "intelius.com",
    "locatefamily.com",
    "mylife.com",
    "nuwber.com",
    "peekyou.com",
    "peoplefinders.com",
    "personlookup.com.au",
    "pipl.com",
    "radaris.com",
    "rocketreach.co",
    "searchpeoplefree.com",
    "smartbackgroundchecks.com",
    "socialcatfish.com",
    "spokeo.com",
    "thatsthem.com",
    "truepeoplesearch.com",
    "truthfinder.com",
    "usphonebook.com",
    "ussearch.com",
    "whitepages.com",
    "whitepages.com.au",
    "zabasearch.com",
    "zoominfo.com",
    // Email providers (freemail) — never the subject's own infrastructure, so a
    // discovered freemail domain must not be deep-expanded.
    "gmail.com",
    "googlemail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "msn.com",
    "office365.com",
    "outlook.com",
    "protonmail.com",
    "proton.me",
    "ymail.com",
    "aol.com",
    "me.com",
    "mac.com",
    "mail.com",
    "gmx.com",
    "gmx.de",
    "gmx.net",
    "zoho.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "tutanota.com",
    "fastmail.com",
    "fastmail.fm",
    "web.de",
    "myway.com",
    // ISP / telco webmail (US + AU) — shared mailbox providers, not a subject's
    // own domain. These flooded a real scan as stranger co-occurrence addresses.
    "comcast.net",
    "verizon.net",
    "att.net",
    "sbcglobal.net",
    "bellsouth.net",
    "cox.net",
    "charter.net",
    "earthlink.net",
    "windstream.net",
    "frontier.net",
    "swbell.net",
    "rr.com",
    "q.com",
    "bigpond.com",
    "bigpond.net.au",
    "optusnet.com.au",
    "iinet.net.au",
    "tpg.com.au",
    "internode.on.net",
    "ozemail.com.au",
    "y7mail.com",
    // DNS / IP lookup tools
    "dnschecker.org",
    "domaintools.com",
    "ip2location.com",
    "ipaddress.com",
    "iplocation.io",
    "whatismyip.com",
    "whatismyipaddress.com",
    "whois.com",
    // Australian mega-sites (common noise in AU OSINT)
    "abc.net.au",
    "news.com.au",
    "smh.com.au",
    "nine.com.au",
    "realestate.com.au",
    "seek.com.au",
    "yellowpages.com.au",
    "carsales.com.au",
    "domain.com.au",
    "gumtree.com.au",
    "ozbargain.com.au",
    "truelocal.com.au",
    "whirlpool.net.au",
    // AU news mastheads — a subject named/quoted in the press is co-occurrence
    // noise, not their own domain.
    "afr.com",
    "couriermail.com.au",
    "dailytelegraph.com.au",
    "heraldsun.com.au",
    "sbs.com.au",
    "theage.com.au",
    "theaustralian.com.au",
    "thewest.com.au",
    // Additional global platforms
    "archive.org",
    "mastodon.social",
    "paypal.com",
    "snapchat.com",
    "threads.net",
];
