//! The account-leg snapshot: how each simple username leg ends in the same ten situations,
//! recorded before the legs share a kernel. A refactor of the legs must leave every row as it is:
//! the outcome's kind, HTTP status and reason, and each entity's kind, value, confidence and tags.
//! Each leg's own tests pin the outcome kinds only, so this is what holds the messages.

use std::fmt::Write as _;

use crate::entity::Entity;
use crate::error::Error;
use crate::http::Transport;
use crate::source_outcome::SourceExecutionOutcome;
use crate::test_support::{OneResponse, Refusing, Silent};

const SNAPSHOT: &str = include_str!("../../tests/fixtures/account_leg_snapshot.tsv");

/// Far past any pacing hold another test leaves at a real host; each scenario steps on from it.
const BASE_NOW: u64 = 2_800_000_000;

type Found = Result<(Vec<Entity>, SourceExecutionOutcome), Error>;
type Run = fn(&dyn Transport, &str, u64) -> Found;

/// One leg: its source, how to run it, the host it asks, a public account it knows, that
/// account's real payload, and the text that names the account in it, which the "different
/// account" payload renames.
struct Leg {
    source: &'static str,
    run: Run,
    host: &'static str,
    handle: &'static str,
    found: &'static str,
    names: &'static [&'static str],
}

macro_rules! run_leg {
    ($module:ident) => {
        |transport: &dyn Transport, handle: &str, now: u64| {
            crate::$module::lookup(transport, handle, "scan-snapshot", now)
                .map(|report| (report.entities, report.outcome))
        }
    };
}

const LOBSTERS: &str = r#"{"username":"jcs","created_at":"2012-06-30T16:39:19.000-05:00","is_admin":true,"is_moderator":true,"karma":16905,"about":"<p>hello, cyberpals</p>","avatar_url":"/avatars/jcs-100.png","invited_by_user":null,"github_username":"jcs"}"#;
const CHESS_COM: &str = r#"{"avatar":"https://images.chesscomfiles.com/uploads/v1/user/15448422.png","player_id":15448422,"@id":"https://api.chess.com/pub/player/hikaru","url":"https://www.chess.com/member/Hikaru","name":"Hikaru Nakamura","username":"hikaru","title":"GM","followers":1423410,"country":"https://api.chess.com/pub/country/US","location":"Florida","last_online":1793735897,"joined":1389043258,"status":"premium","is_streamer":true,"twitch_url":"https://twitch.tv/gmhikaru","verified":false,"league":"Legend","streaming_platforms":[{"type":"twitch","channel_url":"https://twitch.tv/gmhikaru"}]}"#;
const LICHESS: &str = r#"{"id":"thibault","username":"thibault","perfs":{"blitz":{"games":11924,"rating":1744}},"flair":"symbols.transgender-flag","patron":true,"verified":true,"createdAt":1290415680000,"profile":{"bio":"I also produce organic dog meat at https://www.elwooddogmeat.com/","realName":"Thibault Duplessis","links":"github.com/ornicar\nhttps://mas.to/@thibault"},"seenAt":1793746617972,"playTime":{"total":6701989,"tv":18024},"url":"https://lichess.org/@/thibault","count":{"all":23933,"rated":21534}}"#;
const CODEBERG: &str = r#"{"id":70422,"login":"forgejo","login_name":"","source_id":0,"full_name":"Forgejo","email":"forgejo@noreply.codeberg.org","avatar_url":"https://codeberg.org/avatars/dae8ab126a96f6fbd6942cf08ab92382","html_url":"https://codeberg.org/forgejo","language":"","is_admin":false,"last_login":"0001-01-01T00:00:00Z","created":"2022-11-06T07:18:11+01:00","restricted":false,"active":false,"prohibit_login":false,"location":"","pronouns":"","website":"https://forgejo.org","description":"Beyond coding. We forge.","visibility":"public","followers_count":641,"following_count":0,"starred_repos_count":0,"username":"forgejo"}"#;
const DEVTO: &str = r#"{"type_of":"user","id":1,"username":"ben","name":"Ben Halpern","twitter_username":"bendhalpern","github_username":"benhalpern","summary":"A Canadian software developer who thinks he’s funny.","location":"NY","website_url":"http://benhalpern.com","joined_at":"Dec 27, 2015","profile_image":"https://media2.dev.to/x.png"}"#;
const CODEWARS: &str = r#"{"id":"545207bac8e60b30fc000942","username":"g964","name":"","honor":489606,"clan":"None","leaderboardPosition":1,"skills":[],"ranks":{"overall":{"rank":-1,"name":"1 kyu","color":"purple","score":30497}},"codeChallenges":{"totalAuthored":3,"totalCompleted":7000}}"#;
const HUGGINGFACE: &str = r#"{"_id":"5dd96eb166059660ed1ee413","isPro":true,"fullname":"Julien Chaumond","numModels":53,"numDatasets":26,"numSpaces":49,"numPapers":8,"numFollowers":5229,"orgs":[{"id":"5e67bd5b1009063689407478","name":"huggingface","fullname":"Hugging Face"},{"id":"63878a485c68cf2713b9f0af","name":"ph-snps","fullname":"ph-snps"},{"id":"x","name":"../bad"}],"user":"julien-c","type":"user","details":"<3 ML/AI for everyone","createdAt":"2019-11-23T17:38:57.000Z"}"#;
const HACKER_NEWS: &str = r#"{"id":"pg","created":1160418092,"karma":157316,"about":"Bug fixer. Site: &lt;a href=&quot;https://paulgraham.com&quot;&gt;paulgraham.com&lt;/a&gt;","submitted":[1,2,3]}"#;

fn legs() -> [Leg; 8] {
    [
        Leg {
            source: crate::lobsters::SRC,
            run: run_leg!(lobsters),
            host: "lobste.rs",
            handle: "jcs",
            found: LOBSTERS,
            names: &[r#""username":"jcs""#],
        },
        Leg {
            source: crate::chess_com::SRC,
            run: run_leg!(chess_com),
            host: "api.chess.com",
            handle: "hikaru",
            found: CHESS_COM,
            names: &[r#""username":"hikaru""#],
        },
        Leg {
            source: crate::lichess::SRC,
            run: run_leg!(lichess),
            host: "lichess.org",
            handle: "thibault",
            found: LICHESS,
            names: &[r#""id":"thibault""#, r#""username":"thibault""#],
        },
        Leg {
            source: crate::codeberg_user::SRC,
            run: run_leg!(codeberg_user),
            host: "codeberg.org",
            handle: "forgejo",
            found: CODEBERG,
            names: &[r#""login":"forgejo""#, r#""username":"forgejo""#],
        },
        Leg {
            source: crate::devto_user::SRC,
            run: run_leg!(devto_user),
            host: "dev.to",
            handle: "ben",
            found: DEVTO,
            names: &[r#""username":"ben""#],
        },
        Leg {
            source: crate::codewars_user::SRC,
            run: run_leg!(codewars_user),
            host: "www.codewars.com",
            handle: "g964",
            found: CODEWARS,
            names: &[r#""username":"g964""#],
        },
        Leg {
            source: crate::huggingface_user::SRC,
            run: run_leg!(huggingface_user),
            host: "huggingface.co",
            handle: "julien-c",
            found: HUGGINGFACE,
            names: &[r#""user":"julien-c""#],
        },
        Leg {
            source: crate::hacker_news::SRC,
            run: run_leg!(hacker_news),
            host: "hacker-news.firebaseio.com",
            handle: "pg",
            found: HACKER_NEWS,
            names: &[r#""id":"pg""#],
        },
    ]
}

/// `found` with every name in it renamed to another account's.
fn other_account(leg: &Leg) -> String {
    leg.names.iter().fold(leg.found.to_owned(), |body, name| {
        let renamed = name.replacen(leg.handle, "someone-else", 1);
        assert!(
            body.contains(name),
            "{}: {name} is not in its payload",
            leg.source
        );
        body.replace(name, &renamed)
    })
}

/// A field of a snapshot row, with no tab or line break of its own.
fn cell(text: &str) -> String {
    text.replace(['\t', '\n', '\r'], " ")
}

fn row(source: &str, scenario: &str, found: &Found) -> String {
    let mut row = format!("{source}\t{scenario}\t");
    match found {
        Err(error) => {
            write!(row, "error\t{}", cell(&error.to_string())).expect("a String takes a write");
        }
        Ok((entities, outcome)) => {
            let status = outcome
                .http_status
                .map_or_else(|| "-".to_owned(), |status| status.to_string());
            write!(
                row,
                "{:?}\t{status}\t{}\t{}",
                outcome.kind,
                cell(&outcome.reason()),
                entities.len()
            )
            .expect("a String takes a write");
            for entity in entities {
                write!(
                    row,
                    "\t{}={}@{:.2}[{}]",
                    entity.kind,
                    cell(&entity.raw_value),
                    entity.confidence,
                    entity.tags.join(",")
                )
                .expect("a String takes a write");
            }
        }
    }
    row
}

/// Run `leg` for `handle` over `net` at `now`, then close its host's pacing circuit, so one
/// scenario's failures never hold the next one back.
fn ask(leg: &Leg, net: &dyn Transport, handle: &str, now: u64) -> Found {
    let found = (leg.run)(net, handle, now);
    crate::circuit::record_success(leg.host);
    found
}

/// Every snapshot row as this build gives it.
fn rows() -> Vec<String> {
    let mut rows = Vec::new();
    for (index, leg) in legs().iter().enumerate() {
        let mut now = BASE_NOW + u64::try_from(index).expect("a small index") * 1_000_000;
        let mut next = || {
            now += 10_000;
            now
        };
        let other = other_account(leg);
        let shouted = leg.handle.to_ascii_uppercase();
        let scenarios: [(&str, Found); 10] = [
            (
                "found",
                ask(leg, &OneResponse::json(200, leg.found), leg.handle, next()),
            ),
            (
                "shouted",
                ask(leg, &OneResponse::json(200, leg.found), &shouted, next()),
            ),
            (
                "other",
                ask(leg, &OneResponse::json(200, &other), leg.handle, next()),
            ),
            (
                "empty",
                ask(leg, &OneResponse::json(200, "{}"), leg.handle, next()),
            ),
            (
                "null",
                ask(leg, &OneResponse::json(200, "null"), leg.handle, next()),
            ),
            (
                "not_json",
                ask(leg, &OneResponse::json(200, "not json"), leg.handle, next()),
            ),
            (
                "missing",
                ask(
                    leg,
                    &OneResponse::json(404, r#"{"error":"not found"}"#),
                    leg.handle,
                    next(),
                ),
            ),
            (
                "server",
                ask(leg, &OneResponse::json(500, "{}"), leg.handle, next()),
            ),
            ("silent", ask(leg, &Silent, leg.handle, next())),
            ("refused", ask(leg, &Refusing, leg.handle, next())),
        ];
        for (scenario, found) in &scenarios {
            rows.push(row(leg.source, scenario, found));
        }
        rows.push(row(
            leg.source,
            "invalid",
            &ask(leg, &Silent, "bad handle!", next()),
        ));
    }
    rows
}

#[test]
fn every_account_leg_ends_as_it_did() {
    let expected: Vec<&str> = SNAPSHOT
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    let found = rows();
    let changed: Vec<String> = found
        .iter()
        .filter(|row| !expected.contains(&row.as_str()))
        .cloned()
        .collect();
    assert!(
        changed.is_empty() && found.len() == expected.len(),
        "{} rows changed or new:\n{}\nThe snapshot as this run found it:\n{}",
        changed.len(),
        changed.join("\n"),
        found.join("\n")
    );
}
