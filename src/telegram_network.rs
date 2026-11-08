//! Bounded map of a public Telegram channel network, keyless.
//!
//! From one seed channel, read each channel's public page and post preview
//! ([`crate::telegram::observe`]) and follow the other public names its posts forward from or link
//! to, breadth first, to a fixed depth and a fixed number of names read. Every edge keeps how often
//! it was seen. The result is a map of which public channels amplify which, the way researchers
//! trace how a message spreads; an edge is a lead, never an affiliation, and nothing here reads a
//! private chat, a member list or a person's account details.
//!
//! The crawl is bounded twice: by depth and by the number of names read, each with a hard ceiling
//! the operator cannot raise. Names seen but not read because a bound was reached are counted and
//! reported, so a bounded map never reads as the whole network.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;

use crate::error::Error;
use crate::http::Transport;
use crate::telegram::{self, Kind, Observed};

pub const DEFAULT_DEPTH: u8 = 1;
pub const MAX_DEPTH: u8 = 3;
pub const DEFAULT_NAMES: usize = 15;
pub const MAX_NAMES: usize = 50;

pub const USAGE: &str = "usage: huntsman-recon telegram-network HANDLE [--depth 1-3] [--max 1-50]";
pub const HELP: &str = "\
telegram-network HANDLE [--depth N] [--max N]

Map the public Telegram channels around one channel, keyless. Each channel's public page and post
preview (t.me/s/NAME) is read; the other public names its recent posts forward from or link to are
followed breadth first. --depth (default 1, at most 3) bounds how many hops are followed; --max
(default 15, at most 50) bounds how many names are read in all. Every edge keeps how often it was
seen, and names left unread because a bound was reached are counted.

An edge is a lead, never proof of affiliation or control. Only public pages are read: no private
chat, member list, phone number or account detail.
";

/// The crawl's bounds, already held to their ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub depth: u8,
    pub names: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            depth: DEFAULT_DEPTH,
            names: DEFAULT_NAMES,
        }
    }
}

/// The operator's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub seed: String,
    pub limits: Limits,
}

impl Args {
    /// Parse `HANDLE [--depth N] [--max N]`. **Pure.**
    ///
    /// # Errors
    /// A message naming what is wrong with the arguments.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut seed = None;
        let mut limits = Limits::default();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--depth" => {
                    let value = it.next().ok_or("--depth needs a number")?;
                    limits.depth = value
                        .parse::<u8>()
                        .ok()
                        .filter(|d| (1..=MAX_DEPTH).contains(d))
                        .ok_or_else(|| format!("--depth must be 1 to {MAX_DEPTH}"))?;
                }
                "--max" => {
                    let value = it.next().ok_or("--max needs a number")?;
                    limits.names = value
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=MAX_NAMES).contains(n))
                        .ok_or_else(|| format!("--max must be 1 to {MAX_NAMES}"))?;
                }
                other if other.starts_with("--") => return Err(format!("unknown option {other}")),
                other => {
                    if seed.is_some() {
                        return Err("give one seed handle".to_owned());
                    }
                    let handle = telegram::handle_from_link(other)
                        .or_else(|| {
                            let bare = other.trim_start_matches('@');
                            telegram::valid_handle(bare).then(|| bare.to_ascii_lowercase())
                        })
                        .ok_or_else(|| format!("{other} is not a Telegram handle or t.me link"))?;
                    seed = Some(handle);
                }
            }
        }
        Ok(Self {
            seed: seed.ok_or("give a seed handle")?,
            limits,
        })
    }
}

/// One name the crawl read, and what its public page showed.
#[derive(Debug, Clone)]
pub struct Node {
    pub handle: String,
    pub depth: u8,
    /// The page, or why nothing was confirmed.
    pub seen: Result<Observed, String>,
}

/// `from`'s posts forward from (`forwarded_from`) or link to (`mentioned`) `to`, `count` times.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub relation: &'static str,
    pub count: usize,
}

/// The bounded map.
#[derive(Debug, Clone)]
pub struct Network {
    pub seed: String,
    pub limits: Limits,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Names an edge pointed at that were not read because a bound was reached.
    pub unread: BTreeSet<String>,
}

impl Network {
    /// Each name an edge points at, with how many read channels point at it and the summed edge
    /// count, most-amplified first. **Pure.**
    #[must_use]
    pub fn amplified(&self) -> Vec<(String, usize, usize)> {
        let mut by: BTreeMap<&str, (BTreeSet<&str>, usize)> = BTreeMap::new();
        for edge in &self.edges {
            let entry = by.entry(edge.to.as_str()).or_default();
            entry.0.insert(edge.from.as_str());
            entry.1 += edge.count;
        }
        let mut out: Vec<_> = by
            .into_iter()
            .map(|(to, (from, total))| (to.to_owned(), from.len(), total))
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
        out
    }
}

/// Crawl the public channel network around `seed` within `limits`.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses a URL.
pub fn crawl<T: Transport + ?Sized>(
    transport: &T,
    seed: &str,
    limits: Limits,
    now_unix: u64,
) -> Result<Network, Error> {
    let limits = Limits {
        depth: limits.depth.clamp(1, MAX_DEPTH),
        names: limits.names.clamp(1, MAX_NAMES),
    };
    let seed = seed.to_ascii_lowercase();
    let mut queued: BTreeSet<String> = BTreeSet::from([seed.clone()]);
    let mut frontier = VecDeque::from([(seed.clone(), 0u8)]);
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut unread = BTreeSet::new();
    while let Some((handle, depth)) = frontier.pop_front() {
        let observed = telegram::observe(transport, &handle, now_unix)?.map_err(|outcome| {
            outcome
                .detail
                .unwrap_or_else(|| format!("{:?}", outcome.kind))
        });
        if let Ok(Observed {
            page,
            preview: Some(Ok(preview)),
            ..
        }) = &observed
        {
            debug_assert_eq!(page.kind, Kind::Channel);
            let pivots = preview
                .forwarded_from
                .iter()
                .map(|(to, n)| (to, *n, "forwarded_from"))
                .chain(preview.mentions.iter().map(|(to, n)| (to, *n, "mentioned")));
            for (to, count, relation) in pivots {
                edges.push(Edge {
                    from: handle.clone(),
                    to: to.clone(),
                    relation,
                    count,
                });
                if queued.contains(to) {
                    continue;
                }
                if depth + 1 > limits.depth || queued.len() >= limits.names {
                    unread.insert(to.clone());
                    continue;
                }
                queued.insert(to.clone());
                frontier.push_back((to.clone(), depth + 1));
            }
        }
        nodes.push(Node {
            handle,
            depth,
            seen: observed,
        });
    }
    let read: BTreeSet<&str> = nodes.iter().map(|n| n.handle.as_str()).collect();
    unread.retain(|name| !read.contains(name.as_str()));
    Ok(Network {
        seed,
        limits,
        nodes,
        edges,
        unread,
    })
}

/// The map as text: each name read, each edge, the most-amplified names and what was left
/// unread. **Pure.**
#[must_use]
pub fn render(network: &Network) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "telegram-network {}  depth<={}  names<={}",
        network.seed, network.limits.depth, network.limits.names
    );
    let _ = writeln!(out, "\nnames read: {}", network.nodes.len());
    for node in &network.nodes {
        match &node.seen {
            Ok(seen) => {
                let page = &seen.page;
                let size = page
                    .subscribers
                    .map(|n| format!("{n} subscribers"))
                    .or_else(|| page.members.map(|n| format!("{n} members")))
                    .or_else(|| page.monthly_users.map(|n| format!("{n} monthly users")))
                    .unwrap_or_default();
                let activity = match &seen.preview {
                    Some(Ok(p)) => format!(
                        "  posts {}  newest {}",
                        p.posts,
                        p.newest_post_at.as_deref().unwrap_or("?")
                    ),
                    Some(Err(reason)) => format!("  preview not read: {reason}"),
                    None => String::new(),
                };
                let _ = writeln!(
                    out,
                    "node\t{}\tdepth {}\t{}\t{}{}\t{}{}",
                    node.handle,
                    node.depth,
                    page.kind.as_str(),
                    page.title,
                    if page.verified { " [verified]" } else { "" },
                    size,
                    activity
                );
            }
            Err(reason) => {
                let _ = writeln!(
                    out,
                    "node\t{}\tdepth {}\tnot confirmed: {reason}",
                    node.handle, node.depth
                );
            }
        }
    }
    let _ = writeln!(out, "\nedges: {}", network.edges.len());
    for edge in &network.edges {
        let _ = writeln!(
            out,
            "edge\t{}\t{}\t{}\tx{}",
            edge.from, edge.relation, edge.to, edge.count
        );
    }
    let amplified = network.amplified();
    if !amplified.is_empty() {
        let _ = writeln!(
            out,
            "\nmost amplified (channels pointing at it, total count):"
        );
        for (name, from, total) in amplified.iter().take(10) {
            let _ = writeln!(out, "amplified\t{name}\t{from}\t{total}");
        }
    }
    if network.unread.is_empty() {
        let _ = writeln!(out, "\nevery name found within the depth was read");
    } else {
        let _ = writeln!(
            out,
            "\n{} name(s) found but not read because a bound was reached: {}",
            network.unread.len(),
            network
                .unread
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let _ = writeln!(
        out,
        "edges are leads from public posts, never proof of affiliation or control"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::RoutedTransport;

    fn channel(title: &str, subs: u32) -> String {
        format!(
            "<html><div class=\"tgme_page\"><div class=\"tgme_page_title\"><span dir=\"auto\">{title}</span></div><div class=\"tgme_page_extra\">{subs} subscribers</div><div class=\"tgme_page_action\"><a class=\"tgme_action_button_new\">View in Telegram</a></div></div></html>"
        )
    }

    fn preview(own: &str, links: &[&str], forwards: &[&str]) -> String {
        let mut body = format!(
            "<html><div class=\"tgme_widget_message\" data-post=\"{own}/7\"><time datetime=\"2026-11-01T00:00:00+00:00\"></time>"
        );
        for link in links {
            let _ = write!(body, "<a href=\"https://t.me/{link}\">x</a>");
        }
        for from in forwards {
            let _ = write!(
                body,
                "<a class=\"tgme_widget_message_forwarded_from_name\" href=\"https://t.me/{from}/1\">y</a>"
            );
        }
        body.push_str("</div></html>");
        body
    }

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// `seed_chan` links to `alpha_chan` and forwards from `beta_chan`; `alpha_chan` links to
    /// `gamma_chan` and `beta_chan`.
    fn transport() -> RoutedTransport {
        RoutedTransport::new(&[
            (
                "https://t.me/s/seed_chan",
                200,
                leak(preview("seed_chan", &["alpha_chan"], &["beta_chan"])),
            ),
            (
                "https://t.me/s/alpha_chan",
                200,
                leak(preview("alpha_chan", &["gamma_chan", "beta_chan"], &[])),
            ),
            (
                "https://t.me/s/beta_chan",
                200,
                leak(preview("beta_chan", &[], &[])),
            ),
            (
                "https://t.me/s/gamma_chan",
                200,
                leak(preview("gamma_chan", &[], &[])),
            ),
            ("https://t.me/seed_chan", 200, leak(channel("Seed", 100))),
            ("https://t.me/alpha_chan", 200, leak(channel("Alpha", 50))),
            ("https://t.me/beta_chan", 200, leak(channel("Beta", 20))),
            ("https://t.me/gamma_chan", 200, leak(channel("Gamma", 10))),
        ])
    }

    fn handles(network: &Network) -> Vec<&str> {
        network.nodes.iter().map(|n| n.handle.as_str()).collect()
    }

    #[test]
    fn depth_one_reads_the_seed_and_its_neighbours_only() {
        let t = transport();
        let network = crawl(&t, "seed_chan", Limits::default(), 1).expect("crawl");
        assert_eq!(handles(&network), ["seed_chan", "beta_chan", "alpha_chan"]);
        assert!(
            network.unread.contains("gamma_chan"),
            "{:?}",
            network.unread
        );
        assert!(
            !network.unread.contains("beta_chan"),
            "a name read is never unread"
        );
        assert!(network.edges.contains(&Edge {
            from: "seed_chan".into(),
            to: "beta_chan".into(),
            relation: "forwarded_from",
            count: 1
        }));
    }

    #[test]
    fn depth_two_reaches_the_second_hop_and_ranks_the_most_amplified() {
        let t = transport();
        let limits = Limits {
            depth: 2,
            names: 15,
        };
        let network = crawl(&t, "seed_chan", limits, 1).expect("crawl");
        assert_eq!(network.nodes.len(), 4);
        assert!(network.unread.is_empty());
        let top = &network.amplified()[0];
        assert_eq!(
            (top.0.as_str(), top.1),
            ("beta_chan", 2),
            "beta is pointed at by two channels"
        );
        let text = render(&network);
        assert!(text.contains("every name found within the depth was read"));
        assert!(text.contains("never proof of affiliation"));
    }

    #[test]
    fn the_name_cap_stops_reading_and_counts_what_was_left() {
        let t = transport();
        let limits = Limits { depth: 3, names: 2 };
        let network = crawl(&t, "seed_chan", limits, 1).expect("crawl");
        assert_eq!(network.nodes.len(), 2);
        assert!(!network.unread.is_empty());
        assert!(render(&network).contains("not read because a bound was reached"));
    }

    #[test]
    fn a_seed_with_no_public_page_is_one_unconfirmed_node() {
        let t = RoutedTransport::new(&[]);
        let network = crawl(&t, "nobody_here", Limits::default(), 1).expect("crawl");
        assert_eq!(network.nodes.len(), 1);
        assert!(network.nodes[0].seen.is_err());
        assert!(network.edges.is_empty());
    }

    #[test]
    fn limits_above_the_ceiling_are_held_to_it() {
        let t = RoutedTransport::new(&[]);
        let network = crawl(
            &t,
            "nobody_here",
            Limits {
                depth: 9,
                names: 999,
            },
            1,
        )
        .expect("crawl");
        assert_eq!(
            network.limits,
            Limits {
                depth: MAX_DEPTH,
                names: MAX_NAMES
            }
        );
    }

    #[test]
    fn args_accept_handles_links_and_bounded_options() {
        let parse =
            |a: &[&str]| Args::parse(&a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert_eq!(parse(&["@Durov"]).unwrap().seed, "durov");
        assert_eq!(parse(&["https://t.me/s/durov"]).unwrap().seed, "durov");
        let a = parse(&["durov", "--depth", "2", "--max", "30"]).unwrap();
        assert_eq!(
            a.limits,
            Limits {
                depth: 2,
                names: 30
            }
        );
        assert!(parse(&["durov", "--depth", "4"]).is_err());
        assert!(parse(&["durov", "--max", "51"]).is_err());
        assert!(parse(&["bad handle!"]).is_err());
        assert!(parse(&[]).is_err());
        assert!(parse(&["durov", "other"]).is_err());
    }
}
