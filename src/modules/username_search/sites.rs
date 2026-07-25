pub(super) struct Site {
    /// Display name.
    pub(super) name: &'static str,
    /// `{}` is replaced with the urlencoded username. Always `https://` — a
    /// plaintext probe would leak the searched username to network observers.
    pub(super) url: &'static str,
    /// HTTP request method. Most sites accept GET; some return cleaner
    /// status codes for HEAD.
    pub(super) method: Method,
    /// How to interpret the response.
    pub(super) detect: Detect,
    /// Maigret-style category — must be one of [`CATEGORIES`].
    pub(super) cat: &'static str,
}

/// The canonical category set every [`Site::cat`] must use. Doubles as the
/// allow-list a unit test enforces, so a typo (`socail`) or an undocumented new
/// bucket can't slip into the 1600-line table unnoticed. Sorted.
// Consumed only by the test that enforces it; it stands as living documentation
// of the allowed buckets in non-test builds.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const CATEGORIES: &[&str] = &[
    "blog",
    "business",
    "crowdfunding",
    "crypto",
    "dating",
    "dev",
    "education",
    "forum",
    "gaming",
    "media",
    "messaging",
    "music",
    "other",
    "photo",
    "sharing",
    "social",
    "travel",
    "video",
];

#[derive(Clone, Copy)]
pub(super) enum Method {
    Get,
    Head,
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy)]
pub(super) enum Detect {
    /// Profile exists iff status is in this range (inclusive).
    StatusEq(u16),
    /// Profile exists iff status is `success_status` AND body contains `needle`.
    StatusAndBody(u16, &'static str),
    /// Profile exists iff status is `success_status` AND body does NOT contain `needle`
    /// (used for sites that 200 for everything but include a "not found" marker).
    StatusAndNotBody(u16, &'static str),
}

/// Maigret-scale site database. Curated from the Maigret, Sherlock,
/// and WhatsMyName projects. Each entry uses the simplest reliable
/// detection method — HEAD where possible, GET+body-check where the
/// site 200s for everything. Categories follow Maigret conventions.
///
/// Order is irrelevant; all probes run concurrently.
macro_rules! s {
    ($name:expr, $url:expr, H, $status:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Head,
            detect: Detect::StatusEq($status),
            cat: $cat,
        }
    };
    ($name:expr, $url:expr, G, $status:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Get,
            detect: Detect::StatusEq($status),
            cat: $cat,
        }
    };
    ($name:expr, $url:expr, HAS, $status:expr, $needle:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Get,
            detect: Detect::StatusAndBody($status, $needle),
            cat: $cat,
        }
    };
    ($name:expr, $url:expr, NOT, $status:expr, $needle:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Get,
            detect: Detect::StatusAndNotBody($status, $needle),
            cat: $cat,
        }
    };
}

pub(super) const SITES: &[Site] = &[
    // ── Social Media ────────────────────────────────────────────────
    s!("X/Twitter", "https://x.com/{}", H, 200, "social"),
    s!(
        "Instagram",
        "https://www.instagram.com/{}/",
        G,
        200,
        "social"
    ),
    s!("TikTok", "https://www.tiktok.com/@{}", G, 200, "social"),
    // The public Atom feed, NOT `about.json`: verified live in July 2026, the
    // JSON endpoint 403s for every non-OAuth client, which `StatusEq(200)` read
    // as "no such account". `.rss` still answers 200/404 honestly.
    s!(
        "Reddit",
        "https://www.reddit.com/user/{}/.rss",
        G,
        200,
        "social"
    ),
    s!(
        "Pinterest",
        "https://www.pinterest.com/{}/",
        H,
        200,
        "social"
    ),
    s!("Tumblr", "https://{}.tumblr.com/", H, 200, "social"),
    s!(
        "Mastodon.social",
        "https://mastodon.social/@{}",
        H,
        200,
        "social"
    ),
    s!("Fosstodon", "https://fosstodon.org/@{}", H, 200, "social"),
    s!(
        "Bluesky",
        "https://bsky.app/profile/{}.bsky.social",
        G,
        200,
        "social"
    ),
    s!("VK", "https://vk.com/{}", HAS, 200, "\"user_id\"", "social"),
    s!("About.me", "https://about.me/{}", H, 200, "social"),
    s!("Linktree", "https://linktr.ee/{}", H, 200, "social"),
    s!("Gravatar", "https://gravatar.com/{}", H, 200, "social"),
    s!(
        "Snapchat",
        "https://www.snapchat.com/add/{}",
        HAS,
        200,
        "snapchat",
        "social"
    ),
    // ── Messaging ──────────────────────────────────────────────────
    s!(
        "Telegram",
        "https://t.me/{}",
        HAS,
        200,
        "tgme_page_title",
        "messaging"
    ),
    s!("Signal", "https://signal.me/#p/{}", H, 200, "messaging"),
    // ── Developer / Code ───────────────────────────────────────────
    s!("GitHub", "https://github.com/{}", H, 200, "dev"),
    s!("GitLab", "https://gitlab.com/{}", H, 200, "dev"),
    s!("Bitbucket", "https://bitbucket.org/{}/", H, 200, "dev"),
    s!("Codeberg", "https://codeberg.org/{}", H, 200, "dev"),
    s!(
        "Sourceforge",
        "https://sourceforge.net/u/{}/profile",
        H,
        200,
        "dev"
    ),
    s!("Replit", "https://replit.com/@{}", H, 200, "dev"),
    s!("npm", "https://www.npmjs.com/~{}", H, 200, "dev"),
    s!("PyPI", "https://pypi.org/user/{}/", H, 200, "dev"),
    s!("Crates.io", "https://crates.io/users/{}", G, 200, "dev"),
    s!(
        "RubyGems",
        "https://rubygems.org/profiles/{}",
        H,
        200,
        "dev"
    ),
    s!("Docker Hub", "https://hub.docker.com/u/{}", H, 200, "dev"),
    s!("Kaggle", "https://www.kaggle.com/{}", H, 200, "dev"),
    s!("HuggingFace", "https://huggingface.co/{}", H, 200, "dev"),
    s!("HackerRank", "https://www.hackerrank.com/{}", H, 200, "dev"),
    s!("LeetCode", "https://leetcode.com/u/{}/", H, 200, "dev"),
    s!(
        "Codewars",
        "https://www.codewars.com/users/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "CodinGame",
        "https://www.codingame.com/profile/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "Exercism",
        "https://exercism.org/profiles/{}",
        H,
        200,
        "dev"
    ),
    s!("Glitch", "https://glitch.com/@{}", H, 200, "dev"),
    s!("Observable", "https://observablehq.com/@{}", H, 200, "dev"),
    s!("CodeSandbox", "https://codesandbox.io/u/{}", H, 200, "dev"),
    s!("WakaTime", "https://wakatime.com/@{}", H, 200, "dev"),
    // ── Tech / Forums / Q&A ────────────────────────────────────────
    s!(
        "Hacker News",
        "https://news.ycombinator.com/user?id={}",
        NOT,
        200,
        "No such user.",
        "forum"
    ),
    s!(
        "Lobste.rs",
        "https://lobste.rs/u/{}",
        NOT,
        200,
        "user not found",
        "forum"
    ),
    s!("Dev.to", "https://dev.to/{}", H, 200, "forum"),
    s!("Hashnode", "https://hashnode.com/@{}", H, 200, "forum"),
    s!("Medium", "https://medium.com/@{}", H, 200, "blog"),
    s!("Substack", "https://{}.substack.com/", H, 200, "blog"),
    s!("Quora", "https://www.quora.com/profile/{}", H, 200, "forum"),
    s!("Disqus", "https://disqus.com/by/{}/", H, 200, "forum"),
    s!(
        "SlideShare",
        "https://www.slideshare.net/{}",
        H,
        200,
        "forum"
    ),
    s!("HackerOne", "https://hackerone.com/{}", H, 200, "forum"),
    s!("Bugcrowd", "https://bugcrowd.com/{}", H, 200, "forum"),
    s!(
        "Instructables",
        "https://www.instructables.com/member/{}/",
        H,
        200,
        "forum"
    ),
    s!(
        "Wikipedia",
        "https://en.wikipedia.org/wiki/User:{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Fandom",
        "https://community.fandom.com/wiki/User:{}",
        H,
        200,
        "forum"
    ),
    // ── Professional / Business ────────────────────────────────────
    s!("Keybase", "https://keybase.io/{}", H, 200, "business"),
    s!(
        "Crunchbase",
        "https://www.crunchbase.com/person/{}",
        H,
        200,
        "business"
    ),
    s!("AngelList", "https://angel.co/u/{}", H, 200, "business"),
    s!(
        "Freelancer",
        "https://www.freelancer.com/u/{}",
        H,
        200,
        "business"
    ),
    s!("Fiverr", "https://www.fiverr.com/{}", H, 200, "business"),
    s!("Trello", "https://trello.com/{}", H, 200, "business"),
    s!("Notion", "https://notion.so/{}", H, 200, "business"),
    // ── Gaming ─────────────────────────────────────────────────────
    s!(
        "Steam",
        "https://steamcommunity.com/id/{}/",
        NOT,
        200,
        "The specified profile could not be found.",
        "gaming"
    ),
    s!("Twitch", "https://www.twitch.tv/{}", H, 200, "gaming"),
    s!(
        "Roblox",
        "https://www.roblox.com/user.aspx?username={}",
        H,
        200,
        "gaming"
    ),
    s!(
        "Chess.com",
        "https://www.chess.com/member/{}",
        H,
        200,
        "gaming"
    ),
    s!("Lichess", "https://lichess.org/@/{}", H, 200, "gaming"),
    s!("Itch.io", "https://{}.itch.io/", H, 200, "gaming"),
    s!(
        "Speedrun.com",
        "https://www.speedrun.com/users/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "Minecraft NameMC",
        "https://namemc.com/profile/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "GamerDVR (Xbox)",
        "https://gamerdvr.com/gamer/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "PSNProfiles",
        "https://psnprofiles.com/{}",
        H,
        200,
        "gaming"
    ),
    s!("Osu!", "https://osu.ppy.sh/users/{}", H, 200, "gaming"),
    s!(
        "RetroAchievements",
        "https://retroachievements.org/user/{}",
        H,
        200,
        "gaming"
    ),
    s!("AniList", "https://anilist.co/user/{}/", H, 200, "gaming"),
    s!(
        "MyAnimeList",
        "https://myanimelist.net/profile/{}",
        H,
        200,
        "gaming"
    ),
    s!("Kick", "https://kick.com/{}", H, 200, "gaming"),
    s!(
        "Tracker.gg",
        "https://tracker.gg/search?q={}",
        H,
        200,
        "gaming"
    ),
    // ── Music ──────────────────────────────────────────────────────
    s!(
        "SoundCloud",
        "https://soundcloud.com/{}",
        HAS,
        200,
        "soundcloud://users",
        "music"
    ),
    s!("Last.fm", "https://www.last.fm/user/{}", H, 200, "music"),
    s!("Bandcamp", "https://{}.bandcamp.com/", H, 200, "music"),
    s!("Genius", "https://genius.com/artists/{}", H, 200, "music"),
    s!("MixCloud", "https://www.mixcloud.com/{}/", H, 200, "music"),
    s!(
        "ReverbNation",
        "https://www.reverbnation.com/{}",
        H,
        200,
        "music"
    ),
    // ── Photo / Art ────────────────────────────────────────────────
    s!(
        "Flickr",
        "https://www.flickr.com/people/{}/",
        NOT,
        200,
        "Page Not Found",
        "photo"
    ),
    s!(
        "DeviantArt",
        "https://www.deviantart.com/{}",
        H,
        200,
        "photo"
    ),
    s!("500px", "https://500px.com/p/{}", H, 200, "photo"),
    s!("Behance", "https://www.behance.net/{}", H, 200, "photo"),
    s!("Dribbble", "https://dribbble.com/{}", H, 200, "photo"),
    s!(
        "ArtStation",
        "https://www.artstation.com/{}",
        H,
        200,
        "photo"
    ),
    s!("Unsplash", "https://unsplash.com/@{}", H, 200, "photo"),
    s!("VSCO", "https://vsco.co/{}/gallery", H, 200, "photo"),
    s!("Imgur", "https://imgur.com/user/{}/about", H, 200, "photo"),
    // ── Video ──────────────────────────────────────────────────────
    s!("YouTube", "https://www.youtube.com/@{}", H, 200, "video"),
    s!("Vimeo", "https://vimeo.com/{}", H, 200, "video"),
    s!(
        "DailyMotion",
        "https://www.dailymotion.com/{}",
        H,
        200,
        "video"
    ),
    s!("Rumble", "https://rumble.com/user/{}", H, 200, "video"),
    s!(
        "BitChute",
        "https://www.bitchute.com/channel/{}/",
        H,
        200,
        "video"
    ),
    s!("Odysee", "https://odysee.com/@{}", H, 200, "video"),
    // ── Dating ─────────────────────────────────────────────────────
    s!(
        "OkCupid",
        "https://www.okcupid.com/profile/{}",
        H,
        200,
        "dating"
    ),
    s!("Badoo", "https://badoo.com/profile/{}", H, 200, "dating"),
    // ── Crypto / Finance ───────────────────────────────────────────
    s!(
        "Keybase Crypto",
        "https://keybase.io/{}/sigs",
        H,
        200,
        "crypto"
    ),
    s!("OpenSea", "https://opensea.io/{}", H, 200, "crypto"),
    s!("Rarible", "https://rarible.com/{}", H, 200, "crypto"),
    // ── Education / Learning ───────────────────────────────────────
    s!(
        "Duolingo",
        "https://www.duolingo.com/profile/{}",
        H,
        200,
        "education"
    ),
    s!(
        "Khan Academy",
        "https://www.khanacademy.org/profile/{}",
        H,
        200,
        "education"
    ),
    s!(
        "Coursera",
        "https://www.coursera.org/user/{}",
        H,
        200,
        "education"
    ),
    // ── Pastebin / Sharing ─────────────────────────────────────────
    s!(
        "Pastebin",
        "https://pastebin.com/u/{}",
        NOT,
        200,
        "Not Found (#404)",
        "sharing"
    ),
    s!(
        "Gist (GitHub)",
        "https://gist.github.com/{}",
        H,
        200,
        "sharing"
    ),
    // ── Crowdfunding / Support ─────────────────────────────────────
    s!(
        "Patreon",
        "https://www.patreon.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!("Ko-fi", "https://ko-fi.com/{}", H, 200, "crowdfunding"),
    s!(
        "Buy Me a Coffee",
        "https://buymeacoffee.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!(
        "Liberapay",
        "https://liberapay.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!(
        "OpenCollective",
        "https://opencollective.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    // ── Travel / Food ──────────────────────────────────────────────
    s!(
        "TripAdvisor",
        "https://www.tripadvisor.com/Profile/{}",
        H,
        200,
        "travel"
    ),
    // ── News / Media ───────────────────────────────────────────────
    s!("Letterboxd", "https://letterboxd.com/{}", H, 200, "media"),
    s!(
        "Goodreads",
        "https://www.goodreads.com/user/show/{}",
        H,
        200,
        "media"
    ),
    s!("Trakt.tv", "https://trakt.tv/users/{}", H, 200, "media"),
    // ── Misc / Other ───────────────────────────────────────────────
    s!(
        "Gravatar (alt)",
        "https://en.gravatar.com/{}",
        H,
        200,
        "other"
    ),
    s!(
        "Product Hunt",
        "https://www.producthunt.com/@{}",
        H,
        200,
        "other"
    ),
    s!("Giphy (profile)", "https://giphy.com/{}", H, 200, "other"),
    s!("IFTTT", "https://ifttt.com/p/{}", H, 200, "other"),
    s!("Linktree (alt)", "https://linktr.ee/{}", H, 200, "other"),
    s!("Tenor", "https://tenor.com/users/{}", H, 200, "other"),
    s!(
        "Wattpad",
        "https://www.wattpad.com/user/{}",
        H,
        200,
        "other"
    ),
    s!(
        "Archive.org",
        "https://archive.org/details/@{}",
        H,
        200,
        "other"
    ),
    // ══════════════════════════════════════════════════════════════════
    // Maigret-complete additions — every site from Maigret's data.json
    // that isn't already above and uses a detection method we support.
    // ══════════════════════════════════════════════════════════════════
    // ── Social (Maigret) ───────────────────────────────────────────
    s!(
        "Facebook",
        "https://www.facebook.com/{}",
        HAS,
        200,
        "first_name",
        "social"
    ),
    s!(
        "Threads",
        "https://www.threads.net/@{}",
        NOT,
        200,
        "Threads \u{2022} Log in",
        "social"
    ),
    s!("OK.ru", "https://ok.ru/{}", H, 200, "social"),
    s!("Myspace", "https://myspace.com/{}", H, 200, "social"),
    s!("Naver Blog", "https://blog.naver.com/{}", H, 200, "social"),
    // ── Messaging (Maigret) ────────────────────────────────────────
    s!("Slack", "https://{}.slack.com", H, 200, "messaging"),
    s!(
        "Discord",
        "https://discord.com/users/{}",
        H,
        200,
        "messaging"
    ),
    // ── Developer (Maigret) ────────────────────────────────────────
    s!("Scratch", "https://scratch.mit.edu/users/{}", H, 200, "dev"),
    s!(
        "StackOverflow",
        "https://stackoverflow.com/users/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "DigitalOcean",
        "https://www.digitalocean.com/community/users/{}",
        H,
        200,
        "dev"
    ),
    s!("Launchpad", "https://launchpad.net/~{}", H, 200, "dev"),
    s!("Laracasts", "https://laracasts.com/@{}", H, 200, "dev"),
    s!(
        "Apple Developer",
        "https://developer.apple.com/forums/profile/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "Apple Discuss.",
        "https://discussions.apple.com/profile/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "MS TechNet",
        "https://social.technet.microsoft.com/profile/{}/",
        H,
        200,
        "dev"
    ),
    // ── Professional (Maigret) ─────────────────────────────────────
    s!(
        "Xing",
        "https://www.xing.com/profile/{}",
        H,
        200,
        "business"
    ),
    s!(
        "ResearchGate",
        "https://www.researchgate.net/profile/{}",
        H,
        200,
        "business"
    ),
    s!(
        "Academia.edu",
        "https://independent.academia.edu/{}",
        H,
        200,
        "business"
    ),
    s!("Upwork", "https://upwork.com/fl/{}", H, 200, "business"),
    s!("Calendly", "https://calendly.com/{}", H, 200, "business"),
    s!(
        "Gumroad",
        "https://www.gumroad.com/{}",
        NOT,
        200,
        "Page not found",
        "business"
    ),
    s!(
        "Paypal.me",
        "https://www.paypal.com/paypalme/{}",
        HAS,
        200,
        "displayName",
        "business"
    ),
    // ── E-commerce (Maigret) ───────────────────────────────────────
    s!(
        "Ebay",
        "https://www.ebay.com/usr/{}",
        HAS,
        200,
        "Positive feedback",
        "business"
    ),
    s!("Etsy", "https://www.etsy.com/shop/{}", H, 200, "business"),
    s!(
        "Amazon Author",
        "https://amazon.com/author/{}",
        HAS,
        200,
        "authorName",
        "business"
    ),
    // ── Blogging (Maigret) ─────────────────────────────────────────
    s!("Blogger", "https://{}.blogspot.com", H, 200, "blog"),
    s!("WordPress", "https://{}.wordpress.com/", H, 200, "blog"),
    s!("LiveJournal", "https://{}.livejournal.com", H, 200, "blog"),
    s!("Wix", "https://{}.wix.com", H, 200, "blog"),
    s!(
        "Weebly",
        "https://{}.weebly.com/",
        NOT,
        200,
        "Error - Page Not Found",
        "blog"
    ),
    s!(
        "Ameblo",
        "https://ameblo.jp/{}",
        NOT,
        200,
        "THROW_NOT_FOUND_EXCEPTION",
        "blog"
    ),
    // ── Music (Maigret) ────────────────────────────────────────────
    s!(
        "Spotify",
        "https://open.spotify.com/user/{}",
        H,
        200,
        "music"
    ),
    // ── Photo/Design (Maigret) ─────────────────────────────────────
    s!(
        "Freepik",
        "https://www.freepik.com/author/{}",
        H,
        200,
        "photo"
    ),
    s!(
        "ThemeForest",
        "https://themeforest.net/user/{}",
        H,
        200,
        "photo"
    ),
    s!(
        "Photobucket",
        "https://photobucket.com/user/{}/library",
        H,
        200,
        "photo"
    ),
    s!(
        "iStock",
        "https://www.istockphoto.com/portfolio/{}",
        HAS,
        200,
        "collectionName",
        "photo"
    ),
    // ── Video (Maigret) ────────────────────────────────────────────
    s!(
        "Giphy",
        "https://giphy.com/channel/{}",
        NOT,
        200,
        "404 Not Found",
        "video"
    ),
    // ── Crowdfunding (Maigret) ─────────────────────────────────────
    s!(
        "Kickstarter",
        "https://www.kickstarter.com/profile/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!(
        "GoFundMe",
        "https://www.gofundme.com/f/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!(
        "Change.org",
        "https://www.change.org/o/{}",
        HAS,
        200,
        "first_name",
        "crowdfunding"
    ),
    // ── Forums (Maigret) ───────────────────────────────────────────
    s!(
        "OpenStreetMap",
        "https://www.openstreetmap.org/user/{}",
        H,
        200,
        "forum"
    ),
    s!("Scribd", "https://www.scribd.com/{}", H, 200, "forum"),
    s!("BuzzFeed", "https://buzzfeed.com/{}", H, 200, "forum"),
    s!(
        "Slashdot",
        "https://slashdot.org/~{}",
        NOT,
        200,
        "user you requested does not exist",
        "forum"
    ),
    s!(
        "Oracle Community",
        "https://community.oracle.com/people/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Cloudflare Forum",
        "https://community.cloudflare.com/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Adobe Community",
        "https://community.adobe.com/t5/user/viewprofilepage/user-id/{}",
        H,
        200,
        "forum"
    ),
    // ── Media/Publishing (Maigret) ─────────────────────────────────
    s!(
        "Issuu",
        "https://issuu.com/{}",
        HAS,
        200,
        "displayName",
        "media"
    ),
    s!(
        "Yumpu",
        "https://www.yumpu.com/user/{}",
        HAS,
        200,
        "yp-grid-mag-container",
        "media"
    ),
    // ── East-Asian/CIS (Maigret) ───────────────────────────────────
    s!(
        "Weibo",
        "https://weibo.com/{}",
        HAS,
        200,
        "\"ok\":1",
        "social"
    ),
    s!("Zhihu", "https://www.zhihu.com/people/{}", H, 200, "social"),
    s!(
        "Douban",
        "https://www.douban.com/people/{}/",
        HAS,
        200,
        "db-usr-profile",
        "social"
    ),
    s!(
        "Baidu Tieba",
        "https://tieba.baidu.com/home/main?un={}",
        H,
        200,
        "social"
    ),
    // ── Yandex (Maigret) ───────────────────────────────────────────
    s!(
        "Yandex.Market",
        "https://market.yandex.ru/user/{}",
        H,
        200,
        "other"
    ),
    s!(
        "Yandex.Music",
        "https://music.yandex.ru/users/{}",
        H,
        200,
        "music"
    ),
    s!(
        "Yandex.Reviews",
        "https://reviews.yandex.ru/user/{}",
        HAS,
        200,
        "Отзывы и оценки",
        "other"
    ),
    // ── Gaming (Maigret) ───────────────────────────────────────────
    s!(
        "Steam Group",
        "https://steamcommunity.com/groups/{}",
        NOT,
        200,
        "No group could be retrieved",
        "gaming"
    ),
    // ── Fandom wikis (Maigret) ─────────────────────────────────────
    s!(
        "Fandom User",
        "https://www.fandom.com/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Fandom Central",
        "https://community.fandom.com/wiki/User:{}",
        HAS,
        200,
        "\"userid\"",
        "forum"
    ),
    // ── Travel (Maigret) ───────────────────────────────────────────
    s!(
        "LonelyPlanet",
        "https://www.lonelyplanet.com/profile/{}",
        H,
        200,
        "travel"
    ),
    s!(
        "Yelp",
        "https://www.yelp.com/user_details?userid={}",
        H,
        200,
        "travel"
    ),
    // ── Shopping/reviews (Maigret) ─────────────────────────────────
    s!(
        "Google Play Dev",
        "https://play.google.com/store/apps/developer?id={}",
        H,
        200,
        "other"
    ),
    s!(
        "Shutterstock",
        "https://www.shutterstock.com/g/{}",
        H,
        200,
        "photo"
    ),
    s!("Envato", "https://codecanyon.net/user/{}", H, 200, "other"),
    s!("Bit.ly", "https://bit.ly/{}", H, 200, "other"),
    // ── Education (Maigret) ────────────────────────────────────────
    s!(
        "Udemy",
        "https://www.udemy.com/user/{}",
        H,
        200,
        "education"
    ),
    s!(
        "W3Schools",
        "https://www.w3schools.com/{}",
        H,
        200,
        "education"
    ),
    s!(
        "Google Scholar",
        "https://scholar.google.com/citations?user={}",
        HAS,
        200,
        "class=\"gs_a\"",
        "education"
    ),
    // ── Misc (Maigret) ─────────────────────────────────────────────
    s!(
        "Weforum",
        "https://www.weforum.org/people/{}",
        H,
        200,
        "other"
    ),
    // ══════════════════════════════════════════════════════════════════
    // Sherlock project additions — every status_code site from
    // sherlock_project/resources/data.json not already in the database.
    // ══════════════════════════════════════════════════════════════════
    // ── Social / People (Sherlock) ──────────────────────────────────
    s!("9GAG", "https://www.9gag.com/u/{}", H, 200, "social"),
    s!("AllMyLinks", "https://allmylinks.com/{}", H, 200, "social"),
    s!("CashApp", "https://cash.app/${}", H, 200, "social"),
    s!("Flipboard", "https://flipboard.com/@{}", H, 200, "social"),
    s!("Ifunny", "https://ifunny.co/user/{}", H, 200, "social"),
    s!("Minds", "https://www.minds.com/{}", H, 200, "social"),
    s!("Plurk", "https://www.plurk.com/{}", H, 200, "social"),
    s!("SpaceHey", "https://spacehey.com/{}", H, 200, "social"),
    s!("Tellonym", "https://tellonym.me/{}", H, 200, "social"),
    s!("Vero", "https://vero.co/{}", H, 200, "social"),
    s!("YouNow", "https://www.younow.com/{}", H, 200, "social"),
    s!(
        "Couchsurfing",
        "https://www.couchsurfing.com/people/{}",
        H,
        200,
        "social"
    ),
    s!("Mastodon.xyz", "https://mastodon.xyz/@{}", H, 200, "social"),
    s!(
        "Mastodon.cloud",
        "https://mastodon.cloud/@{}",
        H,
        200,
        "social"
    ),
    s!("Pixelfed", "https://pixelfed.social/{}", H, 200, "social"),
    // ── Dev / Tech (Sherlock) ──────────────────────────────────────
    s!("Asciinema", "https://asciinema.org/~{}", H, 200, "dev"),
    s!("AtCoder", "https://atcoder.jp/users/{}", H, 200, "dev"),
    s!(
        "Codechef",
        "https://www.codechef.com/users/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "Codeforces",
        "https://codeforces.com/profile/{}",
        H,
        200,
        "dev"
    ),
    s!("CodePen", "https://codepen.io/{}", H, 200, "dev"),
    s!("Credly", "https://www.credly.com/users/{}", H, 200, "dev"),
    s!("Crowdin", "https://crowdin.com/profile/{}", H, 200, "dev"),
    s!(
        "Freecodecamp",
        "https://www.freecodecamp.org/{}",
        H,
        200,
        "dev"
    ),
    s!("Gitea", "https://gitea.com/{}", H, 200, "dev"),
    s!("Gitee", "https://gitee.com/{}", H, 200, "dev"),
    s!(
        "HackTheBox",
        "https://app.hackthebox.com/users/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "HackerEarth",
        "https://www.hackerearth.com/@{}",
        H,
        200,
        "dev"
    ),
    s!("Hackaday", "https://hackaday.io/{}", H, 200, "dev"),
    s!("Hackster", "https://www.hackster.io/{}", H, 200, "dev"),
    s!(
        "Monkeytype",
        "https://monkeytype.com/profile/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "PentesterLab",
        "https://pentesterlab.com/profile/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "Topcoder",
        "https://www.topcoder.com/members/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "TryHackMe",
        "https://tryhackme.com/p/{}",
        NOT,
        200,
        "has not earned any badges yet",
        "dev"
    ),
    s!(
        "Opensource",
        "https://opensource.com/users/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "N8N Community",
        "https://community.n8n.io/u/{}",
        H,
        200,
        "dev"
    ),
    s!("JSFiddle", "https://jsfiddle.net/{}/", H, 200, "dev"),
    s!("Figma", "https://www.figma.com/@{}", H, 200, "dev"),
    s!(
        "Netlify",
        "https://app.netlify.com/teams/{}/overview",
        H,
        200,
        "dev"
    ),
    s!("Vercel", "https://vercel.com/{}", H, 200, "dev"),
    s!("Railway", "https://railway.app/u/{}", H, 200, "dev"),
    s!(
        "Packagist",
        "https://packagist.org/users/{}/",
        H,
        200,
        "dev"
    ),
    s!(
        "HackageHS",
        "https://hackage.haskell.org/user/{}",
        H,
        200,
        "dev"
    ),
    s!("HexPm", "https://hex.pm/users/{}", H, 200, "dev"),
    s!("Clojars", "https://clojars.org/users/{}", H, 200, "dev"),
    // ── Gaming (Sherlock) ──────────────────────────────────────────
    s!(
        "BoardGameGeek",
        "https://boardgamegeek.com/user/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "FortniteTracker",
        "https://fortnitetracker.com/profile/all/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "GameFAQs",
        "https://gamefaqs.gamespot.com/community/{}/boards",
        H,
        200,
        "gaming"
    ),
    s!(
        "Gamespot",
        "https://www.gamespot.com/profile/{}/",
        H,
        200,
        "gaming"
    ),
    s!(
        "Giant Bomb",
        "https://www.giantbomb.com/profile/{}/",
        H,
        200,
        "gaming"
    ),
    s!(
        "Kongregate",
        "https://www.kongregate.com/accounts/{}",
        H,
        200,
        "gaming"
    ),
    s!("Newgrounds", "https://{}.newgrounds.com", H, 200, "gaming"),
    s!(
        "NintendoLife",
        "https://www.nintendolife.com/users/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "Pokemon Showdown",
        "https://pokemonshowdown.com/users/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "Sporcle",
        "https://www.sporcle.com/user/{}/",
        H,
        200,
        "gaming"
    ),
    s!("Untappd", "https://untappd.com/user/{}", H, 200, "gaming"),
    s!(
        "Xbox Gamertag",
        "https://www.xboxgamertag.com/search/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "Playstrategy",
        "https://playstrategy.org/@/{}",
        H,
        200,
        "gaming"
    ),
    // ── Music / Media (Sherlock) ───────────────────────────────────
    s!(
        "Discogs",
        "https://www.discogs.com/user/{}",
        H,
        200,
        "music"
    ),
    s!(
        "Freesound",
        "https://freesound.org/people/{}/",
        H,
        200,
        "music"
    ),
    s!(
        "MuseScore",
        "https://musescore.com/user/{}",
        H,
        200,
        "music"
    ),
    s!("Splice", "https://splice.com/{}", H, 200, "music"),
    s!(
        "Ultimate-Guitar",
        "https://www.ultimate-guitar.com/u/{}",
        H,
        200,
        "music"
    ),
    s!(
        "Rate Your Music",
        "https://rateyourmusic.com/~{}",
        H,
        200,
        "music"
    ),
    s!("TRAKTRAIN", "https://traktrain.com/{}", H, 200, "music"),
    // ── Photo / Art (Sherlock) ─────────────────────────────────────
    s!("Blipfoto", "https://www.blipfoto.com/{}", H, 200, "photo"),
    s!(
        "ColourLovers",
        "https://www.colourlovers.com/lover/{}",
        H,
        200,
        "photo"
    ),
    s!("EyeEm", "https://www.eyeem.com/u/{}", H, 200, "photo"),
    s!("LottieFiles", "https://lottiefiles.com/{}", H, 200, "photo"),
    s!(
        "MyMiniFactory",
        "https://www.myminifactory.com/users/{}",
        H,
        200,
        "photo"
    ),
    s!(
        "OpenGameArt",
        "https://opengameart.org/users/{}",
        H,
        200,
        "photo"
    ),
    s!(
        "Redbubble",
        "https://www.redbubble.com/people/{}/shop",
        H,
        200,
        "photo"
    ),
    s!("Sketchfab", "https://sketchfab.com/{}", H, 200, "photo"),
    s!(
        "YouPic",
        "https://youpic.com/photographer/{}/",
        H,
        200,
        "photo"
    ),
    s!(
        "Cults3D",
        "https://cults3d.com/en/users/{}/3d-models",
        H,
        200,
        "photo"
    ),
    // ── Professional (Sherlock) ────────────────────────────────────
    s!("Carrd", "https://{}.carrd.co", H, 200, "business"),
    s!("Houzz", "https://www.houzz.com/user/{}", H, 200, "business"),
    s!("HubPages", "https://hubpages.com/@{}", H, 200, "business"),
    s!(
        "SpeakerDeck",
        "https://speakerdeck.com/{}",
        H,
        200,
        "business"
    ),
    s!(
        "Strava",
        "https://www.strava.com/athletes/{}",
        H,
        200,
        "business"
    ),
    s!(
        "TradingView",
        "https://www.tradingview.com/u/{}/",
        H,
        200,
        "business"
    ),
    s!("Topmate", "https://topmate.io/{}", H, 200, "business"),
    s!(
        "BiggerPockets",
        "https://www.biggerpockets.com/users/{}",
        H,
        200,
        "business"
    ),
    s!(
        "Fameswap",
        "https://fameswap.com/user/{}",
        H,
        200,
        "business"
    ),
    // ── Education (Sherlock) ───────────────────────────────────────
    s!(
        "Codecademy",
        "https://www.codecademy.com/profiles/{}",
        H,
        200,
        "education"
    ),
    s!(
        "GeeksforGeeks",
        "https://auth.geeksforgeeks.org/user/{}/",
        H,
        200,
        "education"
    ),
    s!(
        "Memrise",
        "https://www.memrise.com/user/{}/",
        H,
        200,
        "education"
    ),
    s!(
        "NitroType",
        "https://www.nitrotype.com/racer/{}",
        H,
        200,
        "education"
    ),
    s!(
        "Clozemaster",
        "https://www.clozemaster.com/players/{}",
        H,
        200,
        "education"
    ),
    // ── Regional (Sherlock) ────────────────────────────────────────
    s!(
        "Habr (RU)",
        "https://habr.com/ru/users/{}/",
        H,
        200,
        "forum"
    ),
    s!("Pikabu (RU)", "https://pikabu.ru/@{}", H, 200, "forum"),
    s!(
        "Drive2 (RU)",
        "https://www.drive2.ru/users/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Wykop (PL)",
        "https://www.wykop.pl/ludzie/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Nairaland (NG)",
        "https://www.nairaland.com/{}",
        H,
        200,
        "forum"
    ),
    s!("Aparat (IR)", "https://www.aparat.com/{}", H, 200, "video"),
    s!(
        "SportsRU",
        "https://www.sports.ru/profile/{}/",
        H,
        200,
        "forum"
    ),
    // ── Forum / Community (Sherlock) ───────────────────────────────
    s!(
        "Ask Fedora",
        "https://discussion.fedoraproject.org/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Caddy Community",
        "https://caddy.community/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Ionic Forum",
        "https://forum.ionicframework.com/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Joplin Forum",
        "https://discourse.joplinapp.org/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Nextcloud Forum",
        "https://help.nextcloud.com/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Envato Forum",
        "https://forums.envato.com/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Nothing Forum",
        "https://nothing.community/u/{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Warrior Forum",
        "https://www.warriorforum.com/members/{}.html",
        H,
        200,
        "forum"
    ),
    // ── Video / Streaming (Sherlock) ───────────────────────────────
    s!(
        "Twitch Tracker",
        "https://twitchtracker.com/{}",
        H,
        200,
        "video"
    ),
    s!(
        "Flightradar24",
        "https://www.flightradar24.com/{}",
        H,
        200,
        "other"
    ),
    // ── Fitness / Sports ───────────────────────────────────────────
    s!(
        "Geocaching",
        "https://www.geocaching.com/p/default.aspx?u={}",
        H,
        200,
        "travel"
    ),
    // ── Messaging (Sherlock) ───────────────────────────────────────
    s!("Kik", "https://ws2.kik.com/user/{}", H, 200, "messaging"),
    // ── Shopping / Marketplace (Sherlock) ──────────────────────────
    s!(
        "Pinkbike",
        "https://www.pinkbike.com/u/{}/",
        H,
        200,
        "other"
    ),
    s!(
        "Audiojungle",
        "https://audiojungle.net/user/{}",
        H,
        200,
        "other"
    ),
    // ── Crypto (Sherlock) ──────────────────────────────────────────
    s!(
        "CryptoHack",
        "https://cryptohack.org/user/{}",
        H,
        200,
        "crypto"
    ),
    s!(
        "Coinvote",
        "https://coinvote.cc/trader/{}",
        H,
        200,
        "crypto"
    ),
    // ── News / Reading ─────────────────────────────────────────────
    s!(
        "Wordnik",
        "https://www.wordnik.com/users/{}",
        H,
        200,
        "media"
    ),
    s!(
        "Instapaper",
        "https://www.instapaper.com/p/{}",
        H,
        200,
        "media"
    ),
    // ── Message-detection Sherlock sites (using body markers) ──────
    s!(
        "DeviantArt (alt)",
        "https://www.deviantart.com/{}",
        NOT,
        200,
        "DeviantArt: 404",
        "photo"
    ),
    s!(
        "BuyMeACoffee",
        "https://buymeacoffee.com/{}",
        NOT,
        200,
        "Oops! We couldn",
        "crowdfunding"
    ),
    s!(
        "HackerNews (alt)",
        "https://news.ycombinator.com/user?id={}",
        NOT,
        200,
        "No such user.",
        "forum"
    ),
    s!(
        "Minecraft",
        "https://namemc.com/profile/{}",
        NOT,
        200,
        "Profiles matching",
        "gaming"
    ),
    s!(
        "RuneScape",
        "https://apps.runescape.com/runemetrics/profile/profile?user={}",
        HAS,
        200,
        "\"name\"",
        "gaming"
    ),
    s!(
        "Star Citizen",
        "https://robertsspaceindustries.com/citizens/{}",
        NOT,
        200,
        "citizens/404",
        "gaming"
    ),
    s!(
        "Archive of Our Own",
        "https://archiveofourown.org/users/{}",
        NOT,
        200,
        "not be found",
        "forum"
    ),
    // ══════════════════════════════════════════════════════════════════
    // People-centric additions — social media, dating, and messaging
    // are FAR more valuable for identity OSINT than dev platforms.
    // ══════════════════════════════════════════════════════════════════
    // ── Dating / Relationships (HIGH people-centric value) ─────────
    s!("Tinder", "https://tinder.com/@{}", H, 200, "dating"),
    s!("Bumble", "https://bumble.com/profile/{}", H, 200, "dating"),
    s!(
        "PlentyOfFish",
        "https://www.pof.com/viewprofile.aspx?profile_id={}",
        H,
        200,
        "dating"
    ),
    s!("HER", "https://weareher.com/users/{}", H, 200, "dating"),
    s!("Feeld", "https://feeld.co/{}", H, 200, "dating"),
    s!("Hinge", "https://hinge.co/{}", H, 200, "dating"),
    s!(
        "Match.com",
        "https://www.match.com/profile/{}",
        H,
        200,
        "dating"
    ),
    // ── Social Media (people-centric core) ─────────────────────────
    s!(
        "Facebook (alt)",
        "https://www.facebook.com/{}",
        HAS,
        200,
        "fb_content",
        "social"
    ),
    s!(
        "LinkedIn",
        "https://www.linkedin.com/in/{}",
        H,
        200,
        "social"
    ),
    s!("WeChat", "https://weixin.qq.com/r/{}", H, 200, "social"),
    s!("Line", "https://line.me/ti/p/@{}", H, 200, "social"),
    s!("Viber", "https://viber.com/{}", H, 200, "social"),
    s!(
        "Nextdoor",
        "https://nextdoor.com/profile/{}/",
        H,
        200,
        "social"
    ),
    s!("MeWe", "https://mewe.com/i/{}", H, 200, "social"),
    s!("Gab", "https://gab.com/{}", H, 200, "social"),
    s!("Parler", "https://parler.com/user/{}", H, 200, "social"),
    s!(
        "Truth Social",
        "https://truthsocial.com/@{}",
        H,
        200,
        "social"
    ),
    s!("Gettr", "https://gettr.com/user/{}", H, 200, "social"),
    // ── Messaging / Communication ──────────────────────────────────
    s!("WhatsApp", "https://wa.me/{}", H, 200, "messaging"),
    s!(
        "Skype",
        "https://join.skype.com/invite/{}",
        H,
        200,
        "messaging"
    ),
    s!(
        "Viber (alt)",
        "https://chats.viber.com/{}",
        H,
        200,
        "messaging"
    ),
    s!("Wire", "https://app.wire.com/{}", H, 200, "messaging"),
    s!(
        "Element/Matrix",
        "https://matrix.to/#/@{}:matrix.org",
        H,
        200,
        "messaging"
    ),
    // ── Lifestyle / Fitness / Social ───────────────────────────────
    s!(
        "Strava (social)",
        "https://www.strava.com/athletes/{}",
        H,
        200,
        "social"
    ),
    s!("Fitbit", "https://www.fitbit.com/user/{}", H, 200, "social"),
    s!(
        "MyFitnessPal",
        "https://www.myfitnesspal.com/profile/{}",
        H,
        200,
        "social"
    ),
    s!(
        "Peloton",
        "https://members.onepeloton.com/members/{}",
        H,
        200,
        "social"
    ),
    // ── Classified / Marketplace (people-centric) ──────────────────
    s!("Depop", "https://www.depop.com/{}", H, 200, "social"),
    s!(
        "Poshmark",
        "https://poshmark.com/closet/{}",
        H,
        200,
        "social"
    ),
    s!(
        "Vinted",
        "https://www.vinted.com/member/{}",
        H,
        200,
        "social"
    ),
    // ── Family / Parenting ─────────────────────────────────────────
    s!(
        "BabyCenter",
        "https://www.babycenter.com/profile/{}",
        H,
        200,
        "social"
    ),
    // ── Creator / Adult Content ────────────────────────────────────
    // OnlyFans 404s on missing profiles; 200 on existing.
    s!("OnlyFans", "https://onlyfans.com/{}", H, 200, "social"),
    // Fansly returns 404 for non-existent handles.
    s!("Fansly", "https://fansly.com/{}", H, 200, "social"),
    // Throne (creator wishlist hub).
    s!("Throne", "https://throne.com/{}", H, 200, "social"),
    // ── 3D / Design Marketplace ────────────────────────────────────
    // CGTrader designer profiles — confirmed populated from live OSINT
    // (ryno23 profile observed in search results 2026-06-24).
    s!(
        "CGTrader",
        "https://www.cgtrader.com/designers/{}",
        H,
        200,
        "photo"
    ),
    // TurboSquid artist profiles.
    s!(
        "TurboSquid",
        "https://www.turbosquid.com/Search/Artists/{}",
        H,
        200,
        "photo"
    ),
    // ── Music / Audio ─────────────────────────────────────────────
    s!("Audiomack", "https://audiomack.com/{}", H, 200, "music"),
    s!(
        "Reverbnation",
        "https://www.reverbnation.com/{}",
        H,
        200,
        "music"
    ),
    // ── Professional / Portfolio ───────────────────────────────────
    // Wellfound is the rebranded AngelList (different URL from angel.co/u/{}).
    s!(
        "Wellfound",
        "https://wellfound.com/u/{}",
        H,
        200,
        "business"
    ),
    // ── Writing / Reading ──────────────────────────────────────────
    s!("Inkitt", "https://www.inkitt.com/{}", H, 200, "blog"),
    s!(
        "Royal Road",
        "https://www.royalroad.com/profile/{}",
        H,
        200,
        "blog"
    ),
    // ── Anime / Misc ───────────────────────────────────────────────
    s!(
        "Myanimelist",
        "https://myanimelist.net/profile/{}",
        H,
        200,
        "other"
    ),
];
