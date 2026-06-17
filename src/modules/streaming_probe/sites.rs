/// One live-streaming / fan-subscription / adult-video platform to probe.
/// Same probe contract as `username_search::sites::Site` — parallel HEAD/GET
/// requests with three detection modes (status-only, body-must-contain,
/// body-must-not-contain). Kept in a separate module from `username_search`
/// because the target audience (cam, fans, adult) differs and the false-positive
/// cost is higher: a missed profile on GitHub is low stakes; a missed profile on
/// Chaturbate may be the only corroborating identity hit.
pub(super) struct Site {
    pub(super) name: &'static str,
    /// `{}` replaced with the URL-encoded username. Must be `https://`.
    pub(super) url: &'static str,
    pub(super) method: Method,
    pub(super) detect: Detect,
    /// Category bucket — must be a member of [`CATEGORIES`].
    pub(super) cat: &'static str,
}

/// Canonical category set for this module's [`Site::cat`] field.
/// Enforced at test time so a typo fails CI rather than silently
/// mis-classifying (same discipline as `username_search`).
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const CATEGORIES: &[&str] = &[
    "adult", // Adult-video profile pages (Pornhub model, xHamster, xVideos, …)
    "cam",   // Live webcam / streaming platforms (Chaturbate, Stripchat, …)
    "fans",  // Fan-subscription / content-creator platforms (OnlyFans, Fansly, …)
];

#[derive(Clone, Copy)]
pub(super) enum Method {
    Get,
    Head,
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy)]
pub(super) enum Detect {
    /// Profile exists iff HTTP status equals this value.
    StatusEq(u16),
    /// Profile exists iff status matches AND body does NOT contain `needle`
    /// (sites that return 200 for every URL, including missing profiles).
    StatusAndNotBody(u16, &'static str),
}

macro_rules! s {
    // HEAD, status-only
    ($name:expr, $url:expr, H, $status:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Head,
            detect: Detect::StatusEq($status),
            cat: $cat,
        }
    };
    // GET, status + body must NOT contain needle (200-for-all sites)
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

/// Webcam, fan-subscription, and adult-video platform database.
///
/// Detection discipline:
/// - `H, 200` when the site properly 404s non-existent profiles (most platforms).
/// - `NOT, 200, "error_marker"` when the site returns 200 for all URLs and
///   embeds a "not found" message in the body (JS-rendered platforms like OnlyFans).
/// - `HAS, 200, "presence_marker"` when the profile URL exists for all usernames
///   but a specific field/attribute is only present on real profiles.
///
/// Order is irrelevant; all probes run concurrently up to `MAX_CONCURRENT_PROBES`.
pub(super) const SITES: &[Site] = &[
    // ── Webcam / Live Streaming ─────────────────────────────────────────────
    //
    // Chaturbate: non-existent rooms return 200 with "This room doesn't exist"
    // embedded in the page; the trailing-slash form is the canonical profile URL.
    s!(
        "Chaturbate",
        "https://chaturbate.com/{}/",
        NOT,
        200,
        "This room doesn't exist",
        "cam"
    ),
    // Stripchat properly 404s non-existent model pages.
    s!("Stripchat", "https://stripchat.com/{}", H, 200, "cam"),
    // BongaCams profile pages 404 for unknown performers.
    s!("BongaCams", "https://bongacams.com/{}", H, 200, "cam"),
    // Cam4 member pages return 200 for existing, 404 for absent.
    s!("Cam4", "https://www.cam4.com/{}", H, 200, "cam"),
    // CamSoda performer profiles return 200/404 cleanly.
    s!("CamSoda", "https://www.camsoda.com/{}", H, 200, "cam"),
    // MyFreeCams hosts readable profile pages separate from the Flash client.
    s!(
        "MyFreeCams",
        "https://profiles.myfreecams.com/{}",
        H,
        200,
        "cam"
    ),
    // Streamate performer pages 200/404 cleanly.
    s!("Streamate", "https://www.streamate.com/{}", H, 200, "cam"),
    // LiveJasmin performer profile path (EN locale, female category).
    s!(
        "LiveJasmin",
        "https://www.livejasmin.com/en/girls/{}/",
        H,
        200,
        "cam"
    ),
    // ImLive live-page path 200s for active profiles.
    s!("ImLive", "https://www.imlive.com/live/{}/", H, 200, "cam"),
    // Flirt4Free performer profile page path.
    s!(
        "Flirt4Free",
        "https://www.flirt4free.com/free-cams/females/{}/",
        H,
        200,
        "cam"
    ),
    // Amateur.tv performer pages 200/404.
    s!("Amateur.tv", "https://amateur.tv/{}", H, 200, "cam"),
    // Cams.com performer profile pages.
    s!("Cams.com", "https://www.cams.com/{}", H, 200, "cam"),
    // JerkMate performer profile pages.
    s!("JerkMate", "https://jerkmate.com/{}", H, 200, "cam"),
    // SexLikeReal performer profile pages.
    s!(
        "SexLikeReal",
        "https://www.sexlikereal.com/performers/{}",
        H,
        200,
        "cam"
    ),
    // Runetki — Russia's leading cam platform; performers register with a handle
    // that maps directly to their profile URL. Major source for Eastern European
    // performers who maintain a Russian-language presence alongside Western sites.
    s!("Runetki", "https://runetki.com/{}", H, 200, "cam"),
    // Cherry.tv — newer international cam platform with Eastern European roots;
    // popular with Romanian, Ukrainian, and Moldovan performers seeking audiences
    // outside their home markets.
    s!("Cherry.tv", "https://cherry.tv/{}", H, 200, "cam"),
    // ── Fan / Subscription Platforms ────────────────────────────────────────
    //
    // OnlyFans: CloudFlare-rendered; missing profiles return 200 with
    // "Sorry, the page you requested was not found" in the HTML body.
    s!(
        "OnlyFans",
        "https://onlyfans.com/{}",
        NOT,
        200,
        "Sorry, the page you requested was not found",
        "fans"
    ),
    // Fansly properly 404s absent creators.
    s!("Fansly", "https://fansly.com/{}", H, 200, "fans"),
    // ManyVids uses a /Profile/ prefix path that returns 404 for unknown creators.
    s!(
        "ManyVids",
        "https://www.manyvids.com/Profile/{}/",
        H,
        200,
        "fans"
    ),
    // FanCentro creator pages 200/404 cleanly.
    s!("FanCentro", "https://fancentro.com/{}", H, 200, "fans"),
    // Fanvue creator profiles 200/404.
    s!("Fanvue", "https://www.fanvue.com/{}", H, 200, "fans"),
    // Loyalfans creator profile pages.
    s!("Loyalfans", "https://www.loyalfans.com/{}", H, 200, "fans"),
    // AVN Stars (adult industry platform) creator profile pages.
    s!("AVN Stars", "https://stars.avn.com/{}", H, 200, "fans"),
    // PocketStars creator profile pages.
    s!("PocketStars", "https://pocketstars.com/{}", H, 200, "fans"),
    // Passes (newer fan-platform) creator pages.
    s!("Passes", "https://passes.com/{}", H, 200, "fans"),
    // SextPanther phone/fan platform; creator pages 200/404.
    s!(
        "SextPanther",
        "https://www.sextpanther.com/{}",
        H,
        200,
        "fans"
    ),
    // AdmireMe (UK-based fan platform).
    s!("AdmireMe", "https://www.admireme.vip/{}", H, 200, "fans"),
    // Mym — the dominant French-language OF alternative; heavily used in France,
    // Belgium, French Canada, Morocco, and Ivory Coast. A subject active in
    // French-speaking markets often appears here but nowhere else in the English
    // platform set.
    s!("Mym", "https://mym.fans/{}", H, 200, "fans"),
    // Boosty — Russian Patreon/OnlyFans hybrid; the primary subscription-content
    // platform for Russian and CIS-country creators who avoid Western platforms to
    // stay below English-language OSINT radar. 404s absent creators.
    s!("Boosty", "https://boosty.to/{}", H, 200, "fans"),
    // 4Based — Ukrainian/Eastern European OnlyFans alternative built post-2022 as
    // a domestic alternative to Western platforms. Popular with Ukrainian,
    // Belarusian, and Russian creators who want a platform outside Western
    // payment-processor reach.
    s!("4Based", "https://4based.com/{}", H, 200, "fans"),
    // JustForFans — international fan platform targeting gay, bisexual, and
    // queer performers; widely used outside the English-speaking world by creators
    // who maintain a discreet presence on a niche platform rather than mainstream
    // OF/Fansly.
    s!("JustForFans", "https://justfor.fans/{}", H, 200, "fans"),
    // OhMyFans — Spanish-language OnlyFans alternative dominant in Spain, Mexico,
    // Colombia, and Argentina. A subject with a Latin American or Spanish audience
    // often uses this instead of, or alongside, English-language platforms.
    s!("OhMyFans", "https://ohmyfans.com/{}", H, 200, "fans"),
    // Unlockd — British adult fan platform popular with UK creators who consider
    // OnlyFans overexposed; 404s absent creators cleanly.
    s!("Unlockd", "https://unlockd.me/{}", H, 200, "fans"),
    // Cam.tv — Italian-origin hybrid cam/fan platform with a significant European
    // presence (Italy, France, Spain, Eastern Europe). Creators publish both live
    // streams and subscriber content under the same handle.
    s!("Cam.tv", "https://cam.tv/{}", H, 200, "fans"),
    // ── Adult Video / Profile Pages ─────────────────────────────────────────
    //
    // Pornhub model pages 404 for absent performer handles.
    s!(
        "Pornhub",
        "https://www.pornhub.com/model/{}",
        H,
        200,
        "adult"
    ),
    // xHamster user profile pages.
    s!("xHamster", "https://xhamster.com/users/{}", H, 200, "adult"),
    // xVideos profile pages.
    s!(
        "xVideos",
        "https://www.xvideos.com/profiles/{}",
        H,
        200,
        "adult"
    ),
    // SpankBang user profile pages.
    s!(
        "SpankBang",
        "https://spankbang.com/profile/{}/",
        H,
        200,
        "adult"
    ),
    // Erome user album index pages.
    s!("Erome", "https://www.erome.com/{}", H, 200, "adult"),
    // RedTube user profile pages.
    s!(
        "RedTube",
        "https://www.redtube.com/users/{}/profile",
        H,
        200,
        "adult"
    ),
    // MyDirtyHobby — Germany's largest amateur and prosumer adult platform;
    // widely used by German, Austrian, and Swiss creators who maintain a European
    // profile not indexed by English-language discovery tools.
    s!(
        "MyDirtyHobby",
        "https://www.mydirtyhobby.com/{}",
        H,
        200,
        "adult"
    ),
    // SuicideGirls — international alternative/indie adult community with members
    // across North America, Europe, Australia, and South America; a subject with
    // alt-subculture ties frequently appears here before mainstream platforms.
    s!(
        "SuicideGirls",
        "https://www.suicidegirls.com/girls/{}/",
        H,
        200,
        "adult"
    ),
    // Iwara — Japanese-origin 3D-animation adult community (MMD, VRChat, etc.)
    // with a large international audience. Creators use consistent handles across
    // Iwara and mainstream cam/fan platforms, making it a useful pivot point for
    // subjects active in Japanese or anime-adjacent communities.
    s!("Iwara", "https://www.iwara.tv/profile/{}", H, 200, "adult"),
];
