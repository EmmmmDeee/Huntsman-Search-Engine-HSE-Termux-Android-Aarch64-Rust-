//! In-place terminal frame repainting — the render half of a live, continuously
//! updating display.
//!
//! `hse radar` (and any future live view) needs to redraw a small region of the
//! terminal each tick rather than scrolling a fresh block, so the operator reads
//! one evolving map instead of an ever-growing log. Nothing in the CLI did that
//! before: every existing path is append-only `println!`/`eprintln!`, and the
//! tree carries no terminal-UI dependency. This is the minimal, dependency-free
//! primitive that closes the gap — no crossterm/termion, which matters on
//! no-root Termux where the fewer moving parts the better.
//!
//! **Writes to stderr, deliberately.** The live map is progress output; stdout
//! stays a clean machine-readable NDJSON stream, so `hse radar | jq` keeps
//! working while the map repaints on the terminal beside it.
//!
//! **Degrades to append when stderr is not a TTY.** Redirect stderr to a file
//! or a pipe and the frames are written plainly, one after another, with no
//! escape sequences — a log you can actually read, instead of a file full of
//! `\x1b[2K`. This is gated on **stderr**, not stdout: the CLI's existing
//! [`use_color`](super::use_color) tests `stdout().is_terminal()`, which is the
//! wrong stream for this and would emit raw escapes into a redirected stderr
//! whenever stdout happened to be a terminal.
//!
//! The escape-sequence assembly lives in the pure [`Frame::render`], so the
//! whole contract is unit-tested against strings with no terminal attached.

use std::io::{IsTerminal, Write};

/// Move the cursor up `n` lines (CSI `n` A).
fn cursor_up(n: usize) -> String {
    format!("\x1b[{n}A")
}

/// Erase the entire current line, leaving the cursor where it is (CSI 2 K).
/// Emitted before each rewritten line so a shorter new line cannot leave the
/// tail of a longer previous one behind.
const CLEAR_LINE: &str = "\x1b[2K";

/// A repainting region of the terminal: remembers how many lines it drew last
/// time so the next paint can rewind exactly that far and overwrite in place.
pub(super) struct Frame {
    last_lines: usize,
    tty: bool,
}

impl Frame {
    /// A frame that repaints in place when stderr is a terminal, and appends
    /// plainly when it is not.
    pub(super) fn new() -> Self {
        Self {
            last_lines: 0,
            tty: std::io::stderr().is_terminal(),
        }
    }

    /// A frame that always appends (never emits escapes) — the non-TTY
    /// behaviour, constructible directly for tests.
    #[cfg(test)]
    fn appending() -> Self {
        Self {
            last_lines: 0,
            tty: false,
        }
    }

    /// A frame that always repaints in place — constructible directly for tests
    /// so the escape assembly is verifiable without a terminal.
    #[cfg(test)]
    fn repainting() -> Self {
        Self {
            last_lines: 0,
            tty: true,
        }
    }

    /// Build the exact bytes one repaint emits. Pure: takes the frame's current
    /// line count and the new content, returns the payload and does no IO, so
    /// every branch below is testable with no terminal attached.
    ///
    /// In TTY mode the payload is, in order:
    ///   1. a rewind over the previously-drawn lines (skipped on the first paint),
    ///   2. each new line, each preceded by a clear-to-end-of-line, and
    ///   3. when the new frame is SHORTER than the last, a clear of every
    ///      now-orphaned trailing line followed by a rewind back over them —
    ///      without which a shrinking map would leave its own stale tail on
    ///      screen (a device that departed would appear to still be there).
    fn render(&self, lines: &[String]) -> String {
        if !self.tty {
            // Append mode: plain text, no escapes, one line per line.
            let mut out = String::new();
            for line in lines {
                out.push_str(line);
                out.push('\n');
            }
            return out;
        }

        let mut out = String::new();
        if self.last_lines > 0 {
            out.push_str(&cursor_up(self.last_lines));
        }
        for line in lines {
            out.push_str(CLEAR_LINE);
            out.push_str(line);
            out.push('\n');
        }
        if self.last_lines > lines.len() {
            let orphaned = self.last_lines - lines.len();
            for _ in 0..orphaned {
                out.push_str(CLEAR_LINE);
                out.push('\n');
            }
            // Leave the cursor immediately after the new content, so the NEXT
            // paint's rewind distance is the new line count, not the old one.
            out.push_str(&cursor_up(orphaned));
        }
        out
    }

    /// Draw `lines`, overwriting the previously drawn frame in place (or
    /// appending, when stderr is not a terminal).
    ///
    /// Write failures are ignored on purpose: a closed/broken stderr must never
    /// abort a running radar sweep, which is doing real work whose results go to
    /// stdout and the store.
    pub(super) fn repaint(&mut self, lines: &[String]) {
        let payload = self.render(lines);
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(payload.as_bytes());
        let _ = err.flush();
        self.last_lines = lines.len();
    }
}

/// Build the live Bluetooth map's lines from the radar's current state and the
/// increment that just landed.
///
/// Pure (state in, strings out) so the whole layout is unit-tested with no
/// terminal and no radio. Ordering comes from
/// [`BtRadarState::tracks_ranked`](crate::core::radar_live::BtRadarState::tracks_ranked)
/// — most-persistent first — so a device the operator keeps seeing rises to the
/// top of the map rather than jumping around between ticks.
///
/// Rotating (randomized) addresses and the operator's own bonded kit are shown
/// only as counts, never as rows: they are deliberately not followable pins.
pub(super) fn render_bt_map(
    state: &crate::core::radar_live::BtRadarState,
    delta: &crate::core::radar_live::TickDelta,
    tick: u64,
    color: bool,
) -> Vec<String> {
    use crate::core::radar_live::{BtReadOutcome, Presence};

    let mut out = Vec::new();

    // Header. A tick that never read the radio says so plainly: "nothing seen"
    // and "never looked" are different claims, and reporting the second as the
    // first would tell the operator the area is quiet when it was never sampled.
    if delta.read == BtReadOutcome::NotRead {
        out.push(super::color_confidence(
            0.3,
            &format!(
                "◌ bluetooth tick {tick} — radio NOT read (permission/tool \
                 unavailable); this is not evidence nothing is nearby"
            ),
            color,
        ));
    } else {
        out.push(super::color_confidence(
            0.85,
            &format!(
                "◉ bluetooth tick {tick} — {} tracked, +{} new, -{} departed",
                state.len(),
                delta.new.len(),
                delta.departed.len()
            ),
            color,
        ));
    }

    for track in state.tracks_ranked() {
        let (glyph, tier) = match track.presence {
            Presence::New => ("+", 0.85),
            Presence::Present => ("•", 0.7),
            Presence::Missing(_) => ("~", 0.3),
            // Not reachable from a live map (departed tracks are removed in the
            // same tick they are reported), but rendered rather than skipped so
            // the display can never silently drop a row it was handed.
            Presence::Departed => ("-", 0.3),
        };
        let label = track
            .name
            .as_deref()
            .or(track.vendor.as_deref())
            .unwrap_or("unknown device");
        out.push(super::color_confidence(
            tier,
            &format!(
                "  {glyph} {}  {}  seen {}×",
                track.mac,
                super::truncate(label, 28),
                track.sweeps_seen
            ),
            color,
        ));
    }

    // Aggregates last. Both are counts by design — a rotating address is not a
    // followable device, and the operator's own paired kit is self-exposure
    // information rather than a foreign contact.
    if delta.randomized_seen > 0 {
        out.push(super::color_confidence(
            0.3,
            &format!(
                "  ⋯ {} rotating/private address(es) — not trackable",
                delta.randomized_seen
            ),
            color,
        ));
    }
    if delta.bonded_seen > 0 {
        out.push(super::color_confidence(
            0.5,
            &format!(
                "  ⌂ {} of your own paired device(s) discoverable",
                delta.bonded_seen
            ),
            color,
        ));
    }
    if !delta.evicted.is_empty() {
        out.push(super::color_confidence(
            0.3,
            &format!(
                "  ! map at capacity — {} track(s) dropped (not departures)",
                delta.evicted.len()
            ),
            color,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn non_tty_appends_plain_text_with_no_escapes() {
        // Redirected stderr must stay readable: a log file full of `\x1b[2K`
        // would be worse than useless.
        let f = Frame::appending();
        let out = f.render(&lines(&["alpha", "beta"]));
        assert_eq!(out, "alpha\nbeta\n");
        assert!(!out.contains('\x1b'), "no escapes in append mode: {out:?}");
    }

    #[test]
    fn first_tty_paint_does_not_rewind() {
        // There is nothing drawn yet, so rewinding would scroll into and
        // overwrite whatever the terminal already held above us.
        let f = Frame::repainting();
        let out = f.render(&lines(&["one", "two"]));
        assert!(
            !out.contains("\x1b[2A") && !out.starts_with("\x1b[0A"),
            "first paint must not move the cursor up: {out:?}"
        );
        assert_eq!(out, format!("{CLEAR_LINE}one\n{CLEAR_LINE}two\n"));
    }

    #[test]
    fn second_paint_rewinds_exactly_the_previous_line_count() {
        let mut f = Frame::repainting();
        f.last_lines = 3; // as if three lines were drawn last tick
        let out = f.render(&lines(&["a", "b", "c"]));
        assert!(
            out.starts_with(&cursor_up(3)),
            "must rewind exactly 3 lines: {out:?}"
        );
        assert_eq!(
            out,
            format!("\x1b[3A{CLEAR_LINE}a\n{CLEAR_LINE}b\n{CLEAR_LINE}c\n")
        );
    }

    #[test]
    fn every_line_is_cleared_before_being_rewritten() {
        // Without the clear, a shorter new line leaves the tail of the longer
        // previous one visible — e.g. a device name shrinking from
        // "Pixel Buds Pro" to "Pixel" would render as "Pixel Buds Pro"'s tail.
        let mut f = Frame::repainting();
        f.last_lines = 1;
        let out = f.render(&lines(&["short"]));
        assert!(out.contains(&format!("{CLEAR_LINE}short")));
    }

    #[test]
    fn a_shrinking_frame_clears_its_orphaned_tail_and_rewinds_over_it() {
        // THE case a naive implementation gets wrong: the map had 4 rows, now
        // has 2 (two devices departed). Without clearing rows 3-4 the departed
        // devices stay painted on screen — the radar would show devices that
        // are gone, the exact opposite of a live map's purpose.
        let mut f = Frame::repainting();
        f.last_lines = 4;
        let out = f.render(&lines(&["x", "y"]));

        assert!(
            out.starts_with(&cursor_up(4)),
            "rewinds over all 4 old rows"
        );
        // Two orphaned rows are blanked...
        let orphan_blanks = out.matches(&format!("{CLEAR_LINE}\n")).count();
        assert_eq!(orphan_blanks, 2, "both orphaned rows cleared: {out:?}");
        // ...and the cursor comes back so the NEXT paint rewinds by 2, not 4.
        assert!(
            out.ends_with(&cursor_up(2)),
            "cursor returns to just after the new content: {out:?}"
        );
    }

    #[test]
    fn a_growing_frame_needs_no_orphan_clearing() {
        let mut f = Frame::repainting();
        f.last_lines = 1;
        let out = f.render(&lines(&["a", "b", "c"]));
        assert_eq!(
            out,
            format!("\x1b[1A{CLEAR_LINE}a\n{CLEAR_LINE}b\n{CLEAR_LINE}c\n"),
            "growing frames just draw the extra rows"
        );
    }

    #[test]
    fn an_empty_frame_clears_everything_it_had_drawn() {
        // The map going empty (all devices departed) must erase the old rows,
        // not freeze the last populated frame on screen.
        let mut f = Frame::repainting();
        f.last_lines = 2;
        let out = f.render(&[]);
        assert_eq!(out, format!("\x1b[2A{CLEAR_LINE}\n{CLEAR_LINE}\n\x1b[2A"));
    }

    // ── render_bt_map ───────────────────────────────────────────────────────

    use crate::core::radar_live::{BtRadarState, BtReadOutcome};
    use crate::core::radar_track::SweepObservation;

    /// Universally-administered (trackable hardware), matching radar_live's
    /// fixtures.
    const HW1: &str = "3C:5A:B4:11:22:33";
    /// Locally-administered (a rotating privacy address).
    const RND: &str = "36:32:62:36:31:33";

    fn sighting(mac: &str, bonded: bool) -> SweepObservation {
        SweepObservation {
            mac: mac.to_string(),
            name: None,
            bonded,
        }
    }

    #[test]
    fn map_renders_a_tracked_device_row() {
        let mut st = BtRadarState::default();
        let d = st.apply_tick(&[sighting(HW1, false)], BtReadOutcome::Read);
        let map = render_bt_map(&st, &d, 1, false);

        assert!(map[0].contains("tick 1") && map[0].contains("1 tracked"));
        let row = map.iter().find(|l| l.contains(&HW1.to_lowercase()));
        let row = row.expect("the tracked device gets a row");
        assert!(row.contains("seen 1×"));
    }

    #[test]
    fn map_shows_rotating_and_own_devices_only_as_counts() {
        // The defensive invariant, rendered: a randomized address and the
        // operator's own bonded kit must never appear as followable rows.
        let mut st = BtRadarState::default();
        let d = st.apply_tick(
            &[sighting(RND, false), sighting(HW1, true)],
            BtReadOutcome::Read,
        );
        let map = render_bt_map(&st, &d, 1, false);

        assert!(
            !map.iter().any(|l| l.contains(&RND.to_lowercase())),
            "a rotating address must never be pinned as a row: {map:?}"
        );
        assert!(
            !map.iter().any(|l| l.contains(&HW1.to_lowercase())),
            "the operator's own bonded device must not be a foreign row: {map:?}"
        );
        assert!(map.iter().any(|l| l.contains("rotating/private")));
        assert!(map.iter().any(|l| l.contains("your own paired")));
    }

    #[test]
    fn map_says_not_read_rather_than_nothing_nearby() {
        // "We didn't look" must never render as "nothing is there".
        let mut st = BtRadarState::default();
        let d = st.apply_tick(&[], BtReadOutcome::NotRead);
        let map = render_bt_map(&st, &d, 7, false);
        assert!(
            map[0].contains("NOT read") && map[0].contains("not evidence"),
            "a not-read tick must say so explicitly: {:?}",
            map[0]
        );
    }

    #[test]
    fn map_surfaces_capacity_drops_as_distinct_from_departures() {
        let mut st = BtRadarState::with_capacity(1);
        st.apply_tick(&[sighting(HW1, false)], BtReadOutcome::Read);
        let d = st.apply_tick(
            &[sighting(HW1, false), sighting("3C:5A:B4:44:55:66", false)],
            BtReadOutcome::Read,
        );
        let map = render_bt_map(&st, &d, 2, false);
        assert!(
            map.iter()
                .any(|l| l.contains("at capacity") && l.contains("not departures")),
            "a saturated map must say so, and not imply devices left: {map:?}"
        );
    }

    #[test]
    fn repaint_updates_the_remembered_line_count() {
        // The rewind distance for the next tick is the CURRENT line count.
        let mut f = Frame::appending(); // append mode: no terminal needed
        f.repaint(&lines(&["a", "b", "c"]));
        assert_eq!(f.last_lines, 3);
        f.repaint(&lines(&["a"]));
        assert_eq!(f.last_lines, 1);
    }
}
