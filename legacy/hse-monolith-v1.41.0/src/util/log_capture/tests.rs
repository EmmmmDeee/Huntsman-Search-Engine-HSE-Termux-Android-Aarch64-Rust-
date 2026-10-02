use super::*;
    use std::io::Write;

    // ONE test, not several: the ring is process-global, so separate `#[test]`
    // fns run in parallel and race on it (an earlier split into three failed
    // exactly this way). Everything is exercised in sequence here —
    // commit-on-newline, partial-line holding, the dump header, the incremental
    // `tail` cursor, the eviction gap, and clear().
    #[test]
    fn ring_buffer_captures_bounds_tails_and_dumps() {
        // ── commit, partial-line holding, dump header ──
        clear();
        assert_eq!(line_count(), 0);

        let mut w = RingWriter;
        w.write_all(b"line one\nline two\n").expect("should succeed");
        assert_eq!(line_count(), 2);

        // Partial line held until its newline arrives.
        w.write_all(b"partial").expect("should succeed");
        assert_eq!(line_count(), 2, "no newline yet → not committed");
        w.write_all(b" rest\n").expect("should succeed");
        assert_eq!(line_count(), 3);

        let d = dump();
        assert!(d.contains("Huntsman Search Engine"), "header present");
        assert!(d.contains("line one") && d.contains("line two") && d.contains("partial rest"));

        // ── incremental `tail`: first read, resume, already-current ──
        clear();
        let t = tail(0);
        assert!(t.lines.is_empty());
        assert_eq!(t.cursor, 0);
        assert_eq!(t.missed, 0);
        assert_eq!(t.dropped, 0);

        w.write_all(b"a\nb\nc\n").expect("write");
        let t = tail(0);
        assert_eq!(t.lines, vec!["a", "b", "c"]);
        assert_eq!(t.cursor, 3, "cursor is the count of lines ever committed");
        assert_eq!(t.missed, 0);

        // Resuming from the cursor returns only what is new — the core live-view
        // contract.
        w.write_all(b"d\n").expect("write");
        let t2 = tail(t.cursor);
        assert_eq!(t2.lines, vec!["d"]);
        assert_eq!(t2.cursor, 4);
        assert_eq!(t2.missed, 0);

        // Already current: empty, cursor unchanged, no gap.
        let t3 = tail(t2.cursor);
        assert!(t3.lines.is_empty());
        assert_eq!(t3.cursor, 4);
        assert_eq!(t3.missed, 0);

        // ── eviction is reported as `missed`/`dropped`, never silently skipped ──
        // A tiny cap makes eviction deterministic without writing 20k lines.
        clear();
        {
            let mut r = lock();
            r.cap = 3;
        }
        w.write_all(b"0\n1\n2\n3\n4\n").expect("write");
        // A caller that last saw cursor 0 asks for everything from 0. Lines 0
        // and 1 are gone; it gets 2,3,4 and is told 2 were lost.
        let t = tail(0);
        assert_eq!(t.lines, vec!["2", "3", "4"]);
        assert_eq!(t.cursor, 5);
        assert_eq!(t.missed, 2, "lines 0 and 1 were evicted before this read");
        assert_eq!(t.dropped, 2, "ring's all-time eviction count");

        // Restore the real cap and clear so nothing leaks to a later run.
        clear();
        {
            let mut r = lock();
            r.cap = configured_cap();
        }
        assert_eq!(line_count(), 0);
    }
