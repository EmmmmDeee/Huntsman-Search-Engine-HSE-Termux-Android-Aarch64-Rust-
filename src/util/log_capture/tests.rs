use super::*;
    use std::io::Write;

    // One test (not several) because the ring is process-global; parallel
    // tests would race on it. This exercises commit-on-newline, partial-line
    // holding, the dump header, eviction, and clear() in sequence.
    #[test]
    fn ring_buffer_captures_bounds_and_dumps() {
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

        clear();
        assert_eq!(line_count(), 0);
    }
