use super::*;

    #[test]
    fn top_n_ranks_by_frequency_descending() {
        let items = ["a", "b", "a", "c", "b", "a"];
        let result = top_n(items.iter().copied(), 3);
        assert_eq!(result, "a\u{00d7}3, b\u{00d7}2, c\u{00d7}1");
    }

    #[test]
    fn top_n_truncates() {
        let items = ["x", "y", "z", "x", "y", "x"];
        let result = top_n(items.iter().copied(), 2);
        assert_eq!(result, "x\u{00d7}3, y\u{00d7}2");
    }

    #[test]
    fn top_n_empty_input() {
        let result = top_n(std::iter::empty(), 5);
        assert!(result.is_empty());
    }

    #[test]
    fn top_n_tiebreaker_is_alphabetical() {
        let items = ["b", "a", "c"];
        let result = top_n(items.iter().copied(), 3);
        assert_eq!(result, "a\u{00d7}1, b\u{00d7}1, c\u{00d7}1");
    }
