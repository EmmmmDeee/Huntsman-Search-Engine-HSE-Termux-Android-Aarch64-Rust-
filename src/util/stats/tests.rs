use super::*;

    #[test]
    fn mode_breaks_ties_alphabetically_smallest_first() {
        // "apple" and "banana" tie at 2; the smallest string wins, deterministically.
        assert_eq!(mode(&["banana", "apple", "banana", "apple"]), Some("apple"));
        // Clear winner by count.
        assert_eq!(mode(&["x", "y", "y"]), Some("y"));
        // Empty input.
        assert_eq!(mode(&[]), None);
        // Fallback wrapper.
        assert_eq!(mode_or(&[], "fallback"), "fallback");
    }

    #[test]
    fn mode_single_item_is_that_item() {
        assert_eq!(mode(&["only"]), Some("only"));
    }

    #[test]
    fn mode_or_returns_winner_not_fallback_when_non_empty() {
        // The fallback is ignored when there is a winner.
        assert_eq!(mode_or(&["a", "b", "b"], "fallback"), "b");
    }
