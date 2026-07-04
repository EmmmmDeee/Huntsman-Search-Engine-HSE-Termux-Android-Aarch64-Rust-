use super::*;

    #[test]
    fn new_handle_is_not_cancelled() {
        assert!(!CancelHandle::new().is_cancelled());
    }

    #[test]
    fn cancel_is_observable_through_clones() {
        let a = CancelHandle::new();
        let b = a.clone();
        b.cancel();
        assert!(a.is_cancelled());
        assert!(b.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let h = CancelHandle::new();
        h.cancel();
        h.cancel();
        assert!(h.is_cancelled());
    }

    #[test]
    fn default_is_uncancelled() {
        let h: CancelHandle = Default::default();
        assert!(!h.is_cancelled());
    }

    #[test]
    fn child_cancel_does_not_cancel_the_parent() {
        // A per-iteration wall-time deadline (the child) must abort only its own
        // iteration, never the whole session (the parent).
        let parent = CancelHandle::new();
        let child = parent.child();
        assert!(!parent.is_cancelled() && !child.is_cancelled());
        child.cancel();
        assert!(child.is_cancelled(), "the child observes its own cancel");
        assert!(
            !parent.is_cancelled(),
            "cancelling a child (a per-iteration deadline) must NOT cancel the parent session"
        );
    }

    #[test]
    fn parent_cancel_propagates_to_the_child() {
        // An operator session-stop (parent) must still abort the in-flight
        // iteration (child) at its next poll.
        let parent = CancelHandle::new();
        let child = parent.child();
        parent.cancel();
        assert!(parent.is_cancelled());
        assert!(
            child.is_cancelled(),
            "a parent (session) cancel propagates to the in-flight child iteration"
        );
    }

    #[test]
    fn sibling_children_are_independent() {
        // Two iterations' deadline handles don't interfere: one tripping on
        // wall-time leaves the other — and the session — running.
        let parent = CancelHandle::new();
        let a = parent.child();
        let b = parent.child();
        a.cancel();
        assert!(a.is_cancelled());
        assert!(!b.is_cancelled(), "a sibling iteration is unaffected");
        assert!(!parent.is_cancelled(), "the session is unaffected");
    }
