use super::is_broken_pipe_panic;

    #[test]
    fn recognises_only_the_broken_pipe_print_panic() {
        // The exact std print-macro panic message → swallow.
        assert!(is_broken_pipe_panic(
            &"failed printing to stdout: Broken pipe (os error 32)".to_string()
        ));
        assert!(is_broken_pipe_panic(
            &"failed printing to stderr: Broken pipe (os error 32)"
        ));
        // A different output failure → must NOT be swallowed (stays loud).
        assert!(!is_broken_pipe_panic(
            &"failed printing to stdout: No space left on device (os error 28)".to_string()
        ));
        // Unrelated panics → never matched.
        assert!(!is_broken_pipe_panic(&"index out of bounds".to_string()));
        assert!(!is_broken_pipe_panic(&42i32));
    }
