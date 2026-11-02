//! Regressions for raw-text close-token recognition in evidence extraction.
use huntsman_recon::html_text::html_to_text;

#[test]
fn raw_text_prefix_names_do_not_close_script_or_style() {
    for html in [
        "Visible<script>secret</scripting>LEAK</script>After",
        "Visible<style>secret</stylesheet>LEAK</style>After",
        "Visible<script>secret</scriptx>LEAK</script>After",
        "Visible<style>secret</stylex>LEAK</style>After",
    ] {
        assert_eq!(html_to_text(html, 200).as_deref(), Some("VisibleAfter"));
    }
}

#[test]
fn raw_text_unclosed_prefix_does_not_surface_hidden_suffix() {
    for html in [
        "Before<script>secret</scripting>LEAK",
        "Before<style>secret</stylesheet>LEAK",
        "Before<script>secret</script",
    ] {
        assert_eq!(html_to_text(html, 200).as_deref(), Some("Before"));
    }
}

#[test]
fn raw_text_true_closers_preserve_visible_suffix() {
    for html in [
        "Before<SCRIPT>hidden</ScRiPt>After",
        "Before<script>hidden</script >After",
        "Before<style>hidden</style >After",
        "Before<script>hidden</script foo=\">\">After",
    ] {
        assert_eq!(html_to_text(html, 200).as_deref(), Some("BeforeAfter"));
    }
}
