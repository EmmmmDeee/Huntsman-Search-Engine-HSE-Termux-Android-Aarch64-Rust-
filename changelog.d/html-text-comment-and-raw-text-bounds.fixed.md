- Text taken from a web page no longer shows what an unterminated comment hides. A `<!--` with
  no `-->` now hides the rest of the page, as a browser does; before, the comment's contents
  were read as text. A `<script>` or `<style>` element now ends only at its own end tag, so
  `</scripting>` no longer ends one early and exposes the script's text, and `<script-widget>`
  is no longer taken for a script that hides the page after it.
