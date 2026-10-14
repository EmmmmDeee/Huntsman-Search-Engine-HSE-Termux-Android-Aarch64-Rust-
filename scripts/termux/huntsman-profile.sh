# Huntsman shortcuts for interactive Termux shells. install.sh installs this as
# $PREFIX/etc/profile.d/huntsman.sh, which every Termux login shell reads, so
# ~/.bashrc is left alone. Keys stay in ~/.huntsman.env, which huntsman-recon
# reads itself; nothing here exports them.

case $- in
  *i*) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac

# The web UI service.
alias h='huntsman'
alias start='huntsman start'
alias stop='huntsman stop'
alias restart='huntsman restart'
alias status='huntsman status'
alias logs='huntsman logs'
alias clean='huntsman clean'
alias doc='huntsman doctor'
alias cred='huntsman credential-status'

# Lookups.
domain() { huntsman domain "$@"; }
email() { huntsman email "$@"; }
username() { huntsman username "$@"; }
asx() { huntsman id "$@"; }
query() { huntsman query "$@"; }
pipe() { huntsman scan-pipe "$@"; }

# Saved scans, newest first, under ~/huntsman-reports.
latest_json() { ls -t "${HUNTSMAN_REPORTS:-$HOME/huntsman-reports}"/*.json 2>/dev/null | head -n 1; }
latest_md() { ls -t "${HUNTSMAN_REPORTS:-$HOME/huntsman-reports}"/*.md 2>/dev/null | head -n 1; }

# Claims a saved scan marks verified: source, technique, claim, hash prefix.
claims() {
  local target="${1:-$(latest_json)}"
  [ -n "$target" ] || { echo "no saved scan in ~/huntsman-reports"; return 1; }
  echo "verified claims in $(basename "$target"):"
  jq -r '.[] | select(.claim.status == "verified") | [
      .claim.source, (.claim.technique_id // "-"), .claim.claim, (.hash[:12] + "...")
    ] | @tsv' "$target" | if command -v column >/dev/null 2>&1; then column -t -s "$(printf '\t')"; else cat; fi
}

verified() {
  local target="${1:-$(latest_json)}"
  [ -n "$target" ] || { echo "no saved scan in ~/huntsman-reports"; return 1; }
  jq '.[] | select(.claim.status == "verified")' "$target"
}

# A Bluesky DID document from plc.directory; without an argument, the first
# did:plc in the newest saved scan.
did() {
  local id="${1:-}"
  if [ -z "$id" ]; then
    id="$(jq -r '.[].claim.claim' "$(latest_json)" 2>/dev/null | grep -o 'did:plc:[a-z0-9]*' | head -n 1)"
  fi
  [ -n "$id" ] || { echo "usage: did did:plc:..."; return 1; }
  curl -fsS "https://plc.directory/$id" | jq .
}

dossier() {
  local target="${1:-$(latest_md)}"
  [ -n "$target" ] || { echo "no report in ~/huntsman-reports"; return 1; }
  cat "$target"
}

clean_reports() {
  find "${HUNTSMAN_REPORTS:-$HOME/huntsman-reports}" -type f \( -name '*.json' -o -name '*.md' \) -mtime +14 -delete
  echo "removed saved scans and reports older than 14 days"
}
