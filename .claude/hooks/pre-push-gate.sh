#!/usr/bin/env bash
# PreToolUse hook (Bash): refuse a `git push` of a tree the gate has not passed.
#
# Registered in .claude/settings.json under PreToolUse / matcher "Bash", with
# `"if": "Bash(git *)"` so Claude Code only starts this process for commands
# that run git. It reads the hook's JSON input on stdin and finds each `git
# push` in the command, following `cd DIR &&` and `git -C DIR`. For every ref
# the push sends, it asks `scripts/gate-receipt.sh check` whether
# `scripts/gate.sh` passed on that ref's tree. With no receipt it exits 2, and
# Claude Code blocks the push and shows Claude this script's stderr
# (REQ-HARNESS-001).
#
# It only checks. Running the gate here would take minutes on every push and
# repeat work the gate already did. The gate records a receipt when it passes,
# so a push of a tree that passed costs one file lookup.
#
# Not blocked:
#   * any command that is not a push, and `git push --dry-run` / `-n`;
#   * a push that only deletes remote refs (`--delete`, `:branch`);
#   * a checkout that is not HSE, or an HSE commit older than gate receipts
#     (no scripts/gate-receipt.sh at its top level);
#   * everything, when Claude Code itself runs with HSE_PUSH_GATE=off in its
#     environment (e.g. `env` in .claude/settings.local.json). That is a
#     person's decision. A `HSE_PUSH_GATE=off git push` prefix inside the
#     command does nothing, because this process never sees the command's
#     environment.
#
# The command line is split on shell separators without full shell parsing.
# So a quoted `;` or `&&` can make a later word look like its own command.
# That errs toward checking a push that is not really one. It never skips a
# real push.
set -uo pipefail

[ "${HSE_PUSH_GATE:-on}" = off ] && exit 0

INPUT="$(cat)"

# The value of a top-level JSON string field, unescaped. Pure bash on purpose:
# Termux does not ship jq or python by default, and a hook that silently
# passes when its parser is missing enforces nothing.
json_string() { # json_string <field>
    local re="\"$1\"[[:space:]]*:[[:space:]]*\"(([^\"\\\\]|\\\\.)*)\""
    [[ $INPUT =~ $re ]] || return 1
    local v="${BASH_REMATCH[1]}"
    v="${v//\\\\/$'\001'}"
    v="${v//\\\"/\"}"
    v="${v//\\n/$'\n'}"
    v="${v//\\t/$'\t'}"
    v="${v//\\\//\/}"
    v="${v//$'\001'/\\}"
    printf '%s' "$v"
}

COMMAND="$(json_string command)" || exit 0
CWD="$(json_string cwd)" || CWD="$PWD"

# One shell word per array element: surrounding quotes dropped, `~` expanded.
split_words() { # split_words <text> -> WORDS
    WORDS=()
    local w
    set -f
    # shellcheck disable=SC2086  # word splitting is the point here
    set -- $1
    set +f
    for w in "$@"; do
        # `(cd x && git push)` and `{ git push; }` keep their brackets on the
        # neighbouring word.
        w="${w#[(\{]}"; w="${w%[)\}]}"
        w="${w#[\"\']}"; w="${w%[\"\']}"
        [ "$w" = "~" ] && w="$HOME"
        case "$w" in \~/*) w="$HOME/${w#\~/}" ;; esac
        WORDS+=("$w")
    done
}

resolve_dir() { # resolve_dir <base> <path>
    case "$2" in
        /*) printf '%s' "$2" ;;
        *)  printf '%s/%s' "$1" "$2" ;;
    esac
}

BLOCKED=()

# Check one `git push` invocation. $1 is the repo directory, and the rest are
# the words after `push`.
check_push() {
    local dir="$1"; shift
    local top
    top="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || return 0
    local receipt="$top/scripts/gate-receipt.sh"
    [ -x "$receipt" ] || return 0

    local positional=() w
    while [ "$#" -gt 0 ]; do
        w="$1"; shift
        case "$w" in
            -n|--dry-run|-d|--delete) return 0 ;;
            -o|--push-option|--repo|--receive-pack|--exec) shift ;;
            --) positional+=("$@"); break ;;
            -*) ;;
            # A redirection (`2>`, `>log`) the separator split left behind.
            *'>'*|*'<'*) ;;
            *) positional+=("$w") ;;
        esac
    done

    # positional[0] is the remote; everything after it is a refspec.
    local revs=() spec src
    for spec in "${positional[@]:1}"; do
        spec="${spec#+}"
        src="${spec%%:*}"
        # `:dst` (or an empty source) deletes the remote ref; nothing is sent.
        [ -n "$src" ] || continue
        revs+=("$src")
    done
    [ "${#revs[@]}" -gt 0 ] || [ "${#positional[@]}" -gt 1 ] || revs=(HEAD)

    local rev out
    for rev in "${revs[@]}"; do
        # A source git cannot resolve fails the push by itself.
        git -C "$top" rev-parse --verify --quiet "$rev^{tree}" >/dev/null 2>&1 || continue
        if ! out="$(cd "$top" && "$receipt" check "$rev" 2>&1)"; then
            BLOCKED+=("$top: $out")
        fi
    done
}

dir="$CWD"
segments="$COMMAND"
for sep in '&&' '||' ';' '|' '&'; do
    segments="${segments//"$sep"/$'\n'}"
done

while IFS= read -r seg; do
    split_words "$seg"
    [ "${#WORDS[@]}" -gt 0 ] || continue
    i=0
    # Leading VAR=value assignments and command wrappers.
    while [ "$i" -lt "${#WORDS[@]}" ]; do
        case "${WORDS[$i]}" in
            time|command|nohup|env|exec) i=$((i + 1)) ;;
            timeout) i=$((i + 2)) ;;
            *) [[ ${WORDS[$i]} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || break; i=$((i + 1)) ;;
        esac
    done
    [ "$i" -lt "${#WORDS[@]}" ] || continue
    case "${WORDS[$i]}" in
        cd)
            if [ $((i + 1)) -lt "${#WORDS[@]}" ]; then
                dir="$(resolve_dir "$dir" "${WORDS[$((i + 1))]}")"
            else
                dir="$HOME"
            fi
            continue ;;
        git) ;;
        *) continue ;;
    esac
    i=$((i + 1))
    gitdir="$dir"
    # git's own options come before the subcommand.
    while [ "$i" -lt "${#WORDS[@]}" ]; do
        case "${WORDS[$i]}" in
            -C) gitdir="$(resolve_dir "$gitdir" "${WORDS[$((i + 1))]:-.}")"; i=$((i + 2)) ;;
            -c) i=$((i + 2)) ;;
            -*) i=$((i + 1)) ;;
            *) break ;;
        esac
    done
    [ "${WORDS[$i]:-}" = push ] || continue
    check_push "$gitdir" "${WORDS[@]:$((i + 1))}"
done <<<"$segments"

[ "${#BLOCKED[@]}" -eq 0 ] && exit 0

# shellcheck disable=SC2016  # the backticks are literal Markdown for Claude
{
    printf 'HSE pre-push gate: refusing this push, because the gate has not passed on what it sends.\n'
    for b in "${BLOCKED[@]}"; do printf '  %s\n' "$b"; done
    printf '\nRun `scripts/gate.sh --quick` (or the full `scripts/gate.sh`) from the checkout root on\n'
    printf 'exactly this commit, then push again. The gate records a receipt for the tree it\n'
    printf 'checked, and only when every check it ran passed and the tree did not change\n'
    printf 'mid-run. A new commit, amend or rebase is a new tree (REQ-HARNESS-001).\n'
} >&2
exit 2
