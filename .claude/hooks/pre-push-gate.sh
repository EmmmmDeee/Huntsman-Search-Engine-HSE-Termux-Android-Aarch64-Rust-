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
# The command is read by a small quote-aware lexer (`lex` below): single and
# double quotes, backslash escapes, `;` `&&` `||` `|` `&` newlines and
# subshell brackets, and redirections, as the shell reads them. A directory or
# refspec the shell would only know at run time (`$VAR`, `$(…)`, backticks)
# cannot be resolved here, so in an HSE checkout such a push is refused with
# the reason, and so is a command whose quotes do not balance and that
# mentions `push`. Guessing there would let a real push through unchecked
# (REQ-HARNESS-003).
set -uo pipefail

# Drain stdin before any exit. Claude Code writes the hook JSON to this
# process's stdin; exiting first (as the bypass below used to) closes the pipe
# under the writer, which then fails with EPIPE depending on who is scheduled
# first. Every path below reads it, so no exit races the caller.
INPUT="$(cat)"

[ "${HSE_PUSH_GATE:-on}" = off ] && exit 0

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

# Marks a word the shell would only finish at run time: it holds `$` or a
# backtick outside single quotes. Prefixed to the word, never a real character.
DYN=$'\001'
# A command boundary in TOKENS.
SEP=$'\036'

# Split a command line into TOKENS the way the shell would: quotes removed,
# escapes applied, each command's words followed by $SEP, redirections and
# their targets dropped. LEX_OK=0 when a quote is left open.
lex() { # lex <text>
    TOKENS=()
    LEX_OK=1
    local s="$1" n=${#1} i=0 c nx q="" word="" have=0 dyn=0 redir=0 tilde=0
    # Heredocs opened on the current line (delimiter, and whether `<<-`
    # strips leading tabs), whose bodies start after its newline.
    local hd=() hds=() k line rest delim strip
    emit() {
        if [ "$have" = 1 ]; then
            if [ "$redir" = 1 ]; then
                redir=0 # the redirection's target, not an argument
            else
                if [ "$tilde" = 1 ]; then
                    if [ "$word" = "~" ]; then
                        word="$HOME"
                    elif [ "${word#\~/}" != "$word" ]; then
                        word="$HOME/${word#\~/}"
                    fi
                fi
                [ "$dyn" = 1 ] && word="$DYN$word"
                TOKENS+=("$word")
            fi
        fi
        word=""
        have=0
        dyn=0
        tilde=0
    }
    boundary() {
        emit
        redir=0
        TOKENS+=("$SEP")
    }
    while [ "$i" -lt "$n" ]; do
        c="${s:i:1}"
        nx="${s:i+1:1}"
        if [ "$q" = "'" ]; then
            if [ "$c" = "'" ]; then q=""; else word+="$c"; fi
        elif [ "$q" = '"' ]; then
            case "$c" in
                '"') q="" ;;
                '\')
                    case "$nx" in
                        '"' | '\' | '$' | '`') word+="$nx"; i=$((i + 1)) ;;
                        *) word+="$c" ;;
                    esac ;;
                '$' | '`') dyn=1; word+="$c" ;;
                *) word+="$c" ;;
            esac
        else
            case "$c" in
                "'" | '"') q="$c"; have=1 ;;
                '\')
                    # backslash-newline is a line continuation, anything else a literal
                    [ "$nx" = $'\n' ] || word+="$nx"
                    i=$((i + 1))
                    have=1 ;;
                ' ' | $'\t') emit ;;
                $'\n')
                    boundary
                    if [ "${#hd[@]}" -gt 0 ]; then
                        # A heredoc's body is text fed to a command, never
                        # commands: skip to the line after each delimiter.
                        # Read as commands, a commit message or an inline
                        # script is unbalanced quotes and stray `push` words.
                        i=$((i + 1))
                        for k in "${!hd[@]}"; do
                            while [ "$i" -lt "$n" ]; do
                                rest="${s:i}"
                                line="${rest%%$'\n'*}"
                                i=$((i + ${#line} + 1))
                                [ "${hds[k]}" = 1 ] && line="${line#"${line%%[!$'\t']*}"}"
                                [ "$line" = "${hd[k]}" ] && break
                            done
                        done
                        hd=()
                        hds=()
                        continue
                    fi ;;
                ';' | '(' | ')') boundary ;;
                '&' | '|')
                    boundary
                    [ "$nx" = "$c" ] && i=$((i + 1)) ;;
                '<' | '>')
                    if [ "$c" = '<' ] && [ "$nx" = '<' ] && [ "${s:i+2:1}" != '<' ]; then
                        # `<<DELIM`, `<<-DELIM`, `<<'DELIM'`: a heredoc. Note
                        # its delimiter; the body starts on the next line.
                        emit
                        i=$((i + 2))
                        strip=0
                        if [ "${s:i:1}" = '-' ]; then
                            strip=1
                            i=$((i + 1))
                        fi
                        while [ "${s:i:1}" = ' ' ] || [ "${s:i:1}" = $'\t' ]; do i=$((i + 1)); done
                        delim=""
                        while [ "$i" -lt "$n" ]; do
                            c="${s:i:1}"
                            case "$c" in
                                "'" | '"')
                                    i=$((i + 1))
                                    while [ "$i" -lt "$n" ] && [ "${s:i:1}" != "$c" ]; do
                                        delim+="${s:i:1}"
                                        i=$((i + 1))
                                    done ;;
                                '\')
                                    i=$((i + 1))
                                    delim+="${s:i:1}" ;;
                                ' ' | $'\t' | $'\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>') break ;;
                                *) delim+="$c" ;;
                            esac
                            i=$((i + 1))
                        done
                        hd+=("$delim")
                        hds+=("$strip")
                        continue
                    fi
                    # `2>`: a numeric word right before the operator is its fd.
                    if [ "$have" = 1 ] && [[ $word =~ ^[0-9]+$ ]]; then
                        word=""
                        have=0
                    fi
                    emit
                    while [ "${s:i+1:1}" = '>' ] || [ "${s:i+1:1}" = '<' ]; do i=$((i + 1)); done
                    if [ "${s:i+1:1}" = '&' ]; then
                        # `>&2`, `2>&1`, `>&-`: duplicates a descriptor, takes no word
                        i=$((i + 1))
                        while [[ ${s:i+1:1} =~ [0-9-] ]]; do i=$((i + 1)); done
                    else
                        redir=1
                    fi ;;
                '$' | '`') dyn=1; word+="$c"; have=1 ;;
                '~')
                    [ "$have" = 0 ] && tilde=1
                    word+="$c"
                    have=1 ;;
                *) word+="$c"; have=1 ;;
            esac
        fi
        i=$((i + 1))
    done
    [ -z "$q" ] || LEX_OK=0
    boundary
}

is_dynamic() { [ "${1#"$DYN"}" != "$1" ]; }
shown() { printf '%s' "${1#"$DYN"}"; }

resolve_dir() { # resolve_dir <base> <path>
    case "$2" in
        /*) printf '%s' "$2" ;;
        *)  printf '%s/%s' "$1" "$2" ;;
    esac
}

# The HSE checkout containing <dir>, or nothing: not a git checkout, or one
# from before gate receipts (no scripts/gate-receipt.sh at its top level).
hse_top() { # hse_top <dir>
    local top
    top="$(git -C "$1" rev-parse --show-toplevel 2>/dev/null)" || return 1
    [ -x "$top/scripts/gate-receipt.sh" ] || return 1
    printf '%s' "$top"
}

# Whether this session works on HSE: its current directory, or the project it
# started in (the Bash tool's directory persists between commands, so a
# session in this project can sit anywhere). Only then does an unknowable push
# get refused; elsewhere this hook has no business.
in_hse_session() {
    hse_top "$CWD" >/dev/null || { [ -n "${CLAUDE_PROJECT_DIR:-}" ] && hse_top "$CLAUDE_PROJECT_DIR" >/dev/null; }
}

BLOCKED=()

# Check one `git push` invocation. $1 is the repo directory (empty when it
# cannot be known before run time, with $2 saying why), and the rest are the
# words after `push`.
check_push() {
    local dir="$1" unknown="$2"
    shift 2
    if [ -z "$dir" ]; then
        # Which repository this pushes from is decided at run time. If the
        # session is in an HSE checkout, refuse rather than guess.
        in_hse_session || return 0
        BLOCKED+=("cannot tell which repository this push runs in: the directory $unknown is only known at run time. Name it literally, or run the push from inside the checkout.")
        return 0
    fi
    local top
    top="$(hse_top "$dir")" || return 0
    local receipt="$top/scripts/gate-receipt.sh"

    local positional=() w
    while [ "$#" -gt 0 ]; do
        w="$1"
        shift
        case "$w" in
            -n | --dry-run | -d | --delete) return 0 ;;
            -o | --push-option | --repo | --receive-pack | --exec) shift ;;
            --) positional+=("$@"); break ;;
            -* | "$DYN"-*) ;;
            *) positional+=("$w") ;;
        esac
    done

    # positional[0] is the remote; everything after it is a refspec.
    local revs=() spec src
    for spec in "${positional[@]:1}"; do
        if is_dynamic "$spec"; then
            BLOCKED+=("$top: cannot tell what this push sends: the refspec $(shown "$spec") is only known at run time. Name the branch literally.")
            continue
        fi
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

# Walk one command's words (from WORDS): wrappers and assignments first, then
# `cd` (which moves `dir` for the commands after it) or `git … push`.
dir="$CWD"
dir_unknown=""
walk_command() {
    [ "${#WORDS[@]}" -gt 0 ] || return 0
    local i=0
    while [ "$i" -lt "${#WORDS[@]}" ]; do
        case "${WORDS[$i]}" in
            time | command | nohup | env | exec | if | then | else | elif | do | while | until | '!' | '{') i=$((i + 1)) ;;
            timeout) i=$((i + 2)) ;;
            *) [[ ${WORDS[$i]} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || break; i=$((i + 1)) ;;
        esac
    done
    [ "$i" -lt "${#WORDS[@]}" ] || return 0
    case "${WORDS[$i]}" in
        cd)
            local to="${WORDS[$((i + 1))]:-$HOME}"
            if is_dynamic "$to"; then
                dir=""
                dir_unknown="$(shown "$to")"
            elif [ -n "$dir" ]; then
                dir="$(resolve_dir "$dir" "$to")"
            elif [ "${to#/}" != "$to" ]; then
                # An absolute path is known again, whatever came before.
                dir="$to"
                dir_unknown=""
            fi
            return 0 ;;
        git) ;;
        *) return 0 ;;
    esac
    i=$((i + 1))
    local gitdir="$dir" unknown="$dir_unknown" to
    # git's own options come before the subcommand.
    while [ "$i" -lt "${#WORDS[@]}" ]; do
        case "${WORDS[$i]}" in
            -C)
                to="${WORDS[$((i + 1))]:-.}"
                if is_dynamic "$to"; then
                    gitdir=""
                    unknown="$(shown "$to")"
                elif [ -n "$gitdir" ] || [ "${to#/}" != "$to" ]; then
                    gitdir="$(resolve_dir "$gitdir" "$to")"
                fi
                i=$((i + 2)) ;;
            -c) i=$((i + 2)) ;;
            -*) i=$((i + 1)) ;;
            *) break ;;
        esac
    done
    [ "${WORDS[$i]:-}" = push ] || return 0
    check_push "$gitdir" "$unknown" "${WORDS[@]:$((i + 1))}"
}

lex "$COMMAND"
if [ "$LEX_OK" = 0 ] && [[ $COMMAND == *push* ]] && in_hse_session; then
    # Quotes that do not balance: the shell would reject it too, but refusing
    # is the only safe reading of a command that mentions a push.
    BLOCKED+=("cannot parse this command (a quote is left open), so what it pushes is unknown.")
fi
WORDS=()
for t in "${TOKENS[@]}"; do
    if [ "$t" = "$SEP" ]; then
        walk_command
        WORDS=()
    else
        WORDS+=("$t")
    fi
done

[ "${#BLOCKED[@]}" -eq 0 ] && exit 0

# shellcheck disable=SC2016  # the backticks are literal Markdown for Claude
{
    printf 'HSE pre-push gate: refusing this push. The gate has not passed on what it sends, or what it sends cannot be known.\n'
    for b in "${BLOCKED[@]}"; do printf '  %s\n' "$b"; done
    printf '\nRun `scripts/gate.sh --quick` (or the full `scripts/gate.sh`) from the checkout root on\n'
    printf 'exactly this commit, then push again. The gate records a receipt for the tree it\n'
    printf 'checked, and only when every check it ran passed and the tree did not change\n'
    printf 'mid-run. A new commit, amend or rebase is a new tree (REQ-HARNESS-001).\n'
} >&2
exit 2
