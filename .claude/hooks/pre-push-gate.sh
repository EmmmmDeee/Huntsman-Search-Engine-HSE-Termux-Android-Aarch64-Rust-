#!/usr/bin/env bash
# PreToolUse hook (Bash): refuse a `git push` of a tree the gate has not passed.
#
# Registered in .claude/settings.json under PreToolUse / matcher "Bash", for
# every Bash command. A push can hide behind `sh -c`, `eval`, `xargs` or a
# command substitution, and none of those starts with `git`, so the `git *`
# filter this hook used to sit behind let them past unseen (REQ-HARNESS-006).
# A command with no `push` or `send-pack` in it costs one string test.
#
# For each push it finds, the hook resolves every ref the push sends and asks
# `scripts/gate-receipt.sh check` whether `scripts/gate.sh` passed on that
# ref's tree. With no receipt it exits 2: Claude Code blocks the command and
# shows Claude this script's stderr (REQ-HARNESS-001). It only checks.
#
# Two layers enforce the gate. git's own pre-push hook (.githooks/pre-push,
# REQ-HARNESS-004) is handed the exact commit each ref sends, however the push
# was invoked: it is the backstop. This hook sees the command before it runs.
# Its first duty is to refuse what would switch the backstop off: `--no-verify`
# outside a push it has itself checked, a `core.hooksPath` override, git config
# injected through GIT_CONFIG_*, and `send-pack`, which runs no hook at all. Its
# second is to check every push it can read, and in an HSE session to refuse
# every push it cannot (REQ-HARNESS-003, REQ-HARNESS-006).
#
# Not blocked:
#   * a command that is not a push; `git push --dry-run` / `-n`;
#   * a push that only deletes remote refs (`--delete`, `:branch`);
#   * a checkout that is not HSE, or an HSE commit older than gate receipts;
#   * everything, when Claude Code itself runs with HSE_PUSH_GATE=off in its
#     environment (a person's decision). A `HSE_PUSH_GATE=off git push` prefix
#     inside the command does nothing: this process never sees it.
#
# Out of scope, by the receipt's own design ("a record, not a signature"): a
# push set up in an earlier command so that its own text names no push, such
# as an alias defined before, or `core.hooksPath` changed before. That is a
# deliberate way around, not an accident.
#
# The command is read by a quote-aware lexer (`lex`): quotes, escapes, `#`
# comments, `;` `&&` `||` `|` `&` newlines and subshells, redirections,
# heredocs (their bodies are text), arithmetic (opaque), and command
# substitutions, whose bodies are commands of their own even inside double
# quotes. A word the shell only completes at run time (`$VAR`, `$(…)`) is
# marked, and a push whose directory or refspec depends on one is refused in an
# HSE session rather than guessed at.
set -uo pipefail
# Bytes, not characters. Every character the lexer looks for is ASCII, and in a
# UTF-8 locale each `${s:i:1}` rescans the string, so a long command could run
# past the hook's timeout, which Claude Code treats as a pass (REQ-HARNESS-006).
LC_ALL=C

# Drain stdin before any exit (REQ-HARNESS-002).
INPUT="$(cat)"
COMMAND=""

# A cheap, conservative "could this text run a push?" test. A raw substring
# check (`case … in *push*`) is unsound: bash removes quotes and escapes before
# running a word, so `git pu""sh` / `git pus\h` run a push though their text has
# no `push` substring. This strips the characters bash removes during
# quote/escape processing so those are seen, and treats ANSI-C quoting (`$'…'`),
# command substitution (`$(…)`) and backticks — which can assemble a word from
# fragments the strip cannot — as "maybe". Only when none of these can produce
# push/send-pack is it safe to say no (REQ-HARNESS-006). Used only by the
# fail-closed trap, which cannot re-run the lexer (the lexer may be what failed);
# the normal path always lexes.
might_push() { # might_push <text>
    local t="$1"
    # Expansions that can assemble or spell a word the strip below cannot see:
    # command substitution, backticks, ANSI-C `$'…'`, parameter expansion
    # `${…}`, and brace expansion `{a,b}` / `{a..b}`.
    case "$t" in
        *'$('* | *'`'* | *"\$'"* | *'${'* | *'{'*','*'}'* | *'{'*..*'}'*) return 0 ;;
    esac
    t="${t//[\"\'\\]/}"
    case "$t" in *push* | *send-pack*) return 0 ;; esac
    return 1
}

# Claude Code blocks a command only on exit 2. A crash here (an older bash
# tripping `set -u`, say) let a push through unchecked. On a command that could
# push, any other failure now blocks too (REQ-HARNESS-006).
fail_closed() {
    local rc=$?
    { [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; } && return 0
    if might_push "${COMMAND:-$INPUT}"; then
        # shellcheck disable=SC2016  # the backticks are literal Markdown for Claude
        printf 'HSE pre-push gate: the hook failed (exit %s) on a command that may push, so it is refused.\nRun `scripts/gate.sh --quick` on exactly this commit, then push again. If this repeats, the hook needs fixing.\n' "$rc" >&2
        exit 2
    fi
    exit 0
}
trap fail_closed EXIT

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

# Every command is lexed. A raw-substring shortcut here (`case $COMMAND in
# *push*) ;; *) exit 0`) would let a push through: bash removes quotes and
# escapes before running a word, so `git pu""sh` / `git pus\h` run a push though
# their text holds no `push` substring. The lexer does that removal, so the walk
# sees the real `git push`; the cost is lexing every command, which stays well
# inside the hook's timeout even for a long one (REQ-HARNESS-006).

# Marks a word the shell only finishes at run time: it holds `$` or a backtick
# outside single quotes. Prefixed to the word, never a real character.
DYN=$'\001'
# Starts an operator in TOKENS; the operator follows: `;` `&&` `||` `|` `&`
# `nl` (a newline), `(` `)` (a subshell), `sub(` `sub)` (a command
# substitution), `end`.
SEP=$'\036'

# Split a command line into TOKENS the way the shell would: quotes removed,
# escapes applied, words and operators, redirections and their targets
# dropped. LEX_OK=0 when a quote or a substitution is left open, or a heredoc
# that mentions a push never ends.
lex() { # lex <text>
    TOKENS=()
    LEX_OK=1
    local s="$1" n=${#1} i=0 c nx q="" word="" have=0 dyn=0 redir=0 tilde=0
    # Heredocs opened on the current line (delimiter, and whether `<<-` strips
    # leading tabs), whose bodies start after its newline.
    local hd=() hds=() k line rest delim strip found skipped prev
    # Open substitutions, innermost last: the quote state to return to, the
    # kind (`p` for `$(`, `b` for a backtick), and the paren depth outside it.
    local fq=() fk=() fd=() depth=0 last
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
    op() { # op <operator>
        emit
        redir=0
        TOKENS+=("$SEP$1")
    }
    # Open a substitution: the word so far is marked run-time, the body is
    # lexed unquoted as commands of its own.
    sub_open() { # sub_open <kind>
        dyn=1
        have=1
        fq+=("$q")
        fk+=("$1")
        fd+=("$depth")
        depth=0
        q=""
        op 'sub('
    }
    sub_close() {
        op 'sub)'
        last=$((${#fk[@]} - 1))
        q="${fq[last]}"
        depth="${fd[last]}"
        unset 'fq[last]' 'fk[last]' 'fd[last]'
        fq=(${fq[@]+"${fq[@]}"})
        fk=(${fk[@]+"${fk[@]}"})
        fd=(${fd[@]+"${fd[@]}"})
        # The word the substitution sat in goes on, and is run-time.
        dyn=1
        have=1
    }
    # `$((…))` or `((…))`: arithmetic, kept as one opaque run-time word.
    # A `<<` in it is a shift, not a heredoc.
    arith() {
        local d=0 ch
        while [ "$i" -lt "$n" ]; do
            ch="${s:i:1}"
            word+="$ch"
            if [ "$ch" = "(" ]; then
                d=$((d + 1))
            elif [ "$ch" = ")" ]; then
                d=$((d - 1))
                [ "$d" -le 0 ] && break
            fi
            i=$((i + 1))
        done
        dyn=1
        have=1
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
                        $'\n') i=$((i + 1)) ;;
                        *) word+="$c" ;;
                    esac ;;
                '$')
                    if [ "$nx" = "(" ] && [ "${s:i+2:1}" = "(" ]; then
                        arith
                    elif [ "$nx" = "(" ]; then
                        word+='$'
                        i=$((i + 1))
                        sub_open p
                    else
                        dyn=1
                        word+="$c"
                    fi ;;
                '`') word+='`'; sub_open b ;;
                *) word+="$c" ;;
            esac
        else
            case "$c" in
                "'" | '"') q="$c"; have=1 ;;
                '\')
                    # backslash-newline is a line continuation and starts no
                    # word; anything else is a literal
                    if [ "$nx" != $'\n' ]; then
                        word+="$nx"
                        have=1
                    fi
                    i=$((i + 1)) ;;
                ' ' | $'\t') emit ;;
                '#')
                    # A comment starts a word the shell sees as a word start.
                    prev=""
                    [ "$i" = 0 ] || prev="${s:i-1:1}"
                    if [ "$have" = 0 ] && case "$prev" in
                        '' | ' ' | $'\t' | $'\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>') true ;;
                        *) false ;;
                    esac; then
                        while [ "$((i + 1))" -lt "$n" ] && [ "${s:i+1:1}" != $'\n' ]; do i=$((i + 1)); done
                    else
                        word+="$c"
                        have=1
                    fi ;;
                $'\n')
                    op nl
                    if [ "${#hd[@]}" -gt 0 ]; then
                        # A heredoc's body is text fed to a command, never
                        # commands: skip to the line after each delimiter.
                        i=$((i + 1))
                        for k in "${!hd[@]}"; do
                            found=0
                            skipped=""
                            while [ "$i" -lt "$n" ]; do
                                rest="${s:i}"
                                line="${rest%%$'\n'*}"
                                i=$((i + ${#line} + 1))
                                [ "${hds[k]}" = 1 ] && line="${line#"${line%%[!$'\t']*}"}"
                                if [ "$line" = "${hd[k]}" ]; then
                                    found=1
                                    break
                                fi
                                skipped+="$line"$'\n'
                            done
                            # A heredoc that never ends is not one bash would
                            # run; if a push hides in it, refuse rather than skip.
                            if [ "$found" = 0 ] && [[ $skipped == *push* || $skipped == *send-pack* ]]; then
                                LEX_OK=0
                            fi
                        done
                        hd=()
                        hds=()
                        continue
                    fi ;;
                ';') op ';'; while [ "${s:i+1:1}" = ';' ] || [ "${s:i+1:1}" = '&' ]; do i=$((i + 1)); done ;;
                '(')
                    if [ "$nx" = "(" ] && [ "$have" = 0 ]; then
                        arith
                    else
                        [ "${#fk[@]}" -gt 0 ] && depth=$((depth + 1))
                        op '('
                    fi ;;
                ')')
                    if [ "${#fk[@]}" -gt 0 ] && [ "${fk[${#fk[@]} - 1]}" = p ] && [ "$depth" = 0 ]; then
                        sub_close
                    else
                        [ "$depth" -gt 0 ] && depth=$((depth - 1))
                        op ')'
                    fi ;;
                '`')
                    if [ "${#fk[@]}" -gt 0 ] && [ "${fk[${#fk[@]} - 1]}" = b ]; then
                        sub_close
                    else
                        word+='`'
                        sub_open b
                    fi ;;
                '&')
                    if [ "$nx" = '>' ]; then
                        # `&>file`, `&>>file`: a redirection, not a background job
                        emit
                        i=$((i + 1))
                        [ "${s:i+1:1}" = '>' ] && i=$((i + 1))
                        redir=1
                    elif [ "$nx" = '&' ]; then
                        op '&&'
                        i=$((i + 1))
                    else
                        op '&'
                    fi ;;
                '|')
                    if [ "$nx" = '|' ]; then
                        op '||'
                        i=$((i + 1))
                    else
                        op '|'
                        [ "$nx" = '&' ] && i=$((i + 1))
                    fi ;;
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
                '$')
                    if [ "$nx" = "(" ] && [ "${s:i+2:1}" = "(" ]; then
                        arith
                    elif [ "$nx" = "(" ]; then
                        word+='$'
                        i=$((i + 1))
                        sub_open p
                    else
                        dyn=1
                        word+="$c"
                        have=1
                    fi ;;
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
    [ "${#fk[@]}" -eq 0 ] || LEX_OK=0
    op end
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
# from before gate receipts. `-f`, not `-x`: on storage mounted noexec (Android
# shared storage) no file is executable, and the gate must still apply there
# (REQ-HARNESS-006). The receipt script is always run through bash.
hse_top() { # hse_top <dir>
    local top
    top="$(git -C "$1" rev-parse --show-toplevel 2>/dev/null)" || return 1
    [ -f "$top/scripts/gate-receipt.sh" ] || return 1
    printf '%s' "$top"
}

# Whether this session works on HSE: its current directory, or the project it
# started in. Only then is a push the hook cannot resolve refused.
HSE_SESSION=""
in_hse_session() {
    if [ -z "$HSE_SESSION" ]; then
        HSE_SESSION=no
        if hse_top "$CWD" >/dev/null || { [ -n "${CLAUDE_PROJECT_DIR:-}" ] && hse_top "$CLAUDE_PROJECT_DIR" >/dev/null; }; then
            HSE_SESSION=yes
        fi
    fi
    [ "$HSE_SESSION" = yes ]
}

BLOCKED=()
# Set when a command in the line changes core.hooksPath persistently (`git
# config core.hooksPath …`, or `--unset` of it): the config file is on disk, so
# a push anywhere later in the line — even from a subshell that set it — then
# runs with git's own pre-push hook disabled, and is refused (REQ-HARNESS-006).
HOOKS_TAMPERED=0
# Aliases defined inside the command itself (`-c alias.x=…`, `git config
# alias.x …`), which a lookup of the repository's config cannot see yet.
INLINE_ALIASES=()

refuse() { BLOCKED+=("$1"); }

# Check one `git push` invocation. $1 is the repository directory (empty when
# it cannot be known before run time, with $2 saying why), $3 is 1 when the
# git command's own `-c` options change what a push sends, and the rest are
# the words after `push`.
check_push() {
    local dir="$1" unknown="$2" push_config="$3"
    shift 3
    if [ -z "$dir" ]; then
        in_hse_session || return 0
        refuse "cannot tell which repository this push runs in: $unknown is only known at run time. Name it literally, or run the push from inside the checkout."
        return 0
    fi
    local top
    top="$(hse_top "$dir")" || return 0
    local receipt="$top/scripts/gate-receipt.sh"

    # Options git knows that do not change which refs are sent; anything else
    # is refused rather than modelled (REQ-HARNESS-006).
    local positional=() w dry=0 del=0 remote_opt="" unread=""
    while [ "$#" -gt 0 ]; do
        w="$1"
        shift
        case "$w" in
            -n | --dry-run) dry=1 ;;
            --no-dry-run) dry=0 ;;
            -d | --delete) del=1 ;;
            --no-delete) del=0 ;;
            # A known option: it does not widen what is sent. Whether the push
            # is allowed rests on the receipt for what it sends, checked below —
            # `--no-verify` disables git's own hook, not this one, and a push
            # with no receipt is refused regardless of it (REQ-HARNESS-006).
            --no-verify | --verify) ;;
            -u | --set-upstream | -f | --force | --force-with-lease | --force-with-lease=* \
                | --no-force-with-lease | --force-if-includes | --no-force-if-includes \
                | -q | --quiet | -v | --verbose | --progress | --no-progress | --porcelain \
                | --atomic | --no-atomic | --signed | --signed=* | --no-signed | --thin \
                | --no-thin | --recurse-submodules=* | --no-recurse-submodules | -4 | -6 \
                | --ipv4 | --ipv6 | --push-option=* | --receive-pack=* | --exec=*) ;;
            -o | --push-option | --receive-pack | --exec) shift ;;
            --repo) remote_opt="${1:-}"; shift ;;
            --repo=*) remote_opt="${w#--repo=}" ;;
            --) positional+=("$@"); break ;;
            # --all, --mirror, --tags and anything unknown: decided below, so
            # that a dry run of them, which sends nothing, still passes.
            -* | "$DYN"-*) [ -n "$unread" ] || unread="$(shown "$w")" ;;
            *) positional+=("$w") ;;
        esac
    done
    [ "$dry" = 1 ] && return 0
    if [ -n "$unread" ]; then
        refuse "$top: cannot tell what this push sends: option $unread. Push named branches, without it."
        return 0
    fi
    # `--delete` sends deletions only.
    [ "$del" = 1 ] && return 0

    # positional[0] is the remote (unless --repo named it); the rest are refspecs.
    local specs=()
    if [ -n "$remote_opt" ]; then
        specs=(${positional[@]+"${positional[@]}"})
    elif [ "${#positional[@]}" -gt 1 ]; then
        specs=("${positional[@]:1}")
    fi

    local revs=() spec src tagnext=0
    for spec in ${specs[@]+"${specs[@]}"}; do
        if is_dynamic "$spec"; then
            refuse "$top: cannot tell what this push sends: the refspec $(shown "$spec") is only known at run time. Name the branch literally."
            continue
        fi
        if [ "$tagnext" = 1 ]; then
            revs+=("refs/tags/$spec")
            tagnext=0
            continue
        fi
        if [ "$spec" = tag ]; then
            tagnext=1
            continue
        fi
        spec="${spec#+}"
        if [ "$spec" = ":" ]; then
            refuse "$top: \`:\` pushes every branch that matches one on the remote. Push named branches."
            continue
        fi
        src="${spec%%:*}"
        case "$src" in
            *'*'*)
                refuse "$top: the refspec $spec is a pattern, which sends refs the hook cannot list. Push named branches."
                continue ;;
        esac
        # `:dst` (an empty source) deletes the remote ref; nothing is sent.
        [ -n "$src" ] || continue
        revs+=("$src")
    done

    if [ "${#specs[@]}" -eq 0 ]; then
        # No refspec: git decides from config what to send.
        local r="$remote_opt"
        [ -n "$r" ] || r="${positional[0]:-}"
        if is_dynamic "$r"; then
            # A run-time remote name: its `remote.<name>.push`/`mirror` config
            # cannot be read, so what this sends is unknown (REQ-HARNESS-006).
            refuse "$top: cannot tell what this push sends: the remote $(shown "$r") is only known at run time, so its push configuration cannot be read. Name the remote and the branch."
            return 0
        fi
        if [ -z "$r" ]; then
            local cur
            cur="$(git -C "$top" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
            r="$(git -C "$top" config --get "branch.$cur.pushRemote" 2>/dev/null \
                || git -C "$top" config --get remote.pushDefault 2>/dev/null \
                || git -C "$top" config --get "branch.$cur.remote" 2>/dev/null \
                || echo origin)"
        fi
        if [ "$push_config" = 1 ] \
            || [ -n "$(git -C "$top" config --get-all "remote.$r.push" 2>/dev/null)" ] \
            || [ "$(git -C "$top" config --get "remote.$r.mirror" 2>/dev/null)" = true ] \
            || [ "$(git -C "$top" config --get push.default 2>/dev/null)" = matching ]; then
            refuse "$top: this push sends what git's push configuration names (push.default, remote.$r.push or remote.$r.mirror), which the hook does not list. Push named branches."
            return 0
        fi
        revs=(HEAD)
    fi

    local rev out
    for rev in ${revs[@]+"${revs[@]}"}; do
        # A source git cannot resolve fails the push by itself.
        git -C "$top" rev-parse --verify --quiet "$rev^{tree}" >/dev/null 2>&1 || continue
        if ! out="$(cd "$top" && bash "$receipt" check "$rev" 2>&1)"; then
            refuse "$top: $out"
        fi
    done
}

# Where the next command runs: a directory, or "" with DIR_UNKNOWN saying why.
DIR="$CWD"
DIR_UNKNOWN=""
# Inside if/while/until/for/case/select/{ … }, a cd may or may not run.
COND=0

# A `cd` (or `pushd`) that ran: in a pipeline or background job it changes
# nothing that follows; inside a compound command, or when it may fail, the
# directory after it is not known.
apply_cd() { # apply_cd <prev-op> <next-op> <target words…>
    local before="$1" after="$2" to
    shift 2
    case "$before:$after" in
        '|:'* | *':|' | *':&') return 0 ;;
    esac
    # A cd on the far side of `&&`/`||` runs only if its predecessor did (or
    # did not): `cd /missing && cd /; push` leaves the shell where it started,
    # and `cd <hse> || cd /` when the left side succeeds. Its result is not
    # certain, so the directory after it is unknown (REQ-HARNESS-006).
    case "$before" in
        '&&' | '||')
            DIR=""
            DIR_UNKNOWN="the directory after a \`cd\` that runs only conditionally (${before})"
            return 0 ;;
    esac
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -L | -P | -e | -@ | -n) shift ;;
            --) shift; break ;;
            *) break ;;
        esac
    done
    to="${1:-$HOME}"
    if [ "$COND" -gt 0 ]; then
        DIR=""
        DIR_UNKNOWN="the directory after a cd inside if/while/for/case/{ }"
    elif [ "$to" = - ]; then
        DIR=""
        DIR_UNKNOWN="\`cd -\`"
    elif is_dynamic "$to"; then
        DIR=""
        DIR_UNKNOWN="$(shown "$to")"
    else
        local target
        if [ -n "$DIR" ]; then
            target="$(resolve_dir "$DIR" "$to")"
        elif [ "${to#/}" != "$to" ]; then
            target="$to"
        else
            return 0
        fi
        if [ "$after" = '&&' ] || [ -d "$target" ]; then
            DIR="$target"
            DIR_UNKNOWN=""
        else
            DIR=""
            DIR_UNKNOWN="$to (it may not exist, and the push would run where the cd failed)"
        fi
    fi
}

# True when a git subcommand word is `push`/`send-pack`, or one the hook cannot
# resolve to a literal — marked run-time by the lexer (`$(…)`, backticks,
# `$'…'`), or a brace expansion (`pu{sh,x}`, which git never spells a subcommand
# with) — and so cannot be ruled out as a push (REQ-HARNESS-006).
may_be_push_subcommand() { # may_be_push_subcommand <word>
    case "$1" in "$DYN"*) return 0 ;; esac
    case "${1#"$DYN"}" in push | send-pack | *'{'*'}'*) return 0 ;; esac
    return 1
}

# Walk one command's words: prefixes, wrappers that run their arguments, then
# the command itself. $1/$2 are the operators before and after it.
walk_command() { # walk_command <prev-op> <next-op> <words…>
    local before="$1" after="$2"
    shift 2
    [ "$#" -gt 0 ] || return 0
    local words=("$@") i=0 w runtime_args=0 git_config_env=0
    local gitdir="$DIR" unknown="$DIR_UNKNOWN"
    # Assignments first: some decide where git looks.
    while [ "$i" -lt "${#words[@]}" ]; do
        w="${words[i]}"
        case "${w#"$DYN"}" in
            GIT_DIR=* | GIT_WORK_TREE=* | GIT_COMMON_DIR=*)
                gitdir=""
                unknown="the repository chosen by ${w%%=*}"
                i=$((i + 1)) ;;
            GIT_CONFIG_COUNT=* | GIT_CONFIG_KEY_* | GIT_CONFIG_VALUE_* | GIT_CONFIG_PARAMETERS=* \
                | GIT_CONFIG_GLOBAL=* | GIT_CONFIG_SYSTEM=* | GIT_CONFIG_NOSYSTEM=*)
                # git config injected through the environment can set
                # core.hooksPath (or anything), disabling git's own pre-push
                # hook for the command it prefixes (REQ-HARNESS-006).
                git_config_env=1
                i=$((i + 1)) ;;
            *)
                [[ ${w#"$DYN"} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || break
                i=$((i + 1)) ;;
        esac
    done
    # Wrappers that run the rest of the line as a command.
    while [ "$i" -lt "${#words[@]}" ]; do
        w="${words[i]}"
        case "$w" in
            'if' | 'while' | 'until' | 'elif' | '{') COND=$((COND + 1)); i=$((i + 1)) ;;
            'for' | 'case' | 'select') COND=$((COND + 1)); return 0 ;;
            'fi' | 'done' | 'esac' | '}')
                [ "$COND" -gt 0 ] && COND=$((COND - 1))
                i=$((i + 1)) ;;
            'then' | 'else' | 'do' | '!' | 'time' | nohup | builtin) i=$((i + 1)) ;;
            command)
                i=$((i + 1))
                while :; do
                    case "${words[i]:-}" in
                        -v | -V) return 0 ;; # a query, not an invocation
                        -p) i=$((i + 1)) ;;
                        --) i=$((i + 1)); break ;;
                        *) break ;;
                    esac
                done ;;
            exec)
                i=$((i + 1))
                while case "${words[i]:-}" in -c | -l) true ;; -a) i=$((i + 1)); true ;; *) false ;; esac; do i=$((i + 1)); done ;;
            env)
                i=$((i + 1))
                while [ "$i" -lt "${#words[@]}" ]; do
                    w="${words[i]}"
                    case "$w" in
                        -u | --unset) i=$((i + 2)) ;;
                        -C | --chdir)
                            local d="${words[i+1]:-}"
                            if is_dynamic "$d"; then gitdir=""; unknown="$(shown "$d")"
                            elif [ -n "$gitdir" ] || [ "${d#/}" != "$d" ]; then gitdir="$(resolve_dir "$gitdir" "$d")"; fi
                            i=$((i + 2)) ;;
                        --chdir=*)
                            local d="${w#--chdir=}"
                            if is_dynamic "$d"; then gitdir=""; unknown="$(shown "$d")"
                            elif [ -n "$gitdir" ] || [ "${d#/}" != "$d" ]; then gitdir="$(resolve_dir "$gitdir" "$d")"; fi
                            i=$((i + 1)) ;;
                        -S | --split-string | -S?* | --split-string=*)
                            case "$w" in
                                -S | --split-string) walk_text "${words[i+1]:-}" "$gitdir" "$unknown" ;;
                                -S?*) walk_text "${w#-S}" "$gitdir" "$unknown" ;;
                                --split-string=*) walk_text "${w#--split-string=}" "$gitdir" "$unknown" ;;
                            esac
                            return 0 ;;
                        --) # end of env's options; NAME=VALUE assignments and the
                            # command still follow, so keep reading assignments.
                            i=$((i + 1))
                            while [ "$i" -lt "${#words[@]}" ]; do
                                w="${words[i]}"
                                case "${w#"$DYN"}" in
                                    GIT_DIR=* | GIT_WORK_TREE=* | GIT_COMMON_DIR=*)
                                        gitdir=""; unknown="the repository chosen by ${w%%=*}"; i=$((i + 1)) ;;
                                    GIT_CONFIG_COUNT=* | GIT_CONFIG_KEY_* | GIT_CONFIG_VALUE_* | GIT_CONFIG_PARAMETERS=* \
                                        | GIT_CONFIG_GLOBAL=* | GIT_CONFIG_SYSTEM=* | GIT_CONFIG_NOSYSTEM=*)
                                        git_config_env=1; i=$((i + 1)) ;;
                                    *) [[ ${w#"$DYN"} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || break; i=$((i + 1)) ;;
                                esac
                            done
                            break ;;
                        -*) i=$((i + 1)) ;;
                        GIT_DIR=* | GIT_WORK_TREE=* | GIT_COMMON_DIR=*)
                            gitdir=""
                            unknown="the repository chosen by ${w%%=*}"
                            i=$((i + 1)) ;;
                        GIT_CONFIG_COUNT=* | GIT_CONFIG_KEY_* | GIT_CONFIG_VALUE_* | GIT_CONFIG_PARAMETERS=* \
                            | GIT_CONFIG_GLOBAL=* | GIT_CONFIG_SYSTEM=* | GIT_CONFIG_NOSYSTEM=*)
                            git_config_env=1; i=$((i + 1)) ;;
                        *) [[ $w =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || break; i=$((i + 1)) ;;
                    esac
                done ;;
            watch | proot | runuser | parallel)
                # Exec-wrappers whose option grammars are too varied to locate
                # the wrapped command reliably: proot's `-r`/`-b` take paths,
                # parallel replaces `{}` and reads args from stdin/`:::`, runuser
                # takes a positional user or a `-c` command string. So the
                # command boundary is not walked; instead, if the rest of the
                # line spells a `git push` (or send-pack), the wrapper runs a
                # push this hook cannot vet and it is refused in an HSE session.
                # git's own pre-push hook stays the backstop on every configured
                # clone (REQ-HARNESS-006).
                local jw jn jk gw
                for ((jw = i + 1; jw < ${#words[@]}; jw++)); do
                    # A run-time word, or a nested shell/eval, could carry a push
                    # the scan below cannot see. Since these wrappers are not
                    # fully parsed, refuse in an HSE session rather than pass.
                    case "${words[jw]}" in "$DYN"*)
                        in_hse_session && refuse "\`$(shown "${words[i]}")\` runs a command only fixed at run time, which this hook cannot vet for a push. Run \`git push\` with named branches, or from inside the checkout."
                        return 0 ;;
                    esac
                    jn="${words[jw]#"$DYN"}"
                    jn="${jn##*/}"
                    case "$jn" in
                        sh | bash | dash | zsh | ksh | eval)
                            in_hse_session && refuse "\`$(shown "${words[i]}")\` runs a nested shell this hook cannot vet for a push. Run \`git push\` with named branches, or from inside the checkout."
                            return 0 ;;
                        git-push | git-send-pack | send-pack)
                            in_hse_session && refuse "\`$(shown "${words[i]}")\` runs a push this hook cannot vet. Push with a plain \`git push\` and named branches."
                            return 0 ;;
                        git)
                            # Skip git's own global options (some take an
                            # argument) to the subcommand, so `git -C x push` and
                            # `git -c k=v push` are seen, not just `git push`.
                            jk=$((jw + 1))
                            while [ "$jk" -lt "${#words[@]}" ]; do
                                gw="${words[jk]#"$DYN"}"
                                case "$gw" in
                                    -C | -c | --git-dir | --work-tree | --namespace | --config-env | --attr-source | --super-prefix) jk=$((jk + 2)) ;;
                                    -*) jk=$((jk + 1)) ;;
                                    *) break ;;
                                esac
                            done
                            if may_be_push_subcommand "${words[jk]:-}"; then
                                in_hse_session && refuse "\`$(shown "${words[i]}")\` runs a git push whose command and arguments this hook cannot vet (they are only fixed at run time). Push with a plain \`git push\` and named branches, or from inside the checkout."
                                return 0
                            fi ;;
                    esac
                done
                return 0 ;;
            nice)
                i=$((i + 1))
                while :; do
                    case "${words[i]:-}" in
                        -n | --adjustment) i=$((i + 2)) ;;
                        -[0-9]* | --adjustment=*) i=$((i + 1)) ;;
                        --) i=$((i + 1)); break ;;
                        *) break ;;
                    esac
                done ;;
            timeout)
                i=$((i + 1))
                while case "${words[i]:-}" in
                    -s | --signal | -k | --kill-after) i=$((i + 1)); true ;;
                    -*) true ;;
                    *) false ;;
                esac; do i=$((i + 1)); done
                i=$((i + 1)) ;; # the duration
            sudo | doas)
                i=$((i + 1))
                while case "${words[i]:-}" in
                    -u | -g | -C | -D | -h | -p | -r | -t | -U | -T) i=$((i + 1)); true ;;
                    -*) true ;;
                    *) false ;;
                esac; do i=$((i + 1)); done ;;
            setsid | stdbuf | ionice | chrt | taskset | flock | xargs)
                # Options, then (chrt: a priority; taskset: a mask; flock: a
                # lock file) the command. Their option words are skipped; a
                # plain word that is not `git` is the one argument they take.
                local wrapper="$w"
                i=$((i + 1))
                while [ "$i" -lt "${#words[@]}" ]; do
                    w="${words[i]}"
                    case "$wrapper:$w" in
                        xargs:-I | xargs:-n | xargs:-P | xargs:-d | xargs:-a | xargs:-E | xargs:-L | xargs:-s \
                            | stdbuf:-i | stdbuf:-o | stdbuf:-e | ionice:-c | ionice:-n | ionice:-p \
                            | flock:-w | flock:-E | flock:-c) i=$((i + 2)) ;;
                        *:-*) i=$((i + 1)) ;;
                        *) break ;;
                    esac
                done
                case "$wrapper" in
                    chrt | taskset | flock)
                        local nxt="${words[i]:-x}"
                        [ "${nxt##*/}" = git ] || i=$((i + 1)) ;;
                    xargs) runtime_args=1 ;;
                esac ;;
            sh | bash | dash | zsh | ksh | */sh | */bash | */dash | */zsh | */ksh)
                # `sh -c STRING`: STRING is a command line of its own.
                i=$((i + 1))
                while [ "$i" -lt "${#words[@]}" ]; do
                    w="${words[i]}"
                    case "$w" in
                        --rcfile | --init-file) i=$((i + 2)) ;;
                        --*) i=$((i + 1)) ;;
                        -o | +o) i=$((i + 2)) ;;
                        -[!-]* | +[!-]*)
                            case "$w" in
                                *c*) ;;
                                *) i=$((i + 1)); continue ;;
                            esac
                            local code="${words[i+1]:-}"
                            if is_dynamic "$code"; then
                                # The script is assembled at run time; its text is
                                # not what runs, so it cannot be vetted for a push.
                                in_hse_session && refuse "cannot tell what this runs: the script given to $(shown "${words[0]}") -c is only known at run time. Run \`git push\` with named branches, or from inside the checkout."
                            else
                                walk_text "$code" "$gitdir" "$unknown"
                            fi
                            return 0 ;;
                        *) return 0 ;; # a script file: not this hook's to read
                    esac
                done
                return 0 ;;
            eval)
                local joined="" a
                for a in "${words[@]:i+1}"; do
                    if is_dynamic "$a"; then
                        # eval runs its argument as assembled at run time; the
                        # token text is not what runs, so it cannot be vetted.
                        in_hse_session && refuse "cannot tell what this runs: eval of $(shown "$a") is only known at run time. Run \`git push\` with named branches, or from inside the checkout."
                        return 0
                    fi
                    joined+="$a "
                done
                walk_text "$joined" "$gitdir" "$unknown"
                return 0 ;;
            *) break ;;
        esac
    done
    [ "$i" -lt "${#words[@]}" ] || return 0
    w="${words[i]}"
    local name="${w#"$DYN"}"
    name="${name##*/}"
    # A command only known at run time, handed a push: what runs is unknown.
    if is_dynamic "$w"; then
        local rest_w
        for rest_w in "${words[@]:i+1}"; do
            case "${rest_w#"$DYN"}" in push | send-pack)
                in_hse_session && refuse "cannot tell what runs: the command $(shown "$w") is only known at run time, and it is handed a push."
                return 0 ;;
            esac
        done
        return 0
    fi
    case "$name" in
        cd | pushd)
            apply_cd "$before" "$after" "${words[@]:i+1}"
            return 0 ;;
        export | declare | typeset)
            local e
            for e in "${words[@]:i+1}"; do
                case "${e#"$DYN"}" in
                    GIT_DIR=* | GIT_WORK_TREE=* | GIT_COMMON_DIR=*)
                        DIR=""
                        DIR_UNKNOWN="the repository chosen by exporting ${e#"$DYN"}"
                        DIR_UNKNOWN="${DIR_UNKNOWN%%=*}" ;;
                    GIT_DIR | GIT_WORK_TREE | GIT_COMMON_DIR)
                        # A bare `export GIT_DIR` exports a value assigned earlier
                        # in the shell (`GIT_DIR=/x; export GIT_DIR; git push`),
                        # which this hook did not see; the push then runs in a
                        # repository it cannot name, so the directory is unknown
                        # (REQ-HARNESS-006).
                        DIR=""
                        DIR_UNKNOWN="the repository chosen by exporting ${e#"$DYN"}" ;;
                    GIT_CONFIG_COUNT=* | GIT_CONFIG_KEY_* | GIT_CONFIG_VALUE_* | GIT_CONFIG_PARAMETERS=* \
                        | GIT_CONFIG_GLOBAL=* | GIT_CONFIG_SYSTEM=* | GIT_CONFIG_NOSYSTEM=* \
                        | GIT_CONFIG_COUNT | GIT_CONFIG_PARAMETERS | GIT_CONFIG_GLOBAL | GIT_CONFIG_SYSTEM | GIT_CONFIG_NOSYSTEM)
                        # Exported, it sets git config (possibly core.hooksPath)
                        # for every command after it in the line, disabling git's
                        # own pre-push hook for a push there (REQ-HARNESS-006).
                        HOOKS_TAMPERED=1 ;;
                esac
            done
            return 0 ;;
        popd)
            case "$before:$after" in '|:'* | *':|' | *':&') return 0 ;; esac
            DIR=""
            DIR_UNKNOWN="\`popd\`"
            return 0 ;;
        git) ;;
        git-push)
            if [ "$runtime_args" = 1 ]; then
                in_hse_session && refuse "cannot tell what this push sends: xargs supplies its arguments at run time. Push named branches directly."
                return 0
            fi
            if [ "$git_config_env" = 1 ] || [ "$HOOKS_TAMPERED" = 1 ]; then
                in_hse_session && refuse "this push runs with core.hooksPath overridden (GIT_CONFIG_* in the environment, or an earlier \`git config core.hooksPath\`), which switches git's own pre-push gate off."
                return 0
            fi
            check_push "$gitdir" "$unknown" 0 "${words[@]:i+1}"
            return 0 ;;
        git-send-pack | send-pack)
            in_hse_session && refuse "\`$(shown "$w")\` pushes without running git's pre-push hook. Use \`git push\`."
            return 0 ;;
        *) return 0 ;;
    esac
    i=$((i + 1))
    local to push_config=0 hooks=0 key val cmd_aliases=()
    # git's own options come before the subcommand.
    while [ "$i" -lt "${#words[@]}" ]; do
        w="${words[i]}"
        case "$w" in
            -C)
                to="${words[i+1]:-.}"
                if is_dynamic "$to"; then
                    gitdir=""
                    unknown="$(shown "$to")"
                elif [ -n "$gitdir" ] || [ "${to#/}" != "$to" ]; then
                    gitdir="$(resolve_dir "$gitdir" "$to")"
                fi
                i=$((i + 2)) ;;
            -c | --config-env | -c?* | --config-env=*)
                if [ "$w" = -c ] || [ "$w" = --config-env ]; then
                    key="${words[i+1]:-}"
                    i=$((i + 2))
                else
                    key="${w#--config-env=}"
                    [ "$key" = "$w" ] && key="${w#-c}"
                    i=$((i + 1))
                fi
                key="$(shown "$key")"
                val="${key#*=}"
                key="${key%%=*}"
                shopt -s nocasematch
                case "$key" in
                    core.hookspath) hooks=1 ;;
                    push.default | remote.*.push | remote.*.mirror) push_config=1 ;;
                    # `-c alias.x=…` is scoped to THIS invocation, so it is
                    # command-local, not added to the persistent aliases a later
                    # `git x` would resolve (REQ-HARNESS-006).
                    alias.*) cmd_aliases+=("${key#alias.}=$val") ;;
                esac
                shopt -u nocasematch ;;
            --git-dir | --work-tree)
                gitdir=""
                unknown="the repository named by $w"
                i=$((i + 2)) ;;
            --git-dir=* | --work-tree=*)
                gitdir=""
                unknown="the repository named by ${w%%=*}"
                i=$((i + 1)) ;;
            --namespace | --attr-source | --super-prefix) i=$((i + 2)) ;;
            -*) i=$((i + 1)) ;;
            *) break ;;
        esac
    done
    local sub="${words[i]:-}"
    case "$sub" in
        push)
            if [ "$runtime_args" = 1 ]; then
                in_hse_session && refuse "cannot tell what this push sends: xargs supplies its arguments at run time. Push named branches directly."
                return 0
            fi
            if [ "$hooks" = 1 ] || [ "$git_config_env" = 1 ] || [ "$HOOKS_TAMPERED" = 1 ]; then
                in_hse_session && refuse "this push runs with core.hooksPath overridden (a \`git -c\`, GIT_CONFIG_* in the environment, or an earlier \`git config core.hooksPath\`), which switches git's own pre-push gate off."
                return 0
            fi
            check_push "$gitdir" "$unknown" "$push_config" "${words[@]:i+1}"
            return 0 ;;
        send-pack)
            in_hse_session && refuse "\`git send-pack\` pushes without running git's pre-push hook. Use \`git push\`."
            return 0 ;;
        config)
            # `git config [--global] alias.x "push …"` defines an alias this
            # command may use before any lookup could see it. And `git config
            # core.hooksPath …` (or `--unset` of it) rewrites, on disk, where
            # git looks for its pre-push hook — disabling it for a push later in
            # the same line, wherever that push sits (REQ-HARNESS-006).
            local j=$((i + 1)) cw config_readonly=0
            for cw in "${words[@]:i+1}"; do
                case "${cw#"$DYN"}" in
                    --get | --get-all | --get-regexp | --get-urlmatch | --get-color | --get-colorbool \
                        | -l | --list | --name-only | --show-origin | --show-scope) config_readonly=1 ;;
                esac
            done
            # Only a config command that *writes* disables the hook; a read-only
            # `git config --get core.hooksPath` does not (REQ-HARNESS-006).
            if [ "$config_readonly" = 0 ]; then
                for cw in "${words[@]:i+1}"; do
                    cw="${cw#"$DYN"}"
                    shopt -s nocasematch
                    [[ $cw == core.hookspath || $cw == core.hookspath=* ]] && HOOKS_TAMPERED=1
                    shopt -u nocasematch
                done
            fi
            while [[ ${words[j]:-} == -* ]]; do j=$((j + 1)); done
            case "${words[j]:-}" in
                alias.*) INLINE_ALIASES+=("${words[j]#alias.}=${words[j+1]:-}") ;;
            esac
            return 0 ;;
        '') return 0 ;;
    esac
    # A subcommand the hook cannot resolve to a literal word — assembled at run
    # time (`$(…)`, backticks, `$'…'`), or by brace expansion (`pu{sh,x}`) —
    # could be `push` spelled to slip the literal `push)` arm above. It is
    # refused, not guessed, the same as a run-time command name or refspec
    # (REQ-HARNESS-006).
    if may_be_push_subcommand "$sub"; then
        in_hse_session && refuse "cannot tell which git subcommand this runs: \`$(shown "$sub")\` is only fixed at run time (a substitution or brace expansion) and could be a push. Run \`git push\` with named branches, or from inside the checkout."
        return 0
    fi
    # Anything else may be an alias for a push: a command-local `-c alias.x`
    # first, then an alias a `git config alias.x` earlier in the line defined,
    # then the repository's own configured aliases.
    local a value=""
    for a in ${cmd_aliases[@]+"${cmd_aliases[@]}"} ${INLINE_ALIASES[@]+"${INLINE_ALIASES[@]}"}; do
        [ "${a%%=*}" = "$sub" ] && value="${a#*=}"
    done
    if [ -z "$value" ] && [ -n "$gitdir" ]; then
        value="$(git -C "$gitdir" config --get "alias.$sub" 2>/dev/null || true)"
    fi
    case "$value" in
        *push* | *send-pack*)
            in_hse_session && refuse "\`git $sub\` is an alias for \`$value\`, which pushes what the hook cannot check. Push with \`git push\` and named branches."
            ;;
    esac
}

# Lex <text> and walk every command in it. Substitutions and subshells run in
# a copy of the directory state, so a `cd` inside one changes nothing outside.
# <dir>/<unknown> give the directory the text starts in.
WALK_DEPTH=0
walk_text() { # walk_text <text> [<dir> <unknown>]
    WALK_DEPTH=$((WALK_DEPTH + 1))
    if [ "$WALK_DEPTH" -gt 8 ]; then
        in_hse_session && refuse "cannot read this command: its commands nest too deeply."
        WALK_DEPTH=$((WALK_DEPTH - 1))
        return 0
    fi
    local saved_dir="$DIR" saved_unknown="$DIR_UNKNOWN" saved_cond="$COND"
    if [ "$#" -ge 3 ]; then
        DIR="$2"
        DIR_UNKNOWN="$3"
    fi
    COND=0
    lex "$1"
    if [ "$LEX_OK" = 0 ] && in_hse_session; then
        refuse "cannot parse this command (a quote is left open, a substitution is not closed, or a heredoc never ends), so what it pushes is unknown."
    fi
    local toks=("${TOKENS[@]}")
    # words: the words read so far; base: where the current command's words
    # start in it. A substitution's body is a command list of its own, read on
    # top of the words of the command it sits in, which go on after it.
    local t opv words=() base=0 prev=';' bases=() frames=() f last
    flush() { # flush <next-op>
        if [ "${#words[@]}" -gt "$base" ]; then
            walk_command "$prev" "$1" "${words[@]:base}"
            if [ "$base" -gt 0 ]; then words=("${words[@]:0:base}"); else words=(); fi
        fi
    }
    for t in "${toks[@]}"; do
        if [ "${t:0:1}" != "$SEP" ]; then
            words+=("$t")
            continue
        fi
        opv="${t:1}"
        case "$opv" in
            'sub(' | '(')
                # A subshell's body starts a command list; anything before it
                # on the line (a function's name) is a command of its own.
                [ "$opv" = '(' ] && { flush ';'; prev=';'; }
                frames+=("$DIR$SEP$DIR_UNKNOWN$SEP$COND$SEP$prev")
                bases+=("$base")
                base="${#words[@]}"
                prev=';'
                continue ;;
            'sub)' | ')')
                flush ';'
                if [ "${#frames[@]}" -gt 0 ]; then
                    # Back to the enclosing command, in the directory it had:
                    # the body ran in a subshell.
                    last=$((${#frames[@]} - 1))
                    f="${frames[last]}"
                    base="${bases[last]}"
                    unset 'frames[last]' 'bases[last]'
                    frames=(${frames[@]+"${frames[@]}"})
                    bases=(${bases[@]+"${bases[@]}"})
                    DIR="${f%%"$SEP"*}"
                    f="${f#*"$SEP"}"
                    DIR_UNKNOWN="${f%%"$SEP"*}"
                    f="${f#*"$SEP"}"
                    COND="${f%%"$SEP"*}"
                    prev="${f#*"$SEP"}"
                else
                    # A `)` with no `(`: a case pattern. Just a separator.
                    prev=';'
                fi
                continue ;;
        esac
        [ "$opv" = nl ] && opv=';'
        flush "$opv"
        prev="$opv"
    done
    DIR="$saved_dir"
    DIR_UNKNOWN="$saved_unknown"
    COND="$saved_cond"
    WALK_DEPTH=$((WALK_DEPTH - 1))
}

walk_text "$COMMAND"

# Every hook-disabler is tied to the push it modifies while the command is
# walked: `--no-verify` and `git -c core.hooksPath` on the push itself, a
# GIT_CONFIG_* environment prefix on it, and an earlier `git config
# core.hooksPath` that persists to it (HOOKS_TAMPERED). A flat scan over every
# word once stood here; it refused harmless commands whose text merely held the
# word `push` (`git stash push`, `echo push`, a `-m push` message) next to an
# unrelated `--no-verify` on a commit (REQ-HARNESS-006).
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
