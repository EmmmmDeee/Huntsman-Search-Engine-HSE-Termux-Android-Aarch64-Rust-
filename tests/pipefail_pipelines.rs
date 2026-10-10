//! Early-exit pipelines under `pipefail`. `producer | grep -q` lets grep exit at
//! its first match; the producer then takes SIGPIPE and the pipeline reports
//! failure (141) even though the match succeeded. That made the release identity
//! check fail on a 216 KB `strings` stream, and it made the dual-pass runner miss
//! `cannot find` in a large red log. Capture the output first, or use a here-string.
//!
//! The check lexes each shell file and parses the tokens into pipelines. A grep that
//! reads a pipe and can exit early (`-q`, `--quiet`, `--silent`, `-m`, `--max-count`,
//! `-l`, `--files-with-matches`) is flagged unless `|| true` follows its pipeline. A
//! workflow is checked through its `run:` blocks only.

use std::fs;
use std::path::{Path, PathBuf};

/// Recursively collects the workflow and shell files under DIR.
fn workflow_and_script_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            workflow_and_script_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("sh" | "yml" | "yaml")
        ) {
            out.push(path);
        }
    }
}

/// Every workflow, action, and script the repository runs: `.github`, `scripts`, and
/// the shell scripts at the repository root (install.sh among them).
fn files_to_scan() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in [".github", "scripts"] {
        workflow_and_script_files(Path::new(root), &mut files);
    }
    for entry in fs::read_dir(".").expect("the repository root must be readable") {
        let path = entry.expect("readable directory entry").path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("sh") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// The shell text of a file, with its line numbers kept. A shell file is scanned as it
/// is. In a workflow only the `run:` blocks are shell, so other YAML (`value: |` text,
/// `path: |` lists) cannot hide quotes or `|` from the lexer. Other lines become empty.
fn shell_source(path: &Path, text: &str) -> String {
    if matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml" | "yaml")
    ) {
        run_blocks(text)
    } else {
        text.to_owned()
    }
}

/// The column of a `run:` key and its value, if the line has one. A `- ` list marker
/// may come before the key.
fn run_key(line: &str) -> Option<(usize, &str)> {
    let mut rest = line.trim_start();
    while let Some(after_marker) = rest.strip_prefix("- ") {
        rest = after_marker.trim_start();
    }
    let value = rest.strip_prefix("run:")?;
    Some((line.len() - rest.len(), value.trim()))
}

/// One YAML scalar in a single pair of quotes, without them. Other values are as written.
fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

/// Keeps the shell of each `run:` step, one output line per input line: an inline value
/// as written, a block scalar's content with its indentation removed, and nothing else.
fn run_blocks(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = vec![String::new(); lines.len()];
    let mut i = 0;
    while i < lines.len() {
        let Some((key_column, value)) = run_key(lines[i]) else {
            i += 1;
            continue;
        };
        if value.is_empty() || value.starts_with(['|', '>']) {
            // A block scalar: the lines indented past the key are its content.
            let mut content_indent = None;
            i += 1;
            while i < lines.len() {
                let line = lines[i];
                if line.trim().is_empty() {
                    i += 1;
                    continue;
                }
                let indent = line.len() - line.trim_start_matches(' ').len();
                if indent <= key_column {
                    break;
                }
                let base = *content_indent.get_or_insert(indent);
                line.get(base.min(indent)..)
                    .unwrap_or_default()
                    .clone_into(&mut out[i]);
                i += 1;
            }
        } else {
            unquote(value).clone_into(&mut out[i]);
            i += 1;
        }
    }
    out.join("\n")
}

/// A shell token. The lexer resolves quotes, escapes, comments, here-document bodies,
/// and the text of substitutions, so the parser sees words and operators only.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// A word with its quotes and escapes removed. `quoted` is true if any part of it
    /// was quoted.
    Word {
        text: String,
        quoted: bool,
        line: usize,
    },
    /// `|` or `|&`.
    Pipe(usize),
    /// `&&`.
    AndIf(usize),
    /// `||`.
    OrIf(usize),
    /// `;`, `&`, or a newline: the end of a command.
    Sep(usize),
    /// `;;`, which ends a case clause.
    DSemi(usize),
    /// `(`, or a `)` that closes a case pattern.
    LParen(usize),
    /// `)`, which closes a `(` group or a case pattern.
    RParen(usize),
    /// `$(`, a backtick, `<(`, or `>(`.
    OpenSubst(usize),
    /// The close of a substitution opened by `OpenSubst`.
    CloseSubst(usize),
}

impl Tok {
    fn line(&self) -> usize {
        match self {
            Tok::Word { line, .. }
            | Tok::Pipe(line)
            | Tok::AndIf(line)
            | Tok::OrIf(line)
            | Tok::Sep(line)
            | Tok::DSemi(line)
            | Tok::LParen(line)
            | Tok::RParen(line)
            | Tok::OpenSubst(line)
            | Tok::CloseSubst(line) => *line,
        }
    }
}

/// A word being read: its text so far, and where it began.
struct Pending {
    text: String,
    quoted: bool,
    line: usize,
    /// The word begins a command, so a keyword in it would be one.
    at_command: bool,
}

/// A here-document whose body starts on the line after the one that opened it.
struct Heredoc {
    delim: String,
    strip_tabs: bool,
    /// The delimiter was unquoted, so the body is expanded.
    expand: bool,
}

/// What ends a run of code.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Close {
    /// The end of the text.
    Top,
    /// A `)` that closes a `(` or `$(`.
    Paren,
    /// A backtick.
    Backtick,
}

/// Where the lexer is within a `case` statement.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Clause {
    /// After `case`, before `in`.
    Subject,
    /// After `in` or a `;;`, before a `)`. Here `|` separates alternatives.
    Pattern,
    /// After a pattern's `)`, before `;;` or `esac`.
    Body,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    toks: Vec<Tok>,
    word: Option<Pending>,
    heredocs: Vec<Heredoc>,
}

impl Lexer {
    fn new(text: &str, line: usize) -> Self {
        Self {
            chars: text.chars().collect(),
            pos: 0,
            line,
            toks: Vec::new(),
            word: None,
            heredocs: Vec::new(),
        }
    }

    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.pos + ahead).copied()
    }

    /// Consumes one character and counts lines.
    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    /// Lexes code until the close named by `close`, which it consumes.
    fn lex_code(&mut self, close: Close) {
        let mut clauses = Vec::new();
        while let Some(c) = self.peek(0) {
            if !self.code_step(c, close, &mut clauses) {
                return;
            }
        }
        self.end_word(&mut clauses);
    }

    /// Lexes one character of code. Returns false once the close has been consumed.
    fn code_step(&mut self, c: char, close: Close, clauses: &mut Vec<Clause>) -> bool {
        let line = self.line;
        match c {
            ' ' | '\t' | '\r' => {
                self.end_word(clauses);
                self.bump();
            }
            '\n' => {
                self.end_word(clauses);
                self.bump();
                self.toks.push(Tok::Sep(line));
                self.read_heredocs();
            }
            '\\' => self.escape(),
            '\'' => self.single_quoted(),
            '"' => {
                self.mark_quoted();
                self.bump();
                self.expansions(true);
            }
            '#' if self.word.is_none() => self.comment(),
            '$' => self.dollar(clauses),
            '`' if close == Close::Backtick => {
                self.end_word(clauses);
                self.bump();
                return false;
            }
            '`' => {
                self.end_word(clauses);
                self.bump();
                self.substitution(Close::Backtick);
            }
            '(' => {
                self.end_word(clauses);
                self.open_paren(clauses);
            }
            ')' => {
                self.end_word(clauses);
                return self.close_paren(close, clauses);
            }
            '|' => {
                self.end_word(clauses);
                self.pipe(clauses);
            }
            '&' => {
                self.end_word(clauses);
                self.ampersand();
            }
            ';' => {
                self.end_word(clauses);
                self.semicolon(clauses);
            }
            '<' | '>' => {
                self.end_word(clauses);
                self.redirect();
            }
            _ => {
                self.add(c, false);
                self.bump();
            }
        }
        true
    }

    /// Ends the word in progress. Keywords move the `case` state: `case` opens a
    /// statement, `in` starts its patterns, and `esac` closes it.
    fn end_word(&mut self, clauses: &mut Vec<Clause>) {
        if let Some(word) = self.word.as_ref().filter(|word| !word.quoted) {
            match word.text.as_str() {
                "case" if word.at_command => clauses.push(Clause::Subject),
                "in" => {
                    if let Some(top) = clauses.last_mut().filter(|top| **top == Clause::Subject) {
                        *top = Clause::Pattern;
                    }
                }
                "esac" => {
                    let closes = matches!(clauses.last(), Some(Clause::Pattern))
                        || (word.at_command && clauses.last() == Some(&Clause::Body));
                    if closes {
                        clauses.pop();
                    }
                }
                _ => {}
            }
        }
        self.flush_word();
    }

    fn flush_word(&mut self) {
        if let Some(word) = self.word.take() {
            self.toks.push(Tok::Word {
                text: word.text,
                quoted: word.quoted,
                line: word.line,
            });
        }
    }

    /// True when the next word would begin a command.
    fn at_command_start(&self) -> bool {
        match self.toks.last() {
            None
            | Some(
                Tok::Sep(_)
                | Tok::AndIf(_)
                | Tok::OrIf(_)
                | Tok::Pipe(_)
                | Tok::LParen(_)
                | Tok::RParen(_)
                | Tok::OpenSubst(_)
                | Tok::DSemi(_),
            ) => true,
            Some(Tok::Word {
                text,
                quoted: false,
                ..
            }) => matches!(
                text.as_str(),
                "then" | "do" | "else" | "elif" | "if" | "while" | "until" | "!" | "time" | "{"
            ),
            Some(_) => false,
        }
    }

    fn word_mut(&mut self) -> &mut Pending {
        let at_command = self.at_command_start();
        let line = self.line;
        self.word.get_or_insert_with(|| Pending {
            text: String::new(),
            quoted: false,
            line,
            at_command,
        })
    }

    fn add(&mut self, c: char, quoted: bool) {
        let word = self.word_mut();
        word.text.push(c);
        word.quoted |= quoted;
    }

    fn mark_quoted(&mut self) {
        self.word_mut().quoted = true;
    }

    /// Keeps a character of a double-quoted string. Here-document text is not kept.
    fn keep(&mut self, c: char, quoted: bool) {
        if quoted {
            self.add(c, true);
        }
    }

    fn single_quoted(&mut self) {
        self.mark_quoted();
        self.bump();
        while let Some(c) = self.bump() {
            if c == '\'' {
                break;
            }
            self.add(c, true);
        }
    }

    /// `$'...'`: the quote is the next character, and backslash escapes apply.
    fn ansi_c(&mut self) {
        self.mark_quoted();
        self.bump();
        while let Some(c) = self.bump() {
            match c {
                '\'' => break,
                '\\' => {
                    if let Some(next) = self.bump() {
                        self.add(next, true);
                    }
                }
                _ => self.add(c, true),
            }
        }
    }

    /// Reads a double-quoted string after its opening quote. With `quoted` false it
    /// reads the body of an unquoted here-document instead. Either way, substitutions
    /// are lexed as code.
    fn expansions(&mut self, quoted: bool) {
        while let Some(c) = self.peek(0) {
            match c {
                '"' if quoted => {
                    self.bump();
                    return;
                }
                '\\' => match self.peek(1) {
                    Some(next @ ('$' | '`' | '"' | '\\')) => {
                        self.bump();
                        self.bump();
                        self.keep(next, quoted);
                    }
                    Some('\n') => {
                        self.bump();
                        self.bump();
                    }
                    _ => {
                        self.bump();
                        self.keep('\\', quoted);
                    }
                },
                '$' if self.peek(1) == Some('(') => {
                    self.flush_word();
                    self.bump();
                    self.bump();
                    self.substitution(Close::Paren);
                }
                '`' => {
                    self.flush_word();
                    self.bump();
                    self.substitution(Close::Backtick);
                }
                _ => {
                    self.bump();
                    self.keep(c, quoted);
                }
            }
        }
    }

    /// Lexes the code of a substitution whose opener has been consumed.
    fn substitution(&mut self, close: Close) {
        let line = self.line;
        self.toks.push(Tok::OpenSubst(line));
        self.lex_code(close);
        self.toks.push(Tok::CloseSubst(line));
    }

    /// A backslash outside quotes: a line continuation, or an escaped character.
    fn escape(&mut self) {
        match self.peek(1) {
            Some('\n') => {
                self.bump();
                self.bump();
            }
            Some(next) => {
                self.bump();
                self.bump();
                self.add(next, true);
            }
            None => {
                self.bump();
            }
        }
    }

    /// A `#` that starts a word runs to the end of the line.
    fn comment(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.pos += 1;
        }
    }

    fn dollar(&mut self, clauses: &mut Vec<Clause>) {
        match self.peek(1) {
            Some('(') => {
                self.end_word(clauses);
                self.pos += 2;
                self.substitution(Close::Paren);
            }
            Some('\'') => {
                self.bump();
                self.ansi_c();
            }
            // `$"..."` is an ordinary double-quoted string; the quote is lexed next.
            Some('"') => {
                self.bump();
            }
            _ => {
                self.add('$', false);
                self.bump();
            }
        }
    }

    fn open_paren(&mut self, clauses: &[Clause]) {
        let line = self.line;
        self.bump();
        if clauses.last() == Some(&Clause::Pattern) {
            // The optional `(` before a case pattern.
            return;
        }
        self.toks.push(Tok::LParen(line));
        self.lex_code(Close::Paren);
        self.toks.push(Tok::RParen(line));
    }

    /// A `)` ends a case pattern, or else the group that `close` names, or it stands
    /// alone. Returns false when it closed the group.
    fn close_paren(&mut self, close: Close, clauses: &mut [Clause]) -> bool {
        let line = self.line;
        self.bump();
        if let Some(top) = clauses.last_mut().filter(|top| **top == Clause::Pattern) {
            *top = Clause::Body;
            self.toks.push(Tok::RParen(line));
            return true;
        }
        if close == Close::Paren {
            return false;
        }
        self.toks.push(Tok::RParen(line));
        true
    }

    fn pipe(&mut self, clauses: &[Clause]) {
        let line = self.line;
        if clauses.last() == Some(&Clause::Pattern) {
            // `|` separates case alternatives here, not a pipeline.
            self.bump();
            return;
        }
        match self.peek(1) {
            Some('|') => {
                self.pos += 2;
                self.toks.push(Tok::OrIf(line));
            }
            Some('&') => {
                self.pos += 2;
                self.toks.push(Tok::Pipe(line));
            }
            _ => {
                self.bump();
                self.toks.push(Tok::Pipe(line));
            }
        }
    }

    /// `&&`, or `&` ending a command. `&>` is a redirection.
    fn ampersand(&mut self) {
        let line = self.line;
        match self.peek(1) {
            Some('&') => {
                self.pos += 2;
                self.toks.push(Tok::AndIf(line));
            }
            Some('>') => self.pos += 2,
            _ => {
                self.bump();
                self.toks.push(Tok::Sep(line));
            }
        }
    }

    fn semicolon(&mut self, clauses: &mut [Clause]) {
        let line = self.line;
        if matches!(self.peek(1), Some(';' | '&')) {
            self.pos += 2;
            self.toks.push(Tok::DSemi(line));
            if let Some(top) = clauses.last_mut().filter(|top| **top == Clause::Body) {
                *top = Clause::Pattern;
            }
        } else {
            self.bump();
            self.toks.push(Tok::Sep(line));
        }
    }

    /// A redirection, a here-string, a here-document, or a process substitution.
    fn redirect(&mut self) {
        if self.peek(0) == Some('<') && self.peek(1) == Some('<') {
            if self.peek(2) == Some('<') {
                self.pos += 3;
            } else {
                self.heredoc_operator();
            }
        } else if self.peek(1) == Some('(') {
            self.pos += 2;
            self.substitution(Close::Paren);
        } else {
            self.bump();
            if matches!(self.peek(0), Some('>' | '|' | '&')) {
                self.bump();
            }
        }
    }

    /// The `<<` of a here-document. Its delimiter is read now, and its body starts on the
    /// line after this one.
    fn heredoc_operator(&mut self) {
        self.pos += 2;
        let strip_tabs = self.peek(0) == Some('-');
        if strip_tabs {
            self.pos += 1;
        }
        while matches!(self.peek(0), Some(' ' | '\t')) {
            self.pos += 1;
        }
        let (delim, quoted) = self.delimiter();
        self.heredocs.push(Heredoc {
            delim,
            strip_tabs,
            expand: !quoted,
        });
    }

    /// Reads a here-document delimiter with its quotes removed. `quoted` is true if any
    /// part of it was quoted, which makes the body literal.
    fn delimiter(&mut self) -> (String, bool) {
        let mut text = String::new();
        let mut quoted = false;
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>' => break,
                '\'' | '"' => {
                    quoted = true;
                    self.bump();
                    while let Some(inner) = self.bump() {
                        if inner == c {
                            break;
                        }
                        text.push(inner);
                    }
                }
                '\\' => {
                    quoted = true;
                    self.bump();
                    if let Some(next) = self.bump() {
                        text.push(next);
                    }
                }
                _ => {
                    text.push(c);
                    self.bump();
                }
            }
        }
        (text, quoted)
    }

    /// Consumes the bodies of the here-documents opened on the line that just ended.
    /// An unquoted body is lexed for its substitutions.
    fn read_heredocs(&mut self) {
        for heredoc in std::mem::take(&mut self.heredocs) {
            let start = self.line;
            let mut body = Vec::new();
            while self.peek(0).is_some() {
                let line = self.take_line();
                let ends = if heredoc.strip_tabs {
                    line.trim_start_matches('\t') == heredoc.delim.as_str()
                } else {
                    line == heredoc.delim
                };
                if ends {
                    break;
                }
                body.push(line);
            }
            if heredoc.expand {
                let mut inner = Lexer::new(&body.join("\n"), start);
                inner.expansions(false);
                self.toks.extend(inner.toks);
            }
        }
    }

    /// Consumes one line, without its newline, and returns its text.
    fn take_line(&mut self) -> String {
        let mut text = String::new();
        while let Some(c) = self.bump() {
            if c == '\n' {
                break;
            }
            text.push(c);
        }
        text
    }
}

/// Lexes shell text into tokens.
fn lex(text: &str) -> Vec<Tok> {
    let mut lexer = Lexer::new(text, 1);
    lexer.lex_code(Close::Top);
    lexer.toks
}

/// A pipeline: the lines it starts and ends on, and whether `|| true` follows it.
struct Pipeline {
    start: usize,
    end: usize,
    guarded: bool,
}

/// A simple command: its words, and the pipeline whose pipe feeds it, if any.
struct Command {
    words: Vec<String>,
    piped_in: Option<usize>,
}

/// The token that ends the list being parsed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Until {
    /// The end of the text.
    Top,
    /// A `)` that closes a subshell.
    Paren,
    /// The close of a substitution.
    Subst,
    /// A `}` that closes a brace group.
    Brace,
    /// A closing keyword, such as `fi` or `done`.
    Keyword(&'static str),
    /// The `;;` or `esac` that ends a case clause. Neither is consumed.
    CaseBody,
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    pipelines: Vec<Pipeline>,
    commands: Vec<Command>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Tok> {
        self.toks.get(self.pos)
    }

    /// The unquoted word at the cursor, if there is one.
    fn keyword(&self) -> Option<&'a str> {
        match self.peek()? {
            Tok::Word {
                text,
                quoted: false,
                ..
            } => Some(text.as_str()),
            _ => None,
        }
    }

    fn at_word(&self, word: &str) -> bool {
        self.keyword() == Some(word)
    }

    fn at_end(&self, until: Until) -> bool {
        match until {
            Until::Top => false,
            Until::Paren => matches!(self.peek(), Some(Tok::RParen(_))),
            Until::Subst => matches!(self.peek(), Some(Tok::CloseSubst(_))),
            Until::Brace => self.at_word("}"),
            Until::Keyword(word) => self.at_word(word),
            Until::CaseBody => matches!(self.peek(), Some(Tok::DSemi(_))) || self.at_word("esac"),
        }
    }

    fn line_here(&self) -> usize {
        self.toks
            .get(self.pos)
            .or_else(|| self.toks.last())
            .map_or(0, Tok::line)
    }

    fn line_before(&self) -> usize {
        self.pos
            .checked_sub(1)
            .and_then(|i| self.toks.get(i))
            .map_or(0, Tok::line)
    }

    /// Parses commands until `until` ends the list. A closer is consumed.
    fn parse_list(&mut self, piped: Option<usize>, until: Until) {
        while let Some(tok) = self.peek() {
            if self.at_end(until) {
                if until != Until::CaseBody {
                    self.pos += 1;
                }
                return;
            }
            match tok {
                Tok::Sep(_)
                | Tok::Pipe(_)
                | Tok::AndIf(_)
                | Tok::OrIf(_)
                | Tok::DSemi(_)
                | Tok::RParen(_)
                | Tok::CloseSubst(_) => self.pos += 1,
                Tok::Word {
                    text,
                    quoted: false,
                    ..
                } if matches!(text.as_str(), "then" | "do" | "else" | "elif") => self.pos += 1,
                _ => {
                    let before = self.pos;
                    self.parse_andor(piped);
                    if self.pos == before {
                        // No rule accepted this token. Skip it, so the loop always ends.
                        self.pos += 1;
                    }
                }
            }
        }
    }

    /// Skips the newlines that may follow an operator such as `|` or `&&`.
    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Some(Tok::Sep(_))) {
            self.pos += 1;
        }
    }

    fn parse_andor(&mut self, piped: Option<usize>) {
        let mut last = self.parse_pipeline(piped);
        loop {
            match self.peek() {
                Some(Tok::AndIf(_)) => {
                    self.pos += 1;
                    self.skip_newlines();
                    last = self.parse_pipeline(piped);
                }
                Some(Tok::OrIf(_)) => {
                    self.pos += 1;
                    if self.at_word("true") {
                        self.pipelines[last].guarded = true;
                    }
                    self.skip_newlines();
                    last = self.parse_pipeline(piped);
                }
                _ => return,
            }
        }
    }

    /// Parses stages joined by pipes. `piped` is the pipe that feeds the first stage, if
    /// this pipeline sits inside a stage that reads one.
    fn parse_pipeline(&mut self, piped: Option<usize>) -> usize {
        let id = self.pipelines.len();
        let start = self.line_here();
        self.pipelines.push(Pipeline {
            start,
            end: start,
            guarded: false,
        });
        self.parse_stage(piped);
        while matches!(self.peek(), Some(Tok::Pipe(_))) {
            self.pos += 1;
            self.skip_newlines();
            self.parse_stage(Some(id));
        }
        self.pipelines[id].end = self.line_before();
        id
    }

    /// One stage of a pipeline: a simple command, or a compound command whose commands
    /// all read the pipe when it is `piped`.
    fn parse_stage(&mut self, piped: Option<usize>) {
        while self.at_word("!") {
            self.pos += 1;
        }
        match self.keyword() {
            Some("{") => self.group(piped, Until::Brace),
            Some("if") => self.group(piped, Until::Keyword("fi")),
            Some("while" | "until" | "for") => self.group(piped, Until::Keyword("done")),
            Some("case") => self.parse_case(piped),
            Some("function") => {
                // `function name [()] body`
                self.pos += 2;
                if matches!(self.peek(), Some(Tok::LParen(_))) {
                    self.pos += 2;
                }
                self.parse_stage(piped);
            }
            Some(_) => self.parse_simple(piped),
            None => match self.peek() {
                Some(Tok::LParen(_)) => self.group(piped, Until::Paren),
                Some(_) if self.function_header() => {
                    // `name() body`
                    self.pos += 3;
                    self.parse_stage(piped);
                }
                _ => self.parse_simple(piped),
            },
        }
    }

    /// A group or compound command: its opener is consumed, then its body up to `until`.
    fn group(&mut self, piped: Option<usize>, until: Until) {
        self.pos += 1;
        self.parse_list(piped, until);
        self.skip_redirects();
    }

    /// `name ( )`, the start of a function definition.
    fn function_header(&self) -> bool {
        matches!(
            self.toks.get(self.pos..self.pos + 3),
            Some([Tok::Word { .. }, Tok::LParen(_), Tok::RParen(_)])
        )
    }

    /// Skips the words and redirections that trail a compound command, such as the
    /// `< <(...)` after `done`.
    fn skip_redirects(&mut self) {
        loop {
            match self.peek() {
                Some(Tok::Word { .. }) => self.pos += 1,
                Some(Tok::OpenSubst(_)) => self.parse_subst(),
                _ => return,
            }
        }
    }

    /// A substitution is a separate script. Its stdin is not the enclosing pipe.
    fn parse_subst(&mut self) {
        self.pos += 1;
        self.parse_list(None, Until::Subst);
    }

    /// A `case` statement. Its patterns are not commands, and `|` between them is not a
    /// pipe. Each clause body is a list of commands.
    fn parse_case(&mut self, piped: Option<usize>) {
        self.pos += 1;
        loop {
            match self.peek() {
                Some(Tok::OpenSubst(_)) => self.parse_subst(),
                Some(Tok::Word { .. }) => {
                    let subject_done = self.at_word("in");
                    self.pos += 1;
                    if subject_done {
                        break;
                    }
                }
                _ => return,
            }
        }
        loop {
            while matches!(self.peek(), Some(Tok::Sep(_))) {
                self.pos += 1;
            }
            if self.at_word("esac") {
                self.pos += 1;
                return;
            }
            if self.peek().is_none() {
                return;
            }
            loop {
                match self.peek() {
                    None => return,
                    Some(Tok::RParen(_)) => {
                        self.pos += 1;
                        break;
                    }
                    Some(Tok::OpenSubst(_)) => self.parse_subst(),
                    Some(_) => self.pos += 1,
                }
            }
            self.parse_list(piped, Until::CaseBody);
            if matches!(self.peek(), Some(Tok::DSemi(_))) {
                self.pos += 1;
            }
        }
    }

    /// A simple command: its words, with any substitutions in them parsed as separate
    /// scripts.
    fn parse_simple(&mut self, piped: Option<usize>) {
        let mut words = Vec::new();
        loop {
            match self.peek() {
                Some(Tok::Word { text, .. }) => {
                    words.push(text.clone());
                    self.pos += 1;
                }
                Some(Tok::OpenSubst(_)) => self.parse_subst(),
                _ => break,
            }
        }
        if !words.is_empty() {
            self.commands.push(Command {
                words,
                piped_in: piped,
            });
        }
    }
}

/// A pipeline the detector flags, by the lines it spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Flagged {
    start: usize,
    end: usize,
}

/// The pipelines in `text` that feed an early-exit grep and have no `|| true` guard.
fn flagged_pipelines(text: &str) -> Vec<Flagged> {
    let toks = lex(text);
    let mut parser = Parser {
        toks: &toks,
        pos: 0,
        pipelines: Vec::new(),
        commands: Vec::new(),
    };
    parser.parse_list(None, Until::Top);
    let mut flagged: Vec<Flagged> = parser
        .commands
        .iter()
        .filter(|command| is_quiet_grep(&command.words))
        .filter_map(|command| command.piped_in)
        .map(|id| &parser.pipelines[id])
        .filter(|pipeline| !pipeline.guarded)
        .map(|pipeline| Flagged {
            start: pipeline.start,
            end: pipeline.end,
        })
        .collect();
    flagged.sort();
    flagged.dedup();
    flagged
}

/// True when `text` has a pipeline into an early-exit grep without a `|| true` guard.
/// Comment lines never count.
fn pipes_into_grep_quiet(text: &str) -> bool {
    !flagged_pipelines(text).is_empty()
}

/// The start line of each pipeline in `text` that is flagged.
fn flagged_lines(text: &str) -> Vec<usize> {
    flagged_pipelines(text)
        .iter()
        .map(|flagged| flagged.start)
        .collect()
}

/// The source lines a flagged pipeline spans, trimmed and joined, for the failure message.
fn span_text(source: &str, flagged: Flagged) -> String {
    source
        .lines()
        .skip(flagged.start.saturating_sub(1))
        .take(flagged.end.saturating_sub(flagged.start) + 1)
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `NAME=value`, `NAME+=value`, or `NAME[index]=value`.
fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let base = name.split('[').next().unwrap_or_default();
    let mut chars = base.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// How many leading words are options: `-x`, `--long`, and the values of the options in
/// `with_value`. A `--` ends the options and is counted with them.
fn skip_options(words: &[String], with_value: &[&str]) -> usize {
    let mut used = 0;
    while let Some(word) = words.get(used) {
        let word = word.as_str();
        if word == "--" {
            return used + 1;
        }
        if with_value.contains(&word) {
            used += 2;
        } else if word.len() > 1 && word.starts_with('-') {
            used += 1;
        } else {
            break;
        }
    }
    used
}

/// The program a simple command runs, and its arguments. Keywords, assignments, and
/// wrappers that run another program (`env`, `sudo`, `timeout`, and so on) are skipped,
/// and a path such as `/usr/bin/grep` is reduced to its last part.
fn command_of(words: &[String]) -> Option<(&str, &[String])> {
    let mut i = 0;
    while let Some(word) = words.get(i) {
        let name = word.rsplit('/').next().unwrap_or(word);
        i += 1;
        let skipped = match name {
            _ if is_assignment(word) => 0,
            "!" | "then" | "do" | "else" | "elif" | "if" | "while" | "until" | "{" => 0,
            "builtin" | "command" | "exec" | "nohup" | "time" => skip_options(&words[i..], &[]),
            "env" => skip_options(&words[i..], &["-u", "-C", "-S"]),
            "nice" => skip_options(&words[i..], &["-n"]),
            "sudo" => skip_options(
                &words[i..],
                &["-C", "-D", "-g", "-h", "-p", "-r", "-t", "-T", "-u", "-U"],
            ),
            // The duration follows the options of `timeout`.
            "timeout" => skip_options(&words[i..], &["-k", "-s"]) + 1,
            _ => return Some((name, &words[i..])),
        };
        i = (i + skipped).min(words.len());
    }
    None
}

/// True when grep's arguments include an option that lets it stop early: `-q`,
/// `--quiet`, `--silent`, `-m`, `--max-count`, `-l`, or `--files-with-matches`. The
/// value of an option such as `-e PATTERN` or `-A 2` is not an option.
fn has_early_exit_flag(args: &[String]) -> bool {
    let mut early = false;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let arg = arg.as_str();
        i += 1;
        if arg == "--" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, has_value) = match long.split_once('=') {
                Some((name, _)) => (name, true),
                None => (long, false),
            };
            match name {
                "quiet" | "silent" | "files-with-matches" => early = true,
                "max-count" => {
                    early = true;
                    if !has_value {
                        i += 1;
                    }
                }
                "regexp" | "file" | "label" | "after-context" | "before-context" | "context"
                | "binary-files" | "devices" | "directories" | "exclude" | "exclude-from"
                | "exclude-dir" | "include" | "group-separator"
                    if !has_value =>
                {
                    i += 1;
                }
                _ => {}
            }
        } else if let Some(shorts) = arg.strip_prefix('-').filter(|s| !s.is_empty()) {
            for (offset, flag) in shorts.char_indices() {
                if matches!(flag, 'q' | 'l' | 'm') {
                    early = true;
                }
                if matches!(flag, 'm' | 'e' | 'f' | 'A' | 'B' | 'C' | 'd' | 'D') {
                    // The rest of this word is the value, or else the next word is.
                    if offset + flag.len_utf8() == shorts.len() {
                        i += 1;
                    }
                    break;
                }
            }
        }
    }
    early
}

/// True when the command is grep, egrep, or fgrep with an early-exit option.
fn is_quiet_grep(words: &[String]) -> bool {
    command_of(words).is_some_and(|(name, args)| {
        matches!(name, "grep" | "egrep" | "fgrep") && has_early_exit_flag(args)
    })
}

#[test]
fn detector_flags_quiet_grep_pipes_and_nothing_else() {
    assert!(pipes_into_grep_quiet("strings -a x | grep -Fq \"$SHA\""));
    assert!(pipes_into_grep_quiet(
        "  printf '%s' \"$log\" | grep -q 'cannot find'; then"
    ));
    assert!(pipes_into_grep_quiet("a | grep -qx y"));
    assert!(pipes_into_grep_quiet("a | egrep -q y"));
    assert!(pipes_into_grep_quiet("a | fgrep -Fq y"));
    assert!(pipes_into_grep_quiet("a | grep 'x' -q"));
    assert!(pipes_into_grep_quiet("a | grep --quiet x"));
    assert!(pipes_into_grep_quiet("a | command grep -q x"));
    assert!(pipes_into_grep_quiet("a |& grep -q x"));
    assert!(!pipes_into_grep_quiet("grep -q 'cannot find' <<< \"$log\""));
    assert!(!pipes_into_grep_quiet(
        "usage=\"$(strings x | grep -o -m1 y || true)\""
    ));
    assert!(!pipes_into_grep_quiet("cmd | grep -e queue"));
    assert!(!pipes_into_grep_quiet("# readelf | grep -q is the hazard"));
    assert!(!pipes_into_grep_quiet("a || b"));
    assert!(!pipes_into_grep_quiet(
        "if grep -q 'x' \"$f\" || grep -q 'y' \"$f\"; then"
    ));
}

#[test]
fn a_pipe_continued_on_the_next_line_is_one_pipeline() {
    let text = "if curl --fail --silent \"$url\" |\n  grep -q '\"status\"'; then\n  :\nfi\n";
    assert_eq!(flagged_lines(text), [1], "the pipeline starts on line 1");
}

#[test]
fn keyword_led_consumers_are_flagged() {
    let text = "printf '%s' \"$log\" |\n  if grep -q 'cannot find'; then\n  :\nfi\n";
    assert_eq!(
        flagged_lines(text),
        [1],
        "if before grep, on the line after the pipe"
    );
    assert!(pipes_into_grep_quiet("a | while grep -q x; do :; done"));
    assert!(pipes_into_grep_quiet("a | { grep -q x; }"));
    assert!(pipes_into_grep_quiet("a | ( grep -q x )"));
    assert!(pipes_into_grep_quiet("a | if grep -q x; then :; fi"));
}

#[test]
fn wrapped_consumers_are_flagged() {
    assert!(pipes_into_grep_quiet("a | LC_ALL=C grep -q x"));
    assert!(pipes_into_grep_quiet("a | timeout 10 grep -q x"));
    assert!(pipes_into_grep_quiet("a | sudo grep -q x"));
    assert!(pipes_into_grep_quiet("a | /usr/bin/grep -q x"));
    assert!(pipes_into_grep_quiet("a | env -i LC_ALL=C grep -q x"));
    assert!(pipes_into_grep_quiet("a | nice -n 5 command grep -q x"));
    assert!(pipes_into_grep_quiet("a | time -p grep -q x"));
}

#[test]
fn a_pipe_continued_past_blank_and_comment_lines_is_one_pipeline() {
    let comment = "if curl -fsS \"$url\" |\n  # wait for the status field\n  grep -q '\"status\"'; then\n  :\nfi\n";
    assert_eq!(
        flagged_lines(comment),
        [1],
        "comment line between pipe and consumer"
    );
    assert_eq!(
        flagged_lines("a |\n\n  grep -q x\n"),
        [1],
        "blank line between pipe and consumer"
    );
    assert_eq!(
        flagged_lines("a | # note\n  grep -q x\n"),
        [1],
        "comment after the pipe"
    );
}

#[test]
fn a_pipe_inside_quotes_is_not_a_command_boundary() {
    assert!(pipes_into_grep_quiet(
        "found=\"$(strings -a x | grep -E 'ok|done' -q)\""
    ));
    assert!(!pipes_into_grep_quiet("cmd | grep -E 'a|grep -q b'"));
}

#[test]
fn max_count_and_files_with_matches_are_early_exits() {
    assert!(pipes_into_grep_quiet(
        "found=\"$(strings -a -n 8 \"dist/$ASSET\" | grep -m1 'usage: huntsman-recon')\""
    ));
    assert!(pipes_into_grep_quiet("a | grep -l x"));
    assert!(pipes_into_grep_quiet("a | grep --max-count=1 x"));
    assert!(pipes_into_grep_quiet("a | grep --files-with-matches x"));
    assert!(pipes_into_grep_quiet("a | grep -m 1 x"));
}

#[test]
fn an_early_exit_grep_needs_a_true_guard_right_after_it() {
    assert!(!pipes_into_grep_quiet(
        "usage=\"$(strings x | grep -o -m1 y || true)\""
    ));
    assert!(!pipes_into_grep_quiet("a | grep -q x || true"));
    assert!(pipes_into_grep_quiet("a | grep -m1 x || echo none"));
    assert!(pipes_into_grep_quiet("a | grep -q x || echo fallback"));
}

#[test]
fn a_pattern_after_e_is_not_a_quiet_flag() {
    assert!(!pipes_into_grep_quiet("a | grep -e -q"));
}

#[test]
fn a_here_document_body_is_data_and_its_quotes_do_not_leak() {
    let text = "cat <<'PY'\nprint(\"it's a | grep -q b\")\nPY\nlog | grep -q y\n";
    assert_eq!(flagged_lines(text), [4], "only the pipeline after the body");
    assert!(!pipes_into_grep_quiet("cat <<'PY'\nx | grep -q y\nPY\n"));
}

#[test]
fn a_here_document_on_a_piped_line_is_checked_inside_its_substitution() {
    let text = "out=\"$(python3 - <<'PY' | grep -q y\nprint(1)\nPY\n)\"\n";
    assert_eq!(flagged_lines(text), [1]);
}

#[test]
fn a_substitution_in_an_unquoted_here_document_body_is_checked() {
    assert_eq!(flagged_lines("cat <<EOF\n$(a | grep -q y)\nEOF\n"), [2]);
}

#[test]
fn substitutions_backticks_and_process_substitutions_are_checked() {
    assert!(pipes_into_grep_quiet("x=\"$(a | grep -q y)\""));
    assert!(pipes_into_grep_quiet("x=`a | grep -q y`"));
    assert!(!pipes_into_grep_quiet("x=`a | grep -q y || true`"));
    assert!(pipes_into_grep_quiet(
        "while read -r l; do :; done < <(a | grep -q y)"
    ));
}

#[test]
fn comments_escapes_and_line_continuations_shape_pipelines() {
    assert!(!pipes_into_grep_quiet("echo ok # | grep -q x"));
    assert!(pipes_into_grep_quiet("echo \"a # b\" | grep -q x"));
    assert!(!pipes_into_grep_quiet("echo a\\| grep -q x"));
    assert_eq!(flagged_lines("a \\\n  | grep -q x\n"), [1]);
}

#[test]
fn a_guard_covers_the_whole_pipeline_and_a_producer_is_not_a_consumer() {
    assert!(!pipes_into_grep_quiet("a | b | grep -q x || true"));
    assert!(!pipes_into_grep_quiet("grep -q x file | cat"));
    assert_eq!(flagged_lines("a | { echo x; grep -q y; }\n"), [1]);
    assert!(!pipes_into_grep_quiet("a | { echo x; }"));
}

#[test]
fn the_innermost_pipeline_owns_its_consumer() {
    assert!(!pipes_into_grep_quiet("a | { b | grep -q y || true; }"));
    assert!(pipes_into_grep_quiet("a | { b | grep -q y; }"));
}

#[test]
fn a_yaml_workflow_is_checked_through_its_run_blocks() {
    let yaml = "steps:\n  - name: Check\n    run: |\n      if grep -q x y; then\n        :\n      fi\n    with:\n      value: |\n        a | grep -q b\n  - run: cargo test | grep -q c\n";
    let shell = shell_source(Path::new("ci.yml"), yaml);
    assert_eq!(flagged_lines(&shell), [10]);
}

#[test]
fn a_run_block_heredoc_ends_at_its_dedented_delimiter() {
    let yaml = "jobs:\n  x:\n    steps:\n      - run: |\n          cat > notes.md <<NOTES\n          a | grep -q b\n          NOTES\n          x | grep -q y\n";
    let shell = shell_source(Path::new("ci.yml"), yaml);
    assert_eq!(flagged_lines(&shell), [8]);
}

#[test]
fn no_pipeline_feeds_grep_quiet_under_pipefail() {
    let files = files_to_scan();
    assert!(
        files.iter().any(|f| f.starts_with(".github"))
            && files.iter().any(|f| f.starts_with("scripts")),
        "the workflow and script roots must contain files"
    );

    let mut hits = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("readable workflow or script");
        let source = shell_source(file, &text);
        for flagged in flagged_pipelines(&source) {
            hits.push(format!(
                "{}:{}: {}",
                file.display(),
                flagged.start,
                span_text(&source, flagged)
            ));
        }
    }
    assert!(
        hits.is_empty(),
        "producer | grep -q can report SIGPIPE under pipefail; capture the output or use a here-string:\n{}",
        hits.join("\n")
    );
}
