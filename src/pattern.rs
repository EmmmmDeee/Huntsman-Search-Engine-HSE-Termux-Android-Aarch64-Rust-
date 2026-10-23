//! Regular expressions for correlation rules, matched in linear time.
//!
//! The syntax is the part of Python's `re` that Spiderfoot's correlation rules use, and most
//! hand-written rules: literals, `.`, classes (`[a-z0-9\.\-]`, `[^...]`), `\d \w \s` and their
//! negations, `\b \B`, `^ $` (`$` also before a final newline), `\A \Z` (`\Z` the very end only),
//! groups (`(...)`, `(?:...)`, `(?P<name>...)`), alternation, and the quantifiers
//! `* + ? {n} {n,} {n,m} {,m} {,}` (an omitted lower bound is 0; a trailing `?` for laziness is
//! accepted; it cannot change whether a pattern matches). [`Pattern::is_match`] searches anywhere
//! in the text, as `re.search` does. A pattern compiles to at most [`MAX_PROGRAM`] instructions,
//! in time bounded by its length plus that, and groups nest at most 64 deep; a larger one is
//! refused. Matching runs a Pike VM over the compiled program, so its time is bounded by the text
//! length times the program size and a rule cannot stall a scan however it is written.
//! Backreferences and lookaround are refused rather than approximated.

use thiserror::Error;

/// The most instructions one pattern compiles to, a class counting once per item in it; counted
/// repetition is expanded, so `(a{1000}){1000}` and `[a-z0-9]{10000}` are refused here instead
/// of taking memory.
pub const MAX_PROGRAM: usize = 20_000;

/// Groups nested deeper than this are refused, so a hostile pattern cannot exhaust the stack.
const MAX_DEPTH: usize = 64;

/// Why a pattern could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("pattern {pattern:?}: {reason} at character {offset}")]
pub struct PatternError {
    pub pattern: String,
    pub offset: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Perl {
    Digit,
    Word,
    Space,
}

impl Perl {
    fn matches(self, c: char) -> bool {
        match self {
            Self::Digit => c.is_numeric(),
            Self::Word => c.is_alphanumeric() || c == '_',
            Self::Space => c.is_whitespace(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassItem {
    Range(char, char),
    Perl(Perl, bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Class {
    items: Vec<ClassItem>,
    negated: bool,
}

impl Class {
    fn matches(&self, c: char, ignore_case: bool) -> bool {
        let hit = |c: char| {
            self.items.iter().any(|item| match item {
                ClassItem::Range(low, high) => (*low..=*high).contains(&c),
                ClassItem::Perl(kind, negated) => kind.matches(c) != *negated,
            })
        };
        let found = hit(c) || (ignore_case && (hit(lower(c)) || hit(upper(c))));
        found != self.negated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assertion {
    Start,
    End,
    AbsoluteEnd,
    WordBoundary,
    NotWordBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Empty,
    Char(char),
    Any,
    Class(Class),
    Assert(Assertion),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Inst {
    Char(char),
    Any,
    Class(Class),
    Assert(Assertion),
    Split(usize, usize),
    Jmp(usize),
    Match,
}

fn lower(c: char) -> char {
    let mut folded = c.to_lowercase();
    match (folded.next(), folded.next()) {
        (Some(one), None) => one,
        _ => c,
    }
}

fn upper(c: char) -> char {
    let mut folded = c.to_uppercase();
    match (folded.next(), folded.next()) {
        (Some(one), None) => one,
        _ => c,
    }
}

struct Parser<'a> {
    source: &'a str,
    chars: Vec<char>,
    pos: usize,
    ignore_case: bool,
    /// Groups open around the current position.
    depth: usize,
}

impl Parser<'_> {
    fn fail<T>(&self, reason: &str) -> Result<T, PatternError> {
        Err(PatternError {
            pattern: self.source.to_owned(),
            offset: self.pos,
            reason: reason.to_owned(),
        })
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn alternation(&mut self) -> Result<Node, PatternError> {
        let mut branches = vec![self.concat()?];
        while self.eat('|') {
            branches.push(self.concat()?);
        }
        Ok(if branches.len() == 1 {
            branches.remove(0)
        } else {
            Node::Alt(branches)
        })
    }

    fn concat(&mut self) -> Result<Node, PatternError> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.quantified(atom)?);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.remove(0),
            _ => Node::Concat(items),
        })
    }

    fn atom(&mut self) -> Result<Node, PatternError> {
        let Some(c) = self.peek() else {
            return self.fail("pattern ends early");
        };
        self.pos += 1;
        match c {
            '.' => Ok(Node::Any),
            '^' => Ok(Node::Assert(Assertion::Start)),
            '$' => Ok(Node::Assert(Assertion::End)),
            '[' => self.class(),
            '(' => self.group(),
            '\\' => self.escape(false).map(|item| match item {
                Escaped::Char(c) => Node::Char(c),
                Escaped::Perl(kind, negated) => Node::Class(Class {
                    items: vec![ClassItem::Perl(kind, negated)],
                    negated: false,
                }),
                Escaped::Assert(assertion) => Node::Assert(assertion),
            }),
            '*' | '+' | '?' => self.fail("nothing to repeat"),
            c => Ok(Node::Char(c)),
        }
    }

    fn group(&mut self) -> Result<Node, PatternError> {
        if self.eat('?') {
            if self.eat(':') {
                // Non-capturing: the same thing here.
            } else if self.eat('P') && self.eat('<') {
                while let Some(c) = self.peek() {
                    self.pos += 1;
                    if c == '>' {
                        break;
                    }
                }
            } else if self.eat('i') && self.eat(')') {
                self.ignore_case = true;
                return Ok(Node::Empty);
            } else {
                return self.fail(
                    "lookaround, backreferences and inline flags other than (?i) are not supported",
                );
            }
        }
        if self.depth == MAX_DEPTH {
            return self.fail("groups nested too deeply");
        }
        self.depth += 1;
        let inner = self.alternation()?;
        if !self.eat(')') {
            return self.fail("missing )");
        }
        self.depth -= 1;
        Ok(inner)
    }

    fn escape(&mut self, in_class: bool) -> Result<Escaped, PatternError> {
        let Some(c) = self.peek() else {
            return self.fail("pattern ends with \\");
        };
        self.pos += 1;
        Ok(match c {
            'd' => Escaped::Perl(Perl::Digit, false),
            'D' => Escaped::Perl(Perl::Digit, true),
            'w' => Escaped::Perl(Perl::Word, false),
            'W' => Escaped::Perl(Perl::Word, true),
            's' => Escaped::Perl(Perl::Space, false),
            'S' => Escaped::Perl(Perl::Space, true),
            'b' if !in_class => Escaped::Assert(Assertion::WordBoundary),
            'B' if !in_class => Escaped::Assert(Assertion::NotWordBoundary),
            'A' if !in_class => Escaped::Assert(Assertion::Start),
            'Z' if !in_class => Escaped::Assert(Assertion::AbsoluteEnd),
            'b' => Escaped::Char('\u{8}'),
            't' => Escaped::Char('\t'),
            'n' => Escaped::Char('\n'),
            'r' => Escaped::Char('\r'),
            'f' => Escaped::Char('\u{c}'),
            'v' => Escaped::Char('\u{b}'),
            'x' => {
                let digits: String = self.chars.iter().skip(self.pos).take(2).collect();
                let Some(value) = u32::from_str_radix(&digits, 16)
                    .ok()
                    .filter(|_| digits.len() == 2)
                    .and_then(char::from_u32)
                else {
                    return self.fail("\\x needs two hex digits");
                };
                self.pos += 2;
                Escaped::Char(value)
            }
            c if c.is_ascii_digit() => {
                return self.fail("backreferences are not supported");
            }
            c if c.is_ascii_alphabetic() => {
                return self.fail("unknown escape");
            }
            c => Escaped::Char(c),
        })
    }

    fn class(&mut self) -> Result<Node, PatternError> {
        let negated = self.eat('^');
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let Some(c) = self.peek() else {
                return self.fail("missing ]");
            };
            if c == ']' && !first {
                self.pos += 1;
                break;
            }
            first = false;
            self.pos += 1;
            let low = if c == '\\' {
                match self.escape(true)? {
                    Escaped::Char(c) => c,
                    Escaped::Perl(kind, negated) => {
                        items.push(ClassItem::Perl(kind, negated));
                        continue;
                    }
                    Escaped::Assert(_) => return self.fail("assertion in a class"),
                }
            } else {
                c
            };
            let is_range = self.peek() == Some('-')
                && self
                    .chars
                    .get(self.pos + 1)
                    .is_some_and(|next| *next != ']');
            if is_range {
                self.pos += 1;
                let Some(next) = self.peek() else {
                    return self.fail("missing ]");
                };
                self.pos += 1;
                let high = if next == '\\' {
                    match self.escape(true)? {
                        Escaped::Char(c) => c,
                        _ => return self.fail("a range ends in a class escape"),
                    }
                } else {
                    next
                };
                if high < low {
                    return self.fail("range out of order");
                }
                items.push(ClassItem::Range(low, high));
            } else {
                items.push(ClassItem::Range(low, low));
            }
        }
        Ok(Node::Class(Class { items, negated }))
    }

    fn number(&mut self) -> Option<u32> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        let digits: String = self.chars[start..self.pos].iter().collect();
        digits.parse().ok()
    }

    /// `{n}`, `{n,}`, `{n,m}`, `{,m}` or `{,}` after an atom, an omitted lower bound being 0;
    /// anything else (`{}`, a malformed body) leaves `{` to be read as a literal, as Python does.
    /// A bound too large for a `u32` also stays literal, where Python refuses it.
    fn counted(&mut self) -> Option<(u32, Option<u32>)> {
        let start = self.pos;
        if !self.eat('{') {
            return None;
        }
        let parsed = (|| {
            let digits_at = self.pos;
            let min = self.number();
            if self.pos > digits_at && min.is_none() {
                return None;
            }
            if self.eat('}') {
                return min.map(|min| (min, Some(min)));
            }
            if !self.eat(',') {
                return None;
            }
            let min = min.unwrap_or(0);
            if self.eat('}') {
                return Some((min, None));
            }
            let max = self.number()?;
            self.eat('}').then_some((min, Some(max)))
        })();
        if parsed.is_none() {
            self.pos = start;
        }
        parsed
    }

    fn quantified(&mut self, atom: Node) -> Result<Node, PatternError> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => match self.counted() {
                Some(bounds) => bounds,
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };
        if max.is_some_and(|max| max < min) {
            return self.fail("repetition bounds out of order");
        }
        if matches!(atom, Node::Assert(_) | Node::Empty) {
            return self.fail("nothing to repeat");
        }
        // Laziness changes which match is found, never whether one is.
        self.eat('?');
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }
}

enum Escaped {
    Char(char),
    Perl(Perl, bool),
    Assert(Assertion),
}

#[cfg(test)]
thread_local! {
    /// How many times [`Compiler::node`] has run on this thread, so a test can check that a
    /// repeat compiles its body once whatever its bounds.
    static NODE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct Compiler {
    prog: Vec<Inst>,
    /// The program's size against [`MAX_PROGRAM`]: one per instruction, a class one per item.
    cost: usize,
}

impl Compiler {
    fn emit(&mut self, inst: Inst) -> Result<usize, String> {
        let weight = match &inst {
            Inst::Class(class) => class.items.len().max(1),
            _ => 1,
        };
        if self.cost + weight > MAX_PROGRAM {
            return Err(format!("compiles to more than {MAX_PROGRAM} instructions"));
        }
        self.cost += weight;
        self.prog.push(inst);
        Ok(self.prog.len() - 1)
    }

    fn node(&mut self, node: &Node) -> Result<(), String> {
        #[cfg(test)]
        NODE_CALLS.with(|calls| calls.set(calls.get() + 1));
        match node {
            Node::Empty => {}
            Node::Char(c) => {
                self.emit(Inst::Char(*c))?;
            }
            Node::Any => {
                self.emit(Inst::Any)?;
            }
            Node::Class(class) => {
                self.emit(Inst::Class(class.clone()))?;
            }
            Node::Assert(assertion) => {
                self.emit(Inst::Assert(*assertion))?;
            }
            Node::Concat(items) => {
                for item in items {
                    self.node(item)?;
                }
            }
            Node::Alt(branches) => {
                let mut jumps = Vec::new();
                for (index, branch) in branches.iter().enumerate() {
                    if index + 1 < branches.len() {
                        let split = self.emit(Inst::Split(0, 0))?;
                        self.node(branch)?;
                        jumps.push(self.emit(Inst::Jmp(0))?);
                        let next = self.prog.len();
                        self.prog[split] = Inst::Split(split + 1, next);
                    } else {
                        self.node(branch)?;
                    }
                }
                let end = self.prog.len();
                for jump in jumps {
                    self.prog[jump] = Inst::Jmp(end);
                }
            }
            Node::Repeat { node, min, max } => {
                let mut body = None;
                for _ in 0..*min {
                    let before = self.prog.len();
                    self.copy(node, &mut body)?;
                    // A body that compiles to nothing, such as `a{0}`, matches only the empty
                    // text, so one copy stands for them all: the rest would cost no instructions,
                    // only time, and `(?:(?:a{0}){4294967295}){4294967295}` would never finish.
                    if self.prog.len() == before {
                        break;
                    }
                }
                match max {
                    None => {
                        let split = self.emit(Inst::Split(0, 0))?;
                        self.copy(node, &mut body)?;
                        self.emit(Inst::Jmp(split))?;
                        let end = self.prog.len();
                        self.prog[split] = Inst::Split(split + 1, end);
                    }
                    Some(max) => {
                        let mut splits = Vec::new();
                        for _ in *min..*max {
                            splits.push(self.emit(Inst::Split(0, 0))?);
                            self.copy(node, &mut body)?;
                        }
                        let end = self.prog.len();
                        for split in splits {
                            self.prog[split] = Inst::Split(split + 1, end);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// One more copy of a repeat's `node`. The first is compiled and its span kept in `body`;
    /// each later one moves that code, jumps and all, to the end of the program, so a copy
    /// costs its instructions and never the body's own work again: `(?:a{0}...a{0}b){19999}`
    /// compiles its thousands of `a{0}` once, not once a copy.
    fn copy(&mut self, node: &Node, body: &mut Option<(usize, usize)>) -> Result<(), String> {
        let Some((start, end)) = *body else {
            let start = self.prog.len();
            self.node(node)?;
            *body = Some((start, self.prog.len()));
            return Ok(());
        };
        // Every jump in the body lands inside it or just past its end, so one shift moves them.
        let shift = self.prog.len() - start;
        for index in start..end {
            let inst = match &self.prog[index] {
                Inst::Split(first, second) => Inst::Split(first + shift, second + shift),
                Inst::Jmp(target) => Inst::Jmp(target + shift),
                inst => inst.clone(),
            };
            self.emit(inst)?;
        }
        Ok(())
    }
}

/// A compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    prog: Vec<Inst>,
    ignore_case: bool,
}

impl Pattern {
    /// Compile `source`, matching case as written.
    ///
    /// # Errors
    /// [`PatternError`] for syntax outside the supported subset, or a pattern too large to run.
    pub fn new(source: &str) -> Result<Self, PatternError> {
        Self::build(source, false)
    }

    /// Compile `source` to match regardless of case, as Spiderfoot's rules do.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn new_ignore_case(source: &str) -> Result<Self, PatternError> {
        Self::build(source, true)
    }

    fn build(source: &str, ignore_case: bool) -> Result<Self, PatternError> {
        let mut parser = Parser {
            source,
            chars: source.chars().collect(),
            pos: 0,
            ignore_case,
            depth: 0,
        };
        let node = parser.alternation()?;
        if parser.pos < parser.chars.len() {
            return parser.fail("unbalanced )");
        }
        let mut compiler = Compiler {
            prog: Vec::new(),
            cost: 0,
        };
        compiler
            .node(&node)
            .and_then(|()| compiler.emit(Inst::Match).map(|_| ()))
            .map_err(|reason| PatternError {
                pattern: source.to_owned(),
                offset: 0,
                reason,
            })?;
        Ok(Self {
            prog: compiler.prog,
            ignore_case: parser.ignore_case,
        })
    }

    /// Whether the pattern matches anywhere in `text`.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let mut current = Threads::new(self.prog.len());
        let mut next = Threads::new(self.prog.len());
        for at in 0..=chars.len() {
            // A thread starts at every position: a search, not an anchored match.
            if self.add(&mut current, 0, at, &chars) {
                return true;
            }
            let Some(&c) = chars.get(at) else {
                break;
            };
            next.clear();
            for index in 0..current.dense.len() {
                let pc = current.dense[index];
                let advances = match &self.prog[pc] {
                    Inst::Char(want) => {
                        *want == c || (self.ignore_case && lower(*want) == lower(c))
                    }
                    Inst::Any => c != '\n',
                    Inst::Class(class) => class.matches(c, self.ignore_case),
                    _ => false,
                };
                if advances && self.add(&mut next, pc + 1, at + 1, &chars) {
                    return true;
                }
            }
            std::mem::swap(&mut current, &mut next);
        }
        false
    }

    /// Follow every jump, split and assertion from `pc` at `at`, adding the instructions that
    /// read a character; true when the match instruction is reached.
    fn add(&self, threads: &mut Threads, pc: usize, at: usize, chars: &[char]) -> bool {
        let mut stack = vec![pc];
        while let Some(pc) = stack.pop() {
            if !threads.insert(pc) {
                continue;
            }
            match &self.prog[pc] {
                Inst::Match => return true,
                Inst::Jmp(target) => stack.push(*target),
                Inst::Split(first, second) => {
                    stack.push(*second);
                    stack.push(*first);
                }
                Inst::Assert(assertion) => {
                    if holds(*assertion, at, chars) {
                        stack.push(pc + 1);
                    }
                }
                Inst::Char(_) | Inst::Any | Inst::Class(_) => threads.dense.push(pc),
            }
        }
        false
    }
}

fn is_word(c: Option<&char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || *c == '_')
}

fn holds(assertion: Assertion, at: usize, chars: &[char]) -> bool {
    match assertion {
        Assertion::Start => at == 0,
        // As Python's `$`: the end, or just before a final newline.
        Assertion::End => at == chars.len() || (at + 1 == chars.len() && chars[at] == '\n'),
        // As Python's `\Z`: the very end only.
        Assertion::AbsoluteEnd => at == chars.len(),
        Assertion::WordBoundary | Assertion::NotWordBoundary => {
            let before = at.checked_sub(1).and_then(|index| chars.get(index));
            let boundary = is_word(before) != is_word(chars.get(at));
            boundary == (assertion == Assertion::WordBoundary)
        }
    }
}

/// The instructions live at one position: a sparse set, so each is visited once.
struct Threads {
    seen: Vec<bool>,
    visited: Vec<usize>,
    dense: Vec<usize>,
}

impl Threads {
    fn new(size: usize) -> Self {
        Self {
            seen: vec![false; size],
            visited: Vec::new(),
            dense: Vec::new(),
        }
    }

    fn insert(&mut self, pc: usize) -> bool {
        if self.seen[pc] {
            return false;
        }
        self.seen[pc] = true;
        self.visited.push(pc);
        true
    }

    fn clear(&mut self) {
        for pc in self.visited.drain(..) {
            self.seen[pc] = false;
        }
        self.dense.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn search(pattern: &str, text: &str) -> bool {
        Pattern::new_ignore_case(pattern).unwrap().is_match(text)
    }

    #[test]
    fn spiderfoots_rule_patterns_match_as_python_re_search_does() {
        assert!(search(".*[0-9]\\.[0-9].*", "SSH-2.0-OpenSSH_7.2p2"));
        assert!(!search(".*[0-9]\\.[0-9].*", "nginx"));
        assert!(search(".*:3306$", "db.example.com:3306"));
        assert!(!search(".*:3306$", "db.example.com:33060"));
        assert!(search(".*:500[12]0$", "host:50010"));
        assert!(search("40[13]", "403"));
        assert!(!search("^[2-3].*$", "404"));
        assert!(search("^[4-9].*$", "500"));
        assert!(search("MALICIOUS_*", "MALICIOUS_IPADDR"));
        assert!(search("VULNERABILITY_.*", "vulnerability_cve_high"));
        assert!(search(".*dev.*", "DEV-api.example.com"));
        assert!(search(
            "^https?://[a-zA-Z0-9\\.\\-]+/?#?$",
            "https://www.example.com/"
        ));
        assert!(!search(
            "^https?://[a-zA-Z0-9\\.\\-]+/?#?$",
            "https://example.com/a/b"
        ));
        assert!(search("^[a-zA-Z0-9\\.\\-]+$", "www.example.com"));
        assert!(search(".*/.*", "10.0.0.0/8"));
        assert!(!search(".*/.*", "10.0.0.1"));
        // Spiderfoot's internal_host rule writes \\ in a plain YAML scalar: a literal backslash.
        assert!(!search("^192\\\\.168\\\\..*", "192.168.1.1"));
        assert!(search("^10\\..*", "10.1.2.3"));
    }

    #[test]
    fn the_rest_of_the_syntax_matches() {
        assert!(search("(?:foo|bar)baz", "xbarbaz"));
        assert!(search(
            "^(?P<user>[a-z]+)@example\\.com$",
            "jane@example.com"
        ));
        assert!(search("a{2,3}", "baab"));
        assert!(!search("^a{2,3}$", "aaaa"));
        assert!(search("^a{2,}$", "aaaa"));
        assert!(search("\\bcat\\b", "a cat sat"));
        assert!(!search("\\bcat\\b", "concatenate"));
        assert!(search("\\d+\\s\\w+", "42 things"));
        assert!(search("[^0-9]", "12a"));
        assert!(!search("[^0-9]", "123"));
        assert!(search("x{y", "ax{yb"));
        assert!(search("a$", "ba\n"));
        assert!(!search("a.b", "a\nb"));
        assert!(search("", "anything"));
        assert!(search("[\\w.-]+", "a"));
        assert!(Pattern::new("ABC").unwrap().is_match("xABC"));
        assert!(!Pattern::new("ABC").unwrap().is_match("abc"));
        assert!(Pattern::new("(?i)ABC").unwrap().is_match("abc"));
    }

    #[test]
    fn unsupported_or_broken_patterns_are_refused() {
        for bad in [
            "(a", "a)", "[a", "*a", "(?=a)", "(a)\\1", "a{3,1}", "\\q", "[z-a]",
        ] {
            assert!(Pattern::new(bad).is_err(), "{bad}");
        }
        let huge = Pattern::new("(a{1000}){1000}").unwrap_err();
        assert!(huge.reason.contains("instructions"), "{huge}");
    }

    #[test]
    fn groups_nested_past_the_limit_are_refused_before_they_exhaust_the_stack() {
        let nested = |depth: usize| format!("{}a{}", "(".repeat(depth), ")".repeat(depth));
        assert!(search(&nested(MAX_DEPTH), "a"));
        let deep = Pattern::new(&nested(MAX_DEPTH + 1)).unwrap_err();
        assert!(deep.reason.contains("nested too deeply"), "{deep}");
        let hostile = Pattern::new(&"(".repeat(100_000)).unwrap_err();
        assert!(hostile.reason.contains("nested too deeply"), "{hostile}");
        // The limit is on groups open at once, not on groups in all.
        assert!(Pattern::new(&"(a)".repeat(MAX_DEPTH + 1)).is_ok());
        assert!(search(&nested(MAX_DEPTH).repeat(2), "aa"));
    }

    #[test]
    fn compiling_a_repeat_takes_time_for_what_it_emits_only() {
        let (sender, receiver) = std::sync::mpsc::channel();
        // On its own thread, so a regression fails here instead of hanging the suite.
        std::thread::spawn(move || {
            let compiled = [
                "(?:(?:a{0}){4294967295}){4294967295}".to_owned(),
                "^(?:a{0}b{0}){4294967295}c$".to_owned(),
                "^(?:(?i)(?i)){4294967295}c$".to_owned(),
                // About the most a rule file holds: 16,000 `a{0}` in a body copied 19,998 times
                // took seconds when each copy compiled them again.
                format!("^(?:{}b){{19998}}", "a{0}".repeat(16_000)),
                // The same body under an upper bound: each optional copy recompiled it too.
                format!("^(?:{}b){{1,9999}}$", "a{0}".repeat(16_000)),
            ]
            .map(|source| Pattern::new(&source));
            let _ = sender.send(compiled);
        });
        let [nested, concat, flags, wide, optional] = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("compiling a repeat stalled");
        let nested = nested.unwrap();
        assert!(nested.is_match(""));
        assert!(nested.is_match("x"));
        let concat = concat.unwrap();
        assert!(concat.is_match("c"));
        assert!(!concat.is_match("abc"));
        assert!(flags.unwrap().is_match("C"));
        let wide = wide.unwrap();
        assert!(wide.is_match(&"b".repeat(19_998)));
        assert!(!wide.is_match(&"b".repeat(19_997)));
        let optional = optional.unwrap();
        assert!(optional.is_match("b"));
        assert!(optional.is_match(&"b".repeat(9_999)));
        assert!(!optional.is_match(&"b".repeat(10_000)));
        assert!(!optional.is_match(""));
    }

    /// How many times compiling `source` runs [`Compiler::node`].
    fn node_calls(source: &str) -> usize {
        NODE_CALLS.with(|calls| calls.set(0));
        assert!(Pattern::new(source).is_ok(), "{source}");
        NODE_CALLS.with(std::cell::Cell::get)
    }

    #[test]
    fn a_repeat_compiles_its_body_once_whatever_its_bounds() {
        let body = "(?:x|y(?:z|[0-9])*\\b|w{2,3})";
        let once = node_calls(body);
        // The repeat and one compile of its body: every other copy, required, optional or the
        // loop of `{n,}`, moves that code, so the count does not depend on timing.
        for bounds in ["{3}", "{1,3}", "{0,3}", "{2,}", "+", "*", "?"] {
            assert_eq!(node_calls(&format!("{body}{bounds}")), once + 1, "{bounds}");
        }
    }

    #[test]
    fn a_repeat_compiles_to_its_body_written_out_that_many_times() {
        let body = "(?:x|y(?:z|[0-9])*\\b|w{2,3})";
        assert_eq!(
            Pattern::new(&format!("{body}{{3}}")).unwrap(),
            Pattern::new(&body.repeat(3)).unwrap()
        );
        assert_eq!(
            Pattern::new(&format!("{body}{{2,}}")).unwrap(),
            Pattern::new(&format!("{body}{body}{body}*")).unwrap()
        );
    }

    #[test]
    fn a_class_counts_once_per_item_toward_the_program_limit() {
        // One-item classes cost what they did: 19,999 copies and the match instruction fit.
        assert!(Pattern::new("\\d{19999}").is_ok());
        assert!(Pattern::new("[ab]{9999}").is_ok());
        for big in [
            "[ab]{10000}".to_owned(),
            "[a-z0-9]{10000}".to_owned(),
            format!("[{}]{{101}}", "a".repeat(200)),
            format!("[{}]", "a".repeat(30_000)),
        ] {
            let refused = Pattern::new(&big).unwrap_err();
            assert!(refused.reason.contains("instructions"), "{refused}");
        }
    }

    #[test]
    fn an_omitted_repetition_bound_reads_as_python_does() {
        assert!(search("^ab{,2}c$", "abc"));
        assert!(search("^ab{,2}c$", "ac"));
        assert!(!search("^ab{,2}c$", "abbbc"));
        assert!(search("^a{,}$", "aaa"));
        assert!(search("^a{,}$", ""));
        // `{}` and a bound past u32 stay literal text.
        assert!(search("^x{}$", "x{}"));
        assert!(!search("a{99999999999,}", "aaa"));
        assert!(search("a{99999999999,}", "xa{99999999999,}"));
        assert!(Pattern::new("a{,2").unwrap().is_match("a{,2"));
        assert!(Pattern::new("a{3,1}").is_err());
    }

    #[test]
    fn backslash_capital_z_matches_only_at_the_very_end() {
        assert!(!search("a\\Z", "a\n"));
        assert!(search("a\\Z", "ba"));
        assert!(search("a$", "a\n"));
        assert!(search("\\Aa", "ab"));
        assert!(Pattern::new("[\\Z]").is_err());
    }

    #[test]
    fn a_pattern_that_backtracks_badly_in_python_runs_in_linear_time() {
        let pattern = Pattern::new("^(a+)+$").unwrap();
        let text = format!("{}!", "a".repeat(50_000));
        let started = std::time::Instant::now();
        assert!(!pattern.is_match(&text));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// Any pattern built from the syntax's own pieces, valid or not, either compiles and then
    /// matches any text without a panic, or is refused with an error: never a panic either way.
    #[test]
    fn every_generated_pattern_compiles_and_matches_or_is_refused_never_a_panic() {
        const PIECES: &[&str] = &[
            "a", "b", ".", "^", "$", "|", "(", ")", "(?:", "(?P<n>", "(?=", "[", "]", "[^", "-",
            "a-z", "\\", "\\d", "\\W", "\\s", "\\b", "\\B", "\\Z", "\\1", "*", "+", "?", "*?", "{",
            "}", "{2}", "{2,}", "{,3}", "{1,2}", "{9999}", ",", "é", "😀", "\\x41", "\\.",
        ];
        const TEXTS: &[&str] = &["", "a", "ab ba", "aaaaaaaa!", "é😀 a-b_c 9", "\n\t x"];
        let mut state: u64 = 0x5EED_4E6E_CAFE_F00D;
        let mut draw = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
        };
        for case in 0..20_000 {
            let pattern: String = (0..draw(10)).map(|_| PIECES[draw(PIECES.len())]).collect();
            let outcome = std::panic::catch_unwind(|| {
                for compiled in [Pattern::new(&pattern), Pattern::new_ignore_case(&pattern)]
                    .into_iter()
                    .flatten()
                {
                    for text in TEXTS {
                        let _ = compiled.is_match(text);
                    }
                }
            });
            assert!(outcome.is_ok(), "case {case} panicked on {pattern:?}");
        }
    }
}
