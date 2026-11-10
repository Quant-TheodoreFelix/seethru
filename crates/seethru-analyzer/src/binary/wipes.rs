const MAX_TOKENS: usize = 2_000_000;
const MAX_LOOP_LINES: u32 = 8;
const KEPT_CALLS: &[&str] = &[
    "write_volatile",
    "explicit_bzero",
    "memset_s",
    "SecureZeroMemory",
    "OPENSSL_cleanse",
    "sodium_memzero",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wipe {
    pub(crate) line: u32,
    pub(crate) region: (u32, u32),
    pub(crate) function: (u32, u32),
    pub(crate) kept: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ident,
    Number,
    Punct(u8),
}

#[derive(Debug, Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    line: u32,
    kind: Kind,
}

impl Token<'_> {
    fn is(&self, punct: u8) -> bool {
        self.kind == Kind::Punct(punct)
    }

    fn word(&self, text: &str) -> bool {
        self.kind == Kind::Ident && self.text == text
    }

    fn is_zero(&self) -> bool {
        if self.kind != Kind::Number {
            return false;
        }
        let digits = self.text.replace('_', "");
        let digits = [
            "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "usize",
        ]
        .iter()
        .find_map(|suffix| digits.strip_suffix(suffix))
        .unwrap_or(&digits);
        let digits = digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0b"))
            .or_else(|| digits.strip_prefix("0o"))
            .unwrap_or(digits);
        !digits.is_empty() && digits.bytes().all(|byte| byte == b'0')
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

fn is_ident_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

fn raw_string(bytes: &[u8], at: usize) -> Option<usize> {
    let mut cursor = at;
    if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let mut hashes = 0usize;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes[cursor + 1..]
                .iter()
                .take(hashes)
                .filter(|byte| **byte == b'#')
                .count()
                == hashes
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn quoted(bytes: &[u8], at: usize) -> usize {
    let mut cursor = at + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'"' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    bytes.len()
}

fn char_literal(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(at + 1) == Some(&b'\\') {
        let close = bytes[at + 2..]
            .iter()
            .take(12)
            .skip(1)
            .position(|byte| *byte == b'\'')?;
        return Some(at + 2 + 1 + close + 1);
    }
    let inner = text.get(at + 1..)?.chars().next()?;
    let end = at + 1 + inner.len_utf8();
    (inner != '\'' && bytes.get(end) == Some(&b'\'')).then_some(end + 1)
}

fn lex(text: &str) -> Vec<Token<'_>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut line = 1u32;
    let mut at = 0usize;
    let newlines = |from: usize, to: usize| {
        u32::try_from(
            bytes[from..to.min(bytes.len())]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
        )
        .unwrap_or(u32::MAX)
    };
    while at < bytes.len() && tokens.len() < MAX_TOKENS {
        let byte = bytes[at];
        if byte == b'\n' {
            line = line.saturating_add(1);
            at += 1;
        } else if byte.is_ascii_whitespace() {
            at += 1;
        } else if byte == b'/' && bytes.get(at + 1) == Some(&b'/') {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else if byte == b'/' && bytes.get(at + 1) == Some(&b'*') {
            let start = at;
            let mut depth = 1usize;
            at += 2;
            while at < bytes.len() && depth > 0 {
                if bytes[at] == b'/' && bytes.get(at + 1) == Some(&b'*') {
                    depth += 1;
                    at += 2;
                } else if bytes[at] == b'*' && bytes.get(at + 1) == Some(&b'/') {
                    depth -= 1;
                    at += 2;
                } else {
                    at += 1;
                }
            }
            line = line.saturating_add(newlines(start, at));
        } else if byte == b'"' {
            let end = quoted(bytes, at);
            line = line.saturating_add(newlines(at, end));
            at = end;
        } else if byte == b'\'' {
            at = char_literal(text, at).unwrap_or(at + 1);
        } else if is_ident_start(byte) {
            if let Some(end) = raw_string(bytes, at) {
                line = line.saturating_add(newlines(at, end));
                at = end;
                continue;
            }
            if matches!(byte, b'b' | b'c') && bytes.get(at + 1) == Some(&b'"') {
                let end = quoted(bytes, at + 1);
                line = line.saturating_add(newlines(at, end));
                at = end;
                continue;
            }
            if byte == b'b' && bytes.get(at + 1) == Some(&b'\'') {
                at = char_literal(text, at + 1).unwrap_or(at + 2);
                continue;
            }
            let start = at;
            while at < bytes.len() && is_ident_part(bytes[at]) {
                at += 1;
            }
            if let Some(word) = text.get(start..at) {
                tokens.push(Token {
                    text: word,
                    line,
                    kind: Kind::Ident,
                });
            }
        } else if byte.is_ascii_digit() {
            let start = at;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            tokens.push(Token {
                text: &text[start..at],
                line,
                kind: Kind::Number,
            });
        } else {
            if byte < 0x80 {
                tokens.push(Token {
                    text: &text[at..at + 1],
                    line,
                    kind: Kind::Punct(byte),
                });
            }
            at += 1;
        }
    }
    tokens
}

fn pairs(tokens: &[Token<'_>]) -> Vec<Option<usize>> {
    let mut out = vec![None; tokens.len()];
    let mut open: Vec<(usize, u8)> = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        match token.kind {
            Kind::Punct(b'(') => open.push((at, b')')),
            Kind::Punct(b'[') => open.push((at, b']')),
            Kind::Punct(b'{') => open.push((at, b'}')),
            Kind::Punct(close @ (b')' | b']' | b'}')) => {
                if let Some(position) = open.iter().rposition(|(_, wanted)| *wanted == close) {
                    let (start, _) = open[position];
                    open.truncate(position);
                    out[start] = Some(at);
                    out[at] = Some(start);
                }
            }
            _ => {}
        }
    }
    out
}

struct Function {
    line: u32,
    open: usize,
    close: usize,
}

fn functions(tokens: &[Token<'_>], pairs: &[Option<usize>]) -> Vec<Function> {
    let mut out = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        if !token.word("fn")
            || tokens
                .get(at + 1)
                .is_none_or(|next| next.kind != Kind::Ident)
        {
            continue;
        }
        let mut cursor = at + 2;
        while let Some(next) = tokens.get(cursor) {
            if next.is(b';') || next.is(b'}') {
                break;
            }
            if next.is(b'{') {
                if let Some(close) = pairs[cursor] {
                    out.push(Function {
                        line: token.line,
                        open: cursor,
                        close,
                    });
                }
                break;
            }
            cursor = match (next.kind, pairs[cursor]) {
                (Kind::Punct(b'(' | b'['), Some(close)) => close + 1,
                _ => cursor + 1,
            };
        }
    }
    out
}

fn statement_start(tokens: &[Token<'_>], at: usize) -> usize {
    let mut cursor = at;
    while cursor > 0 {
        let before = &tokens[cursor - 1];
        if before.is(b';') || before.is(b'{') || before.is(b'}') {
            break;
        }
        cursor -= 1;
    }
    cursor
}

fn arguments(tokens: &[Token<'_>], pairs: &[Option<usize>], open: usize) -> Vec<(usize, usize)> {
    let Some(close) = pairs.get(open).copied().flatten() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut start = open + 1;
    let mut cursor = open + 1;
    while cursor < close {
        let token = &tokens[cursor];
        if token.is(b',') {
            out.push((start, cursor));
            start = cursor + 1;
        }
        cursor = match (token.kind, pairs[cursor]) {
            (Kind::Punct(b'(' | b'[' | b'{'), Some(end)) if end > cursor => end + 1,
            _ => cursor + 1,
        };
    }
    if start < close {
        out.push((start, close));
    }
    out
}

fn receiver<'a>(tokens: &[Token<'a>], pairs: &[Option<usize>], dot: usize) -> Option<&'a str> {
    let mut cursor = dot.checked_sub(1)?;
    loop {
        let token = tokens.get(cursor)?;
        match token.kind {
            Kind::Punct(b')') => {
                let name = pairs[cursor]?.checked_sub(1)?;
                if tokens[name].kind != Kind::Ident || !tokens.get(name.checked_sub(1)?)?.is(b'.') {
                    return None;
                }
                cursor = name.checked_sub(2)?;
            }
            Kind::Punct(b']') => cursor = pairs[cursor]?.checked_sub(1)?,
            Kind::Ident => return (token.text != "self").then_some(token.text),
            _ => return None,
        }
    }
}

fn first_name<'a>(tokens: &[Token<'a>], range: (usize, usize)) -> Option<&'a str> {
    (range.0..range.1).find_map(|at| {
        let token = &tokens[at];
        let next = tokens.get(at + 1);
        let skipped = token.kind != Kind::Ident
            || matches!(token.text, "mut" | "self" | "as" | "unsafe" | "const")
            || next.is_some_and(|next| next.is(b':') || next.is(b'(') || next.is(b'!'));
        (!skipped).then_some(token.text)
    })
}

fn single_zero(tokens: &[Token<'_>], range: Option<&(usize, usize)>) -> bool {
    range.is_some_and(|(start, end)| end - start == 1 && tokens[*start].is_zero())
}

struct Found<'a> {
    at: usize,
    end: usize,
    receiver: Option<&'a str>,
    kept: bool,
}

fn call<'a>(tokens: &[Token<'a>], pairs: &[Option<usize>], at: usize) -> Option<Found<'a>> {
    let token = &tokens[at];
    let open = at + 1;
    if !tokens.get(open)?.is(b'(') {
        return None;
    }
    let end = pairs[open]?;
    let method = at > 0 && tokens[at - 1].is(b'.');
    let kept = |receiver| Found {
        at,
        end,
        receiver,
        kept: true,
    };
    if KEPT_CALLS.contains(&token.text) {
        return Some(kept(None));
    }
    if token.text == "zeroize" && method {
        return Some(kept(None));
    }
    let args = arguments(tokens, pairs, open);
    let receiver = match (token.text, method) {
        ("fill", true) if args.len() == 1 && single_zero(tokens, args.first()) => {
            receiver(tokens, pairs, at - 1)
        }
        ("write_bytes", true) if args.len() == 2 && single_zero(tokens, args.first()) => {
            receiver(tokens, pairs, at - 1)
        }
        ("write_bytes" | "memset", false)
            if args.len() == 3 && single_zero(tokens, args.get(1)) =>
        {
            first_name(tokens, args[0])
        }
        _ => return None,
    };
    Some(Found {
        at,
        end,
        receiver: Some(receiver?),
        kept: false,
    })
}

fn assignment<'a>(tokens: &[Token<'a>], pairs: &[Option<usize>], at: usize) -> Option<Found<'a>> {
    let name = tokens.get(at.checked_sub(1)?)?;
    if name.kind != Kind::Ident || name.text == "self" {
        return None;
    }
    if let Some(before) = at.checked_sub(2).and_then(|index| tokens.get(index))
        && (before.is(b':') || matches!(before.text, "let" | "mut" | "const" | "static"))
    {
        return None;
    }
    let open = at + 1;
    if !tokens.get(open)?.is(b'[') || !tokens.get(open + 1)?.is_zero() {
        return None;
    }
    if !tokens.get(open + 2)?.is(b';') {
        return None;
    }
    let close = pairs[open]?;
    tokens.get(close + 1)?.is(b';').then_some(Found {
        at: at - 1,
        end: close,
        receiver: Some(name.text),
        kept: false,
    })
}

fn loop_region(
    tokens: &[Token<'_>],
    pairs: &[Option<usize>],
    at: usize,
    limit: (usize, usize),
) -> Option<(u32, u32)> {
    let mut cursor = at;
    loop {
        let open = (limit.0 + 1..cursor).rev().find(|index| {
            tokens[*index].is(b'{') && pairs[*index].is_some_and(|close| close > at)
        })?;
        let close = pairs[open]?;
        if open > 0 && tokens[open - 1].word("unsafe") {
            cursor = open;
            continue;
        }
        let head = &tokens[statement_start(tokens, open)];
        let lines = (head.line, tokens[close].line);
        let is_loop = matches!(head.text, "for" | "while" | "loop") && head.kind == Kind::Ident;
        return (is_loop && lines.1 - lines.0 <= MAX_LOOP_LINES).then_some(lines);
    }
}

pub(crate) fn find(text: &str) -> Vec<Wipe> {
    let tokens = lex(text);
    let pairs = pairs(&tokens);
    let functions = functions(&tokens, &pairs);
    let mut out = Vec::new();
    for at in 0..tokens.len() {
        let found = match tokens[at].kind {
            Kind::Ident => call(&tokens, &pairs, at),
            Kind::Punct(b'=') => assignment(&tokens, &pairs, at),
            _ => None,
        };
        let Some(found) = found else {
            continue;
        };
        let Some(function) = functions
            .iter()
            .filter(|function| function.open < found.at && found.end < function.close)
            .min_by_key(|function| function.close - function.open)
        else {
            continue;
        };
        if !found.kept {
            let Some(receiver) = found.receiver else {
                continue;
            };
            let used_later = tokens[found.end + 1..function.close]
                .iter()
                .any(|token| token.word(receiver));
            if used_later {
                continue;
            }
        }
        let start = statement_start(&tokens, found.at);
        let mut region = (tokens[start].line, tokens[found.end].line);
        if found.kept
            && let Some(around) =
                loop_region(&tokens, &pairs, found.at, (function.open, function.close))
        {
            region = (region.0.min(around.0), region.1.max(around.1));
        }
        out.push(Wipe {
            line: tokens[found.at].line,
            region,
            function: (function.line, tokens[function.close].line),
            kept: found.kept,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Wipe, find};

    const SOURCE: &str = r#"
pub fn removed(input: &[u8]) -> u8 {
    let mut key = [0u8; 32];
    key.copy_from_slice(input);
    let out = mix(&key);
    key.fill(0);
    out
}

pub fn kept(input: &[u8]) -> u8 {
    let mut key = [0u8; 32];
    let out = mix(&key);
    for slot in key.iter_mut() {
        unsafe { core::ptr::write_volatile(slot, 0) };
    }
    out
}

fn prepared(buffer: &mut [u8]) -> usize {
    buffer.fill(0);
    buffer.len()
}

struct Holder { key: [u8; 16], pad: Vec<u8> }

impl Drop for Holder {
    fn drop(&mut self) {
        // key.fill(0) in a comment and "key.fill(0)" in text do not count
        let note = "pad.fill(0)";
        self.key = [0; 16];
        unsafe { core::ptr::write_bytes(self.pad.as_mut_ptr(), 0, self.pad.len()) };
        self.pad
            .as_mut_slice()
            .fill(0x00);
        let _ = note;
    }
}

fn other(mut scratch: Vec<u8>, a: u8) -> bool {
    scratch.fill(1);
    scratch.zeroize();
    let lifetime: &'static str = "x";
    let quote = '"';
    let same = a == 0;
    lifetime.len() == 1 && quote == '"' && same
}
"#;

    fn lines(wipes: &[Wipe], kept: bool) -> Vec<u32> {
        wipes
            .iter()
            .filter(|wipe| wipe.kept == kept)
            .map(|wipe| wipe.line)
            .collect()
    }

    #[test]
    fn finds_wipes_that_nothing_reads_afterwards() {
        let wipes = find(SOURCE);
        assert_eq!(lines(&wipes, false), [6, 30, 34], "{wipes:?}");
        assert_eq!(lines(&wipes, true), [14, 41], "{wipes:?}");
    }

    #[test]
    fn records_the_function_and_the_lines_of_the_statement() {
        let wipes = find(SOURCE);
        let first = &wipes[0];
        assert_eq!((first.function, first.region), ((2, 8), (6, 6)));
        let volatile = wipes.iter().find(|wipe| wipe.line == 14);
        assert_eq!(volatile.map(|wipe| wipe.region), Some((13, 15)));
        let chained = wipes.iter().find(|wipe| wipe.line == 34);
        assert_eq!(chained.map(|wipe| wipe.region), Some((32, 34)));
    }

    #[test]
    fn survives_text_that_is_not_rust() {
        assert!(find("fn x( { key.fill(0) ").is_empty());
        assert!(find("\"unterminated key.fill(0)").is_empty());
        assert!(find("r#\"raw").is_empty());
        assert!(find("'").is_empty());
        assert_eq!(find("}}}} fn a() { b.fill(0); }").len(), 1);
    }
}
