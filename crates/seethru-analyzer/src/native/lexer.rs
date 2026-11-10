pub(crate) const MAX_TOKENS: usize = 400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Ident,
    Text,
    Number,
    Punct(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Token {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

pub(crate) struct Tokens<'a> {
    pub source: &'a str,
    pub list: Vec<Token>,
    pub truncated: bool,
}

impl Tokens<'_> {
    pub(crate) fn text(&self, index: usize) -> &str {
        self.list
            .get(index)
            .and_then(|token| self.source.get(token.start..token.end))
            .unwrap_or_default()
    }

    pub(crate) fn kind(&self, index: usize) -> Option<Kind> {
        self.list.get(index).map(|token| token.kind)
    }

    pub(crate) fn is_punct(&self, index: usize, punct: u8) -> bool {
        self.kind(index) == Some(Kind::Punct(punct))
    }

    pub(crate) fn literal(&self, index: usize) -> Option<&str> {
        let token = self.list.get(index)?;
        if token.kind != Kind::Text {
            return None;
        }
        let raw = self.source.get(token.start..token.end)?;
        raw.strip_prefix('"')?.strip_suffix('"')
    }
}

pub(crate) fn lex(source: &str) -> Tokens<'_> {
    let bytes = source.as_bytes();
    let mut list = Vec::new();
    let mut at = 0;
    let mut line_start = true;
    let mut truncated = false;
    while let Some(&byte) = bytes.get(at) {
        if list.len() >= MAX_TOKENS {
            truncated = true;
            break;
        }
        match byte {
            b'\n' => {
                line_start = true;
                at += 1;
            }
            b' ' | b'\t' | b'\r' | 0x0c => at += 1,
            b'/' if bytes.get(at + 1) == Some(&b'/') => at = line_end(bytes, at),
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                at = find(bytes, at + 2, b"*/").map_or(bytes.len(), |end| end + 2);
            }
            b'#' if line_start => at = line_end(bytes, at),
            b'"' => {
                let end = quoted_end(bytes, at, b'"');
                list.push(Token {
                    kind: Kind::Text,
                    start: at,
                    end,
                });
                at = end;
                line_start = false;
            }
            b'\'' => {
                at = quoted_end(bytes, at, b'\'');
                line_start = false;
            }
            _ if byte.is_ascii_digit() => {
                let start = at;
                while bytes.get(at).is_some_and(|b| {
                    b.is_ascii_alphanumeric()
                        || *b == b'.'
                        || *b == b'_'
                        || (*b == b'\'' && bytes.get(at + 1).is_some_and(u8::is_ascii_alphanumeric))
                }) {
                    at += 1;
                }
                list.push(Token {
                    kind: Kind::Number,
                    start,
                    end: at,
                });
                line_start = false;
            }
            _ if is_ident_start(byte) => {
                let start = at;
                while bytes.get(at).is_some_and(|b| is_ident_part(*b)) {
                    at += 1;
                }
                let raw = bytes.get(at) == Some(&b'"')
                    && source
                        .get(start..at)
                        .is_some_and(|word| word.ends_with('R') && word.len() <= 3);
                if raw {
                    at = raw_end(bytes, at);
                    list.push(Token {
                        kind: Kind::Number,
                        start,
                        end: at,
                    });
                } else {
                    list.push(Token {
                        kind: Kind::Ident,
                        start,
                        end: at,
                    });
                }
                line_start = false;
            }
            _ => {
                if byte.is_ascii() {
                    list.push(Token {
                        kind: Kind::Punct(byte),
                        start: at,
                        end: at + 1,
                    });
                }
                at += 1;
                line_start = false;
            }
        }
    }
    Tokens {
        source,
        list,
        truncated,
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

fn is_ident_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

fn line_end(bytes: &[u8], mut at: usize) -> usize {
    while let Some(&byte) = bytes.get(at) {
        if byte == b'\n' {
            let continued = at > 0
                && (bytes.get(at - 1) == Some(&b'\\')
                    || (bytes.get(at - 1) == Some(&b'\r')
                        && at > 1
                        && bytes.get(at - 2) == Some(&b'\\')));
            if !continued {
                return at;
            }
        }
        at += 1;
    }
    bytes.len()
}

fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| from + position)
}

fn quoted_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut at = start + 1;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\\' => at += 2,
            b'\n' => return at,
            _ if byte == quote => return at + 1,
            _ => at += 1,
        }
    }
    bytes.len()
}

fn raw_end(bytes: &[u8], quote: usize) -> usize {
    let Some(open) = find(bytes, quote + 1, b"(").filter(|open| open - quote <= 17) else {
        return quoted_end(bytes, quote, b'"');
    };
    let mut closing = vec![b')'];
    closing.extend_from_slice(bytes.get(quote + 1..open).unwrap_or_default());
    closing.push(b'"');
    find(bytes, open + 1, &closing).map_or(bytes.len(), |end| end + closing.len())
}

#[cfg(test)]
mod tests {
    use super::{Kind, lex};

    #[test]
    fn comments_directives_and_literals_do_not_leak_tokens() {
        let source = "#include <a.h>\n#define X(a) \\\n  call(a)\n// f(1)\n/* g(2) */ int main(void) { char c = '{'; return h(\"a\\\"b)\", R\"x(})x\", 1'000); }\n";
        let tokens = lex(source);
        let words: Vec<&str> = (0..tokens.list.len())
            .filter(|index| tokens.kind(*index) == Some(Kind::Ident))
            .map(|index| tokens.text(index))
            .collect();
        assert_eq!(words, ["int", "main", "void", "char", "c", "return", "h"]);
        let open = tokens
            .list
            .iter()
            .filter(|token| token.kind == Kind::Punct(b'{'))
            .count();
        let close = tokens
            .list
            .iter()
            .filter(|token| token.kind == Kind::Punct(b'}'))
            .count();
        assert_eq!((open, close), (1, 1));
        let text = (0..tokens.list.len()).find_map(|index| tokens.literal(index));
        assert_eq!(text, Some("a\\\"b)"));
    }
}
