#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Word,
    QuotedIdent,
    Str,
    Number,
    Punct(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub kind: Kind,
    pub text: String,
    pub line: u32,
    pub column: u32,
}

impl Token {
    pub(crate) fn is_word(&self, word: &str) -> bool {
        self.kind == Kind::Word && self.text == word
    }

    pub(crate) fn is_punct(&self, c: char) -> bool {
        self.kind == Kind::Punct(c)
    }
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: u32,
    column: u32,
}

impl Lexer<'_> {
    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next()?;
        if c == '\n' {
            self.line = self.line.saturating_add(1);
            self.column = 1;
        } else {
            self.column = self.column.saturating_add(1);
        }
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn skip_line(&mut self) {
        while let Some(c) = self.bump() {
            if c == '\n' {
                break;
            }
        }
    }

    fn skip_block_comment(&mut self) {
        let mut depth = 1usize;
        while let Some(c) = self.bump() {
            if c == '/' && self.eat('*') {
                depth += 1;
            } else if c == '*' && self.eat('/') {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
        }
    }

    fn quoted(&mut self, quote: char, backslash_escapes: bool) -> String {
        let mut out = String::new();
        while let Some(c) = self.bump() {
            if backslash_escapes && c == '\\' {
                if let Some(next) = self.bump() {
                    out.push(next);
                }
            } else if c == quote {
                if self.eat(quote) {
                    out.push(quote);
                } else {
                    break;
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn dollar_body(&mut self, tag: &str) -> String {
        let closing: Vec<char> = format!("${tag}$").chars().collect();
        let mut body: Vec<char> = Vec::new();
        while let Some(c) = self.bump() {
            body.push(c);
            if body.ends_with(&closing) {
                body.truncate(body.len() - closing.len());
                break;
            }
        }
        body.into_iter().collect()
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

pub(crate) fn tokenize(source: &str) -> Vec<Token> {
    let mut lexer = Lexer {
        chars: source.chars().peekable(),
        line: 1,
        column: 1,
    };
    let mut tokens = Vec::new();

    while let Some(c) = lexer.peek() {
        let (line, column) = (lexer.line, lexer.column);
        let push = |tokens: &mut Vec<Token>, kind: Kind, text: String| {
            tokens.push(Token {
                kind,
                text,
                line,
                column,
            });
        };

        if c.is_whitespace() {
            lexer.bump();
            continue;
        }
        lexer.bump();
        match c {
            '-' if lexer.peek() == Some('-') => lexer.skip_line(),
            '/' if lexer.peek() == Some('*') => {
                lexer.bump();
                lexer.skip_block_comment();
            }
            '\'' => {
                let text = lexer.quoted('\'', false);
                push(&mut tokens, Kind::Str, text);
            }
            '"' => {
                let text = lexer.quoted('"', false);
                push(&mut tokens, Kind::QuotedIdent, text);
            }
            '$' => {
                let mut tag = String::new();
                while let Some(next) = lexer.peek() {
                    if is_ident_continue(next) && next != '$' {
                        tag.push(next);
                        lexer.bump();
                    } else {
                        break;
                    }
                }
                let starts_like_tag = tag
                    .chars()
                    .next()
                    .is_none_or(|first| !first.is_ascii_digit());
                if starts_like_tag && lexer.eat('$') {
                    let body = lexer.dollar_body(&tag);
                    push(&mut tokens, Kind::Str, body);
                } else {
                    push(&mut tokens, Kind::Word, format!("${tag}"));
                }
            }
            c if c.is_ascii_digit() => {
                let mut text = String::from(c);
                while let Some(next) = lexer.peek() {
                    if next.is_ascii_alphanumeric() || next == '.' || next == '_' {
                        text.push(next);
                        lexer.bump();
                    } else {
                        break;
                    }
                }
                push(&mut tokens, Kind::Number, text);
            }
            c if is_ident_start(c) => {
                let mut text = String::from(c);
                while let Some(next) = lexer.peek() {
                    if is_ident_continue(next) {
                        text.push(next);
                        lexer.bump();
                    } else {
                        break;
                    }
                }
                let escape_prefix = text.eq_ignore_ascii_case("e");
                if escape_prefix && lexer.peek() == Some('\'') {
                    lexer.bump();
                    let body = lexer.quoted('\'', true);
                    push(&mut tokens, Kind::Str, body);
                } else {
                    push(&mut tokens, Kind::Word, text.to_lowercase());
                }
            }
            c => push(&mut tokens, Kind::Punct(c), c.to_string()),
        }
    }
    tokens
}

pub(crate) fn statements(tokens: &[Token]) -> impl Iterator<Item = &[Token]> {
    tokens
        .split(|token| token.is_punct(';'))
        .filter(|statement| !statement.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{Kind, statements, tokenize};

    fn words(source: &str) -> Vec<String> {
        tokenize(source)
            .into_iter()
            .map(|token| token.text)
            .collect()
    }

    #[test]
    fn lowercases_words_and_keeps_quoted_identifiers() {
        let tokens = tokenize(r#"CREATE TABLE "Todo Items" (id int)"#);
        assert_eq!(tokens[0].text, "create");
        assert_eq!(tokens[2].kind, Kind::QuotedIdent);
        assert_eq!(tokens[2].text, "Todo Items");
    }

    #[test]
    fn skips_comments_and_nested_block_comments() {
        assert_eq!(
            words("select 1 -- create table x\n/* a /* b */ create table y */ ;"),
            vec!["select", "1", ";"]
        );
    }

    #[test]
    fn dollar_quoted_bodies_hide_semicolons() {
        let source = "create function f() returns void as $body$ begin; alter table t disable row level security; end $body$ language plpgsql; select 1;";
        let tokens = tokenize(source);
        assert_eq!(statements(&tokens).count(), 2);
    }

    #[test]
    fn strings_handle_doubled_and_escaped_quotes() {
        let tokens = tokenize(r"select 'it''s', E'a\'b';");
        assert_eq!(tokens[1].text, "it's");
        assert_eq!(tokens[3].text, "a'b");
    }

    #[test]
    fn positional_parameters_are_not_dollar_quotes() {
        assert_eq!(words("select $1 ;"), vec!["select", "$1", ";"]);
    }

    #[test]
    fn tracks_line_and_column() {
        let tokens = tokenize("select\n  'x'");
        assert_eq!((tokens[1].line, tokens[1].column), (2, 3));
    }

    #[test]
    fn unterminated_input_does_not_panic() {
        let _ = tokenize("select 'abc");
        let _ = tokenize("select $$abc");
        let _ = tokenize("/* abc");
        let _ = tokenize("\"abc");
    }
}
