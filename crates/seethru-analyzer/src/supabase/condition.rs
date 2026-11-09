use super::{
    Condition, Token, always_true, is_name, literal_str, matching_close, single_equals, split_top,
    strip_parens, top_positions,
};

enum Term {
    Open,
    SignedIn,
    Buckets(Vec<String>),
}

pub(super) fn condition(tokens: &[Token], storage: bool) -> Condition {
    let inner = strip_parens(tokens);
    if inner.is_empty() {
        return Condition::default();
    }
    if !top_positions(inner, |t| t.is_word("or")).is_empty() {
        return Condition::default();
    }
    let mut result = Condition {
        open: true,
        ..Condition::default()
    };
    for term in split_top(inner, |t| t.is_word("and")) {
        match term_of(term, storage) {
            Some(Term::Open) => {}
            Some(Term::SignedIn) => result.signed_in = true,
            Some(Term::Buckets(ids)) => result.buckets.extend(ids),
            None => result.open = false,
        }
    }
    if !result.open {
        result.signed_in = false;
    }
    result
}

fn term_of(term: &[Token], storage: bool) -> Option<Term> {
    let term = strip_parens(term);
    if always_true(term) {
        return Some(Term::Open);
    }
    if is_login(term) {
        return Some(Term::SignedIn);
    }
    if storage {
        return bucket_ids(term).map(Term::Buckets);
    }
    None
}

fn strip_cast(tokens: &[Token]) -> &[Token] {
    let mut inner = tokens;
    while inner.len() >= 4 {
        let tail = &inner[inner.len() - 3..];
        if tail[0].is_punct(':') && tail[1].is_punct(':') && is_name(&tail[2]) {
            inner = &inner[..inner.len() - 3];
        } else {
            break;
        }
    }
    inner
}

fn normalize(tokens: &[Token]) -> &[Token] {
    let mut current = tokens;
    loop {
        let stripped = strip_cast(strip_parens(current));
        let stripped = match stripped.split_first() {
            Some((first, rest)) if first.is_word("select") => rest,
            _ => stripped,
        };
        if stripped.len() == current.len() {
            return stripped;
        }
        current = stripped;
    }
}

fn is_call(tokens: &[Token], function: &str) -> bool {
    matches!(
        normalize(tokens),
        [auth, dot, name, open, close]
            if auth.is_word("auth")
                && dot.is_punct('.')
                && name.is_word(function)
                && open.is_punct('(')
                && close.is_punct(')')
    )
}

fn is_login(term: &[Token]) -> bool {
    if let [rest @ .., is, not, null] = term
        && is.is_word("is")
        && not.is_word("not")
        && null.is_word("null")
    {
        return is_call(rest, "uid");
    }
    let Some((left, right)) = single_equals(term) else {
        return false;
    };
    (is_call(left, "role") && literal_str(normalize(right)) == Some("authenticated"))
        || (is_call(right, "role") && literal_str(normalize(left)) == Some("authenticated"))
}

fn is_bucket_column(tokens: &[Token]) -> bool {
    let tokens = strip_parens(tokens);
    let Some((last, prefix)) = tokens.split_last() else {
        return false;
    };
    if !(is_name(last) && last.text.eq_ignore_ascii_case("bucket_id")) {
        return false;
    }
    prefix.chunks(2).all(|pair| match pair {
        [name, dot] => is_name(name) && dot.is_punct('.'),
        _ => false,
    })
}

fn bucket_ids(term: &[Token]) -> Option<Vec<String>> {
    if let Some((left, right)) = single_equals(term) {
        let literal = if is_bucket_column(left) {
            literal_str(normalize(right))
        } else if is_bucket_column(right) {
            literal_str(normalize(left))
        } else {
            None
        };
        return literal.map(|id| vec![id.to_owned()]);
    }
    let positions = top_positions(term, |t| t.is_word("in"));
    let [index] = positions.as_slice() else {
        return None;
    };
    let left = &term[..*index];
    let right = inside_parens(&term[*index + 1..])?;
    if !is_bucket_column(left) {
        return None;
    }
    let mut ids = Vec::new();
    for item in split_top(right, |t| t.is_punct(',')) {
        ids.push(literal_str(normalize(item))?.to_owned());
    }
    (!ids.is_empty()).then_some(ids)
}

fn inside_parens(tokens: &[Token]) -> Option<&[Token]> {
    if tokens.first()?.is_punct('(') && matching_close(tokens) == Some(tokens.len() - 1) {
        tokens.get(1..tokens.len() - 1)
    } else {
        None
    }
}
