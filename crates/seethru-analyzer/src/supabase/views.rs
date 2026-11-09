use std::collections::BTreeSet;

use seethru_core::Location;

use super::{
    Cursor, DEFAULT_SCHEMA, Kind, Migrations, TableKey, Token, View, checks_caller, is_admin_role,
    is_name, matching_close,
};

const ALIAS_STOPS: &[&str] = &[
    "where",
    "join",
    "inner",
    "left",
    "right",
    "full",
    "cross",
    "natural",
    "on",
    "using",
    "group",
    "order",
    "limit",
    "union",
    "intersect",
    "except",
    "window",
    "having",
    "offset",
    "fetch",
    "for",
    "tablesample",
    "lateral",
    "returning",
    "with",
    "select",
    "from",
    "and",
    "or",
];

const FROM_INSIDE: &[&str] = &[
    "extract",
    "substring",
    "trim",
    "overlay",
    "position",
    "btrim",
];

#[derive(Clone, Copy)]
pub(super) struct ViewForm {
    pub replace: bool,
    pub materialized: bool,
    pub temporary: bool,
}

pub(super) fn security_invoker_option(options: &[Token]) -> Option<bool> {
    let index = options.iter().position(|t| t.is_word("security_invoker"))?;
    if !options.get(index + 1).is_some_and(|t| t.is_punct('=')) {
        return Some(true);
    }
    let value = options.get(index + 2)?;
    let text = value.text.to_ascii_lowercase();
    match (value.kind.clone(), text.as_str()) {
        (Kind::Word | Kind::Str, "true" | "on" | "yes") | (Kind::Number, "1") => Some(true),
        (Kind::Word | Kind::Str, "false" | "off" | "no") | (Kind::Number, "0") => Some(false),
        _ => None,
    }
}

fn trim_tail(query: &[Token]) -> &[Token] {
    let mut end = query.len();
    for _ in 0..2 {
        let part = &query[..end];
        if let [.., with, no, data] = part
            && data.is_word("data")
            && no.is_word("no")
            && with.is_word("with")
        {
            end -= 3;
        } else if let [.., with, data] = part
            && data.is_word("data")
            && with.is_word("with")
        {
            end -= 2;
        } else if let [.., check, option] = part
            && check.is_word("check")
            && option.is_word("option")
        {
            end -= 2;
            if end > 0 && (query[end - 1].is_word("cascaded") || query[end - 1].is_word("local")) {
                end -= 1;
            }
            if end > 0 && query[end - 1].is_word("with") {
                end -= 1;
            }
        }
    }
    &query[..end]
}

fn cte_names(tokens: &[Token]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let introduced = index
            .checked_sub(1)
            .and_then(|i| tokens.get(i))
            .is_some_and(|t| t.is_word("with") || t.is_word("recursive") || t.is_punct(','));
        if !is_name(token) || !introduced {
            continue;
        }
        let mut at = index + 1;
        if tokens.get(at).is_some_and(|t| t.is_punct('(')) {
            match tokens.get(at..).and_then(matching_close) {
                Some(close) => at += close + 1,
                None => continue,
            }
        }
        if !tokens.get(at).is_some_and(|t| t.is_word("as")) {
            continue;
        }
        at += 1;
        if tokens.get(at).is_some_and(|t| t.is_word("not")) {
            at += 1;
        }
        if tokens.get(at).is_some_and(|t| t.is_word("materialized")) {
            at += 1;
        }
        if tokens.get(at).is_some_and(|t| t.is_punct('(')) {
            names.insert(token.text.clone());
        }
    }
    names
}

fn skip_group(tokens: &[Token], at: usize) -> usize {
    match tokens.get(at..).and_then(matching_close) {
        Some(close) => at + close + 1,
        None => tokens.len(),
    }
}

fn skip_alias(tokens: &[Token], at: usize) -> usize {
    let mut next = at;
    if tokens.get(next).is_some_and(|t| t.is_word("as")) {
        next += 1;
        if tokens.get(next).is_some_and(is_name) {
            next += 1;
        }
    } else if let Some(token) = tokens.get(next)
        && (token.kind == Kind::QuotedIdent
            || (token.kind == Kind::Word && !ALIAS_STOPS.contains(&token.text.as_str())))
    {
        next += 1;
    }
    if next > at && tokens.get(next).is_some_and(|t| t.is_punct('(')) {
        next = skip_group(tokens, next);
    }
    next
}

fn read_items(
    tokens: &[Token],
    start: usize,
    list: bool,
    ctes: &BTreeSet<String>,
    reads: &mut BTreeSet<TableKey>,
) {
    let mut at = start;
    loop {
        while tokens
            .get(at)
            .is_some_and(|t| t.is_word("lateral") || t.is_word("only"))
        {
            at += 1;
        }
        let Some(first) = tokens.get(at) else {
            return;
        };
        if first.is_punct('(') {
            at = skip_group(tokens, at);
        } else if is_name(first) {
            let (schema, name, next) = match (tokens.get(at + 1), tokens.get(at + 2)) {
                (Some(dot), Some(second)) if dot.is_punct('.') && is_name(second) => {
                    (Some(first), second, at + 3)
                }
                _ => (None, first, at + 1),
            };
            if tokens.get(next).is_some_and(|t| t.is_punct('(')) {
                at = skip_group(tokens, next);
            } else {
                at = next;
                if schema.is_some() || !ctes.contains(&name.text) {
                    reads.insert(TableKey {
                        schema: schema
                            .map_or_else(|| DEFAULT_SCHEMA.to_owned(), |s| s.text.clone()),
                        name: name.text.clone(),
                    });
                }
            }
        } else {
            return;
        }
        at = skip_alias(tokens, at);
        if list && tokens.get(at).is_some_and(|t| t.is_punct(',')) {
            at += 1;
        } else {
            return;
        }
    }
}

fn view_reads(tokens: &[Token]) -> BTreeSet<TableKey> {
    let ctes = cte_names(tokens);
    let mut reads = BTreeSet::new();
    let mut scopes: Vec<bool> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.is_punct('(') {
            let special = index
                .checked_sub(1)
                .and_then(|i| tokens.get(i))
                .is_some_and(|t| t.kind == Kind::Word && FROM_INSIDE.contains(&t.text.as_str()));
            scopes.push(special);
        } else if token.is_punct(')') {
            scopes.pop();
        } else if token.is_word("join") {
            read_items(tokens, index + 1, false, &ctes, &mut reads);
        } else if token.is_word("from") {
            let inside = scopes.last() == Some(&true);
            let distinct = index
                .checked_sub(1)
                .and_then(|i| tokens.get(i))
                .is_some_and(|t| t.is_word("distinct"));
            if !inside && !distinct {
                read_items(tokens, index + 1, true, &ctes, &mut reads);
            }
        }
    }
    reads
}

impl Migrations {
    pub(super) fn create_view(&mut self, cursor: &mut Cursor<'_>, at: Location, form: ViewForm) {
        let if_not_exists = cursor.eat_seq(&["if", "not", "exists"]);
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        if form.temporary || (if_not_exists && self.views.contains_key(&key)) {
            return;
        }
        if cursor.peek_is_punct('(') {
            cursor.parenthesized();
        }
        let mut security_invoker = false;
        if cursor.eat("with")
            && let Some(options) = cursor.parenthesized()
        {
            security_invoker = security_invoker_option(options).unwrap_or(false);
        }
        cursor.eat("as");
        let query = trim_tail(cursor.rest());
        let reads = view_reads(query);
        let checks = checks_caller(query);
        if form.replace
            && let Some(existing) = self.views.get_mut(&key)
        {
            existing.materialized = form.materialized;
            existing.security_invoker = security_invoker;
            existing.checks_caller = checks;
            existing.reads = reads;
            existing.defined_at = at;
            return;
        }
        let readers = self.defaults.readers_in(&key.schema);
        self.views.insert(
            key,
            View {
                materialized: form.materialized,
                security_invoker,
                owner_is_admin: true,
                checks_caller: checks,
                reads,
                readers,
                defined_at: at,
            },
        );
    }

    pub(super) fn alter_view(&mut self, cursor: &mut Cursor<'_>) {
        cursor.eat_seq(&["if", "exists"]);
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        let rest = cursor.rest();
        let mut rename = None;
        let mut index = 0;
        while let Some(token) = rest.get(index) {
            index += 1;
            let next = rest.get(index);
            if (token.is_word("set") || token.is_word("reset"))
                && next.is_some_and(|n| n.is_punct('('))
            {
                let end = rest
                    .get(index..)
                    .and_then(matching_close)
                    .map_or(rest.len(), |close| index + close + 1);
                let options = &rest[index..end];
                let value = if token.is_word("set") {
                    security_invoker_option(options)
                } else if options.iter().any(|t| t.is_word("security_invoker")) {
                    Some(false)
                } else {
                    None
                };
                if let (Some(value), Some(view)) = (value, self.views.get_mut(&key)) {
                    view.security_invoker = value;
                }
                index = end;
            } else if token.is_word("owner") && next.is_some_and(|n| n.is_word("to")) {
                if let (Some(role), Some(view)) = (rest.get(index + 1), self.views.get_mut(&key))
                    && is_name(role)
                {
                    view.owner_is_admin = is_admin_role(&role.text);
                }
            } else if token.is_word("rename")
                && next.is_some_and(|n| n.is_word("to"))
                && let Some(name) = rest.get(index + 1).filter(|t| is_name(t))
            {
                rename = Some(name.text.clone());
            }
        }
        if let Some(name) = rename {
            self.rename_table(&key, name);
        }
    }

    pub(super) fn drop_views(&mut self, cursor: &mut Cursor<'_>) {
        cursor.eat_seq(&["if", "exists"]);
        while let Some(key) = cursor.qualified_name() {
            self.views.remove(&key);
            if !cursor.eat_punct(',') {
                break;
            }
        }
    }
}
