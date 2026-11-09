use std::collections::BTreeSet;

use seethru_core::Location;

use super::{
    Cursor, DEFAULT_SCHEMA, Function, Kind, Migrations, TableKey, Token, checks_caller,
    is_admin_role, is_name, locate, tokenize,
};

const NON_CALLS: &[&str] = &[
    "exists",
    "in",
    "values",
    "coalesce",
    "count",
    "array",
    "any",
    "all",
    "select",
    "row",
    "cast",
    "case",
    "filter",
    "over",
    "nullif",
    "greatest",
    "least",
    "format",
    "concat",
    "and",
    "or",
    "not",
    "on",
    "as",
    "using",
    "from",
    "join",
    "where",
    "then",
    "else",
    "when",
    "end",
    "returning",
    "set",
    "into",
    "table",
];

struct Clauses {
    returns_trigger: bool,
    returns_boolean: bool,
    security: Option<(bool, Location)>,
    body: Vec<Token>,
}

fn clauses(rest: &[Token], rel_path: &str) -> Option<Clauses> {
    let mut found = Clauses {
        returns_trigger: false,
        returns_boolean: false,
        security: None,
        body: Vec::new(),
    };
    let mut have_body = false;
    let mut depth = 0usize;
    let mut index = 0;
    while let Some(token) = rest.get(index) {
        index += 1;
        if token.is_punct('(') {
            depth += 1;
            continue;
        }
        if token.is_punct(')') {
            depth = depth.saturating_sub(1);
            continue;
        }
        if depth > 0 || token.kind != Kind::Word {
            continue;
        }
        let next = rest.get(index);
        match token.text.as_str() {
            "begin" if next.is_some_and(|n| n.is_word("atomic")) => return None,
            "returns" => {
                let mut at = index;
                let set = rest.get(at).is_some_and(|t| t.is_word("setof"));
                if set {
                    at += 1;
                }
                if rest.get(at + 1).is_some_and(|t| t.is_punct('.')) {
                    at += 2;
                }
                found.returns_trigger = rest.get(at).is_some_and(|t| {
                    is_name(t) && matches!(t.text.as_str(), "trigger" | "event_trigger")
                });
                found.returns_boolean =
                    !set && rest.get(at).is_some_and(|t| {
                        is_name(t) && matches!(t.text.as_str(), "boolean" | "bool")
                    }) && !rest.get(at + 1).is_some_and(|t| t.is_punct('['));
            }
            "security" => {
                if let Some(next) = next {
                    if next.is_word("definer") {
                        found.security = Some((true, locate(rel_path, token)));
                    } else if next.is_word("invoker") {
                        found.security = Some((false, locate(rel_path, token)));
                    }
                }
            }
            "as" if !have_body => {
                if let Some(body) = next.filter(|t| t.kind == Kind::Str) {
                    found.body = tokenize(&body.text);
                    have_body = true;
                }
            }
            "return" if !have_body => {
                found.body = rest.get(index..).unwrap_or_default().to_vec();
                break;
            }
            _ => {}
        }
    }
    Some(found)
}

fn calls_in(tokens: &[Token]) -> BTreeSet<TableKey> {
    let mut calls = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if !is_name(token) || !tokens.get(index + 1).is_some_and(|t| t.is_punct('(')) {
            continue;
        }
        let before = index.checked_sub(1).and_then(|i| tokens.get(i));
        if before.is_some_and(|t| t.is_punct('.')) {
            let schema = index.checked_sub(2).and_then(|i| tokens.get(i));
            if let Some(schema) = schema.filter(|t| is_name(t)) {
                calls.insert(TableKey {
                    schema: schema.text.clone(),
                    name: token.text.clone(),
                });
            }
        } else if token.kind == Kind::QuotedIdent || !NON_CALLS.contains(&token.text.as_str()) {
            calls.insert(TableKey {
                schema: DEFAULT_SCHEMA.to_owned(),
                name: token.text.clone(),
            });
        }
    }
    calls
}

impl Migrations {
    pub(super) fn create_function(
        &mut self,
        cursor: &mut Cursor<'_>,
        at: Location,
        rel_path: &str,
    ) {
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        if cursor.parenthesized().is_none() {
            return;
        }
        let Some(parsed) = clauses(cursor.rest(), rel_path) else {
            return;
        };
        let (security_definer, security_at) = match parsed.security {
            Some((definer, location)) => (definer, Some(location)),
            None => (false, None),
        };
        let checks = checks_caller(&parsed.body);
        let calls = calls_in(&parsed.body);
        if let Some(existing) = self.functions.get_mut(&key) {
            existing.security_definer = security_definer;
            existing.security_at = security_at;
            existing.returns_trigger = parsed.returns_trigger;
            existing.returns_boolean = parsed.returns_boolean;
            existing.checks_caller = checks;
            existing.calls = calls;
            existing.defined_at = at;
            return;
        }
        let executors = self.defaults.executors_in(&key.schema);
        self.functions.insert(
            key,
            Function {
                security_definer,
                security_at,
                returns_trigger: parsed.returns_trigger,
                returns_boolean: parsed.returns_boolean,
                owner_is_admin: true,
                checks_caller: checks,
                calls,
                executors,
                defined_at: at,
            },
        );
    }

    pub(super) fn alter_function(&mut self, cursor: &mut Cursor<'_>, rel_path: &str) {
        cursor.eat_seq(&["if", "exists"]);
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        cursor.parenthesized();
        let rest = cursor.rest();
        let mut rename = None;
        let mut index = 0;
        while let Some(token) = rest.get(index) {
            index += 1;
            let next = rest.get(index);
            if token.is_word("security") {
                let definer = next.filter(|n| n.is_word("definer")).map(|_| true);
                let invoker = next.filter(|n| n.is_word("invoker")).map(|_| false);
                if let (Some(value), Some(function)) =
                    (definer.or(invoker), self.functions.get_mut(&key))
                {
                    function.security_definer = value;
                    function.security_at = Some(locate(rel_path, token));
                }
            } else if token.is_word("owner") && next.is_some_and(|n| n.is_word("to")) {
                if let (Some(role), Some(function)) =
                    (rest.get(index + 1), self.functions.get_mut(&key))
                    && is_name(role)
                {
                    function.owner_is_admin = is_admin_role(&role.text);
                }
            } else if token.is_word("rename")
                && next.is_some_and(|n| n.is_word("to"))
                && let Some(name) = rest.get(index + 1).filter(|t| is_name(t))
            {
                rename = Some(name.text.clone());
            }
        }
        if let Some(name) = rename
            && let Some(function) = self.functions.remove(&key)
        {
            self.functions.insert(
                TableKey {
                    schema: key.schema,
                    name,
                },
                function,
            );
        }
    }

    pub(super) fn drop_functions(&mut self, cursor: &mut Cursor<'_>) {
        cursor.eat_seq(&["if", "exists"]);
        while let Some(key) = cursor.qualified_name() {
            cursor.parenthesized();
            self.functions.remove(&key);
            if !cursor.eat_punct(',') {
                break;
            }
        }
    }
}
