mod buckets;
mod condition;
mod emit;
mod functions;
mod grants;
mod lexer;
mod views;

use std::collections::{BTreeMap, BTreeSet};

use seethru_core::{BucketVisibility, Location, PolicyCommand, RlsStatus};

use condition::condition;
use lexer::{Kind, Token, statements, tokenize};
use views::ViewForm;

const DEFAULT_SCHEMA: &str = "public";
const EXPOSED_SCHEMAS: &[&str] = &["public"];
const MANAGED_SCHEMAS: &[&str] = &[
    "auth",
    "storage",
    "extensions",
    "realtime",
    "vault",
    "graphql",
    "graphql_public",
    "net",
    "cron",
    "pgsodium",
    "supabase_functions",
    "supabase_migrations",
    "information_schema",
    "pg_catalog",
];
const ANONYMOUS_ROLES: &[&str] = &["public", "anon"];
const SIGNED_IN_ROLES: &[&str] = &["authenticated"];
const ADMIN_ROLES: &[&str] = &["postgres", "supabase_admin"];
const SESSION_ROLES: &[&str] = &["current_user", "session_user", "current_role"];
const CALLER_FUNCTIONS: &[&str] = &["uid", "jwt", "role", "email"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TableKey {
    schema: String,
    name: String,
}

#[derive(Debug, Clone)]
struct Table {
    rls: RlsStatus,
    defined_at: Option<Location>,
    rls_changed_at: Option<Location>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Roles(BTreeSet<String>);

impl Roles {
    fn of(roles: &[&str]) -> Self {
        Self(roles.iter().map(|role| (*role).to_owned()).collect())
    }

    fn grant(&mut self, role: &str) {
        self.0.insert(role.to_owned());
    }

    fn revoke(&mut self, role: &str) {
        self.0.remove(role);
    }

    fn anyone(&self) -> bool {
        ANONYMOUS_ROLES.iter().any(|role| self.0.contains(*role))
    }

    fn signed_in(&self) -> bool {
        self.0.contains("public") || SIGNED_IN_ROLES.iter().any(|role| self.0.contains(*role))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Condition {
    open: bool,
    signed_in: bool,
    buckets: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct Policy {
    command: PolicyCommand,
    roles: Vec<String>,
    permissive: bool,
    using: Condition,
    check: Condition,
    location: Location,
}

#[derive(Debug, Clone)]
struct View {
    materialized: bool,
    security_invoker: bool,
    owner_is_admin: bool,
    checks_caller: bool,
    reads: BTreeSet<TableKey>,
    readers: Roles,
    defined_at: Location,
}

#[derive(Debug, Clone)]
struct Function {
    security_definer: bool,
    security_at: Option<Location>,
    returns_trigger: bool,
    returns_boolean: bool,
    owner_is_admin: bool,
    checks_caller: bool,
    calls: BTreeSet<TableKey>,
    executors: Roles,
    defined_at: Location,
}

#[derive(Debug, Clone)]
struct Bucket {
    visibility: BucketVisibility,
    defined_at: Option<Location>,
}

#[derive(Debug, Clone)]
struct Defaults {
    executors: Roles,
    schema_executors: BTreeMap<String, Roles>,
    readers: Roles,
    schema_readers: BTreeMap<String, Roles>,
}

impl Default for Defaults {
    fn default() -> Self {
        let supabase = Roles::of(&["anon", "authenticated", "service_role"]);
        Self {
            executors: Roles::of(&["public"]),
            schema_executors: BTreeMap::from([(DEFAULT_SCHEMA.to_owned(), supabase.clone())]),
            readers: Roles::default(),
            schema_readers: BTreeMap::from([(DEFAULT_SCHEMA.to_owned(), supabase)]),
        }
    }
}

impl Defaults {
    fn executors_in(&self, schema: &str) -> Roles {
        let mut roles = self.executors.clone();
        if let Some(extra) = self.schema_executors.get(schema) {
            roles.0.extend(extra.0.iter().cloned());
        }
        roles
    }

    fn readers_in(&self, schema: &str) -> Roles {
        let mut roles = self.readers.clone();
        if let Some(extra) = self.schema_readers.get(schema) {
            roles.0.extend(extra.0.iter().cloned());
        }
        roles
    }
}

#[derive(Default)]
pub(crate) struct Migrations {
    tables: BTreeMap<TableKey, Table>,
    policies: BTreeMap<(TableKey, String), Policy>,
    defined_in: BTreeMap<TableKey, String>,
    views: BTreeMap<TableKey, View>,
    functions: BTreeMap<TableKey, Function>,
    buckets: BTreeMap<String, Bucket>,
    defaults: Defaults,
}

impl Migrations {
    pub(crate) fn apply_file(&mut self, rel_path: &str, source: &str) {
        let tokens = tokenize(source);
        for statement in statements(&tokens) {
            let location = |token: &Token| locate(rel_path, token);
            let Some(first) = statement.first() else {
                continue;
            };
            let at = location(first);
            let mut cursor = Cursor::new(statement);
            if cursor.eat("create") {
                let replace = cursor.eat_seq(&["or", "replace"]);
                let temporary = cursor.eat("temporary") || cursor.eat("temp");
                cursor.eat("recursive");
                let materialized = cursor.eat("materialized");
                if cursor.eat("table") || cursor.eat_seq(&["unlogged", "table"]) {
                    if let Some(key) = cursor.table_name_after_if_not_exists() {
                        self.create_table(key, at, rel_path);
                    }
                } else if cursor.eat("view") {
                    self.create_view(
                        &mut cursor,
                        at,
                        ViewForm {
                            replace,
                            materialized,
                            temporary,
                        },
                    );
                } else if cursor.eat("function") {
                    self.create_function(&mut cursor, at, rel_path);
                } else if cursor.eat("policy") {
                    self.create_policy(&mut cursor, at);
                }
            } else if cursor.eat("alter") {
                if cursor.eat("table") {
                    self.alter_table(&mut cursor, &at);
                } else if cursor.eat("view") || cursor.eat_seq(&["materialized", "view"]) {
                    self.alter_view(&mut cursor);
                } else if cursor.eat("function") {
                    self.alter_function(&mut cursor, rel_path);
                } else if cursor.eat_seq(&["default", "privileges"]) {
                    self.alter_default_privileges(&mut cursor);
                }
            } else if cursor.eat("drop") {
                if cursor.eat("table") {
                    self.drop_tables(&mut cursor);
                } else if cursor.eat("policy") {
                    self.drop_policy(&mut cursor);
                } else if cursor.eat("view") || cursor.eat_seq(&["materialized", "view"]) {
                    self.drop_views(&mut cursor);
                } else if cursor.eat("function") {
                    self.drop_functions(&mut cursor);
                }
            } else if cursor.eat("grant") {
                self.grant_or_revoke(&mut cursor, true);
            } else if cursor.eat("revoke") {
                self.grant_or_revoke(&mut cursor, false);
            } else if cursor.eat("insert") {
                self.insert_buckets(&mut cursor, at);
            } else if cursor.eat("update") {
                self.update_buckets(&mut cursor);
            } else if cursor.eat("delete") {
                self.delete_buckets(&mut cursor);
            }
        }
    }

    fn create_table(&mut self, key: TableKey, at: Location, rel_path: &str) {
        self.defined_in.insert(key.clone(), rel_path.to_owned());
        self.tables.insert(
            key,
            Table {
                rls: RlsStatus::Disabled,
                defined_at: Some(at),
                rls_changed_at: None,
            },
        );
    }

    fn table_mut(&mut self, key: TableKey) -> &mut Table {
        self.tables.entry(key).or_insert(Table {
            rls: RlsStatus::Unknown,
            defined_at: None,
            rls_changed_at: None,
        })
    }

    fn alter_table(&mut self, cursor: &mut Cursor<'_>, at: &Location) {
        cursor.eat_seq(&["if", "exists"]);
        cursor.eat("only");
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        cursor.eat_punct('*');
        if cursor.eat_seq(&["rename", "to"]) {
            if let Some(new_name) = cursor.identifier() {
                self.rename_table(&key, new_name);
            }
            return;
        }
        let rest = cursor.rest();
        for window in rest.windows(3) {
            if window[0].is_word("owner")
                && window[1].is_word("to")
                && let Some(view) = self.views.get_mut(&key)
            {
                view.owner_is_admin = is_admin_role(&window[2].text);
            }
        }
        for window in rest.windows(4) {
            let toggled = if window[0].is_word("enable") {
                Some(RlsStatus::Enabled)
            } else if window[0].is_word("disable") {
                Some(RlsStatus::Disabled)
            } else {
                None
            };
            let is_rls = window[1].is_word("row")
                && window[2].is_word("level")
                && window[3].is_word("security");
            if let (Some(status), true) = (toggled, is_rls) {
                let table = self.table_mut(key.clone());
                table.rls = status;
                table.rls_changed_at = Some(at.clone());
            }
        }
    }

    fn rename_table(&mut self, key: &TableKey, new_name: String) {
        let new_key = TableKey {
            schema: key.schema.clone(),
            name: new_name,
        };
        if let Some(table) = self.tables.remove(key) {
            self.tables.insert(new_key.clone(), table);
        }
        if let Some(view) = self.views.remove(key) {
            self.views.insert(new_key.clone(), view);
        }
        if let Some(path) = self.defined_in.remove(key) {
            self.defined_in.insert(new_key.clone(), path);
        }
        let moved: Vec<_> = self
            .policies
            .keys()
            .filter(|(table, _)| table == key)
            .cloned()
            .collect();
        for old in moved {
            if let Some(policy) = self.policies.remove(&old) {
                self.policies.insert((new_key.clone(), old.1), policy);
            }
        }
    }

    fn drop_tables(&mut self, cursor: &mut Cursor<'_>) {
        cursor.eat_seq(&["if", "exists"]);
        while let Some(key) = cursor.qualified_name() {
            self.tables.remove(&key);
            self.defined_in.remove(&key);
            self.policies.retain(|(table, _), _| table != &key);
            if !cursor.eat_punct(',') {
                break;
            }
        }
    }

    fn drop_policy(&mut self, cursor: &mut Cursor<'_>) {
        cursor.eat_seq(&["if", "exists"]);
        let Some(name) = cursor.identifier() else {
            return;
        };
        if !cursor.eat("on") {
            return;
        }
        if let Some(key) = cursor.qualified_name() {
            self.policies.remove(&(key, name));
        }
    }

    fn create_policy(&mut self, cursor: &mut Cursor<'_>, at: Location) {
        let Some(name) = cursor.identifier() else {
            return;
        };
        if !cursor.eat("on") {
            return;
        }
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        let mut policy = Policy {
            command: PolicyCommand::All,
            roles: vec!["public".to_owned()],
            permissive: true,
            using: Condition::default(),
            check: Condition::default(),
            location: at,
        };
        if cursor.eat("as") {
            policy.permissive = !cursor.eat("restrictive");
            cursor.eat("permissive");
        }
        if cursor.eat("for") {
            policy.command = match cursor.word().as_deref() {
                Some("select") => PolicyCommand::Select,
                Some("insert") => PolicyCommand::Insert,
                Some("update") => PolicyCommand::Update,
                Some("delete") => PolicyCommand::Delete,
                _ => PolicyCommand::All,
            };
        }
        if cursor.eat("to") {
            let mut roles = Vec::new();
            while let Some(role) = cursor.identifier() {
                roles.push(role);
                if !cursor.eat_punct(',') {
                    break;
                }
            }
            if !roles.is_empty() {
                policy.roles = roles;
            }
        }
        let storage = key.schema == "storage" && key.name == "objects";
        if cursor.eat("using") {
            policy.using = cursor
                .parenthesized()
                .map(|tokens| condition(tokens, storage))
                .unwrap_or_default();
        }
        if cursor.eat_seq(&["with", "check"]) {
            policy.check = cursor
                .parenthesized()
                .map(|tokens| condition(tokens, storage))
                .unwrap_or_default();
        }
        self.table_mut(key.clone());
        self.policies.insert((key, name), policy);
    }

    pub(crate) fn is_view(&self, schema: &str, name: &str) -> bool {
        self.views.contains_key(&TableKey {
            schema: schema.to_owned(),
            name: name.to_owned(),
        })
    }

    fn function_checks_caller(&self, key: &TableKey) -> bool {
        let Some(function) = self.functions.get(key) else {
            return false;
        };
        function.checks_caller
            || function.calls.iter().any(|callee| {
                self.functions
                    .get(callee)
                    .is_some_and(|callee| callee.checks_caller)
            })
    }
}

fn always_true(tokens: &[Token]) -> bool {
    match strip_parens(tokens) {
        [only] => only.is_word("true"),
        [a, eq, b] => {
            a.kind == Kind::Number && eq.is_punct('=') && b.kind == Kind::Number && a.text == b.text
        }
        _ => false,
    }
}

fn locate(rel_path: &str, token: &Token) -> Location {
    Location {
        path: rel_path.to_owned(),
        line: token.line,
        column: token.column,
    }
}

fn is_admin_role(role: &str) -> bool {
    ADMIN_ROLES.contains(&role) || SESSION_ROLES.contains(&role)
}

fn is_name(token: &Token) -> bool {
    matches!(token.kind, Kind::Word | Kind::QuotedIdent)
}

fn strip_parens(tokens: &[Token]) -> &[Token] {
    let mut inner = tokens;
    while inner.len() >= 2
        && inner.first().is_some_and(|t| t.is_punct('('))
        && inner.last().is_some_and(|t| t.is_punct(')'))
        && matching_close(inner) == Some(inner.len() - 1)
    {
        inner = &inner[1..inner.len() - 1];
    }
    inner
}

fn top_positions(tokens: &[Token], pred: impl Fn(&Token) -> bool) -> Vec<usize> {
    let mut depth = 0usize;
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.is_punct('(') || token.is_punct('[') {
            depth += 1;
        } else if token.is_punct(')') || token.is_punct(']') {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && pred(token) {
            found.push(index);
        }
    }
    found
}

fn split_top(tokens: &[Token], pred: impl Fn(&Token) -> bool) -> Vec<&[Token]> {
    let mut parts = Vec::new();
    let mut start = 0;
    for index in top_positions(tokens, pred) {
        parts.push(&tokens[start..index]);
        start = index + 1;
    }
    parts.push(&tokens[start..]);
    parts
}

fn is_cast_tail(tokens: &[Token]) -> bool {
    tokens.is_empty()
        || (tokens.len() >= 3
            && tokens[0].is_punct(':')
            && tokens[1].is_punct(':')
            && tokens[2..].iter().all(is_name))
}

fn literal_str(tokens: &[Token]) -> Option<&str> {
    let tokens = strip_parens(tokens);
    let first = tokens.first()?;
    (first.kind == Kind::Str && is_cast_tail(&tokens[1..])).then_some(first.text.as_str())
}

fn single_equals(tokens: &[Token]) -> Option<(&[Token], &[Token])> {
    let operators = top_positions(tokens, |t| {
        t.is_punct('=') || t.is_punct('<') || t.is_punct('>') || t.is_punct('!')
    });
    let [index] = operators.as_slice() else {
        return None;
    };
    tokens[*index]
        .is_punct('=')
        .then(|| (&tokens[..*index], &tokens[*index + 1..]))
}

fn checks_caller(tokens: &[Token]) -> bool {
    tokens
        .iter()
        .any(|t| t.kind == Kind::Str && t.text.contains("request.jwt"))
        || tokens.windows(3).any(|w| {
            w[0].is_word("auth")
                && w[1].is_punct('.')
                && w[2].kind == Kind::Word
                && CALLER_FUNCTIONS.contains(&w[2].text.as_str())
        })
}

fn matching_close(tokens: &[Token]) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if token.is_punct('(') {
            depth += 1;
        } else if token.is_punct(')') {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

struct Cursor<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.pos)
    }

    fn eat(&mut self, word: &str) -> bool {
        if self.peek().is_some_and(|token| token.is_word(word)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn peek_is_punct(&self, c: char) -> bool {
        self.peek().is_some_and(|token| token.is_punct(c))
    }

    fn names(&mut self) -> Vec<String> {
        let mut names = Vec::new();
        while let Some(name) = self.identifier() {
            names.push(name);
            if !self.eat_punct(',') {
                break;
            }
        }
        names
    }

    fn eat_punct(&mut self, c: char) -> bool {
        if self.peek().is_some_and(|token| token.is_punct(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_seq(&mut self, words: &[&str]) -> bool {
        let matches = words.iter().enumerate().all(|(offset, word)| {
            self.tokens
                .get(self.pos + offset)
                .is_some_and(|token| token.is_word(word))
        });
        if matches {
            self.pos += words.len();
        }
        matches
    }

    fn word(&mut self) -> Option<String> {
        let token = self.peek()?;
        if token.kind == Kind::Word {
            self.pos += 1;
            Some(token.text.clone())
        } else {
            None
        }
    }

    fn identifier(&mut self) -> Option<String> {
        let token = self.peek()?;
        match token.kind {
            Kind::Word | Kind::QuotedIdent | Kind::Str => {
                self.pos += 1;
                Some(token.text.clone())
            }
            _ => None,
        }
    }

    fn qualified_name(&mut self) -> Option<TableKey> {
        let first = self.identifier()?;
        if self.eat_punct('.') {
            let name = self.identifier()?;
            Some(TableKey {
                schema: first,
                name,
            })
        } else {
            Some(TableKey {
                schema: DEFAULT_SCHEMA.to_owned(),
                name: first,
            })
        }
    }

    fn table_name_after_if_not_exists(&mut self) -> Option<TableKey> {
        self.eat_seq(&["if", "not", "exists"]);
        self.qualified_name()
    }

    fn parenthesized(&mut self) -> Option<&'a [Token]> {
        let rest = self.rest();
        if !rest.first()?.is_punct('(') {
            return None;
        }
        let close = matching_close(rest)?;
        self.pos += close + 1;
        rest.get(..=close)
    }

    fn rest(&self) -> &'a [Token] {
        self.tokens.get(self.pos..).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod parse_tests;
