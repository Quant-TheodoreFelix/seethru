mod lexer;

use std::collections::BTreeMap;

use seethru_core::{
    EdgeKind, FileRole, Location, Node, NodeId, NodeKind, PolicyCommand, RlsStatus, RuleId,
    Severity,
};

use crate::graph::Graph;
use crate::rules;
use lexer::{Kind, Token, statements, tokenize};

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

#[derive(Debug, Clone)]
struct Policy {
    command: PolicyCommand,
    roles: Vec<String>,
    permissive: bool,
    using_true: bool,
    check_true: bool,
    location: Location,
}

#[derive(Default)]
pub(crate) struct Migrations {
    tables: BTreeMap<TableKey, Table>,
    policies: BTreeMap<(TableKey, String), Policy>,
    defined_in: BTreeMap<TableKey, String>,
}

impl Migrations {
    pub(crate) fn apply_file(&mut self, rel_path: &str, source: &str) {
        let tokens = tokenize(source);
        for statement in statements(&tokens) {
            let location = |token: &Token| Location {
                path: rel_path.to_owned(),
                line: token.line,
                column: token.column,
            };
            let Some(first) = statement.first() else {
                continue;
            };
            let at = location(first);
            let mut cursor = Cursor::new(statement);
            if cursor.eat("create") {
                cursor.eat_seq(&["or", "replace"]);
                if cursor.eat("table") || cursor.eat_seq(&["unlogged", "table"]) {
                    if let Some(key) = cursor.table_name_after_if_not_exists() {
                        self.create_table(key, at, rel_path);
                    }
                } else if cursor.eat("policy") {
                    self.create_policy(&mut cursor, at);
                }
            } else if cursor.eat("alter") {
                if cursor.eat("table") {
                    self.alter_table(&mut cursor, &at);
                }
            } else if cursor.eat("drop") {
                if cursor.eat("table") {
                    self.drop_tables(&mut cursor);
                } else if cursor.eat("policy") {
                    self.drop_policy(&mut cursor);
                }
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
            using_true: false,
            check_true: false,
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
        if cursor.eat("using") {
            policy.using_true = cursor.parenthesized().is_some_and(always_true);
        }
        if cursor.eat_seq(&["with", "check"]) {
            policy.check_true = cursor.parenthesized().is_some_and(always_true);
        }
        self.table_mut(key.clone());
        self.policies.insert((key, name), policy);
    }

    pub(crate) fn emit(self, graph: &mut Graph) {
        for (key, table) in &self.tables {
            if MANAGED_SCHEMAS.contains(&key.schema.as_str()) {
                continue;
            }
            let table_id = table_id(key);
            graph.add_node(Node {
                id: table_id.clone(),
                label: table_label(key),
                kind: NodeKind::Table {
                    schema: key.schema.clone(),
                    rls: table.rls,
                },
                location: table
                    .defined_at
                    .clone()
                    .or_else(|| table.rls_changed_at.clone()),
            });
            if let Some(path) = self.defined_in.get(key) {
                let file_id = graph.add_file(path, FileRole::Migration);
                graph.add_edge(file_id, table_id.clone(), EdgeKind::Defines);
            }
            let exposed = EXPOSED_SCHEMAS.contains(&key.schema.as_str());
            if exposed && table.rls == RlsStatus::Disabled {
                let text = rules::rls_disabled(&table_label(key));
                graph.add_finding(
                    RuleId::SupabaseRlsDisabled,
                    Severity::Critical,
                    text,
                    table_id,
                    table
                        .rls_changed_at
                        .clone()
                        .or_else(|| table.defined_at.clone()),
                );
            }
        }

        for ((key, name), policy) in &self.policies {
            if MANAGED_SCHEMAS.contains(&key.schema.as_str()) {
                continue;
            }
            let reach = policy_reach(policy);
            let policy_id = NodeId::new(format!("policy:{}.{}/{}", key.schema, key.name, name));
            graph.add_node(Node {
                id: policy_id.clone(),
                label: name.clone(),
                kind: NodeKind::Policy {
                    command: policy.command,
                    roles: policy.roles.clone(),
                    unrestricted: reach.is_some(),
                },
                location: Some(policy.location.clone()),
            });
            graph.add_edge(table_id(key), policy_id.clone(), EdgeKind::GuardedBy);

            let exposed = EXPOSED_SCHEMAS.contains(&key.schema.as_str());
            if let (true, Some(reach)) = (exposed, reach) {
                let severity = policy_severity(reach, policy.command);
                let text = rules::policy_unrestricted(
                    &table_label(key),
                    name,
                    reach == Reach::Anyone,
                    policy.command,
                );
                graph.add_finding(
                    RuleId::SupabasePolicyUnrestricted,
                    severity,
                    text,
                    policy_id,
                    Some(policy.location.clone()),
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    Anyone,
    SignedIn,
}

fn policy_reach(policy: &Policy) -> Option<Reach> {
    if !policy.permissive {
        return None;
    }
    let open = match policy.command {
        PolicyCommand::Insert => policy.check_true,
        PolicyCommand::Select
        | PolicyCommand::Update
        | PolicyCommand::Delete
        | PolicyCommand::All => policy.using_true,
    };
    if !open {
        return None;
    }
    let has = |roles: &[&str]| {
        policy
            .roles
            .iter()
            .any(|role| roles.contains(&role.as_str()))
    };
    if has(ANONYMOUS_ROLES) {
        Some(Reach::Anyone)
    } else if has(SIGNED_IN_ROLES) {
        Some(Reach::SignedIn)
    } else {
        None
    }
}

fn policy_severity(reach: Reach, command: PolicyCommand) -> Severity {
    match (reach, command) {
        (Reach::Anyone, PolicyCommand::All | PolicyCommand::Update | PolicyCommand::Delete) => {
            Severity::Critical
        }
        (Reach::Anyone, PolicyCommand::Insert) => Severity::High,
        (Reach::Anyone, PolicyCommand::Select) => Severity::Medium,
        (Reach::SignedIn, PolicyCommand::All | PolicyCommand::Update | PolicyCommand::Delete) => {
            Severity::High
        }
        (Reach::SignedIn, PolicyCommand::Insert) => Severity::Medium,
        (Reach::SignedIn, PolicyCommand::Select) => Severity::Low,
    }
}

fn always_true(tokens: &[Token]) -> bool {
    let mut inner = tokens;
    while inner.len() >= 2
        && inner.first().is_some_and(|t| t.is_punct('('))
        && inner.last().is_some_and(|t| t.is_punct(')'))
        && matching_close(inner) == Some(inner.len() - 1)
    {
        inner = &inner[1..inner.len() - 1];
    }
    match inner {
        [only] => only.is_word("true"),
        [a, eq, b] => {
            a.kind == Kind::Number && eq.is_punct('=') && b.kind == Kind::Number && a.text == b.text
        }
        _ => false,
    }
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

fn table_id(key: &TableKey) -> NodeId {
    NodeId::new(format!("table:{}.{}", key.schema, key.name))
}

fn table_label(key: &TableKey) -> String {
    if key.schema == DEFAULT_SCHEMA {
        key.name.clone()
    } else {
        format!("{}.{}", key.schema, key.name)
    }
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
