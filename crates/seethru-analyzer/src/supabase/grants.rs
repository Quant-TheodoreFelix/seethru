use super::{Cursor, Kind, Migrations, Roles, TableKey};

const OTHER_OBJECTS: &[&str] = &[
    "sequence",
    "schema",
    "database",
    "domain",
    "type",
    "language",
    "large",
    "foreign",
    "tablespace",
    "parameter",
    "procedure",
    "all",
];

#[derive(Default)]
struct Privileges {
    execute: bool,
    select: bool,
    all: bool,
    column_level: bool,
}

fn privileges(cursor: &mut Cursor<'_>) -> Option<Privileges> {
    let mut found = Privileges::default();
    loop {
        let token = cursor.peek()?;
        if token.is_word("on") {
            return Some(found);
        }
        if token.is_punct('(') {
            found.column_level = true;
            cursor.parenthesized()?;
            continue;
        }
        cursor.pos += 1;
        if token.kind == Kind::Word {
            match token.text.as_str() {
                "execute" => found.execute = true,
                "select" => found.select = true,
                "all" => found.all = true,
                _ => {}
            }
        }
    }
}

fn function_names(cursor: &mut Cursor<'_>) -> Vec<TableKey> {
    let mut keys = Vec::new();
    while let Some(key) = cursor.qualified_name() {
        cursor.parenthesized();
        keys.push(key);
        if !cursor.eat_punct(',') {
            break;
        }
    }
    keys
}

fn relation_names(cursor: &mut Cursor<'_>) -> Vec<TableKey> {
    let mut keys = Vec::new();
    while let Some(key) = cursor.qualified_name() {
        keys.push(key);
        if !cursor.eat_punct(',') {
            break;
        }
    }
    keys
}

fn change(roles: &mut Roles, names: &[String], grant: bool) {
    for name in names {
        if grant {
            roles.grant(name);
        } else {
            roles.revoke(name);
        }
    }
}

enum Target {
    Functions(Vec<TableKey>),
    AllFunctions(Vec<String>),
    Relations(Vec<TableKey>),
    AllTables(Vec<String>),
}

impl Migrations {
    pub(super) fn grant_or_revoke(&mut self, cursor: &mut Cursor<'_>, grant: bool) {
        if !grant && cursor.eat_seq(&["grant", "option", "for"]) {
            return;
        }
        let Some(found) = privileges(cursor) else {
            return;
        };
        if !cursor.eat("on") {
            return;
        }
        let target = if cursor.eat("function") || cursor.eat("routine") {
            Target::Functions(function_names(cursor))
        } else if cursor.eat_seq(&["all", "functions", "in", "schema"])
            || cursor.eat_seq(&["all", "routines", "in", "schema"])
        {
            Target::AllFunctions(cursor.names())
        } else if cursor.eat_seq(&["all", "tables", "in", "schema"]) {
            Target::AllTables(cursor.names())
        } else if cursor.eat("table") {
            Target::Relations(relation_names(cursor))
        } else if cursor
            .peek()
            .is_some_and(|t| OTHER_OBJECTS.iter().any(|word| t.is_word(word)))
        {
            return;
        } else {
            Target::Relations(relation_names(cursor))
        };
        if !cursor.eat(if grant { "to" } else { "from" }) {
            return;
        }
        let roles = cursor.names();
        let executes = found.execute || found.all;
        let reads = (found.select || found.all) && (grant || !found.column_level);
        match target {
            Target::Functions(keys) if executes => {
                for key in keys {
                    if let Some(function) = self.functions.get_mut(&key) {
                        change(&mut function.executors, &roles, grant);
                    }
                }
            }
            Target::AllFunctions(schemas) if executes => {
                for (key, function) in &mut self.functions {
                    if schemas.contains(&key.schema) {
                        change(&mut function.executors, &roles, grant);
                    }
                }
            }
            Target::Relations(keys) if reads => {
                for key in keys {
                    if let Some(view) = self.views.get_mut(&key) {
                        change(&mut view.readers, &roles, grant);
                    }
                }
            }
            Target::AllTables(schemas) if reads => {
                for (key, view) in &mut self.views {
                    if schemas.contains(&key.schema) {
                        change(&mut view.readers, &roles, grant);
                    }
                }
            }
            _ => {}
        }
    }

    pub(super) fn alter_default_privileges(&mut self, cursor: &mut Cursor<'_>) {
        let mut owners: Option<Vec<String>> = None;
        let mut schemas = Vec::new();
        loop {
            if cursor.eat("for") {
                if !(cursor.eat("role") || cursor.eat("user")) {
                    return;
                }
                owners = Some(cursor.names());
            } else if cursor.eat_seq(&["in", "schema"]) {
                schemas = cursor.names();
            } else {
                break;
            }
        }
        let grant = if cursor.eat("grant") {
            true
        } else if cursor.eat("revoke") {
            if cursor.eat_seq(&["grant", "option", "for"]) {
                return;
            }
            false
        } else {
            return;
        };
        let Some(found) = privileges(cursor) else {
            return;
        };
        if !cursor.eat("on") {
            return;
        }
        let functions = if cursor.eat("functions") || cursor.eat("routines") {
            true
        } else if cursor.eat("tables") {
            false
        } else {
            return;
        };
        if !cursor.eat(if grant { "to" } else { "from" }) {
            return;
        }
        let roles = cursor.names();
        if owners.is_some_and(|owners| !owners.iter().any(|owner| owner == "postgres")) {
            return;
        }
        if functions {
            if !(found.execute || found.all) {
                return;
            }
            if schemas.is_empty() {
                change(&mut self.defaults.executors, &roles, grant);
            }
            for schema in schemas {
                let entry = self.defaults.schema_executors.entry(schema).or_default();
                change(entry, &roles, grant);
            }
        } else {
            if !((found.select || found.all) && (grant || !found.column_level)) {
                return;
            }
            if schemas.is_empty() {
                change(&mut self.defaults.readers, &roles, grant);
            }
            for schema in schemas {
                let entry = self.defaults.schema_readers.entry(schema).or_default();
                change(entry, &roles, grant);
            }
        }
    }
}
