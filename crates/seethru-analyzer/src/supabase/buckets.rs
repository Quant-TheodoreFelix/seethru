use seethru_core::{BucketVisibility, Location};

use super::{
    Bucket, Cursor, Kind, Migrations, TableKey, Token, is_cast_tail, is_name, literal_str,
    single_equals, split_top, strip_parens, top_positions,
};

fn is_buckets(key: &TableKey) -> bool {
    key.schema == "storage" && key.name == "buckets"
}

fn visibility_of(tokens: &[Token]) -> BucketVisibility {
    let tokens = strip_parens(tokens);
    let Some(first) = tokens.first() else {
        return BucketVisibility::Unknown;
    };
    if !matches!(first.kind, Kind::Word | Kind::Str) || !is_cast_tail(&tokens[1..]) {
        return BucketVisibility::Unknown;
    }
    match first.text.to_ascii_lowercase().as_str() {
        "true" => BucketVisibility::Public,
        "false" => BucketVisibility::Private,
        _ => BucketVisibility::Unknown,
    }
}

fn named(token: &Token, name: &str) -> bool {
    is_name(token) && token.text.eq_ignore_ascii_case(name)
}

fn id_equals(tokens: &[Token]) -> Option<String> {
    let (left, right) = single_equals(strip_parens(tokens))?;
    let is_id = |side: &[Token]| matches!(strip_parens(side), [only] if named(only, "id"));
    let id = if is_id(left) {
        literal_str(right)
    } else if is_id(right) {
        literal_str(left)
    } else {
        None
    };
    id.map(str::to_owned)
}

impl Migrations {
    pub(super) fn insert_buckets(&mut self, cursor: &mut Cursor<'_>, at: Location) {
        if !cursor.eat("into") {
            return;
        }
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        if !is_buckets(&key) {
            return;
        }
        if cursor.eat("as") {
            cursor.identifier();
        }
        let columns: Option<Vec<String>> = if cursor.peek_is_punct('(') {
            cursor.parenthesized().map(|tokens| {
                tokens
                    .iter()
                    .filter(|t| is_name(t))
                    .map(|t| t.text.to_ascii_lowercase())
                    .collect()
            })
        } else {
            None
        };
        if !cursor.eat("values") {
            return;
        }
        let mut tuples = Vec::new();
        while cursor.peek_is_punct('(') {
            let Some(tuple) = cursor.parenthesized() else {
                break;
            };
            tuples.push(tuple);
            if !cursor.eat_punct(',') {
                break;
            }
        }
        let keep_existing = cursor
            .rest()
            .windows(2)
            .any(|w| w[0].is_word("do") && w[1].is_word("nothing"));
        for tuple in tuples {
            let inner = tuple
                .get(1..tuple.len().saturating_sub(1))
                .unwrap_or_default();
            let values = split_top(inner, |t| t.is_punct(','));
            let (id, visibility) = match &columns {
                Some(columns) => {
                    let Some(id_at) = columns.iter().position(|c| c == "id") else {
                        continue;
                    };
                    let visibility = match columns.iter().position(|c| c == "public") {
                        None => BucketVisibility::Private,
                        Some(public_at) => values
                            .get(public_at)
                            .map_or(BucketVisibility::Unknown, |v| visibility_of(v)),
                    };
                    (values.get(id_at).and_then(|v| literal_str(v)), visibility)
                }
                None => (
                    values.first().and_then(|v| literal_str(v)),
                    BucketVisibility::Unknown,
                ),
            };
            let Some(id) = id else {
                continue;
            };
            if keep_existing && self.buckets.contains_key(id) {
                continue;
            }
            self.buckets.insert(
                id.to_owned(),
                Bucket {
                    visibility,
                    defined_at: Some(at.clone()),
                },
            );
        }
    }

    pub(super) fn update_buckets(&mut self, cursor: &mut Cursor<'_>) {
        cursor.eat("only");
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        if !is_buckets(&key) {
            return;
        }
        if cursor.eat("as") {
            cursor.identifier();
        }
        if !cursor.eat("set") {
            return;
        }
        let rest = cursor.rest();
        let where_at = top_positions(rest, |t| t.is_word("where")).first().copied();
        let (assignments, condition) = match where_at {
            Some(index) => (&rest[..index], Some(&rest[index + 1..])),
            None => (rest, None),
        };
        if !assignments.iter().any(|t| named(t, "public")) {
            return;
        }
        let simple = split_top(assignments, |t| t.is_punct(','))
            .into_iter()
            .find_map(|assignment| match assignment {
                [target, equals, value @ ..] if named(target, "public") && equals.is_punct('=') => {
                    Some(visibility_of(value))
                }
                _ => None,
            })
            .filter(|visibility| *visibility != BucketVisibility::Unknown);
        let id = condition.and_then(id_equals);
        if let (Some(visibility), Some(id)) = (simple, id) {
            let bucket = self.buckets.entry(id).or_insert(Bucket {
                visibility,
                defined_at: None,
            });
            bucket.visibility = visibility;
        } else {
            for bucket in self.buckets.values_mut() {
                bucket.visibility = BucketVisibility::Unknown;
            }
        }
    }

    pub(super) fn delete_buckets(&mut self, cursor: &mut Cursor<'_>) {
        if !cursor.eat("from") {
            return;
        }
        cursor.eat("only");
        let Some(key) = cursor.qualified_name() else {
            return;
        };
        if !is_buckets(&key) || !cursor.eat("where") {
            return;
        }
        if let Some(id) = id_equals(cursor.rest()) {
            self.buckets.remove(&id);
        }
    }
}
