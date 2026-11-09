use seethru_core::BucketVisibility;

use super::{Condition, Migrations, TableKey, condition, tokenize};

fn apply(sql: &str) -> Migrations {
    let mut migrations = Migrations::default();
    migrations.apply_file("m.sql", sql);
    migrations
}

fn key(schema: &str, name: &str) -> TableKey {
    TableKey {
        schema: schema.to_owned(),
        name: name.to_owned(),
    }
}

fn public(name: &str) -> TableKey {
    key("public", name)
}

fn roles(roles: &super::Roles) -> Vec<&str> {
    roles.0.iter().map(String::as_str).collect()
}

fn cond(sql: &str, storage: bool) -> Condition {
    condition(&tokenize(sql), storage)
}

fn reads(migrations: &Migrations, name: &str) -> Vec<String> {
    migrations.views[&public(name)]
        .reads
        .iter()
        .map(|k| format!("{}.{}", k.schema, k.name))
        .collect()
}

#[test]
fn condition_always_true_forms() {
    for sql in ["true", "(true)", "((1 = 1))", "true and 1 = 1"] {
        let c = cond(sql, false);
        assert!(c.open && !c.signed_in && c.buckets.is_empty(), "{sql}");
    }
    for sql in [
        "",
        "false",
        "1 = 2",
        "true or false",
        "owner = x",
        "true and x",
    ] {
        assert!(!cond(sql, false).open, "{sql}");
    }
}

#[test]
fn condition_login_checks() {
    for sql in [
        "auth.uid() is not null",
        "(select auth.uid()) is not null",
        "((select auth.uid())::text) is not null",
        "auth.role() = 'authenticated'",
        "'authenticated' = auth.role()",
        "(select auth.role()) = 'authenticated'::text",
        "auth.role()::text = 'authenticated'",
        "(auth.uid() is not null) and true",
    ] {
        let c = cond(sql, false);
        assert!(c.open && c.signed_in, "{sql}");
    }
    assert!(!cond("auth.role() = 'anon'", false).open);
    assert!(!cond("auth.uid() = owner_id", false).open);
    assert!(!cond("auth.uid() is null", false).open);
    assert!(!cond("auth.uid() is not null or true", false).open);
}

#[test]
fn condition_buckets_only_for_storage() {
    let c = cond("bucket_id = 'avatars'", true);
    assert!(c.open && !c.signed_in);
    assert_eq!(roles_of(&c), vec!["avatars"]);
    assert!(!cond("bucket_id = 'avatars'", false).open);

    assert_eq!(roles_of(&cond("bucket_id = 'x'::text", true)), vec!["x"]);
    assert_eq!(
        roles_of(&cond("\"bucket_id\" = 'x'::\"text\"", true)),
        vec!["x"]
    );
    assert_eq!(roles_of(&cond("'x' = bucket_id", true)), vec!["x"]);
    assert_eq!(roles_of(&cond("objects.bucket_id = 'x'", true)), vec!["x"]);
    assert_eq!(
        roles_of(&cond("bucket_id in ('a', 'b'::text, 'c')", true)),
        vec!["a", "b", "c"]
    );
    let c = cond("(bucket_id = 'x') and (auth.uid() is not null)", true);
    assert!(c.open && c.signed_in);
    assert_eq!(roles_of(&c), vec!["x"]);
}

fn roles_of(c: &Condition) -> Vec<&str> {
    c.buckets.iter().map(String::as_str).collect()
}

#[test]
fn condition_rejects_other_terms() {
    assert!(!cond("(storage.foldername(name))[1] = auth.uid()::text", true).open);
    let c = cond(
        "bucket_id = 'x' and (storage.foldername(name))[1] = auth.uid()::text",
        true,
    );
    assert!(!c.open && !c.signed_in);
    assert_eq!(roles_of(&c), vec!["x"]);
    assert!(cond("bucket_id = 'x' or true", true).buckets.is_empty());
    assert!(!cond("bucket_id in ('a', lower(b))", true).open);
    assert!(!cond("bucket_id <> 'x'", true).open);
    assert!(!cond("bucket_id = 'x' or true", true).open);
    assert!(!cond("bucket_id not in ('a')", true).open);
    assert!(!cond("x between 1 and 2", true).open);
}

#[test]
fn table_policies_keep_their_meaning() {
    let m = apply(
        "create table t (id int);
         create policy a on t for select using (true);
         create policy b on t for select to authenticated using (auth.uid() is not null);
         create policy c on t for insert with check (1 = 1);",
    );
    let p = |name: &str| &m.policies[&(public("t"), name.to_owned())];
    assert!(p("a").using.open && !p("a").using.signed_in);
    assert!(p("b").using.open && p("b").using.signed_in);
    assert!(p("c").check.open);
}

#[test]
fn storage_policies_plain_and_dump_form() {
    let m = apply(
        "create policy p1 on storage.objects for select using (bucket_id = 'pics');
         CREATE POLICY \"p2\" ON \"storage\".\"objects\" FOR INSERT TO \"authenticated\" WITH CHECK ((\"bucket_id\" = 'pics'::\"text\"));
         create policy p3 on storage.objects for select using ((storage.foldername(name))[1] = auth.uid()::text);",
    );
    let p = |name: &str| &m.policies[&(key("storage", "objects"), name.to_owned())];
    assert!(p("p1").using.open);
    assert_eq!(roles_of(&p("p1").using), vec!["pics"]);
    assert!(p("p2").check.open);
    assert_eq!(roles_of(&p("p2").check), vec!["pics"]);
    assert!(!p("p3").using.open);
}

#[test]
fn function_basic_properties() {
    let m = apply(
        "create function public.f(a int, b text) returns int language sql security definer as $$ select 1 $$;
         create function g() returns int as $$ select 1 $$ language sql;",
    );
    let f = &m.functions[&public("f")];
    assert!(f.security_definer);
    assert_eq!(f.security_at.as_ref().map(|l| l.line), Some(1));
    assert!(!f.returns_trigger && f.owner_is_admin && !f.checks_caller);
    assert_eq!(f.defined_at.path, "m.sql");
    assert_eq!(
        roles(&f.executors),
        vec!["anon", "authenticated", "public", "service_role"]
    );
    let g = &m.functions[&public("g")];
    assert!(!g.security_definer && g.security_at.is_none());
}

#[test]
fn function_attributes_after_body_and_quoted_language() {
    let m = apply(
        "CREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; END; $$ LANGUAGE plpgsql SECURITY DEFINER;
         create function g() returns void security invoker language 'plpgsql' set search_path = '' as $b$ begin end $b$;
         create function h() returns void external security definer stable parallel safe cost 10 language plpgsql as 'select 1';",
    );
    assert!(m.functions[&public("f")].security_definer);
    assert!(!m.functions[&public("g")].security_definer);
    assert!(m.functions[&public("h")].security_definer);
}

#[test]
fn function_boolean_detection() {
    let m = apply(
        "create function a() returns boolean language sql as 'select true';
         CREATE FUNCTION b() RETURNS \"bool\" AS 'select true' LANGUAGE sql;
         create function c() returns setof boolean language sql as 'select true';
         create function d() returns boolean[] language sql as 'select array[true]';
         create function e() returns int language sql as 'select 1';",
    );
    for name in ["a", "b"] {
        assert!(m.functions[&public(name)].returns_boolean, "{name}");
    }
    for name in ["c", "d", "e"] {
        assert!(!m.functions[&public(name)].returns_boolean, "{name}");
    }
}

#[test]
fn function_trigger_detection() {
    let m = apply(
        "create function a() returns trigger language plpgsql as $$ begin return new; end $$;
         CREATE FUNCTION b() RETURNS TRIGGER AS $$ begin return new; end $$ LANGUAGE plpgsql;
         CREATE OR REPLACE FUNCTION \"public\".\"c\"() RETURNS \"trigger\" LANGUAGE \"plpgsql\" AS $$ begin return new; end $$;
         create function d() returns event_trigger language plpgsql as $$ begin end $$;
         create function e() returns table (trigger int) language sql as 'select 1';
         create function f() returns setof public.items language sql as 'select 1';
         create function g() returns int language sql as 'select 1';",
    );
    for name in ["a", "b", "c", "d"] {
        assert!(m.functions[&public(name)].returns_trigger, "{name}");
    }
    for name in ["e", "f", "g"] {
        assert!(!m.functions[&public(name)].returns_trigger, "{name}");
    }
}

#[test]
fn function_body_checks_caller_and_calls() {
    let m = apply(
        "create function a() returns int language sql as $$ select auth.uid() $$;
         create function b() returns int language sql as $$ select (auth.jwt() ->> 'role')::int $$;
         create function c() returns text language sql as $$ select current_setting('request.jwt.claims', true) $$;
         create function d() returns int language sql as $$ select 1 $$;
         create function e() returns int language sql as $$ select auth.email() is not null $$;
         create function f() returns int language sql as $$ select helper(1) + private.other(2) + coalesce(x, 1) + count(*) from t where exists (select 1) $$;
         create function r() returns int language sql return auth.uid() is not null;",
    );
    for name in ["a", "b", "c", "e", "r"] {
        assert!(m.functions[&public(name)].checks_caller, "{name}");
    }
    assert!(!m.functions[&public("d")].checks_caller);
    let calls: Vec<_> = m.functions[&public("f")].calls.iter().cloned().collect();
    assert_eq!(calls, vec![key("private", "other"), public("helper")]);
}

#[test]
fn function_checks_caller_one_level() {
    let m = apply(
        "create function checker() returns bool language sql as $$ select auth.uid() is not null $$;
         create function viaone() returns int language sql as $$ select 1 where checker() $$;
         create function other() returns int language sql as $$ select 1 where viaone() $$;",
    );
    assert!(m.function_checks_caller(&public("checker")));
    assert!(m.function_checks_caller(&public("viaone")));
    assert!(!m.function_checks_caller(&public("other")));
    assert!(!m.function_checks_caller(&public("missing")));
}

#[test]
fn function_replace_keeps_executors_and_owner() {
    let m = apply(
        "create function f() returns int language sql as 'select 1';
         revoke execute on function f() from public, anon;
         alter function f() owner to someone;
         create or replace function f() returns int language sql security definer as $$ select auth.uid() $$;",
    );
    let f = &m.functions[&public("f")];
    assert_eq!(roles(&f.executors), vec!["authenticated", "service_role"]);
    assert!(!f.owner_is_admin);
    assert!(f.security_definer && f.checks_caller);
}

#[test]
fn function_overload_later_definition_wins() {
    let m = apply(
        "create function f(a int) returns int language sql security definer as 'select 1';
         create function f(a text) returns int language sql as 'select 2';",
    );
    assert_eq!(m.functions.len(), 1);
    assert!(!m.functions[&public("f")].security_definer);
}

#[test]
fn function_atomic_body_is_skipped() {
    let m = apply(
        "create function f() returns int language sql security definer begin atomic select 1; end;
         create function g() returns int language sql as 'select 1';",
    );
    assert!(!m.functions.contains_key(&public("f")));
    assert!(m.functions.contains_key(&public("g")));
}

#[test]
fn alter_function_actions() {
    let m = apply(
        "create function f() returns int language sql as 'select 1';
         alter function f() security definer;
         create function g(int) returns int language sql security definer as 'select 1';
         ALTER FUNCTION public.g(int) SECURITY INVOKER OWNER TO \"app\";
         create function h() returns int language sql as 'select 1';
         alter function if exists h external security definer, owner to supabase_admin;
         alter function nothere() security definer;",
    );
    let f = &m.functions[&public("f")];
    assert!(f.security_definer);
    assert_eq!(
        f.security_at.as_ref().map(|l| (l.line, l.column)),
        Some((2, 29))
    );
    let g = &m.functions[&public("g")];
    assert!(!g.security_definer && !g.owner_is_admin);
    let h = &m.functions[&public("h")];
    assert!(h.security_definer && h.owner_is_admin);
    assert!(!m.functions.contains_key(&public("nothere")));
}

#[test]
fn alter_function_rename_and_owner_back() {
    let m = apply(
        "create function old() returns int language sql as 'select 1';
         alter function old() rename to renamed;
         alter function renamed() owner to app;
         alter function renamed() owner to \"postgres\";",
    );
    assert!(!m.functions.contains_key(&public("old")));
    assert!(m.functions[&public("renamed")].owner_is_admin);
}

#[test]
fn drop_function_forms() {
    let m = apply(
        "create function a() returns int language sql as 'select 1';
         create function b(int) returns int language sql as 'select 1';
         create function c() returns int language sql as 'select 1';
         create function d() returns int language sql as 'select 1';
         drop function if exists a();
         drop function public.b(int, text), c cascade;",
    );
    assert_eq!(m.functions.keys().collect::<Vec<_>>(), vec![&public("d")]);
}

#[test]
fn revoke_from_anon_only_leaves_public() {
    let m = apply(
        "create function f() returns int language sql as 'select 1';
         revoke execute on function f() from anon;",
    );
    let f = &m.functions[&public("f")];
    assert!(f.executors.anyone());
    assert!(!f.executors.0.contains("anon"));
    let m = apply(
        "create function f() returns int language sql as 'select 1';
         revoke all on function f() from public;
         revoke execute on function public.f() from anon;",
    );
    let f = &m.functions[&public("f")];
    assert!(!f.executors.anyone());
    assert!(f.executors.signed_in());
}

#[test]
fn revoke_everything_then_grant_back() {
    let m = apply(
        "create function f() returns int language sql as 'select 1';
         revoke all privileges on function f() from public, anon, authenticated, service_role;
         grant execute on function f(int) to authenticated;
         grant select on function f() to anon;",
    );
    assert_eq!(
        roles(&m.functions[&public("f")].executors),
        vec!["authenticated"]
    );
}

#[test]
fn dump_style_grants() {
    let m = apply(
        "CREATE OR REPLACE FUNCTION \"public\".\"f\"() RETURNS \"trigger\" LANGUAGE \"plpgsql\" SECURITY DEFINER AS $$ begin return new; end $$;
         ALTER FUNCTION \"public\".\"f\"() OWNER TO \"postgres\";
         REVOKE ALL ON FUNCTION \"public\".\"f\"() FROM PUBLIC;
         GRANT ALL ON FUNCTION \"public\".\"f\"() TO \"anon\";
         GRANT ALL ON FUNCTION \"public\".\"f\"() TO \"service_role\";",
    );
    let f = &m.functions[&public("f")];
    assert!(f.returns_trigger && f.security_definer && f.owner_is_admin);
    assert_eq!(
        roles(&f.executors),
        vec!["anon", "authenticated", "service_role"]
    );
    assert!(f.executors.anyone());
}

#[test]
fn grant_ignores_revoke_grant_option_and_other_objects() {
    let m = apply(
        "create function f() returns int language sql as 'select 1';
         revoke grant option for execute on function f() from public;
         grant execute on procedure f() to anon;
         grant usage on schema public to anon;
         grant all on sequence s to anon;
         grant execute on function f() to anon with grant option;",
    );
    assert!(m.functions[&public("f")].executors.0.contains("public"));
}

#[test]
fn grant_all_functions_in_schema() {
    let m = apply(
        "create function f() returns int language sql as 'select 1';
         create function private.g() returns int language sql as 'select 1';
         revoke execute on all functions in schema public from public, anon, authenticated;
         grant all on all routines in schema private to anon;
         revoke execute on function f(), g() from service_role;",
    );
    assert!(roles(&m.functions[&public("f")].executors).is_empty());
    assert!(
        m.functions[&key("private", "g")]
            .executors
            .0
            .contains("anon")
    );
}

#[test]
fn default_privileges_in_schema() {
    let m = apply(
        "create function before() returns int language sql as 'select 1';
         alter default privileges in schema public revoke execute on functions from anon, authenticated;
         create function after() returns int language sql as 'select 1';",
    );
    assert_eq!(
        roles(&m.functions[&public("before")].executors),
        vec!["anon", "authenticated", "public", "service_role"]
    );
    assert_eq!(
        roles(&m.functions[&public("after")].executors),
        vec!["public", "service_role"]
    );
}

#[test]
fn default_privileges_global() {
    let m = apply(
        "alter default privileges revoke execute on functions from public;
         create function f() returns int language sql as 'select 1';
         create function other.g() returns int language sql as 'select 1';",
    );
    assert!(!m.functions[&public("f")].executors.0.contains("public"));
    assert!(m.functions[&public("f")].executors.0.contains("anon"));
    assert!(roles(&m.functions[&key("other", "g")].executors).is_empty());
}

#[test]
fn default_privileges_for_role_filter() {
    let m = apply(
        "alter default privileges for role supabase_admin in schema public revoke execute on functions from anon;
         alter default privileges for role postgres, other in schema public revoke execute on functions from authenticated;
         alter default privileges for user postgres grant execute on functions to extra;
         alter default privileges for role other grant execute on functions to ignored;
         alter default privileges in schema public grant execute on routines to later;
         create function f() returns int language sql as 'select 1';",
    );
    assert_eq!(
        roles(&m.functions[&public("f")].executors),
        vec!["anon", "extra", "later", "public", "service_role"]
    );
}

#[test]
fn default_privileges_tables_feed_views() {
    let m = apply(
        "alter default privileges in schema public revoke select on tables from anon;
         create view v1 as select 1;
         alter default privileges grant all on tables to public;
         create view v2 as select 1;
         alter default privileges in schema public revoke grant option for select on tables from authenticated;
         create view v3 as select 1;",
    );
    assert_eq!(
        roles(&m.views[&public("v1")].readers),
        vec!["authenticated", "service_role"]
    );
    assert!(m.views[&public("v2")].readers.0.contains("public"));
    assert!(m.views[&public("v3")].readers.0.contains("authenticated"));
}

#[test]
fn view_grants_and_revokes() {
    let m = apply(
        "create view v as select 1;
         create view w as select 1;
         create view private.x as select 1;
         revoke select on v from anon;
         revoke select (a) on w from anon;
         grant select (a) on private.x to anon;
         grant select on table w, v to public;
         revoke all on all tables in schema public from authenticated;
         grant insert on v to nobody;
         grant select on sequence v to nobody;
         grant select on all tables in schema private to authenticated;",
    );
    assert_eq!(
        roles(&m.views[&public("v")].readers),
        vec!["public", "service_role"]
    );
    assert_eq!(
        roles(&m.views[&public("w")].readers),
        vec!["anon", "public", "service_role"]
    );
    assert_eq!(
        roles(&m.views[&key("private", "x")].readers),
        vec!["anon", "authenticated"]
    );
}

#[test]
fn view_basic_reads() {
    let m = apply(
        "create view v as select a.id, b.x from auth.users au, posts a join public.comments as b on b.post_id = a.id left join \"Users\" u using (id);
         create view only_alias as select * from t1 x, t2 y where x.id = y.id;",
    );
    assert_eq!(
        reads(&m, "v"),
        vec![
            "auth.users",
            "public.Users",
            "public.comments",
            "public.posts"
        ]
    );
    assert_eq!(reads(&m, "only_alias"), vec!["public.t1", "public.t2"]);
}

#[test]
fn view_reads_cte_subquery_and_functions() {
    let m = apply(
        "create view v as
         with recursive base as (select * from real_a), extra (c) as materialized (select 1 from real_b)
         select * from base, extra, (select * from nested_c) s, generate_series(1, 3) g, unnest(arr) as u(n), real_d d
         where exists (select 1 from real_e where extract(year from created_at) = 1)
         and x is distinct from y;
         create view lat as select * from t, lateral (select * from inner_f) l;",
    );
    assert_eq!(
        reads(&m, "v"),
        vec![
            "public.nested_c",
            "public.real_a",
            "public.real_b",
            "public.real_d",
            "public.real_e"
        ]
    );
    assert_eq!(reads(&m, "lat"), vec!["public.inner_f", "public.t"]);
}

#[test]
fn view_shape_and_tails() {
    let m = apply(
        "create or replace view v (a, b) with (security_invoker = true) as select auth.uid(), 1 from t with local check option;
         create materialized view mv as select * from t with no data;
         create temp view tv as select 1;
         create view q as select 1 with data;
         create recursive view r (n) as select 1 union all select n from r;",
    );
    let v = &m.views[&public("v")];
    assert!(v.security_invoker && v.checks_caller && !v.materialized && v.owner_is_admin);
    assert_eq!(reads(&m, "v"), vec!["public.t"]);
    assert!(m.views[&public("mv")].materialized);
    assert_eq!(reads(&m, "mv"), vec!["public.t"]);
    assert!(!m.views.contains_key(&public("tv")));
    assert!(m.views.contains_key(&public("q")));
    assert!(m.views.contains_key(&public("r")));
}

#[test]
fn view_security_invoker_variants() {
    let sql = |option: &str| {
        let m = apply(&format!("create view v with ({option}) as select 1;"));
        m.views[&public("v")].security_invoker
    };
    for yes in [
        "security_invoker",
        "security_invoker = true",
        "security_invoker=on",
        "security_invoker = 'true'",
        "security_invoker = yes",
        "security_invoker = 1",
        "security_barrier, security_invoker",
    ] {
        assert!(sql(yes), "{yes}");
    }
    for no in [
        "security_invoker = false",
        "security_invoker = off",
        "security_invoker = no",
        "security_invoker = 0",
        "security_barrier = true",
    ] {
        assert!(!sql(no), "{no}");
    }
}

#[test]
fn view_replace_keeps_readers_and_owner() {
    let m = apply(
        "create view v as select 1 from a;
         revoke select on v from anon;
         alter view v owner to someone;
         create or replace view v with (security_invoker = on) as select auth.uid() from b;",
    );
    let v = &m.views[&public("v")];
    assert_eq!(roles(&v.readers), vec!["authenticated", "service_role"]);
    assert!(!v.owner_is_admin && v.security_invoker && v.checks_caller);
    assert_eq!(reads(&m, "v"), vec!["public.b"]);
    let m = apply(
        "create view v as select 1;
         create view if not exists v with (security_invoker = true) as select 2 from z;",
    );
    assert!(!m.views[&public("v")].security_invoker);
}

#[test]
fn alter_view_actions() {
    let m = apply(
        "create view v as select 1;
         alter view v set (security_invoker = true);
         create view w with (security_invoker) as select 1;
         alter view if exists public.w reset (security_invoker);
         create materialized view mv as select 1;
         alter materialized view mv owner to app;
         create view t as select 1;
         alter table t owner to app;
         create view u as select 1;
         alter view u rename to u2;
         alter view u2 set (security_barrier = true);
         alter view ghost set (security_invoker = true);",
    );
    assert!(m.views[&public("v")].security_invoker);
    assert!(!m.views[&public("w")].security_invoker);
    assert!(!m.views[&public("mv")].owner_is_admin);
    assert!(!m.views[&public("t")].owner_is_admin);
    assert!(!m.views.contains_key(&public("u")));
    assert!(m.views.contains_key(&public("u2")));
    assert!(!m.views.contains_key(&public("ghost")));
}

#[test]
fn alter_table_rename_moves_view() {
    let m = apply(
        "create view v as select 1;
         alter table v rename to v2;",
    );
    assert!(!m.is_view("public", "v"));
    assert!(m.is_view("public", "v2"));
}

#[test]
fn drop_view_forms() {
    let m = apply(
        "create view a as select 1;
         create materialized view b as select 1;
         create view c as select 1;
         create view d as select 1;
         drop view if exists a;
         drop materialized view b;
         drop view public.c, nothere cascade;",
    );
    assert_eq!(m.views.keys().collect::<Vec<_>>(), vec![&public("d")]);
}

#[test]
fn buckets_insert_forms() {
    let m = apply(
        "insert into storage.buckets (id, name, public) values ('a', 'a', true);
         INSERT INTO \"storage\".\"buckets\" (\"id\", \"name\", \"public\") VALUES ('b', 'b', 'false'), ('c', 'c', 'true'::boolean), ('d', 'd', f());
         insert into storage.buckets (id, name) values ('e', 'e');
         insert into storage.buckets (name, public, id) values ('f', true, 'f') on conflict (id) do nothing;
         insert into storage.buckets values ('g', 'g');
         insert into storage.buckets (id, name) select 'h', 'h';
         insert into storage.buckets (id, name, public) values (var, 'i', true), ('j', 'j', false);",
    );
    let vis = |id: &str| m.buckets.get(id).map(|b| b.visibility);
    assert_eq!(vis("a"), Some(BucketVisibility::Public));
    assert_eq!(vis("b"), Some(BucketVisibility::Private));
    assert_eq!(vis("c"), Some(BucketVisibility::Public));
    assert_eq!(vis("d"), Some(BucketVisibility::Unknown));
    assert_eq!(vis("e"), Some(BucketVisibility::Private));
    assert_eq!(vis("f"), Some(BucketVisibility::Public));
    assert_eq!(vis("g"), Some(BucketVisibility::Unknown));
    assert_eq!(vis("h"), None);
    assert_eq!(vis("i"), None);
    assert_eq!(vis("j"), Some(BucketVisibility::Private));
    assert_eq!(m.buckets["a"].defined_at.as_ref().map(|l| l.line), Some(1));
}

#[test]
fn buckets_on_conflict_do_nothing_keeps_existing() {
    let m = apply(
        "insert into storage.buckets (id, public) values ('a', false);
         insert into storage.buckets (id, public) values ('a', true), ('b', true) on conflict do nothing;
         insert into storage.buckets (id, public) values ('b', false) on conflict (id) do update set public = excluded.public;",
    );
    assert_eq!(m.buckets["a"].visibility, BucketVisibility::Private);
    assert_eq!(m.buckets["b"].visibility, BucketVisibility::Private);
}

#[test]
fn buckets_update_forms() {
    let m = apply(
        "insert into storage.buckets (id, public) values ('a', false), ('b', false);
         update storage.buckets set public = true where id = 'a';
         update storage.buckets set public = true where id = 'ghost';
         update storage.buckets set file_size_limit = 5 where id = 'b';
         update \"storage\".\"buckets\" set \"public\" = 'false'::boolean where 'b' = id;",
    );
    assert_eq!(m.buckets["a"].visibility, BucketVisibility::Public);
    assert_eq!(m.buckets["b"].visibility, BucketVisibility::Private);
    assert_eq!(m.buckets["ghost"].visibility, BucketVisibility::Public);
    assert!(m.buckets["ghost"].defined_at.is_none());
    let m = apply(
        "insert into storage.buckets (id, public) values ('a', false), ('b', true);
         update storage.buckets set public = true where name like 'x%';",
    );
    assert!(
        m.buckets
            .values()
            .all(|b| b.visibility == BucketVisibility::Unknown)
    );
    let m = apply(
        "insert into storage.buckets (id, public) values ('a', false);
         update storage.buckets set public = not public;",
    );
    assert_eq!(m.buckets["a"].visibility, BucketVisibility::Unknown);
}

#[test]
fn buckets_delete_forms() {
    let m = apply(
        "insert into storage.buckets (id, public) values ('a', true), ('b', true), ('c', true);
         delete from storage.buckets where id = 'a';
         delete from storage.buckets where name = 'b';
         delete from storage.buckets;
         delete from other.buckets where id = 'c';",
    );
    assert_eq!(m.buckets.keys().collect::<Vec<_>>(), vec!["b", "c"]);
}

#[test]
fn truncated_input_never_panics() {
    let statements = [
        "create function",
        "create function f(",
        "create function f() returns",
        "create function f() returns setof",
        "create or replace function f() security",
        "create function f() as",
        "alter function",
        "alter function f(",
        "alter function f() owner to",
        "alter function f() rename",
        "drop function",
        "drop function f(",
        "grant",
        "grant select",
        "grant select (",
        "grant select on",
        "grant execute on function",
        "grant execute on function f( to",
        "revoke grant option for",
        "revoke all on all tables in schema",
        "alter default privileges",
        "alter default privileges for",
        "alter default privileges for role",
        "alter default privileges in schema",
        "alter default privileges grant execute on functions to",
        "create view",
        "create view v (",
        "create view v with (",
        "create view v as select * from",
        "create view v as select * from (",
        "create view v as with x as (",
        "create view v as select * from a join",
        "alter view",
        "alter view v set (",
        "alter view v rename to",
        "drop view",
        "insert into storage.buckets",
        "insert into storage.buckets (",
        "insert into storage.buckets (id) values (",
        "insert into storage.buckets (id) values ('a'",
        "insert into storage.buckets (id) values ()",
        "update storage.buckets set",
        "update storage.buckets set public =",
        "update storage.buckets set public = true where",
        "delete from storage.buckets where",
        "delete from storage.buckets where id =",
        "create policy p on storage.objects using (bucket_id in (",
        "create policy p on storage.objects using (bucket_id in ()",
        "create policy p on storage.objects using ((((",
    ];
    for statement in statements {
        let m = apply(statement);
        let _ = (m.functions.len(), m.views.len(), m.buckets.len());
        let mut cumulative = String::new();
        cumulative.push_str(statement);
        let _ = apply(&format!("{cumulative}; create table t (id int);"));
    }
    let _ = cond("(", true);
    let _ = cond(")", true);
    let _ = cond("and", true);
    let _ = cond("bucket_id =", true);
    let _ = cond("auth.uid() is not", false);
}
