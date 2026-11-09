use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, CallExpression, ComputedMemberExpression, ExportAllDeclaration,
    ExportFromDeclaration, Expression, ImportDeclaration, ImportExpression, StaticMemberExpression,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;

pub(crate) const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
const MAX_NESTING: usize = 512;
const MAX_IMPORTS: usize = 2_000;
const SERVER_ONLY_MODULE: &str = "server-only";
const QUERY_METHODS: &[(&str, Access)] = &[
    ("select", Access::Read),
    ("insert", Access::Write),
    ("update", Access::Write),
    ("upsert", Access::Write),
    ("delete", Access::Write),
];
const INTERESTING_ENV_PARTS: &[&str] = &[
    "KEY", "SECRET", "TOKEN", "PASSWORD", "SUPABASE", "DATABASE", "PRIVATE", "SERVICE",
];
const SERVICE_ROLE_ENV_PARTS: &[&str] = &[
    "SERVICE_ROLE",
    "SERVICE_KEY",
    "SUPABASE_SECRET",
    "SB_SECRET",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Access {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Directive {
    UseClient,
    UseServer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvRead {
    pub name: String,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TableQuery {
    pub table: String,
    pub access: Access,
    pub offset: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub directive: Option<Directive>,
    pub server_only: bool,
    pub imports: Vec<String>,
    pub env_reads: Vec<EnvRead>,
    pub queries: Vec<TableQuery>,
}

pub(crate) fn is_interesting_env(name: &str) -> bool {
    INTERESTING_ENV_PARTS.iter().any(|part| name.contains(part))
}

pub(crate) fn is_service_role_env(name: &str) -> bool {
    SERVICE_ROLE_ENV_PARTS
        .iter()
        .any(|part| name.contains(part))
}

pub(crate) fn analyze(rel_path: &str, source: &str) -> Option<Facts> {
    if source.len() > MAX_SCRIPT_BYTES || nesting_depth(source) > MAX_NESTING {
        return None;
    }
    let source_type = SourceType::from_path(rel_path).ok()?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if parsed.fatal_error {
        return None;
    }
    let mut collector = Collector::default();
    for directive in &parsed.program.directives {
        match directive.directive.as_str() {
            "use client" => collector.facts.directive = Some(Directive::UseClient),
            "use server" => collector.facts.directive = Some(Directive::UseServer),
            _ => {}
        }
    }
    collector.visit_program(&parsed.program);
    Some(collector.facts)
}

fn nesting_depth(source: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    for byte in source.bytes() {
        match byte {
            b'(' | b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

#[derive(Default)]
struct Collector {
    facts: Facts,
}

impl Collector {
    fn import(&mut self, specifier: &str) {
        if specifier == SERVER_ONLY_MODULE {
            self.facts.server_only = true;
        } else if self.facts.imports.len() < MAX_IMPORTS
            && !self.facts.imports.iter().any(|seen| seen == specifier)
        {
            self.facts.imports.push(specifier.to_owned());
        }
    }

    fn env_read(&mut self, name: &str, offset: u32) {
        if is_interesting_env(name) {
            self.facts.env_reads.push(EnvRead {
                name: name.to_owned(),
                offset: offset as usize,
            });
        }
    }
}

fn is_env_object(expr: &Expression<'_>) -> bool {
    if expr.is_specific_member_access("process", "env") {
        return true;
    }
    match expr.get_inner_expression() {
        Expression::StaticMemberExpression(member) => {
            member.property.name.as_str() == "env"
                && matches!(
                    member.object.get_inner_expression(),
                    Expression::ImportMeta(_)
                )
        }
        _ => false,
    }
}

fn is_storage(expr: &Expression<'_>) -> bool {
    matches!(
        expr.get_inner_expression(),
        Expression::StaticMemberExpression(member) if member.property.name.as_str() == "storage"
    )
}

fn literal_text<'a>(expr: &Expression<'a>) -> Option<&'a str> {
    match expr.get_inner_expression() {
        Expression::StringLiteral(literal) => literal.value.as_str(),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            template.quasis.first()?.value.cooked?.as_str()
        }
        _ => None,
    }
}

fn first_literal<'a>(arguments: &[Argument<'a>]) -> Option<&'a str> {
    literal_text(arguments.first()?.as_expression()?)
}

impl<'a> Visit<'a> for Collector {
    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if !it.import_kind.is_type()
            && let Some(specifier) = it.source.value.as_str()
        {
            self.import(specifier);
        }
    }

    fn visit_export_from_declaration(&mut self, it: &ExportFromDeclaration<'a>) {
        if !it.export_kind.is_type()
            && let Some(specifier) = it.source.value.as_str()
        {
            self.import(specifier);
        }
    }

    fn visit_export_all_declaration(&mut self, it: &ExportAllDeclaration<'a>) {
        if !it.export_kind.is_type()
            && let Some(specifier) = it.source.value.as_str()
        {
            self.import(specifier);
        }
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if let Some(specifier) = literal_text(&it.source) {
            self.import(specifier);
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if is_env_object(&it.object) {
            self.env_read(it.property.name.as_str(), it.span.start);
        }
        walk::walk_static_member_expression(self, it);
    }

    fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
        if is_env_object(&it.object)
            && let Some(name) = literal_text(&it.expression)
        {
            self.env_read(name, it.span.start);
        }
        walk::walk_computed_member_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = it.callee.get_inner_expression()
            && callee.name.as_str() == "require"
            && let Some(specifier) = first_literal(&it.arguments)
        {
            self.import(specifier);
        }
        if let Expression::StaticMemberExpression(callee) = it.callee.get_inner_expression() {
            let method = callee.property.name.as_str();
            if method == "get"
                && callee.object.is_specific_member_access("Deno", "env")
                && let Some(name) = first_literal(&it.arguments)
            {
                self.env_read(name, it.span.start);
            }
            if let Some((_, access)) = QUERY_METHODS.iter().find(|(name, _)| *name == method)
                && let Expression::CallExpression(from_call) = callee.object.get_inner_expression()
                && let Expression::StaticMemberExpression(from) =
                    from_call.callee.get_inner_expression()
                && from.property.name.as_str() == "from"
                && !is_storage(&from.object)
                && let Some(table) = first_literal(&from_call.arguments)
            {
                self.facts.queries.push(TableQuery {
                    table: table.to_owned(),
                    access: *access,
                    offset: from_call.span.start as usize,
                });
            }
        }
        walk::walk_call_expression(self, it);
    }
}

#[cfg(test)]
mod tests {
    use super::{Access, Directive, analyze, is_service_role_env};

    fn names(source: &str) -> Vec<String> {
        analyze("src/a.ts", source)
            .map(|facts| facts.env_reads.into_iter().map(|read| read.name).collect())
            .unwrap_or_default()
    }

    #[test]
    fn finds_env_reads_in_every_common_form() {
        let source = r#"
            const a = import.meta.env.VITE_SUPABASE_URL;
            const b = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
            const c = process.env["STRIPE_SECRET_KEY"];
            const d = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
            const e = (import.meta as any).env.VITE_CAST_SUPABASE_KEY;
            const f = import.meta.env.MODE;
        "#;
        assert_eq!(
            names(source),
            vec![
                "VITE_SUPABASE_URL",
                "NEXT_PUBLIC_SUPABASE_ANON_KEY",
                "STRIPE_SECRET_KEY",
                "SUPABASE_SERVICE_ROLE_KEY",
                "VITE_CAST_SUPABASE_KEY",
            ]
        );
    }

    #[test]
    fn finds_supabase_table_queries_with_access() {
        let source = r#"
            await supabase.from("todos").select("*").eq("done", false);
            await supabase.from(`notes`).insert({ body });
            await client.from('profiles').update({ name }).eq('id', id);
            await supabase.storage.from("avatars").upload(path, file);
            await supabase.storage.from("avatars").update(path, file);
            await supabase.storage.from("avatars").remove([path]);
            Array.from("abc");
            await supabase.from(tableName).select();
        "#;
        let facts = analyze("src/a.tsx", source).unwrap_or_default();
        let queries: Vec<(&str, Access)> = facts
            .queries
            .iter()
            .map(|query| (query.table.as_str(), query.access))
            .collect();
        assert_eq!(
            queries,
            vec![
                ("todos", Access::Read),
                ("notes", Access::Write),
                ("profiles", Access::Write)
            ]
        );
    }

    #[test]
    fn reads_framework_directives() {
        let client = analyze(
            "app/page.tsx",
            "'use client';\nexport default function P() { return <div/>; }",
        );
        assert_eq!(
            client.and_then(|facts| facts.directive),
            Some(Directive::UseClient)
        );
        let server = analyze(
            "app/actions.ts",
            "\"use server\";\nexport async function a() {}",
        );
        assert_eq!(
            server.and_then(|facts| facts.directive),
            Some(Directive::UseServer)
        );
    }

    #[test]
    fn collects_runtime_imports_and_skips_type_only_ones() {
        let source = r#"
            import "server-only";
            import React from "react";
            import { a } from "./a";
            import type { B } from "./b";
            export { c } from "@/c";
            export type { D } from "./d";
            export * from "../e";
            const f = await import("./f");
            const g = require("./g");
            import { a as again } from "./a";
        "#;
        let facts = analyze("src/x.ts", source).unwrap_or_default();
        assert!(facts.server_only);
        assert_eq!(
            facts.imports,
            vec!["react", "./a", "@/c", "../e", "./f", "./g"]
        );
    }

    #[test]
    fn rejects_unparseable_or_hostile_input() {
        assert!(analyze("src/a.ts", &"(".repeat(10_000)).is_none());
        assert!(analyze("src/a.unknown", "const a = 1;").is_none());
    }

    #[test]
    fn recognizes_service_role_env_names() {
        assert!(is_service_role_env("VITE_SUPABASE_SERVICE_ROLE_KEY"));
        assert!(is_service_role_env("SUPABASE_SERVICE_KEY"));
        assert!(!is_service_role_env("VITE_SUPABASE_ANON_KEY"));
    }
}
