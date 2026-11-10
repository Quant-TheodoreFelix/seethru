use std::collections::BTreeMap;

use oxc_ast::ast::{
    Argument, ArrowFunctionExpression, AssignmentTarget, BinaryOperator, CallExpression,
    ChainElement, Declaration, ExportAllDeclaration, ExportDeclaration, ExportDefaultDeclaration,
    ExportDefaultDeclarationKind, ExportFromDeclaration, ExportNamedDeclaration, Expression,
    Function, IdentifierReference, IfStatement, ImportDeclaration, ImportDeclarationSpecifier,
    LogicalOperator, MethodDefinition, ModuleExportName, NewExpression, ObjectProperty,
    ObjectPropertyKind, Program, PropertyKey, ReturnStatement, Statement, TryStatement,
    UnaryOperator, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{ScopeFlags, Scoping, SymbolId};
use seethru_core::{Location, SecretKind};

use super::catalog::{
    EXIT_CALLS, STORAGE_OPS, TABLE_OPS, auth_like, is_clerk, is_jose, is_jsonwebtoken,
    is_next_auth, is_secret_name, is_supabase_js, is_supabase_ssr,
};
use super::model::{
    Access, CallSite, Candidate, ExportTarget, FileFlow, FlowFunction, Imported, Matcher, Op,
    Strength, Target, Value,
};
use crate::Lines;

const MAX_FUNCTIONS: usize = 2_000;
const MAX_CALLS: usize = 20_000;
const MAX_COVER: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Returns,
    Throws,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Return,
    Throw,
}

impl Exit {
    fn exits_caller(self) -> bool {
        self == Self::Throw
    }
}

struct Check {
    strength: Strength,
    form: Form,
    name: &'static str,
}

struct Buffered {
    check: Option<Check>,
    callee: Option<Value>,
    name: String,
    location: Location,
}

#[derive(Default)]
struct Context {
    index: usize,
    frames: Vec<Vec<u32>>,
    last_frame: Vec<u32>,
    buffers: Vec<Vec<Buffered>>,
    pending: BTreeMap<SymbolId, (Strength, &'static str)>,
    results: BTreeMap<SymbolId, (Value, String)>,
}

pub(crate) fn collect(
    program: &Program<'_>,
    scoping: &Scoping,
    rel_path: &str,
    lines: &Lines<'_>,
) -> FileFlow {
    let mut collector = Collector {
        scoping,
        rel_path,
        lines,
        flow: FileFlow::default(),
        stack: Vec::new(),
        name_hint: None,
        calls_seen: 0,
    };
    collector.visit_program(program);
    collector.flow
}

struct Collector<'s> {
    scoping: &'s Scoping,
    rel_path: &'s str,
    lines: &'s Lines<'s>,
    flow: FileFlow,
    stack: Vec<Context>,
    name_hint: Option<String>,
    calls_seen: usize,
}

fn strip<'e, 'a>(expr: &'e Expression<'a>) -> &'e Expression<'a> {
    let mut current = expr.get_inner_expression();
    while let Expression::AwaitExpression(inner) = current {
        current = inner.argument.get_inner_expression();
    }
    current
}

fn is_function_like(expr: &Expression<'_>) -> bool {
    matches!(
        expr.get_inner_expression(),
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
    )
}

fn literal(expr: &Expression<'_>) -> Option<String> {
    match strip(expr) {
        Expression::StringLiteral(text) => text.value.as_str().map(str::to_owned),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
            .quasis
            .first()?
            .value
            .cooked?
            .as_str()
            .map(str::to_owned),
        _ => None,
    }
}

fn first_literal(arguments: &[Argument<'_>]) -> Option<String> {
    literal(arguments.first()?.as_expression()?)
}

fn export_name(name: &ModuleExportName<'_>) -> String {
    name.name().as_str().to_owned()
}

fn property_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str().to_owned()),
        PropertyKey::StringLiteral(text) => text.value.as_str().map(str::to_owned),
        _ => None,
    }
}

fn member_property<'e, 'a>(expr: &'e Expression<'a>) -> Option<(&'e Expression<'a>, &'e str)> {
    match strip(expr) {
        Expression::StaticMemberExpression(member) => {
            Some((&member.object, member.property.name.as_str()))
        }
        Expression::ChainExpression(chain) => match &chain.expression {
            ChainElement::StaticMemberExpression(member) => {
                Some((&member.object, member.property.name.as_str()))
            }
            _ => None,
        },
        _ => None,
    }
}

fn call_of<'e, 'a>(expr: &'e Expression<'a>) -> Option<&'e CallExpression<'a>> {
    match strip(expr) {
        Expression::CallExpression(call) => Some(call),
        Expression::ChainExpression(chain) => match &chain.expression {
            ChainElement::CallExpression(call) => Some(call),
            _ => None,
        },
        _ => None,
    }
}

fn is_named_member(expr: &Expression<'_>, name: &str) -> bool {
    member_property(expr).is_some_and(|(_, property)| property == name)
}

fn is_global(expr: &Expression<'_>, name: &str) -> bool {
    matches!(strip(expr), Expression::Identifier(id) if id.name.as_str() == name)
}

fn exit_of(statement: &Statement<'_>) -> Option<Exit> {
    match statement {
        Statement::ReturnStatement(statement) => {
            let redirects = statement
                .argument
                .as_ref()
                .and_then(|argument| call_of(argument))
                .is_some_and(|call| {
                    matches!(strip(&call.callee), Expression::Identifier(id) if EXIT_CALLS.contains(&id.name.as_str()))
                });
            Some(if redirects { Exit::Throw } else { Exit::Return })
        }
        Statement::ThrowStatement(_) => Some(Exit::Throw),
        Statement::ExpressionStatement(expression) => {
            let call = call_of(&expression.expression)?;
            match strip(&call.callee) {
                Expression::Identifier(id) if EXIT_CALLS.contains(&id.name.as_str()) => {
                    Some(Exit::Throw)
                }
                _ => None,
            }
        }
        Statement::BlockStatement(block) => block.body.iter().find_map(exit_of),
        _ => None,
    }
}

fn mentions_denied_status(statement: &Statement<'_>) -> bool {
    struct Finder(bool);
    impl<'a> Visit<'a> for Finder {
        fn visit_numeric_literal(&mut self, it: &oxc_ast::ast::NumericLiteral<'a>) {
            if it.value == 401.0 || it.value == 403.0 {
                self.0 = true;
            }
        }
    }
    let mut finder = Finder(false);
    finder.visit_statement(statement);
    finder.0
}

enum Atom<'e, 'a> {
    Ref(SymbolId),
    Call(&'e CallExpression<'a>),
    Secret,
}

impl<'s> Collector<'s> {
    fn location(&self, offset: u32) -> Location {
        self.lines.location(self.rel_path, offset as usize)
    }

    fn context(&mut self) -> Option<&mut Context> {
        self.stack.last_mut()
    }

    fn current(&mut self) -> Option<&mut FlowFunction> {
        let index = self.stack.last()?.index;
        self.flow.functions.get_mut(index)
    }

    fn symbol_of(&self, id: &IdentifierReference<'_>) -> Option<SymbolId> {
        let reference = id.reference_id.get()?;
        self.scoping.get_reference(reference).symbol_id()
    }

    fn import_of(&self, expr: &Expression<'_>) -> Option<&(String, Imported)> {
        match strip(expr) {
            Expression::Identifier(id) => self.flow.imports.get(&self.symbol_of(id)?),
            _ => None,
        }
    }

    fn named_import(&self, expr: &Expression<'_>) -> Option<(&str, &str)> {
        match self.import_of(expr)? {
            (specifier, Imported::Named(name)) => Some((specifier.as_str(), name.as_str())),
            _ => None,
        }
    }

    fn start_function(&mut self, name: Option<String>, offset: u32) -> Option<usize> {
        if self.flow.functions.len() >= MAX_FUNCTIONS {
            self.flow.opaque = true;
            return None;
        }
        let index = self.flow.functions.len();
        self.flow.functions.push(FlowFunction {
            name: name
                .or_else(|| self.name_hint.take())
                .unwrap_or_else(|| "<anonymous>".to_owned()),
            location: self.location(offset),
            returns: Vec::new(),
            calls: Vec::new(),
            accesses: Vec::new(),
            candidates: Vec::new(),
        });
        self.name_hint = None;
        self.stack.push(Context {
            index,
            ..Context::default()
        });
        Some(index)
    }

    fn cover(&self) -> Vec<u32> {
        let Some(context) = self.stack.last() else {
            return Vec::new();
        };
        let mut cover: Vec<u32> = context.frames.iter().flatten().copied().collect();
        cover.sort_unstable();
        cover.dedup();
        cover.truncate(MAX_COVER);
        cover
    }

    fn is_top(&self) -> bool {
        self.stack
            .last()
            .is_some_and(|context| context.frames.len() == 1)
    }

    fn add_candidate(&mut self, candidate: Candidate) -> Option<u32> {
        let function = self.current()?;
        let id = u32::try_from(function.candidates.len()).ok()?;
        function.candidates.push(candidate);
        Some(id)
    }

    fn activate(&mut self, candidate: Candidate) {
        if let Some(id) = self.add_candidate(candidate)
            && let Some(frame) = self.context().and_then(|context| context.frames.last_mut())
        {
            frame.push(id);
        }
    }

    fn value_of(&self, expr: &Expression<'_>) -> Value {
        let expr = strip(expr);
        if let Some(name) = self.env_name(expr) {
            return Value::Env(name);
        }
        match expr {
            Expression::Identifier(id) => match self.symbol_of(id) {
                Some(symbol) => Value::Binding(symbol),
                None => Value::Global(id.name.as_str().to_owned()),
            },
            Expression::StaticMemberExpression(member) => match strip(&member.object) {
                Expression::Identifier(object) => match self.symbol_of(object) {
                    Some(symbol)
                        if matches!(
                            self.flow.imports.get(&symbol),
                            Some((_, Imported::Namespace))
                        ) =>
                    {
                        Value::Member(symbol, member.property.name.as_str().to_owned())
                    }
                    _ => Value::Unknown,
                },
                _ => Value::Unknown,
            },
            Expression::CallExpression(call) => {
                if self.is_supabase_constructor(call) {
                    let key = call
                        .arguments
                        .get(1)
                        .and_then(Argument::as_expression)
                        .map_or(Value::Unknown, |key| self.value_of(key));
                    return Value::Client {
                        key: Box::new(key),
                        location: self.location(call.span.start),
                    };
                }
                Value::Call(Box::new(self.value_of(&call.callee)))
            }
            Expression::LogicalExpression(logical)
                if matches!(
                    logical.operator,
                    LogicalOperator::Coalesce | LogicalOperator::Or
                ) =>
            {
                self.value_of(&logical.left)
            }
            Expression::StringLiteral(_) | Expression::TemplateLiteral(_) => match literal(expr) {
                Some(text) if is_service_literal(&text) => Value::SecretLiteral,
                _ => Value::Unknown,
            },
            _ => Value::Unknown,
        }
    }

    fn env_name(&self, expr: &Expression<'_>) -> Option<String> {
        match expr {
            Expression::StaticMemberExpression(member) if is_env_object(&member.object) => {
                Some(member.property.name.as_str().to_owned())
            }
            Expression::ComputedMemberExpression(member) if is_env_object(&member.object) => {
                literal(&member.expression)
            }
            Expression::CallExpression(call)
                if call.callee.is_specific_member_access("Deno", "env")
                    || matches!(
                        strip(&call.callee),
                        Expression::StaticMemberExpression(member)
                            if member.property.name.as_str() == "get"
                                && member.object.is_specific_member_access("Deno", "env")
                    ) =>
            {
                first_literal(&call.arguments)
            }
            _ => None,
        }
    }

    fn is_supabase_constructor(&self, call: &CallExpression<'_>) -> bool {
        if let Some((specifier, name)) = self.named_import(&call.callee) {
            return (name == "createClient" && is_supabase_js(specifier))
                || ((name == "createServerClient" || name == "createBrowserClient")
                    && is_supabase_ssr(specifier));
        }
        if let Some((object, property)) = member_property(&call.callee)
            && property == "createClient"
            && let Some((specifier, Imported::Namespace)) = self.import_of(object)
        {
            return is_supabase_js(specifier);
        }
        false
    }

    fn check_of(&self, call: &CallExpression<'_>) -> Option<Check> {
        let check = |strength, form, name| {
            Some(Check {
                strength,
                form,
                name,
            })
        };
        if let Some((object, property)) = member_property(&call.callee) {
            return match property {
                "getUser" if is_named_member(object, "auth") => {
                    check(Strength::Verified, Form::Returns, "getUser")
                }
                "getClaims" if is_named_member(object, "auth") => {
                    check(Strength::Verified, Form::Returns, "getClaims")
                }
                "getSession" if is_named_member(object, "auth") => {
                    check(Strength::Weak, Form::Returns, "getSession")
                }
                "constructEvent" | "constructEventAsync" if is_named_member(object, "webhooks") => {
                    check(Strength::Verified, Form::Throws, "constructEvent")
                }
                "verifyIdToken" => check(Strength::Verified, Form::Throws, "verifyIdToken"),
                "verifySessionCookie" => {
                    check(Strength::Verified, Form::Throws, "verifySessionCookie")
                }
                "protect"
                    if is_global(object, "auth")
                        || self
                            .named_import(object)
                            .is_some_and(|(specifier, _)| is_clerk(specifier))
                        || call_of(object).is_some_and(|inner| {
                            self.named_import(&inner.callee)
                                .is_some_and(|(specifier, _)| is_clerk(specifier))
                        }) =>
                {
                    check(Strength::Verified, Form::Throws, "protect")
                }
                "jwtVerify"
                    if self
                        .import_of(object)
                        .is_some_and(|(specifier, _)| is_jose(specifier)) =>
                {
                    check(Strength::Verified, Form::Throws, "jwtVerify")
                }
                "verify"
                    if self
                        .import_of(object)
                        .is_some_and(|(specifier, _)| is_jsonwebtoken(specifier)) =>
                {
                    check(Strength::Verified, Form::Throws, "verify")
                }
                "timingSafeEqual" => check(Strength::Verified, Form::Returns, "timingSafeEqual"),
                _ => None,
            };
        }
        let (specifier, name) = self.named_import(&call.callee)?;
        match name {
            "getServerSession" if is_next_auth(specifier) => {
                check(Strength::Verified, Form::Returns, "getServerSession")
            }
            "auth" if is_clerk(specifier) => check(Strength::Verified, Form::Returns, "auth"),
            "currentUser" if is_clerk(specifier) => {
                check(Strength::Verified, Form::Returns, "currentUser")
            }
            "jwtVerify" if is_jose(specifier) => {
                check(Strength::Verified, Form::Throws, "jwtVerify")
            }
            "verify" if is_jsonwebtoken(specifier) => {
                check(Strength::Verified, Form::Throws, "verify")
            }
            "timingSafeEqual" => check(Strength::Verified, Form::Returns, "timingSafeEqual"),
            _ => None,
        }
    }

    fn callee_value(&self, call: &CallExpression<'_>) -> Option<Value> {
        match strip(&call.callee) {
            Expression::Identifier(_) => Some(self.value_of(&call.callee)),
            Expression::StaticMemberExpression(_) => match self.value_of(&call.callee) {
                Value::Member(symbol, name) => Some(Value::Member(symbol, name)),
                _ => None,
            },
            _ => None,
        }
    }

    fn callee_name(call: &CallExpression<'_>) -> String {
        match strip(&call.callee) {
            Expression::Identifier(id) => id.name.as_str().to_owned(),
            _ => member_property(&call.callee)
                .map(|(_, property)| property.to_owned())
                .unwrap_or_default(),
        }
    }

    fn record_access(&mut self, call: &CallExpression<'_>) {
        let Some((object, method)) = member_property(&call.callee) else {
            return;
        };
        let found = if let Some((_, write)) = TABLE_OPS.iter().find(|(name, _)| *name == method)
            && let Some(from) = call_of(object)
            && let Some((receiver, "from")) = member_property(&from.callee)
            && let Some(table) = first_literal(&from.arguments)
        {
            if let Some((client, "storage")) = member_property(receiver) {
                STORAGE_OPS
                    .iter()
                    .find(|(name, _)| *name == method)
                    .map(|(_, write)| (client, *write, Target::Bucket(table)))
            } else {
                Some((receiver, *write, Target::Table(table)))
            }
        } else if let Some((_, write)) = STORAGE_OPS.iter().find(|(name, _)| *name == method)
            && let Some(from) = call_of(object)
            && let Some((storage, "from")) = member_property(&from.callee)
            && let Some((client, "storage")) = member_property(storage)
        {
            let bucket = first_literal(&from.arguments).unwrap_or_default();
            Some((client, *write, Target::Bucket(bucket)))
        } else {
            None
        };
        let access = if let Some((receiver, write, target)) = found {
            Some((
                self.value_of(receiver),
                if write { Op::Write } else { Op::Read },
                target,
            ))
        } else if method == "rpc" {
            let name = first_literal(&call.arguments).unwrap_or_default();
            Some((self.value_of(object), Op::Rpc, Target::Function(name)))
        } else if let Some((auth, "admin")) = member_property(object)
            && let Some((client, "auth")) = member_property(auth)
        {
            Some((
                self.value_of(client),
                Op::Admin,
                Target::Admin(method.to_owned()),
            ))
        } else {
            None
        };
        if let Some((receiver, op, target)) = access {
            let location = self.location(call.span.start);
            let cover = self.cover();
            if let Some(function) = self.current() {
                function.accesses.push(Access {
                    receiver,
                    op,
                    target,
                    location,
                    cover,
                });
            }
        }
    }

    fn after_statement(&mut self, statement: &Statement<'_>, buffered: Vec<Buffered>) {
        match statement {
            Statement::ExpressionStatement(expression) => {
                self.statement_calls(buffered);
                if let Expression::AssignmentExpression(assign) = strip(&expression.expression)
                    && let AssignmentTarget::AssignmentTargetIdentifier(target) = &assign.left
                    && let Some(symbol) = self.symbol_of(target)
                {
                    self.bind_result(&[symbol], &assign.right);
                }
            }
            Statement::VariableDeclaration(declaration) => {
                self.statement_calls(buffered);
                for declarator in &declaration.declarations {
                    let Some(init) = &declarator.init else {
                        continue;
                    };
                    let symbols: Vec<SymbolId> = declarator
                        .id
                        .get_binding_identifiers()
                        .iter()
                        .filter_map(|id| id.symbol_id.get())
                        .collect();
                    self.bind_result(&symbols, init);
                }
            }
            Statement::IfStatement(branch) => self.exit_branch(branch),
            _ => {}
        }
    }

    fn statement_calls(&mut self, buffered: Vec<Buffered>) {
        let top = self.is_top();
        for call in buffered {
            match call.check {
                Some(Check {
                    form: Form::Throws,
                    strength,
                    name,
                }) => self.activate(Candidate::Guard {
                    strength,
                    exits_caller: true,
                    top,
                    name: name.to_owned(),
                    location: call.location,
                }),
                Some(Check {
                    form: Form::Returns,
                    strength,
                    ..
                }) => self.activate(Candidate::Pending { strength }),
                None => match call.callee {
                    Some(callee) => self.activate(Candidate::CallGuard {
                        callee,
                        name: call.name,
                        tested: false,
                        top,
                    }),
                    None if auth_like(&call.name) => self.activate(Candidate::Unknown),
                    None => {}
                },
            }
        }
    }

    fn bind_result(&mut self, symbols: &[SymbolId], init: &Expression<'_>) {
        if symbols.is_empty() {
            return;
        }
        let check = self.find_check(init);
        let derived = self.pending_ref(init);
        let result = call_of(init).and_then(|call| {
            if self.check_of(call).is_some() || self.is_supabase_constructor(call) {
                return None;
            }
            self.callee_value(call)
                .map(|callee| (callee, Self::callee_name(call)))
        });
        let Some(context) = self.context() else {
            return;
        };
        for symbol in symbols {
            if let Some(found) = check.or(derived) {
                context.pending.insert(*symbol, found);
            } else if let Some(result) = &result {
                context.results.insert(*symbol, result.clone());
            }
        }
    }

    fn find_check(&self, expr: &Expression<'_>) -> Option<(Strength, &'static str)> {
        struct Finder<'c, 's> {
            collector: &'c Collector<'s>,
            found: Option<(Strength, &'static str)>,
        }
        impl<'a> Visit<'a> for Finder<'_, '_> {
            fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
                if self.found.is_none()
                    && let Some(check) = self.collector.check_of(it)
                    && check.form == Form::Returns
                {
                    self.found = Some((check.strength, check.name));
                }
                walk::walk_call_expression(self, it);
            }
            fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
            fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
        }
        let mut finder = Finder {
            collector: self,
            found: None,
        };
        finder.visit_expression(expr);
        finder.found
    }

    fn pending_ref(&self, expr: &Expression<'_>) -> Option<(Strength, &'static str)> {
        let context = self.stack.last()?;
        let mut found = None;
        self.each_ref(expr, &mut |symbol| {
            if found.is_none() {
                found = context.pending.get(&symbol).copied();
            }
        });
        found
    }

    fn each_ref(&self, expr: &Expression<'_>, visit: &mut dyn FnMut(SymbolId)) {
        struct Refs<'c, 's, 'f> {
            collector: &'c Collector<'s>,
            visit: &'f mut dyn FnMut(SymbolId),
        }
        impl<'a> Visit<'a> for Refs<'_, '_, '_> {
            fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
                if let Some(symbol) = self.collector.symbol_of(it) {
                    (self.visit)(symbol);
                }
            }
            fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
            fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
        }
        let mut refs = Refs {
            collector: self,
            visit,
        };
        refs.visit_expression(expr);
    }

    fn mentions_secret(&self, expr: &Expression<'_>) -> bool {
        struct Finder<'c, 's> {
            collector: &'c Collector<'s>,
            found: bool,
        }
        impl<'a> Visit<'a> for Finder<'_, '_> {
            fn visit_expression(&mut self, it: &Expression<'a>) {
                if let Some(name) = self.collector.env_name(strip(it))
                    && is_secret_name(&name)
                {
                    self.found = true;
                    return;
                }
                if let Expression::Identifier(id) = strip(it)
                    && let Some(symbol) = self.collector.symbol_of(id)
                    && let Some(Value::Env(name)) = self.collector.flow.bindings.get(&symbol)
                    && is_secret_name(name)
                {
                    self.found = true;
                    return;
                }
                walk::walk_expression(self, it);
            }
        }
        let mut finder = Finder {
            collector: self,
            found: false,
        };
        finder.visit_expression(expr);
        finder.found
    }

    fn failure_atoms<'e, 'a>(
        &self,
        test: &'e Expression<'a>,
        atoms: &mut Vec<Atom<'e, 'a>>,
        partial: &mut bool,
    ) {
        match strip(test) {
            Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
                self.success_atoms(&unary.argument, atoms);
            }
            Expression::LogicalExpression(logical) => match logical.operator {
                LogicalOperator::Or | LogicalOperator::Coalesce => {
                    self.failure_atoms(&logical.left, atoms, partial);
                    self.failure_atoms(&logical.right, atoms, partial);
                }
                LogicalOperator::And => {
                    let mut inner = Vec::new();
                    self.failure_atoms(&logical.left, &mut inner, partial);
                    self.failure_atoms(&logical.right, &mut inner, partial);
                    if self.relevant(&inner) {
                        *partial = true;
                    }
                }
            },
            Expression::BinaryExpression(binary) => match binary.operator {
                BinaryOperator::Equality | BinaryOperator::StrictEquality => {
                    let nullish = |expr: &Expression<'_>| {
                        matches!(strip(expr), Expression::NullLiteral(_))
                            || is_global(expr, "undefined")
                            || literal(expr).as_deref() == Some("undefined")
                    };
                    if nullish(&binary.right) {
                        self.ref_atoms(&binary.left, atoms);
                    } else if nullish(&binary.left) {
                        self.ref_atoms(&binary.right, atoms);
                    }
                }
                BinaryOperator::Inequality | BinaryOperator::StrictInequality => {
                    if self.mentions_secret(&binary.left) || self.mentions_secret(&binary.right) {
                        atoms.push(Atom::Secret);
                    }
                    self.ref_atoms(&binary.left, atoms);
                    self.ref_atoms(&binary.right, atoms);
                }
                _ => {}
            },
            Expression::Identifier(id) if id.name.as_str().to_ascii_lowercase().contains("err") => {
                if let Some(symbol) = self.symbol_of(id) {
                    atoms.push(Atom::Ref(symbol));
                }
            }
            Expression::StaticMemberExpression(member)
                if member
                    .property
                    .name
                    .as_str()
                    .to_ascii_lowercase()
                    .contains("err") =>
            {
                self.ref_atoms(&member.object, atoms);
            }
            _ => {}
        }
    }

    fn relevant(&self, atoms: &[Atom<'_, '_>]) -> bool {
        let Some(context) = self.stack.last() else {
            return false;
        };
        atoms.iter().any(|atom| match atom {
            Atom::Secret => true,
            Atom::Ref(symbol) => {
                context.pending.contains_key(symbol) || context.results.contains_key(symbol)
            }
            Atom::Call(call) => {
                self.check_of(call).is_some()
                    || self.callee_value(call).is_some()
                    || auth_like(&Self::callee_name(call))
            }
        })
    }

    fn success_atoms<'e, 'a>(&self, test: &'e Expression<'a>, atoms: &mut Vec<Atom<'e, 'a>>) {
        match strip(test) {
            Expression::LogicalExpression(logical) if logical.operator == LogicalOperator::And => {
                self.success_atoms(&logical.left, atoms);
                self.success_atoms(&logical.right, atoms);
            }
            Expression::BinaryExpression(binary)
                if matches!(
                    binary.operator,
                    BinaryOperator::Equality | BinaryOperator::StrictEquality
                ) =>
            {
                if self.mentions_secret(&binary.left) || self.mentions_secret(&binary.right) {
                    atoms.push(Atom::Secret);
                }
            }
            Expression::UnaryExpression(_) | Expression::LogicalExpression(_) => {}
            _ => self.ref_atoms(test, atoms),
        }
    }

    fn ref_atoms<'e, 'a>(&self, expr: &'e Expression<'a>, atoms: &mut Vec<Atom<'e, 'a>>) {
        if let Some(call) = call_of(expr) {
            atoms.push(Atom::Call(call));
            return;
        }
        let mut found = Vec::new();
        self.each_ref(expr, &mut |symbol| found.push(symbol));
        atoms.extend(found.into_iter().map(Atom::Ref));
    }

    fn guard_from_atoms(
        &self,
        atoms: &[Atom<'_, '_>],
        exits_caller: bool,
        top: bool,
        at: u32,
    ) -> Vec<Candidate> {
        let mut out = Vec::new();
        let Some(context) = self.stack.last() else {
            return out;
        };
        for atom in atoms {
            match atom {
                Atom::Secret => out.push(Candidate::Guard {
                    strength: Strength::Verified,
                    exits_caller,
                    top,
                    name: "secret".to_owned(),
                    location: self.location(at),
                }),
                Atom::Ref(symbol) => {
                    if let Some((strength, name)) = context.pending.get(symbol) {
                        out.push(Candidate::Guard {
                            strength: *strength,
                            exits_caller,
                            top,
                            name: (*name).to_owned(),
                            location: self.location(at),
                        });
                    } else if let Some((callee, name)) = context.results.get(symbol) {
                        out.push(Candidate::CallGuard {
                            callee: callee.clone(),
                            name: name.clone(),
                            tested: true,
                            top: top && exits_caller,
                        });
                    }
                }
                Atom::Call(call) => {
                    if let Some(check) = self.check_of(call) {
                        out.push(Candidate::Guard {
                            strength: check.strength,
                            exits_caller,
                            top,
                            name: check.name.to_owned(),
                            location: self.location(call.span.start),
                        });
                    } else if let Some(callee) = self.callee_value(call) {
                        out.push(Candidate::CallGuard {
                            callee,
                            name: Self::callee_name(call),
                            tested: true,
                            top: top && exits_caller,
                        });
                    } else if auth_like(&Self::callee_name(call)) {
                        out.push(Candidate::Unknown);
                    }
                }
            }
        }
        out
    }

    fn exit_branch(&mut self, branch: &IfStatement<'_>) {
        let Some(exit) = exit_of(&branch.consequent) else {
            return;
        };
        let mut atoms = Vec::new();
        let mut partial = false;
        self.failure_atoms(&branch.test, &mut atoms, &mut partial);
        let top = self.is_top();
        let found = if partial {
            Vec::new()
        } else {
            self.guard_from_atoms(&atoms, exit.exits_caller(), top, branch.span.start)
        };
        let recognized = found
            .iter()
            .any(|candidate| matches!(candidate, Candidate::Guard { .. }));
        for candidate in found {
            self.activate(candidate);
        }
        if partial || (!recognized && mentions_denied_status(&branch.consequent)) {
            self.activate(Candidate::Unknown);
        }
    }

    fn branch_candidates(&self, branch: &IfStatement<'_>) -> (Vec<Candidate>, Vec<Candidate>) {
        let mut success = Vec::new();
        self.success_atoms(&branch.test, &mut success);
        let consequent = self.guard_from_atoms(&success, false, false, branch.span.start);
        let mut failure = Vec::new();
        let mut partial = false;
        self.failure_atoms(&branch.test, &mut failure, &mut partial);
        let alternate = if partial || branch.alternate.is_none() {
            Vec::new()
        } else {
            self.guard_from_atoms(&failure, false, false, branch.span.start)
        };
        (consequent, alternate)
    }

    fn visit_guarded(&mut self, candidates: Vec<Candidate>, statement: &Statement<'_>) {
        let ids: Vec<u32> = candidates
            .into_iter()
            .filter_map(|candidate| self.add_candidate(candidate))
            .collect();
        let pushed = !ids.is_empty();
        if pushed && let Some(context) = self.context() {
            context.frames.push(ids);
        }
        self.visit_statement(statement);
        if pushed && let Some(context) = self.context() {
            context.frames.pop();
        }
    }

    fn function_arguments(&mut self, call: &CallExpression<'_>, serve: bool) {
        let last_function = call
            .arguments
            .iter()
            .rposition(|argument| argument.as_expression().is_some_and(is_function_like));
        for (position, argument) in call.arguments.iter().enumerate() {
            if let Some(expr) = argument.as_expression()
                && is_function_like(expr)
            {
                let index = self.flow.functions.len();
                let location = self.location(call.span.start);
                let cover = self.cover();
                if let Some(function) = self.current() {
                    function.calls.push(CallSite {
                        callee: Value::Function(index),
                        location,
                        cover,
                    });
                }
                if serve && Some(position) == last_function {
                    self.flow.serve_handlers.push(Value::Function(index));
                }
                self.name_hint = Some("<callback>".to_owned());
            } else if serve
                && last_function.is_none()
                && position + 1 == call.arguments.len()
                && let Some(expr) = argument.as_expression()
            {
                let handler = self.value_of(expr);
                self.flow.serve_handlers.push(handler);
            }
            self.visit_argument(argument);
        }
    }

    fn record_export_declaration(&mut self, declaration: &Declaration<'_>) {
        match declaration {
            Declaration::FunctionDeclaration(function) => {
                if let Some(id) = &function.id
                    && let Some(symbol) = id.symbol_id.get()
                {
                    self.flow.exports.insert(
                        id.name.as_str().to_owned(),
                        ExportTarget::Local(Value::Binding(symbol)),
                    );
                }
            }
            Declaration::VariableDeclaration(variables) => {
                for declarator in &variables.declarations {
                    for id in declarator.id.get_binding_identifiers() {
                        if let Some(symbol) = id.symbol_id.get() {
                            self.flow.exports.insert(
                                id.name.as_str().to_owned(),
                                ExportTarget::Local(Value::Binding(symbol)),
                            );
                        }
                    }
                    if declarator
                        .id
                        .get_identifier_name()
                        .as_ref()
                        .map(|name| name.as_str())
                        == Some("config")
                        && let Some(Expression::ObjectExpression(object)) = declarator
                            .init
                            .as_ref()
                            .map(|init| init.get_inner_expression())
                    {
                        self.flow.matcher = object.properties.iter().find_map(|property| {
                            let ObjectPropertyKind::ObjectProperty(property) = property else {
                                return None;
                            };
                            (property_name(&property.key).as_deref() == Some("matcher"))
                                .then(|| matcher_of(&property.value))
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

fn matcher_of(value: &Expression<'_>) -> Matcher {
    if let Some(text) = literal(value) {
        return Matcher::Patterns(vec![text]);
    }
    if let Expression::ArrayExpression(array) = value.get_inner_expression() {
        let mut patterns = Vec::new();
        for element in &array.elements {
            match element.as_expression().and_then(literal) {
                Some(text) => patterns.push(text),
                None => return Matcher::Unknown,
            }
        }
        return Matcher::Patterns(patterns);
    }
    Matcher::Unknown
}

fn is_env_object(expr: &Expression<'_>) -> bool {
    if expr.is_specific_member_access("process", "env") {
        return true;
    }
    matches!(
        expr.get_inner_expression(),
        Expression::StaticMemberExpression(member)
            if member.property.name.as_str() == "env"
                && matches!(member.object.get_inner_expression(), Expression::ImportMeta(_))
    )
}

fn is_service_literal(text: &str) -> bool {
    crate::secrets::find(text).iter().any(|hit| {
        matches!(
            hit.kind,
            SecretKind::SupabaseServiceRoleKey | SecretKind::SupabaseSecretKey
        )
    })
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_program(&mut self, it: &Program<'a>) {
        if self
            .start_function(Some("<module>".to_owned()), 0)
            .is_none()
        {
            return;
        }
        walk::walk_program(self, it);
        self.stack.pop();
    }

    fn visit_statements(&mut self, it: &oxc_allocator::Vec<'a, Statement<'a>>) {
        let Some(context) = self.context() else {
            return;
        };
        context.frames.push(Vec::new());
        for statement in it {
            if let Some(context) = self.context() {
                context.buffers.push(Vec::new());
            }
            self.visit_statement(statement);
            let buffered = self
                .context()
                .and_then(|context| context.buffers.pop())
                .unwrap_or_default();
            self.after_statement(statement, buffered);
        }
        if let Some(context) = self.context() {
            context.last_frame = context.frames.pop().unwrap_or_default();
        }
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if it.import_kind.is_type() {
            return;
        }
        let Some(specifier) = it.source.value.as_str() else {
            return;
        };
        for item in it.specifiers.iter().flatten() {
            let (local, imported) = match item {
                ImportDeclarationSpecifier::ImportSpecifier(named) => {
                    if named.import_kind.is_type() {
                        continue;
                    }
                    let name = export_name(&named.imported);
                    let imported = if name == "default" {
                        Imported::Default
                    } else {
                        Imported::Named(name)
                    };
                    (&named.local, imported)
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
                    (&default.local, Imported::Default)
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
                    (&namespace.local, Imported::Namespace)
                }
            };
            if let Some(symbol) = local.symbol_id.get() {
                self.flow
                    .imports
                    .insert(symbol, (specifier.to_owned(), imported));
            }
        }
    }

    fn visit_export_declaration(&mut self, it: &ExportDeclaration<'a>) {
        walk::walk_export_declaration(self, it);
        self.record_export_declaration(&it.declaration);
    }

    fn visit_export_named_declaration(&mut self, it: &ExportNamedDeclaration<'a>) {
        if it.export_kind.is_type() {
            return;
        }
        for specifier in &it.specifiers {
            if specifier.export_kind.is_type() {
                continue;
            }
            if let ModuleExportName::IdentifierReference(local) = &specifier.local {
                let value = match self.symbol_of(local) {
                    Some(symbol) => Value::Binding(symbol),
                    None => Value::Unknown,
                };
                self.flow
                    .exports
                    .insert(export_name(&specifier.exported), ExportTarget::Local(value));
            }
        }
    }

    fn visit_export_from_declaration(&mut self, it: &ExportFromDeclaration<'a>) {
        if it.export_kind.is_type() {
            return;
        }
        let Some(source) = it.source.value.as_str() else {
            return;
        };
        for specifier in &it.specifiers {
            if specifier.export_kind.is_type() {
                continue;
            }
            let local = export_name(&specifier.local);
            let imported = if local == "default" {
                Imported::Default
            } else {
                Imported::Named(local)
            };
            self.flow.exports.insert(
                export_name(&specifier.exported),
                ExportTarget::From {
                    specifier: source.to_owned(),
                    imported,
                },
            );
        }
    }

    fn visit_export_all_declaration(&mut self, it: &ExportAllDeclaration<'a>) {
        if it.export_kind.is_type() {
            return;
        }
        let Some(source) = it.source.value.as_str() else {
            return;
        };
        match &it.exported {
            Some(name) => {
                self.flow.exports.insert(
                    export_name(name),
                    ExportTarget::From {
                        specifier: source.to_owned(),
                        imported: Imported::Namespace,
                    },
                );
            }
            None => self.flow.star_exports.push(source.to_owned()),
        }
    }

    fn visit_export_default_declaration(&mut self, it: &ExportDefaultDeclaration<'a>) {
        let value = match &it.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(_) => {
                self.name_hint = Some("default".to_owned());
                Value::Function(self.flow.functions.len())
            }
            ExportDefaultDeclarationKind::ClassDeclaration(_)
            | ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => Value::Unknown,
            other => match other.as_expression() {
                Some(expr) if is_function_like(expr) => {
                    self.name_hint = Some("default".to_owned());
                    Value::Function(self.flow.functions.len())
                }
                Some(expr) => self.value_of(expr),
                None => Value::Unknown,
            },
        };
        self.flow
            .exports
            .insert("default".to_owned(), ExportTarget::Local(value));
        walk::walk_export_default_declaration(self, it);
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        let name = it.id.as_ref().map(|id| id.name.as_str().to_owned());
        let Some(index) = self.start_function(name, it.span.start) else {
            return;
        };
        if let Some(symbol) = it.id.as_ref().and_then(|id| id.symbol_id.get()) {
            self.flow.bindings.insert(symbol, Value::Function(index));
        }
        walk::walk_function(self, it, flags);
        self.stack.pop();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if self.start_function(None, it.span.start).is_none() {
            return;
        }
        if let Some(expression) = it.body.as_expression() {
            let value = self.value_of(expression);
            if let Some(function) = self.current() {
                function.returns.push(value);
            }
        }
        walk::walk_arrow_function_expression(self, it);
        self.stack.pop();
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.name_hint = property_name(&it.key);
        walk::walk_method_definition(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if is_function_like(&it.value) {
            self.name_hint = property_name(&it.key);
        }
        walk::walk_object_property(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(id) = it.id.get_binding_identifier()
            && let Some(symbol) = id.symbol_id.get()
            && let Some(init) = &it.init
        {
            let value = if is_function_like(init) {
                self.name_hint = Some(id.name.as_str().to_owned());
                Value::Function(self.flow.functions.len())
            } else {
                self.value_of(init)
            };
            self.flow.bindings.insert(symbol, value);
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let Some(argument) = &it.argument {
            let value = self.value_of(argument);
            if let Some(function) = self.current() {
                function.returns.push(value);
            }
        }
        walk::walk_return_statement(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        let (consequent, alternate) = self.branch_candidates(it);
        self.visit_expression(&it.test);
        self.visit_guarded(consequent, &it.consequent);
        if let Some(other) = &it.alternate {
            self.visit_guarded(alternate, other);
        }
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        self.visit_block_statement(&it.block);
        let inner = self
            .context()
            .map(|context| std::mem::take(&mut context.last_frame))
            .unwrap_or_default();
        let catch_exit = it
            .handler
            .as_ref()
            .map(|handler| handler.body.body.iter().find_map(exit_of));
        if let Some(handler) = &it.handler {
            self.visit_catch_clause(handler);
        }
        if let Some(finalizer) = &it.finalizer {
            self.visit_block_statement(finalizer);
        }
        let carries = match catch_exit {
            None => Some(None),
            Some(Some(exit)) => Some(Some(exit)),
            Some(None) => None,
        };
        let top = self.is_top();
        let copied: Vec<Candidate> = {
            let Some(function) = self
                .stack
                .last()
                .and_then(|c| self.flow.functions.get(c.index))
            else {
                return;
            };
            inner
                .iter()
                .filter_map(|id| function.candidates.get(*id as usize))
                .filter_map(|candidate| match (candidate, carries) {
                    (Candidate::Pending { .. } | Candidate::Unknown, _) => Some(candidate.clone()),
                    (_, None) => None,
                    (
                        Candidate::Guard {
                            strength,
                            exits_caller,
                            name,
                            location,
                            ..
                        },
                        Some(exit),
                    ) => Some(Candidate::Guard {
                        strength: *strength,
                        exits_caller: exit.map_or(*exits_caller, Exit::exits_caller),
                        top,
                        name: name.clone(),
                        location: location.clone(),
                    }),
                    (
                        Candidate::CallGuard {
                            callee,
                            name,
                            tested,
                            ..
                        },
                        Some(exit),
                    ) => Some(Candidate::CallGuard {
                        callee: callee.clone(),
                        name: name.clone(),
                        tested: *tested,
                        top: top && exit.is_none_or(Exit::exits_caller),
                    }),
                })
                .collect()
        };
        for candidate in copied {
            self.activate(candidate);
        }
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if is_global(&it.callee, "Function") {
            self.flow.opaque = true;
        }
        walk::walk_new_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.calls_seen += 1;
        if self.calls_seen > MAX_CALLS {
            self.flow.opaque = true;
            return;
        }
        if is_global(&it.callee, "eval") {
            self.flow.opaque = true;
        }
        if self.is_supabase_constructor(it) {
            let key = it
                .arguments
                .get(1)
                .and_then(Argument::as_expression)
                .map_or(Value::Unknown, |key| self.value_of(key));
            let location = self.location(it.span.start);
            self.flow.clients.push((key, location));
        }
        self.record_access(it);
        let check = self.check_of(it);
        let callee = if check.is_some() || self.is_supabase_constructor(it) {
            None
        } else {
            self.callee_value(it)
        };
        let location = self.location(it.span.start);
        if let Some(value) = &callee {
            let cover = self.cover();
            if let Some(function) = self.current() {
                function.calls.push(CallSite {
                    callee: value.clone(),
                    location: location.clone(),
                    cover,
                });
            }
        }
        let name = Self::callee_name(it);
        if let Some(buffer) = self
            .context()
            .and_then(|context| context.buffers.last_mut())
        {
            buffer.push(Buffered {
                check,
                callee,
                name,
                location,
            });
        }
        let serve = it.callee.is_specific_member_access("Deno", "serve")
            || is_global(&it.callee, "serve")
            || matches!(self.named_import(&it.callee), Some((_, "serve")));
        self.visit_expression(&it.callee);
        self.function_arguments(it, serve);
    }
}
