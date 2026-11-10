use std::collections::HashMap;

use super::asm::{Cpu, Naming};

pub(crate) type Value = u32;

const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_FUNCTIONS: usize = 200_000;
const MAX_INSTRUCTIONS: usize = 400_000;
const MAX_METADATA: usize = 4_000_000;
const MAX_FRAMES: usize = 64;
const MAX_SCOPE_HOPS: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Callee {
    Function(String),
    Copy,
    Opaque,
    Assembly,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Alloca,
    Load {
        ptr: Option<Value>,
    },
    Store {
        volatile: bool,
        value: Option<Value>,
        ptr: Option<Value>,
    },
    Alias {
        of: Vec<Value>,
    },
    Offset {
        base: Option<Value>,
        indexes: Vec<Value>,
    },
    Call {
        callee: Callee,
        args: Vec<Option<Value>>,
        returns_pointer: bool,
    },
    Divide {
        operands: Vec<Value>,
        by_variable: bool,
    },
    Return {
        value: Option<Value>,
    },
    Branch {
        on: Value,
        to: Vec<u32>,
    },
    Address {
        operands: Vec<Value>,
    },
    Other {
        operands: Vec<Value>,
    },
}

#[derive(Debug)]
pub(crate) struct Instruction {
    pub result: Option<Value>,
    pub op: Op,
    pub debug: Option<u32>,
    pub automatic: bool,
    pub block: u32,
}

#[derive(Debug)]
pub(crate) struct Function {
    pub symbol: String,
    pub params: Vec<Option<Value>>,
    pub values: u32,
    pub body: Vec<Instruction>,
    pub unoptimized: bool,
    pub exported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Frame {
    pub path: String,
    pub line: u32,
}

struct Place {
    line: u32,
    scope: Option<u32>,
    inlined_at: Option<u32>,
}

struct Scope {
    file: Option<u32>,
    parent: Option<u32>,
    drops: Option<bool>,
}

#[derive(Default)]
pub(crate) struct Module {
    pub functions: Vec<Function>,
    pub truncated: bool,
    pub naming: Naming,
    pub cpu: Cpu,
    pub file_assembly: bool,
    places: HashMap<u32, Place>,
    scopes: HashMap<u32, Scope>,
    files: HashMap<u32, String>,
}

impl Module {
    pub(crate) fn frames(&self, debug: u32) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut next = Some(debug);
        for _ in 0..MAX_FRAMES {
            let Some(place) = next.and_then(|id| self.places.get(&id)) else {
                break;
            };
            if let Some(path) = place.scope.and_then(|scope| self.file_of(scope)) {
                out.push(Frame {
                    path: path.to_owned(),
                    line: place.line,
                });
            }
            next = place.inlined_at;
        }
        out
    }

    fn is_automatic(&self, debug: u32) -> bool {
        let mut next = Some(debug);
        for _ in 0..MAX_FRAMES {
            let Some(place) = next.and_then(|id| self.places.get(&id)) else {
                break;
            };
            let mut scope = place.scope;
            for _ in 0..MAX_SCOPE_HOPS {
                let Some(found) = scope.and_then(|id| self.scopes.get(&id)) else {
                    break;
                };
                match found.drops {
                    Some(true) => return true,
                    Some(false) => break,
                    None => scope = found.parent,
                }
            }
            next = place.inlined_at;
        }
        false
    }

    fn file_of(&self, scope: u32) -> Option<&str> {
        let mut next = Some(scope);
        for _ in 0..MAX_SCOPE_HOPS {
            let scope = self.scopes.get(&next?)?;
            if let Some(file) = scope.file {
                return self.files.get(&file).map(String::as_str);
            }
            next = scope.parent;
        }
        None
    }
}

struct Token<'a> {
    local: bool,
    name: &'a str,
    end: usize,
}

fn tokens(text: &str) -> Vec<Token<'_>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
                i += 1;
            }
            sigil @ (b'%' | b'@') => {
                let start = i + 1;
                let mut end = start;
                if bytes.get(start) == Some(&b'"') {
                    end += 1;
                    while end < bytes.len() && bytes[end] != b'"' {
                        end += 1;
                    }
                    end = (end + 1).min(bytes.len());
                } else {
                    while end < bytes.len()
                        && (bytes[end].is_ascii_alphanumeric()
                            || matches!(bytes[end], b'_' | b'.' | b'$' | b'-'))
                    {
                        end += 1;
                    }
                }
                if end > start
                    && let Some(name) = text.get(start..end)
                {
                    out.push(Token {
                        local: sigil == b'%',
                        name,
                        end,
                    });
                }
                i = end.max(i + 1);
            }
            _ => i += 1,
        }
    }
    out
}

fn split_top(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            b')' | b']' | b'}' | b'>' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                if let Some(part) = text.get(start..i) {
                    out.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(part) = text.get(start..)
        && !part.trim().is_empty()
    {
        out.push(part);
    }
    out
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn metadata_start(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
            }
            b',' if bytes.get(i + 1) == Some(&b' ') && bytes.get(i + 2) == Some(&b'!') => {
                return i;
            }
            _ => {}
        }
        i += 1;
    }
    text.len()
}

fn number_after(text: &str, marker: &str) -> Option<u32> {
    let rest = text.get(text.find(marker)? + marker.len()..)?;
    let digits: &str = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or_default();
    digits.parse().ok()
}

struct Names<'a> {
    ids: HashMap<&'a str, Value>,
}

impl<'a> Names<'a> {
    fn id(&mut self, name: &'a str) -> Value {
        let next = u32::try_from(self.ids.len()).unwrap_or(u32::MAX);
        *self.ids.entry(name).or_insert(next)
    }

    fn locals(&mut self, text: &'a str) -> Vec<Value> {
        tokens(text)
            .into_iter()
            .filter(|token| token.local)
            .map(|token| self.id(token.name))
            .collect()
    }

    fn last(&mut self, text: &'a str) -> Option<Value> {
        self.locals(text).pop()
    }
}

fn unquote(name: &str) -> &str {
    name.strip_prefix('"')
        .and_then(|name| name.strip_suffix('"'))
        .unwrap_or(name)
}

pub(crate) fn parse(text: &str) -> Module {
    let mut module = Module::default();
    let mut current: Option<(Function, Names<'_>, Option<u32>)> = None;
    let mut blocks: HashMap<&str, u32> = HashMap::new();
    let mut block = 0u32;
    let mut switching = false;
    let mut attribute_of: Vec<Option<u32>> = Vec::new();
    let mut unoptimized: HashMap<u32, bool> = HashMap::new();

    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            module.truncated |=
                current.is_some() || line.starts_with("define ") || line.starts_with('!');
            continue;
        }
        if let Some((function, names, attribute)) = current.as_mut() {
            if line == "}" {
                function.values = u32::try_from(names.ids.len()).unwrap_or(u32::MAX);
                attribute_of.push(*attribute);
                if let Some((function, _, _)) = current.take() {
                    module.functions.push(function);
                }
                continue;
            }
            if function.body.len() >= MAX_INSTRUCTIONS {
                module.truncated = true;
                continue;
            }
            if !line.starts_with([' ', '\t']) {
                if let Some(label) = block_label(line) {
                    block = block_id(&mut blocks, label);
                }
                continue;
            }
            if switching {
                switching = !line.trim_start().starts_with(']');
                if let Some(Instruction {
                    op: Op::Branch { to, .. },
                    ..
                }) = function.body.last_mut()
                {
                    to.extend(targets(line, &mut blocks));
                }
                continue;
            }
            if let Some(mut instruction) = instruction(line, names) {
                if let Op::Branch { to, .. } = &mut instruction.op {
                    to.extend(targets(line, &mut blocks));
                    switching = line.trim_end().ends_with('[');
                }
                if line.trim_start().starts_with("to label ")
                    && let Some(Instruction {
                        op:
                            Op::Call {
                                callee: Callee::Assembly,
                                ..
                            },
                        debug: debug @ None,
                        ..
                    }) = function.body.last_mut()
                {
                    *debug = instruction.debug;
                }
                instruction.block = block;
                function.body.push(instruction);
            }
            continue;
        }
        if line.starts_with("define ") {
            if module.functions.len() >= MAX_FUNCTIONS {
                module.truncated = true;
                continue;
            }
            current = header(line);
            blocks.clear();
            block = block_id(&mut blocks, "");
            switching = false;
        } else if line.starts_with('!') {
            if module.places.len() + module.scopes.len() + module.files.len() >= MAX_METADATA {
                module.truncated = true;
                continue;
            }
            metadata(line, &mut module);
        } else if let Some(layout) = line.strip_prefix("target datalayout = ") {
            module.naming = Naming::of(layout);
        } else if let Some(triple) = line.strip_prefix("target triple = ") {
            module.cpu = Cpu::of(triple);
        } else if line.starts_with("module asm ") {
            module.file_assembly = true;
        } else if let Some(rest) = line.strip_prefix("attributes #")
            && let Some(id) = number_after(line, "attributes #")
        {
            let words = rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_');
            unoptimized.insert(id, words.into_iter().any(|word| word == "optnone"));
        }
    }
    let mut functions = std::mem::take(&mut module.functions);
    for (function, attribute) in functions.iter_mut().zip(attribute_of) {
        function.unoptimized = attribute
            .and_then(|id| unoptimized.get(&id).copied())
            .unwrap_or(false);
        let glue = is_drop(&function.symbol);
        for instruction in &mut function.body {
            instruction.automatic =
                glue || instruction.debug.is_some_and(|id| module.is_automatic(id));
        }
    }
    module.functions = functions;
    module
}

fn block_label(line: &str) -> Option<&str> {
    let (name, rest) = line.split_once(':')?;
    let rest = rest.trim_start();
    if name.is_empty() || name.starts_with(';') || !(rest.is_empty() || rest.starts_with(';')) {
        return None;
    }
    Some(name)
}

fn block_id<'a>(blocks: &mut HashMap<&'a str, u32>, name: &'a str) -> u32 {
    let next = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
    *blocks.entry(name).or_insert(next)
}

fn targets<'a>(line: &'a str, blocks: &mut HashMap<&'a str, u32>) -> Vec<u32> {
    let mut out = Vec::new();
    let mut tail = line;
    while let Some(at) = tail.find("label %") {
        let rest = tail.get(at + "label %".len()..).unwrap_or_default();
        let end = rest
            .find(|c: char| c == ',' || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let name = rest.get(..end).unwrap_or_default();
        out.push(block_id(blocks, name));
        tail = rest.get(end..).unwrap_or_default();
    }
    out
}

fn is_exported(line: &str, symbol: &str) -> bool {
    let linkage = line.split('@').next().unwrap_or_default();
    let hidden = [
        "internal",
        "private",
        "linkonce",
        "weak",
        "available_externally",
    ];
    let mangled = symbol.starts_with("_ZN") || symbol.starts_with("_R");
    let runtime = symbol == "main"
        || symbol.starts_with("__")
        || symbol.starts_with("rust_")
        || symbol.contains('.');
    !mangled
        && !runtime
        && !linkage
            .split_ascii_whitespace()
            .any(|word| hidden.iter().any(|kind| word.starts_with(kind)))
}

pub(crate) fn is_panic(symbol: &str) -> bool {
    let library = ["4core", "5alloc", "3std"]
        .iter()
        .any(|part| symbol.contains(part));
    let stops = [
        "panicking",
        "_fail17h",
        "_failed17h",
        "panic_already",
        "handle_alloc_error",
    ];
    library && stops.iter().any(|part| symbol.contains(part))
}

fn is_drop(name: &str) -> bool {
    name.contains("drop_in_place") || name.contains("Drop$GT$4drop") || name.contains("4Drop4drop")
}

fn header(line: &str) -> Option<(Function, Names<'_>, Option<u32>)> {
    let symbol = tokens(line).into_iter().find(|token| !token.local)?;
    if line.as_bytes().get(symbol.end) != Some(&b'(') {
        return None;
    }
    let close = matching_paren(line, symbol.end)?;
    let mut names = Names {
        ids: HashMap::new(),
    };
    let params = split_top(line.get(symbol.end + 1..close)?)
        .into_iter()
        .map(|param| names.last(param))
        .collect();
    let tail = line.get(close..)?;
    let attribute = tail
        .find(" #")
        .and_then(|at| tail.get(at..))
        .and_then(|rest| number_after(rest, " #"));
    let symbol = unquote(symbol.name);
    Some((
        Function {
            symbol: symbol.to_owned(),
            params,
            values: 0,
            body: Vec::new(),
            unoptimized: false,
            exported: is_exported(line, symbol),
        },
        names,
        attribute,
    ))
}

fn instruction<'a>(line: &'a str, names: &mut Names<'a>) -> Option<Instruction> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with(';') {
        return None;
    }
    let cut = metadata_start(line);
    let debug = line
        .get(cut..)
        .and_then(|tail| number_after(tail, "!dbg !"));
    let text = line.get(..cut)?;
    let (result, text) = match tokens(text).into_iter().next() {
        Some(first) if first.local && text.starts_with('%') => {
            let rest = text
                .get(first.end..)
                .and_then(|rest| rest.strip_prefix(" = "))?;
            (Some(names.id(first.name)), rest)
        }
        _ => (None, text),
    };
    let (word, rest) = text.split_once(' ').unwrap_or((text, ""));
    let op = match word {
        "alloca" => Op::Alloca,
        "load" => {
            let parts = split_top(rest);
            Op::Load {
                ptr: parts.get(1).and_then(|part| names.last(part)),
            }
        }
        "store" => {
            let (volatile, rest) = match rest.strip_prefix("volatile ") {
                Some(rest) => (true, rest),
                None => (false, rest),
            };
            let parts = split_top(rest);
            Op::Store {
                volatile,
                value: parts.first().and_then(|part| names.last(part)),
                ptr: parts.get(1).and_then(|part| names.last(part)),
            }
        }
        "getelementptr" => {
            let parts = split_top(rest);
            Op::Offset {
                base: parts.get(1).and_then(|part| names.last(part)),
                indexes: parts
                    .iter()
                    .skip(2)
                    .flat_map(|part| names.locals(part))
                    .collect(),
            }
        }
        "phi" => {
            let mut incoming = Vec::new();
            let mut tail = rest;
            while let Some(open) = tail.find('[') {
                let Some(close) = tail.get(open..).and_then(|rest| rest.find(']')) else {
                    break;
                };
                let pair = tail.get(open + 1..open + close).unwrap_or_default();
                let value = pair.split(',').next().unwrap_or_default();
                incoming.extend(names.last(value));
                tail = tail.get(open + close + 1..).unwrap_or_default();
            }
            if rest.starts_with("ptr ") {
                Op::Alias { of: incoming }
            } else {
                Op::Other { operands: incoming }
            }
        }
        "select" => {
            let parts = split_top(rest);
            let pointer = parts
                .get(1)
                .is_some_and(|part| part.trim_start().starts_with("ptr "));
            if pointer {
                Op::Alias {
                    of: parts
                        .iter()
                        .skip(1)
                        .filter_map(|part| names.last(part))
                        .collect(),
                }
            } else {
                Op::Other {
                    operands: names.locals(rest),
                }
            }
        }
        "sdiv" | "udiv" | "srem" | "urem" => {
            let parts = split_top(rest);
            Op::Divide {
                by_variable: parts
                    .last()
                    .is_some_and(|part| !names.locals(part).is_empty()),
                operands: names.locals(rest),
            }
        }
        "ret" => Op::Return {
            value: names.last(rest),
        },
        "br" | "switch" => {
            let first = split_top(rest).into_iter().next().unwrap_or_default();
            match names.last(first) {
                Some(on) if !first.trim_start().starts_with("label ") => {
                    Op::Branch { on, to: Vec::new() }
                }
                _ => return None,
            }
        }
        "unreachable" | "resume" | "indirectbr" => return None,
        "inttoptr" => Op::Address {
            operands: names.locals(rest),
        },
        "extractvalue" | "freeze" | "bitcast" | "addrspacecast" => Op::Alias {
            of: names.locals(rest),
        },
        "call" | "invoke" | "callbr" => call(rest, names),
        "tail" | "musttail" | "notail" => match rest.strip_prefix("call ") {
            Some(rest) => call(rest, names),
            None => Op::Other {
                operands: names.locals(rest),
            },
        },
        _ => Op::Other {
            operands: names.locals(rest),
        },
    };
    Some(Instruction {
        result,
        op,
        debug,
        automatic: false,
        block: 0,
    })
}

fn call<'a>(rest: &'a str, names: &mut Names<'a>) -> Op {
    let bytes = rest.as_bytes();
    let mut depth = 0usize;
    let mut depth_at = Vec::with_capacity(bytes.len());
    let mut quoted = false;
    for byte in bytes {
        if *byte == b'"' {
            quoted = !quoted;
        }
        if !quoted && *byte == b')' {
            depth = depth.saturating_sub(1);
        }
        depth_at.push(depth);
        if !quoted && *byte == b'(' {
            depth += 1;
        }
    }
    let target = tokens(rest)
        .into_iter()
        .find(|token| bytes.get(token.end) == Some(&b'(') && depth_at.get(token.end) == Some(&0));
    let Some(target) = target else {
        let assembly = rest
            .split('"')
            .next()
            .unwrap_or_default()
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| word == "asm");
        let values = rest.split(" to label ").next().unwrap_or_default();
        return Op::Call {
            callee: if assembly {
                Callee::Assembly
            } else {
                Callee::Opaque
            },
            args: names.locals(values).into_iter().map(Some).collect(),
            returns_pointer: false,
        };
    };
    let close = matching_paren(rest, target.end).unwrap_or(rest.len());
    let args: Vec<Option<Value>> = split_top(rest.get(target.end + 1..close).unwrap_or_default())
        .into_iter()
        .map(|arg| names.last(arg))
        .collect();
    let name = unquote(target.name);
    let callee = if target.local {
        Callee::Opaque
    } else if name.starts_with("llvm.memcpy") || name.starts_with("llvm.memmove") {
        Callee::Copy
    } else if name.starts_with("llvm.") {
        Callee::Opaque
    } else {
        Callee::Function(name.to_owned())
    };
    let returns_pointer = rest
        .get(..target.end)
        .unwrap_or_default()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word == "ptr");
    Op::Call {
        callee,
        args,
        returns_pointer,
    }
}

fn metadata(line: &str, module: &mut Module) {
    let Some(id) = number_after(line, "!") else {
        return;
    };
    let Some((_, body)) = line.split_once(" = ") else {
        return;
    };
    let body = body.strip_prefix("distinct ").unwrap_or(body);
    let Some(open) = body.find('(') else {
        return;
    };
    let kind = body.get(..open).unwrap_or_default();
    let Some(inner) = body.get(open + 1..).and_then(|rest| rest.strip_suffix(')')) else {
        return;
    };
    let mut line_number = 0u32;
    let mut scope = None;
    let mut inlined_at = None;
    let mut file = None;
    let mut filename = None;
    let mut directory = None;
    let mut name = None;
    for field in split_top(inner) {
        let Some((key, value)) = field.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let node = || value.strip_prefix('!').and_then(|n| n.parse::<u32>().ok());
        match key.trim() {
            "line" => line_number = value.parse().unwrap_or(0),
            "scope" => scope = node(),
            "inlinedAt" => inlined_at = node(),
            "file" => file = node(),
            "name" => name = Some(text_value(value)),
            "filename" => filename = Some(text_value(value)),
            "directory" => directory = Some(text_value(value)),
            _ => {}
        }
    }
    match kind {
        "!DILocation" => {
            module.places.insert(
                id,
                Place {
                    line: line_number,
                    scope,
                    inlined_at,
                },
            );
        }
        "!DIFile" => {
            let name = filename.unwrap_or_default();
            let directory = directory.unwrap_or_default();
            let path = if name.starts_with('/') || directory.is_empty() {
                name
            } else {
                format!("{}/{name}", directory.trim_end_matches('/'))
            };
            module.files.insert(id, path);
        }
        _ if scope.is_some() || file.is_some() => {
            module.scopes.insert(
                id,
                Scope {
                    file,
                    parent: scope,
                    drops: (kind == "!DISubprogram").then(|| {
                        name.as_deref()
                            .is_some_and(|name| name == "drop" || name.starts_with("drop_in_place"))
                    }),
                },
            );
        }
        _ => {}
    }
}

fn text_value(raw: &str) -> String {
    let raw = unquote(raw);
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let pair: String = chars.clone().take(2).collect();
        match u8::from_str_radix(&pair, 16) {
            Ok(byte) if pair.len() == 2 && byte.is_ascii() => {
                out.push(char::from(byte));
                chars.nth(1);
            }
            _ => out.push(c),
        }
    }
    out
}
