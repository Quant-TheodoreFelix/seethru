use std::collections::BTreeMap;

use oxc_semantic::SymbolId;
use seethru_core::Location;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Strength {
    Weak,
    Verified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Imported {
    Default,
    Named(String),
    Namespace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Function(usize),
    Binding(SymbolId),
    Member(SymbolId, String),
    Call(Box<Value>),
    Client { key: Box<Value>, location: Location },
    Env(String),
    SecretLiteral,
    Global(String),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Op {
    Read,
    Rpc,
    Admin,
    Write,
}

impl Op {
    pub(crate) fn changes_data(self) -> bool {
        matches!(self, Self::Write | Self::Admin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Table(String),
    Bucket(String),
    Function(String),
    Admin(String),
}

#[derive(Debug, Clone)]
pub(crate) struct Access {
    pub receiver: Value,
    pub op: Op,
    pub target: Target,
    pub location: Location,
    pub cover: Vec<u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct CallSite {
    pub callee: Value,
    pub location: Location,
    pub cover: Vec<u32>,
}

#[derive(Debug, Clone)]
pub(crate) enum Candidate {
    Guard {
        strength: Strength,
        exits_caller: bool,
        top: bool,
        name: String,
        location: Location,
    },
    Pending {
        strength: Strength,
    },
    Unknown,
    CallGuard {
        callee: Value,
        name: String,
        tested: bool,
        top: bool,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct FlowFunction {
    pub name: String,
    pub location: Location,
    pub returns: Vec<Value>,
    pub calls: Vec<CallSite>,
    pub accesses: Vec<Access>,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExportTarget {
    Local(Value),
    From {
        specifier: String,
        imported: Imported,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Matcher {
    Patterns(Vec<String>),
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FileFlow {
    pub imports: BTreeMap<SymbolId, (String, Imported)>,
    pub exports: BTreeMap<String, ExportTarget>,
    pub star_exports: Vec<String>,
    pub bindings: BTreeMap<SymbolId, Value>,
    pub functions: Vec<FlowFunction>,
    pub clients: Vec<(Value, Location)>,
    pub serve_handlers: Vec<Value>,
    pub matcher: Option<Matcher>,
    pub opaque: bool,
}
