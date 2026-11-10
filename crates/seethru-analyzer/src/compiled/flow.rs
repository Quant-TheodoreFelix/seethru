use std::collections::{BTreeSet, HashMap};

use super::ir::{Callee, Function, Module, Op, Value, is_panic};

const MAX_ROUNDS: usize = 64;
const MAX_LOCAL_ROUNDS: usize = 64;
const MAX_LABELLED_PARAMS: usize = 31;

type Labels = u128;

const WIPED: Labels = 1;
const ANY: Labels = u64::MAX as Labels;
const DIRECT: Labels = !ANY;

fn direct(labels: Labels) -> Labels {
    (labels & ANY & !WIPED) << 64
}

fn through(labels: Labels, given: Labels) -> Labels {
    let mut out = 0;
    if labels & ANY != 0 {
        out |= given & ANY;
    }
    if labels & DIRECT != 0 {
        out |= given & DIRECT;
    }
    out
}

fn value_label(param: usize) -> Labels {
    if param < MAX_LABELLED_PARAMS {
        1 << (1 + 2 * param)
    } else {
        0
    }
}

fn pointee_label(param: usize) -> Labels {
    if param < MAX_LABELLED_PARAMS {
        1 << (2 + 2 * param)
    } else {
        0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Site {
    pub module: usize,
    pub function: usize,
    pub debug: u32,
    pub by_variable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Stop {
    pub module: usize,
    pub debug: u32,
}

pub(crate) struct Flow {
    pub sites: Vec<Site>,
    pub stops: Vec<Stop>,
    pub entries: usize,
    pub wipes: usize,
    pub truncated: bool,
}

#[derive(Default, Clone, PartialEq, Eq)]
struct Summary {
    returns: Labels,
    leaves: Vec<Labels>,
    wipes: Vec<bool>,
    reads: Vec<bool>,
    secret: Labels,
    outside: Labels,
}

struct Local {
    bases: Vec<Vec<Value>>,
    value: Vec<Labels>,
    memory: Vec<Labels>,
    wiped: Vec<bool>,
    read: Vec<bool>,
    address: Vec<bool>,
}

impl Local {
    fn is_device(&self, pointer: Value) -> bool {
        self.roots(pointer)
            .into_iter()
            .any(|root| self.address.get(root as usize).copied().unwrap_or(false))
    }

    fn new(function: &Function) -> Self {
        let size = function.values as usize;
        let mut bases = vec![Vec::new(); size];
        let mut address = vec![false; size];
        for instruction in &function.body {
            let Some(result) = instruction.result else {
                continue;
            };
            if matches!(instruction.op, Op::Address { .. })
                && let Some(slot) = address.get_mut(result as usize)
            {
                *slot = true;
            }
            let Some(slot) = bases.get_mut(result as usize) else {
                continue;
            };
            match &instruction.op {
                Op::Offset {
                    base: Some(base), ..
                } => slot.push(*base),
                Op::Alias { of } => slot.extend(of.iter().copied()),
                Op::Call {
                    callee: Callee::Function(_) | Callee::Opaque,
                    args,
                    returns_pointer: true,
                } => slot.extend(args.iter().flatten().copied()),
                _ => {}
            }
        }
        let mut local = Self {
            bases,
            value: vec![0; size],
            memory: vec![0; size],
            wiped: vec![false; size],
            read: vec![false; size],
            address,
        };
        for (position, param) in function.params.iter().enumerate() {
            if let Some(param) = param {
                let value = value_label(position);
                let pointee = pointee_label(position);
                local.add_value(*param, value | direct(value));
                local.add_memory(*param, pointee | direct(pointee), false);
            }
        }
        local
    }

    fn roots(&self, value: Value) -> Vec<Value> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![value];
        while let Some(value) = stack.pop() {
            if !seen.insert(value) {
                continue;
            }
            match self.bases.get(value as usize) {
                Some(bases) if !bases.is_empty() => stack.extend(bases.iter().copied()),
                _ => out.push(value),
            }
        }
        out
    }

    fn of(&self, value: Value) -> Labels {
        self.value.get(value as usize).copied().unwrap_or(0)
    }

    fn of_all(&self, values: &[Value]) -> Labels {
        values.iter().fold(0, |all, value| all | self.of(*value))
    }

    fn held(&self, pointer: Value) -> Labels {
        self.roots(pointer).into_iter().fold(0, |all, root| {
            all | self.memory.get(root as usize).copied().unwrap_or(0)
        })
    }

    fn add_value(&mut self, value: Value, labels: Labels) -> bool {
        match self.value.get_mut(value as usize) {
            Some(slot) if *slot | labels != *slot => {
                *slot |= labels;
                true
            }
            _ => false,
        }
    }

    fn add_memory(&mut self, pointer: Value, labels: Labels, wiped: bool) -> bool {
        let mut changed = false;
        for root in self.roots(pointer) {
            if let Some(slot) = self.memory.get_mut(root as usize)
                && *slot | labels != *slot
            {
                *slot |= labels;
                changed = true;
            }
            if wiped
                && let Some(slot) = self.wiped.get_mut(root as usize)
                && !*slot
            {
                *slot = true;
                changed = true;
            }
        }
        changed
    }

    fn mark_read(&mut self, pointer: Value) -> bool {
        let mut changed = false;
        for root in self.roots(pointer) {
            if let Some(slot) = self.read.get_mut(root as usize)
                && !*slot
            {
                *slot = true;
                changed = true;
            }
        }
        changed
    }

    fn translate(&self, labels: Labels, args: &[Option<Value>]) -> Labels {
        let mut out = labels & WIPED;
        for (position, arg) in args.iter().enumerate().take(MAX_LABELLED_PARAMS) {
            let Some(arg) = arg else { continue };
            let value = value_label(position);
            let pointee = pointee_label(position);
            out |= through(labels & (value | direct(value)), self.of(*arg));
            out |= through(labels & (pointee | direct(pointee)), self.held(*arg));
        }
        out
    }

    fn step(
        &mut self,
        function: &Function,
        resolve: &dyn Fn(&str) -> Option<usize>,
        summaries: &[Summary],
        returns: &mut Labels,
    ) -> bool {
        let mut moved = false;
        for instruction in &function.body {
            let labels = match &instruction.op {
                Op::Alloca => 0,
                Op::Load { ptr } => match ptr {
                    Some(ptr) => {
                        moved |= self.mark_read(*ptr);
                        (self.of(*ptr) & ANY) | self.held(*ptr)
                    }
                    None => 0,
                },
                Op::Store {
                    volatile,
                    value,
                    ptr,
                } => {
                    if let Some(ptr) = ptr {
                        let stored = value.map_or(0, |value| self.of(value));
                        if *volatile {
                            if !instruction.automatic && !self.is_device(*ptr) {
                                moved |= self.add_memory(*ptr, WIPED, true);
                            }
                        } else if stored != 0 {
                            moved |= self.add_memory(*ptr, stored, false);
                        }
                    }
                    0
                }
                Op::Alias { of } => self.of_all(of),
                Op::Offset { base, indexes } => {
                    base.map_or(0, |base| self.of(base)) | self.of_all(indexes)
                }
                Op::Divide { operands, .. } | Op::Other { operands } | Op::Address { operands } => {
                    self.of_all(operands)
                }
                Op::Branch { .. } => 0,
                Op::Return { value } => {
                    *returns |= value.map_or(0, |value| self.of(value));
                    0
                }
                Op::Call { callee, args, .. } => match callee {
                    Callee::Copy => {
                        if let (Some(Some(to)), Some(Some(from))) = (args.first(), args.get(1)) {
                            let copied = self.held(*from);
                            moved |= self.mark_read(*from);
                            if copied != 0 {
                                moved |= self.add_memory(*to, copied, false);
                            }
                        }
                        0
                    }
                    Callee::Opaque => {
                        for arg in args.iter().flatten() {
                            moved |= self.mark_read(*arg);
                        }
                        args.iter()
                            .flatten()
                            .fold(0, |all, value| all | self.of(*value))
                    }
                    Callee::Function(name) => match resolve(name) {
                        None => {
                            for arg in args.iter().flatten() {
                                moved |= self.mark_read(*arg);
                            }
                            0
                        }
                        Some(at) => {
                            let callee = &summaries[at];
                            for (position, arg) in args.iter().enumerate() {
                                let Some(arg) = arg else { continue };
                                let wipes = !instruction.automatic
                                    && callee.wipes.get(position).copied().unwrap_or(false);
                                if callee.reads.get(position).copied().unwrap_or(true) {
                                    moved |= self.mark_read(*arg);
                                }
                                let mut left = self.translate(
                                    callee.leaves.get(position).copied().unwrap_or(0),
                                    args,
                                );
                                if wipes {
                                    left |= WIPED;
                                }
                                if left != 0 || wipes {
                                    moved |= self.add_memory(*arg, left, wipes);
                                }
                            }
                            self.translate(callee.returns, args)
                        }
                    },
                },
            };
            if labels != 0
                && let Some(result) = instruction.result
            {
                moved |= self.add_value(result, labels);
            }
        }
        moved
    }
}

pub(crate) fn analyze(modules: &[Module]) -> Flow {
    let mut anywhere: HashMap<&str, usize> = HashMap::new();
    let mut nearby: HashMap<(usize, &str), usize> = HashMap::new();
    let mut functions: Vec<(usize, &Function)> = Vec::new();
    let mut firsts: Vec<usize> = Vec::new();
    for (module_at, module) in modules.iter().enumerate() {
        firsts.push(functions.len());
        for function in &module.functions {
            let symbol = function.symbol.as_str();
            anywhere.entry(symbol).or_insert(functions.len());
            nearby.entry((module_at, symbol)).or_insert(functions.len());
            functions.push((module_at, function));
        }
    }
    let mut summaries = vec![Summary::default(); functions.len()];
    let mut entries = 0usize;
    for (summary, (_, function)) in summaries.iter_mut().zip(&functions) {
        if function.exported && function.params.iter().any(Option::is_some) {
            entries += 1;
            for position in 0..function.params.len() {
                summary.outside |= direct(value_label(position) | pointee_label(position));
            }
        }
    }
    let mut locals: Vec<Local> = functions
        .iter()
        .map(|(_, function)| Local::new(function))
        .collect();
    let mut truncated = true;
    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        for at in 0..functions.len() {
            let (module_at, function) = functions[at];
            let resolve = |name: &str| {
                nearby
                    .get(&(module_at, name))
                    .or_else(|| anywhere.get(name))
                    .copied()
            };
            let local = &mut locals[at];
            let mut returns = summaries[at].returns;
            for _ in 0..MAX_LOCAL_ROUNDS {
                if !local.step(function, &resolve, &summaries, &mut returns) {
                    break;
                }
            }
            let param_flags = |read: &dyn Fn(usize) -> Labels| -> Vec<Labels> {
                function
                    .params
                    .iter()
                    .map(|param| param.map_or(0, |param| read(param as usize)))
                    .collect()
            };
            let leaves = param_flags(&|at| local.memory.get(at).copied().unwrap_or(0) & !WIPED);
            let flag = |flags: &[bool], param: &Option<Value>| {
                param.is_some_and(|param| flags.get(param as usize).copied().unwrap_or(false))
            };
            let reads: Vec<bool> = function
                .params
                .iter()
                .map(|param| flag(&local.read, param))
                .collect();
            let wipes: Vec<bool> = function
                .params
                .iter()
                .map(|param| flag(&local.wiped, param) && !flag(&local.read, param))
                .collect();
            let returns = returns & !WIPED;
            let secret = summaries[at].secret | WIPED;
            let outside = summaries[at].outside;
            let mut requests: Vec<(usize, Labels, Labels)> = Vec::new();
            for instruction in &function.body {
                let Op::Call {
                    callee: Callee::Function(name),
                    args,
                    ..
                } = &instruction.op
                else {
                    continue;
                };
                let Some(callee_at) = resolve(name) else {
                    continue;
                };
                let mut passed = 0;
                let mut given = 0;
                for (position, arg) in args.iter().enumerate() {
                    let Some(arg) = arg else { continue };
                    let value = local.of(*arg);
                    let held = local.held(*arg);
                    if value & secret != 0 {
                        passed |= value_label(position);
                    }
                    if held & secret != 0 {
                        passed |= pointee_label(position);
                    }
                    if value & outside != 0 {
                        given |= direct(value_label(position));
                    }
                    if held & outside != 0 {
                        given |= direct(pointee_label(position));
                    }
                }
                if passed != 0 || given != 0 {
                    requests.push((callee_at, passed, given));
                }
            }
            let summary = &mut summaries[at];
            if summary.returns != returns
                || summary.leaves != leaves
                || summary.wipes != wipes
                || summary.reads != reads
            {
                summary.returns = returns;
                summary.leaves = leaves;
                summary.wipes = wipes;
                summary.reads = reads;
                changed = true;
            }
            for (callee_at, passed, given) in requests {
                let callee = &mut summaries[callee_at];
                if callee.secret | passed != callee.secret {
                    callee.secret |= passed;
                    changed = true;
                }
                if callee.outside | given != callee.outside {
                    callee.outside |= given;
                    changed = true;
                }
            }
        }
        if !changed {
            truncated = false;
            break;
        }
    }

    let mut sites = Vec::new();
    let mut stops = Vec::new();
    let mut wipes = 0usize;
    for (at, (module_at, function)) in functions.iter().enumerate() {
        let local = &locals[at];
        let secret = summaries[at].secret | WIPED;
        let outside = summaries[at].outside;
        let mut panics: HashMap<u32, u32> = HashMap::new();
        if outside != 0 {
            for instruction in &function.body {
                if let Op::Call {
                    callee: Callee::Function(name),
                    ..
                } = &instruction.op
                    && is_panic(name)
                    && let Some(debug) = instruction.debug
                {
                    panics.entry(instruction.block).or_insert(debug);
                }
            }
        }
        for instruction in &function.body {
            if let Op::Store {
                volatile: true,
                ptr: Some(ptr),
                ..
            } = &instruction.op
                && !instruction.automatic
                && !local.is_device(*ptr)
            {
                wipes += 1;
            }
            if let Op::Branch { on, to } = &instruction.op
                && local.of(*on) & outside != 0
            {
                for block in to {
                    if let Some(debug) = panics.get(block) {
                        stops.push(Stop {
                            module: *module_at,
                            debug: *debug,
                        });
                    }
                }
            }
            if let Op::Divide {
                operands,
                by_variable,
            } = &instruction.op
                && local.of_all(operands) & secret != 0
                && let Some(debug) = instruction.debug
            {
                sites.push(Site {
                    module: *module_at,
                    function: at - firsts[*module_at],
                    debug,
                    by_variable: *by_variable,
                });
            }
        }
    }
    sites.sort();
    sites.dedup();
    stops.sort();
    stops.dedup();
    Flow {
        sites,
        stops,
        entries,
        wipes,
        truncated,
    }
}
