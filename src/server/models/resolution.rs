use crate::server::models::{calls::CallSite, symbols::Symbol};

#[derive(Clone, Debug)]
pub struct ResolvedArgument {
    pub raw: String,
    pub chain: Vec<Symbol>, // full assignment chain: [arg_sym, assigned_from, ..., origin]
}

#[derive(Debug)]
pub struct ResolvedCall {
    pub call: CallSite,
    pub arguments: Vec<ResolvedArgument>,
}

// single step in a variable assignment chain, with the symbol it was assigned from.
// used internally by the resolver, will feed into chain walking later.

#[derive(Debug)]
pub struct ResolvedVariable {
    pub name: String,
    pub chain: Vec<Symbol>,
}

// TODO: implement this

#[derive(Debug)]
pub struct ResolvedImports {
    pub symbol: Symbol,
    pub assigned_from: Option<Symbol>,
}

#[derive(Debug)]
pub struct ResolutionTable {
    pub calls: Vec<ResolvedCall>,
    pub variables: Vec<ResolvedVariable>,
}

impl ResolutionTable {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            variables: Vec::new(),
        }
    }
}
