use crate::server::models::{calls::CallSite, symbols::Symbol};

#[derive(Clone)]
pub struct ResolvedArgument {
    pub raw: String,
    pub chain: Vec<Symbol>, // full assignment chain: [arg_sym, assigned_from, ..., origin]
}

#[derive(Clone)]
pub struct ResolvedCall {
    pub call: CallSite,
    pub arguments: Vec<ResolvedArgument>,
}

// single step in a variable assignment chain, with the symbol it was assigned from.
// used internally by the resolver, will feed into chain walking later.
pub struct ResolvedVariable {
    pub symbol: Symbol,
    pub assigned_from: Option<Symbol>,
}

pub struct ResolutionTable {
    pub calls: Vec<ResolvedCall>,
}

impl ResolutionTable {
    pub fn new() -> Self {
        Self { calls: Vec::new() }
    }
}
