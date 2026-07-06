use crate::server::models::{calls::CallSite, symbols::Symbol};

pub struct ResolvedArgument {
    pub raw: String,
    pub symbol: Option<Symbol>,
    pub assigned_from: Option<String>,
}

pub struct ResolvedCall {
    pub call: CallSite,
    pub arguments: Vec<ResolvedArgument>,
}

pub struct ResolutionTable {
    pub calls: Vec<ResolvedCall>,
}

impl ResolutionTable {
    pub fn new() -> Self {
        Self { calls: Vec::new() }
    }
}