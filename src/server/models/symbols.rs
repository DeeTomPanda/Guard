use std::collections::HashMap;
#[derive(Debug)]
pub enum SymbolKind {
    Function,
    Method,
    Variable,
    Parameter,
    Import,
    Class,
    Struct,
}

pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub scope: String,
}

pub struct SymbolTable {
    pub symbols: HashMap<String, Vec<Symbol>>,
}
