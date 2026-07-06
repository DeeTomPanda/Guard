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

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
        }
    }

    pub fn insert(&mut self, file: String, symbol: Symbol) {
        self.symbols
            .entry(file)
            .or_insert_with(Vec::new)
            .push(symbol);
    }
}
