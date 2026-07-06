use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum SymbolKind {
    Function,
    Method,
    Variable,
    Parameter,
    Import,
    Class,
    Struct,
}

#[derive(Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub scope: String,
    pub assigned_from: Option<String>, // takes r.h.s text, e.g. x=y; (or) x=func(a); etc...
}

pub struct SymbolTable {
    pub symbols: HashMap<String, Vec<Symbol>>,
    // to speed up scans
    // file :{"name::scope": { vec![Symbol,Symbol] }}
    pub index: HashMap<String, HashMap<String, Vec<Symbol>>>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, file: String, symbol: Symbol) {
        self.symbols
            .entry(file)
            .or_insert_with(Vec::new)
            .push(symbol);
    }

    pub fn build_index(&mut self) {
        for (file, symbols) in &self.symbols {
            let file_index = self.index.entry(file.clone()).or_insert_with(HashMap::new);

            for symbol in symbols {
                let key = format!("{}::{}", symbol.name, symbol.scope);
                file_index
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push(symbol.clone()); // push not insert, no overwrite
            }
        }
    }
}
