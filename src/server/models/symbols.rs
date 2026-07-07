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

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub scope: String,
    pub assigned_from: Option<String>, // takes r.h.s text, e.g. x=y; (or) x=func(a); etc...
}
#[derive(Debug)]
pub struct SymbolTable {
    pub symbols: HashMap<String, Vec<Symbol>>,
    // to speed up scans
    pub index: HashMap<String, HashMap<String, Vec<Symbol>>>, // file :{"name::scope": { vec![Symbol,Symbol] }}
    pub fn_index: HashMap<String, HashMap<String, Vec<Symbol>>>, // file :{"name": { vec![Symbol,Symbol] }}
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            index: HashMap::new(),
            fn_index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, file: String, symbol: Symbol) {
        self.symbols
            .entry(file)
            .or_default()
            .push(symbol);
    }

    pub fn build_index(&mut self) {
        for (file, symbols) in &self.symbols {
            let file_index = self.index.entry(file.clone()).or_default();

            for symbol in symbols {
                if matches!(symbol.kind, SymbolKind::Function | SymbolKind::Method) {
                    self.fn_index
                        .entry(file.clone())
                        .or_default()
                        .entry(symbol.name.clone())
                        .or_default()
                        .push(symbol.clone());
                } else {
                    let key = format!("{}::{}", symbol.name, symbol.scope);
                    file_index
                        .entry(key)
                        .or_default()
                        .push(symbol.clone()); // push not insert, no overwrite
                }
            }
        }
    }
}
