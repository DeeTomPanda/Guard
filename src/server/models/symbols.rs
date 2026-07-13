use crate::server::module_resolver::ImportResolver;
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

#[derive(Debug, Clone, PartialEq)]
pub enum AssignedFrom {
    /// Another identifier.
    ///
    /// Examples:
    ///   const x = y;
    ///   const id = userId;
    Identifier(String),

    /// A function or method call.
    ///
    /// Examples:
    ///   const sql = buildQuery("users", id);
    ///   const conn = connect();
    Call {
        /// Name of the function being called.
        callee: String,

        /// Raw argument expressions passed to the call.
        arguments: Vec<String>,
    },

    /// A property/member access.
    ///
    /// Examples:
    ///   const id = req.body.id;
    ///   const db = config.database;
    ///   const q = obj.query;
    Member {
        /// Left-hand side object (e.g. "req.body", "config", "obj").
        object: String,

        /// Final property being accessed (e.g. "id", "database", "query").
        property: String,
    },

    /// A literal value.
    ///
    /// Examples:
    ///   const x = 42;
    ///   const s = "hello";
    ///   const ok = true;
    ///   const r = /abc/g;
    Literal(String),

    /// Any expression that doesn't fit a more specific category.
    ///
    /// Examples:
    ///   const x = a + b;
    ///   const y = foo ? bar : baz;
    ///   const z = new Date();
    ///   const v = arr[i];
    Expression(String),

    /// An imported module/path.
    ///
    /// Examples:
    ///   import { query } from "./db";
    ///   const db = require("./db");
    ///
    /// Stores the resolved module stem/path (e.g. "/project/src/db").
    Import(String),
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub scope: String,
    pub assigned_from: Option<AssignedFrom>, // takes r.h.s descriptor, e.g. x=y; (or) x=func(a); (or) import path "databse/sql" (or)"base_path/index.js" etc...
}

#[derive(Debug)]
pub struct SymbolTable {
    pub symbols: HashMap<String, Vec<Symbol>>,
    // to speed up scans
    pub index: HashMap<String, HashMap<String, Vec<Symbol>>>, // file :{"name::scope": { vec![Symbol,Symbol] }}
    pub fn_index: HashMap<String, HashMap<String, Vec<Symbol>>>, // file :{"name": { vec![Symbol,Symbol] }}
    pub import_index: HashMap<String, HashMap<String, Vec<String>>>, // file:{"import":{vec!["/path/to/file.ext", ...]}}
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            index: HashMap::new(),
            fn_index: HashMap::new(),
            import_index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, file: String, symbol: Symbol) {
        self.symbols.entry(file).or_default().push(symbol);
    }

    pub fn build_indexes(&mut self, import_resolver: &ImportResolver) {
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
                } else if matches!(symbol.kind, SymbolKind::Import) {
                    if let Some(AssignedFrom::Import(stem)) = &symbol.assigned_from {
                        // local import identifier -> candidate parsed files
                        //
                        // JS:
                        //   db -> [db.ts, db.js]
                        //
                        // Go:
                        //   populated by package resolver instead
                        let matches = import_resolver.resolve(stem, file);

                        if !matches.is_empty() {
                            self.import_index
                                .entry(file.clone())
                                .or_default()
                                .entry(symbol.name.clone())
                                .or_default()
                                .extend(matches);
                        }
                    }
                } else {
                    let key = format!("{}::{}", symbol.name, symbol.scope);
                    file_index.entry(key).or_default().push(symbol.clone()); // push not insert, no overwrite
                }
            }
        }
    }
}
