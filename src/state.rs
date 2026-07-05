use crate::server::models::{symbols::SymbolTable,findings::FinalFindings};
use std::collections::HashMap;

pub struct AppState {
    // HashMap<scan_id, HashMap<file_name, Vec<Findings>>>
    pub results: HashMap<String, Vec<FinalFindings>>,
    pub symbol_table: Option<SymbolTable>, 
}

impl AppState {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            symbol_table:None
        }
    }
}
