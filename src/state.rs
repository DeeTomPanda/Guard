use crate::server::models::{calls::CallTable, findings::FinalFindings, resolution::ResolutionTable, symbols::SymbolTable};
use std::collections::HashMap;

pub struct ScanData {
    pub findings: Vec<FinalFindings>,
    pub symbol_table: SymbolTable,
    pub call_table: CallTable,
    pub resolution_table:ResolutionTable
}
pub struct AppState {
    // HashMap<scan_id, HashMap<file_name, [Vec<Findings>,SymbolTable]>>
    pub results: HashMap<String, ScanData>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }
}
