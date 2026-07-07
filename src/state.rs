use crate::server::models::{
    calls::CallTable, data_flow_graph::DataFlowGraph, findings::FinalFindings,
    resolution::ResolutionTable, symbols::SymbolTable,
};
use std::collections::HashMap;

pub struct ScanData {
    pub findings: Vec<FinalFindings>,
    pub symbol_table: SymbolTable,
    pub call_table: CallTable,
    pub resolution_table: ResolutionTable,
    pub graph: DataFlowGraph,
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
