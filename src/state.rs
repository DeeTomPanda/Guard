use std::collections::HashMap;
use crate::server::models::findings::{FinalFindings};

pub struct AppState {
    // HashMap<scan_id, HashMap<file_name, Vec<Findings>>>
    pub results: HashMap<String, Vec<FinalFindings>>,
}



impl AppState {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }
}