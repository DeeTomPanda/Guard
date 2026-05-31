use std::collections::HashMap;
use crate::server::model::Findings;

pub struct AppState {
    pub results: HashMap<String, Vec<Findings>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }
}