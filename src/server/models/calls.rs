use std::collections::HashMap;

pub struct CallSite {
    pub callee: String,          // function name
    pub object: Option<String>,  // e.g. db.query, db is object
    pub arguments: Vec<String>,  
    pub caller: String,          // not to be confused with calle
    pub file: String,
    pub line: usize,
    pub column: usize,
}

pub struct CallTable {
    pub calls: HashMap<String, Vec<CallSite>>, 
}

impl CallTable {
    pub fn new() -> Self {
        Self {
            calls: HashMap::new(),
        }
    }

    pub fn insert(&mut self, file: String, call: CallSite) {
        self.calls
            .entry(file)
            .or_insert_with(Vec::new)
            .push(call);
    }

    pub fn total(&self) -> usize {
        self.calls.values().map(|v| v.len()).sum()
    }
}