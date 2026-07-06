use super::{calls::CallSite, symbols::Symbol};
use std::collections::HashMap;

struct CallGraphNode {
    id: String,
    symbol: Symbol,
}

struct CallGraphEdge {
    callee:String,
    caller:String,
    call: CallSite,
}

struct CallGraph{
    pub nodes: HashMap<String, CallGraphNode>,  // id to node
    pub edges: Vec<CallGraphEdge>,
}