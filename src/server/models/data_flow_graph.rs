use crate::server::models::{
    calls::CallSite,
    symbols::{SymbolKind, SymbolTable},
};
use std::collections::HashMap;

// Node

#[derive(Debug, Clone)]
pub enum NodeKind {
    Function,
    Variable,
    Parameter,
    Import,
}

impl From<&SymbolKind> for NodeKind {
    fn from(k: &SymbolKind) -> Self {
        match k {
            SymbolKind::Function | SymbolKind::Method | SymbolKind::Class | SymbolKind::Struct => {
                NodeKind::Function
            }
            SymbolKind::Variable => NodeKind::Variable,
            SymbolKind::Parameter => NodeKind::Parameter,
            SymbolKind::Import => NodeKind::Import,
        }
    }
}

#[derive(Debug)]
pub struct GraphNode {
    pub name: String,
    pub kind: NodeKind,
    pub file: String,
    pub line: usize,
}

//  Edge

#[derive(Debug, Clone)]
pub enum EdgeKind {
    Calls,           // function to function
    Assigns,         // rhs to lhs  (data flows from rhs into lhs: Y = X means X is passed to Y)
    PassedAs(usize), // variable to callee, as argument at index N
}
#[derive(Debug, Clone)]
pub struct EdgeSite {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from: String, // source node key
    pub to: String,   // target node key
    pub kind: EdgeKind,
    pub site: EdgeSite, // source location in code
}

//  Graph

// Unified call + data-flow graph.
//
// forward["name::file"] edges leaving that node  (follow data toward sinks)
// reverse["name::file"] edges arriving at that node (trace back to sources)
#[derive(Debug)]
pub struct DataFlowGraph {
    pub nodes: HashMap<String, GraphNode>,
    pub forward: HashMap<String, Vec<GraphEdge>>, // traversal from a node outward
    pub reverse: HashMap<String, Vec<GraphEdge>>, // taint: walk backward to sources
}

impl DataFlowGraph {
    pub fn new() -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            nodes: HashMap::new(),
        }
    }
    //  internal helpers

    // look up a function in SymbolTable for real kind/line; fall back to synthetic node.
    // callee may be in another file (cross file impl pending)
    pub fn register_function(
        &mut self,
        name: &str,
        obj: Option<&str>,
        file: &str,
        st: &SymbolTable,
    ) -> String {
        let found = st
            .fn_index
            .get(file)
            .and_then(|m| m.get(name))
            .and_then(|v| v.first());

        let found = found.or_else(|| {
            let alias = obj?;

            let source_files = st.import_index.get(file)?.get(alias)?;

            // then iterate over fn index and reoslve symbol
            source_files
                .iter()
                .find_map(|src| st.fn_index.get(src)?.get(name).and_then(|v| v.first()))
        });

        let (key, node) = match found {
            Some(sym) => (
                format!("{}::{}::{}", sym.name, sym.scope, sym.file), // scope-qualified, collision-safe
                GraphNode {
                    name: sym.name.clone(),
                    kind: NodeKind::Function,
                    file: sym.file.clone(),
                    line: sym.line,
                },
            ),
            None => (
                format!("{}::unresolved::{}", name, file), // e.g. db.query — external/unresolvable
                GraphNode {
                    name: name.to_string(),
                    kind: NodeKind::Function,
                    file: file.to_string(),
                    line: 0,
                },
            ),
        };

        if !self.nodes.contains_key(&key) {
            self.nodes.insert(key.clone(), node);
        }
        key
    }

    pub fn register_variable(&mut self) {}

    pub fn add_edge(&mut self, edge: GraphEdge) {
        self.reverse
            .entry(edge.to.clone())
            .or_default()
            .push(edge.clone());
        self.forward
            .entry(edge.from.clone())
            .or_default()
            .push(edge);
    }

    // query helpers

    // all edges leaving `key`, follow data flow toward sinks
    pub fn edges_from(&self, key: &str) -> &[GraphEdge] {
        self.forward.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    // all edges arriving at `key`,` trace back to taint sources
    pub fn edges_to(&self, key: &str) -> &[GraphEdge] {
        self.reverse.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    // find a node by name + file
    pub fn find_node(&self, name: &str, file: &str) -> Option<(&String, &GraphNode)> {
        self.nodes
            .iter()
            .find(|(_, n)| n.name == name && n.file == file)
    }

    pub fn node_key(&self, name: &str, scope: &str, file: &str) -> String {
        
        format!("{}::{}::{}", name, scope, file)
    }
}
