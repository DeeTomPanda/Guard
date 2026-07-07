
use crate::server::models::{
    data_flow_graph::{DataFlowGraph, EdgeKind, EdgeSite, GraphEdge, GraphNode, NodeKind},
    resolution::ResolutionTable,
    symbols::SymbolTable,
};

pub struct DataFlowGraphBuilder;

impl DataFlowGraphBuilder {
    // for now builds only from call tables
    // TODO: add imports
    pub fn build(resolution: &ResolutionTable, symbol_table: &SymbolTable) -> DataFlowGraph {
        let mut graph = DataFlowGraph::new();
        // add functions to graph first
        Self::add_functions(&mut graph, resolution, symbol_table);
        Self::add_variables(&mut graph, resolution);

        graph
    }

    fn add_variables(graph: &mut DataFlowGraph, resolution: &ResolutionTable) {
        for var in &resolution.variables {
            // assigns: walk the chain in window[1] (rhs) → window[0] (lhs) fashion
            // X = Y means data flows from Y into X → edge: Y → X
            for window in var.chain.windows(2) {
                let (lhs, rhs) = (&window[0], &window[1]);

                let lhs_key = graph.node_key(&lhs.name, &lhs.file);
                let rhs_key = graph.node_key(&rhs.name, &rhs.file);

                graph
                    .nodes
                    .entry(rhs_key.clone())
                    .or_insert_with(|| GraphNode {
                        name: rhs.name.clone(),
                        kind: NodeKind::from(&rhs.kind),
                        file: rhs.file.clone(),
                        line: rhs.line,
                    });

                graph.add_edge(GraphEdge {
                    from: rhs_key,
                    to: lhs_key,
                    kind: EdgeKind::Assigns,
                    site: EdgeSite {
                        file: rhs.file.clone(),
                        line: rhs.line,
                        column: rhs.column,
                    },
                });
            }
        }
    }

    fn add_functions(
        graph: &mut DataFlowGraph,
        resolution: &ResolutionTable,
        symbol_table: &SymbolTable,
    ) {
        for resolved in &resolution.calls {
            let call = &resolved.call;

            let caller_key = graph.register_function(&call.caller, &call.file, symbol_table);
            let callee_key = graph.register_function(&call.callee, &call.file, symbol_table);
            let edge_site = EdgeSite {
                file: call.file.clone(),
                line: call.line,
                column: call.column,
            };

            // calls edge: caller → callee
            graph.add_edge(GraphEdge {
                from: caller_key.clone(),
                to: callee_key.clone(),
                kind: EdgeKind::Calls,
                site: edge_site.clone(),
            });

            for (i, arg) in resolved.arguments.iter().enumerate() {
                // chain[0] = the arg variable itself
                // chain[1..] = what it was assigned from, recursively
                let Some(sym) = arg.chain.first() else {
                    continue;
                };

                let sym_key = graph.node_key(&sym.name, &sym.file);
                graph
                    .nodes
                    .entry(sym_key.clone())
                    .or_insert_with(|| GraphNode {
                        name: sym.name.clone(),
                        kind: NodeKind::from(&sym.kind),
                        file: sym.file.clone(),
                        line: sym.line,
                    });

                // PassedAs: sym flows into callee as arg[i]
                graph.add_edge(GraphEdge {
                    from: sym_key.clone(),
                    to: callee_key.clone(),
                    kind: EdgeKind::PassedAs(i),
                    site: edge_site.clone(),
                });

                // assigns: walk the chain in window[1] (rhs) → window[0] (lhs) fashion
                // X = Y means data flows from Y into X → edge: Y → X
                for window in arg.chain.windows(2) {
                    let (lhs, rhs) = (&window[0], &window[1]);

                    let lhs_key = graph.node_key(&lhs.name, &lhs.file);
                    let rhs_key = graph.node_key(&rhs.name, &rhs.file);

                    graph
                        .nodes
                        .entry(rhs_key.clone())
                        .or_insert_with(|| GraphNode {
                            name: rhs.name.clone(),
                            kind: NodeKind::from(&rhs.kind),
                            file: rhs.file.clone(),
                            line: rhs.line,
                        });

                    graph.add_edge(GraphEdge {
                        from: rhs_key,
                        to: lhs_key,
                        kind: EdgeKind::Assigns,
                        site: edge_site.clone(),
                    });
                }
            }
        }
    }
}
