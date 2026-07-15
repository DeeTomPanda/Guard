use ignore::WalkBuilder;
use rayon::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::server::models::resolution::{ResolvedCall, ResolvedVariable};
use crate::server::taint_engine::data_flow_graph::DataFlowGraphBuilder;
use crate::AppState;
use crate::{
    server::{
        guard::Guard,
        models::{
            calls::{CallSite, CallTable},
            data_flow_graph::{DataFlowGraph, EdgeKind, NodeKind},
            findings::{severity_order, FinalFindings},
            symbols::{Symbol, SymbolTable},
        },
        module_resolver::ImportResolver,
        taint_engine::resolve::Resolver,
    },
    state::ScanData,
};

// start the scan of the directory
pub async fn scan(path: String, state: Arc<RwLock<AppState>>) -> String {
    // canonicalize here, make everyting absolute
    let canonical_path = std::fs::canonicalize(&path)
        .expect("scan path must exist")
        .to_string_lossy()
        .into_owned();

    let guard_scanner = Guard::new();
    let entries: Vec<_> = WalkBuilder::new(&canonical_path)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| Guard::determine_language(&e.path().to_string_lossy()).is_some())
        .collect();

    // collect both findings AND symbols AND callsites in parallel
    let all_results: Vec<(FinalFindings, Vec<Symbol>, Vec<CallSite>)> = entries
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let mut scan_result = guard_scanner.scan(&content, &path.to_string_lossy());
                    if scan_result.findings.is_empty() && scan_result.symbols.is_empty() {
                        return None;
                    }
                    scan_result
                        .findings
                        .sort_by_key(|f| severity_order(&f.severity));
                    Some((
                        FinalFindings {
                            file_name: canonical_path.clone(),
                            findings: scan_result.findings,
                        },
                        scan_result.symbols,
                        scan_result.calls,
                    ))
                }
                Err(e) => {
                    eprintln!("Error reading file {}: {}", path.display(), e);
                    None
                }
            }
        })
        .collect();

    /* after all that it would be like e.g.
        all_results = [
        (FinalFindings { file: "express/index.js" }, vec![Symbol, Symbol], vec![CallSite, CallSite]),
        (FinalFindings { file: "express/router.js" }, vec![Symbol, Symbol], vec![CallSite, CallSite]),
        (FinalFindings { file: "express/utils.js" }, vec![Symbol], vec![CallSite, CallSite]),
    ] */

    // separate them after parallel scan is done
    let mut all_findings = Vec::new();
    let mut all_symbols = Vec::new();
    let mut all_calls = Vec::new();

    for (findings, symbols, calls) in all_results {
        all_findings.push(findings);
        all_symbols.push(symbols);
        all_calls.push(calls);
    }

    // flatten symbols into SymbolTable
    let mut symbol_table = SymbolTable::new();
    for symbols in all_symbols {
        for symbol in symbols {
            symbol_table.insert(symbol.file.clone(), symbol);
        }
    }

    let all_files: Vec<String> = entries
        .iter()
        .map(|p| p.path().to_string_lossy().into_owned())
        .collect();

    let import_resolver = ImportResolver::new(&canonical_path, &all_files);
    symbol_table.build_indexes(&import_resolver);

    // flatten calls into CallTable
    let mut call_table = CallTable::new();
    for calls in all_calls {
        for call in calls {
            call_table.insert(call.file.clone(), call);
        }
    }

    let resolution_table = Resolver::resolve(&symbol_table, &call_table);
    let graph = DataFlowGraphBuilder::build(&resolution_table, &symbol_table);


    // show_graph(&graph);

    let scan_id = Uuid::new_v4().to_string();
    let mut state = state.write().await;

    let scan_data = ScanData {
        findings: all_findings,
        symbol_table,
        call_table,
        resolution_table,
        graph: DataFlowGraph::new(),
    };

    state.results.insert(scan_id.clone(), scan_data);

    scan_id
}

fn show_graph(graph: &DataFlowGraph) {
    print!("\n");
    for (node_id, node) in &graph.nodes {
        let kind = match node.kind {
            NodeKind::Function => "function",
            NodeKind::Import => "import",
            NodeKind::Parameter => "param",
            NodeKind::Variable => "var",
        };

        println!("NODE: {} ({})  {}", node_id, node.name, kind);

        if let Some(edges) = graph.forward.get(node_id) {
            for edge in edges {
                let rel = match edge.kind {
                    EdgeKind::Calls => "CALLS",
                    EdgeKind::PassedAs(usize) => "ARG",
                    EdgeKind::Assigns => "ASSIGNMENT",
                };

                println!("      └── {} → {} ", rel, edge.to);
            }
        }

        println!();
    }
}
