use ignore::WalkBuilder;
use rayon::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::server::taint_engine::data_flow_graph::DataFlowGraphBuilder;
use crate::AppState;
use crate::{
    server::{
        models::{
            calls::{CallSite, CallTable},
            data_flow_graph::DataFlowGraph,
            findings::{severity_order, FinalFindings},
            symbols::{Symbol, SymbolTable},
        },
        service::OWASPScanner,
        taint_engine::resolve::Resolver,
    },
    state::ScanData,
};

// start the scan of the directory
pub async fn scan(path: String, state: Arc<RwLock<AppState>>) -> String {
    let owasp_scanner = OWASPScanner::new();
    let entries: Vec<_> = WalkBuilder::new(&path)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| OWASPScanner::determine_language(&e.path().to_string_lossy()).is_some())
        .collect();

    // collect both findings AND symbols AND callsites in parallel
    let all_results: Vec<(FinalFindings, Vec<Symbol>, Vec<CallSite>)> = entries
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let mut scan_result = owasp_scanner.scan(&content, &path.to_string_lossy());
                    if scan_result.findings.is_empty() && scan_result.symbols.is_empty() {
                        return None;
                    }
                    scan_result
                        .findings
                        .sort_by_key(|f| severity_order(&f.severity));
                    Some((
                        FinalFindings {
                            file_name: path.to_string_lossy().to_string(),
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
    symbol_table.build_index();

    // flatten calls into CallTable
    let mut call_table = CallTable::new();
    for calls in all_calls {
        for call in calls {
            call_table.insert(call.file.clone(), call);
        }
    }

    let resolution_table = Resolver::resolve(&symbol_table, &call_table);
    let _graph = DataFlowGraphBuilder::build(&resolution_table, &symbol_table);

    // for resolved in &resolution_table.calls {
    //     println!(
    //         "{}() caller: {}",
    //         resolved.call.callee, resolved.call.caller
    //     );
    //     for arg in &resolved.arguments {
    //         println!(
    //             "  arg: {} → symbol: {:?} → assigned: {:?}",
    //             arg.raw,
    //             arg.symbol.as_ref().map(|s| &s.name),
    //             arg.assigned_from
    //         );
    //     }
    // }

    for var in &resolution_table.variables {
        println!("variable: {}", var.name);
        dbg!(&var.chain);
    }

    // print!("\n");
    // for (node_id, node) in &graph.nodes {
    //     println!("NODE: {} ({})", node_id, node.name);

    //     if let Some(edges) = graph.forward.get(node_id) {
    //         for edge in edges {
    //             let rel = match edge.kind {
    //                 EdgeKind::Calls => "CALLS",
    //                 EdgeKind::PassedAs(usize) => "ARG",
    //                 EdgeKind::Assigns=>"ASSIGNMENT"
    //             };

    //             println!("      └── {} → {}", rel, edge.to);
    //         }
    //     }

    //     println!();
    // }

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
