use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::server::service::OWASPScanner;
use crate::AppState;
use crate::{
    server::models::{
        findings::{severity_order, FinalFindings},
        symbols::{Symbol, SymbolTable},
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

    // collect both findings AND symbols in parallel
    let all_results: Vec<(FinalFindings, Vec<Symbol>)> = entries
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
        (FinalFindings { file: "express/index.js" }, vec![Symbol, Symbol]),
        (FinalFindings { file: "express/router.js" }, vec![Symbol, Symbol]),
        (FinalFindings { file: "express/utils.js" }, vec![Symbol]),
    ] */

    // separate them after parallel scan is done
    let (all_findings, all_symbols): (Vec<FinalFindings>, Vec<Vec<Symbol>>) =
        all_results.into_iter().unzip();

    // flatten symbols into SymbolTable
    let mut symbol_map: HashMap<String, Vec<Symbol>> = HashMap::new();
    for symbols in all_symbols {
        for symbol in symbols {
            symbol_map
                .entry(symbol.file.clone())
                .or_insert_with(Vec::new)
                .push(symbol);
        }
    }

    let scan_id = Uuid::new_v4().to_string();
    let mut state = state.write().await;
    let symbol_table = SymbolTable {
        symbols: symbol_map,
    };
    let scan_data = ScanData {
        findings: all_findings,
        symbol_table,
    };

    state.results.insert(scan_id.clone(), scan_data);

    scan_id
}
