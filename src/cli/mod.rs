use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::server::model::{severity_order, FinalFindings};
use crate::server::service::OWASPScanner;
use crate::AppState;

// start the scan of the directory
pub async fn scan(path: String, state: Arc<RwLock<AppState>>) -> String {
    let owasp_scanner = OWASPScanner::new();
    let mut all_findings: Vec<FinalFindings> = Vec::new();

    for entry in WalkDir::new(path) {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.to_str().unwrap().contains("node_modules") {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str());
        if matches!(ext, Some("js") | Some("jsx") | Some("ts") | Some("tsx")) {
            // it's a js/ts related file
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    // run the scan for each file and collect findings
                    let mut findings =
                        owasp_scanner.scan(&content, path.to_string_lossy().as_ref());
                    if findings.is_empty() {
                        continue;
                    }
                    findings.sort_by_key(|f| severity_order(&f.severity));
                    all_findings.push(FinalFindings {
                        file_name: path.to_string_lossy().to_string(),
                        findings,
                    });
                }
                Err(e) => {
                    eprintln!("Error reading file {}: {}", path.display(), e);
                }
            }
        }
    }
    let scan_id = Uuid::new_v4().to_string();
    let mut state = state.write().await;
    state.results.insert(scan_id.clone(), all_findings);

    scan_id
}
