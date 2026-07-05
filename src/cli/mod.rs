use rayon::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::server::models::findings::{severity_order, FinalFindings};
use crate::server::service::OWASPScanner;
use crate::AppState;

const IGNORED_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".git",
    ".idea",
    ".vscode",
    "dist",
    "build",
];

// start the scan of the directory
pub async fn scan(path: String, state: Arc<RwLock<AppState>>) -> String {
    let owasp_scanner = OWASPScanner::new();

    let entries: Vec<_> = WalkDir::new(&path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            !e.path().components().any(|c| {
                c.as_os_str()
                    .to_str()
                    .map(|s| IGNORED_DIRS.contains(&s))
                    .unwrap_or(false) // maybe not utf-8, but still try and log error if any
            })
        })
        .filter(|e| OWASPScanner::determine_language(&e.path().to_string_lossy()).is_some())
        .collect();

    // scan in parallel using rayon
    let all_findings: Vec<FinalFindings> = entries
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let mut findings = owasp_scanner.scan(&content, &path.to_string_lossy());
                    if findings.is_empty() {
                        return None;
                    }
                    findings.sort_by_key(|f| severity_order(&f.severity));
                    Some(FinalFindings {
                        file_name: path.to_string_lossy().to_string(),
                        findings,
                    })
                }
                Err(e) => {
                    eprintln!("Error reading file {}: {}", path.display(), e);
                    None
                }
            }
        })
        .collect();

    let scan_id = Uuid::new_v4().to_string();
    let mut state = state.write().await;
    state.results.insert(scan_id.clone(), all_findings);
    scan_id
}
