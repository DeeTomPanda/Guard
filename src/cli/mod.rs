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
    let mut all_findings: Vec<FinalFindings> = Vec::new();

    for entry in WalkDir::new(path) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("encountered error: {}", err);
                continue;
            }
        };
        let path = entry.path();

        // ignore common dependency/build directories for multiple languages.
        if path.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .map(|segment| IGNORED_DIRS.contains(&segment))
                .unwrap_or(false)
        }) {
            continue;
        }

        let file_path = path.to_string_lossy();
        let is_supported_file = OWASPScanner::determine_language(file_path.as_ref()).is_some();

        if is_supported_file {
            // scan files for supported languages (JS, TS, Go, etc.)
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
