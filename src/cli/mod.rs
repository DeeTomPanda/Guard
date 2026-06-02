
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use walkdir::WalkDir;
use uuid::Uuid;

use crate::AppState;
use crate::server::model::{FinalFindings,Findings,severity_order};
use crate::server::service::OWASPScanner;


// start the scan of the directory 
pub async fn scan(path: String, state: Arc<RwLock<AppState>>) -> String {
    
    let owasp_scanner = OWASPScanner::new();
    let mut all_findings: Vec<FinalFindings> = Vec::new();
    
    for entry in WalkDir::new(path) {
        let entry = entry.unwrap();
        let path = entry.path();
        
        if path.to_str()
        .unwrap()
        .contains("node_modules") {
            continue; 
        }
        
        if path.extension().and_then(|e| e.to_str()) == Some("js") {
            // it's a js file
            match std::fs::read_to_string(path){
                Ok(content)=>{
                    // run the scan for each file and collect findings
                    let mut findings = owasp_scanner.scan(&content, path.to_string_lossy().as_ref());
                    if findings.is_empty(){
                        continue;
                    }
                    findings.sort_by_key(|f| severity_order(&f.severity)); 
                    all_findings.push(FinalFindings {
                        file_name: path.to_string_lossy().to_string(),
                        findings
                    });
                },
                Err(e)=>{
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