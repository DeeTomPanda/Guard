use crate::server::detectors::{
    JavaScriptScanner,
    Scanner
};
use crate::server::model::Findings;
use std::collections::HashMap;

#[derive(Eq, Hash, PartialEq)]
pub enum Language {
    JavaScript,
    Python,
    Java,
    Golang,
}
pub struct OWASPScanner {
    scanners: HashMap<Language, Vec<Box<dyn Scanner>>>,
    // dyn because its a trait object, we want to store different types of detectors in the same vector
}

impl OWASPScanner {
    pub fn new() -> Self {
        let mut scanners: HashMap<Language, Vec<Box<dyn Scanner>>> = HashMap::new();

        scanners.insert(
            Language::JavaScript,
            vec![Box::new(JavaScriptScanner)],
        );

        OWASPScanner { scanners }
    }

    pub fn scan(&self, codebase: &str, file_path: &str) -> Vec<Findings> {
        let mut all_findings: Vec<Findings> = Vec::new();
        let language = match Self::determine_language(file_path) {
            Some(lang) => lang,
            None => return all_findings,
        };

        let scanners = match self.scanners.get(&language) {
            Some(d) => d,
            None => return all_findings,
        };
        
        for scanner in scanners {
            let findings = scanner.scan(codebase, file_path);
            all_findings.extend(findings);
        }
        all_findings
    }

    // this can gow to support more languages
    pub fn determine_language(file_path: &str) -> Option<Language> {
        if file_path.ends_with(".js") {
            Some(Language::JavaScript)
        } else if file_path.ends_with(".py") {
            Some(Language::Python)
        } else if file_path.ends_with(".java") {
            Some(Language::Java)
        } else if file_path.ends_with(".go") {
            Some(Language::Golang)
        } else {
            None
        }
    }
}
