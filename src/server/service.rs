use crate::server::detectors::{GolangScanner, JavaScriptScanner, Scanner, TypeScriptScanner};
use crate::server::models::results::ScanResult;

use std::collections::HashMap;

#[derive(Eq, Hash, PartialEq)]
pub enum Language {
    JavaScript,
    TypeScript,
    Python,
    Java,
    Golang,
}
pub struct OWASPScanner {
    scanners: HashMap<Language, Box<dyn Scanner>>,
    // dyn because its a trait object, we want to store different types of detectors in the same vector
}

impl OWASPScanner {
    pub fn new() -> Self {
        let mut scanners: HashMap<Language, Box<dyn Scanner>> = HashMap::new();

        scanners.insert(Language::JavaScript, Box::new(JavaScriptScanner));
        scanners.insert(Language::TypeScript, Box::new(TypeScriptScanner));
        scanners.insert(Language::Golang, Box::new(GolangScanner));

        OWASPScanner { scanners }
    }

    pub fn scan(&self, codebase: &str, file_path: &str) -> ScanResult {
        let dummy = ScanResult {
            findings: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
        };
        let language = match Self::determine_language(file_path) {
            Some(lang) => lang,
            None => return dummy,
        };

        let scanner = match self.scanners.get(&language) {
            Some(d) => d,
            None => return dummy,
        };

        let scan_result = scanner.scan(codebase, file_path);
        scan_result
    }

    // this can gow to support more languages
    pub fn determine_language(file_path: &str) -> Option<Language> {
        if file_path.ends_with(".js") {
            Some(Language::JavaScript)
        } else if file_path.ends_with(".ts") {
            Some(Language::TypeScript)
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
