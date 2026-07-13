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
pub struct Guard {
    scanners: HashMap<Language, Box<dyn Scanner>>,
    // dyn because its a trait object, we want to store different types of detectors in the same vector
}

impl Guard {
    pub fn new() -> Self {
        let mut scanners: HashMap<Language, Box<dyn Scanner>> = HashMap::new();

        scanners.insert(Language::JavaScript, Box::new(JavaScriptScanner));
        scanners.insert(Language::TypeScript, Box::new(TypeScriptScanner));
        scanners.insert(Language::Golang, Box::new(GolangScanner));

        Guard { scanners }
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

        scanner.scan(codebase, file_path)
    }

    // this can grow to support more languages
    pub fn determine_language(file_path: &str) -> Option<Language> {
        match file_path.rsplit('.').next().unwrap_or("") {
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "ts" | "tsx" => Some(Language::TypeScript),
            "go" => Some(Language::Golang),
            // "py" => Some(Language::Python),
            // "java" => Some(Language::Java),
            _ => None,
        }
    }
}
