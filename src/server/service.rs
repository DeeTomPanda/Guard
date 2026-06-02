use crate::server::detectors::{
    Detector, JavaSciptEval, JavaSciptHardCodedSecret, JavaSciptSQLInjection,
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
    detectors: HashMap<Language, Vec<Box<dyn Detector>>>,
    // dyn because its a trait object, we want to store different types of detectors in the same vector
}

impl OWASPScanner {
    pub fn new() -> Self {
        let mut detectors: HashMap<Language, Vec<Box<dyn Detector>>> = HashMap::new();

        detectors.insert(
            Language::JavaScript,
            vec![
                Box::new(JavaSciptEval),
                Box::new(JavaSciptHardCodedSecret),
                Box::new(JavaSciptSQLInjection),
            ],
        );

        OWASPScanner { detectors }
    }

    pub fn scan(&self, codebase: &str, file_path: &str) -> Vec<Findings> {
        let mut all_findings: Vec<Findings> = Vec::new();
        let language = match Self::determine_language(file_path) {
            Some(lang) => lang,
            None => return all_findings,
        };

        let detectors = match self.detectors.get(&language) {
            Some(d) => d,
            None => return all_findings,
        };
        
        for detector in detectors {
            let findings = detector.detect(codebase, file_path);
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
