use crate::server::detectors::{Detector, Eval, HardCodedSecret, SQLInjection};
use crate::server::model::Findings;

pub struct OWASPScanner{
    detectors:Vec<Box<dyn Detector>>,
    // dyn because its a trait object, we want to store different types of detectors in the same vector
}

impl OWASPScanner{
    pub fn new()->Self{
        OWASPScanner{
            detectors:vec![
                Box::new(HardCodedSecret),
                Box::new(SQLInjection),
                Box::new(Eval)
            ]
        }
    }

    pub fn scan(&self, codebase:&str, file_path:&str)->Vec<Findings>{
        let mut all_findings:Vec<Findings> = Vec::new();
        for detector in &self.detectors{
            let findings = detector.detect(codebase, file_path);
            all_findings.extend(findings);
        }
        all_findings
    }
}