pub struct Scanner{
    detectors:Vec<Box<dyn Detector>>,
    // dyn because its a trait object, we want to store different types of detectors in the same vector
}

impl Scanner{
    pub fn new()->Self{
        Scanner{
            detectors:vec![
                Box::new(HardCodedSecret),
                Box::new(SQLInjection),
                Box::new(Eval)
            ]
        }
    }

    pub fn scan(&self, codebase:&str)->Vec<Findings>{
        let mut all_findings:Vec<Findings> = Vec::new();
        for detector in &self.detectors{
            let findings = detector.detect(codebase);
            all_findings.extend(findings);
        }
        all_findings
    }
}