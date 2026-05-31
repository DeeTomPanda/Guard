use regex::Regex;
use crate::{Findings};
use crate::server::model::VulnerabilityType;
use super::Detector;


pub struct Eval;

// checks presence of any eval() in the codebase
impl Detector for Eval{
    fn detect(&self, lines:&str, file_path:&str)->Vec<Findings>{
        let mut findings:Vec<Findings> = Vec::new();
        let pattern = Regex::new(r"\beval\s*\(").unwrap();
        
        for (i,line) in lines.lines().enumerate(){
            if pattern.is_match(line){
                findings.push(Findings{
                    vuln_type: VulnerabilityType::Eval,
                    lines: (i+1).to_string(),
                    file_path: String::from(file_path),
                    snippet: line.trim().to_string()
                })
            }
        }

        findings
    }
}