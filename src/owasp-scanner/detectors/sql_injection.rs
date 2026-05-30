use regex::Regex;
use crate::Findings;
use crate::detectors::Detector;

struct SQLInjection;

impl Detector for SQLInjection{
    
    fn detect(&self, lines:&str, file_path:&str)->Vec<Findings>{
        let patterns = [
        r"(?i)(select|insert|update|delete)\s+.*\+",
        r"`.*\$\{.*\}.*`",
        r"(?i)\bsql\s*=\s*.*(\+|\$\{)",
        ];
        let mut findings:Vec<Findings> = Vec::new();
        for (i,line) in lines.lines().enumerate(){
            for pattern in &patterns{
                let regex = Regex::new(pattern).unwrap();
                if regex.is_match(line){
                    findings.push(Findings{
                        vuln_type: VulnerabilityType::SQLInjection,
                        lines: (i+1).to_string(),
                        file_path: String::from(file_path),
                        snippet: line.trim().to_string()
                    });
                    break;
                }
            }
        }
        findings
    }
}