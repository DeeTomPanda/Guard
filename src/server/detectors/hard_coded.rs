use regex::Regex;
use crate::Findings;
use crate::server::model::VulnerabilityType;
use super::Detector;

pub struct HardCodedSecret;

impl Detector for HardCodedSecret{
    fn detect(&self, lines:&str, file_path:&str)->Vec<Findings>{
       let patterns = [
    r#"(?i)\b(password|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)\b\s*[:=]\s*['\"`][^'\"`]{3,}['\"`]"#];

        let mut findings:Vec<Findings> = Vec::new();
        for (i,line) in lines.lines().enumerate(){
            for pattern in &patterns{
                let regex = Regex::new(pattern).unwrap();
                if regex.is_match(line){
                    findings.push(Findings{
                        vuln_type: VulnerabilityType::HardcodedSecret,
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