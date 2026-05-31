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

// tests for eval detector
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detects_eval_with_variable() {
        let code =r#"
        let user_input = "some input";
        eval(user_input);
        "#;
        
        let detector=Eval{};
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].vuln_type, VulnerabilityType::Eval);
        assert_eq!(findings[0].lines, "3");
        assert_eq!(findings[0].file_path, "test.js");
        assert_eq!(findings[0].snippet, "eval(user_input);");
    }
    
    #[test]
    fn test_no_eval() {
        let code = r#"
        console.log("hello");
        const x = 1 + 1;
    "#;
        let detector = Eval;
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 0);
    }
    
    #[test]
    fn test_multiple_evals() {
        let code = r#"
        eval(input1);
        eval(input2);
    "#;
        let detector = Eval;
        let findings = detector.detect(code, "test.js"  );
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].vuln_type, VulnerabilityType::Eval);
        assert_eq!(findings[0].lines, "2");
        assert_eq!(findings[0].snippet, "eval(input1);");
        assert_eq!(findings[1].lines, "3");
        assert_eq!(findings[1].snippet, "eval(input2);");
        assert_eq!(findings[1].vuln_type, VulnerabilityType::Eval);
    }
}