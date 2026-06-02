use regex::Regex;
use crate::Findings;
use crate::server::model::{Severity, VulnerabilityType};
use super::Detector;

pub struct SQLInjection;

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
                        line_no: (i+1).to_string(),
                        file_path: String::from(file_path),
                        snippet: line.trim().to_string(),
                        severity:Severity::Critical
                    });
                    break;
                }
            }
        }
        findings
    }
}

// tests for SQLInjection detector

mod test{

    use super::*;

    #[test]
    fn test_sql_injection_positive(){
        let code = r#"
        let user_input = "some input";
        let query = "SELECT * FROM users WHERE name = '" + user_input + "'";
        let anotherQuery = `SELECT * FROM users WHERE name = '${user_input}'`;
        "#;
        let detector = SQLInjection;
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].vuln_type, VulnerabilityType::SQLInjection);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].line_no, "3");
        assert_eq!(findings[0].file_path, "test.js");
        assert_eq!(findings[0].snippet, "let query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\";");
        assert_eq!(findings[1].vuln_type, VulnerabilityType::SQLInjection);
        assert_eq!(findings[1].line_no  , "4");
        assert_eq!(findings[1].snippet,"let anotherQuery = `SELECT * FROM users WHERE name = '${user_input}'`;");
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    #[test]
    fn test_sql_injection_negative(){
        let code = r#"
        let user_input = "some input";
        let query = "SELECT * FROM users WHERE name = ?";
        "#;
        let detector = SQLInjection;
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 0);
    }
}