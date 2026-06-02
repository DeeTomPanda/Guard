use regex::Regex;
use crate::Findings;
use crate::server::model::{VulnerabilityType,Severity};
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
                        line_no: (i+1).to_string(),
                        file_path: String::from(file_path),
                        snippet: line.trim().to_string(),
                        severity: Severity::High,
                    });
                    break;
                }
            }
        }
        findings
    }
}


// tests for hard coded secret
#[cfg(test)]
mod tests{
    
    use super::*;
    
    #[test]
    fn test_with_hard_coded_secret(){
        let code = r#"
        const password = "mysecretpassword";
        const apiKey = "12345-abcde-67890-fghij";
        const token = "token12345";
        "#;
        
        let detector=HardCodedSecret;
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].vuln_type, VulnerabilityType::HardcodedSecret);
        assert_eq!(findings[0].line_no, "2");
        assert_eq!(findings[0].snippet, "const password = \"mysecretpassword\";");
        assert_eq!(findings[0].file_path, "test.js");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].vuln_type, VulnerabilityType::HardcodedSecret);
        assert_eq!(findings[1].line_no,"3");
        assert_eq!(findings[1].snippet, "const apiKey = \"12345-abcde-67890-fghij\";");
        assert_eq!(findings[1].file_path, "test.js");
        assert_eq!(findings[2].vuln_type, VulnerabilityType::HardcodedSecret);
        assert_eq!(findings[2].snippet, "const token = \"token12345\";");
        assert_eq!(findings[2].file_path, "test.js");
        assert_eq!(findings[2].line_no,"4");
        assert_eq!(findings[2].severity, Severity::High);
    }

    #[test]
    fn test_with_no_hard_coded_secrets(){
        let code=r#"
        let myVar="abcde";
        const config = {
            username: "admin",
        }"#; 
        let detector=HardCodedSecret;
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_with_false_positives(){
        let code = r#"
        const password = getPasswordFromEnv();
        const apiKey = fetchApiKey();
        const token = generateToken();
        "#;
        let detector=HardCodedSecret;
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 0);
    }
}