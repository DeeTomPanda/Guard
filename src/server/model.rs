use std::fmt::Debug;
pub enum VulnerabilityType{
    Eval,
    HardcodedSecret,
    SQLInjection
}


impl Debug for VulnerabilityType{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vuln_str = match self{
            VulnerabilityType::Eval => "Eval",
            VulnerabilityType::HardcodedSecret => "Hardcoded Secret",
            VulnerabilityType::SQLInjection => "SQL Injection"
        };
        write!(f, "{}", vuln_str)
    }
}

#[derive(Debug)]
pub struct Findings{
    pub vuln_type:VulnerabilityType,
    pub lines:String,
    pub file_path:String,
    pub snippet:String
}
