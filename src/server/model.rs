use std::fmt::Debug;
use std::cmp::PartialEq;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub enum VulnerabilityType{
    Eval,
    HardcodedSecret,
    SQLInjection
}

// custom trait implementations to make life easier !
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

impl PartialEq for VulnerabilityType {
    fn eq(&self,other: &Self) -> bool {
        matches!((self, other), 
            (VulnerabilityType::Eval, VulnerabilityType::Eval) |
            (VulnerabilityType::HardcodedSecret, VulnerabilityType::HardcodedSecret) |
            (VulnerabilityType::SQLInjection, VulnerabilityType::SQLInjection)
        )
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
} 

#[derive(Debug,PartialEq,Serialize, Deserialize)]
pub struct Findings{
    pub vuln_type:VulnerabilityType,
    pub lines:String,
    pub file_path:String,
    pub snippet:String
}
