use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::fmt::Debug;

#[derive(Serialize, Deserialize)]
pub enum VulnerabilityType {
    Eval,
    HardcodedSecret,
    SQLInjection,
    UnsafeTypeAssertion,
}
#[derive(Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}


impl VulnerabilityType {
    pub fn rule_id(&self) -> &'static str {
        match self {
            VulnerabilityType::Eval => "eval-dangerous-call",
            VulnerabilityType::SQLInjection => "sql-injection",
            VulnerabilityType::HardcodedSecret => "hardcoded-secret",
            VulnerabilityType::UnsafeTypeAssertion => "unsafe-type-assertion",
        }
    }

    pub fn rule_name(&self) -> &'static str {
        match self {
            VulnerabilityType::Eval => "Eval / Dangerous Call",
            VulnerabilityType::SQLInjection => "SQL Injection",
            VulnerabilityType::HardcodedSecret => "Hardcoded Secret",
            VulnerabilityType::UnsafeTypeAssertion => "Unsafe Type Assertion",
        }
    }
}


pub fn severity_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

// custom trait implementations to make life easier !
impl Debug for VulnerabilityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vuln_str = match self {
            VulnerabilityType::Eval => "Eval",
            VulnerabilityType::HardcodedSecret => "Hardcoded Secret",
            VulnerabilityType::SQLInjection => "SQL Injection",
            VulnerabilityType::UnsafeTypeAssertion => "Potential Unsafe Assertion",
        };
        write!(f, "{}", vuln_str)
    }
}

impl PartialEq for VulnerabilityType {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (VulnerabilityType::Eval, VulnerabilityType::Eval)
                | (
                    VulnerabilityType::HardcodedSecret,
                    VulnerabilityType::HardcodedSecret
                )
                | (
                    VulnerabilityType::SQLInjection,
                    VulnerabilityType::SQLInjection
                )
                | (
                    VulnerabilityType::UnsafeTypeAssertion,
                    VulnerabilityType::UnsafeTypeAssertion
                )
        )
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
}

impl Debug for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let severity_str = match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        };
        write!(f, "{}", severity_str)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Findings {
    pub vuln_type: VulnerabilityType,
    pub line_no: String,
    pub file_path: String,
    pub snippet: String,
    pub severity: Severity,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FinalFindings {
    pub file_name: String,
    pub findings: Vec<Findings>,
}
