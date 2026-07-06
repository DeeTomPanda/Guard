use super::calls::CallSite;
use super::findings::Findings;
use super::symbols::Symbol;

pub struct ScanResult {
    pub findings: Vec<Findings>,
    pub symbols: Vec<Symbol>,
    pub calls: Vec<CallSite>,
}
