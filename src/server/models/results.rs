use super::findings::Findings;
use super::symbols::Symbol;
use super::calls::CallSite;

pub struct ScanResult {
    pub findings: Vec<Findings>,
    pub symbols: Vec<Symbol>,
    pub calls :Vec<CallSite>
}