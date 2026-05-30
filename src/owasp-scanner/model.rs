
enum VulnerabilityType{
    Eval,
    HardcodedSecret,
    SQLInjection
}

struct Findings{
    pub vuln_type:VulnerabilityType,
    pub lines:String,
    pub file_path:String,
    pub snippet:String
}
