#[cfg(test)]
mod test {
    use crate::server::detectors::{Scanner, TypeScriptScanner};
    use crate::server::models::findings::VulnerabilityType;

    // declare once, use everywhere
    static SCANNER: TypeScriptScanner = TypeScriptScanner {};

    #[test]
    fn detects_eval_wrapped_in_as_any() {
        let code = r#"(eval as any)("alert(1)");"#;
        let findings = SCANNER.scan(code, "test.ts");
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::Eval));
    }

    #[test]
    fn detects_secret_wrapped_in_satisfies() {
        let code = r#"
        const config = {
            password: "secret123"
        } satisfies Config;
    "#;
        let findings = SCANNER.scan(code, "test.ts");
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::HardcodedSecret));
    }

    #[test]
    fn detects_as_any_usage() {
        let code = r#"const x = userInput as any;"#;
        let findings = SCANNER.scan(code, "test.ts");
        dbg!(&findings);
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::UnsafeTypeAssertion));
    }

    #[test]
    fn detects_eval_nested_in_call_arguments() {
        let code = r#"db.query(eval("SELECT * FROM " + table));"#;
        let findings = SCANNER.scan(code, "test.ts");
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::Eval));
    }
}
