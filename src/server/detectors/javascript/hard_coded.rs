use super::parser::parse_to_ast;
use super::utils::{is_hardcoded_secret, is_secret_name};
use crate::server::detectors::Detector;
use crate::server::model::{Severity, VulnerabilityType};
use crate::Findings;
use oxc::allocator::Allocator;
use oxc::ast_visit::Visit;
use oxc::span::GetSpan;
use oxc_ast::ast::{BindingPattern, Expression, VariableDeclarator};

pub struct JavaSciptHardCodedSecret {}

impl JavaSciptHardCodedSecret {
    pub fn initialize() -> Self {
        Self {}
    }
}

struct HardCodedSecretVisitor<'a> {
    findings: Vec<Findings>,
    file_path: &'a str,
    source_text: &'a str,
}

impl Detector for JavaSciptHardCodedSecret {
    fn detect(&self, code: &str, file_path: &str) -> Vec<Findings> {
        let allocator = Allocator::default();

        let ast = match parse_to_ast(code, &allocator, file_path) {
            Ok(program) => program,
            Err(e) => {
                eprintln!("Parse error: {}", e);
                return vec![];
            }
        };

        let mut visitor = HardCodedSecretVisitor {
            findings: Vec::new(),
            file_path,
            source_text: code,
        };

        visitor.visit_program(&ast);

        visitor.findings
    }
}

// visitor implementation for AST traversal
impl<'a> Visit<'a> for HardCodedSecretVisitor<'a> {
    fn visit_variable_declarator(&mut self, node: &VariableDeclarator<'a>) {
        // Get varibale name from AST first
        if let BindingPattern::BindingIdentifier(ident) = &node.id {
            // check for Object Pattern like const config = {password: "secret"}
            if let Some(Expression::ObjectExpression(obj_lit)) = &node.init {
                for prop in &obj_lit.properties {
                    if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) = prop {
                        if let oxc_ast::ast::PropertyKey::StaticIdentifier(ident) = &prop.key {
                            let key_name = ident.name.to_lowercase();
                            if is_secret_name(&key_name) {
                                // check if the value is a string literal or template literal without expressions
                                let value = &prop.value;
                                if let Some(value) = is_hardcoded_secret(value) {
                                    self.report(&key_name, &value, prop.span().start as usize);
                                }
                            }
                        }
                    }
                }
            } else {
                // then check for normal variable declaration like const password
                let var_name = ident.name.to_lowercase();

                // check if variable name contains keywords commonly associated with secrets
                let is_secret = is_secret_name(&var_name);
                if !is_secret {
                    return;
                }

                // determine what type of expression is associated, must be string literal or template literal without expressions
                if let Some(init) = &node.init {
                    if let Some(value) = is_hardcoded_secret(init) {
                        self.report(&var_name, &value, init.span().start as usize);
                    }
                }
            }
        }
    }
}

impl HardCodedSecretVisitor<'_> {
    fn report(&mut self, key: &str, value: &str, span_start: usize) {
        let line = self.source_text[..span_start].lines().count();

        self.findings.push(Findings {
            vuln_type: VulnerabilityType::HardcodedSecret,
            line_no: line.to_string(),
            file_path: self.file_path.to_string(),
            snippet: format!("{key} = \"{value}\""),
            severity: Severity::High,
        });
    }
}

// tests for hard coded secret
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn detects_basic_hardcoded_secrets() {
        let code = r#"
        const password = "secret123";
        const apiKey = "abcd";
        const token = `xyz`;
        const obj={
            password:"objsecret"
        }
    "#;

        let detector = JavaSciptHardCodedSecret {};
        let findings = detector.detect(code, "test.js");

        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn test_with_no_hard_coded_secrets() {
        let code = r#"
        let myVar="abcde";
        const config = {
            username: "admin",
            passwd:`${getPassword()}`,
            password: getPassword(),
        }"#;

        let detector = JavaSciptHardCodedSecret {};
        let findings = detector.detect(code, "test.js");
                println!("{:#?}", findings);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_with_false_positives() {
        let code = r#"
        const password = getPasswordFromEnv();
        const apiKey = fetchApiKey();
        const token = generateToken();
        "#;
        let detector = JavaSciptHardCodedSecret {};
        let findings = detector.detect(code, "test.js");
        assert_eq!(findings.len(), 0);
    }
}
