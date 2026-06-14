use crate::server::detectors::shared::common_parser::{CodeVisitor,parse_to_ast};
use crate::server::detectors::Scanner;
use oxc::ast_visit::Visit;
use crate::Findings;
use oxc::allocator::Allocator;

pub struct TypeScriptScanner;

// checks presence of any eval() in the codebase
// hardcoded secrets
// SQL Injection vulnerabilities
impl Scanner for TypeScriptScanner {
    fn scan(&self, code: &str, file_path: &str) -> Vec<Findings> {
        let allocator = Allocator::default();

        let ast = match parse_to_ast(code, &allocator, file_path) {
            Ok(program) => program,
            Err(e) => {
                eprintln!("Parse error: {}", e);
                return vec![];
            }
        };

        let mut visitor = CodeVisitor {
            findings: Vec::new(),
            file_path,
            source_text: code,
        };

        visitor.visit_program(&ast);
        visitor.list_possible_threats()
    }
}
