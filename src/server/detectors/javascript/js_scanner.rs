use crate::server::detectors::shared::common_parser::CodeVisitor;
use crate::server::detectors::Scanner;
use crate::server::models::results::ScanResult;
use oxc::allocator::Allocator;
use oxc::ast_visit::Visit;

pub struct JavaScriptScanner;

// checks presence of any eval() in the codebase
// hardcoded secrets
// SQL Injection vulnerabilities
impl Scanner for JavaScriptScanner {
    fn scan(&self, code: &str, file_path: &str) -> ScanResult {
        let allocator = Allocator::default();
        let mut visitor = CodeVisitor::new(file_path, code);

        let ast = match CodeVisitor::parse_to_ast(code, &allocator, file_path) {
            Ok(program) => program,
            Err(e) => {
                eprintln!("Parse error: {}", e);
                return ScanResult {
                    findings: vec![],
                    symbols: vec![],
                    calls: vec![],
                };
            }
        };

        visitor.visit_program(&ast);
        visitor.into_scan_result()
    }
}
