use crate::server::models::findings::{Severity, VulnerabilityType};
use crate::server::{detectors::Scanner, models::findings::Findings};

pub struct GolangScanner;

pub (super) struct GolangTreeSitter<'a> {
    findings: Vec<Findings>,
    file_path: &'a str,
}

impl Scanner for GolangScanner{
    fn scan(&self, code: &str, file_path: &str) -> Vec<Findings> {
        let mut tree_sitter = GolangTreeSitter::new(file_path);
        tree_sitter.analyze(code);
        tree_sitter.list_possible_threats()
    }
}

impl<'a> GolangTreeSitter<'a> {
    pub fn new(file_path: &'a str) -> Self {
        Self {
            findings: Vec::new(),
            file_path,
        }
    }

    fn analyze(&mut self, code: &str) {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_go::LANGUAGE;
        if let Err(err) = parser.set_language(&language.into()) {
            eprintln!(
                "go parser could not be initialized err: {} \nCheck that tree-sitter and tree-sitter-go versions match.",
                 err
            );
            return;
        }

        let tree = match parser.parse(code, None) {
            Some(tree) => tree,
            None => {
                eprintln!("go parser failed to analyze");
                return;
            }
        };
        let root = tree.root_node();
        let bytes = code.as_bytes();
        // check for hardcoded secrets
        self.check_secrets(root, bytes);
        // check for SQL injection vulnerabilities
        self.check_sql_sprintf(root, bytes);
        self.check_sql_db(root, bytes);
        self.check_gorm(root, bytes);
        // check for command injection vulnerabilities
        self.check_exec(root, bytes);
        self.check_syscall(root, bytes);
        // check for unsafe file operations
        self.check_file_ops(root, bytes);

    }

    pub(super) fn report(
        &mut self,
        snippet: &str,
        line: &str,
        vuln_type: VulnerabilityType,
        severity: Severity,
    ) {
        // avoid duplicate findings for the same vuln type, line and snippet
        let exists = self.findings.iter().any(|f| {
            f.vuln_type == vuln_type && f.line_no == line && f.snippet == snippet
        });

        if exists {
            return;
        }

        self.findings.push(Findings {
            vuln_type,
            line_no: line.to_string(),
            file_path: self.file_path.to_string(),
            snippet: snippet.to_string(),
            severity,
        });
    }

    pub fn list_possible_threats(self) -> Vec<Findings> {
        self.findings
    }
}
